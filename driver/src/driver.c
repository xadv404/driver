#include "driver.h"

// Sauvegarde pour restauration propre au déchargement
static PLDR_DATA_TABLE_ENTRY g_ModuleEntry = NULL;
static PLIST_ENTRY           g_PrevFlink   = NULL;
static PLIST_ENTRY           g_PrevBlink   = NULL;

/*
 * HideSelf : retire le driver de PsLoadedModuleList.
 *
 * DriverObject->DriverSection pointe vers le LDR_DATA_TABLE_ENTRY
 * du driver, utilisé par le noyau pour tenir la liste des modules chargés.
 * RemoveEntryList délie l'entrée sans libérer la mémoire.
 */
VOID HideSelf(_In_ PDRIVER_OBJECT DriverObject)
{
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    if (!entry) {
        DbgPrint("[SelfHide] DriverSection NULL, abandon\n");
        return;
    }

    g_ModuleEntry = entry;
    // Sauvegarde des voisins pour restauration
    g_PrevFlink = entry->InLoadOrderLinks.Flink;
    g_PrevBlink = entry->InLoadOrderLinks.Blink;

    RemoveEntryList(&entry->InLoadOrderLinks);
    // Évite les accès dangling si quelqu'un lit l'entrée malgré tout
    InitializeListHead(&entry->InLoadOrderLinks);

    DbgPrint("[SelfHide] Retiré de PsLoadedModuleList\n");
}

/*
 * RestoreSelf : ré-insère l'entrée avant le déchargement.
 *
 * Sans cette restauration, le Memory Manager tente de parcourir
 * la liste au déchargement et provoque un BSOD (accès à une entrée
 * dont les liens sont invalides).
 */
VOID RestoreSelf(VOID)
{
    if (!g_ModuleEntry || !g_PrevBlink) return;

    // Ré-insertion entre le Blink sauvegardé et son Flink actuel
    g_ModuleEntry->InLoadOrderLinks.Flink = g_PrevBlink->Flink;
    g_ModuleEntry->InLoadOrderLinks.Blink = g_PrevBlink;
    g_PrevBlink->Flink->Blink = &g_ModuleEntry->InLoadOrderLinks;
    g_PrevBlink->Flink        = &g_ModuleEntry->InLoadOrderLinks;

    g_ModuleEntry = NULL;
    DbgPrint("[SelfHide] Entrée restaurée dans PsLoadedModuleList\n");
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    RestoreSelf();
    DbgPrint("[SelfHide] Driver déchargé\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[SelfHide] Driver chargé — dissimulation en cours...\n");
    HideSelf(DriverObject);

    return STATUS_SUCCESS;
}
