#include "stealth.h"

// ---------------------------------------------------------------------------
// GetNtoskrnlBase
//
// Le premier élément de PsLoadedModuleList est toujours ntoskrnl.exe.
// Utilisé pour délimiter la plage de scan des patterns.
// ---------------------------------------------------------------------------
PVOID GetNtoskrnlBase(VOID)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    PLIST_ENTRY    list = (PLIST_ENTRY)MmGetSystemRoutineAddress(&name);
    if (!list || list->Flink == list) return NULL;

    PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(
        list->Flink, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    return e->DllBase;
}

// ---------------------------------------------------------------------------
// CleanHashLinks — retrait de la table de hachage LDR noyau
//
// En parallèle de InLoadOrderLinks, le noyau maintient une hash-table de
// modules indexée par nom (utilisée par MmGetSystemRoutineAddress, etc.).
// Les outils qui cherchent un driver par nom passeront par cette table.
// ---------------------------------------------------------------------------
VOID CleanHashLinks(_Inout_ PLDR_DATA_TABLE_ENTRY entry)
{
    if (!entry) return;
    if (IsListEmpty(&entry->HashLinks)) return;

    RemoveEntryList(&entry->HashLinks);
    InitializeListHead(&entry->HashLinks);
}

// ---------------------------------------------------------------------------
// ZeroLdrFields — zeroing des champs restants dans LDR_DATA_TABLE_ENTRY
//
// Après déliage des listes, la structure est encore en mémoire.
// Un scan brut (cherche DllBase, SizeOfImage valides) peut retrouver
// notre driver. On zeroise tout ce qui peut identifier l'image.
// ---------------------------------------------------------------------------
VOID ZeroLdrFields(_Inout_ PLDR_DATA_TABLE_ENTRY entry)
{
    if (!entry) return;
    entry->DllBase     = NULL;
    entry->EntryPoint  = NULL;
    entry->SizeOfImage = 0;
    entry->CheckSum    = 0;
    entry->TimeDateStamp = 0;
    entry->Flags       = 0;
    entry->LoadCount   = 0;
    entry->SectionPointer = NULL;
}

// ---------------------------------------------------------------------------
// CleanPiDDBCache — suppression de l'entrée dans PiDDBCacheTable
//
// Windows maintient une RTL_AVL_TABLE (PiDDBCacheTable) indexée par
// TimeDateStamp pour chaque driver jamais chargé. Process Hacker et les
// anti-cheats l'interrogent pour détecter des drivers cachés ou suspects.
//
// Méthode :
//  1. Lire notre TimeDateStamp depuis le PE header (avant ErasePeHeader)
//  2. Localiser PiDDBCacheTable par pattern scan dans ntoskrnl
//  3. Parcourir la liste ordonnée et supprimer notre entrée
//
// Pattern ciblé (Windows 10 1903–22H2 x64) :
//   66 03 D2          ← add dx, dx
//   4C 8D 05 xx xx xx xx  ← lea r8, [rip + PiDDBCacheTable]
//
// DOIT être appelé AVANT ErasePeHeader (on lit le header PE ici).
// ---------------------------------------------------------------------------
VOID CleanPiDDBCache(_In_ PVOID ImageBase)
{
    if (!ImageBase) return;

    // Lire le timestamp depuis notre PE header avant qu'il soit effacé
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    if (dos->e_lfanew <= 0 || dos->e_lfanew >= 0x400) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    ULONG ts = nt->FileHeader.TimeDateStamp;
    if (ts == 0) return;  // timestamp nul → aucune entrée créée

    // Base et taille de ntoskrnl
    PVOID ntBase = GetNtoskrnlBase();
    if (!ntBase) return;

    PIMAGE_DOS_HEADER ntDos = (PIMAGE_DOS_HEADER)ntBase;
    PIMAGE_NT_HEADERS ntNt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)ntBase + ntDos->e_lfanew);
    ULONG ntSize = ntNt->OptionalHeader.SizeOfImage;

    // Pattern scan : "66 03 D2 4C 8D 05"
    BYTE pat[6] = { 0x66, 0x03, 0xD2, 0x4C, 0x8D, 0x05 };
    PUCHAR scan  = (PUCHAR)ntBase;
    PRTL_AVL_TABLE pCache = NULL;

    __try {
        for (ULONG i = 0; i + 10 < ntSize; i++) {
            if (RtlCompareMemory(scan + i, pat, 6) != 6) continue;

            LONG   rel       = *(PLONG)(scan + i + 6);
            ULONG_PTR cand   = (ULONG_PTR)(scan + i + 10) + rel;

            if (cand <= (ULONG_PTR)ntBase ||
                cand >= (ULONG_PTR)ntBase + ntSize) continue;

            pCache = (PRTL_AVL_TABLE)cand;
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { pCache = NULL; }

    if (!pCache) return;

    // Parcourir la liste ordonnée de la table AVL et supprimer notre entrée.
    // On passe à DISPATCH_LEVEL pour éviter la préemption pendant la
    // manipulation (pas d'accès pages paginées au-delà, mais la table
    // elle-même est en mémoire non paginée).
    KIRQL irql;
    KeRaiseIrql(DISPATCH_LEVEL, &irql);

    __try {
        PPiDDBCacheEntry e =
            (PPiDDBCacheEntry)RtlEnumerateGenericTableAvl(pCache, TRUE);
        while (e) {
            if (e->TimeDateStamp == ts) {
                // Supprimer uniquement de la liste ordonnée.
                // Ne pas appeler RtlDeleteElementGenericTableAvl ici car
                // il réutilise le compare routine avec des champs qu'on ne
                // connaît pas complètement → crash potentiel.
                // La suppression de List suffit pour tromper les énumérations.
                RemoveEntryList(&e->List);
                InitializeListHead(&e->List);
                break;
            }
            e = (PPiDDBCacheEntry)RtlEnumerateGenericTableAvl(pCache, FALSE);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }

    KeLowerIrql(irql);
}

// ---------------------------------------------------------------------------
// ErasePeHeaderPhys — effacement via adresse physique
//
// Contrairement à la version MDL (qui peut échouer sur les pages R/O),
// MmMapIoSpace mappe directement la page physique en lecture-écriture
// sans passer par les PTEs virtuelles de l'image.
// Résultat : pas de risque d'exception même sur une page .text protégée.
//
// DOIT être appelé EN DERNIER (après CleanPiDDBCache et FindSelfBase).
// ---------------------------------------------------------------------------
VOID ErasePeHeaderPhys(_In_ PVOID ImageBase)
{
    if (!ImageBase) return;

    PHYSICAL_ADDRESS phys = MmGetPhysicalAddress(ImageBase);
    if (!phys.QuadPart) return;

    PVOID mapped = MmMapIoSpace(phys, PAGE_SIZE, MmNonCached);
    if (!mapped) return;

    RtlSecureZeroMemory(mapped, PAGE_SIZE);
    MmUnmapIoSpace(mapped, PAGE_SIZE);
}
