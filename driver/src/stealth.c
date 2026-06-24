#include "stealth.h"

// ---------------------------------------------------------------------------
// GetNtoskrnlBase
// Premier élément de PsLoadedModuleList = ntoskrnl.exe
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
// CleanHashLinks
// Retire de la hash-table LDR noyau (lookup par nom de module)
// ---------------------------------------------------------------------------
VOID CleanHashLinks(_Inout_ PLDR_DATA_TABLE_ENTRY entry)
{
    if (!entry || IsListEmpty(&entry->HashLinks)) return;
    RemoveEntryList(&entry->HashLinks);
    InitializeListHead(&entry->HashLinks);
}

// ---------------------------------------------------------------------------
// ZeroLdrFields
// Zeroise les champs identifiants de la LDR_DATA_TABLE_ENTRY après déliage
// ---------------------------------------------------------------------------
VOID ZeroLdrFields(_Inout_ PLDR_DATA_TABLE_ENTRY entry)
{
    if (!entry) return;
    entry->DllBase        = NULL;
    entry->EntryPoint     = NULL;
    entry->SizeOfImage    = 0;
    entry->CheckSum       = 0;
    entry->TimeDateStamp  = 0;
    entry->Flags          = 0;
    entry->LoadCount      = 0;
    entry->SectionPointer = NULL;
}

// ---------------------------------------------------------------------------
// PhysZeroRange — helper : zeroise une plage virtuelle via adresse physique
//
// Compatible Intel et AMD :
//   - MmCached (WB) évite le conflit MTRR avec le mapping WB original
//   - KeMemoryBarrier() garantit la cohérence sur les multi-CCD AMD Zen
//   - fallback MmNonCached si MmCached échoue (IOMMU strict)
// ---------------------------------------------------------------------------
static VOID PhysZeroRange(_In_ ULONG_PTR va, _In_ ULONG size)
{
    ULONG_PTR pageStart = va & ~(PAGE_SIZE - 1ULL);
    ULONG_PTR pageEnd   = (va + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1ULL);

    for (ULONG_PTR page = pageStart; page < pageEnd; page += PAGE_SIZE) {
        PHYSICAL_ADDRESS phys = MmGetPhysicalAddress((PVOID)page);
        if (!phys.QuadPart) continue;

        PVOID mapped = MmMapIoSpace(phys, PAGE_SIZE, MmCached);
        if (!mapped) mapped = MmMapIoSpace(phys, PAGE_SIZE, MmNonCached);
        if (!mapped) continue;

        ULONG_PTR zeroOff = (page >= va) ? 0 : (va - page);
        ULONG_PTR zeroEnd = (ULONG_PTR)(page + PAGE_SIZE) > (va + size)
                             ? (va + size - page) : PAGE_SIZE;
        if (zeroEnd > zeroOff)
            RtlSecureZeroMemory((PUCHAR)mapped + zeroOff, zeroEnd - zeroOff);

        MmUnmapIoSpace(mapped, PAGE_SIZE);
    }
    // Barrière cohérence mémoire — critique sur AMD multi-CCD (Zen2/Zen3)
    KeMemoryBarrier();
}

// ---------------------------------------------------------------------------
// ZeroImportTable
//
// Zeroise les descripteurs d'import (IMAGE_IMPORT_DESCRIPTOR + hint-name table)
// via adresse physique. L'IAT (pointeurs de fonctions résolus) est préservée
// car le driver en a besoin pour s'exécuter.
//
// Intérêt : un scanner qui identifie le driver par ses imports
// (MmGetSystemRoutineAddress, RemoveEntryList, etc.) ne trouve plus rien.
//
// DOIT être appelé AVANT ErasePeHeaderPhys (on lit DataDirectory ici).
// ---------------------------------------------------------------------------
VOID ZeroImportTable(_In_ PVOID ImageBase)
{
    if (!ImageBase) return;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        // Import descriptors
        PIMAGE_DATA_DIRECTORY impDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (impDir->VirtualAddress && impDir->Size)
            PhysZeroRange((ULONG_PTR)ImageBase + impDir->VirtualAddress, impDir->Size);

        // Bound import directory (metadata supplémentaire d'imports)
        PIMAGE_DATA_DIRECTORY bndDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
        if (bndDir->VirtualAddress && bndDir->Size)
            PhysZeroRange((ULONG_PTR)ImageBase + bndDir->VirtualAddress, bndDir->Size);

        // Export directory (rare pour un driver, mais on couvre)
        PIMAGE_DATA_DIRECTORY expDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (expDir->VirtualAddress && expDir->Size)
            PhysZeroRange((ULONG_PTR)ImageBase + expDir->VirtualAddress, expDir->Size);

    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// ---------------------------------------------------------------------------
// ValidPiDDBTable — validation d'un candidat RTL_AVL_TABLE
//
// Un vrai PiDDBCacheTable a ses routines (Compare/Allocate/Free) dans
// la plage .text de ntoskrnl, et un nombre d'éléments non nul et raisonnable.
// Cette validation évite les faux positifs et les crashs sur tout CPU.
// ---------------------------------------------------------------------------
static BOOLEAN ValidPiDDBTable(_In_ PRTL_AVL_TABLE t,
                                _In_ ULONG_PTR ntStart,
                                _In_ ULONG_PTR ntEnd)
{
    __try {
        ULONG_PTR cmp   = (ULONG_PTR)t->CompareRoutine;
        ULONG_PTR alloc = (ULONG_PTR)t->AllocateRoutine;
        ULONG_PTR free_ = (ULONG_PTR)t->FreeRoutine;

        if (cmp   < ntStart || cmp   >= ntEnd) return FALSE;
        if (alloc < ntStart || alloc >= ntEnd) return FALSE;
        if (free_ < ntStart || free_ >= ntEnd) return FALSE;

        ULONG n = t->NumberGenericTableElements;
        return (n > 0 && n < 0x4000);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return FALSE; }
}

// ---------------------------------------------------------------------------
// CleanPiDDBCache
//
// Approche universelle Intel + AMD, tous builds Windows 10/11 :
//
// On ne cherche PAS un pattern d'octets spécifique à une version.
// On scanne TOUTES les occurrences de "4C 8D 05 xx xx xx xx"
// (LEA R8, [rip+offset]) dans ntoskrnl.exe, car PiDDBCacheTable est
// systématiquement passé en R8 (3ème argument) aux fonctions AVL.
// Cette convention d'appel (x64 ABI) est indépendante du CPU.
//
// Pour chaque candidat, ValidPiDDBTable() vérifie la cohérence de la
// structure RTL_AVL_TABLE avant d'agir → pas de crash sur faux positif.
//
// DOIT être appelé AVANT ErasePeHeaderPhys et ZeroImportTable.
// ---------------------------------------------------------------------------
VOID CleanPiDDBCache(_In_ PVOID ImageBase)
{
    if (!ImageBase) return;

    __try {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ImageBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        ULONG ts = nt->FileHeader.TimeDateStamp;
        if (ts == 0) return;

        PVOID ntBase = GetNtoskrnlBase();
        if (!ntBase) return;

        PIMAGE_NT_HEADERS ntNt =
            (PIMAGE_NT_HEADERS)((ULONG_PTR)ntBase +
            ((PIMAGE_DOS_HEADER)ntBase)->e_lfanew);
        ULONG     ntSize  = ntNt->OptionalHeader.SizeOfImage;
        ULONG_PTR ntStart = (ULONG_PTR)ntBase;
        ULONG_PTR ntEnd   = ntStart + ntSize;

        PRTL_AVL_TABLE pCache = NULL;
        PUCHAR         scan   = (PUCHAR)ntBase;

        for (ULONG i = 0; i + 7 < ntSize && !pCache; i++) {
            // LEA R8, [rip+offset]
            if (scan[i] != 0x4C || scan[i+1] != 0x8D || scan[i+2] != 0x05)
                continue;

            LONG      rel  = *(PLONG)(scan + i + 3);
            ULONG_PTR cand = (ULONG_PTR)(scan + i + 7) + rel;

            if (cand <= ntStart || cand >= ntEnd) continue;
            if (cand & 7) continue;

            if (ValidPiDDBTable((PRTL_AVL_TABLE)cand, ntStart, ntEnd))
                pCache = (PRTL_AVL_TABLE)cand;
        }

        if (!pCache) return;

        KIRQL irql;
        KeRaiseIrql(DISPATCH_LEVEL, &irql);
        __try {
            PPiDDBCacheEntry e =
                (PPiDDBCacheEntry)RtlEnumerateGenericTableAvl(pCache, TRUE);
            while (e) {
                if (e->TimeDateStamp == ts) {
                    RemoveEntryList(&e->List);
                    InitializeListHead(&e->List);
                    break;
                }
                e = (PPiDDBCacheEntry)RtlEnumerateGenericTableAvl(pCache, FALSE);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        KeLowerIrql(irql);

    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

// ---------------------------------------------------------------------------
// CleanRegistryEntry
//
// Supprime la clé de registre du service après chargement (mode sc uniquement).
// Le driver est déjà en mémoire quand DriverEntry est appelé — la clé est
// inutile et constitue une trace visible dans le registre.
// Après suppression : sc stop et sc delete échoueront (clé introuvable),
// ce qui empêche également la désinstallation par un adversaire.
// ---------------------------------------------------------------------------
VOID CleanRegistryEntry(_In_ PUNICODE_STRING RegistryPath)
{
    if (!RegistryPath || !RegistryPath->Buffer || !RegistryPath->Length) return;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    HANDLE hKey = NULL;
    if (!NT_SUCCESS(ZwOpenKey(&hKey, DELETE, &oa))) return;
    ZwDeleteKey(hKey);
    ZwClose(hKey);
}

// ---------------------------------------------------------------------------
// ErasePeHeaderPhys
//
// Efface la première page (PE header) via adresse physique.
//
// Intel vs AMD :
//   - MmNonCached (UC) sur une page WB → conflit MTRR sur AMD Zen
//     (AMD APM vol.2 sec. "MTRR Aliasing" — downgrade UC sur Intel,
//      comportement indéfini ou #GP sur AMD)
//   - Correction : MmCached (WB) = même type que le mapping original
//   - KeMemoryBarrier() après write = cohérence L3 inter-CCD (Zen2/Zen3)
//
// DOIT être appelé EN DERNIER.
// ---------------------------------------------------------------------------
VOID ErasePeHeaderPhys(_In_ PVOID ImageBase)
{
    if (!ImageBase) return;
    PhysZeroRange((ULONG_PTR)ImageBase, PAGE_SIZE);
}

// ---------------------------------------------------------------------------
// HideVadRegion — couche 6 : camouflage dans EPROCESS.VadRoot
//
// Même avec le PE header effacé et la LDR nettoyée, la région mémoire du
// driver reste visible comme allocation privée exécutable anonyme dans
// l'arbre VAD du processus System — c'est ce que cherche EAC (F2).
//
// Stratégie : modifier les VadFlags du nœud MMVAD_SHORT trouvé :
//   - effacer PrivateMemory (bit 51) → plus une allocation privée
//   - changer VadType (bits 54-56) de VadNone(0) à VadImageMap(2)
//     → ressemble à un mapping de section légitime
//
// On ne supprime PAS le nœud (la rééquilibration AVL n'est pas exportée).
// La modification des flags n'affecte pas les PTEs réels → exécution OK.
//
// Table d'offsets EPROCESS.VadRoot (RTL_AVL_TREE) par build Windows x64 :
//   17763(1809)=0x628  18362/18363(1903/1909)=0x658  19041+(2004/Win11)=0x7D8
// ---------------------------------------------------------------------------

typedef struct { ULONG Build; ULONG Offset; } VAD_OFFSET_ENTRY;

static const VAD_OFFSET_ENTRY g_VadOffsets[] = {
    { 17763, 0x628 },   // Win10 1809
    { 18362, 0x658 },   // Win10 1903
    { 18363, 0x658 },   // Win10 1909
    { 19041, 0x7D8 },   // Win10 2004
    { 19042, 0x7D8 },   // Win10 20H2
    { 19043, 0x7D8 },   // Win10 21H1
    { 19044, 0x7D8 },   // Win10 21H2
    { 19045, 0x7D8 },   // Win10 22H2
    { 22000, 0x7D8 },   // Win11 21H2
    { 22621, 0x7D8 },   // Win11 22H2
    { 22631, 0x7D8 },   // Win11 23H2
    { 26100, 0x7D8 },   // Win11 24H2
};

VOID HideVadRegion(_In_ PVOID ImageBase)
{
    if (!ImageBase) return;

    // PsInitialSystemProcess via export table (pas d'extern, pas de dépendance statique)
    UNICODE_STRING symName = RTL_CONSTANT_STRING(L"PsInitialSystemProcess");
    PEPROCESS *pSys = (PEPROCESS *)MmGetSystemRoutineAddress(&symName);
    if (!pSys || !*pSys) return;
    PEPROCESS eproc = *pSys;

    // Offset VadRoot selon build
    RTL_OSVERSIONINFOW osv = { sizeof(osv) };
    if (!NT_SUCCESS(RtlGetVersion(&osv))) return;

    ULONG vadOff = 0;
    for (ULONG i = 0; i < ARRAYSIZE(g_VadOffsets); i++) {
        if (g_VadOffsets[i].Build == osv.dwBuildNumber) {
            vadOff = g_VadOffsets[i].Offset;
            break;
        }
    }
    if (!vadOff) {
        if (osv.dwBuildNumber >= 19041) vadOff = 0x7D8;
        else return;
    }

    PRTL_AVL_TREE  vadRoot = (PRTL_AVL_TREE)((PUCHAR)eproc + vadOff);
    ULONG_PTR      ourVpn  = (ULONG_PTR)ImageBase >> PAGE_SHIFT;

    __try {
        PRTL_BALANCED_NODE node = vadRoot->Root;
        while (node) {
            PMMVAD_SHORT vad = (PMMVAD_SHORT)node;
            ULONG_PTR startVpn = ((ULONG64)vad->StartingVpnHigh << 32) | vad->StartingVpn;
            ULONG_PTR endVpn   = ((ULONG64)vad->EndingVpnHigh   << 32) | vad->EndingVpn;

            if (ourVpn >= startVpn && ourVpn <= endVpn) {
                // Nœud trouvé — pool noyau writable directement
                volatile ULONG64 *pFlags =
                    (volatile ULONG64 *)((PUCHAR)vad + FIELD_OFFSET(MMVAD_SHORT, VadFlags));
                ULONG64 flags = *pFlags;
                flags &= ~(1ULL   << VAD_PRIVATE_MEMORY_BIT);
                flags &= ~(0x7ULL << VAD_TYPE_SHIFT);
                flags |=  (VAD_TYPE_IMAGE_MAP << VAD_TYPE_SHIFT);
                *pFlags = flags;
                KeMemoryBarrier();
                break;
            }
            node = (ourVpn < startVpn) ? node->Left : node->Right;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}
