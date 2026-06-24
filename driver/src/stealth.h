#pragma once
#include "driver.h"

typedef struct _PiDDBCacheEntry {
    LIST_ENTRY     List;
    ULONG          TimeDateStamp;
    ULONG          SizeOfImage;
    UNICODE_STRING DriverName;
    NTSTATUS       LoadStatus;
} PiDDBCacheEntry, *PPiDDBCacheEntry;

// ---------------------------------------------------------------------------
// Structures VAD (Virtual Address Descriptors)
// ---------------------------------------------------------------------------

typedef struct _RTL_BALANCED_NODE {
    struct _RTL_BALANCED_NODE *Left;
    struct _RTL_BALANCED_NODE *Right;
    ULONG_PTR                  ParentValue;  // bits 0-1 = balance, reste = ptr parent
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

typedef struct _RTL_AVL_TREE {
    PRTL_BALANCED_NODE Root;
} RTL_AVL_TREE, *PRTL_AVL_TREE;

// MMVAD_SHORT — layout x64 stable depuis build 19041 jusqu'à 26100
typedef struct _MMVAD_SHORT {
    RTL_BALANCED_NODE VadNode;          // 0x00
    ULONG             StartingVpn;      // 0x18
    ULONG             EndingVpn;        // 0x1C
    ULONG             StartingVpnHigh;  // 0x20
    ULONG             EndingVpnHigh;    // 0x24
    ULONG_PTR         u1;               // 0x28
    ULONG_PTR         u2;               // 0x30
    ULONG_PTR         u3;               // 0x38
    ULONG64           VadFlags;         // 0x40
} MMVAD_SHORT, *PMMVAD_SHORT;

#define VAD_PRIVATE_MEMORY_BIT  51ULL   // bit 51 de VadFlags
#define VAD_TYPE_SHIFT          54ULL   // bits 54-56
#define VAD_TYPE_IMAGE_MAP      2ULL    // VadImageMap

PVOID GetNtoskrnlBase(VOID);
VOID  CleanHashLinks(_Inout_ PLDR_DATA_TABLE_ENTRY entry);
VOID  ZeroLdrFields(_Inout_ PLDR_DATA_TABLE_ENTRY entry);
VOID  ZeroImportTable(_In_ PVOID ImageBase);
VOID  CleanPiDDBCache(_In_ PVOID ImageBase);
VOID  CleanRegistryEntry(_In_ PUNICODE_STRING RegistryPath);
VOID  HideVadRegion(_In_ PVOID ImageBase);
VOID  ErasePeHeaderPhys(_In_ PVOID ImageBase);
