#pragma once
#include "driver.h"

// Structure de cache PiDDB (stable Windows 10 1903-22H2 x64)
// Indexée par TimeDateStamp dans une RTL_AVL_TABLE
typedef struct _PiDDBCacheEntry {
    LIST_ENTRY     List;
    ULONG          TimeDateStamp;
    ULONG          SizeOfImage;
    UNICODE_STRING DriverName;
    NTSTATUS       LoadStatus;
} PiDDBCacheEntry, *PPiDDBCacheEntry;

PVOID GetNtoskrnlBase(VOID);
VOID  CleanHashLinks(_Inout_ PLDR_DATA_TABLE_ENTRY entry);
VOID  ZeroLdrFields(_Inout_ PLDR_DATA_TABLE_ENTRY entry);
VOID  CleanPiDDBCache(_In_ PVOID ImageBase);
VOID  ErasePeHeaderPhys(_In_ PVOID ImageBase);
