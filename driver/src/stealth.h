#pragma once
#include "driver.h"

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
VOID  ZeroImportTable(_In_ PVOID ImageBase);
VOID  CleanPiDDBCache(_In_ PVOID ImageBase);
VOID  CleanRegistryEntry(_In_ PUNICODE_STRING RegistryPath);
VOID  ErasePeHeaderPhys(_In_ PVOID ImageBase);
