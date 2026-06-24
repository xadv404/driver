#pragma once
#include <ntddk.h>

// LDR_DATA_TABLE_ENTRY : structure noyau non exportée, stable depuis XP
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// MM_UNLOADED_DRIVER : historique des 50 derniers drivers déchargés
typedef struct _MM_UNLOADED_DRIVER {
    UNICODE_STRING  Name;
    PVOID           ModuleStart;
    PVOID           ModuleEnd;
    ULONG64         UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

#define MM_UNLOADED_DRIVERS_SIZE 50

VOID HideFromLoadedList(_In_ PDRIVER_OBJECT DriverObject);
VOID ObfuscateLdrEntry(_In_ PDRIVER_OBJECT DriverObject);
VOID CleanMmUnloadedDrivers(_In_ PDRIVER_OBJECT DriverObject);

VOID RestoreSelf(VOID);
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
