/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include <Windows.h>
#include <iostream>

typedef struct _MUNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} MUNICODE_STRING;
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	bool DebuggerEnabled;
	bool DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
typedef struct _OBJECT_TYPE_INFORMATION
{
	MUNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

struct _CCPROCESS_BASIC_INFORMATION
{
	int ExitStatus;
	void* PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
};

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

// Define some offsets
#define PEB_BeingDebuggedOffset 0x2
#ifdef _WIN64
#define NAKED
#define GetPebFunction() __readgsqword(0x60)
#define MAX_ADDRESS_SIZE 0x8
#define PEB_Offset 0x60
#define PEB_NtGlobalFlagOffset 0xBC
#define HeapPEB_Offset 0x30
#define HeapFlagsBaseWinHigher 0x70
#define HeapForceFlagsBaseWinHigher 0x74
#define HeapFlagsBaseWinLower 0x14
#define HeapForceFlagsBaseWinLower 0x18
#else
#define NAKED _declspec(naked)
#define GetPebFunction() __readfsdword(0x30)
#define MAX_ADDRESS_SIZE 0x4
#define PEB_Offset 0x30
#define PEB_NtGlobalFlagOffset 0x68
#define HeapPEB_Offset 0x18
#define HeapFlagsBaseWinHigher 0x40
#define HeapForceFlagsBaseWinHigher 0x44
#define HeapFlagsBaseWinLower 0xC
#define HeapForceFlagsBaseWinLower 0x10
#endif

// Thread flags
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L) 
#define STATUS_NO_YIELD_PERFORMED        ((NTSTATUS)0x40000024L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_PORT_NOT_SET              ((NTSTATUS)0xC0000353L)

extern char ColdHisdepath[MAX_PATH];