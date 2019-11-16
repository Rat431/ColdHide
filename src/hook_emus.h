/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include "Defs.h"
#include <Winternl.h>
#include <tlhelp32.h>

// Define original functions
typedef NTSTATUS(NTAPI* __NtQueryInformationProcess__)(IN HANDLE, IN PROCESSINFOCLASS, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(NTAPI* __NtSetInformationThread__)(IN HANDLE, IN THREADINFOCLASS, IN PVOID, IN ULONG);
typedef NTSTATUS(NTAPI* __NtQuerySystemInformation__)(IN SYSTEM_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(NTAPI* __NtClose__)(IN HANDLE);
typedef NTSTATUS(NTAPI* __NtQueryObject__)(IN HANDLE, IN OBJECT_INFORMATION_CLASS, OUT PVOID, IN ULONG, OUT PULONG);
typedef NTSTATUS(NTAPI* __NtGetContextThread__)(IN HANDLE, OUT PCONTEXT);
typedef NTSTATUS(NTAPI* __NtSetContextThread__)(IN HANDLE, IN PCONTEXT);
typedef NTSTATUS(NTAPI* __NtContinue__)(IN PCONTEXT, IN BOOLEAN);
typedef NTSTATUS(NTAPI* __NtCreateThreadEx__)(OUT PHANDLE, IN ACCESS_MASK, IN OUT POBJECT_ATTRIBUTES, IN HANDLE,
	IN PVOID,
	IN OUT PVOID,
	IN ULONG,
	IN OUT ULONG_PTR,
	IN OUT SIZE_T,
	IN OUT SIZE_T,
	IN OUT PPS_ATTRIBUTE_LIST
);
typedef NTSTATUS(NTAPI* __NtSetInformationProcess__)(IN HANDLE, IN PROCESS_INFORMATION_CLASS, IN PVOID, IN ULONG);
typedef NTSTATUS(NTAPI* __NtYieldExecution__)();
typedef NTSTATUS(NTAPI* __NtSetDebugFilterState__)(IN ULONG, IN ULONG, IN BOOLEAN);
typedef VOID(NTAPI* __KiUserExceptionDispatcher__)(IN PEXCEPTION_RECORD, IN PCONTEXT);

typedef BOOL(WINAPI* __Process32First__)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* __Process32Next__)(HANDLE, LPPROCESSENTRY32);

namespace Hook_emu
{
	void InitHookFunctionsVars();

	extern "C"
	{
		_declspec(dllexport) NTSTATUS NTAPI __NtQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG  ProcessInformationLength,
			OUT PULONG ReturnLength);
		_declspec(dllexport) NTSTATUS NTAPI __NtSetInformationThread(
			IN HANDLE          ThreadHandle,
			IN THREADINFOCLASS ThreadInformationClass,
			IN PVOID           ThreadInformation,
			IN ULONG           ThreadInformationLength
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtQuerySystemInformation(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID                   SystemInformation,
			IN ULONG                    SystemInformationLength,
			OUT PULONG                  ReturnLength
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtClose(
			IN HANDLE Handle
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtQueryObject(
			IN HANDLE                   Handle,
			IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
			OUT PVOID                    ObjectInformation,
			IN ULONG                    ObjectInformationLength,
			OUT PULONG                   ReturnLength
		);

		// DRx functions
		_declspec(dllexport) NTSTATUS NTAPI __NtGetContextThread(
			IN HANDLE               ThreadHandle,
			OUT PCONTEXT            pContext
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtSetContextThread(
			IN HANDLE               ThreadHandle,
			IN PCONTEXT            pContext
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtContinue(
			IN PCONTEXT ThreadContext, 
			IN BOOLEAN RaiseAlert
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtCreateThreadEx(
			_Out_ PHANDLE ThreadHandle,
			_In_ ACCESS_MASK DesiredAccess,
			_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
			_In_ HANDLE ProcessHandle,
			_In_ PVOID StartRoutine,
			_In_opt_ PVOID Argument,
			_In_ ULONG CreateFlags,
			_In_opt_ ULONG_PTR ZeroBits,
			_In_opt_ SIZE_T StackSize,
			_In_opt_ SIZE_T MaximumStackSize,
			_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtSetInformationProcess(
			IN HANDLE ProcessHandle,
			IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
			IN PVOID ProcessInformation,
			IN ULONG ProcessInformationLength
		);
		_declspec(dllexport) VOID NTAPI __KiUserExceptionDispatcher(
			IN PEXCEPTION_RECORD ExceptionRecord,
			IN PCONTEXT Context
		);
		VOID NTAPI __RKiUserExceptionDispatcher(
			IN PEXCEPTION_RECORD ExceptionRecord,
			IN PCONTEXT Context
		);
		_declspec(dllexport) NTSTATUS NTAPI __NtYieldExecution();
		_declspec(dllexport) NTSTATUS NTAPI __NtSetDebugFilterState(
			IN ULONG ComponentId,
			IN ULONG Level,
			IN BOOLEAN State
		);

		_declspec(dllexport) BOOL WINAPI __Process32FirstW(
			HANDLE hSnapshot, 
			LPPROCESSENTRY32 lppe
		);
		_declspec(dllexport) BOOL WINAPI __Process32NextW(
			HANDLE hSnapshot,
			LPPROCESSENTRY32 lppe
		);
	}
}