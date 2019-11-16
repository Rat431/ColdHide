/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#include "hook_emus.h"
#include "hooks.h"

// Vars
static ULONG BreakT = NULL;
static bool IsEnabledTracing = false;
static DWORD_PTR DebugFlags = 1;

static CONTEXT FakeContext[0x90000] = { 0 };
static CONTEXT BeckupHardwareBP[0x90000] = { 0 };
static bool KIUEDFlag[0x90000] = { 0 };

namespace Hook_emu
{
	void InitHookFunctionsVars()
	{
		for (size_t i = 0; i < 0x90000; i++)
		{
			std::memset(&FakeContext[i], 0, sizeof(CONTEXT));
			std::memset(&BeckupHardwareBP[i], 0, sizeof(CONTEXT));
		}
	}
	extern "C"
	{

		_declspec(dllexport) NTSTATUS NTAPI __NtQueryInformationProcess(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG  ProcessInformationLength,
			OUT PULONG ReturnLength)
		{
			NTSTATUS Return = STATUS_SUCCESS;

			// Call the restored function 
			__NtQueryInformationProcess__ Call = (__NtQueryInformationProcess__)Hooks_Informastion::Nt_QueryProcessP;
			Return = Call(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

			if (NT_SUCCESS(Return) && ProcessInformation > NULL)
			{
				if (ProcessInformationClass == 0x07) // Debug port
				{
					// Check if is the correct size
					if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
						*(DWORD_PTR*)ProcessInformation = 0;
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
				if (ProcessInformationClass == 0x1E) //  Debug object
				{
					// Check if is the correct size
					if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
						*(DWORD_PTR*)ProcessInformation = 0;
						return 0xC0000353; // STATUS_PORT_NOT_SET
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
				if (ProcessInformationClass == 0x1F) // Debug flags
				{
					// Check if is the correct size
					if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
						*(DWORD_PTR*)ProcessInformation = DebugFlags;
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
				if (ProcessInformationClass == 0x00) // Basic information
				{
					// Patch Parent PID
					_CCPROCESS_BASIC_INFORMATION* pb = (_CCPROCESS_BASIC_INFORMATION*)ProcessInformation;
					pb->InheritedFromUniqueProcessId = (HANDLE)Hooks_Informastion::FPPID;
				}
				if (ProcessInformationClass == 29) // ProcessBreakOnTermination
				{
					// Check if is the correct size
					if (ProcessInformationLength >= sizeof(ULONG)) {
						*(ULONG*)ProcessInformation = BreakT;
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
				if (ProcessInformationClass == 32)
				{
					if (IsEnabledTracing)
						return STATUS_SUCCESS;
					else
						return STATUS_INVALID_PARAMETER;
				}
			}
			return Return;
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtSetInformationThread(
			IN HANDLE          ThreadHandle,
			IN THREADINFOCLASS ThreadInformationClass,
			IN PVOID           ThreadInformation,
			IN ULONG           ThreadInformationLength
		)
		{
			// Ignore the call with ThreadHideFromDebugger flag
			if (ThreadInformationClass == 0x11 && ThreadInformation <= NULL && ThreadInformationLength <= NULL)
			{
				return STATUS_SUCCESS;
			}
			__NtSetInformationThread__ Call = (__NtSetInformationThread__)Hooks_Informastion::Nt_SetThreadInformationP;
			return Call(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtQuerySystemInformation(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID                   SystemInformation,
			IN ULONG                    SystemInformationLength,
			OUT PULONG                  ReturnLength
		)
		{
			NTSTATUS Return = STATUS_SUCCESS;

			__NtQuerySystemInformation__ Call = (__NtQuerySystemInformation__)Hooks_Informastion::Nt_QuerySystemP;
			Return = Call(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

			if (NT_SUCCESS(Return) && SystemInformation > NULL)
			{
				// Check if is requesting SystemKernelDebuggerInformation(0x23) flag
				if (SystemInformationClass == 0x23)
				{
					if (SystemInformationLength >= sizeof(_SYSTEM_KERNEL_DEBUGGER_INFORMATION)) {
						_SYSTEM_KERNEL_DEBUGGER_INFORMATION* skdi = (_SYSTEM_KERNEL_DEBUGGER_INFORMATION*)SystemInformation;
						skdi->DebuggerEnabled = false;
						skdi->DebuggerNotPresent = true;
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
			}
			return Return;
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtClose(
			IN HANDLE Handle
		)
		{
			BYTE BUFF[2] = { 0 };
			NTSTATUS Return = STATUS_SUCCESS;

			__NtClose__ CallClose = (__NtClose__)Hooks_Informastion::Nt_CloseP;
			__NtQueryObject__ CallQuery = (__NtQueryObject__)Hooks_Informastion::Nt_QueryObjectP;

			// Check if the handle is valid
			if ((Return = CallQuery(Handle, (OBJECT_INFORMATION_CLASS)0x4, BUFF, 0x2, NULL)) != STATUS_INVALID_HANDLE) {
				return CallClose(Handle);
			}
			return Return;
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtQueryObject(
			IN HANDLE                   Handle,
			IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
			OUT PVOID                    ObjectInformation,
			IN ULONG                    ObjectInformationLength,
			OUT PULONG                   ReturnLength
		)
		{

			NTSTATUS Return = STATUS_SUCCESS;
			__NtQueryObject__ Call = (__NtQueryObject__)Hooks_Informastion::Nt_QueryObjectP;
			Return = Call(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

			if (NT_SUCCESS(Return) && ObjectInformation > NULL)
			{
				if (ObjectInformationClass == 0x2)
				{
					// Check if is the correct size
					if (ObjectInformationLength >= sizeof(OBJECT_TYPE_INFORMATION)) {
						POBJECT_TYPE_INFORMATION object = (POBJECT_TYPE_INFORMATION)ObjectInformation;
						object->TotalNumberOfObjects = TRUE;
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
				if (ObjectInformationClass == 0x3)
				{
					// Check if is the correct size
					if (ObjectInformationLength >= sizeof(OBJECT_TYPE_INFORMATION)) {
						POBJECT_TYPE_INFORMATION object = (POBJECT_TYPE_INFORMATION)ObjectInformation;
						object->TotalNumberOfObjects = TRUE;
					}
					else
						return STATUS_INVALID_PARAMETER;
				}
			}
			return Return;
		}

		// DRx functions
		_declspec(dllexport) NTSTATUS NTAPI __NtGetContextThread(
			IN HANDLE               ThreadHandle,
			OUT PCONTEXT            pContext
		)
		{
			NTSTATUS Return = STATUS_SUCCESS;
			__NtGetContextThread__ Call = (__NtGetContextThread__)Hooks_Informastion::Nt_NtGetContextThreadP;

			if (pContext > NULL) {
				if (pContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
					size_t CurrOffset = Hooks_Manager::GetOffsetByThreadID(GetThreadId(ThreadHandle));

					// Now each Thread handle should have its own CONTEXT.
					pContext->Dr0 = FakeContext[CurrOffset].Dr0;
					pContext->Dr1 = FakeContext[CurrOffset].Dr1;
					pContext->Dr2 = FakeContext[CurrOffset].Dr2;
					pContext->Dr3 = FakeContext[CurrOffset].Dr3;
					pContext->Dr6 = FakeContext[CurrOffset].Dr6;
					pContext->Dr7 = FakeContext[CurrOffset].Dr7;

					// Clean the flag
					DWORD Flags = pContext->ContextFlags;
					pContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;

					// If the flag different means there's other requested.
					if (Flags != pContext->ContextFlags) {
						if (Flags) {
							Return = Call(ThreadHandle, pContext);

							// Once we got context infos without the CONTEXT_DEBUG_REGISTERS, we can restore the original flags to be safe.
							pContext->ContextFlags = Flags;
							return Return;
						}
					}
					return STATUS_SUCCESS;
				}
			}
			return Call(ThreadHandle, pContext);
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtSetContextThread(
			IN HANDLE               ThreadHandle,
			IN PCONTEXT            pContext
		)
		{
			NTSTATUS Return = STATUS_SUCCESS;
			__NtSetContextThread__ Call = (__NtSetContextThread__)Hooks_Informastion::Nt_NtSetContextThreadP;

			if (pContext > NULL) {
				if (pContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
					if (Hooks_Config::FakeContextEmulation) {
						size_t CurrOffset = Hooks_Manager::GetOffsetByThreadID(GetThreadId(ThreadHandle));

						// Now each Thread handle should have its own CONTEXT.
						FakeContext[CurrOffset].Dr0 = pContext->Dr0;
						FakeContext[CurrOffset].Dr1 = pContext->Dr1;
						FakeContext[CurrOffset].Dr2 = pContext->Dr2;
						FakeContext[CurrOffset].Dr3 = pContext->Dr3;
						FakeContext[CurrOffset].Dr6 = pContext->Dr6;
						FakeContext[CurrOffset].Dr7 = pContext->Dr7;
					}

					// Clean the flag
					DWORD Flags = pContext->ContextFlags;
					pContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;

					// If the flag different means there's other requested.
					if (Flags != pContext->ContextFlags) {
						if (Flags) {
							Return = Call(ThreadHandle, pContext);

							// Once we got context infos without the CONTEXT_DEBUG_REGISTERS, we can restore the original flags to be safe.
							pContext->ContextFlags = Flags;
							return Return;
						}
					}
					return STATUS_SUCCESS;
				}
			}
			return Call(ThreadHandle, pContext);
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtContinue(
			IN PCONTEXT ThreadContext,
			IN BOOLEAN RaiseAlert
		)
		{
			__NtContinue__ Call = (__NtContinue__)Hooks_Informastion::Nt_ContinueP;
			if (ThreadContext > NULL) {
				size_t CurrOffset = Hooks_Manager::GetOffsetByThreadID(GetCurrentThreadId());

				// Now each Thread handle should have its own CONTEXT.
				if (KIUEDFlag[CurrOffset]) {
					ThreadContext->Dr0 = BeckupHardwareBP[CurrOffset].Dr0;
					ThreadContext->Dr1 = BeckupHardwareBP[CurrOffset].Dr1;
					ThreadContext->Dr2 = BeckupHardwareBP[CurrOffset].Dr2;
					ThreadContext->Dr3 = BeckupHardwareBP[CurrOffset].Dr3;
					ThreadContext->Dr6 = BeckupHardwareBP[CurrOffset].Dr6;
					ThreadContext->Dr7 = BeckupHardwareBP[CurrOffset].Dr7;

					KIUEDFlag[CurrOffset] = false;
				}
			}
			return Call(ThreadContext, RaiseAlert);
		}
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
		)
		{
			__NtCreateThreadEx__ Call = (__NtCreateThreadEx__)Hooks_Informastion::Nt_CreateThreadExP;
			ULONG Flags = CreateFlags;

			if (Flags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) {
				Flags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
			}
			return Call(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, Flags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtSetInformationProcess(
			IN HANDLE ProcessHandle,
			IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
			IN PVOID ProcessInformation,
			IN ULONG ProcessInformationLength
		)
		{
			__NtSetInformationProcess__ Call = (__NtSetInformationProcess__)Hooks_Informastion::Nt_SetInformationProcessP;

			if (ProcessInformationClass == 32)
			{
				IsEnabledTracing = true;
				return NULL;
			}
			if (ProcessInformationClass == 0x1F) // Debug flags
			{
				// Check if is the correct size
				if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
					DebugFlags = *(DWORD_PTR*)ProcessInformation;
				}
				else
					return STATUS_INVALID_PARAMETER;
			}
			return Call(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
		}
		_declspec(dllexport) VOID NTAPI __KiUserExceptionDispatcher(
			IN PEXCEPTION_RECORD ExceptionRecord,
			IN PCONTEXT Context
		)
		{
			if (Context > NULL) {
				if (Context->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
					size_t CurrOffset = Hooks_Manager::GetOffsetByThreadID(GetCurrentThreadId());

					// Now each Thread handle should have its own CONTEXT.
					BeckupHardwareBP[CurrOffset].Dr0 = Context->Dr0;
					BeckupHardwareBP[CurrOffset].Dr1 = Context->Dr1;
					BeckupHardwareBP[CurrOffset].Dr2 = Context->Dr2;
					BeckupHardwareBP[CurrOffset].Dr3 = Context->Dr3;
					BeckupHardwareBP[CurrOffset].Dr6 = Context->Dr6;
					BeckupHardwareBP[CurrOffset].Dr7 = Context->Dr7;

					Context->Dr0 = FakeContext[CurrOffset].Dr0;
					Context->Dr1 = FakeContext[CurrOffset].Dr1;
					Context->Dr2 = FakeContext[CurrOffset].Dr2;
					Context->Dr3 = FakeContext[CurrOffset].Dr3;
					Context->Dr6 = FakeContext[CurrOffset].Dr6;
					Context->Dr7 = FakeContext[CurrOffset].Dr7;

					KIUEDFlag[CurrOffset] = true;
				}
			}
		}
		NAKED VOID NTAPI __RKiUserExceptionDispatcher(
			IN PEXCEPTION_RECORD ExceptionRecord,
			IN PCONTEXT Context
		)
		{
			// We'll write bytes manually for x64.
#ifndef _WIN64
			_asm
			{
				push dword ptr[esp + 4]
				push dword ptr[esp + 4]
				call __KiUserExceptionDispatcher
				jmp Hooks_Informastion::Nt_ExceptionDispatcherP
			}
#endif
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtYieldExecution()
		{
			return 0x40000024; // STATUS_NO_YIELD_PERFORMED
		}
		_declspec(dllexport) NTSTATUS NTAPI __NtSetDebugFilterState(
			IN ULONG ComponentId,
			IN ULONG Level,
			IN BOOLEAN State
		)
		{
			return 0xC0000022; // STATUS_ACCESS_DENIED
		}

		_declspec(dllexport) BOOL WINAPI __Process32FirstW(
			HANDLE hSnapshot,
			LPPROCESSENTRY32 lppe
		)
		{
			BOOL Return = NULL;
			__Process32First__ Call = (__Process32First__)Hooks_Informastion::Kernel32_Process32FirstWP;
			Return = Call(hSnapshot, lppe);

			// Here we patch again the parent PID
			if (Return)
			{
				if (lppe->th32ProcessID == Hooks_Informastion::CurrentProcessID) {
					lppe->th32ParentProcessID = Hooks_Informastion::FPPID;
				}
			}
			return Return;
		}
		_declspec(dllexport) BOOL WINAPI __Process32NextW(
			HANDLE hSnapshot,
			LPPROCESSENTRY32 lppe
		)
		{
			BOOL Return = NULL;
			__Process32Next__ Call = (__Process32Next__)Hooks_Informastion::Kernel32_Process32NextWP;
			Return = Call(hSnapshot, lppe);

			// Here we patch again the parent PID
			if (Return)
			{
				if (lppe->th32ProcessID == Hooks_Informastion::CurrentProcessID) {
					lppe->th32ParentProcessID = Hooks_Informastion::FPPID;
				}
			}
			return Return;
		}
	}
}