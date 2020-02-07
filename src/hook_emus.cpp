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
	static bool Cleaned = false;
	void InitHookFunctionsVars()
	{
		if (!Cleaned)
		{
			for (size_t i = 0; i < 0x90000; i++)
			{
				std::memset(&FakeContext[i], 0, sizeof(CONTEXT));
				std::memset(&BeckupHardwareBP[i], 0, sizeof(CONTEXT));
			}
			Cleaned = true;
		}
	}
	
	// proxied functions 
	NTSTATUS NTAPI __NtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG  ProcessInformationLength, PULONG ReturnLength)
	{
		NTSTATUS Return = STATUS_SUCCESS;

		// Call the restored function 
		__NtQueryInformationProcess__ ___NtQueryInformationProcess__ = (__NtQueryInformationProcess__)Hooks_Informastion::Nt_QueryProcessP;
		Return = ___NtQueryInformationProcess__(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

		if (NT_SUCCESS(Return))
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
			else if (ProcessInformationClass == 0x1E) //  Debug object
			{
				// Check if is the correct size
				if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
					*(DWORD_PTR*)ProcessInformation = 0;
					return STATUS_PORT_NOT_SET;
				}
				else
					return STATUS_INVALID_PARAMETER;
			}
			else if (ProcessInformationClass == 0x1F) // Debug flags
			{
				// Check if is the correct size
				if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
					*(DWORD_PTR*)ProcessInformation = DebugFlags;
				}
				else
					return STATUS_INVALID_PARAMETER;
			}
			else if (ProcessInformationClass == 0x00) // Basic information
			{
				// Patch Parent PID
				_CCPROCESS_BASIC_INFORMATION* pb = (_CCPROCESS_BASIC_INFORMATION*)ProcessInformation;
				pb->InheritedFromUniqueProcessId = (HANDLE)Hooks_Informastion::FPPID;
			}
			else if (ProcessInformationClass == 29) // ProcessBreakOnTermination
			{
				// Check if is the correct size
				if (ProcessInformationLength >= sizeof(ULONG)) {
					*(ULONG*)ProcessInformation = BreakT;
				}
				else
					return STATUS_INVALID_PARAMETER;
			}
			else if (ProcessInformationClass == 32)
			{
				if (IsEnabledTracing)
					return STATUS_SUCCESS;
				else
					return STATUS_INVALID_PARAMETER;
			}
		}
		return Return;
	}
	NTSTATUS NTAPI __NtSetInformationThread(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
	{
		// Ignore the call with ThreadHideFromDebugger flag
		__NtSetInformationThread__ ___NtSetInformationThread__ = (__NtSetInformationThread__)Hooks_Informastion::Nt_SetThreadInformationP;
		if (ThreadInformationClass == 0x11 && ThreadInformation <= NULL && ThreadInformationLength <= NULL)
		{
			return STATUS_SUCCESS;
		}
		return ___NtSetInformationThread__(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
	}
	NTSTATUS NTAPI __NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
	{
		NTSTATUS Return = STATUS_SUCCESS;

		__NtQuerySystemInformation__ ___NtQuerySystemInformation__ = (__NtQuerySystemInformation__)Hooks_Informastion::Nt_QuerySystemP;
		Return = ___NtQuerySystemInformation__(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

		if (NT_SUCCESS(Return))
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
	NTSTATUS NTAPI __NtClose(HANDLE Handle)
	{
		BYTE BUFF[2] = { 0 };
		NTSTATUS Return = STATUS_SUCCESS;

		__NtClose__ ___NtClose__ = (__NtClose__)Hooks_Informastion::Nt_CloseP;
		__NtQueryObject__ ___NtQueryObject__ = (__NtQueryObject__)Hooks_Informastion::Nt_QueryObjectP;

		// Check if the handle is valid
		if ((Return = ___NtQueryObject__(Handle, (OBJECT_INFORMATION_CLASS)0x4, BUFF, 0x2, NULL)) != STATUS_INVALID_HANDLE) {
			return ___NtClose__(Handle);
		}
		return Return;
	}
	NTSTATUS NTAPI __NtQueryObject(HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength)
	{
		NTSTATUS Return = STATUS_SUCCESS;
		__NtQueryObject__ ___NtQueryObject__ = (__NtQueryObject__)Hooks_Informastion::Nt_QueryObjectP;
		Return = ___NtQueryObject__(Handle, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);

		if (NT_SUCCESS(Return))
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
	NTSTATUS NTAPI __NtGetContextThread(HANDLE ThreadHandle, PCONTEXT pContext)
	{
		NTSTATUS Return = STATUS_SUCCESS;
		__NtGetContextThread__ ___NtGetContextThread__ = (__NtGetContextThread__)Hooks_Informastion::Nt_NtGetContextThreadP;

		if (pContext) {
			if (pContext->ContextFlags & CONTEXT_DEBUG_REGISTERS) {
				size_t CurrOffset = Hooks_Manager::GetOffsetByThreadID(GetThreadId(ThreadHandle));

				// Clean the flag
				DWORD Flags = pContext->ContextFlags;
				pContext->ContextFlags &= ~CONTEXT_DEBUG_REGISTERS;

				if (pContext->ContextFlags) {
					Return = ___NtGetContextThread__(ThreadHandle, pContext);

					// Now each Thread handle should have its own CONTEXT.
					pContext->Dr0 = FakeContext[CurrOffset].Dr0;
					pContext->Dr1 = FakeContext[CurrOffset].Dr1;
					pContext->Dr2 = FakeContext[CurrOffset].Dr2;
					pContext->Dr3 = FakeContext[CurrOffset].Dr3;
					pContext->Dr6 = FakeContext[CurrOffset].Dr6;
					pContext->Dr7 = FakeContext[CurrOffset].Dr7;

					// Once we got context infos without the CONTEXT_DEBUG_REGISTERS, we can restore the original flags to be safe.
					pContext->ContextFlags = Flags;
					return Return;
				}

				// Now each Thread handle should have its own CONTEXT.
				pContext->Dr0 = FakeContext[CurrOffset].Dr0;
				pContext->Dr1 = FakeContext[CurrOffset].Dr1;
				pContext->Dr2 = FakeContext[CurrOffset].Dr2;
				pContext->Dr3 = FakeContext[CurrOffset].Dr3;
				pContext->Dr6 = FakeContext[CurrOffset].Dr6;
				pContext->Dr7 = FakeContext[CurrOffset].Dr7;

				// Once we got context infos without the CONTEXT_DEBUG_REGISTERS, we can restore the original flags to be safe.
				pContext->ContextFlags = Flags;
				return STATUS_SUCCESS;
			}
		}
		return ___NtGetContextThread__(ThreadHandle, pContext);
	}
	NTSTATUS NTAPI __NtSetContextThread(HANDLE ThreadHandle, PCONTEXT pContext)
	{
		NTSTATUS Return = STATUS_SUCCESS;
		__NtSetContextThread__ ___NtSetContextThread__ = (__NtSetContextThread__)Hooks_Informastion::Nt_NtSetContextThreadP;

		if (pContext) {
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

				if (pContext->ContextFlags) {
					Return = ___NtSetContextThread__(ThreadHandle, pContext);

					// Once we got context infos without the CONTEXT_DEBUG_REGISTERS, we can restore the original flags to be safe.
					pContext->ContextFlags = Flags;
					return Return;
				}
				pContext->ContextFlags = Flags;
				return STATUS_SUCCESS;
			}
		}
		return ___NtSetContextThread__(ThreadHandle, pContext);
	}

	NTSTATUS NTAPI __NtContinue(PCONTEXT ThreadContext, BOOLEAN RaiseAlert)
	{
		__NtContinue__ ___NtContinue__ = (__NtContinue__)Hooks_Informastion::Nt_ContinueP;

		if (ThreadContext) {
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
		return ___NtContinue__(ThreadContext, RaiseAlert);
	}
	NTSTATUS NTAPI __NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
	{
		__NtCreateThreadEx__ ___NtCreateThreadEx__ = (__NtCreateThreadEx__)Hooks_Informastion::Nt_CreateThreadExP;
		ULONG Flags = CreateFlags;
		if (Flags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER) {
			Flags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
		}
		return ___NtCreateThreadEx__(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, Flags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	}
	NTSTATUS NTAPI __NtSetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
	{
		__NtSetInformationProcess__ ___NtSetInformationProcess__ = (__NtSetInformationProcess__)Hooks_Informastion::Nt_SetInformationProcessP;
		if (ProcessInformationClass == 32)
		{
			IsEnabledTracing = true;
			return STATUS_SUCCESS;
		}
		else if (ProcessInformationClass == 0x1F) // Debug flags
		{
			// Check if is the correct size
			if (ProcessInformationLength >= sizeof(DWORD_PTR)) {
				DebugFlags = *(DWORD_PTR*)ProcessInformation;
			}
			else
				return STATUS_INVALID_PARAMETER;
		}
		return ___NtSetInformationProcess__(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	}
	NTSTATUS NTAPI __NtYieldExecution()
	{
		return STATUS_NO_YIELD_PERFORMED;
	}
	NTSTATUS NTAPI __NtSetDebugFilterState(ULONG ComponentId, ULONG Level, BOOLEAN State)
	{
		return STATUS_ACCESS_DENIED;
	}

	VOID NTAPI __KiUserExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
	{
		if (Context) {
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
	NAKED VOID NTAPI __RKiUserExceptionDispatcher(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
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


	BOOL WINAPI __Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
	{
		BOOL Return;
		__Process32First__ ___Process32First__ = (__Process32First__)Hooks_Informastion::Kernel32_Process32FirstWP;
		Return = ___Process32First__(hSnapshot, lppe);

		// Here we patch again the parent PID
		if (Return)
		{
			if (lppe->th32ProcessID == Hooks_Informastion::CurrentProcessID) {
				lppe->th32ParentProcessID = Hooks_Informastion::FPPID;
			}
		}
		return Return;
	}
	BOOL WINAPI __Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
	{
		BOOL Return;
		__Process32Next__ ___Process32Next__ = (__Process32Next__)Hooks_Informastion::Kernel32_Process32NextWP;
		Return = ___Process32Next__(hSnapshot, lppe);

		// Here we patch again the parent PID
		if (Return)
		{
			if (lppe->th32ProcessID == Hooks_Informastion::CurrentProcessID) {
				lppe->th32ParentProcessID = Hooks_Informastion::FPPID;
			}
		}
		return Return;
	}
	DWORD WINAPI __GetTickCount()
	{
		return 1;	// Return static value
	}
	ULONGLONG WINAPI __GetTickCount64()
	{
		return 1;	// Return static value
	}
}