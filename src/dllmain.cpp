/*
	Copyright (c) 2019 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#include "pch.h"
#include "hooks.h"

char ColdHisdepath[MAX_PATH] = { 0 };

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		char myfile[MAX_PATH] = { 0 };
		GetModuleFileNameA(hModule, myfile, MAX_PATH);
		int size = lstrlenA(myfile);
		for (int i = size; i > 0; i--) {
			if (myfile[i] == '\\') {
				RtlFillMemory(&myfile[i + 1], size - i + 1, NULL);
				break;

			}
		}
		lstrcpyA(ColdHisdepath, myfile);
		Hooks_Manager::Init((ULONG_PTR)hModule);
	}
	if (ul_reason_for_call == DLL_PROCESS_DETACH)
	{
		Hooks_Manager::ShutDown();
	}
	return TRUE;
}

