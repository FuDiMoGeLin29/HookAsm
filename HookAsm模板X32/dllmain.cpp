// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "framework.h"
#include "main.h"

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		Main::init_hook();
		HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Main::run, 0, 0, 0);
		if (hThread != NULL)
		{
			CloseHandle(hThread);
		}
		break;
	}
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		Main::dll_exit();
		break;
	}
	return TRUE;
}

