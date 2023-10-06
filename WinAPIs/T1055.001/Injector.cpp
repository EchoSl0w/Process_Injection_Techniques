#include <Windows.h>
#include <stdio.h>

int Error(const char* msg) {
	printf("%s (%u)\n", msg, GetLastError);
	return 1;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("Usage Injector.exe <PID> <Path to DLL>");
		return 0;
	}

	int pid = atoi(argv[1]);

	printf("Obtaining handle to target process");
	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, 0, pid);
	if (hProcess == NULL) {
		return Error("Failed in obtaining handle to process");
	}
	printf("Allocating memory...\n");
	void* buffer = VirtualAllocEx(hProcess, NULL, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (buffer == NULL) {
		return Error("Failed in allocating memory");
	}
	printf("Writing memory...\n");
	if (!WriteProcessMemory(hProcess, buffer, argv[2], strlen(argv[2]), NULL)) {
		return Error("Failed in WriteProcessMemory");
	}
	printf("Creating remote thread...\n");
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA"),
		buffer, 0, NULL);
	if (!hThread)
		return Error("Failed to create thread");
	printf("SUCCESS!");

	return 0;

}