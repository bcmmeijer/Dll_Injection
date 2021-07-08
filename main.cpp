#include <windows.h>
#include <tlhelp32.h>

DWORD get_pid(const char* process) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

#ifdef _UNICODE
#undef PROCESSENTRY32
#undef Process32First
#undef Process32Next
#endif

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(pe);

	if (!Process32First(snapshot, &pe)) {
		CloseHandle(snapshot);
		return 0;
	}

	DWORD pid = 0;
	do {
		if (!strcmp(pe.szExeFile, process)) {
			pid = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(snapshot, &pe));

	CloseHandle(snapshot);
	return pid;
}

int main(int argc, char** argv) {

	if (argc < 3) return 1;

	const char* process = argv[1];
	const char* dllpath = argv[2];

	DWORD pid = get_pid(process);
	if (!pid) return 1;

	size_t dllpathlen = strlen(dllpath) + 1;

	HANDLE hproc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, false, pid);
	if (hproc == INVALID_HANDLE_VALUE)
		return 1;

	void* remote_buf = VirtualAllocEx(hproc, nullptr, dllpathlen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!remote_buf) {
		CloseHandle(hproc);
		return 1;
	}

	if (!WriteProcessMemory(hproc, remote_buf, dllpath, dllpathlen, nullptr)) {
		VirtualFreeEx(hproc, remote_buf, 0, MEM_RELEASE | MEM_FREE);
		CloseHandle(hproc);
		return 1;
	}

	HANDLE hthread = CreateRemoteThread(hproc, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remote_buf, 0, nullptr);
	if (!hthread) {
		VirtualFreeEx(hproc, remote_buf, 0, MEM_RELEASE | MEM_FREE);
		CloseHandle(hproc);
		return 1;
	}

	CloseHandle(hproc);
	return 0;
}
