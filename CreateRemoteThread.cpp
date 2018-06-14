#include <stdio.h>  
#include <windows.h>  
#include <tlhelp32.h>  

DWORD dwProcessID = 0;
HANDLE hProcessHandle = NULL;
LPVOID pAddrStart = NULL;
HANDLE hThreadHandle = NULL;

int dll_inject(DWORD dwProcessID, const char *pDllName)
{
	BOOL bSuccess = FALSE;
	hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hProcessHandle == NULL)
	{
		printf("OpenProcess error\n");
		return -1;
	}
	pAddrStart = VirtualAllocEx(hProcessHandle, 0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pAddrStart == NULL)
	{
		printf("VirtualAllocEx error\n");
		return -1;
	}
	bSuccess = WriteProcessMemory(hProcessHandle, pAddrStart, pDllName, 1024, 0);
	if (!bSuccess)
	{
		printf("WriteProcessMemory error\n");
		return -1;
	}
	hThreadHandle = CreateRemoteThread(hProcessHandle,
		0,
		0,
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"),
		pAddrStart,
		0,
		0);
	if (hThreadHandle == NULL)
	{
		printf("CreateRemoteThread error");
		return -1;
	}
	WaitForSingleObject(hThreadHandle, INFINITE);

	VirtualFreeEx(hProcessHandle, pAddrStart, 0, MEM_RELEASE);
	CloseHandle(hThreadHandle);
	CloseHandle(hProcessHandle);
	return 0;
}

int dll_free(DWORD dwProcessID, const char *pDllName)
{
	BOOL bMore = FALSE, bFound = FALSE;
	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };
	LPTHREAD_START_ROUTINE pThreadProc;
	BOOL bSuccess = FALSE;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessID);
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me)) {
		if (!_tcsicmp((LPCTSTR)me.szModule, pDllName) ||
			!_tcsicmp((LPCTSTR)me.szExePath, pDllName)) {
			bFound = TRUE;
			break;
		}
	}
	if (!bFound) {
		CloseHandle(hSnapshot);
		return FALSE;
	}

	hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
	if (hProcessHandle == NULL)
	{
		printf("OpenProcess error\n");
		return -1;
	}

	hThreadHandle = CreateRemoteThread(hProcessHandle,
		0,
		0,
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(GetModuleHandle("kernel32.dll"), "FreeLibrary"),
		me.modBaseAddr,
		0,
		0);
	WaitForSingleObject(hThreadHandle, INFINITE);
	VirtualFreeEx(hProcessHandle, pAddrStart, 0, MEM_RELEASE);
	CloseHandle(hThreadHandle);
	CloseHandle(hProcessHandle);
	return 0;
}
BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
  
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{ 
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}

int main()
{
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	DWORD pid = 788;
//		dll_inject(pid, "c:\\test\\calc_x64.dll"); 
//		dll_free(pid, "c:\\test\\calc_x64.dll");
	dll_inject(pid, "c:\\test\\Win32Project3.dll");
	dll_free(pid, "c:\\test\\Win32Project3.dll");
	return 0;
}
