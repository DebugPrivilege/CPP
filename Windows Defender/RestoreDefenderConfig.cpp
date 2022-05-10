// DISCLAIMER: This was coded up to get the job done, so no. I will not make any change to it anymore.
// Supported version: Windows Server 2016 +

// Description: RestoreDefenderConfig is primary meant for IR cases to perform tactical remediation. Think of cases where the threat actor starts tampering Defender, and you want to restore Defender AV.
// The thought process behind is this is the following: Threat actor disabled Windows Defender across the environment and we want to restore the settings to a healthy state.
// Deployment options: (Examples)
// 1. GPO -> Open Group Policy Management Console -> Create Scheduled Task -> Run as SYSTEM -> Specify the CLI option -> Link GPO to OU
// 2. Remote PowerShell -> Connect to remote machine -> Execute the binary with the specified CLI option
// 3. PsExec

#include <windows.h>
#include <DbgHelp.h>
#include <iostream>
#include <TlHelp32.h>
#include <WinReg.h>

VOID displayHelp()
{
	wprintf(L"Usage: RestoreDefenderConfig.exe <option> \n\n");
	wprintf(L"Options:\n");
	wprintf(L"--help\t\t\t\tDisplay command-line options\n");
	wprintf(L"--start\t\t\t\tRestore Windows Defender AV configuration in a healthy state\n");
	wprintf(L"--removeThreats\t\t\tRemoving active threats with High or Severe impact\n");
	wprintf(L"--removeAllThreats\t\tRemoving all active threats regardless the severity\n");
	wprintf(L"--removeAllExclusions\t\t\Removing all broad AV exclusions\n");
	wprintf(L"--removeAllExtensions\t\t\Removing broad extensions that have been excluded from AV\n");
	wprintf(L"--removeAllDirectories\t\t\Removing broad directories that have been excluded from AV\n");
	wprintf(L"--quickScan\t\t\tRun a quick Windows Defender AV scan\n");
	wprintf(L"--fullScan\t\t\tRun a full Windows Defender AV scan\n");
	wprintf(L"--listAll\t\t\tList all items that were quarantined by AV\n");
	wprintf(L"--getThreats\t\t\tGet active and past malware threats that Windows Defender detected\n");
	wprintf(L"--getFiles\t\t\tGet diagnostic data of Windows Defender\n");
	wprintf(L"--disableWDigest\t\tTurn off WDigest\n");

	exit(0);
}

BOOL IsElevatedProcess()
{
	BOOL is_elevated = FALSE;
	HANDLE token = NULL; // A pointer to a handle that identifies the new opened access token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &token)) // Open a handle to the access token for the calling process.
	{
		TOKEN_ELEVATION elevation; // Data structure indicating whether a token has elevated privileges
		DWORD TokenIsElevated = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &TokenIsElevated))
		{
			is_elevated = elevation.TokenIsElevated;
		}
	}
	if (token)
	{
		CloseHandle(token); // Close an object handle
	}
	return is_elevated;
}

VOID RemoveDisableAntiSpywareValue(wchar_t* user, wchar_t* host)
{
	HKEY hKey;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Policies\\Microsoft\\Windows Defender"), 0, KEY_SET_VALUE, &hKey);

	// Delete DisableAntispyware value
	LONG deleteValue = RegDeleteValueW(hKey, L"DisableAntiSpyware");

	if (deleteValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully removed the DisableAntiSpyware registry value" << std::endl;
	}
	else {
		std::cout << "[-] Error in removing the DisableAntiSpyware value. Registry value may not exist " << std::endl;
	}
}

VOID RemoveDisableAntiVirusValue(wchar_t* user, wchar_t* host)
{
	HKEY hKey;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Policies\\Microsoft\\Windows Defender"), 0, KEY_SET_VALUE, &hKey);

	// Delete DisableAntispyware value
	LONG deleteValue = RegDeleteValueW(hKey, L"DisableAntiVirus");

	if (deleteValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully removed the DisableAntiVirus registry value" << std::endl;
	}
	else {
		std::cout << "[-] Error in removing the DisableAntiVirus value. Registry value may not exist " << std::endl;
	}
}

VOID RemoveDisableRoutineActionKey(wchar_t* user, wchar_t* host)
{
	HKEY hKey;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Policies\\Microsoft\\Windows Defender"), 0, KEY_SET_VALUE, &hKey);

	// Delete DisableAntispyware value
	LONG deleteValue = RegDeleteValueW(hKey, L"DisableRoutinelyTakingAction");

	if (deleteValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully removed the DisableRoutinelyTakingAction registry value" << std::endl;
	}
	else {
		std::cout << "[-] Error in removing the DisableRoutinelyTakingAction value. Registry value does not exist " << std::endl;
	}
}

VOID RemoveBlockAtFirstSeen(wchar_t* user, wchar_t* host)
{
	HKEY hKey;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows Defender\\Spynet"), 0, KEY_SET_VALUE, &hKey);

	// Delete DisableAntispyware value
	LONG deleteValue = RegDeleteValueW(hKey, L"DisableBlockAtFirstSeen");

	if (deleteValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully removed the DisableBlockAtFirstSeen registry value" << std::endl;
	}
	else {
		std::cout << "[-] Error in removing the DisableBlockAtFirstSeen value. Registry value does not exist " << std::endl;
	}
}

VOID DisableLocalAdminMerge(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"DisableLocalAdminMerge", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned off DisableLocalAdminMerge" << std::endl;
	}
	else {
		std::cout << "[-] Error in removing DisableLocalAdminMerge value. Registry value does not exist " << std::endl;
	}
}

VOID DisableBehaviorMonitoring(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"DisableBehaviorMonitoring", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned on Behavior Monitoring" << std::endl;
	}
	else {
		std::cout << "[-] Error in modifying DisableBehaviorMonitoring value. Registry value does not exist. " << std::endl;
	}
}

VOID DisableIOAVProtection(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"DisableIOAVProtection", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned on IOAV protection " << std::endl;
	}
	else {
		std::cout << "[-] Error in modifying DisableIOAVProtection value. Registry value does not exist.  " << std::endl;
	}
}

VOID DisableOnAccessProtection(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"DisableOnAccessProtection", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned on Access Protection " << std::endl;
	}
	else {
		std::cout << "[-] Error in modifying DisableOnAccessProtection value. Registry value does not exist.  " << std::endl;
	}
}

VOID DisableRealtimeMonitoring(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"DisableRealtimeMonitoring", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned on Real-Time monitoring " << std::endl;
	}
	else {
		std::cout << "[-] Error in modifying DisableRealtimeMonitoring value. Registry value does not exist.  " << std::endl;
	}
}

VOID DisableScanOnRealtimeEnable(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"DisableScanOnRealtimeEnable", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned on Scan on real-time protection" << std::endl;
	}
	else {
		std::cout << "[-] Error in modifying DisableScanOnRealtimeEnable value. Registry value does not exist.  " << std::endl;
	}
}

VOID TurnOnWinDefETW(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 1;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\Microsoft-Windows-Windows Defender/Operational", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"	Enabled", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned on Microsoft-Windows-Defender/Operational" << std::endl;
	}
	else {
		std::cout << "[-] Error in turning on Windows Defender ETW. ETW Provider already enabled " << std::endl;
	}
}

BOOL StartWinDefendService() {
	// Get a handle to the SCM database. 

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		L"WinDefend",  // name of service 
		SERVICE_START);  // full access 

	if (schService == NULL)
	{
		std::cout << "[-] Could not open Service Manager [WinDefend]" << std::endl;
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Attempt to start the service.

	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError()) {
			std::cout << "[+] WinDefend Service already running" << std::endl;
		}
		else {

			std::cout << "[-] WinDefend Service failed" << std::endl;
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

BOOL StartWdFilterService() {
	// Get a handle to the SCM database. 

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		L"WdFilter",  // name of service 
		SERVICE_START);  // full access 

	if (schService == NULL)
	{
		std::cout << "[-] Could not open Service Manager [WdFilter]" << std::endl;
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Attempt to start the service.

	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError()) {
			std::cout << "[+] WdFilter Service already running" << std::endl;
		}
		else {

			std::cout << "[-] WdFilter Service failed" << std::endl;
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

BOOL StartWdNisDrvService() {
	// Get a handle to the SCM database. 

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		L"WdNisDrv",  // name of service 
		SERVICE_START);  // full access 

	if (schService == NULL)
	{
		std::cout << "[-] Could not open Service Manager [WdNisDrv]" << std::endl;
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Attempt to start the service.

	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError()) {
			std::cout << "[+] WdNisDrv Service already running" << std::endl;
		}
		else {

			std::cout << "[-] WdNisDrv Service failed" << std::endl;
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

BOOL StartWdNisSvcService() {
	// Get a handle to the SCM database. 

	SC_HANDLE schSCManager = OpenSCManager(
		NULL,                    // local computer
		NULL,                    // servicesActive database 
		SC_MANAGER_ALL_ACCESS);  // full access rights 

	// Get a handle to the service.

	SC_HANDLE schService = OpenService(
		schSCManager,         // SCM database 
		L"WdNisSvc",  // name of service 
		SERVICE_START);  // full access 

	if (schService == NULL)
	{
		std::cout << "[-] Could not open Service Manager [WdNisSvc]" << std::endl;
		CloseServiceHandle(schSCManager);
		return FALSE;
	}

	// Attempt to start the service.

	if (!StartService(
		schService,  // handle to service 
		0,           // number of arguments 
		NULL))      // no arguments 
	{
		if (ERROR_SERVICE_ALREADY_RUNNING == GetLastError()) {
			std::cout << "[+] WdNisSvc Service already running" << std::endl;
		}
		else {

			std::cout << "[-] WdNisSvc Service failed" << std::endl;
			CloseServiceHandle(schService);
			CloseServiceHandle(schSCManager);
			return FALSE;
		}
	}
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	return TRUE;
}

VOID TurnOnRTP(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Set-MpPreference -DisableRealtimeMonitoring $false";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL EnableRTP = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (EnableRTP) {
		std::cout << "[+] Successfully enabled Real-Time Protection " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in turning on Real-Time Protection. RTP may already have been enabled " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID TurnOnBehaviorMonitoring(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Set-MpPreference -DisableBehaviorMonitoring 0";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL EnableBM = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (EnableBM) {
		std::cout << "[+] Successfully enabled Behavior Monitoring " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in turning on Behavior Monitoring. Behavior Monitoring may already been enabled " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID TurnOnIOVA(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Set-MpPreference -DisableIOAVProtection 0";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL EnableIOVA = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (EnableIOVA) {
		std::cout << "[+] Successfully enabled IOVA Protection " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in turning on IOVA Protection " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID EnableScriptScanning(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Set-MpPreference -DisableScriptScanning 0";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL EnableRTP = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (EnableRTP) {
		std::cout << "[+] Successfully enabled Script Scanning " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in turning on Script Scanning. Script Scanning may already have been enabled " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID RemoveThreats(wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Remove-MpPreference -HighThreatDefaultAction";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL threatRemove = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (threatRemove) {
		std::cout << "[+] Successfully removed threats with a High severity " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing High severity threats. " << std::endl;
	};

	wchar_t cmd2[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg2[] = L" Remove-MpPreference -SevereThreatDefaultAction";

	BOOL threatRemove2 = CreateProcessW(cmd2, arg2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (threatRemove2) {
		std::cout << "[+] Successfully removed threats with a Severe severity " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing Severe threats " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID RemoveAllThreats(wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Remove-MpPreference -HighThreatDefaultAction";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL removeThreat = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (removeThreat) {
		std::cout << "[+] Successfully removed threats with a High severity " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing High threats. " << std::endl;
	};

	wchar_t cmd2[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg2[] = L" Remove-MpPreference -SevereThreatDefaultAction";

	BOOL removeThreat2 = CreateProcessW(cmd2, arg2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (removeThreat2) {
		std::cout << "[+] Successfully removed threats with a Severe severity " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing Severe threats " << std::endl;
	}

	wchar_t cmd3[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg3[] = L" Remove-MpPreference -ModerateThreatDefaultAction";

	BOOL removeThreat3 = CreateProcessW(cmd3, arg3, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (removeThreat3) {
		std::cout << "[+] Successfully removed threats with a Moderate severity " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing Moderate threats " << std::endl;
	}

	wchar_t cmd4[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg4[] = L" Remove-MpPreference -LowThreatDefaultAction";

	BOOL removeThreat4 = CreateProcessW(cmd4, arg4, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (removeThreat4) {
		std::cout << "[+] Successfully removed threats with a Low severity " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing Low severity threats " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID RemoveAllExclusions(wchar_t* user, wchar_t* host)
{
	// Removing broad AV exclusions for common directories attackers stage their tools

	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Remove-MpPreference -ExclusionPath 'C:\\'";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL RemoveExc = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc) {
		std::cout << "[+] Successfully removed C:\\ from AV exclusion" << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\ from AV exclusion " << std::endl;
	}

	wchar_t cmd2[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg2[] = L" Remove-MpPreference -ExclusionPath 'C:'";

	BOOL RemoveExc2 = CreateProcessW(cmd2, arg2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc2) {
		std::cout << "[+] Successfully removed C: from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C: from AV exclusion " << std::endl;
	}

	wchar_t cmd3[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg3[] = L" Remove-MpPreference -ExclusionPath 'C:\\*'";

	BOOL RemoveExc3 = CreateProcessW(cmd3, arg3, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc3) {
		std::cout << "[+] Successfully removed C:\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd4[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg4[] = L" Remove-MpPreference -ExclusionPath 'D:\\'";

	BOOL RemoveExc4 = CreateProcessW(cmd4, arg4, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc4) {
		std::cout << "[+] Successfully removed D:\\ from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing D:\\ from AV exclusion " << std::endl;
	}

	wchar_t cmd5[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg5[] = L" Remove-MpPreference -ExclusionPath 'D:'";

	BOOL RemoveExc5 = CreateProcessW(cmd5, arg5, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc5) {
		std::cout << "[+] Successfully removed D: from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing D: from AV exclusion " << std::endl;
	}

	wchar_t cmd6[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg6[] = L" Remove-MpPreference -ExclusionPath 'D:\\*'";

	BOOL RemoveExc6 = CreateProcessW(cmd6, arg6, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc6) {
		std::cout << "[+] Successfully removed D:\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing D:\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd7[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg7[] = L" Remove-MpPreference -ExclusionPath '%ProgramData%'";

	BOOL RemoveExc7 = CreateProcessW(cmd7, arg7, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc7) {
		std::cout << "[+] Successfully removed C:\\ProgramData from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\ProgramData from AV exclusion " << std::endl;
	}

	wchar_t cmd8[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg8[] = L" Remove-MpPreference -ExclusionPath 'C:\\Temp'";

	BOOL RemoveExc8 = CreateProcessW(cmd8, arg8, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc8) {
		std::cout << "[+] Successfully removed C:\\Temp from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Temp from AV exclusion " << std::endl;
	}

	wchar_t cmd9[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg9[] = L" Remove-MpPreference -ExclusionPath 'C:\\Temp\\'";

	BOOL RemoveExc9 = CreateProcessW(cmd9, arg9, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc9) {
		std::cout << "[+] Successfully removed C:\\Temp\\ from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Temp\\ from AV exclusion " << std::endl;
	}

	wchar_t cmd10[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg10[] = L" Remove-MpPreference -ExclusionPath 'C:\\Temp\\*'";

	BOOL RemoveExc10 = CreateProcessW(cmd10, arg10, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc10) {
		std::cout << "[+] Successfully removed C:\\Temp\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Temp\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd11[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg11[] = L" Remove-MpPreference -ExclusionPath 'C:\\Windows\\Temp'";

	BOOL RemoveExc11 = CreateProcessW(cmd11, arg11, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc11) {
		std::cout << "[+] Successfully removed C:\\Windows\\Temp from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Windows\\Temp from AV exclusion " << std::endl;
	}

	wchar_t cmd12[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg12[] = L" Remove-MpPreference -ExclusionPath 'C:\\Windows\\Temp\\*'";

	BOOL RemoveExc12 = CreateProcessW(cmd12, arg12, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc12) {
		std::cout << "[+] Successfully removed C:\\Windows\\Temp\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Windows\\Temp\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd13[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg13[] = L" Remove-MpPreference -ExclusionPath 'C:\\Users'";

	BOOL RemoveExc13 = CreateProcessW(cmd13, arg13, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc13) {
		std::cout << "[+] Successfully removed C:\\Users from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Users from AV exclusion " << std::endl;
	}

	wchar_t cmd14[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg14[] = L" Remove-MpPreference -ExclusionPath 'C:\\Users\\*'";

	BOOL RemoveExc14 = CreateProcessW(cmd14, arg14, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc14) {
		std::cout << "[+] Successfully removed C:\\Users\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Users\\* from AV exclusion " << std::endl;
	}

	// Excluding broad extensions

	wchar_t cmd15[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg15[] = L" Remove-MpPreference -ExclusionExtension '.7z'";

	BOOL RemoveExc15 = CreateProcessW(cmd15, arg15, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc15) {
		std::cout << "[+] Successfully removed .7z from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .7z from AV exclusion " << std::endl;
	}

	wchar_t cmd16[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg16[] = L" Remove-MpPreference -ExclusionExtension '.bat'";

	BOOL RemoveExc16 = CreateProcessW(cmd16, arg16, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc16) {
		std::cout << "[+] Successfully removed .bat from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .bat from AV exclusion " << std::endl;
	}

	wchar_t cmd17[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg17[] = L" Remove-MpPreference -ExclusionExtension '.exe'";

	BOOL RemoveExc17 = CreateProcessW(cmd17, arg17, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc17) {
		std::cout << "[+] Successfully removed .exe from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .exe from AV exclusion " << std::endl;
	}

	wchar_t cmd18[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg18[] = L" Remove-MpPreference -ExclusionExtension '.dll'";

	BOOL RemoveExc18 = CreateProcessW(cmd18, arg18, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc18) {
		std::cout << "[+] Successfully removed .dll from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .dll from AV exclusion " << std::endl;
	}

	wchar_t cmd19[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg19[] = L" Remove-MpPreference -ExclusionExtension '.bin'";

	BOOL RemoveExc19 = CreateProcessW(cmd19, arg19, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc19) {
		std::cout << "[+] Successfully removed .bin from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .bin from AV exclusion " << std::endl;
	}

	wchar_t cmd20[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg20[] = L" Remove-MpPreference -ExclusionExtension '.cab'";

	BOOL RemoveExc20 = CreateProcessW(cmd20, arg20, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc20) {
		std::cout << "[+] Successfully removed .cab from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .cab from AV exclusion " << std::endl;
	}

	wchar_t cmd21[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg21[] = L" Remove-MpPreference -ExclusionExtension '.cmd'";

	BOOL RemoveExc21 = CreateProcessW(cmd21, arg21, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc21) {
		std::cout << "[+] Successfully removed .cmd from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .cmd from AV exclusion " << std::endl;
	}

	wchar_t cmd22[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg22[] = L" Remove-MpPreference -ExclusionExtension '.com'";

	BOOL RemoveExc22 = CreateProcessW(cmd22, arg22, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc22) {
		std::cout << "[+] Successfully removed .com from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .com from AV exclusion " << std::endl;
	}

	wchar_t cmd23[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg23[] = L" Remove-MpPreference -ExclusionExtension '.cpl'";

	BOOL RemoveExc23 = CreateProcessW(cmd23, arg23, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc23) {
		std::cout << "[+] Successfully removed .cpl from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .cpl from AV exclusion " << std::endl;
	}

	wchar_t cmd24[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg24[] = L" Remove-MpPreference -ExclusionExtension '.fla'";

	BOOL RemoveExc24 = CreateProcessW(cmd24, arg24, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc24) {
		std::cout << "[+] Successfully removed .fla from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .fla from AV exclusion " << std::endl;
	}

	wchar_t cmd25[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg25[] = L" Remove-MpPreference -ExclusionExtension '.gif'";

	BOOL RemoveExc25 = CreateProcessW(cmd25, arg25, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc25) {
		std::cout << "[+] Successfully removed .gif from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .gif from AV exclusion " << std::endl;
	}

	wchar_t cmd26[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg26[] = L" Remove-MpPreference -ExclusionExtension '.gif'";

	BOOL RemoveExc26 = CreateProcessW(cmd26, arg26, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc26) {
		std::cout << "[+] Successfully removed .gif from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .gif from AV exclusion " << std::endl;
	}

	wchar_t cmd27[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg27[] = L" Remove-MpPreference -ExclusionExtension '.gz'";

	BOOL RemoveExc27 = CreateProcessW(cmd27, arg27, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc27) {
		std::cout << "[+] Successfully removed .gz from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .gz from AV exclusion " << std::endl;
	}

	wchar_t cmd28[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg28[] = L" Remove-MpPreference -ExclusionExtension '.hta'";

	BOOL RemoveExc28 = CreateProcessW(cmd28, arg28, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc28) {
		std::cout << "[+] Successfully removed .hta from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .hta from AV exclusion " << std::endl;
	}

	wchar_t cmd29[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg29[] = L" Remove-MpPreference -ExclusionExtension '.inf'";

	BOOL RemoveExc29 = CreateProcessW(cmd29, arg29, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc29) {
		std::cout << "[+] Successfully removed .inf from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .inf from AV exclusion " << std::endl;
	}

	wchar_t cmd30[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg30[] = L" Remove-MpPreference -ExclusionExtension '.java'";

	BOOL RemoveExc30 = CreateProcessW(cmd30, arg30, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc30) {
		std::cout << "[+] Successfully removed .java from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .java from AV exclusion " << std::endl;
	}

	wchar_t cmd31[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg31[] = L" Remove-MpPreference -ExclusionExtension '.jar'";

	BOOL RemoveExc31 = CreateProcessW(cmd31, arg31, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc31) {
		std::cout << "[+] Successfully removed .jar from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .jar from AV exclusion " << std::endl;
	}

	wchar_t cmd32[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg32[] = L" Remove-MpPreference -ExclusionExtension '.jpeg'";

	BOOL RemoveExc32 = CreateProcessW(cmd32, arg32, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc32) {
		std::cout << "[+] Successfully removed .jpeg from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .jpeg from AV exclusion " << std::endl;
	}

	wchar_t cmd33[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg33[] = L" Remove-MpPreference -ExclusionExtension '.jpg'";

	BOOL RemoveExc33 = CreateProcessW(cmd33, arg33, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc33) {
		std::cout << "[+] Successfully removed .jpg from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .jpg from AV exclusion " << std::endl;
	}

	wchar_t cmd34[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg34[] = L" Remove-MpPreference -ExclusionExtension '.js'";

	BOOL RemoveExc34 = CreateProcessW(cmd34, arg34, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc34) {
		std::cout << "[+] Successfully removed .js from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .js from AV exclusion " << std::endl;
	}

	wchar_t cmd35[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg35[] = L" Remove-MpPreference -ExclusionExtension '.msi'";

	BOOL RemoveExc35 = CreateProcessW(cmd35, arg35, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc35) {
		std::cout << "[+] Successfully removed .msi from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .msi from AV exclusion " << std::endl;
	}

	wchar_t cmd36[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg36[] = L" Remove-MpPreference -ExclusionExtension '.ocx'";

	BOOL RemoveExc36 = CreateProcessW(cmd36, arg36, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc36) {
		std::cout << "[+] Successfully removed .ocx from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .ocx from AV exclusion " << std::endl;
	}

	wchar_t cmd37[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg37[] = L" Remove-MpPreference -ExclusionExtension '.png'";

	BOOL RemoveExc37 = CreateProcessW(cmd37, arg37, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc37) {
		std::cout << "[+] Successfully removed .png from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .png from AV exclusion " << std::endl;
	}

	wchar_t cmd38[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg38[] = L" Remove-MpPreference -ExclusionExtension '.ps1'";

	BOOL RemoveExc38 = CreateProcessW(cmd38, arg38, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc38) {
		std::cout << "[+] Successfully removed .ps1 from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .ps1 from AV exclusion " << std::endl;
	}

	wchar_t cmd40[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg40[] = L" Remove-MpPreference -ExclusionExtension '.tmp'";

	BOOL RemoveExc40 = CreateProcessW(cmd40, arg40, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc40) {
		std::cout << "[+] Successfully removed .tmp from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .tmp from AV exclusion " << std::endl;
	}

	wchar_t cmd41[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg41[] = L" Remove-MpPreference -ExclusionExtension '.vbe'";

	BOOL RemoveExc41 = CreateProcessW(cmd41, arg41, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc41) {
		std::cout << "[+] Successfully removed .vbe from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .vbe from AV exclusion " << std::endl;
	}

	wchar_t cmd42[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg42[] = L" Remove-MpPreference -ExclusionExtension '.vbs'";

	BOOL RemoveExc42 = CreateProcessW(cmd42, arg42, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc42) {
		std::cout << "[+] Successfully removed .vbs from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .vbs from AV exclusion " << std::endl;
	}

	wchar_t cmd43[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg43[] = L" Remove-MpPreference -ExclusionExtension '.wsf'";

	BOOL RemoveExc43 = CreateProcessW(cmd43, arg43, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc43) {
		std::cout << "[+] Successfully removed .wsf from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .wsf from AV exclusion " << std::endl;
	}

	wchar_t cmd44[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg44[] = L" Remove-MpPreference -ExclusionExtension '.zip'";

	BOOL RemoveExc44 = CreateProcessW(cmd44, arg44, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc44) {
		std::cout << "[+] Successfully removed .zip from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .zip from AV exclusion " << std::endl;
	}

	wchar_t cmd45[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg45[] = L" Remove-MpPreference -ExclusionExtension '.sys'";

	BOOL RemoveExc45 = CreateProcessW(cmd45, arg45, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc45) {
		std::cout << "[+] Successfully removed .sys from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .sys from AV exclusion " << std::endl;
	}

	wchar_t cmd46[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg46[] = L" Remove-MpPreference -ExclusionExtension '.scr'";

	BOOL RemoveExc46 = CreateProcessW(cmd46, arg46, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc46) {
		std::cout << "[+] Successfully removed .scr from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .scr from AV exclusion " << std::endl;
	}

	wchar_t cmd47[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg47[] = L" Remove-MpPreference -ExclusionExtension '.py'";

	BOOL RemoveExc47 = CreateProcessW(cmd47, arg47, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc47) {
		std::cout << "[+] Successfully removed .py from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .py from AV exclusion " << std::endl;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID RemoveExtensions(wchar_t* host)
{
	// Excluding broad extensions

	wchar_t cmd15[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg15[] = L" Remove-MpPreference -ExclusionExtension '.7z'";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL RemoveExc15 = CreateProcessW(cmd15, arg15, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc15) {
		std::cout << "[+] Successfully removed .7z from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .7z from AV exclusion " << std::endl;
	}

	wchar_t cmd16[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg16[] = L" Remove-MpPreference -ExclusionExtension '.bat'";

	BOOL RemoveExc16 = CreateProcessW(cmd16, arg16, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc16) {
		std::cout << "[+] Successfully removed .bat from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .bat from AV exclusion " << std::endl;
	}

	wchar_t cmd17[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg17[] = L" Remove-MpPreference -ExclusionExtension '.exe'";

	BOOL RemoveExc17 = CreateProcessW(cmd17, arg17, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc17) {
		std::cout << "[+] Successfully removed .exe from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .exe from AV exclusion " << std::endl;
	}

	wchar_t cmd18[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg18[] = L" Remove-MpPreference -ExclusionExtension '.dll'";

	BOOL RemoveExc18 = CreateProcessW(cmd18, arg18, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc18) {
		std::cout << "[+] Successfully removed .dll from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .dll from AV exclusion " << std::endl;
	}

	wchar_t cmd19[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg19[] = L" Remove-MpPreference -ExclusionExtension '.bin'";

	BOOL RemoveExc19 = CreateProcessW(cmd19, arg19, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc19) {
		std::cout << "[+] Successfully removed .bin from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .bin from AV exclusion " << std::endl;
	}

	wchar_t cmd20[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg20[] = L" Remove-MpPreference -ExclusionExtension '.cab'";

	BOOL RemoveExc20 = CreateProcessW(cmd20, arg20, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc20) {
		std::cout << "[+] Successfully removed .cab from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .cab from AV exclusion " << std::endl;
	}

	wchar_t cmd21[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg21[] = L" Remove-MpPreference -ExclusionExtension '.cmd'";

	BOOL RemoveExc21 = CreateProcessW(cmd21, arg21, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc21) {
		std::cout << "[+] Successfully removed .cmd from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .cmd from AV exclusion " << std::endl;
	}

	wchar_t cmd22[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg22[] = L" Remove-MpPreference -ExclusionExtension '.com'";

	BOOL RemoveExc22 = CreateProcessW(cmd22, arg22, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc22) {
		std::cout << "[+] Successfully removed .com from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .com from AV exclusion " << std::endl;
	}

	wchar_t cmd23[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg23[] = L" Remove-MpPreference -ExclusionExtension '.cpl'";

	BOOL RemoveExc23 = CreateProcessW(cmd23, arg23, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc23) {
		std::cout << "[+] Successfully removed .cpl from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .cpl from AV exclusion " << std::endl;
	}

	wchar_t cmd24[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg24[] = L" Remove-MpPreference -ExclusionExtension '.fla'";

	BOOL RemoveExc24 = CreateProcessW(cmd24, arg24, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc24) {
		std::cout << "[+] Successfully removed .fla from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .fla from AV exclusion " << std::endl;
	}

	wchar_t cmd25[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg25[] = L" Remove-MpPreference -ExclusionExtension '.gif'";

	BOOL RemoveExc25 = CreateProcessW(cmd25, arg25, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc25) {
		std::cout << "[+] Successfully removed .gif from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .gif from AV exclusion " << std::endl;
	}

	wchar_t cmd26[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg26[] = L" Remove-MpPreference -ExclusionExtension '.gif'";

	BOOL RemoveExc26 = CreateProcessW(cmd26, arg26, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc26) {
		std::cout << "[+] Successfully removed .gif from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .gif from AV exclusion " << std::endl;
	}

	wchar_t cmd27[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg27[] = L" Remove-MpPreference -ExclusionExtension '.gz'";

	BOOL RemoveExc27 = CreateProcessW(cmd27, arg27, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc27) {
		std::cout << "[+] Successfully removed .gz from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .gz from AV exclusion " << std::endl;
	}

	wchar_t cmd28[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg28[] = L" Remove-MpPreference -ExclusionExtension '.hta'";

	BOOL RemoveExc28 = CreateProcessW(cmd28, arg28, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc28) {
		std::cout << "[+] Successfully removed .hta from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .hta from AV exclusion " << std::endl;
	}

	wchar_t cmd29[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg29[] = L" Remove-MpPreference -ExclusionExtension '.inf'";

	BOOL RemoveExc29 = CreateProcessW(cmd29, arg29, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc29) {
		std::cout << "[+] Successfully removed .inf from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .inf from AV exclusion " << std::endl;
	}

	wchar_t cmd30[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg30[] = L" Remove-MpPreference -ExclusionExtension '.java'";

	BOOL RemoveExc30 = CreateProcessW(cmd30, arg30, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc30) {
		std::cout << "[+] Successfully removed .java from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .java from AV exclusion " << std::endl;
	}

	wchar_t cmd31[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg31[] = L" Remove-MpPreference -ExclusionExtension '.jar'";

	BOOL RemoveExc31 = CreateProcessW(cmd31, arg31, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc31) {
		std::cout << "[+] Successfully removed .jar from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .jar from AV exclusion " << std::endl;
	}

	wchar_t cmd32[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg32[] = L" Remove-MpPreference -ExclusionExtension '.jpeg'";

	BOOL RemoveExc32 = CreateProcessW(cmd32, arg32, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc32) {
		std::cout << "[+] Successfully removed .jpeg from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .jpeg from AV exclusion " << std::endl;
	}

	wchar_t cmd33[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg33[] = L" Remove-MpPreference -ExclusionExtension '.jpg'";

	BOOL RemoveExc33 = CreateProcessW(cmd33, arg33, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc33) {
		std::cout << "[+] Successfully removed .jpg from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .jpg from AV exclusion " << std::endl;
	}

	wchar_t cmd34[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg34[] = L" Remove-MpPreference -ExclusionExtension '.js'";

	BOOL RemoveExc34 = CreateProcessW(cmd34, arg34, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc34) {
		std::cout << "[+] Successfully removed .js from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .js from AV exclusion " << std::endl;
	}

	wchar_t cmd35[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg35[] = L" Remove-MpPreference -ExclusionExtension '.msi'";

	BOOL RemoveExc35 = CreateProcessW(cmd35, arg35, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc35) {
		std::cout << "[+] Successfully removed .msi from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .msi from AV exclusion " << std::endl;
	}

	wchar_t cmd36[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg36[] = L" Remove-MpPreference -ExclusionExtension '.ocx'";

	BOOL RemoveExc36 = CreateProcessW(cmd36, arg36, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc36) {
		std::cout << "[+] Successfully removed .ocx from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .ocx from AV exclusion " << std::endl;
	}

	wchar_t cmd37[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg37[] = L" Remove-MpPreference -ExclusionExtension '.png'";

	BOOL RemoveExc37 = CreateProcessW(cmd37, arg37, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc37) {
		std::cout << "[+] Successfully removed .png from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .png from AV exclusion " << std::endl;
	}

	wchar_t cmd38[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg38[] = L" Remove-MpPreference -ExclusionExtension '.ps1'";

	BOOL RemoveExc38 = CreateProcessW(cmd38, arg38, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc38) {
		std::cout << "[+] Successfully removed .ps1 from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .ps1 from AV exclusion " << std::endl;
	}

	wchar_t cmd40[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg40[] = L" Remove-MpPreference -ExclusionExtension '.tmp'";

	BOOL RemoveExc40 = CreateProcessW(cmd40, arg40, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc40) {
		std::cout << "[+] Successfully removed .tmp from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .tmp from AV exclusion " << std::endl;
	}

	wchar_t cmd41[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg41[] = L" Remove-MpPreference -ExclusionExtension '.vbe'";

	BOOL RemoveExc41 = CreateProcessW(cmd41, arg41, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc41) {
		std::cout << "[+] Successfully removed .vbe from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .vbe from AV exclusion " << std::endl;
	}

	wchar_t cmd42[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg42[] = L" Remove-MpPreference -ExclusionExtension '.vbs'";

	BOOL RemoveExc42 = CreateProcessW(cmd42, arg42, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc42) {
		std::cout << "[+] Successfully removed .vbs from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .vbs from AV exclusion " << std::endl;
	}

	wchar_t cmd43[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg43[] = L" Remove-MpPreference -ExclusionExtension '.wsf'";

	BOOL RemoveExc43 = CreateProcessW(cmd43, arg43, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc43) {
		std::cout << "[+] Successfully removed .wsf from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .wsf from AV exclusion " << std::endl;
	}

	wchar_t cmd44[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg44[] = L" Remove-MpPreference -ExclusionExtension '.zip'";

	BOOL RemoveExc44 = CreateProcessW(cmd44, arg44, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc44) {
		std::cout << "[+] Successfully removed .zip from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .zip from AV exclusion " << std::endl;
	}

	wchar_t cmd45[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg45[] = L" Remove-MpPreference -ExclusionExtension '.sys'";

	BOOL RemoveExc45 = CreateProcessW(cmd45, arg45, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc45) {
		std::cout << "[+] Successfully removed .sys from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .sys from AV exclusion " << std::endl;
	}

	wchar_t cmd46[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg46[] = L" Remove-MpPreference -ExclusionExtension '.scr'";

	BOOL RemoveExc46 = CreateProcessW(cmd46, arg46, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc46) {
		std::cout << "[+] Successfully removed .scr from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .scr from AV exclusion " << std::endl;
	}

	wchar_t cmd47[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg47[] = L" Remove-MpPreference -ExclusionExtension '.py'";

	BOOL RemoveExc47 = CreateProcessW(cmd47, arg47, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc47) {
		std::cout << "[+] Successfully removed .py from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing .py from AV exclusion " << std::endl;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID RemoveDirectories(wchar_t* user, wchar_t* host)
{
	// Removing broad AV exclusions for common directories attackers stage their tools

	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Remove-MpPreference -ExclusionPath 'C:\\'";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL RemoveExc = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc) {
		std::cout << "[+] Successfully removed C:\\ from AV exclusion" << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\ from AV exclusion " << std::endl;
	}

	wchar_t cmd2[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg2[] = L" Remove-MpPreference -ExclusionPath 'C:'";

	BOOL RemoveExc2 = CreateProcessW(cmd2, arg2, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc2) {
		std::cout << "[+] Successfully removed C: from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C: from AV exclusion " << std::endl;
	}

	wchar_t cmd3[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg3[] = L" Remove-MpPreference -ExclusionPath 'C:\\*'";

	BOOL RemoveExc3 = CreateProcessW(cmd3, arg3, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc3) {
		std::cout << "[+] Successfully removed C:\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd4[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg4[] = L" Remove-MpPreference -ExclusionPath 'D:\\'";

	BOOL RemoveExc4 = CreateProcessW(cmd4, arg4, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc4) {
		std::cout << "[+] Successfully removed D:\\ from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing D:\\ from AV exclusion " << std::endl;
	}

	wchar_t cmd5[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg5[] = L" Remove-MpPreference -ExclusionPath 'D:'";

	BOOL RemoveExc5 = CreateProcessW(cmd5, arg5, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc5) {
		std::cout << "[+] Successfully removed D: from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing D: from AV exclusion " << std::endl;
	}

	wchar_t cmd6[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg6[] = L" Remove-MpPreference -ExclusionPath 'D:\\*'";

	BOOL RemoveExc6 = CreateProcessW(cmd6, arg6, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc6) {
		std::cout << "[+] Successfully removed D:\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing D:\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd7[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg7[] = L" Remove-MpPreference -ExclusionPath '%ProgramData%'";

	BOOL RemoveExc7 = CreateProcessW(cmd7, arg7, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc7) {
		std::cout << "[+] Successfully removed C:\\ProgramData from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\ProgramData from AV exclusion " << std::endl;
	}

	wchar_t cmd8[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg8[] = L" Remove-MpPreference -ExclusionPath 'C:\\Temp'";

	BOOL RemoveExc8 = CreateProcessW(cmd8, arg8, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc8) {
		std::cout << "[+] Successfully removed C:\\Temp from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Temp from AV exclusion " << std::endl;
	}

	wchar_t cmd9[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg9[] = L" Remove-MpPreference -ExclusionPath 'C:\\Temp\\'";

	BOOL RemoveExc9 = CreateProcessW(cmd9, arg9, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc9) {
		std::cout << "[+] Successfully removed C:\\Temp\\ from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Temp\\ from AV exclusion " << std::endl;
	}

	wchar_t cmd10[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg10[] = L" Remove-MpPreference -ExclusionPath 'C:\\Temp\\*'";

	BOOL RemoveExc10 = CreateProcessW(cmd10, arg10, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc10) {
		std::cout << "[+] Successfully removed C:\\Temp\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Temp\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd11[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg11[] = L" Remove-MpPreference -ExclusionPath 'C:\\Windows\\Temp'";

	BOOL RemoveExc11 = CreateProcessW(cmd11, arg11, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc11) {
		std::cout << "[+] Successfully removed C:\\Windows\\Temp from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Windows\\Temp from AV exclusion " << std::endl;
	}

	wchar_t cmd12[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg12[] = L" Remove-MpPreference -ExclusionPath 'C:\\Windows\\Temp\\*'";

	BOOL RemoveExc12 = CreateProcessW(cmd12, arg12, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc12) {
		std::cout << "[+] Successfully removed C:\\Windows\\Temp\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Windows\\Temp\\* from AV exclusion " << std::endl;
	}

	wchar_t cmd13[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg13[] = L" Remove-MpPreference -ExclusionPath 'C:\\Users'";

	BOOL RemoveExc13 = CreateProcessW(cmd13, arg13, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc13) {
		std::cout << "[+] Successfully removed C:\\Users from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Users from AV exclusion " << std::endl;
	}

	wchar_t cmd14[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg14[] = L" Remove-MpPreference -ExclusionPath 'C:\\Users\\*'";

	BOOL RemoveExc14 = CreateProcessW(cmd14, arg14, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (RemoveExc14) {
		std::cout << "[+] Successfully removed C:\\Users\\* from AV exclusion " << std::endl;
	}
	else
	{
		std::cout << "[-] Error in removing C:\\Users\\* from AV exclusion " << std::endl;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID TurnOff_WDigest(wchar_t* user, wchar_t* host)
{
	HKEY hKey;
	DWORD data = 0;

	// Open Registry Key Path
	LONG openReg = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest", 0, KEY_SET_VALUE, &hKey);

	// Enabling WDigest
	LONG setValue = RegSetValueExW(hKey, L"UseLogonCredential", 0, REG_DWORD, (LPBYTE)&data, sizeof(data));

	if (setValue == ERROR_SUCCESS) {
		std::cout << "[+] Successfully turned off WDigest" << std::endl;
	}
	else {
		std::cout << "[-] Error in turning off WDigest " << std::endl;
	}
}

VOID QuickScan(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
	wchar_t arg[] = L" -Scan -ScanType 1";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL restartWinDefend = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (restartWinDefend) {
		std::cout << "[+] Successfully started a quick AV scan " << std::endl;
	}
	else
	{
		std::cout << "[-] Failed to start a quick AV scan. " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID FullScan(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
	wchar_t arg[] = L" -Scan -ScanType 2";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL restartWinDefend = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (restartWinDefend) {
		std::cout << "[+] Successfully started a full AV scan " << std::endl;
	}
	else
	{
		std::cout << "[-] Failed to start a full AV scan. " << std::endl;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID Quarantined(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
	wchar_t arg[] = L" -Restore -ListAll";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL restartWinDefend = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (restartWinDefend) {
		std::cout << "[+] Successfully displayed files that were quarantined by AV " << std::endl;
	}
	else
	{
		std::cout << "[-] Failed to display files that were quarantined by AV " << std::endl;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID GetCabFiles(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Program Files\\Windows Defender\\MpCmdRun.exe";
	wchar_t arg[] = L" -GetFiles";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL restartWinDefend = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (restartWinDefend) {
		std::cout << "[+] Successfully collected diagnostic data from Windows Defender " << std::endl;
	}
	else
	{
		std::cout << "[-] Failed to collect diagnostic data from Windows Defender " << std::endl;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

VOID GetThreats(wchar_t* user, wchar_t* host)
{
	wchar_t cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
	wchar_t arg[] = L" Get-MpThreatDetection";

	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;

	BOOL restartWinDefend = CreateProcessW(cmd, arg, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (restartWinDefend) {
		std::cout << "[+] Successfully displayed past and active malware threats that AV detected " << std::endl;
	}
	else
	{
		std::cout << "[-] Failed to display past and active malware threats " << std::endl;
	}

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

int wmain(int argc, wchar_t* argv[])
{
	wchar_t* user = NULL;
	wchar_t* host = NULL;

	// Check elevated process
	if (!IsElevatedProcess()) {
		std::cout << "[-] Error: Execute with administrative privileges." << std::endl;
		return 1;
	}

	// Display CLI options
	if (argc == 1)
		displayHelp();

	if (_wcsicmp(argv[1], L"--help") == 0)
	{
		displayHelp();
	}

	if (_wcsicmp(argv[1], L"--start") == 0)
	{
		if (argc == 2)
		{
			RemoveDisableAntiSpywareValue(user, NULL); // Remove DisableAntiSpyware value
			RemoveDisableAntiVirusValue(user, NULL); // Remove DisableAntiVirus value
			RemoveDisableRoutineActionKey(user, NULL); // Remove DisableRoutineActionKey value
			RemoveBlockAtFirstSeen(user, NULL); // Remove DisableBlockAtFirstSeen value
			DisableLocalAdminMerge(user, NULL); // Remove DisableLocalAdminMerge value
			DisableBehaviorMonitoring(user, NULL); // Windows Server 2016
			DisableIOAVProtection(user, NULL); // Windows Server 2016
			DisableOnAccessProtection(user, NULL); // Windows Server 2016
			DisableRealtimeMonitoring(user, NULL); // Windows Server 2016
			DisableScanOnRealtimeEnable(user, NULL); // Windows Server 2016
			TurnOnWinDefETW(user, NULL); // Turn on Microsoft-Windows-Defender/Operational if tampered
			StartWinDefendService(); // Start WinDefend service
			StartWdFilterService(); // Start WdFilter service
			StartWdNisDrvService(); // Start WdNisDrv service
			StartWdNisSvcService(); // Start WdNisSvc service
			TurnOnRTP(user, NULL); // Enable Real-Time Protection
			TurnOnBehaviorMonitoring(user, NULL); // Enable Behavior Monitoring
			TurnOnIOVA(user, NULL); // Enable IOVA Protection
			EnableScriptScanning(user, NULL); // Enable Script Scanning
		}
		else if (_wcsicmp(argv[1], L"--start") == 0)
		{
			if (argc == 3)
			{
				RemoveThreats(NULL); // Using Remove-MpPreference to remove High & Severe threats
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --start. \n");

		return 0;
	}

	// -removeThreats option
	else if (_wcsicmp(argv[1], L"--removeThreats") == 0)
	{
		if (argc == 2)
		{
			RemoveThreats(NULL);
		}
	}
	else if (_wcsicmp(argv[1], L"--removeThreats") == 0)
	{
		if (argc == 3)
		{
			RemoveThreats(NULL);
		}
		else
			wprintf(L" [-] Error: Invalid options for --removeThreats.\n");

		return 0;
	}

	// -removeAllThreats option
	else if (_wcsicmp(argv[1], L"--removeAllThreats") == 0)
	{
		if (argc == 2)
		{
			RemoveAllThreats(NULL); // Using Remove-MpPreference to all threats despite severity
		}
		else if (_wcsicmp(argv[1], L"--removeAllThreats") == 0)
		{
			if (argc == 3)
			{
				RemoveAllThreats(NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --removeAllThreats.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--removeAllExclusions") == 0)
	{
		if (argc == 2)
		{
			RemoveAllExclusions(user, NULL); // Using Remove-MpPreference to remove all broad AV exclusions
		}
		else if (_wcsicmp(argv[1], L"--removeAllExclusions") == 0)
		{
			if (argc == 3)
			{
				RemoveAllExclusions(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --removeAllExclusions.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--removeAllExtensions") == 0)
	{
		if (argc == 2)
		{
			RemoveExtensions(NULL); // Using Remove-MpPreference to remove broad extensions that are excluded from AV
		}
		else if (_wcsicmp(argv[1], L"--removeAllExtensions") == 0)
		{
			if (argc == 3)
			{
				RemoveExtensions(NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --removeAllExtensions.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--removeAllDirectories") == 0)
	{
		if (argc == 2)
		{
			RemoveDirectories(user, NULL); // Using Remove-MpPreference to remove broad extensions that are excluded from AV
		}
		else if (_wcsicmp(argv[1], L"--removeAllDirectories") == 0)
		{
			if (argc == 3)
			{
				RemoveDirectories(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --removeAllDirectories.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--disableWDigest") == 0)
	{
		if (argc == 2)
		{
			TurnOff_WDigest(user, NULL); // Disabling WDigest
		}
		else if (_wcsicmp(argv[1], L"--disableWDigest") == 0)
		{
			if (argc == 3)
			{
				TurnOff_WDigest(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --disableWDigest.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--quickScan") == 0)
	{
		if (argc == 2)
		{
			QuickScan(user, NULL); // Run quick AV scan
		}
		else if (_wcsicmp(argv[1], L"--quickScan") == 0)
		{
			if (argc == 3)
			{
				QuickScan(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --quickScan.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--fullScan") == 0)
	{
		if (argc == 2)
		{
			FullScan(user, NULL); // Run full AV scan
		}
		else if (_wcsicmp(argv[1], L"--fullScan") == 0)
		{
			if (argc == 3)
			{
				FullScan(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --fullScan.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--listAll") == 0)
	{
		if (argc == 2)
		{
			Quarantined(user, NULL); // List all files that were quarantined
		}
		else if (_wcsicmp(argv[1], L"--listAll") == 0)
		{
			if (argc == 3)
			{
				Quarantined(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --listAll.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--getFiles") == 0)
	{
		if (argc == 2)
		{
			GetCabFiles(user, NULL); // Collect diagnostic data of Windows Defender
		}
		else if (_wcsicmp(argv[1], L"--getFiles") == 0)
		{
			if (argc == 3)
			{
				GetCabFiles(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --listAll.\n");

		return 0;
	}
	else if (_wcsicmp(argv[1], L"--getThreats") == 0)
	{
		if (argc == 2)
		{
			GetThreats(user, NULL); // Get active and past malware threats that Windows Defender detected
		}
		else if (_wcsicmp(argv[1], L"--getThreats") == 0)
		{
			if (argc == 3)
			{
				GetThreats(user, NULL);
			}
		}
		else
			wprintf(L" [-] Error: Invalid options for --getThreats.\n");

		return 0;
	}
	else
		displayHelp();

	return 0;
}
