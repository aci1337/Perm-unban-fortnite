#include <iostream>
#include <string>
#include <windows.h>
#include <time.h>

using namespace std;

BOOL SetVolumeInformation(LPCSTR lpRootPathName, LPCSTR lpVolumeName, DWORD dwVolumeSerialNumber, DWORD dwMaximumComponentLength)
{
	BOOL bResult;
	DWORD dwFileSystemFlags;
	CHAR szFileSystemName[MAX_PATH];

	bResult = GetVolumeInformation(lpRootPathName, NULL, 0, NULL, NULL, &dwFileSystemFlags, szFileSystemName, MAX_PATH);

	if (bResult)
	{
		bResult = SetVolumeInformation(lpRootPathName, lpVolumeName, dwVolumeSerialNumber, dwMaximumComponentLength);
	}

	return bResult;
}

BOOL SetVolumeID(LPCSTR lpRootPathName, DWORD VolumeID)
{
	BOOL bResult = FALSE;
	DWORD dwDataSize;
	DWORD dwSerialNumber;
	CHAR szVolumeName[MAX_PATH];
	CHAR szFileSystemName[MAX_PATH];
	DWORD dwMaxComponentLen;
	DWORD dwFileSystemFlags;

	dwDataSize = GetVolumeInformation(lpRootPathName, szVolumeName, MAX_PATH, &dwSerialNumber, &dwMaxComponentLen, &dwFileSystemFlags, szFileSystemName, MAX_PATH);


	if (dwSerialNumber != VolumeID)
	{
		bResult = SetVolumeInformation(lpRootPathName, szVolumeName, VolumeID, NULL);
	}

	return bResult;
}
#include <filesystem>
#include <stdio.h>
#include <tchar.h>
#include <IPHlpApi.h>
#include <stdlib.h>
#include <iptypes.h>
#pragma comment(lib, "IPHlpApi.lib")
#include <algorithm>
#include <random>

std::string GenerateMACAddress()
{
	std::string macAddress;
	const char* charset = "ABCDEF0123456789";
	const char* charset2 = "26AE";

	for (int i = 0; i < 12; i++)
	{
		if (i == 2)
		{
			int randomChar = rand() % 4;
			macAddress += charset2[randomChar];
		}
		else
		{
			int randomChar = rand() % 16;
			macAddress += charset[randomChar];
		}
	}

	return macAddress;
}

BOOL SetMACAddress(std::string macAddress)
{
	HKEY hKey;
	LONG regResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}"), 0, KEY_ALL_ACCESS, &hKey);

	if (regResult != ERROR_SUCCESS)
	{
		return FALSE;
	}

	for (int i = 0; i < 3; i++)
	{
		std::string subkeyName = std::to_string(i) + "000";
		HKEY hSubKey;
		regResult = RegOpenKeyEx(hKey, TEXT(subkeyName.c_str()), 0, KEY_ALL_ACCESS, &hSubKey);

		if (regResult != ERROR_SUCCESS)
		{
			RegCloseKey(hKey);
			return FALSE;
		}

		regResult = RegSetValueEx(hSubKey, TEXT("NetworkAddress"), 0, REG_SZ, (LPBYTE)macAddress.c_str(), macAddress.size());

		if (regResult != ERROR_SUCCESS)
		{
			RegCloseKey(hSubKey);
			RegCloseKey(hKey);
			return FALSE;
		}

		DWORD powerSavingMode = 24;
		regResult = RegSetValueEx(hSubKey, TEXT("PnPCapabilities"), 0, REG_DWORD, (LPBYTE)&powerSavingMode, sizeof(DWORD));

		if (regResult != ERROR_SUCCESS)
		{
			RegCloseKey(hSubKey);
			RegCloseKey(hKey);
			return FALSE;
		}

		RegCloseKey(hSubKey);
	}

	RegCloseKey(hKey);

	return TRUE;
}

BOOL ResetNetworkAdapters()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	
	std::string commandStr = "netsh interface set interface name=\"%s\" disable";
	CreateProcess(NULL, (LPSTR)commandStr.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	
	WaitForSingleObject(pi.hProcess, INFINITE);

	
	commandStr = "netsh interface set interface name=\"%s\" enable";
	CreateProcess(NULL, (LPSTR)commandStr.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);

	
	WaitForSingleObject(pi.hProcess, INFINITE);

	return TRUE;
}

/*void generateMacAddress(BYTE* macAddress)
{
	for (int i = 0; i < 6; i++)
		macAddress[i] = (BYTE)(rand() % 256);
}

void changeMacAddress(const char* adapterName, BYTE* macAddress)
{
	IP_ADAPTER_ADDRESSES* addresses = NULL;
	ULONG addressesLength = 0;

	
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &addressesLength) == ERROR_BUFFER_OVERFLOW)
	{
		addresses = (IP_ADAPTER_ADDRESSES*)malloc(addressesLength);
		if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &addressesLength) == NO_ERROR)
		{
			
			for (IP_ADAPTER_ADDRESSES* address = addresses; address != NULL; address = address->Next)
			{
				
				if (strcmp(address->AdapterName, adapterName) == 0)
				{
					ULONG status = SetAdapterIpAddress(address->Luid, macAddress);
					if (status != NO_ERROR)
						cout << "Failed to change MAC address: " << status << endl;

					break;
				}
			}
		}

		free(addresses);
	}
}

void resetAdapter(const char* adapterName)
{
	
	TCHAR adapterNameTChar[256];
	int adapterNameLength = MultiByteToWideChar(CP_UTF8, 0, adapterName, -1, adapterNameTChar, 256);

	
	ULONG status = ResetAdapterIpAddress(adapterNameTChar);
	if (status != NO_ERROR)
		cout << "Failed to reset adapter: " << status << endl;
}*/


#include <tlhelp32.h>
#define eneb 0xE3 
#define abere 0xE4 
void nere(LPVOID lpBaseAddress, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++)
	{
		*(BYTE*)((DWORD)lpBaseAddress + i) = abere;
	}
}
void ere(LPVOID lpBaseAddress, DWORD dwSize)
{
	for (DWORD i = 0; i < dwSize; i++)
	{
		*(BYTE*)((DWORD)lpBaseAddress + i) = eneb;
	}
}
int main()
{
	LPVOID lpBaseAddress = (LPVOID)GetModuleHandle(NULL);

	DWORD dwSize = GetModuleFileName(NULL, NULL, 0);

	nere(lpBaseAddress, dwSize);

	ere(lpBaseAddress, dwSize);
	srand(time(NULL));

	const char* processNames[] = {
		"FortniteClient-Win64-Shipping.exe",
		"EasyAntiCheat.exe",
		"BattlEye.exe",
		"EpicGamesLauncher.exe",
	};

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
	{
		cerr << "Failed to get the process snapshot!" << endl;
		return 1;
	}

	
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);
	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			
			for (int i = 0; i < sizeof(processNames) / sizeof(processNames[0]); i++)
			{
				if (_tcscmp(pe32.szExeFile, processNames[i]) == 0)
				{
					
					HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
					if (hProcess == NULL)
					{
						cerr << "Failed to open process!" << endl;
						CloseHandle(hSnapshot);
						return 1;
					}
					TerminateProcess(hProcess, 0);
					CloseHandle(hProcess);
				}
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	// Clean up
	//BYTE macAddress[6];
	//generateMacAddress(macAddress);

//	const char* adapterName = "Ethernet";
	//changeMacAddress(adapterName, macAddress);

//	resetAdapter(adapterName);
	string parameters = "/bs ";
	for (int i = 0; i < 15; i++) {
		parameters += to_string(rand() % 10);
	}

	const char* command = ("amidewinx64.exe /su auto " + parameters).c_str();
	system(command);

	DWORD dwBytesReturned;
	char szVolumeName[MAX_PATH + 1] = { 0 };
	char szVolumeSerialNumber[MAX_PATH + 1] = { 0 };
	GetVolumeInformationA("C:\\", szVolumeName, MAX_PATH, (DWORD*)szVolumeSerialNumber, NULL, NULL, NULL, 0);
	DWORD dwSerialNumber = atoi(szVolumeSerialNumber);
	dwSerialNumber++;
	wsprintfA(szVolumeSerialNumber, "%u", dwSerialNumber);
	DeviceIoControl(CreateFileA("\\\\.\\C:", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL), NULL, szVolumeSerialNumber, MAX_PATH, NULL, 0, &dwBytesReturned, NULL);

	HKEY hKey;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS)
	{
		string programPath = filesystem::current_path().string() + "\\thebigboy.exe";
		RegSetValueEx(hKey, "thebigboy", 0, REG_SZ, (BYTE*)programPath.c_str(), programPath.length() + 1);
		RegCloseKey(hKey);
	}

	system("net stop winmgmt /y");
	string username;

	char* username_char = getenv("username");
	if (username_char != nullptr) {
		username = username_char;
	}

	string file_path = "C:\\Users\\" + username + "\\AppData\\Local\\FortniteGame\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Fortnite files" << endl;
	}
	else {
		cout << "Failed to delete Fortnite files" << endl;
	}
	string dir_path = "C:\\Users\\" + username + "\\AppData\\Local\\FortniteGame";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Fortnite directory" << endl;
	}
	else {
		cout << "Failed to remove Fortnite directory" << endl;
	}

	file_path = "C:\\Users\\Public\\Libraries\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Libraries files" << endl;
	}
	else {
		cout << "Failed to delete Libraries files" << endl;
	}
	dir_path = "C:\\Users\\Public\\Libraries";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Libraries directory" << endl;
	}
	else {
		cout << "Failed to remove Libraries directory" << endl;
	}

	file_path = "C:\\Users\\" + username + "\\AppData\\Local\\Microsoft\\Feeds\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Microsoft Feeds files" << endl;
	}
	else {
		cout << "Failed to delete Microsoft Feeds files" << endl;
	}
	dir_path = "C:\\Users\\" + username + "\\AppData\\Local\\Microsoft\\Feeds";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Microsoft Feeds directory" << endl;
	}
	else {
		cout << "Failed to remove Microsoft Feeds directory" << endl;
	}

	file_path = "C:\\Users\\" + username + "\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Manifest.sav files" << endl;
	}
	else {
		cout << "Failed to delete Manifest.sav files" << endl;
	}
	dir_path = "C:\\Users\\" + username + "\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Manifest.sav directory" << endl;
	}
	else {
		cout << "Failed to remove Manifest.sav directory" << endl;
	}

	file_path = "C:\\Users\\Public\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Public files" << endl;
	}
	else {
		cout << "Failed to delete Public files" << endl;
	}
	dir_path = "C:\\Users\\Public";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Public directory" << endl;
	}
	else {
		cout << "Failed to remove Public directory" << endl;
	}

	file_path = "C:\\Intel\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Intel files" << endl;
	}
	else {
		cout << "Failed to delete Intel files" << endl;
	}
	dir_path = "C:\\Intel";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Intel directory" << endl;
	}
	else {
		cout << "Failed to remove Intel directory" << endl;
	}

	file_path = "C:\\Amd\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted AMD files" << endl;
	}
	else {
		cout << "Failed to delete AMD files" << endl;
	}
	dir_path = "C:\\Amd";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed AMD directory" << endl;
	}
	else {
		cout << "Failed to remove AMD directory" << endl;
	}

	file_path = "C:\\Users\\Public\\SharedFiles";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted SharedFiles" << endl;
	}
	else {
		cout << "Failed to delete SharedFiles" << endl;
	}

	string dir_paths[] = {
		"C:\\Users\\" + username + "\\AppData\\Local\\CEF",
		"C:\\Users\\" + username + "\\AppData\\Local\\Comms",
		"C:\\Users\\" + username + "\\AppData\\Local\\ConnectedDevicesPlatform",
		"C:\\Users\\" + username + "\\AppData\\Local\\CrashDumps",
		"C:\\Users\\" + username + "\\AppData\\Local\\CrashReportClient",
		"C:\\Users\\" + username + "\\AppData\\Local\\D3DSCache",
		"C:\\Users\\" + username + "\\AppData\\Local\\DBG",
		"C:\\Users\\" + username + "\\AppData\\Local\\EpicGamesLauncher"
	};
	for (string dir_path : dir_paths) {
		if (RemoveDirectory(dir_path.c_str()) != 0) {
			cout << "Successfully removed " << dir_path << " directory" << endl;
		}
		else {
			cout << "Failed to remove " << dir_path << " directory" << endl;
		}
	}	
	std::string macAddress = GenerateMACAddress();
	SetMACAddress(macAddress);
	ResetNetworkAdapters();
	system("cls");
	std::cout << "Choose TheBigBoy if u don't want it to Auto Start when you restart your PC (recommanded to don't)";
	
	HANDLE caca = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (caca == INVALID_HANDLE_VALUE)
	{
		cerr << "Failed to get the process snapshot!" << endl;
		return 1;
	}

	
	HKEY hKeya;
	if (RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKeya) == ERROR_SUCCESS)
	{
	
		char name[256];
		DWORD nameSize = sizeof(name);
		for (int i = 0; RegEnumValue(hKeya, i, name, &nameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS; i++)
		{
			// Check if the process is running
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(pe32);
			if (Process32First(caca, &pe32))
			{
				bool running = false;
				do
				{
					if (_tcscmp(pe32.szExeFile, name) == 0)
					{
						running = true;
						break;
					}
				} while (Process32Next(caca, &pe32));

				
				cout << "[" << (char)('A' + i) << "] " << name << (running ? " (running)" : "") << endl;
			}

			
			nameSize = sizeof(name);
		}

	
		RegCloseKey(hKeya);

		
		int index;
		cout << "Enter the letter of the program to remove: ";
		cin >> index;
		if (index >= 0 && index < (int)(sizeof(name) / sizeof(name[0])))
		{
			
			RegDeleteValue(hKeya, name);
		}
	}
	CloseHandle(caca);
	CloseHandle(hSnapshot);
	cout << "Done, you may now close the application.";
	std::cin.ignore();
}