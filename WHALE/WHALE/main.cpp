#include <Windows.h>
#include <iostream>
#include <string>
#include "NewSection.h"
#include <time.h>



void DeleteDirectory(char* strPath)
{
	SHFILEOPSTRUCTA strOper = { 0 };
	strOper.hwnd = NULL;
	strOper.wFunc = FO_DELETE;
	strOper.pFrom = strPath;
	strOper.fFlags = FOF_SILENT | FOF_NOCONFIRMATION;

	if (SHFileOperationA(&strOper)) {
		std::cout << "[!] Unicode directory deletion problem" << std::endl;
	}
}

bool directoryExists(const std::string& dirName)
{
	DWORD fileType = GetFileAttributesA(dirName.c_str());
	if (fileType == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	if (fileType & FILE_ATTRIBUTE_DIRECTORY) {
		return true;
	}
	return false;
}

void clearDirectory() {
	char removedDir1[MAX_PATH] = { 0 };
	char removedDir2[MAX_PATH] = { 0 };
	sprintf(removedDir1, "%sx64\\JustLoader\\", SOLUTIONDIR);
	sprintf(removedDir2, "%HuanLoader\\x64\\", SOLUTIONDIR);
	if (directoryExists(removedDir1)) {
		DeleteDirectory(removedDir1);
	}
	if (directoryExists(removedDir2)) {
		DeleteDirectory(removedDir2);
	}
}

char* compileLoader() {
	clearDirectory();
	const char* vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	//getting the directory of visual studio [it changes cz of what version && what copy]
	//for ex, this was the output on my machine: C:\Program Files (x86)\Microsoft Visual Studio\2019\Community

	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char fullCommand[MAX_PATH] = { 0 };
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			//Remove new line
			compilerPath[strlen(compilerPath) - 1] = '\0';
			//compiling HuanLoader using vs command line:
			sprintf(fullCommand, "\"\"%s\\MSBuild\\Current\\Bin\\MSBuild.exe\" %s\\WHALE.sln /t:HuanLoader /property:Configuration=JustLoader /property:RuntimeLibrary=MT\"\n", compilerPath, SOLUTIONDIR);
			FILE* pipe2 = _popen(fullCommand, "rt");
			_pclose(pipe2);
			char* loaderBinaryPath = (char*)malloc(MAX_PATH);
			sprintf(loaderBinaryPath, "%sx64\\JustLoader\\HuanLoader.exe", SOLUTIONDIR);
			if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(loaderBinaryPath) && GetLastError() == ERROR_FILE_NOT_FOUND) {
				std::cout << "[!] Compiled binary not found!" << std::endl;
				free(loaderBinaryPath);
				return NULL;
			}
			else {
				return loaderBinaryPath;
			}
		}
		else {
			std::cout << "[!] Visual Studio compiler path is not found! " << std::endl;
			return NULL;
		}
		_pclose(pipe);
		return NULL;
	}
	return NULL;
}



int main(int argc, char* argv[]) {
	//printBanner();

	if (argc != 2) {
		std::cout << "\t[+] Usage: " << argv[0] << " <exe path> " << std::endl << std::endl;
		system("PAUSE");
		return -1;
	}
	srand(time(NULL));
	size_t fileSize = 0;
	//reading the content of our binary file 
	char* binaryContent = readBinary(argv[1], &fileSize);
	if (binaryContent == NULL || fileSize == 0) {
		std::cout << "[!] Error on reading the exe file !" << std::endl;
		return 0;
	}
	std::cout << "\n\t[+] " << argv[1] << " is reading ..." << std::endl;
	size_t newFileSize = 0;
	//compiling the loader.
	char* loaderPath = compileLoader();
	size_t loaderSize = 0;
	if (loaderPath == NULL) {
		std::cout << std::endl << "[!] Error on compiling loader !" << std::endl;
		return 0;
	}
	//loaderContent is the readed part from the loader with loaderPath and loaderSize
	char* loaderContent = readBinary(loaderPath, &loaderSize);
	std::cout << "\t[+] DONE !" << std::endl;
	//creating new binary, with loaderContent and encrypting binaryContent 
	char* newBinary = createNewSectionHeader(loaderContent, (unsigned char*)binaryContent, fileSize, &newFileSize);
	if (newBinary == NULL) {
		std::cout << std::endl << "[!] Error on adding a new section header !" << std::endl;
		return 0;
	}
	std::cout << "\t[+] ADDING THE DECODING HEADERS ...." << std::endl;
	//saving the newBinary under the name of ENCargv[1] .
	char NewName[150];
	strcpy(NewName, "Enc");
	strcat(NewName, argv[1]);
	printf("\t[+] Saving as: %s \n", NewName);

	bool returnResult = saveNewPE(newBinary, newFileSize, NewName);
	std::cout << "\t[+] DONE !" << std::endl;

	//freenig allocated contents from the binary and from the loader [with the path]
	clearDirectory();
	if (returnResult) {
		std::cout << "\t[+] encrypted file is created as " << NewName << std::endl;
	}
	delete[] binaryContent;
	delete[] loaderContent;
	free(loaderPath);
	return 0;
}