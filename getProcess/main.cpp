
#include "CHandleLook.h"
#include <windows.h>
#include <iostream>
#include <map>
#include <TlHelp32.h>



using namespace std;



//#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004



bool traverseProcesses(std::map<std::string, int>& pnameID) {

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(pe32); 	
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);	
	if (hProcessSnap == INVALID_HANDLE_VALUE) { 
		std::cout << "CreateToolhelp32Snapshot Error!" << std::endl;;		
		return false; 
	} 	

	BOOL bResult = Process32First(hProcessSnap, &pe32); 	
	while (bResult) {

		char szpname[1024] = { 0 };
		WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, wcslen(pe32.szExeFile), szpname, 1024, 0, 0);
		std::string name = szpname;		

		int id = pe32.th32ProcessID; 		
		//std::cout << "[" << ++num << "] : " << "Process Name:" << name << "  " << "ProcessID:" << id << std::endl; 		
		pnameID.insert(std::pair<string, int>(name, id)); //×Öµä´æ´¢		
		bResult = Process32Next(hProcessSnap,&pe32);	
	} 	
	CloseHandle(hProcessSnap); 	
	return true;
}



int main() {

	int result = 0;
	//SYNCHRONIZE
	HANDLE my = OpenMutexA(0x100000, 0, "Global\\{D390F0C7-BDBA-4fd2-B58D-146D5175334E}");
	if (my)
	{
		result = CloseHandle(my);
	}
	else {
		return 0;
	}

	std::map<std::string, int> processinfo;
	boolean ret = traverseProcesses(processinfo);
	if (ret )
	{
		CHandleLook handlelook;
		handlelook.Init(); 

		handlelook.GetObjectFormHandle(my);

 		std::map<std::string, int> ::iterator it;
 		for (it = processinfo.begin(); it != processinfo.end(); it++)
 		{
 		}
	}

	return 0;
}