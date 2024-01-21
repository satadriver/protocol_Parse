
#include "security.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>


using namespace std;

int  Security::isDebuggered ()
{
	return IsDebuggerPresent();
#ifndef _WIN64
	int result = 0;
	__asm
	{
		// 进程的PEB
		mov eax, fs:[30h]
		// 控制堆操作函数的工作方式的标志位
		mov eax, [eax + 68h]
		// 操作系统会加上这些标志位FLG_HEAP_ENABLE_TAIL_CHECK, 
		// FLG_HEAP_ENABLE_FREE_CHECK and FLG_HEAP_VALIDATE_PARAMETERS，
		// 它们的并集就是x70
		// 下面的代码相当于C/C++的
		// eax = eax & 0x70
		and eax, 0x70
		mov result, eax
	}

	return result != 0;
#else
	return IsDebuggerPresent();
#endif
}


int __stdcall Security::antiDebug() {
	while (1)
	{
		if (isDebuggered())
		{
			//MessageBoxA(0, "debuggered", "debuggered", MB_OK);
			ExitProcess(0);
		}

		Sleep(3000);
	}
}


int Security::loginCheck(int runmode,string &user,string &pass) {

	if (runmode == 3 || runmode == 4 || runmode == 2)
	{
		return TRUE;
	}

	char szuser[1024] = { 0 };
	if (user == "")
	{
		printf("please input username:");
		scanf("%s", szuser);
	}
	else {
		lstrcpyA(szuser, user.c_str());
	}

	char szpw[1024];
	if (pass == "")
	{
		printf("please input password:");
		scanf("%s", szpw);
	}
	else {
		lstrcpyA(szpw, pass.c_str());
	}


	string usrname = "";
	if (runmode == 1 || runmode == 3 || runmode == 4)
	{
		//usrname = G_USERNAME;

	}else if (runmode == 2)
	{
		//usrname = SERVER_USERNAME;
	}
	else {
		return FALSE;
	}
	
	string password = "123456";
	if (lstrcmpiA(szuser, usrname.c_str()) || lstrcmpiA(szpw, password.c_str()))
	{
		return FALSE;
	}

	user = usrname;
	pass = password;
	return TRUE;
}