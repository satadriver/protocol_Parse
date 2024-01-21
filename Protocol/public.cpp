

#include <winsock2.h>
#include <windows.h>
#include "HttpUtils.h"
#include <iostream>
#include "Public.h"
#include "protocol.h"
#include <time.h>

using namespace std;




string Public::getDateTime() {
	SYSTEMTIME sttime = { 0 };
	GetLocalTime(&sttime);

	char sztime[MAX_PATH] = { 0 };
	int len = wsprintfA(sztime, "%u/%u/%u %u:%u:%u", sttime.wYear, sttime.wMonth, sttime.wDay, sttime.wHour, sttime.wMinute, sttime.wSecond);
	return string(sztime);
}

DWORD Public::GetLocalIpAddress()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData = { 0 };
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
	{
		return FALSE;
	}

	char local[MAX_PATH] = { 0 };
	int iRet = gethostname(local, sizeof(local));
	if (iRet)
	{
		return FALSE;
	}
	hostent* ph = gethostbyname(local);
	if (ph == NULL)
	{
		return FALSE;
	}

	in_addr addr = { 0 };
	memcpy(&addr, ph->h_addr_list[0], sizeof(in_addr));
	if (addr.S_un.S_addr == 0)
	{
		return FALSE;
	}

	char szip[MAX_PATH] = { 0 };
	unsigned char cip[4] = { 0 };
	memmove(cip, &addr.S_un.S_addr, 4);
	int ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);
	printf("get ip from hostname:%s\r\n", szip);

	return addr.S_un.S_addr;
}


string Public::winPath2Linux(const char * winpath) {
	char linuxpath[1024];
	lstrcpyA(linuxpath, winpath);

	for (int i = 0; i < lstrlenA(winpath); i++)
	{
		if (winpath[i] == '\\')
		{
			linuxpath[i] = '/';
		}
	}

	return string(linuxpath);
}

string Public::getpath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\";
}




string Public::getUserUrl(string username, string filename) {

	char buf[1024] = { 0 };
	buf[0] = '/';
	lstrcatA(buf, username.c_str());
	lstrcatA(buf, "/");
	lstrcatA(buf, filename.c_str());
	return string(buf);
	//string path = string("/").append(username).append("/").append(filename);
	//return path;
	//string path = (string("/") + username + string("/") + string(filename));
	//return path;
}


string gDataPath = "";

string Public::getDataPath() {
	if (gDataPath == "")
	{
		char szcurdir[MAX_PATH] = { 0 };
		int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
		gDataPath = string(szcurdir) + "\\" + "output" + "\\";
		
	}
	return gDataPath;
}

string Public::getConfigPath() {
	char szcurdir[MAX_PATH] = { 0 };
	int ret = GetCurrentDirectoryA(MAX_PATH, szcurdir);
	return string(szcurdir) + "\\" + "config" + "\\";
}

int Public::WriteDataFile(char * szFileName, unsigned char * strBuffer, int iCounter, char * tag)
{
	string fn = getDataPath() + szFileName;
	int iRet = 0;
	FILE * fpFile = 0;
	iRet = fopen_s(&fpFile, fn.c_str(), "ab+");
	if (fpFile > 0)
	{
		iRet = fwrite(tag, 1, lstrlenA(tag), fpFile);
		iRet = fwrite(strBuffer, 1, iCounter, fpFile);
		fclose(fpFile);
		if (iRet != iCounter)
		{
			printf("写文件:%s错误\n", szFileName);
			return FALSE;
		}
		return TRUE;
	}
	else
	{
		printf("打开文件:%s错误\n", szFileName);
		return FALSE;
	}
	return FALSE;
}


DWORD Public::WriteDataFile(const char * pFileName, const char * pData, DWORD dwDataSize)
{
	string fn = getDataPath() + pFileName;
	HANDLE hFile = CreateFileA(fn.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile, 0, 0, FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int iRet = WriteFile(hFile, pData, dwDataSize, &dwCnt, 0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != dwDataSize)
	{
		return FALSE;
	}

	return TRUE;
}



DWORD Public::WriteLogFile(const char * pData)
{
	string fn = getDataPath() + LOG_FILENAME;
	HANDLE hFile = CreateFileA(fn.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	DWORD dwCnt = SetFilePointer(hFile, 0, 0, FILE_END);
	if (dwCnt == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	int len = lstrlenA(pData);
	int iRet = WriteFile(hFile, pData, len, &dwCnt, 0);
	CloseHandle(hFile);
	if (iRet == 0 || dwCnt != len)
	{
		return FALSE;
	}

	return TRUE;
}


;





int Public::removespace(char * src, char * dst)
{
	int len = strlen(src);
	int i = 0, j = 0;
	for (; i < len; i++) {
		if (src[i] == ' ' || src[i] == 0x9) {
			continue;
		}
		else {
			dst[j] = src[i];
			j++;
		}
	}
	*(dst + j) = 0;
	return j;
}





DWORD Public::checkInstanceExist()
{
	HANDLE hMutex = CreateMutexA(NULL, TRUE, SERVER_MUTEX_NAME);
	DWORD dwRet = GetLastError();
	if (hMutex)
	{
		if (ERROR_ALREADY_EXISTS == dwRet)
		{
			printf("mutex already exist,please shutdown the program and run one instance\r\n");
			CloseHandle(hMutex);
			return FALSE;
		}
		else
		{
			printf("program start running\r\n");
			return (DWORD)hMutex;
		}
	}
	else {
		printf("CreateMutexA error\r\n");
		return FALSE;
	}
}


int Public::hex2str(const unsigned char * hex, int len, int lowercase, unsigned char * str) {

	int casevalue = 55;
	if (lowercase)
	{
		casevalue = 87;
	}

	int j = 0;
	int i = 0;
	for (i = 0, j = 0; i < len; i++)
	{
		unsigned char c = hex[i];

		unsigned char c1 = c >> 4;
		if (c1 >= 0 && c1 <= 9)
		{
			c1 += 0x30;
		}
		else {
			c1 += casevalue;		//uppercase is 55,87 is lowercase
		}

		unsigned char c2 = c & 0xf;
		if (c2 >= 0 && c2 <= 9)
		{
			c2 += 0x30;
		}
		else {
			c2 += casevalue;
		}

		str[j++] = c1;
		str[j++] = c2;
	}

	return j;
}


VOID GetCompileTime(LPSYSTEMTIME lpCompileTime)
{
	string ret = __TIMESTAMP__;

	char Mmm[4] = { 0 };
	sscanf_s(__DATE__, "%3s %hu %hu", Mmm, sizeof(Mmm),&lpCompileTime->wDay, &lpCompileTime->wYear);
	Mmm[3] = Mmm[2]; 
	Mmm[2] = Mmm[0]; 
	Mmm[0] = Mmm[3]; 
	Mmm[3] = 0;

	switch (*(DWORD*)Mmm) {
	case (DWORD)('Jan') : 
		lpCompileTime->wMonth = 1; 
		break;
	case (DWORD)('Feb') : 
		lpCompileTime->wMonth = 2; 
		break;
	case (DWORD)('Mar') : 
		lpCompileTime->wMonth = 3; 
		break;
	case (DWORD)('Apr') : 
		lpCompileTime->wMonth = 4; 
		break;
	case (DWORD)('May') : 
		lpCompileTime->wMonth = 5; 
		break;
	case (DWORD)('Jun') : 
		lpCompileTime->wMonth = 6; 
		break;
	case (DWORD)('Jul') : 
		lpCompileTime->wMonth = 7; 
		break;
	case (DWORD)('Aug') : 
		lpCompileTime->wMonth = 8; 
		break;
	case (DWORD)('Sep') : 
		lpCompileTime->wMonth = 9; 
		break;
	case (DWORD)('Oct') : 
		lpCompileTime->wMonth = 10; 
		break;
	case (DWORD)('Nov') : 
		lpCompileTime->wMonth = 11; 
		break;
	case (DWORD)('Dec') : 
		lpCompileTime->wMonth = 12; 
		break;
	default:lpCompileTime->wMonth = 0;
	}
	sscanf_s(__TIME__, "%hu:%hu:%hu", &lpCompileTime->wHour,&lpCompileTime->wMinute, &lpCompileTime->wSecond);

	lpCompileTime->wDayOfWeek = lpCompileTime->wMilliseconds = 0;
}

#define DURATION_VALID 86400*30

string Public::GetInetIPAddress() {

	int ret = 0;

	string ip = "";

	char * httprequest = \
		"GET / HTTP/1.1\r\n"\
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"\
		"Accept-Language: zh-CN\r\n"\
		"Upgrade-Insecure-Requests: 1\r\n"\
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36 Edge/16.16299\r\n"
		"Accept-Encoding: gzip, deflate\r\n"\
		"Host: api.ipify.org\r\n"\
		"Connection: Keep-Alive\r\n\r\n";

		//http://icanhazip.com/
	hostent * pHostent = gethostbyname("api.ipify.org");
	if (pHostent == 0)
	{
		return ip;
	}

	ULONG  pPIp = *(DWORD*)((CHAR*)pHostent + sizeof(hostent) - sizeof(DWORD_PTR));
	ULONG  pIp = *(ULONG*)pPIp;
	DWORD dwip = *(DWORD*)pIp;

	sockaddr_in stServSockAddr = { 0 };
	stServSockAddr.sin_addr.S_un.S_addr = dwip;
	stServSockAddr.sin_port = ntohs(HTTP_PORT);
	stServSockAddr.sin_family = AF_INET;

	SOCKET hSock = socket(AF_INET, SOCK_STREAM, 0);
	if (hSock == INVALID_SOCKET)
	{
		return ip;
	}

	ret = connect(hSock, (sockaddr*)&stServSockAddr, sizeof(sockaddr_in));
	if (ret == INVALID_SOCKET)
	{
		closesocket(hSock);
		return ip;
	}

	ret = send(hSock, httprequest, lstrlenA(httprequest), 0);
	if (ret <= 0)
	{
		closesocket(hSock);
		return ip;
	}

	char buf[1024];
	int recvlen = recv(hSock, buf, 1024, 0);
	closesocket(hSock);
	if (recvlen <= 0 || recvlen >= 1024)
	{
		return ip;
	}
	*(UINT*)(buf + recvlen) = 0;

	char * p = strstr(buf, "\r\n\r\n");
	if (p)
	{
		p += lstrlenA("\r\n\r\n");
		ip = string(p);
	}

	SYSTEMTIME stlt = { 0 };
	GetCompileTime(&stlt);
	tm tmlast = { 0 };
	tmlast.tm_year = stlt.wYear - 1900;
	tmlast.tm_mon = stlt.wMonth-1;
	tmlast.tm_mday = stlt.wDay;
	tmlast.tm_hour = stlt.wHour;
	tmlast.tm_min = stlt.wMinute;
	tmlast.tm_sec = stlt.wSecond;
	time_t timelast = mktime(&tmlast) - 8*3600;

	tm tmnow = HttpUtils::gettimefromhttp(buf);
	time_t timenow = mktime(&tmnow);

	if (timenow - timelast > DURATION_VALID)
	{
#ifdef NDEBUG
		Public::WriteLogFile("out of date\r\n");
		ExitProcess(0);
#endif
	}
	return ip;
}