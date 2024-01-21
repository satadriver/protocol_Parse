#pragma once
#include <windows.h>
#include <iostream>

#define MAC_ADDRESS_SIZE 6

using namespace std;

#define SERVER_MUTEX_NAME "protocol.exe"

class Public {
public:



	

	static DWORD GetLocalIpAddress();

	static int WriteDataFile(char * szFileName, unsigned char * strBuffer, int iCounter, char * tag);

	static DWORD Public::WriteDataFile(const char * pFileName, const char * pData, DWORD dwDataSize);

	static DWORD WriteLogFile(const char * pData);


	static int removespace(char * src, char * dst);

	static string Public::getpath();

	static string Public::getUserUrl(string username, string filename);

	static string Public::getDateTime();

	static DWORD Public::checkInstanceExist();

	static int Public::hex2str(const unsigned char * hex, int len, int lowercase, unsigned char * str);

	static string winPath2Linux(const char * winpath);

	static string Public::getDataPath();

	static string Public::getConfigPath();

	static string Public::GetInetIPAddress();
};