

#include "FileOper.h"
#include <time.h>
#include "Shlwapi.h"

#pragma comment( lib, "Shlwapi.lib")


unsigned char gkey[CRYPT_KEY_SIZE];


int FileOper::isFileExist(string filename) {

	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		return FALSE;
	}
	else {
		fclose(fp);
		return TRUE;
	}
}


int FileOper::getFileSize(string filename) {
	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		return FALSE;
	}

	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);

	fclose(fp);
	return filesize;
}



string FileOper::getDateTime() {

	time_t t = time(NULL);

	char ch[MAX_PATH] = { 0 };

	strftime(ch, sizeof(ch) - 1, "%Y-%m-%d %H:%M:%S", localtime(&t));

	return ch;
}



int FileOper::fileReader(string filename, char ** lpbuf, int *bufsize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "rb");
	if (fp <= 0)
	{
		printf("fileReader fopen file:%s error\r\n", filename.c_str());
		return FALSE;
	}

	ret = fseek(fp, 0, FILE_END);

	int filesize = ftell(fp);

	ret = fseek(fp, 0, FILE_BEGIN);

	*bufsize = filesize;

	*lpbuf = new char[filesize + 1024];

	ret = fread(*lpbuf, 1, filesize, fp);
	fclose(fp);
	if (ret <= FALSE)
	{
		delete lpbuf;
		return FALSE;
	}

	*(*lpbuf + filesize) = 0;
	return filesize;
}



int FileOper::fileWriter(string filename, const char * lpdate, int datesize) {
	int ret = 0;

	FILE * fp = fopen(filename.c_str(), "ab+");
	if (fp <= 0)
	{
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}


int FileOper::fileWriter(string filename, const char * lpdate, int datesize, int cover) {
	int ret = 0;

	FILE * fp = 0;
	if (cover) {
		fp = fopen(filename.c_str(), "wb");
	}
	else {
		fp = fopen(filename.c_str(), "ab+");
	}

	if (fp <= 0)
	{
		return FALSE;
	}

	ret = fwrite(lpdate, 1, datesize, fp);
	fclose(fp);
	if (ret == FALSE)
	{
		return FALSE;
	}

	return datesize;
}


DWORD FileOper::GetCryptKey(unsigned char * pKey)
{
	SYSTEMTIME stSystime = { 0 };
	GetSystemTime(&stSystime);

	DWORD dwTickCnt[CRYPT_KEY_SIZE / sizeof(DWORD)] = { 0 };
	for (int i = 0; i < CRYPT_KEY_SIZE / sizeof(DWORD); i++)
	{
		dwTickCnt[i] = GetTickCount();
	}

	unsigned char * pSystemTime = (unsigned char*)&stSystime;
	unsigned char * pTickCnt = (unsigned char*)dwTickCnt;
	for (int j = 0; j < CRYPT_KEY_SIZE; j++)
	{
		pKey[j] = pSystemTime[j] ^ pTickCnt[j];
	}

	for (int i = 0; i < CRYPT_KEY_SIZE; i++)
	{
		if (pKey[i] >= 0x80)
		{
			pKey[i] = pKey[i] - 0x80;
		}
	}

	return TRUE;
}






void FileOper::CryptData(unsigned char * pdata, int size, unsigned char * pkey, int keylen) {

	for (int i = 0, j = 0; i < size;)
	{
		pdata[i] ^= pkey[j];
		j++;
		if (j == keylen)
		{
			j = 0;
		}
		i++;
	}
}

