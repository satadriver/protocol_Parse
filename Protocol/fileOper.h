#pragma once


#include <windows.h>
#include <iostream>

using namespace std;

#define CRYPT_KEY_SIZE 16



class FileOper {
public:


	static int FileOper::fileWriter(string filename, const char * lpdate, int datesize, int cover);
	static	int FileOper::isFileExist(string filename);
	static	int FileOper::getFileSize(string filename);
	static	string FileOper::getDateTime();
	static	int FileOper::fileReader(string filename, char ** lpbuf, int *bufsize);
	static	int FileOper::fileWriter(string filename, const char * lpdate, int datesize);

	static DWORD GetCryptKey(unsigned char * pKey);
	static void CryptData(unsigned char * pdata, int size, unsigned char * pkey, int keylen);


};






















