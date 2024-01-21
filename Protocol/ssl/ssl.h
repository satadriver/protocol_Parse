#pragma once

#include "../DataList.h"
#include <vector>
#include <iostream>
#include "../http/http.h"
using namespace std;

#pragma pack(1)

typedef struct
{
	unsigned char version;
	unsigned char length;
	unsigned char type;
	unsigned short ver;
	unsigned short cipherSpecLen;
	unsigned short sessionIdLen;
	unsigned short challengeLen;
}RESSLHEADER, *LPRESSLHEADER;

typedef struct
{
	unsigned char contenttype;
	unsigned short version;
	unsigned short hdrlen;

	unsigned char handshaketype;
	unsigned char handshakelen[3];
	unsigned short handshakever;

	unsigned int unixtime;
	unsigned char randombytes[28];

	unsigned char sessionidlen;

	//	unsigned char [] sessionid;
	// 	unsigned char cmlen;
	// 	unsigned char compressmethod;
}SSLHEADER, *LPSSLHEADER;


typedef struct {
	//	unsigned short extlen;
	unsigned short exttype;
	unsigned short typelen;
}SSLHEADER_EXTENSIONS, *LPSSLHEADER_EXTENSIONS;;

typedef struct
{
	unsigned short exttype;
	unsigned short typelen;

	unsigned short sernamelistlen;
	unsigned char servernametype;
	unsigned short sernamelen;
}CLIENTHELLO_SERVERNAME, *LPCLIENTHELLO_SERVERNAME;

#pragma pack()



class SSL {
public:
	static int init(vector<DNSSSL_REGULATION>sslnames);

	static int SSL::getServerNameFromClientHello(char * data, int len, char * servername, int & version);
	static int processSSL(DATALISTHEADER hdr);

	static int isSSL(DATALISTHEADER hdr);
};