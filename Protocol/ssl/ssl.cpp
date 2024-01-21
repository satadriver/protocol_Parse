
#include "ssl.h"
#include <WinSock2.h>
#include "../ProtocolParser.h"
#include "../ResultFile.h"
#include "../fileOper.h"
#include "../http/http.h"


vector<DNSSSL_REGULATION> gSslNames;

int SSL::getServerNameFromClientHello(char * data, int len, char * servername, int & version) {

	SSLHEADER * lphdr = (LPSSLHEADER)data;

	//check ssl client hello length
	int sslhellolen = ntohs(lphdr->hdrlen);
	if (sslhellolen + 5 != len)
	{
		printf("ssl client hello header length:%u,size:%u\r\n", len, sslhellolen);
		return -1;		//ip segment packet,need to wait
	}

	char * ciphersuit = data + sizeof(SSLHEADER) + lphdr->sessionidlen;
	int cipherlen = ntohs(*(short*)ciphersuit);
	if (cipherlen >= len || cipherlen <= 0)
	{
		printf("ssl client hello cipher suit length error\r\n");
		return -1;
	}

	char * compress = ciphersuit + sizeof(short) + cipherlen;
	int comppresslen = *compress;
	if (comppresslen < 0)
	{
		printf("ssl client hello comppress methods length error\r\n");
		return -1;
	}

	char * lpexthdr = compress + sizeof(char) + comppresslen;
	int extlen = ntohs(*(short*)lpexthdr);
	int extbefore = lpexthdr - data + sizeof(short);
	if (extbefore + extlen != len)
	{
		printf("client hello extensions length:%u,ext before length:%u,client hello length:%u\r\n", extlen, extbefore, len);
		return -1;
	}

	LPSSLHEADER_EXTENSIONS lpext = (LPSSLHEADER_EXTENSIONS)(lpexthdr + sizeof(short));
	while (1)
	{
		if (lpext->exttype == 0)
		{
			LPCLIENTHELLO_SERVERNAME lpserver = (LPCLIENTHELLO_SERVERNAME)lpext;
			if (lpserver->servernametype == 0)
			{
				int servernamelen = ntohs(lpserver->sernamelen);
				if (servernamelen >= MAX_PATH || servernamelen <= 0)
				{
					printf("ssl client hello host name length:%u error\r\n", servernamelen);
					return -1;
				}
				char * lpservername = (char*)((unsigned int)lpserver + sizeof(CLIENTHELLO_SERVERNAME));
				memcpy(servername, lpservername, servernamelen);
				*(servername + servernamelen) = 0;
				return TRUE;
			}
		}

		int extblocksize = sizeof(SSLHEADER_EXTENSIONS) + ntohs(lpext->typelen);
		if (extblocksize >= len || extblocksize <= 0)
		{
			printf("client hello extensions block size error\r\n");
			return -1;
		}
		lpext = (LPSSLHEADER_EXTENSIONS)((unsigned int)lpext + extblocksize);
		if ((int)lpext - (int)data >= len)
		{
			break;
		}
	}

	return FALSE;
}

int SSL::processSSL(DATALISTHEADER hdr) {
	char szhost[256];
	int ver = 0;
	int ret = 0;
	ret = getServerNameFromClientHello(hdr.datalist->data, hdr.sizelist->size, szhost, ver);
	if (ret > 0)
	{
		for (unsigned int i =0;i < gSslNames.size();i ++)
		{
			if (lstrcmpiA(szhost, gSslNames[i].host.c_str()) == 0)
			{
				ResultFile::writeRecord(hdr, gSslNames[i].pro, "on", szhost);
			}
		}	
	}

	return TRUE;
}

int SSL::isSSL(DATALISTHEADER hdr) {
	if ( hdr.sock.protocol == IPPROTO_TCP)
	{
		SSLHEADER * lphdr = (LPSSLHEADER)hdr.datalist->data;
		if (lphdr->contenttype == 0x16 && lphdr->handshaketype == 1)
		{
			int mainver = lphdr->version & 0xff;
			int subver = (lphdr->version & 0xff00) >> 8;

			int handshakemainver = lphdr->handshakever & 0xff;
			int handshakesubver = (lphdr->handshakever) >> 8;
			if (mainver == 3 && handshakemainver == 3)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

int SSL::init(vector<DNSSSL_REGULATION> sslnames) {
	
	gSslNames = sslnames;

	return 0;
}


