#pragma once


#include <windows.h>
#include <iostream>
#include "Packet.h"

using namespace std;

class HttpUtils {
public:
	static int getContentLen(string lphttpdata, int len);

	static bool isAscIP(string ip);

	static string getValueFromKey(const char * lphttphdr, string & key);

	static string HttpUtils::getValueFromKeyWithoutSpace(const char * lphttphdr, string & searchkey);

	static string getHttpHeader(const char* lphttpdata, int len,char ** data);

	static string HttpUtils::getFullUrl(const char * lppacket, int len);

	static string HttpUtils::getShortUrl(const char * lppacket);

	static string HttpUtils::getPureUrl(const char * lppacket, int len);

	static int checkHttpHdrEntity(const char * data, int len, int &httptype);


	static int isHttpPacket(const char * lpdata);

	static int isHttpConnect(const char * lpdata);

	static int parseHttpProxy(const char * lpdata, string &host, unsigned short &port,string & url);

	
	static int HttpUtils::getRange(const char * httphdr, int & begin, int & end);

	static string getIPstr(unsigned long ulIP);

	static string HttpUtils::getIPv6str(unsigned char ipv6[]);

	static string HttpUtils::getIPPortStr(unsigned long ulIP, int port);

	static string HttpUtils::host2Dns(string host);

	static string dns2Host(char * dns);

	static string getmacstr(unsigned char *mac);

	static tm HttpUtils::gettimefromhttp(string httpresponse);
};