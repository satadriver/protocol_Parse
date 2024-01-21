
#include "HttpUtils.h"
#include <time.h>
#include <iostream>
#include <vector>
#include "Packet.h"
#include "Public.h"


using namespace std;

int HttpUtils::isHttpConnect(const char * lpdata) {
	if (memcmp(lpdata, "CONNECT ", 8) == 0)
	{
		return 8;
	}
	return 0;
}

int HttpUtils::isHttpPacket(const char * lpdata) {

	//HTTP 1.0
	if (memcmp(lpdata, "POST ", 5) == 0) {
		return 5;
	}else if (memcmp(lpdata, "GET ", 4) == 0)
	{
		return 4;
	}else if (memcmp(lpdata, "HEAD ", 5) == 0)
	{
		return 5;
	}
	//HTTP 1.1
	else if (memcmp(lpdata, "PUT ", 4) == 0)
	{
		return 4;
	}else if (memcmp(lpdata, "CONNECT ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "OPTIONS ", 8) == 0)
	{
		return 8;
	}
	else if (memcmp(lpdata, "DELETE ", 7) == 0)
	{
		return 7;
	}
	else if (memcmp(lpdata, "TRACE ", 6) == 0)
	{
		return 6;
	}
	
	return FALSE;
}




string HttpUtils::getValueFromKey(const char * lphttphdr, string & searchkey) {

	string key = "\r\n" + searchkey + ": ";
	char * phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char * pend = strstr(phdr, "\r\n");
		int len = pend - phdr;
		if (pend && len > 0 && len < 256)
		{
			string value = string(phdr, len);
			return value;
		}
	}

	return "";
}


string HttpUtils::getValueFromKeyWithoutSpace(const char * lphttphdr, string & searchkey) {

	string key = "\r\n" + searchkey + ":";
	char * phdr = strstr((char*)lphttphdr, key.c_str());
	if (phdr)
	{
		phdr += key.length();
		char * pend = strstr(phdr, "\r\n");
		int len = pend - phdr;
		if (pend && len > 0 && len < 256)
		{
			string value = string(phdr, len);
			return value;
		}
	}

	return "";
}




int HttpUtils::getContentLen(string httphdr, int len) {
	string contentlen = getValueFromKey(httphdr.c_str(), string("Content-Length"));
	int cl = strtoul(contentlen.c_str(), 0, 10);
	return cl;
}


bool HttpUtils::isAscIP(string ip) {
	DWORD j = 0;
	for (j = 0; j < ip.length(); j++)
	{
		if ((ip.at(j) >= '0' && ip.at(j) <= '9') || ip.at(j) == '.')
		{
			continue;
		}
		else {
			break;
		}
	}

	if (j == ip.length())
	{
		return true;
	}

	return false;
}





int HttpUtils::checkHttpHdrEntity(const char * data, int datalen,int & type) {

	int ret = 0;

	int len = isHttpPacket(data);
	if (len <= 0)
	{
		type = 0;
		return -1;
	}

	if (isHttpConnect(data))
	{
		type = 4;
		return TRUE;
	}
	else if (memcmp(data + len, "http://", 7) == 0)
	{
		type = 2;
	}
	else if (memcmp(data + len, "https://", 8) == 0)
	{
		type = 3;
	}
	else {
		type = 1;
	}

	//connect Ò²ÊÇ\r\n\r\n½áÎ²
	char * httpend = strstr((char*)data, "\r\n\r\n");
	if (httpend <= 0)
	{
		return FALSE;
	}
	else {
		return TRUE;
	}
	
}



int HttpUtils::parseHttpProxy(const char * lpdata, string &host, unsigned short &port, string & url) {
	char szout[4096];
	int len = isHttpPacket(lpdata);
	if (len <= 0)
	{
		return -1;
	}

	string strhost = string(lpdata + len);

	if (memcmp(strhost.c_str(), "http://", 7) == 0)
	{
		strhost = strhost.substr(7);
	}
	else if (memcmp(strhost.c_str(), "https://", 8) == 0)
	{
		strhost = strhost.substr(8);
	}
	else if (isHttpConnect(lpdata))
	{
		//connect without http:// or https://,but with :443 or :80
	}
	else {
		return FALSE;
	}

	int pos = 0;
	pos = strhost.find(" HTTP/1.1");
	if (pos >= 0)
	{
		strhost = strhost.substr(0, pos);
	}
	else {
		pos = strhost.find(" HTTP/1.0");
		if (pos >= 0)
		{
			strhost = strhost.substr(0, pos);
		}
		else {
			wsprintfA(szout, "parse proxy packet error:%s\r\n", strhost.c_str());
			Public::WriteLogFile(szout);
			//return FALSE;
		}
	}

	pos = strhost.find("/");
	if (pos > 0)
	{
		url = strhost.substr(pos);
		strhost = strhost.substr(0, pos);
	}

	pos = strhost.find("?");
	if (pos > 0)
	{
		strhost = strhost.substr(0, pos);
	}

	pos = strhost.find(":");
	if (pos >= 0)
	{
		string strport = strhost.substr(pos + 1);
		port = atoi(strport.c_str());
		strhost = strhost.substr(0, pos);
	}


	host = strhost;

	return TRUE;
}



string HttpUtils::getHttpHeader(const char * data, int len,char ** lphttpdata) {
	int ret = isHttpPacket(data);
	if (ret <= 0)
	{
		return "";
	}

	char * lphdr = strstr((char*)data, "\r\n\r\n");
	if (lphdr <= FALSE)
	{
		*lphttpdata = 0;
		return string(data);
	}

	lphdr += 4;
	string httphdr = string(data, lphdr - data);
	*lphttpdata = lphdr;
	return httphdr;
}


string HttpUtils::getFullUrl(const char * lppacket, int len) {
	string url = "";

// 	char * flag = strstr((char*)lppacket, "?");
// 	if (flag)
// 	{
// 		int len = flag + 1 - lppacket;
// 		url = string(lppacket, len);
// 		return url;
// 	}

	char * lphdr = strstr((char*)lppacket, " HTTP/1.1\r\n");
	if (lphdr)
	{
		int urllen = lphdr - lppacket;
		url = string(lppacket, urllen);
	}
	else {
		lphdr = strstr((char*)lppacket, " HTTP/1.0\r\n");
		if (lphdr)
		{
			int urllen = lphdr - lppacket;
			url = string(lppacket, urllen);
		}
	}
	
	return url;
}


//end with ?
string HttpUtils::getShortUrl(const char * lppacket) {
	string url = "";

	char * flag = strstr((char*)lppacket, "?");
	if (flag)
	{
		int len = flag + 1 - lppacket;
		url = string(lppacket, len);
	}
	else {
		url = lppacket;
	}
	 
	return url;
}

//end without ?
string HttpUtils::getPureUrl(const char * lppacket, int len) {
	string url = "";

	int offset = isHttpPacket(lppacket);
	if (offset <= 0)
	{
		return url;
	}

	const char *packhdr = lppacket + offset;

	char * lphdr = strstr((char*)packhdr, " HTTP/1.1\r\n");
	if (lphdr)
	{
		int urllen = lphdr - packhdr;
		url = string(packhdr, urllen);
	}
	else {
		lphdr = strstr((char*)packhdr, " HTTP/1.0\r\n");
		if (lphdr)
		{
			int urllen = lphdr - packhdr;
			url = string(packhdr, urllen);
		}
	}

	int pos = url.find("?");
	if ( pos != -1)
	{
		url = url.substr(0, pos);
	}

	pos = url.find("&");
	if (pos != -1)
	{
		url = url.substr(0, pos);
	}
	return url;
}

/*
vector<string> getParamFromUrl(string url) {
	vector<string> ret;
	int pos = url.find("?");
	if (pos != -1)
	{
		string substr = url.substr(pos + 1);

		int size = 0;

		while (TRUE)
		{
			pos = substr.find("&");
			if (pos != -1)
			{
				ret.push_back(substr.substr(0, pos));
				substr = substr.substr(pos + 1);
			}
			else {
				ret.push_back(substr.substr(0, pos));
				break;
			}
		}
	}
	return ret;
}*/





int HttpUtils::getRange(const char * httphdr,int & begin,int & end) {
	string value = getValueFromKey(httphdr, string("Range"));
	if (value == "")
	{
		return -1;
	}
	else {
		string flag = "bytes=";
		int pos = value.find(flag);
		if (pos != -1)
		{
			value = value.substr(flag.length());
		}
	}

	if (value.back() == '-')
	{
		value = value.substr(0, value.length() - 1);
		begin = atoi(value.c_str());
		end = -1;
		return 0;
	}
	else {
		int pos = value.find("-");
		if (pos == -1)
		{
			printf("parse partial error\r\n");
			return -1;
		}

		string start = value.substr(0, pos);
		string over = value.substr(pos + 1);
		begin = atoi(start.c_str());
		end = atoi(over.c_str());
		return 0;
	}
}

string HttpUtils::getmacstr(unsigned char * mac) {
	char szmac[32];
	wsprintfA(szmac, "%02x_%02x_%02x_%02x_%02x_%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return szmac;
}




string HttpUtils::getIPstr(unsigned long ulIP) {
	unsigned char cip[sizeof(unsigned long)] = { 0 };
	memmove(cip, &ulIP, sizeof(unsigned long));
	char szip[16] = { 0 };
	int ret = wsprintfA(szip, "%u.%u.%u.%u", cip[0], cip[1], cip[2], cip[3]);

	return string(szip);
}


string HttpUtils::getIPv6str(unsigned char ipv6[]) {

	unsigned char szip[16] = { 0 };
	int ret = Public::hex2str(ipv6, IPV6_IP_SIZE,0,szip);

	*(szip + ret) = 0;
	return string((char*)szip);
}

string HttpUtils::getIPPortStr(unsigned long ulIP,int port) {
	unsigned char cip[4] = { 0 };
	memmove(cip, &ulIP, 4);
	char szip[16] = { 0 };
	int ret = wsprintfA(szip, "%u.%u.%u.%u:%u", cip[0], cip[1], cip[2], cip[3], port);
	return string(szip);
}





string HttpUtils::dns2Host(char * dns) {
	char szhost[256] = { 0 };
	int dnslen = lstrlenA(dns);
	if (dnslen >= 256)
	{
		return "";
	}
	for (int i = 0, j = 0; i < dnslen;)
	{
		int partlen = dns[i];
		if (partlen > 0 && partlen < 64)
		{
			memcpy(szhost + j, dns + i + 1, partlen);

			i += (partlen + 1);

			j += partlen;

			*(szhost + j) = '.';

			j++;
		}
		else {
			break;
		}
	}

	int hostlen = lstrlenA(szhost);
	if (hostlen > 0)
	{
		*(szhost + hostlen - 1) = 0;
	}

	return szhost;
}



string HttpUtils::host2Dns(string host) {
	string newstr = "";
	for (unsigned int j = 0; j < host.length(); ) {

		if (host.c_str()[j] == '.') {
			newstr.append((char*)&j);

			string tmp = host.substr(0, j);
			newstr.append(tmp);

			host = host.substr(j + 1);
			//must reset j,for old.length() changed
			j = 0;
		}
		else {
			j++;
		}
	}

	if (host.length() > 0) {
		int k = host.length();
		newstr.append((char*)&k);
		newstr.append(host);
	}

	//discard first .
	if (newstr.length() > 0 && newstr.at(0) == '.')
	{
		newstr = newstr.substr(1);
	}
	
	return newstr;
}

tm HttpUtils::gettimefromhttp(string httpresponse) {
	tm sttm = { 0 };

	string key = "Date";
	//Tue, 24 Sep 2019 02:33:54 GMT
	string strtime = getValueFromKey(httpresponse.c_str(), key);
	if (strtime == "" || strtime.find("GMT") == -1)
	{
		return sttm;
	}
	
	int y = 0;
	int m = 0;
	int d = 0;
	int h = 0;
	int minute = 0;
	int s = 0;
	string w = "";
	int pos = strtime.find(",");
	if (pos > 0)
	{
		w = strtime.substr(0, pos);

		pos = strtime.find(" ");
		if (pos > 0)
		{
			pos++;

			int next = strtime.find(" ", pos);
			string strd = strtime.substr(pos, next - pos);
			d = atoi(strd.c_str());

			pos = next + 1;
			next = strtime.find(" ",pos);
			if (next > 0)
			{
				string strm = strtime.substr(pos, next - pos);
				if (strm == "Jan")
				{
					m = 0;
				}else if (strm == "Feb")
				{
					m = 1;
				}else if (strm == "Mar")
				{
					m = 2;
				}else if (strm == "Apr")
				{
					m = 3;
				}else if (strm == "May")
				{
					m = 4;
				}else if (strm == "Jun")
				{
					m = 5;
				}else if (strm == "Jul")
				{
					m = 6;
				}else if (strm == "Aug")
				{
					m = 7;
				}else if (strm == "Sep")
				{
					m = 8;
				}else if (strm == "Oct")
				{
					m = 9;
				}else if (strm == "Nov")
				{
					m = 10;
				}else if (strm == "Dec")
				{
					m = 11;
				}

				pos = next + 1;
				next = strtime.find(" ", pos );
				if (next > 0)
				{
					string stry = strtime.substr(pos , next - pos );
					y = atoi(stry.c_str());

					pos = next + 1;
					next = strtime.find(" ", pos );
					if (next > 0)
					{
						string strlast = strtime.substr(pos, next - pos);
							
						pos = strlast.find(":");
						if (pos > 0)
						{
							string strh = strlast.substr(0 , pos);
							h = atoi(strh.c_str());
						}

						pos += 1;
						next = strlast.find(":",pos);
						if (next > 0)
						{
							string strmin = strlast.substr(pos, next - pos);
							minute = atoi(strmin.c_str());
						}

						string strs = strlast.substr(next + 1);
						s = atoi(strs.c_str());

						sttm.tm_year = y - 1900;
						sttm.tm_mon = m;
						sttm.tm_mday = d;
						sttm.tm_hour = h;
						sttm.tm_min = minute;
						sttm.tm_sec = s;
					}
				}
			}
		}
	}

	return sttm;
}