

#include "config.h"
#include "FileOper.h"
#include "Public.h"
#include <winsock.h>
#include <algorithm>
#include "protocol.h"
#include "http/http.h"
#include "HttpUtils.h"


vector<string> Config::parseAttackCfg(string fn, unsigned long *serverip, int *speed, int * opensslflag, int *runmode) {
	char * buf = 0;
	int fs = 0;

	printf("parsing file:%s:\r\n", fn.c_str());

	vector <string> DnsAttackList;

	int ret = FileOper::fileReader(fn, &buf, &fs);
	if (ret <= 0) {
		return DnsAttackList;
	}

	int cfglen = Public::removespace(buf, buf);
	string str = string(buf, cfglen);
	delete buf;

	string substr = "";
	int flag = 0;
	while (1) {
		int linepos = str.find(CRLN);
		if (linepos >= 0) {
			substr = str.substr(0, linepos);
			str = str.substr(linepos + 1);
		}
		else {
			linepos = str.find(CRLNLINUX);
			if (linepos >= 0) {
				substr = str.substr(0, linepos);
				str = str.substr(linepos + 1);
			}
			else {
				substr = str;
				flag = 1;
			}
		}

		if (substr.length() > 0 && substr.at(0) == '#')
		{
			continue;
		}

		const char* end = 0;
		const char* hdr = 0;
		char * speedhdr = "speed=";
		string opensslcfg = "opensslcfg=";
		string dnsserver = "dataServer=";
		char *mode = "mode=";



		hdr = strstr(substr.c_str(), "[");
		if (hdr > 0) {
			hdr += strlen("[");
			end = strstr(hdr, "]");
			if (end > 0 && (end - hdr > 0)) {

				string value = string(hdr, end - hdr);

				int pos = value.find(dnsserver);
				if (pos != -1) {
					value.replace(pos, dnsserver.length(), "");
					if (value == "auto")
					{
						//*serverip = inet_addr(value.c_str());
						*serverip = 0;
						printf("set server ip:%s\r\n", value.c_str());
					}
					else {
						//parse ip error return 0xffffffff
						*serverip = inet_addr(value.c_str());
						printf("set server ip:%s\r\n", value.c_str());
					}
				}
				else if (memcmp(value.c_str(), opensslcfg.c_str(), opensslcfg.length()) == 0)
				{
					string opensslconfig = value.substr(opensslcfg.length());
					*opensslflag = atoi(opensslconfig.c_str());
					printf("set openssl value:%d\r\n", *opensslflag);
				}
				else if (memcmp(value.c_str(), speedhdr, strlen(speedhdr)) == 0)
				{
					string strspeed = value.substr(strlen(speedhdr));
					*speed = atoi(strspeed.c_str());
					printf("set winpcap speed:%d\r\n", *speed);
				}
				else if (memcmp(value.c_str(), mode, strlen(mode)) == 0)
				{
					string strmode = value.substr(strlen(mode));
					*runmode = atoi(strmode.c_str());
					printf("set runmode:%d\r\n", *runmode);
				}
				else {
					DnsAttackList.push_back(value);
					printf("add attack host:%s\r\n", value.c_str());
				}
			}
		}

		if (flag > 0) {
			break;
		}


		continue;
	}

	return DnsAttackList;

}


int getHttpRegulation(string str, vector <DNSSSL_REGULATION> & ssllist, vector <DNSSSL_REGULATION> & dnslist, 
	vector<HTTP_REGULATION> &httplist) {
	const char* end = 0;
	const char* hdr = 0;

	string tmpstr = str;

	while (1) {
		hdr = strstr(tmpstr.c_str(), "[url=\"");
		if (hdr > 0) {
			end = strstr(hdr, "]");
			if (end > 0)
			{
				string substr = string(hdr, end - hdr + 1);

				tmpstr = tmpstr.substr(end + 1 - tmpstr.c_str());

				hdr = substr.c_str();
				hdr += lstrlenA("[url=\"");
				end = strstr(hdr, "\"");
				if (end > 0) {

					string url = string(hdr, end - hdr);

					hdr = strstr(substr.c_str(), "host=\"");
					hdr += lstrlenA("host=\"");
					end = strstr(hdr, "\"");
					string host = string(hdr, end - hdr);

					hdr = strstr(substr.c_str(), "mode=\"");
					hdr += lstrlenA("mode=\"");
					end = strstr(hdr, "\"");
					string mode = string(hdr, end - hdr);

					hdr = strstr(substr.c_str(), "key=\"");
					hdr += lstrlenA("key=\"");
					end = strstr(hdr, "\"");
					string key = string(hdr, end - hdr);

					hdr = strstr(substr.c_str(), "pro=\"");
					hdr += lstrlenA("pro=\"");
					end = strstr(hdr, "\"");
					string pro = string(hdr, end - hdr);

					if (mode == "http")
					{
						hdr = strstr(substr.c_str(), "pos=\"");
						hdr += lstrlenA("pos=\"");
						end = strstr(hdr, "\"");
						string pos = string(hdr, end - hdr);


						HTTP_REGULATION regulation;
						regulation.url = url;
						regulation.host = host;
						regulation.mode = mode;
						regulation.key = key;
						regulation.pro = pro;
						regulation.pos = pos;
						httplist.push_back(regulation);
					}else if (mode == "dns")
					{
						string hostdns = HttpUtils::host2Dns(host);
						DNSSSL_REGULATION dns;
						dns.host = hostdns;
						dns.mode = mode;
						dns.pro = pro;
						dnslist.push_back(dns);
					}
					else if (mode == "ssl")
					{
						DNSSSL_REGULATION ssl;
						ssl.host = host;
						ssl.mode = mode;
						ssl.pro = pro;
						ssllist.push_back(ssl);
					}
				}
				else {
					break;
				}
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}
	return 0;
}


int Config::parseHttpCfg(string fn, vector <DNSSSL_REGULATION> & ssllist, vector <DNSSSL_REGULATION> & dnslist, 
	vector<HTTP_REGULATION> &httplist,vector<unsigned int> & udpsports, vector<unsigned int> & udpdports,
	vector<unsigned int> & tcpsports, vector<unsigned int> & tcpdports) {
	printf("parsing file:%s\r\n", fn.c_str());

	int httpcnt = 0;
	int sslcnt = 0;

	char * buf = 0;
	int fs = 0;
	int ret = FileOper::fileReader(fn, &buf, &fs);
	if (ret <= 0) {
		return 0;
	}

	int cfglen = Public::removespace(buf, buf);
	string str = string(buf, cfglen);
	delete buf;

	
	const char* end = 0;
	const char* hdr = 0;

	string substr = str;
	while (1) {
		hdr = strstr(substr.c_str(), "[udpsrc:");
		if (hdr > 0) {
			hdr += strlen("[udpsrc:");
			end = strstr(hdr, "]");
			if (end > 0)
			{
				string strport = string(hdr, end - hdr);
				unsigned int port = atoi(strport.c_str());
				udpsports.push_back(ntohs(port));

				substr = substr.substr(end + 1 - substr.c_str());
				hdr = substr.c_str();
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}

	substr = str;
	while (1) {
		hdr = strstr(substr.c_str(), "[udpdst:");
		if (hdr > 0) {
			hdr += strlen("[udpdst:");
			end = strstr(hdr, "]");
			if (end > 0)
			{
				string strport = string(hdr, end - hdr);
				unsigned int port = atoi(strport.c_str());
				udpdports.push_back(ntohs(port));

				substr = substr.substr(end + 1 - substr.c_str());
				hdr = substr.c_str();
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}


	substr = str;
	end = 0;
	hdr = 0;
	while (1) {
		hdr = strstr(substr.c_str(), "[tcpsrc:");
		if (hdr > 0) {
			hdr += strlen("[tcpsrc:");
			end = strstr(hdr, "]");
			if (end > 0)
			{
				string strport = string(hdr, end - hdr);
				unsigned int port = atoi(strport.c_str());
				tcpsports.push_back(ntohs(port));

				substr = substr.substr(end + 1 - substr.c_str());
				hdr = substr.c_str();
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}

	substr = str;
	end = 0;
	hdr = 0;
	while (1) {
		hdr = strstr(substr.c_str(), "[tcpdst:");
		if (hdr > 0) {
			hdr += strlen("[tcpdst:");
			end = strstr(hdr, "]");
			if (end > 0)
			{
				string strport = string(hdr, end - hdr);
				unsigned int port = atoi(strport.c_str());
				tcpdports.push_back(ntohs(port));

				substr = substr.substr(end + 1 - substr.c_str());
				hdr = substr.c_str();
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}

	/*
	string substr = str;
	const char* end = 0;
	const char* hdr = 0;
	hdr = strstr(substr.c_str(), "[https:\r\n");
	if (hdr > 0) {
		hdr += strlen("[https:\r\n");
		end = strstr(hdr, "]");
		if (end > 0)
		{
			substr = string(hdr, end - hdr);
			hdr = substr.c_str();
			while (1) {
				end = strstr(hdr, "\r\n");
				if (end > 0 ) {
					string value = string(hdr, end - hdr);
					if (value.length() > 0)
					{
						ssllist.push_back(value);
						sslcnt++;
						printf("ssl add:%s\r\n", value.c_str());
					}
					
					hdr = end + 2;
				}
				else {
					break;
				}
			}
		}
	}
	substr = str;
	hdr = strstr(substr.c_str(), "[http:\r\n");
	if (hdr > 0) {
		hdr += strlen("[http:\r\n");
		end = strstr(hdr, "]");
		if (end > 0)
		{
			substr = string(hdr, end - hdr);
			hdr = substr.c_str();
			while (1) {
				end = strstr(hdr, "\r\n");
				if (end > 0) {
					string value = string(hdr, end - hdr);
					if (value.length() > 0)
					{
						httpAttackList.push_back(value);
						httpcnt ++;
						printf("http add:%s\r\n", value.c_str());
					}

					hdr = end + 2;
				}
				else {
					break;
				}
			}
		}
	}*/

	getHttpRegulation(str, ssllist,dnslist, httplist);
	return 0;
}






int Config::shiftDnsFormat(vector<string> & dnses) {
	for (unsigned int i = 0; i < dnses.size(); i++) {

		string old = dnses[i];
		if (old.length() <= 0) {
			continue;
		}

		string newstr = "";
		for (unsigned int j = 0; j < old.length(); j++) {

			if (old.c_str()[j] == '.') {
				newstr.append((char*)&j);
				string tmp = old.substr(0, j);
				newstr.append(tmp);
				old = old.substr(j + 1);

				j = 0;
			}
		}

		if (old.length() > 0) {
			int k = old.length();
			newstr.append((char*)&k);
			newstr.append(old);
		}

		dnses[i] = newstr;

	}

	sort(dnses.begin(), dnses.end());

	return 0;
}

