#include "http.h"
#include "../ProtocolParser.h"
#include "../HttpUtils.h"
#include "../ResultFile.h"
#include "../fileOper.h"
#include "../Shopping/taobao.h"
#include <WinSock2.h>

vector <HTTP_REGULATION> gHttpRegulation;

int HTTP::init(vector<HTTP_REGULATION> httpnames) {
	gHttpRegulation = httpnames;
	return 0;
}


string geturlvalue(string key,string url) {
	char * hdr = strstr((char*)url.c_str(), key.c_str());
	if (hdr > 0)
	{
		hdr += key.length();
		char * end = strstr(hdr, "&");
		if (end > 0)
		{
			string value = string(hdr, end - hdr);
			return value;
		}else 
		{
			return string(hdr);
		}
	}

	return "";
}

int HTTP::processHttp(DATALISTHEADER hdr) {
	int ret = 0;

	string http = string(hdr.datalist->data, hdr.datalist->hdr.size);
	string url = HttpUtils::getFullUrl(http.c_str(), http.size());

	string hostkey = "Host";
	string host = HttpUtils::getValueFromKey(http.c_str(), hostkey);
	for (unsigned int i = 0; i < gHttpRegulation.size(); i++)
	{
		if (strstr(host.c_str(), gHttpRegulation[i].host.c_str()) == 0 && strstr(url.c_str(), gHttpRegulation[i].url.c_str()))
		{
			if (gHttpRegulation[i].key != "")
			{
				string value = "";
				if (gHttpRegulation[i].pos == "url")
				{
					value = geturlvalue(gHttpRegulation[i].key, url);
				}else 
				{
					string pos = gHttpRegulation[i].pos;
					string data = HttpUtils::getValueFromKey(http.c_str(),pos);
					
					value = geturlvalue(gHttpRegulation[i].key, data);
				}

				ResultFile::writeRecord(hdr, gHttpRegulation[i].pro, "on", value);
			}

			string dst = "http://" + host + url;
		}
	}

	return 0;
}


int HTTP::isHttp(DATALISTHEADER hdr) {
	if ( hdr.sock.protocol == IPPROTO_TCP)
	{
		return HttpUtils::isHttpPacket(hdr.datalist->data);
	}
	return FALSE;
}


/*
GET /cgi-bin/micromsg-bin/newgetdns?uin=973536807&clientversion=654313012&scene=0&net=1&md5=7d88cbc097f131ee693e807b94a0ed78&devicetype=android-28&lan=zh_CN&sigver=2&lasteffecttime=1565366159 HTTP/1.0
Accept: *//*
Accept-Encoding: deflate
Cache-Control: no-cache
Connection: close
Content-Type: application/octet-stream
Host: dns.weixin.qq.com
User-Agent: MicroMessenger Client
*/