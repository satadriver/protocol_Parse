
#include "Radius.h"
#include "../packet.h"
#include <WinSock2.h>
#include "../HttpUtils.h"
#include "../ResultFile.h"

int Radius::isRadius(DATALISTHEADER hdr) {

	if (hdr.sock.protocol == 17)
	{
		if (hdr.sock.dstport == 1812 || hdr.sock.srcport == 1812 || hdr.sock.dstport == 1813 || hdr.sock.srcport == 1813)
		{
			LPRADIUSHEADER radius = (LPRADIUSHEADER)hdr.datalist->data;
			if (radius->code == 4)
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}

int Radius::processRadius(DATALISTHEADER hdr) {

	string user = "";
	string clientmac = "";
	string nasserver = "";
	string clientip = "";

	string unknownip = "";
	string unknownmac = "";

	LPRADIUSHEADER radius = (LPRADIUSHEADER)hdr.datalist->data;
	int radiuslen = ntohs(radius->len);

	LPRADIUSAVPHDR avp = (LPRADIUSAVPHDR)(hdr.datalist->data + sizeof(RADIUSHEADER));
	while (1)
	{
		int len = avp->avplen - sizeof(RADIUSAVPHDR);
		if (len > 0 && len < 127)
		{
			if (avp->avptype == 1)
			{
				user = string((char*)avp + sizeof(RADIUSAVPHDR),len);
			}
			else if (avp->avptype == 4)
			{
				unsigned long nas = *(unsigned long*)((char*)avp + sizeof(RADIUSAVPHDR));
				nasserver = HttpUtils::getIPstr(nas);
			}
			else if (avp->avptype == 8)
			{
				unsigned long ip = *(unsigned long*)((char*)avp + sizeof(RADIUSAVPHDR));
				clientip = HttpUtils::getIPstr(ip);
			}
			else if (avp->avptype == 0x1f)
			{
				clientmac = string((char*)avp + sizeof(RADIUSAVPHDR),len);
			}
			else if (avp->avptype == 0x1a)
			{
				LPRADIUSAVPHDR next = (LPRADIUSAVPHDR)((char*)avp + sizeof(RADIUSAVPHDR) + 4);
				while (1)
				{
					len = next->avplen - sizeof(RADIUSAVPHDR);
					if (next->avptype == 0x3c)
					{
						string unknown = string((char*)next + sizeof(RADIUSAVPHDR), len);
						int pos = unknown.find(" ");
						if (pos > 0)
						{
							unknownip = unknown.substr(0, pos);
							unknownmac = unknown.substr(pos + 1);
						}
						
						break;
					}

					next = (LPRADIUSAVPHDR)((char*)next + next->avplen);
					if ((char*)next - (char*)radius >= radiuslen)
					{
						break;
					}
				}
				break;
			}
		}
		else {
			break;
		}
	
		avp = (LPRADIUSAVPHDR)((char*)avp + avp->avplen);
		if ((char*)avp - (char*)radius >= radiuslen)
		{
			break;
		}
	}

	if (user != "" && clientip != "")
	{
		char info[1024];
		wsprintfA(info, "{\"user\":\"%s\",\"ip\":\"%s\",\"mac\":\"%s\",\"nas\":\"%s\"}",
			user.c_str(), clientip.c_str(), clientmac.c_str(),nasserver.c_str());
		ResultFile::writeRecord(hdr, "radius", "on", info);
	}
	return 0;
}

//RADIUS协议的认证端口号为1812（1645端口由于冲突已经不再使用），计费端口号为1813或1646端口由于冲突已经不再使用