
#include "dns.h"
#include "../http/http.h"
#include "../packet.h"
#include "../ResultFile.h"
#include "../HttpUtils.h"
#include "../ProtocolParser.h"

vector<DNSSSL_REGULATION> gDnsList;

int DNS::isDns(DATALISTHEADER hdr) {
	if (hdr.sock.dstport == 53 && hdr.sock.protocol == 0x11)
	{
		return TRUE;
	}
	return FALSE;
}

int DNS::processDns(DATALISTHEADER hdr) {
	LPPACKSIZELIST listsize = hdr.sizelist;
	LPDATABLOCKLIST list = hdr.datalist;
	char data[0x1000];
	int ret = 0;
	int offset = 0;
	while (list && listsize)
	{
		ret = DataBlockList::getNextPacket(list, offset, listsize, (char*)data);
		if (ret)
		{
			char * dnsname = data + sizeof(DNSHEADER);
			for (unsigned int i = 0; i < gDnsList.size(); i++)
			{
				if (strstr(dnsname, gDnsList[i].host.c_str()))
				{
					string host = HttpUtils::dns2Host((char*)gDnsList[i].host.c_str());
					ResultFile::writeRecord(hdr, gDnsList[i].pro, "on", host);
				}
			}
		}
		else {
			break;
		}
	}

	return 0;
}

int DNS::init(vector<DNSSSL_REGULATION> dnslist) {
	gDnsList = dnslist;
	return 0;
}