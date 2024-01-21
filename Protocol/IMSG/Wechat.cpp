
#include "Wechat.h"
#include "../ProtocolParser.h"
#include "../ResultFile.h"
#include <WinSock2.h>
#include "../SearchData.h"

int Wechat::isWeixin( DATALISTHEADER hdr) {
	if (hdr.sock.protocol == 6 && *(int*)hdr.datalist->data == 0x010000ab  )
	{
		if (hdr.sock.dstport == 443 || hdr.sock.dstport == 80)
		{
			return TRUE;
		}
	}
	return 0;
}


int Wechat::processWeixin(DATALISTHEADER hdr) {

	int offset = 0;
	int pos = DataBlockList::find("http://",lstrlenA("https://"),hdr.datalist,offset);
	if (pos > 0)
	{
		string data = string(hdr.datalist->data + pos);
		int start = data.find("uin=");
		if (start != -1)
		{
			string sub = data.substr(start + lstrlenA("uin="));
			int end = sub.find("&");
			if (end != -1)
			{
				string uid = sub.substr(0, end);
				ResultFile::writeRecord(hdr, "weixin", "on", uid);
			}
		}
	}
	else {
		pos = DataBlockList::find("weixinnum", lstrlenA("weixinnum"), hdr.datalist, offset);
		if (pos > 0)
		{
			offset += lstrlenA("weixinnum");
			int size = ntohl(*(int*)(hdr.datalist->data + offset));
			if (size > 0 && size <= 11)
			{
				string uid = string(hdr.datalist->data + offset + 4, size);
				ResultFile::writeRecord(hdr, "weixin", "on", uid);
			}
			
		}
	}

	return 0;
}