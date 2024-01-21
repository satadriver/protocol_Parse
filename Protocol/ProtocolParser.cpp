#include "ProtocolParser.h"
#include "public.h"
#include "IMSG/mobileQQ.h"
#include "IMSG/QQ.h"
#include <windows.h>
#include <WinSock2.h>
#include "ssl/ssl.h"
#include "http/http.h"
#include "radius/radius.h"
#include "Shopping/taobao.h"
#include "dns/dns.h"
#include "IMSG/Wechat.h"
#include "ResultFile.h"



int ProtocolParser::parse(DATALISTHEADER hdr) {
	int ret = 0;
	if (HTTP::isHttp(hdr))
	{
		ret = HTTP::processHttp(hdr);
	}else if (SSL::isSSL(hdr))
	{
		ret = SSL::processSSL(hdr);
	}
	else if (MobileQQ::isMobileQQPack(hdr))
	{
		LPDATABLOCKLIST list = hdr.datalist;
		int offset = 0;
		char * data = 0;
		while (list != 0 && offset < list->hdr.size)
		{
			int blocksize = ntohl(*(int*)(list->data + offset));
			ret = DataBlockList::getBlock(list, offset, blocksize, &data);
			if (ret > 0)
			{
				ret = MobileQQ::parsePacket(data, blocksize, hdr.sock.dstport, hdr.sock.srcport,hdr);
				delete data;
				data = 0;
			}
			else {
				delete data;
				string fn = ResultFile::formatfn(hdr,"mqq_error");
				ret = DataBlockList::writeBlocks(hdr.datalist, fn);
				break;
			}
		}

		list = hdr.datalist2;
		offset = 0;
		data = 0;
		while (list != 0 && offset < list->hdr.size)
		{
			int blocksize = ntohl(*(int*)(list->data + offset));
			ret = DataBlockList::getBlock(list, offset, blocksize, &data);
			if (ret > 0)
			{
				ret = MobileQQ::parsePacket(data, blocksize, hdr.sock.dstport, hdr.sock.srcport, hdr);
				delete data;
				data = 0;
			}
			else {
				string fn = ResultFile::formatfn(hdr, "mqq_error");
				ret = DataBlockList::writeBlocks(hdr.datalist2, fn);
				delete data;
				break;
			}
		}
	}else if (QQ::isQQ(hdr.datalist->data,hdr.sizelist->size,hdr))
	{
		ret = QQ::processQQ(hdr.datalist, hdr.sizelist, hdr);

		ret = QQ::processQQ(hdr.datalist2, hdr.sizelist2, hdr);
	}else if (Radius::isRadius(hdr))
	{
		ret = Radius::processRadius(hdr);
	}else if (DNS::isDns(hdr))
	{
		ret = DNS::processDns(hdr);
	}
	else if (Taobao::isTaobao(hdr))
	{
		ret = Taobao::processTaobao(hdr);
	}
	else if (Wechat::isWeixin(hdr))
	{
		ret = Wechat::processWeixin(hdr);
	}
	return 0;
}









