#include "qq.h"
#include "qqcrypt.h"
#include <WinSock2.h>
#include "../public.h"
#include "../ProtocolParser.h"
#include "../ResultFile.h"
#include "../fileOper.h"
#include <windows.h>


int QQ::isQQ(const char * data, int len, DATALISTHEADER hdr) {
	if (hdr.sock.protocol == 0x11 )
	{
		if ( hdr.sock.dstport == 8000)
		{
			int firstsize = hdr.sizelist->size;
			if (hdr.datalist->data[0] == 0x02 && hdr.datalist->data[firstsize-1] == 0x03 )
			{
				return TRUE;
			}
		}
	}
	return FALSE;
}




int QQ::processQQ(LPDATABLOCKLIST list, LPPACKSIZELIST sizelist, DATALISTHEADER hdr) {
	int ret = 0;

	char lpbuf [0x1000];
	int offset = 0;
	while (list && sizelist)
	{
		int len = DataBlockList::getNextPacket(list, offset, sizelist, (char*)lpbuf);
		if (len > 0)
		{
			QQHEADER * qqhdr = (QQHEADER*)(lpbuf + 1);
			if (qqhdr->cmd == 0x2508)
			{
				int pad = sizeof(QQHEADER) ;
				if (memcmp(lpbuf + 1 + pad, "\x03\x00\x00\x00", 4) == 0)//010101
				{
					pad += 15;
				}else if (memcmp(lpbuf + 1 + pad,"\x00\x00\x00",3) == 0)
				{
					pad += 15;
				}
				char * offset = lpbuf + 1 + pad;
				int size = len - 1 - pad - 1 ;

				unsigned char *key = (unsigned char*)offset;

				int decodelen = size + 1024;
				unsigned char *decodebuf = new unsigned char[size + 1024];

				int ret = qq_decrypt((unsigned char*)offset + 16, size - 16, key, decodebuf, &decodelen);
				if (ret > 0)
				{
					Public::WriteDataFile("qq.dat", (const char*)decodebuf, decodelen);
				}

				delete decodebuf;

				char szqq[16];
				sprintf(szqq, "%u", ntohl(qqhdr->qq));
				ResultFile::writeRecord(hdr, "qq", "on", szqq);
			}
// 			else if (qqhdr->cmd == 0x3608)
// 			{
// 				char szqq[16];
// 				sprintf(szqq, "%u", ntohl(qqhdr->qq));
// 				ResultFile::writeRecord(hdr, "qq", "on", szqq);
// 			}
		}
		else {

// 			string fn = ProtocolParser::formatfn(hdr, "qq_error");
// 			ret = ProtocolParser::writeBlocks(list, fn);
 			break;
		}
	}
	
	return 0;
}


/*
POST /qbrowser HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0) QQBrowser/9.0
Host: update.browser.qq.com
Content-Length: 345
Connection: Keep-Alive
Cache-Control: no-cache
Cookie: uin_cookie=2210853762; euin_cookie=53DFE9A7024225C8649F40745723E578AC136F6862ECF843

{
"COS": "10.0.17763",
"CSoftID": 22,
"CVer": "1.6.6699.999",
"Cmd": 1,
"ExeVer": "1.0.1118.400",
"GUID": "9308ec3d7b7602d10f39e90f88399236",
"InstallTimeStamp": 1557478990,
"QID": 16785570,
"QQVer": "9.1.3.25332",
"SupplyID": 0,
"TriggerMode": 1,
"UIN": 0,
"bPatch": 0,
"osDigit": 64
}
HTTP/1.1 200
Date: Sun, 11 Aug 2019 03:14:20 GMT
Content-Length: 450
Connection: keep-alive

{ "CSoftID": 22, "CommandLine": "", "Desp": "\u0031\u002e\u0030\u002e\u0031\u0031\u0036\u0030\u002e\u0034\u0030", "DownloadUrl": "http://dl_dir.qq.com/invc/tt/minibrowser11.zip", "ErrCode": 0, "File": "minibrowser11.zip", "Flags": 1, "Hash": "b1309eb4312bd83d154a4b2b1b66547b", "InstallType": 0, "NewVer": "1.0.1160.400", "PatchFile": "QBDeltaUpdate.exe", "PatchHash": "b1309eb4312bd83d154a4b2b1b66547b", "Sign": "", "Size": 36003449, "VerType": "" }
*/