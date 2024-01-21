
#include "taobao.h"
#include <WinSock2.h>
#include "../ResultFile.h"

int Taobao::isTaobao(DATALISTHEADER hdr) {
	if (hdr.sock.dstport == 80 && memcmp(hdr.datalist->data,"\x88\x06\x00\x00\x01\x00",4) == 0 )
	{
		return TRUE;
	}
	return FALSE;

}


int Taobao::processTaobao(DATALISTHEADER hdr) {
	short len = ntohs(*(short*)(hdr.datalist->data + 26));
	if (len > 4 && len < 64)
	{
		string account = string(hdr.datalist->data + 28, len);
		ResultFile::writeRecord(hdr, "taobao", "on", account);
	}
	return 0;
}


