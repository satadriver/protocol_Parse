#pragma once

#include "../DataList.h"


typedef struct  
{
	unsigned int sign;
	unsigned char unknown[3];	//02 27 14
	unsigned int uin;
	unsigned char pad[13];	//0
	unsigned char flag;		//0xe9

}WEIXIN_FILETRANSFER_PACKET;

class Wechat {
public:
	static int isWeixin( DATALISTHEADER hdr);
	static int processWeixin(DATALISTHEADER hdr);
};