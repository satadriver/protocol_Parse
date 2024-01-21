#pragma once

#include "../DataList.h"

#pragma pack(1)
typedef struct {
	unsigned short ver;
	unsigned short cmd;
	unsigned short seq;
	unsigned int qq;
}QQHEADER,*LPQQHEADER;
#pragma pack()

class QQ {
public:
	static int isQQ(const char * data, int len, DATALISTHEADER hdr);
	static int processQQ(LPDATABLOCKLIST list, LPPACKSIZELIST sizelist, DATALISTHEADER hdr);
};