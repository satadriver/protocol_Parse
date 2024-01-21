#pragma once
#include "../DataList.h"

#pragma pack(1)
typedef struct {
	string host;
	string url;
	string mode;
	string key;
	string pro;
	string pos;
}HTTP_REGULATION,*LPHTTP_REGULATION;

typedef struct {
	string host;
	string mode;
	string pro;
}DNSSSL_REGULATION, *LPDNSSSL_REGULATION;
#pragma pack()


class HTTP {
public:
	static int init(vector<HTTP_REGULATION> httpnames);
	static int processHttp(DATALISTHEADER hdr);
	static int isHttp(DATALISTHEADER hdr);
};