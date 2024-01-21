#pragma once

#include "../DataList.h"
#include "../http/http.h"

class DNS {
public:
	static int DNS::init(vector<DNSSSL_REGULATION> dnslist);
	static int isDns(DATALISTHEADER hdr);
	static int processDns(DATALISTHEADER hdr);
};