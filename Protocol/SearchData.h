#pragma once

#include "DataList.h"

class SearchData {
public:
	static const char* getstring(const char * flag, int flaglen, const char *data, int datalen);
	static int getstring(char * flag, char * endflag, char * lpdata, char * lpdst, int start);
};