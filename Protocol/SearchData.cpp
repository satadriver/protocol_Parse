#include "SearchData.h"
#include <windows.h>

const char* SearchData::getstring(const char * flag, int flaglen, const char *data,int datalen) {
	int len = datalen - flaglen;
	for (int i = 0; i < len ;i ++)
	{
		if (memcmp(flag,data + i,flaglen) == 0)
		{
			return data + i + flaglen;
		}
	}

	return 0;
}

int SearchData::getstring(char * flag, char * endflag, char * lpdata, char * lpdst, int start) {
	int flaglen = lstrlenA(flag);
	char * lphdr = strstr(lpdata, flag);
	if (lphdr)
	{
		if (start)
		{
			lphdr += flaglen;
		}

		char * lpend = strstr(lphdr, endflag);
		if (lpend)
		{
			int len = lpend - lphdr;
			memmove(lpdst, lphdr, len);
			*(lpdst + len) = 0;
			return len;
		}
	}
	return FALSE;
}


