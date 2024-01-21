#pragma once

#include "DataList.h"

class ResultFile {
public:
	static string formatFile(SESSIONSOCKET sock, string action, string info, string pro);

	static string formatMac(unsigned char *mac);
	static string formatIp(unsigned int ip);

	static void ResultFile::writeRecord(DATALISTHEADER hdr, string pro, string action, string info);

	static string formatfn(DATALISTHEADER hdr, string pro);
};