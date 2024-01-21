#pragma once



#include "DataList.h"
#include <iostream>

using namespace std;

#ifdef PARSE_ATTACKER

class ParseAttacker {
public:

	static void writePcapFile(pcap_pkthdr * phdr1, const char * data1, pcap_pkthdr * phdr2, const char * data2,
		DATALISTHEADER hdr, string filename);
	static int checkAttacker(DATALISTHEADER hdr);
	static int bubbleSortDns(DATALISTHEADER hdr, LPDATABLOCKLIST datalist, LPPACKSIZELIST sizelist, int packcnt);
	static int bubbleSortTcp(DATALISTHEADER hdr, LPDATABLOCKLIST datalist, LPPACKSIZELIST sizelist, int packcnt);
	static void writeAttackerData(string filename, const char * src, int srclen, const char * dst, int dstlen);

	static int __stdcall myMsgBox();

	static void ParseAttacker::timerMsgBox();
};

#endif