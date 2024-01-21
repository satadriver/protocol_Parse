#pragma once

#include <windows.h>
#include <vector>
#include <iostream>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

using namespace std;

typedef struct  
{
	pcap_t *pcapt;
	__int64 *packcnts;
	
}PCAPPARAMS,*LPPCAPPARAMS;

class PacketParser {
public:
	static int __stdcall peeping(LPPCAPPARAMS);
};