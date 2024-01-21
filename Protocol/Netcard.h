#pragma once

#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <IPTypes.h>
#include <vector>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

using namespace std;


typedef struct
{
	string name;
	unsigned long ip;
	unsigned long mask;
	unsigned long netgateip;
	unsigned char mac[6];
	pcap_t * pcapt;
	__int64 packcnts;
}MYADAPTERINFO, *LPMYADAPTERINFO;

class NetCard {
public:
	static int initWinSocket(void);
	static PIP_ADAPTER_INFO ShowNetCardInfo(int *);
	static PIP_ADAPTER_INFO GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq);

	static vector<MYADAPTERINFO> selectWeapon();

	static string selectWeaponOld(unsigned long * localIP, unsigned long * netmask, unsigned long * netgateip, unsigned char * lpmac);
};