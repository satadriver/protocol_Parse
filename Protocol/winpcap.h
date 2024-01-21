#pragma once

#include <iostream>
#include <string>
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"

using namespace std;

#define PCAP_OPEN_LIVE_TO_MS_VALUE_NEGTIVE	-1
#define WINPCAP_MAX_BUFFER_SIZE				0x1000000
#define PCAP_OPENFLAG_PROMISCUOUS			1
#define WINPCAP_MAX_PACKET_SIZE				0x10000	
#define PCAP_PORT_FILTER					"ip"			
//#define PCAP_PORT_FILTER					"tcp dst port 80 or tcp dst port 8080 or tcp dst port 8000 or udp dst port 53"	
#define PCAP_FILTER_MASK_VALUE				0xffffff

class Winpcap {
public:
	static pcap_t * init(string devname, int delay, unsigned long netmask);

	static int dumpfile(string filename, string devname);
};
