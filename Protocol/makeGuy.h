#pragma once
#include "protocol.h"

#pragma pack(1)

typedef struct {
	unsigned long ip;
	unsigned char mac[MAC_ADDRESS_SIZE+2];
	unsigned char imei[16];
	unsigned char imsi[16];
	unsigned char phone[16];
	unsigned char nick[16];
}GUYINDEX,*LPGUYINDEX;

#pragma pack()