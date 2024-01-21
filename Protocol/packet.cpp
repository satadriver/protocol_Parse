

#include "Packet.h"


int Packet::getIPHdr(LPMACHEADER mac, LPPPPOEHEADER & pppoe, LPIPHEADER &ip, LPIPV6HEADER &ipv6) {
	char * nexthdr = (char*)mac + sizeof(MACHEADER);
	int nextprotocol = mac->Protocol;

	if (nextprotocol == 0x0081)
	{

		LPHEADER8021Q p8021q = (LPHEADER8021Q)nexthdr;

		if (p8021q->type == 0x0081)
		{
			LPHEADER8021Q p8021q2 = LPHEADER8021Q((char*)p8021q + sizeof(HEADER8021Q));

			nexthdr = (char*)p8021q2 + (sizeof(HEADER8021Q));

			nextprotocol = p8021q2->type;
		}
		else {
			nexthdr = (char*)p8021q + sizeof(HEADER8021Q);

			nextprotocol = p8021q->type;
		}
	}
	else if (nextprotocol == 0x9899 || nextprotocol == 0xa788 || nextprotocol == 0xcc88)
	{
		return 0;
	}

	//assume ip hdr is after pppoe
	//0x8863（Discovery阶段或拆链阶段）或者0x8864（Session阶段）
	if (nextprotocol == 0x6488)
	{
		//0×C021 LCP数据报文
		//0×8021 NCP数据报文
		//0×0021 IP数据报文

		pppoe = (LPPPPOEHEADER)nexthdr;
		nextprotocol = pppoe->protocol;

		if (nextprotocol == 0x2100)
		{
			nexthdr = (char*)pppoe + sizeof(PPPOEHEADER);

			ip = (LPIPHEADER)nexthdr;

			return 1;
		}
		else if (nextprotocol == 0x5700 || nextprotocol == 0x5780) //ipv6
		{
			nexthdr = (char*)pppoe + sizeof(PPPOEHEADER);

			ipv6 = (LPIPV6HEADER)nexthdr;

			return 2;
		}
		else if (nextprotocol == 0x23c2 || nextprotocol == 0x23c0)
		{
			return 3;
		}
		else if (nextprotocol == 0x21c0 || nextprotocol == 0x0101  || nextprotocol == 0x22c0 || nextprotocol == 0x2180)
		{
			return 0;
		}
		else {
			return -1;
		}
	}
	else if (nextprotocol == 0x0008)
	{
		ip = (LPIPHEADER)nexthdr;
		return 1;
	}
	else if (nextprotocol == 0xdd86)
	{
		ipv6 = (LPIPV6HEADER)nexthdr;

		return 2;
	}
	//0x2700 IEEE 802.3
	else if (nextprotocol == 0x0608 || nextprotocol == 0x6388 || nextprotocol == 0x2700)
	{
		return 0;
	}
	else {
		return -1;
	}
}