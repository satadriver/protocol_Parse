#include "parseAttacker.h"
#include "ResultFile.h"
#include <WinSock2.h>
#include "packet.h"
#include "public.h"

#ifdef PARSE_ATTACKER

int __stdcall ParseAttacker::myMsgBox() {

	MessageBoxA(0, "you are under attack!", "you are under attack!", MB_OK);
	return 0;
}

void ParseAttacker::timerMsgBox() {
	//CloseHandle(CreateThread(0, 0, (LPTHREAD_START_ROUTINE)myMsgBox, 0, 0, 0));
}

vector <unsigned int> getDnsResult(const char * data,int size) {

	vector <unsigned int> ips;

	const char * name = data + sizeof(DNSHEADER);

	unsigned short reqtype = *(unsigned short*)((char*)name + lstrlenA(name) + 1);
	unsigned short reqcls = *(unsigned short*)((char*)name + lstrlenA(name) + 1 + 2);
	if (reqcls != 0x0100 || reqtype != 0x0100)
	{
		return ips;
	}

	LPDNSANSWER ans = (LPDNSANSWER)(name + lstrlenA(name) + 1 + 4);

	do
	{
		int totalsize = (char*)ans - data;
		if (totalsize >= size || totalsize <= 0)
		{
			break;
		}
		else if (ans->Type == 0x0100 && ans->Class == 0x0100 && ans->AddrLen == 0x0400)
		{
			ips.push_back(ans->Address);
			ans = (LPDNSANSWER)((char*)ans + sizeof(DNSANSWER));
		}
		else if (ans->Type == 0x0500 && ans->Class == 0x0100)
		{
			int cnamelen = ntohs(ans->AddrLen);

			const char * cname = (const char*)((char*)ans + sizeof(DNSANSWER) - 4);

			ans = (LPDNSANSWER)(cname + cnamelen);
		}
		else {
			int cnamelen = ntohs(ans->AddrLen);

			const char * cname = (const char*)((char*)ans + sizeof(DNSANSWER) - 4);

			ans = (LPDNSANSWER)(cname + cnamelen);
		}
	} while (1);

	return ips;
}






int ParseAttacker::bubbleSortDns(DATALISTHEADER hdr, LPDATABLOCKLIST datalist, LPPACKSIZELIST sizelist,int packcnt) {

	int ret = 0;

	LPDATABLOCKLIST firstdata = datalist;

	int firstoffset = 0;

	LPPACKSIZELIST firstsize = sizelist;

	char firstarray[DATA_BLOCK_SIZE];
	char nextarrayy[DATA_BLOCK_SIZE];
	char * firstbuf = firstarray;
	char * nextbuf = nextarrayy;

	for (int i = 0; i < packcnt; i++)
	{
		ret = DataBlockList::getBlock(firstdata, firstoffset, firstsize->size, &firstbuf);
		if (ret <= 0)
		{
			break;
		}

		LPPACKSIZELIST nextsize = firstsize->next;
		LPDATABLOCKLIST nextdata = firstdata;
		int nextoffset = firstoffset;

		LPIPHEADER firstip = 0;
		LPPPPOEHEADER firstpppoe = 0;
		LPIPV6HEADER firstipv6 = 0;
		char * firstpackdata = 0;
		int firstpackdatasize = 0;
		ret = Packet::getIPHdr((LPMACHEADER)firstbuf, firstpppoe, firstip, firstipv6);
		if (ret == 1)
		{
			LPUDPHEADER firstudp = (LPUDPHEADER)((char*)firstip + (firstip->HeaderSize << 2));
			firstpackdata = (char*)firstudp + sizeof(UDPHEADER);
			firstpackdatasize = ntohs(firstip->PacketSize) - (firstip->HeaderSize << 2) - sizeof(UDPHEADER);
		}
		else if (ret == 2)
		{
			LPUDPHEADER firstudp = (LPUDPHEADER)((char*)firstipv6 + sizeof(IPV6HEADER));
			firstpackdata = (char*)firstudp + sizeof(UDPHEADER);
			firstpackdatasize = ntohs(firstipv6->PayloadLen) - sizeof(IPV6HEADER) - sizeof(UDPHEADER);
		}
		else {
			break;
		}

		

		for (int j = i + 1; j < packcnt; j++)
		{
			ret = DataBlockList::getBlock(nextdata, nextoffset, nextsize->size, &nextbuf);
			if (ret <= 0)
			{
				break;;
			}

			LPIPHEADER nextip = 0;
			LPPPPOEHEADER nextpppoe = 0;
			LPIPV6HEADER nextipv6 = 0;
			char * nextpackdata = 0;
			int nextpackdatasize = 0;
			ret = Packet::getIPHdr((LPMACHEADER)nextbuf, nextpppoe, nextip, nextipv6);
			if (ret == 1) {
				LPUDPHEADER nextudp = (LPUDPHEADER)((char*)nextip + (nextip->HeaderSize << 2));
				nextpackdata = (char*)nextudp + sizeof(UDPHEADER);
				nextpackdatasize = ntohs(nextip->PacketSize) - (nextip->HeaderSize<<2) - sizeof(UDPHEADER);
			}else if (ret == 2)
			{
				LPUDPHEADER nextudp = (LPUDPHEADER)((char*)nextipv6 + sizeof(IPV6HEADER));
				nextpackdata = (char*)nextudp + sizeof(UDPHEADER);
				nextpackdatasize = ntohs(nextipv6->PayloadLen) - sizeof(IPV6HEADER) - sizeof(UDPHEADER);
			}
			else {
				break;
			}

			LPDNSHEADER dns = (LPDNSHEADER)firstpackdata;
			char * dnsname = firstpackdata + sizeof(DNSHEADER);
			LPDNSHEADER nextdns = (LPDNSHEADER)nextpackdata;
			char * nextdnsname = nextpackdata + sizeof(DNSHEADER);
			if ((dns->TransactionID == nextdns->TransactionID) && (lstrcmpiA(nextdnsname,dnsname) == 0))
			{
				int cmpsize = firstpackdatasize;
				if (firstpackdatasize > nextpackdatasize)
				{
					cmpsize = nextpackdatasize;
				}

				if (nextsize->size != firstsize->size || memcmp(firstpackdata, nextpackdata, cmpsize) )
				{
					int writeflag = 0;

					vector<unsigned int> ips1 = getDnsResult(firstpackdata, firstpackdatasize);
					vector<unsigned int> ips2 = getDnsResult(nextpackdata, nextpackdatasize);
					if (ips1.size() > 0 && (ips1.size() == ips2.size()))
					{

						for (int n = 0; n < ips1.size(); n++)
						{
							int find = 0;

							for (int m = 0; m < ips2.size(); m++)
							{
								if (ips1[n] == ips2[m])
								{
									find ++;
									break;
								}
							}

							if (find == 0)
							{
								writeflag = TRUE;
								break;
							}
						}
					}
					else {
						writeflag = TRUE;
					}

					if (writeflag)
					{
						string fn = ResultFile::formatfn(hdr, "dnsattack");
						writePcapFile(&firstsize->hdr, firstbuf, &nextsize->hdr, nextbuf, hdr, fn);

						timerMsgBox();
						return TRUE;
					}
				}
			}

			nextsize = nextsize->next;
		}

		firstsize = firstsize->next;
	}

	return FALSE;
}

int ParseAttacker::bubbleSortTcp(DATALISTHEADER hdr,LPDATABLOCKLIST datalist, LPPACKSIZELIST sizelist,int packcnt) {

	int ret = 0;

	LPDATABLOCKLIST firstdata = datalist;

	int firstoffset = 0;

	LPPACKSIZELIST firstsize = sizelist;

	char firstarray[DATA_BLOCK_SIZE];
	char nextarrayy[DATA_BLOCK_SIZE];
	char * nextbuf = nextarrayy;
	char * firstbuf = firstarray;
	
	for (int i = 0; i < packcnt; i++)
	{
		ret = DataBlockList::getBlock(firstdata, firstoffset, firstsize->size, &firstbuf);
		if (ret <= 0)
		{
			break;
		}

		LPPACKSIZELIST nextsize = firstsize->next;
		LPDATABLOCKLIST nextdata = firstdata;
		int nextoffset = firstoffset;

		int firstseq = 0;
		int firstack = 0;
		LPIPHEADER firstip = 0;
		LPPPPOEHEADER firstpppoe = 0;
		LPIPV6HEADER firstipv6 = 0;
		LPTCPHEADER firsttcp = 0;
		char * firstpackdata = 0;
		int firstpackdatasize = 0;

		ret = Packet::getIPHdr((LPMACHEADER)firstbuf, firstpppoe, firstip, firstipv6);
		if (ret == 1)
		{
			firsttcp = (LPTCPHEADER)((char*)firstip + (firstip->HeaderSize << 2));
			firstpackdata = (char*)((char*)firsttcp + (firsttcp->HeaderSize << 2));
			firstpackdatasize = ntohs(firstip->PacketSize) - (firstip->HeaderSize << 2) - (firsttcp->HeaderSize << 2);
		}
		else if (ret == 2)
		{
			firsttcp = (LPTCPHEADER)((char*)firstipv6 + sizeof(IPV6HEADER));
			firstpackdata = (char*)((char*)firsttcp + (firsttcp->HeaderSize << 2));
			firstpackdatasize = ntohs(firstipv6->PayloadLen) - sizeof(IPV6HEADER) - (firsttcp->HeaderSize << 2);
		}
		else {
			break;
		}
		firstseq = firsttcp->SeqNum;
		firstack = firsttcp->AckNum;

		for (int j = i + 1; j < packcnt; j++)
		{
			ret = DataBlockList::getBlock(nextdata, nextoffset, nextsize->size, &nextbuf);
			if (ret <= 0)
			{
				break;
			}

			int nextack = 0;
			int nextseq = 0;
			LPIPHEADER nextip = 0;
			LPPPPOEHEADER nextpppoe = 0;
			LPIPV6HEADER nextipv6 = 0;
			char * nextpackdata = 0;
			int nextpackdatasize = 0;
			LPTCPHEADER nexttcp = 0;
			ret = Packet::getIPHdr((LPMACHEADER)nextbuf, nextpppoe, nextip, nextipv6);
			if (ret == 1) {
				nexttcp = (LPTCPHEADER)((char*)nextip + (nextip->HeaderSize << 2));
				nextpackdata = (char*)((char*)nexttcp + (nexttcp->HeaderSize << 2));
				nextpackdatasize = ntohs(nextip->PacketSize) - (nextip->HeaderSize << 2) - (nexttcp->HeaderSize << 2);
			}
			else if (ret == 2)
			{
				nexttcp = (LPTCPHEADER)((char*)nextipv6 + sizeof(IPV6HEADER));
				nextpackdata = (char*)((char*)nexttcp + (nexttcp->HeaderSize << 2));
				nextpackdatasize = ntohs(nextipv6->PayloadLen) - sizeof(IPV6HEADER) - (nexttcp->HeaderSize << 2);
			}
			else {
				break;
			}
			nextseq = nexttcp->SeqNum;
			nextack = nexttcp->AckNum;

			if (firstseq == nextseq && firstack == nextack)
			{
				int cmpsize = firstpackdatasize;
				if (firstpackdatasize > nextpackdatasize)
				{
					cmpsize = nextpackdatasize;
				}


				if (cmpsize > 0 && (/*nextsize->size != firstsize->size ||*/ memcmp(firstpackdata, nextpackdata, cmpsize)))
				{
					string fn = ResultFile::formatfn(hdr, "tcpattack");
					writePcapFile(&firstsize->hdr, firstbuf, &nextsize->hdr, nextbuf, hdr, fn);

					timerMsgBox();
					return TRUE;
				}
			}

			nextsize = nextsize->next;
		}

		firstsize = firstsize->next;
	}

	return FALSE;
}

int ParseAttacker::checkAttacker(DATALISTHEADER hdr) {
	int ret = FALSE;
	if (hdr.sock.protocol == IPPROTO_TCP)
	{
		if (hdr.packcnt2 >= 2)
		{
			ret = bubbleSortTcp(hdr, hdr.datalist2, hdr.sizelist2, hdr.packcnt2);
			if (ret )
			{
				return TRUE;
			}
		}

		if (hdr.packcnt >= 2)
		{
			ret = bubbleSortTcp(hdr, hdr.datalist, hdr.sizelist, hdr.packcnt);
		}
	}
	else if (hdr.sock.protocol == IPPROTO_UDP && (hdr.sock.srcport == 53 || hdr.sock.dstport == 53))
	{
		if (hdr.packcnt != hdr.packcnt2)
		{
			if (hdr.packcnt2 >= 2)
			{
				ret = bubbleSortDns(hdr, hdr.datalist2, hdr.sizelist2, hdr.packcnt2);
				if (ret)
				{
					return TRUE;
				}
			}

			if (hdr.packcnt >= 2)
			{
				ret = bubbleSortDns(hdr, hdr.datalist, hdr.sizelist, hdr.packcnt);
			}
		}
	}

	return 0;
}

void ParseAttacker::writePcapFile(pcap_pkthdr * phdr1, const char * data1, pcap_pkthdr * phdr2, const char * data2,
	DATALISTHEADER hdr, string filename) {
	int ret = 0;
	string fn = Public::getDataPath() + filename + ".pcap";
	pcap_dumper_t *pdumper = pcap_dump_open(hdr.sock.pcapt, fn.c_str());
	if (pdumper <= 0)
	{
		Public::WriteLogFile("pcap_dump_open error\r\n");
		return;
	}
	pcap_dump((u_char*)pdumper, phdr1, (u_char*)data1);
	pcap_dump((u_char*)pdumper, phdr2, (u_char*)data2);

	char bufarray[DATA_BLOCK_SIZE];
	char * buf = bufarray;
	int firstoffset = 0;
	LPDATABLOCKLIST firstdata = hdr.datalist;
	LPPACKSIZELIST firstsize = hdr.sizelist;
	while (firstdata && firstsize) {
		ret = DataBlockList::getBlock(firstdata, firstoffset, firstsize->size, &buf);
		if (ret <= 0)
		{
			break;
		}
		pcap_dump((u_char*)pdumper, &firstsize->hdr, (u_char*)buf);

		firstsize = firstsize->next;
	}

	firstdata = hdr.datalist2;
	firstsize = hdr.sizelist2;
	firstoffset = 0;
	while (firstdata && firstsize) {
		ret = DataBlockList::getBlock(firstdata, firstoffset, firstsize->size, &buf);
		if (ret <= 0)
		{
			break;
		}
		pcap_dump((u_char*)pdumper, &firstsize->hdr, (u_char*)buf);
		firstsize = firstsize->next;
	}

	pcap_dump_close(pdumper);
}

void ParseAttacker::writeAttackerData(string filename, const char * src, int srclen, const char * dst, int dstlen) {
	string fn = Public::getDataPath() + filename;
	FILE * fp = fopen(fn.c_str(), "ab+");
	if (fp > 0)
	{
		string srcflag = "src packet:\r\n";
		string attackflag = "attack packet:\r\n";

		int ret = fwrite(srcflag.c_str(), 1, srcflag.length(), fp);
		ret = fwrite(src, 1, srclen, fp);

		ret = fwrite("\r\n\r\n", 1, 4, fp);

		ret = fwrite(attackflag.c_str(), 1, attackflag.length(), fp);
		ret = fwrite(dst, 1, dstlen, fp);

		ret = fwrite("\r\n\r\n", 1, 4, fp);
		fclose(fp);
	}
	else {

	}
}



int filterCname(const char * data1, const char * data2) {
	LPDNSHEADER dns1 = (LPDNSHEADER)data1;
	LPDNSHEADER dns2 = (LPDNSHEADER)data2;

	const char * name1 = data1 + sizeof(DNSHEADER);
	const char * name2 = data2 + sizeof(DNSHEADER);

	LPDNSANSWER ans2 = (LPDNSANSWER)(name1 + lstrlenA(name1) + 1 + 4);
	LPDNSANSWER ans1 = (LPDNSANSWER)(name2 + lstrlenA(name2) + 1 + 4);

	do
	{
		if (ans1->Type == 0x0100 && ans2->Type == 0x0100)
		{
			break;
		}

		if (ans2->Type != ans1->Type || ans1->Name != ans2->Name || ans2->Class != ans1->Class)
		{
			return FALSE;
		}

		if (ans2->Type == 0x0500 && ans1->Type == 0x0500 && ans1->Name == ans2->Name && ans2->Class == 0x0100 && ans1->Class == 0x0100)
		{
			int datalen1 = ntohs(ans1->AddrLen);
			int datalen2 = ntohs(ans2->AddrLen);
			const char * cname1 = (const char*)(ans1 + sizeof(DNSANSWER) - 4);
			const char * cname2 = (const char*)(ans2 + sizeof(DNSANSWER) - 4);
			if (datalen2 != datalen1 || memcmp(cname2, cname1, datalen1))
			{
				return FALSE;
			}

			ans2 = (LPDNSANSWER)(cname2 + datalen2);
			ans1 = (LPDNSANSWER)(cname1 + datalen1);
		}
		else {
			return FALSE;
		}
	} while (1);

	while (1)
	{
	}
	int datalen1 = ntohs(ans1->AddrLen);
	int datalen2 = ntohs(ans2->AddrLen);
	const char * cname1 = (const char*)(ans1 + sizeof(DNSANSWER) - 4);
	const char * cname2 = (const char*)(ans2 + sizeof(DNSANSWER) - 4);
	if (datalen2 != datalen1 || memcmp(cname2, cname1, datalen1))
	{
		return FALSE;
	}

	ans2 = (LPDNSANSWER)(cname2 + datalen2);
	ans1 = (LPDNSANSWER)(cname1 + datalen1);

	if (ans1->Type == 0x0100 && ans2->Type == 0x0100 && ans2->Class == 0x0100 && ans1->Class == 0x0100)
	{
		vector <unsigned int> ip1;
		vector<unsigned int> ip2;

	}
	else {
		return FALSE;
	}

	return 0;
}
#endif