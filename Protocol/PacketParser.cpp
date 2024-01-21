
#include <vector>
#include <string>
#include <iostream>
#include "Public.h"
#include "Packet.h"
#include "include\\pcap.h"
#include "include\\pcap\\pcap.h"
#include "winpcap.h"
#include <unordered_map>
#include <vector>
#include <map>
#include "packetParser.h"
#include "DataList.h"
#include "SoftFilter.h"
#include "parseAttacker.h"

using namespace  std;

int __stdcall PacketParser::peeping(LPPCAPPARAMS remoteparams)
{
	PCAPPARAMS params = *remoteparams;

	int iRet = 0;

	int errorcnt = 0;

	char szout[1024];

	try {
		pcap_pkthdr *	pHeader = 0;
		const char * pData = 0;

		char * packData = 0;
		int packDataLen = 0;

		while (TRUE)
		{
			iRet = pcap_next_ex(params.pcapt, &pHeader, (const unsigned char**)&pData);
			if (iRet == 0)
			{
				continue;
			}
			else if (iRet < 0)
			{
				wsprintfA(szout,"pcap_next_ex error:%d\r\n", iRet);
				Public::WriteLogFile(szout);

				errorcnt++;
				if (errorcnt >= 1024)
				{
					errorcnt = 0;
					//MessageBoxA(0, "restart program", "restart program", MB_OK);
					return 0;
				}
				continue;
			}

			if (pHeader->len != pHeader->caplen || pHeader->caplen >= WINPCAP_MAX_PACKET_SIZE || pHeader->caplen <= 0)
			{
				wsprintfA(szout,"pcap_next_ex packet caplen:%u or len:%u error\r\n", pHeader->caplen, pHeader->len);
				Public::WriteLogFile(szout);
				continue;
			}

			int iCapLen = pHeader->len;
			*((char*)pData + iCapLen) = 0;

 			(*params.packcnts)++;
// 			if (*params.packcnts % 0x10000 == 0)
// 			{
// 				wsprintfA(szout, "sniffer packets:%I64u\r\n", *params.packcnts);
// 				Public::WriteLogFile(szout);
// 			}

			LPPPPOEHEADER pppoe = 0;
			LPIPHEADER pIPHdr = 0;
			LPIPV6HEADER pIPV6 = 0;
			LPMACHEADER pMac = (LPMACHEADER)pData;
			int iptype = Packet::getIPHdr(pMac, pppoe, pIPHdr, pIPV6);
			if (iptype < 0)
			{
				Public::WriteLogFile("not found ip header\r\n");
				Public::WriteDataFile(LOG_FILENAME, (char*)pData, iCapLen);
				continue;
			}
			else if (iptype == 1)
			{
				if (pIPHdr->Version != 4)
				{
					Public::WriteLogFile("ip header version error\r\n");
					continue;
				}

				int iIpHdrLen = pIPHdr->HeaderSize << 2;
				if (pIPHdr->Protocol == IPPROTO_TCP)
				{
					LPTCPHEADER pTcpHdr = (LPTCPHEADER)((char*)pIPHdr + iIpHdrLen);
					int iTcpHdrLen = pTcpHdr->HeaderSize << 2;
					packData = (char*)pTcpHdr + iTcpHdrLen;
					packDataLen = ntohs(pIPHdr->PacketSize) - iIpHdrLen - iTcpHdrLen;
					//packDataLen = iCapLen - (packData - pData);
					if (/*pTcpHdr->FIN || pTcpHdr->SYN ||*/ packDataLen > 0 )
					{
						
#ifndef PARSE_ATTACKER
						if (SoftFilter::portFilter(pTcpHdr->SrcPort, pTcpHdr->DstPort, IPPROTO_TCP))
#endif
						{
							SESSIONSOCKET sock = { 0 };
							sock.srcip = pIPHdr->SrcIP;
							sock.srcport = ntohs(pTcpHdr->SrcPort);
							sock.dstip = pIPHdr->DstIP;
							sock.dstport = ntohs(pTcpHdr->DstPort);
							sock.protocol = pIPHdr->Protocol;
							memcpy(sock.srcmac, pMac->SrcMAC, MAC_ADDRESS_SIZE);
							memcpy(sock.dstmac, pMac->DstMAC, MAC_ADDRESS_SIZE);
#ifdef PARSE_ATTACKER
							sock.pcapt = params.pcapt;
							DataBlockList::push(pHeader, &sock, pData, iCapLen, pTcpHdr->FIN, pTcpHdr->SYN);
#else
							DataBlockList::push(pHeader,&sock, packData, packDataLen, pTcpHdr->FIN,pTcpHdr->SYN);
#endif
						}
					}
				}else if (pIPHdr->Protocol == IPPROTO_UDP)
				{
					LPUDPHEADER pUDPHdr = (LPUDPHEADER)((char*)pIPHdr + iIpHdrLen);
					packData = (char*)pUDPHdr + sizeof(UDPHEADER);
					//packDataLen = iCapLen - (packData - pData);
					packDataLen = ntohs(pIPHdr->PacketSize) - iIpHdrLen - sizeof(UDPHEADER);
					if (packDataLen > 0)
					{
#ifndef PARSE_ATTACKER
						if (SoftFilter::portFilter(pUDPHdr->SrcPort, pUDPHdr->DstPort, IPPROTO_UDP))
#endif
						{
							SESSIONSOCKET sock = { 0 };
							sock.srcip = pIPHdr->SrcIP;
							sock.srcport = ntohs(pUDPHdr->SrcPort);
							sock.dstip = pIPHdr->DstIP;
							sock.dstport = ntohs(pUDPHdr->DstPort);
							sock.protocol = pIPHdr->Protocol;
							memcpy(sock.srcmac, pMac->SrcMAC, MAC_ADDRESS_SIZE);
							memcpy(sock.dstmac, pMac->DstMAC, MAC_ADDRESS_SIZE);
#ifdef PARSE_ATTACKER
							sock.pcapt = params.pcapt;
							DataBlockList::push(pHeader, &sock, pData, iCapLen);
#else
							DataBlockList::push(pHeader, &sock, packData, packDataLen);
#endif
						}
					}
				}
			}
			else if (iptype == 2)
			{
				LPIPV6HEADER pIPHdr = (LPIPV6HEADER)pIPV6;
				if (pIPHdr->Version != 6)
				{
					continue;
				}

				int iIpHdrLen = sizeof(IPV6HEADER);
				if (pIPHdr->NextPacket == IPPROTO_TCP)
				{
					LPTCPHEADER pTcpHdr = (LPTCPHEADER)((char*)pIPHdr + iIpHdrLen);
					int iTcpHdrLen = pTcpHdr->HeaderSize << 2;
					char * packData = (char*)pTcpHdr + iTcpHdrLen;
					//int packDataLen = iCapLen - (packData - pData);
					packDataLen = ntohs(pIPHdr->PayloadLen) - iTcpHdrLen;
					if (/*pTcpHdr->FIN || pTcpHdr->SYN ||*/ packDataLen > 0)
					{
#ifndef PARSE_ATTACKER
						if (SoftFilter::portFilter(pTcpHdr->SrcPort, pTcpHdr->DstPort, IPPROTO_TCP))
#endif
						{
							SESSIONSOCKET sock = { 0 };
							sock.srcip = 0;
							sock.srcport = ntohs(pTcpHdr->SrcPort);
							sock.dstip = 0;
							sock.dstport = ntohs(pTcpHdr->DstPort);
							sock.protocol = IPPROTO_TCP;
							memcpy(sock.srcmac, pMac->SrcMAC, MAC_ADDRESS_SIZE);
							memcpy(sock.dstmac, pMac->DstMAC, MAC_ADDRESS_SIZE);
#ifdef PARSE_ATTACKER
							sock.pcapt = params.pcapt;
							DataBlockList::push(pHeader, &sock, pData, iCapLen, pTcpHdr->FIN, pTcpHdr->SYN);
#else
							DataBlockList::push(pHeader, &sock, packData, packDataLen, pTcpHdr->FIN, pTcpHdr->SYN);
#endif
						}
					}
				}
				else if (pIPHdr->NextPacket == IPPROTO_UDP)
				{
					LPUDPHEADER pUDPHdr = (LPUDPHEADER)((char*)pIPHdr + iIpHdrLen);
					packData = (char*)pUDPHdr + sizeof(UDPHEADER);
					//packDataLen = iCapLen - (packData - pData);
					packDataLen = ntohs(pIPHdr->PayloadLen) - sizeof(UDPHEADER);
					if (packDataLen > 0)
					{
#ifndef PARSE_ATTACKER
						if (SoftFilter::portFilter(pUDPHdr->SrcPort, pUDPHdr->DstPort, IPPROTO_UDP))
#endif
						{
							SESSIONSOCKET sock = { 0 };
							sock.srcip = 0;
							sock.srcport = ntohs(pUDPHdr->SrcPort);
							sock.dstip = 0;
							sock.dstport = ntohs(pUDPHdr->DstPort);
							sock.protocol = IPPROTO_UDP;
							memcpy(sock.srcmac, pMac->SrcMAC, MAC_ADDRESS_SIZE);
							memcpy(sock.dstmac, pMac->DstMAC, MAC_ADDRESS_SIZE);
#ifdef PARSE_ATTACKER
							sock.pcapt = params.pcapt;
							DataBlockList::push(pHeader, &sock, pData, iCapLen);
#else
							DataBlockList::push(pHeader, &sock, packData, packDataLen);
#endif
						}
					}
				}
			}else if (iptype == 3)
			{
				//pppeo
			}
		}
	}
	catch (...)
	{
		Public::WriteLogFile("packet sniffer exception\r\n");
		return FALSE;
	}

	return TRUE;
}
