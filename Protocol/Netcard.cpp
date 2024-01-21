#pragma once


#include <winsock2.h>
#include <windows.h>
#include <Iptypes.h >
#include <iphlpapi.h>
#include "Public.h"
#include "NetCard.h"
#include "protocol.h"
#include "public.h"

#define WSASTARTUP_VERSION 0x0202



vector<MYADAPTERINFO> NetCard::selectWeapon() {
	vector<MYADAPTERINFO> names ;
	int	iInterfaceCnt = 0;
	PIP_ADAPTER_INFO padpterInfo = ShowNetCardInfo(&iInterfaceCnt);
	if (padpterInfo == FALSE || iInterfaceCnt <= 0)
	{
		getchar();
		return names;
	}

	PIP_ADAPTER_INFO padapters = padpterInfo;
	for (int i = 0;i < iInterfaceCnt;i++)
	{
		MYADAPTERINFO info = { "" };
		info.name = padapters->AdapterName;
		info.ip = inet_addr(padapters->IpAddressList.IpAddress.String);
		info.netgateip = inet_addr(padapters->GatewayList.IpAddress.String);
		info.mask = inet_addr(padapters->IpAddressList.IpMask.String);
		memmove(info.mac, padapters->Address, MAC_ADDRESS_SIZE);
		names.push_back(info);
		padapters = padapters->Next;
	}

	GlobalFree((char*)padpterInfo);
	return names;
}


string NetCard::selectWeaponOld(unsigned long * localIP, unsigned long * netmask, unsigned long * netgateip, unsigned char * lpmac) {
	int	iInterfaceCnt = 0;
	PIP_ADAPTER_INFO padpterInfo = ShowNetCardInfo(&iInterfaceCnt);
	if (padpterInfo == FALSE)
	{
		getchar();
		return "";
	}

	printf("please select net card(1-%d):", iInterfaceCnt);
	int			iChooseNum = 0;
	scanf_s("%d", &iChooseNum);
	printf("\n");
	if (iChooseNum < 1 || iChooseNum > iInterfaceCnt)
	{
		printf("Interface number out of range\n");
		getchar();
		return "";
	}
	PIP_ADAPTER_INFO pAdapter = GetNetCardAdapter(padpterInfo, iChooseNum - 1);

	string adaptername = pAdapter->AdapterName;
	*localIP = inet_addr(pAdapter->IpAddressList.IpAddress.String);
	*netmask = inet_addr(pAdapter->IpAddressList.IpMask.String);
	*netgateip = inet_addr(pAdapter->GatewayList.IpAddress.String);
	memmove(lpmac, pAdapter->Address, MAC_ADDRESS_SIZE);


// 	printf("get ip:%s,mac:%s,netmask:%s,gatewayip:%s\r\n", HttpUtils::getIPstr(*localIP).c_str(),
// 		Init::getmac(lpmac).c_str(), HttpUtils::getIPstr(*netmask).c_str(),
// 		HttpUtils::getIPstr(*netgateip).c_str());
	GlobalFree((char*)padpterInfo);
	return adaptername;
}



PIP_ADAPTER_INFO NetCard::ShowNetCardInfo(int *count) {
	char szout[1024];
	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)GlobalAlloc(GPTR, sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL)
	{
		printf("ShowNetCardInfo GlobalAlloc error\r\n");
		return FALSE;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		GlobalFree((char*)pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)GlobalAlloc(GPTR, ulOutBufLen);
		if (pAdapterInfo == NULL)
		{
			printf("ShowNetCardInfo GetAdaptersInfo first error\r\n");
			return FALSE;
		}
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR)
	{
		int number = 0;
		PIP_ADAPTER_INFO pAdapter = 0;
		printf("������װ�������б�����:\r\n");
		for (pAdapter = pAdapterInfo; pAdapter != NULL; pAdapter = pAdapter->Next)
		{
			/*
			if(pAdapter->Type != MIB_IF_TYPE_ETHERNET && pAdapter->Type !=  IF_TYPE_IEEE80211)
			{
			continue;
			}

			if(pAdapter->AddressLength != MAC_ADDRESS_SIZE)
			{
			continue;
			}
			if (lstrlenA(pAdapter->IpAddressList.IpAddress.String) < 8 || lstrlenA(pAdapter->GatewayList.IpAddress.String) < 8)
			{
			continue;
			}

			if (RtlCompareMemory(pAdapter->IpAddressList.IpAddress.String,"0.0.0.0",7) != 7 && RtlCompareMemory(pAdapter->GatewayList.IpAddress.String,"0.0.0.0",7) != 7)
			{
			break;
			}
			*/
			number++;
			wsprintfA(szout,"��������:\t%d\r\n��������:\t%s\r\n��������:\t%s\r\n��������:\t%d\r\n����IP��ַ:\t%s\r\n����IP��ַ:\t%s\r\n\r\n",
				number, pAdapter->AdapterName, pAdapter->Description, pAdapter->Type, pAdapter->IpAddressList.IpAddress.String,
				pAdapter->GatewayList.IpAddress.String);
			Public::WriteLogFile(szout);
			printf(szout);
		}

		*count = number;
		//GlobalFree((char*)pAdapterInfo); 
		return pAdapterInfo;
	}
	else
	{
		printf("GetNetCardInfo GetAdaptersInfo second error\r\n");
		GlobalFree((char*)pAdapterInfo);
		return FALSE;
	}
}




PIP_ADAPTER_INFO NetCard::GetNetCardAdapter(PIP_ADAPTER_INFO pAdapterInfo, int seq) {

	PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
	for (int number = 0; number < seq; pAdapter = pAdapter->Next, number++)
	{
		if (pAdapter == NULL)
		{
			return FALSE;
		}
	}
	return pAdapter;
}


int NetCard::initWinSocket(void) {
	WSADATA	stWsa = { 0 };
	int nRetCode = WSAStartup(WSASTARTUP_VERSION, &stWsa);
	if (nRetCode)
	{
		printf("WSAStartup error code:%d\n", GetLastError());
		getchar();
		return -1;
	}

	return 0;
}
