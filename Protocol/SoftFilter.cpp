
#include "SoftFilter.h"
#include <windows.h>
#include <vector>
#include <WinSock2.h>

using namespace std;

vector<unsigned int> gUdpsFilter;
vector<unsigned int> gUdpdFilter;
vector<unsigned int> gTcpsFilter;
vector<unsigned int> gTcpdFilter;

int SoftFilter::portFilter(unsigned short srcport, unsigned short dstport, int pro) {
	if (pro == IPPROTO_TCP)
	{
		for (unsigned int i = 0; i < gTcpsFilter.size(); i++)
		{
			if ( srcport == gTcpsFilter[i])
			{
				return TRUE;
			}
		}

		for (unsigned int i = 0; i < gTcpdFilter.size(); i++)
		{
			if (dstport == gTcpdFilter[i] )
			{
				return TRUE;
			}
		}
		return FALSE;
	}
	else if (pro == IPPROTO_UDP)
	{
		for (unsigned int i = 0;i < gUdpdFilter.size();i ++)
		{
			if (dstport == gUdpdFilter[i])
			{
				return TRUE;
			}
		}

		for (unsigned int i = 0; i < gUdpsFilter.size(); i++)
		{
			if (srcport == gUdpsFilter[i] )
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	return FALSE;
}

int SoftFilter::init(vector<unsigned int> udpsports, vector<unsigned int> udpdports, 
	vector<unsigned int> tcpsports, vector<unsigned int> tcpdports) {
	gUdpsFilter = udpsports;
	gUdpdFilter = udpdports;
	gTcpsFilter = tcpsports;
	gTcpdFilter = tcpdports;
	return 0;
}