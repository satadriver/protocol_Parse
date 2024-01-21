#include "DataList.h"
#include "ProtocolParser.h"
#include "public.h"
#include "parseAttacker.h"



unordered_map <string, DATALISTHEADER> gDataMap;

CRITICAL_SECTION gcs = { 0 };

void DataBlockList::enterlock() {
	EnterCriticalSection(&gcs);
}

void DataBlockList::leavelock() {
	LeaveCriticalSection(&gcs);
}

int DataBlockList::push(pcap_pkthdr *pcaphdr,SESSIONSOCKET *sock, const char * data, int datalen) {
	return push(pcaphdr,sock, data, datalen, 0,0);
}

int DataBlockList::push(pcap_pkthdr *pcaphdr, SESSIONSOCKET *sock, const char * data, int datalen,int fin,int syn) {

	if (datalen > DATA_BLOCK_SIZE || datalen < 0)
	{
		printf("push size:%u error\r\n", datalen);
		return FALSE;
	}

	int ret = 0;
	char szfirstkey[1024];
	wsprintfA(szfirstkey, "%x_%x_%x_%x_%x", sock->srcip, sock->srcport, sock->dstip, sock->dstport, sock->protocol);

	enterlock();

	unordered_map <string, DATALISTHEADER>::iterator it = gDataMap.find(string(szfirstkey));
	if (it == gDataMap.end())
	{
		char sznextkey[1024];
		wsprintfA(sznextkey, "%x_%x_%x_%x_%x", sock->dstip, sock->dstport, sock->srcip, sock->srcport, sock->protocol);
		it = gDataMap.find(string(sznextkey));
		if (it == gDataMap.end())
		{
			if (datalen > 0 )
			{
				DATALISTHEADER hdr = { 0 };
				hdr.sock = *sock;

				LPDATABLOCKLIST datalist = new DATABLOCKLIST;
				memset(&(datalist->hdr), 0, sizeof(datalist->hdr));
				memcpy(datalist->data, data, datalen);
				datalist->hdr.size = datalen;
				hdr.datalist = datalist;
				hdr.lastdata = datalist;

				LPPACKSIZELIST packsizelist = new PACKSIZELIST;
				memset(packsizelist, 0, sizeof(PACKSIZELIST));
				packsizelist->size = datalen;
#ifdef PARSE_ATTACKER
				packsizelist->hdr = *pcaphdr;
#endif
				hdr.sizelist = packsizelist;
				hdr.lastsize = packsizelist;

				hdr.totalsize = datalen;
				hdr.starttime = time(0);
				hdr.packcnt = 1;
				
				LPDATABLOCKLIST datalist2 = new DATABLOCKLIST;
				memset(&(datalist2->hdr), 0, sizeof(datalist2->hdr));
				hdr.datalist2 = datalist2;
				hdr.lastdata2 = datalist2;
				hdr.starttime2 = hdr.starttime;

				pair< std::unordered_map< string, DATALISTHEADER >::iterator, bool > retit;
				retit = gDataMap.insert(pair<string, DATALISTHEADER>(string(szfirstkey), hdr));
				if (retit.second == 0) {
					printf("gDataMap insert error\r\n");
					ret = -1;
				}
				else {
					ret = datalen;
				}
			}
		}
		else {
			if (datalen > 0)
			{
				DATABLOCKLIST * lastdata2 = it->second.lastdata2;
				int least = DATA_BLOCK_SIZE - lastdata2->hdr.size;
				if (least < 0 || least > DATA_BLOCK_SIZE)
				{
					printf("least size:%u error\r\n", least);
					return FALSE;
				}

				if (datalen >= least)
				{
					memcpy(lastdata2->data + lastdata2->hdr.size, data, least);
					lastdata2->hdr.size += least;

					DATABLOCKLIST * nextdata = new DATABLOCKLIST;
					memset(&(nextdata->hdr), 0, sizeof(nextdata->hdr));
					memcpy(nextdata->data, data + least, datalen - least);
					nextdata->hdr.size = datalen - least;
					nextdata->hdr.previous = lastdata2;
					lastdata2->hdr.next = nextdata;
					it->second.lastdata2 = nextdata;
				}
				else {
					memcpy(lastdata2->data + lastdata2->hdr.size, data, datalen);
					lastdata2->hdr.size += datalen;
				}

				it->second.totalsize2 += datalen;
				it->second.starttime2 = time(0);
				it->second.packcnt2 ++;

				LPPACKSIZELIST nextsize = new PACKSIZELIST;
				memset(nextsize, 0, sizeof(PACKSIZELIST));
				nextsize->size = datalen;
#ifdef PARSE_ATTACKER
				nextsize->hdr = *pcaphdr;
#endif
				if (it->second.sizelist2 && it->second.lastsize2)
				{
					nextsize->previous = it->second.lastsize2;
					it->second.lastsize2->next = nextsize;
					it->second.lastsize2 = nextsize;
				}
				else {
					it->second.sizelist2 = nextsize;
					it->second.lastsize2 = nextsize;
				}

				ret = datalen;	
			}

			if (fin | syn)
			{
				it->second.ready2 = TRUE;
				it->second.ready = TRUE;
			}
		}
	}
	else {
		if (datalen > 0)
		{
			DATABLOCKLIST * lastdata = it->second.lastdata;
			int least = DATA_BLOCK_SIZE - lastdata->hdr.size;
			if (least < 0 || least > DATA_BLOCK_SIZE)
			{
				printf("least size:%u error\r\n", least);
				return FALSE;
			}

			if (datalen >= least )
			{
				memcpy(lastdata->data + lastdata->hdr.size, data, least);
				lastdata->hdr.size += least;

				DATABLOCKLIST * nextdata = new DATABLOCKLIST;
				memset(&nextdata->hdr, 0, sizeof(nextdata->hdr));
				memcpy(nextdata->data, data + least, datalen - least);
				nextdata->hdr.size = datalen - least;

				lastdata->hdr.next = nextdata;
				nextdata->hdr.previous = lastdata;
				it->second.lastdata = nextdata;
			}
			else {
				memcpy(lastdata->data + lastdata->hdr.size, data, datalen);
				lastdata->hdr.size += datalen;
			}

			it->second.totalsize += datalen;
			it->second.packcnt++;
			it->second.starttime = time(0);

			LPPACKSIZELIST nextsize = new PACKSIZELIST;
			memset(nextsize, 0, sizeof(PACKSIZELIST));
			nextsize->size = datalen;
#ifdef PARSE_ATTACKER
			nextsize->hdr = *pcaphdr;
#endif
			nextsize->previous = it->second.lastsize;
			it->second.lastsize->next = nextsize;
			it->second.lastsize = nextsize;

			ret = datalen;
		}

		if (fin | syn)
		{
			it->second.ready2 = TRUE;
			it->second.ready = TRUE;
		}
	}

	leavelock();
	return ret;
}




int __stdcall DataBlockList::process() {

	int ret = 0;

	while (TRUE)
	{
		vector <DATALISTHEADER> result;
		result.clear();
		time_t now = time(0);
		unordered_map <string, DATALISTHEADER>::iterator it;

		enterlock();

		for (it = gDataMap.begin(); it != gDataMap.end(); ) {
			if (it->second.ready || it->second.ready2 ||
				(now - it->second.starttime >= STREAM_TIMEOUT &&  now - it->second.starttime2 >= STREAM_TIMEOUT)
				|| it->second.packcnt >= MAX_PACKET_CNT || it->second.packcnt2 >= MAX_PACKET_CNT ||
				it->second.totalsize >= MAX_BLOCK_SIZE || it->second.totalsize2 >= MAX_BLOCK_SIZE
				)
			{
				result.push_back(it->second);

				gDataMap.erase(it ++);
			}
			else {
				it++;
			}
		}

		leavelock();

		for (unsigned int i = 0;i < result.size(); i ++)
		{
			__try {
#ifndef PARSE_ATTACKER
				ret = ProtocolParser::parse(result[i]);
#else
				ret = ParseAttacker::checkAttacker(result[i]);
#endif
			}
			__except (1) {
				printf("parse exception\r\n");
			}
			
			remove(result[i]);
		}
		
		Sleep(PROCESS_WAITTIME);
	}
	return 0;
}


int DataBlockList::remove(DATALISTHEADER hdr) {

	LPDATABLOCKLIST datalist = hdr.datalist;
	while (datalist)
	{
		
		DATABLOCKLIST * list = datalist;

		datalist = datalist->hdr.next;

		delete list;
	}

	LPPACKSIZELIST sizelist = hdr.sizelist;
	while (sizelist)
	{
		LPPACKSIZELIST list = sizelist;
		sizelist = sizelist->next;
		delete list;
		list = 0;
	}

	LPDATABLOCKLIST datalist2 = hdr.datalist2;
	while (datalist2)
	{
		DATABLOCKLIST * list = datalist2;

		datalist2 = datalist2->hdr.next;

		delete list;
	}

	LPPACKSIZELIST sizelist2 = hdr.sizelist2;
	while (sizelist2)
	{
		LPPACKSIZELIST list = sizelist2;
		sizelist2 = sizelist2->next;
		delete list;
	}

	return 0;
}


void DataBlockList::init() {
	InitializeCriticalSection(&gcs);
}


int DataBlockList::getBlock(LPDATABLOCKLIST &datalist, int & offset, int size, char **data) {
	if (offset >= DATA_BLOCK_SIZE || offset < 0 || size >= MAX_BLOCK_SIZE || size <= 0 || datalist <= 0)
	{
		printf("getblock datalist:%p,offset:%u,size:%u error\r\n", datalist, offset, size);
		return 0;
	}

	if (*data == 0)
	{
		*data = new char[size + 1024];
	}

	int leastsize = DATA_BLOCK_SIZE - offset;
	if (size < leastsize)
	{
		memcpy(*data, datalist->data + offset, size);
		offset += size;
		return size;
	}

	memcpy(*data, datalist->data + offset, leastsize);
	datalist = datalist->hdr.next;
	offset = 0;
	
	int newoffset = leastsize;
	int leasttotal = size - leastsize;
	int times = leasttotal / DATA_BLOCK_SIZE;
	for (int i = 0; i < times; i++)
	{
		memcpy(*data + newoffset, datalist->data, datalist->hdr.size);
		newoffset += datalist->hdr.size;
		datalist = datalist->hdr.next;
		if (datalist <= 0)
		{
			break;
		}
	}

	int mod = leasttotal % DATA_BLOCK_SIZE;
	if (mod)
	{
		memcpy(*data + newoffset, datalist->data, mod);
		newoffset += mod;
		offset = mod;
	}

	return newoffset;
}



int DataBlockList::getNextPacket(LPDATABLOCKLIST &datalist, int &offset, LPPACKSIZELIST &sizelist, char *data) {
	if (sizelist <= 0 || datalist <= 0 || offset < 0 || offset >= DATA_BLOCK_SIZE)
	{
		printf("getNextPacket datalist:%p,sizelist:%p error\r\n", datalist, sizelist);
		return 0;
	}

	int size = sizelist->size;
	if (size >= DATA_BLOCK_SIZE || size <= 0)
	{
		return FALSE;
	}

	sizelist = sizelist->next;

	int leastsize = DATA_BLOCK_SIZE - offset;
	if (size < leastsize)
	{
		memcpy(data, datalist->data + offset, size);
		offset += size;
		return size;
	}

	memcpy(data, datalist->data + offset, leastsize);
	datalist = datalist->hdr.next;
	offset = 0;
	
	int newoffset = leastsize;
	int leasttotal = size - leastsize;

	int times = leasttotal / DATA_BLOCK_SIZE;
	for (int i = 0; i < times; i++)
	{
		memcpy(data + newoffset, datalist->data, DATA_BLOCK_SIZE);
		newoffset += DATA_BLOCK_SIZE;
		sizelist = sizelist->next;
		datalist = datalist->hdr.next;
		if (datalist <= 0)
		{
			break;
		}
	}

	int mod = leasttotal % DATA_BLOCK_SIZE;
	if (mod)
	{
		memcpy(data + newoffset, datalist->data, mod);
		newoffset += mod;
		offset = mod;
	}

	return newoffset;
}


int DataBlockList::writeBlocks(LPDATABLOCKLIST list, string filename) {
	int ret = 0;
	string fn = Public::getDataPath() + filename;
	FILE * fp = fopen(fn.c_str(), "ab+");
	if (fp <= 0)
	{
		return FALSE;
	}

	int filesize = 0;
	while (list)
	{
		ret = fwrite(list->data, 1, list->hdr.size, fp);
		filesize += list->hdr.size;
		list = list->hdr.next;
	}

	fclose(fp);
	return filesize;
}

int DataBlockList::find(char * flag, int flaglen, LPDATABLOCKLIST &first, int & offset) {
	int ret = 0;

	while (first)
	{
		int size = first->hdr.size - flaglen;

		for (int i = 0; i <= size; i++)
		{
			if (memcmp(first->data + i, flag, flaglen) == 0)
			{
				offset = i;
				return i;
			}
		}
		first = first->hdr.next;
	}

	return -1;
}