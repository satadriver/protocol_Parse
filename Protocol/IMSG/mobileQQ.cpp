
#include "mobileQQ.h"
#include "winsock2.h"
#include "qqcrypt.h"
#include "../public.h"
#include "../ProtocolParser.h"
#include "../ResultFile.h"
#include "../fileOper.h"
#include "../SearchData.h"


int parseHeartbeat(const char * data, int len) {
	const char * pos = SearchData::getstring("Heartbeat.Alive", lstrlenA("Heartbeat.Alive"), data, len);
	if (pos)
	{
		pos = pos - lstrlenA("Heartbeat.Alive") - 2;
		int len = ntohl(*(short*)pos);
		pos += len;

		len = ntohs(*(short*)pos);
		pos += len;

		len = ntohs(*(short*)pos);
		string imei = string(pos + 2, len - 2);
		pos += len;

		len = ntohs(*(short*)pos);
		pos += len;

		len = ntohs(*(short*)(pos -2));
		if (*pos == '|')
		{
			string imsi = string(pos, len - 2);
			imsi = imsi.substr(1);
			int dot = imsi.find("|");
			if (dot > 0)
			{
				imsi = imsi.substr(0, dot);
			}
		}		
	}

	return 0;
}

int MobileQQ::parsePacket(const char * data, int &len,int dport,int sport,DATALISTHEADER hdr) {

	const char * qqdata = data;

	LPMOBILEQQ_PACK_HDR qqhdr = (LPMOBILEQQ_PACK_HDR)qqdata;
	int offset = ntohl(qqhdr->offset);
	if (offset >= 0x80 || offset < 0)
	{
		offset = 4;
	}

	qqdata = qqdata + sizeof(MOBILEQQ_PACK_HDR) + offset;

	string qqno = "";
	char qqnolen = *qqdata - sizeof(int);
	if (qqnolen >= 5 && qqnolen <= 10)
	{
		qqdata++;
		qqno = string(qqdata, qqnolen);
	}
	else {
		printf("error qq no len\r\n");
		return -1;
	}

	qqdata += qqnolen;

	if (qqhdr->cryption == 2)
	{
		ResultFile::writeRecord(hdr, "mqq", "on", qqno);

		unsigned char key[16] = { 0 };

		int cryptlen = len - (qqdata - data);
		unsigned char *decodebuf = new unsigned char[cryptlen + 4096];
		int decodelen = cryptlen + 4096;
		int ret = qq_decrypt((unsigned char*)qqdata, cryptlen, key, decodebuf, &decodelen);
		if (/*ret && */decodelen > 0)
		{
			*(decodebuf + decodelen) = 0;
			printf("succeed decrypted size:%u,encrypted size:%u\r\n", decodelen, cryptlen);
			Public::WriteDataFile("mobileqq.dat", (const char*)decodebuf, decodelen);

			//ResultFile::writeRecord(hdr, "mqq", "on", qqno);
		}
		else {
			printf("error:decrypted size:%u,encrypted size:%u\r\n", decodelen, cryptlen);
			//printf("decrypt mobile qq fix crypt packet error\r\n");
		}

		delete decodebuf;
	}
	else if(qqhdr->cryption == 0){
		printf("no cryption mobile qq packet\r\n");
	}
	else if (qqhdr->cryption == 1)
	{

	}
	else {
		printf("error qq packet cryption\r\n");
		return -1;
	}

	return 0;
}


int MobileQQ::isMobileQQPack(DATALISTHEADER hdr) {
	int dport = hdr.sock.dstport;
	char * data = hdr.datalist->data;
	int len = hdr.sizelist->size;

	if (hdr.sock.protocol == 6 &&(dport == 8080 || dport == 443 || dport == 80 || dport == 14000))
	{
		int packlen = ntohl(*(int*)data);
		if (len == packlen )
		{
			char crypt = *(data + 8);
			if (crypt == 1 || crypt == 2 || crypt == 0)
			{
				int ver = *(int*)(data + sizeof(int));
				//3 = 2010 11 = 2016
				if (ver == 0x0a000000 || ver == 0x0b000000 || ver == 0x09000000)
				{
					return TRUE;
				}
			}
		}
	}

	return FALSE;
}






