
#include "ResultFile.h"
#include <winsock2.h>
#include "ProtocolParser.h"
#include "public.h"
#include "fileOper.h"
#include "MySqlite.h"


string ResultFile::formatMac(unsigned char *mac) {
	char szmac[1024];
	sprintf(szmac, "%02x_%02x_%02x_%02x_%02x_%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return szmac;
}

string ResultFile::formatIp(unsigned int ip) {
	unsigned char * lpip = (unsigned char*)&ip;
	char szip[16];
	sprintf(szip, "%u.%u.%u.%u",lpip[0], lpip[1], lpip[2], lpip[3]);
	return szip;
}

string ResultFile::formatFile(SESSIONSOCKET sock,string action, string info,string pro) {
	char strsock[1024];
	time_t now = time(0);
	sprintf(strsock, 
		"{\"smac\":\"%s\",\"sip\":\"%s\",\"sport\":\"%u\",\"dmac\":\"%s\",\"dip\":\"%s\",\"dport\":\"%u\",\"t\":\"%I64d\",\"pro\":\"%s\",\"act\":\"%s\",\"info\":\"%s\"}",
		formatMac(sock.srcmac).c_str(),
		formatIp(sock.srcip).c_str(),
		ntohs(sock.srcport), 
		formatMac(sock.dstmac).c_str(),
		formatIp(sock.dstip).c_str(),
		ntohs(sock.dstport),
		now,
		pro.c_str(),
		action.c_str(),
		info.c_str());
	return strsock;
}

void ResultFile::writeRecord(DATALISTHEADER hdr,string pro,string action, string info) {
	string filename = Public::getDataPath() + formatfn(hdr,pro) ;
	string content = ResultFile::formatFile(hdr.sock, action, info, pro);

	FileOper::fileWriter(filename, content.c_str(), content.length());

	MySqlite * sql = new MySqlite();
	sql->push(hdr, pro, action,info);
	delete sql;
	return;
}


string ResultFile::formatfn(DATALISTHEADER hdr, string pro) {
	char szfn[1024];
	wsprintfA(szfn, "%02x%02x%02x%02x%02x%02x_%x_%x_%02x%02x%02x%02x%02x%02x_%x_%x_%x_%I64u_%s",
		hdr.sock.srcmac[0], hdr.sock.srcmac[1], hdr.sock.srcmac[2],
		hdr.sock.srcmac[3], hdr.sock.srcmac[4], hdr.sock.srcmac[5],
		hdr.sock.srcip, hdr.sock.srcport,
		hdr.sock.dstmac[0], hdr.sock.dstmac[1], hdr.sock.dstmac[2],
		hdr.sock.dstmac[3], hdr.sock.dstmac[4], hdr.sock.dstmac[5],
		hdr.sock.dstip, hdr.sock.dstport,
		hdr.sock.protocol,
		hdr.starttime,
		pro.c_str());
	return szfn;
}