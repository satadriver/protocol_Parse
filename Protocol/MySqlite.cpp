#include "public.h"
#include "MySqlite.h"
#include "DataList.h"
#include "HttpUtils.h"
#include <WinSock2.h>
#include <iostream>

using namespace std;

#pragma comment(lib,"sqlite.lib")

static int sqlite3Callback(void * param, int cnt, char **value, char **name);

MySqlite::MySqlite() {
	int cnt = 0;
	while (1)
	{
		int res = sqlite3_open(SQLITE_FILENAME, &mSqlite);
		if (res == SQLITE_BUSY)
		{
			Sleep(100);
			cnt++;
			if (cnt > 5)
			{
				char szout[1024];
				wsprintfA(szout, "sqlite3_open error:%s\r\n", sqlite3_errmsg(mSqlite));
				Public::WriteLogFile(szout);
				return;
			}
		}else if (res == SQLITE_OK)
		{
			return;
		}
		else {
			char szout[1024];
			wsprintfA(szout, "sqlite3_open error:%s\r\n", sqlite3_errmsg(mSqlite));
			Public::WriteLogFile(szout);
			return;
		}
	}
}

MySqlite::~MySqlite() {
	close();
}

int MySqlite::close() {
	sqlite3_close(mSqlite);
	return 0;
}


bool MySqlite::push( DATALISTHEADER hdr,string pro, string action,string content) {
	string format = "insert into protocol(smac,sip,sport,dmac,dip,dport,pack,time,pro,action,content) values ('%s','%s','%u','%s','%s','%u','%u','%I64u','%s','%s','%s')";    

	string smac = HttpUtils::getmacstr(hdr.sock.srcmac);
	string dmac = HttpUtils::getmacstr(hdr.sock.dstmac);
	string sip = HttpUtils::getIPstr(hdr.sock.srcip);
	string dip = HttpUtils::getIPstr(hdr.sock.dstip);

	char* error = 0;
	char cmd[0x10000];
	sprintf(cmd, format.c_str(), 
		smac.c_str(), sip.c_str(),hdr.sock.srcport, 
		dmac.c_str(), dip.c_str(), hdr.sock.dstport,
		hdr.sock.protocol,
		hdr.starttime, pro.c_str(), action.c_str(), content.c_str());
	int res = sqlite3_exec(mSqlite, cmd, sqlite3Callback,0, &error);
	if (res != SQLITE_OK) { 
		char szout[1024];
		wsprintfA(szout, "sqlite3_exec error:%s\r\n", error);
		Public::WriteLogFile(szout);
		return false; 
	}    
	return true; 
} 


bool MySqlite::createTable() {
	string cmd = "CREATE TABLE protocol "
		"(id INTEGER,"
		"smac varchar(32),"
		"sip varchar(32),"
		"sport INTEGER,"
		"dmac varchar(32),"
		"dip varchar(32),"
		"dport INTEGER,"
		"pack INTEGER,"
		"time INTEGER,"
		"pro varchar(64),"
		"action varchar(64),"
		"content TEXT)";

	char* error = 0;
	int res = sqlite3_exec(mSqlite, cmd.c_str(), sqlite3Callback, 0, &error);
	if (res != SQLITE_OK) {
		char szout[1024];
		wsprintfA(szout, "sqlite3_exec error:%s\r\n", error);
		Public::WriteLogFile(szout);
		return false;
	}
	return true;
}

static vector<MYPROTOCOLDATA> gResult;

static int sqlite3Callback(void * param, int cnt, char **value, char **name) {

	MYPROTOCOLDATA mydata = { "" };
	for (int i = 0; i < cnt; i++) {

		if (name[i])
		{
			mydata.item[i][0] = name[i];
		}
		else {
			mydata.item[i][0] = "";
		}

		if (value[i])
		{
			mydata.item[i][1] = value[i];
		}
		else {
			mydata.item[i][1] = "";
		}

		printf("name:%s,value:%s\r\n", name[i], value[i]);
	}

	gResult.push_back(mydata);
	return 0;
}

vector<MYPROTOCOLDATA> MySqlite::get(string key,string value) {
	char* error = 0;

	gResult.clear();

	char cmd[0x1000];
	//lstrcpyA(cmd, "select * from protocol");
	sprintf(cmd, "select * from protocol where '%s' = '%s'", key.c_str(), value.c_str());
	int res = sqlite3_exec(mSqlite,cmd , sqlite3Callback, "test", &error);
	//sqlite3Callback complete
	if (res != SQLITE_OK) {
		char szout[1024];
		wsprintfA(szout, "sqlite3_exec error:%s\r\n", error);
		Public::WriteLogFile(szout);
	}

	return gResult;
}
