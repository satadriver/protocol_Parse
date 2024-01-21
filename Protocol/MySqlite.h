#pragma once

#include <iostream>
#include "sqlite3.h"
#include "DataList.h"

using namespace std;

#pragma pack(1)

/*
typedef struct {
	string id;
	string smac;
	string sip;
	string sport;
	string dmac;
	string dip;
	string dport;
	string pack;
	string time;
	string pro;
	string action;
	string content;
}MYPROTOCOLDATA,*LPMYPROTOCOLDATA;
*/

typedef struct {
	string item[12][2] ;
}MYPROTOCOLDATA, *LPMYPROTOCOLDATA;

#define SQLITE_FILENAME "protocol.db"

#pragma pack()

class MySqlite {
public:
	sqlite3 * mSqlite;
	

	MySqlite();
	~MySqlite();
	int close();
	bool push(DATALISTHEADER hdr,string pro, string action, string content);
	vector<MYPROTOCOLDATA> get(string key, string value);
	bool MySqlite::createTable();

	//static int sqlite3Callback(void * reserved, int cnt, char **value, char **name);
};