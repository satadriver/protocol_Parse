#pragma once

#include <string>
#include <iostream>
#include "http/http.h"
#include <vector>

using namespace std;



#define ATTACKTARGET_FILENAME				"attack_target.txt"








class Config {
public:
	static int Config::parseHttpCfg(string fn, vector <DNSSSL_REGULATION> & ssllist, vector <DNSSSL_REGULATION> & dnslist,
		vector<HTTP_REGULATION> &httpregulations, vector<unsigned int> & udpsports, vector<unsigned int> & udpdports,
		vector<unsigned int> & tcpsports, vector<unsigned int> & tcpdports);

	static vector<string> parseAttackCfg(string fn, unsigned long *dnsip, int *speed, int * flag, int * runmode);

	static int shiftDnsFormat(vector<string> & dnses);
};