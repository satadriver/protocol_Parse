#pragma once
#include <vector>

using namespace std;

class SoftFilter {
public:
	static int portFilter(unsigned short srcport, unsigned short dstport,int pro);
	static int init(vector<unsigned int> udpsports, vector<unsigned int> udpdports,
		vector<unsigned int> tcpsports, vector<unsigned int> tcpdports);
};