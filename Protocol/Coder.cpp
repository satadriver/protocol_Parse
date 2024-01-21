
#include "Coder.h"
#include "public.h"

int Coder::UTF8ToGBK(const char* utf8, char ** lpdatabuf)
{
	if (lpdatabuf <= 0)
	{
		return FALSE;
	}
	int needunicodelen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
	if (needunicodelen <= 0)
	{
		Public::WriteLogFile("UTF8ToGBK MultiByteToWideChar get len error\r\n");
		*lpdatabuf = 0;
		return FALSE;
	}
	needunicodelen += 1024;
	wchar_t* wstr = new wchar_t[needunicodelen];
	memset(wstr, 0, needunicodelen * 2);
	int unicodelen = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wstr, needunicodelen);
	if (unicodelen <= 0)
	{
		*lpdatabuf = 0;
		delete[] wstr;
		Public::WriteLogFile("UTF8ToGBK MultiByteToWideChar error\r\n");
		return FALSE;
	}
	*(int*)(wstr + unicodelen) = 0;
	int needgbklen = WideCharToMultiByte(CP_ACP, 0, wstr, -1, NULL, 0, NULL, NULL);
	if (needgbklen <= 0)
	{
		*lpdatabuf = 0;
		delete[] wstr;
		Public::WriteLogFile("UTF8ToGBK WideCharToMultiByte get len error\r\n");
		return FALSE;
	}
	needgbklen += 1024;
	*lpdatabuf = new char[needgbklen];
	memset(*lpdatabuf, 0, needgbklen);

	int gbklen = WideCharToMultiByte(CP_ACP, 0, wstr, -1, *lpdatabuf, needgbklen, NULL, NULL);
	delete[] wstr;
	if (gbklen <= 0)
	{
		delete[](*lpdatabuf);
		*lpdatabuf = 0;
		Public::WriteLogFile("UTF8ToGBK WideCharToMultiByte error\r\n");
		return FALSE;
	}

	*(*lpdatabuf + gbklen) = 0;
	return gbklen;
}






int Coder::GBKToUTF8(const char* gb2312, char ** lpdatabuf)
{
	if (lpdatabuf <= 0)
	{
		return FALSE;
	}
	int needunicodelen = MultiByteToWideChar(CP_ACP, 0, gb2312, -1, NULL, 0);
	if (needunicodelen <= 0)
	{
		*lpdatabuf = 0;
		Public::WriteLogFile("GBKToUTF8 MultiByteToWideChar get len error\r\n");
		return FALSE;
	}
	needunicodelen += 1024;
	wchar_t* wstr = new wchar_t[needunicodelen];
	memset(wstr, 0, needunicodelen * 2);
	int unicodelen = MultiByteToWideChar(CP_ACP, 0, gb2312, -1, wstr, needunicodelen);
	if (unicodelen <= 0)
	{
		*lpdatabuf = 0;
		delete[] wstr;
		Public::WriteLogFile("GBKToUTF8 MultiByteToWideChar error\r\n");
		return FALSE;
	}
	*(int*)(wstr + unicodelen) = 0;
	int needutf8len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
	if (needutf8len <= 0)
	{
		Public::WriteLogFile("GBKToUTF8 WideCharToMultiByte get len error\r\n");
		*lpdatabuf = 0;
		delete[] wstr;
		return FALSE;
	}
	needutf8len += 1024;
	*lpdatabuf = new char[needutf8len];
	memset(*lpdatabuf, 0, needutf8len);
	int utf8len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, *lpdatabuf, needutf8len, NULL, NULL);
	delete[] wstr;
	if (utf8len <= 0)
	{
		delete *lpdatabuf;
		*lpdatabuf = 0;
		Public::WriteLogFile("GBKToUTF8 WideCharToMultiByte error\r\n");
		return FALSE;
	}

	*(*lpdatabuf + utf8len) = 0;
	return utf8len;
}