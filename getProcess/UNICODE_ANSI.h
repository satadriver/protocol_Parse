#pragma once

#ifndef UNICODE_ANSI_H

#define UNICODE_ANSI_H

#include <Windows.h>

static bool UnicodeToAnsi(const wchar_t *WideChar, char *MultiChar, int nSize) {

	int nRet = WideCharToMultiByte(CP_ACP, 0, WideChar, wcslen(WideChar), NULL, 0, NULL, NULL);

	if (nRet <= 0) return false;

	if (nRet > nSize) return false;

	nRet = WideCharToMultiByte(CP_ACP, 0, WideChar, wcslen(WideChar), MultiChar, nSize, NULL, NULL);

	if (nRet <= 0) return false;

	return true;

}

static bool AnsiToUnicode(const char *MultiChar, wchar_t *WideChar, int nSize) {

	int nRet = MultiByteToWideChar(CP_ACP, 0, MultiChar, strlen(MultiChar), NULL, 0);

	if (nRet <= 0) return false;

	if (nRet > nSize) return false;

	nRet = MultiByteToWideChar(CP_ACP, 0, MultiChar, strlen(MultiChar), WideChar, nSize);

	if (nRet <= 0) return false;

	return true;

}

#endif