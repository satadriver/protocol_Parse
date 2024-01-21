#include "CHandleLook.h"
#include <vector>
#include "UNICODE_ANSI.h"

using namespace std;

#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define BUFSIZE MAX_PATH

CHandleLook::CHandleLook() {}

CHandleLook::~CHandleLook() {

	if (hNtdll != NULL)
	{
		FreeLibrary(hNtdll);
	}
}

std::list< ProcessHandleInfor> *CHandleLook::GetHandleList()
{
	return &m_processInfo;
}

void CHandleLook::Init() {

	if (hNtdll == NULL) {
		hNtdll = LoadLibraryA(("ntdll.dll"));
	}

	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, ("NtQueryInformationProcess"));

	NtQueryObject = (pNtQueryObject)GetProcAddress(hNtdll, ("NtQueryObject"));

	RtlAppendUnicodeToString = (pRtlAppendUnicodeToString)GetProcAddress(hNtdll, ("RtlAppendUnicodeToString"));

	NtOpenSymbolicLinkObject = (pNtOpenSymbolicLinkObject)GetProcAddress(hNtdll, ("NtOpenSymbolicLinkObject"));

	NtQuerySymbolicLinkObject = (pNtQuerySymbolicLinkObject)GetProcAddress(hNtdll, ("NtQuerySymbolicLinkObject"));

	NtClose = (pNtClose)GetProcAddress(hNtdll, ("NtClose"));

	RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, ("RtlInitUnicodeString"));

	RtlFreeUnicodeString = (pRtlFreeUnicodeString)GetProcAddress(hNtdll, ("RtlFreeUnicodeString"));
}

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG ProcessId;			//进程标识符 
	UCHAR ObjectTypeNumber;		//打开的对象的类型
	UCHAR Flags;				//句柄属性标志
	USHORT Handle;				//句柄数值,在进程打开的句柄中唯一标识某个句柄
	PVOID Object;				//这个就是句柄对应的EPROCESS的地址
	ACCESS_MASK GrantedAccess;	//句柄对象的访问权限
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[0x100000];
}SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

//FileType = "Mutant"
//FilePath = "\\BaseNamedObjects\\{D390F0C7-BDBA-4fd2-B58D-146D5175334E}"




void test(HANDLE my) {
	INT ret = 0;

	typedef DWORD(WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD, PVOID, DWORD, PDWORD);
	HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");

	char *buf = new char[0x1000000];
	int buflen = 0x1000000;
	ret = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, buf, buflen, NULL);
	if (NT_SUCCESS(ret)) {

		SYSTEM_HANDLE_INFORMATION_EX *lpinfo = (SYSTEM_HANDLE_INFORMATION_EX*)buf;

		//微软设计让-1作为代表自身进程句柄
		HANDLE hthisproc = GetCurrentProcess();

		for (size_t i = 0; i < lpinfo->NumberOfHandles; i++) {

			if (lpinfo->Information[i].ProcessId == 8792)
			{
				printf("handle:%u,pid:%u,type:%u,flag:%u\r\n", lpinfo->Information[i].Handle,
					lpinfo->Information[i].ProcessId, lpinfo->Information[i].ObjectTypeNumber, lpinfo->Information[i].Flags);
			}
		}
	}
}

bool CHandleLook::GetObjectFormHandle(HANDLE my) {

	//test(my);

	INT ret = 0;

	typedef DWORD(WINAPI *NTQUERYSYSTEMINFORMATION)(DWORD, PVOID, DWORD, PDWORD);
	HMODULE hNtDll = LoadLibrary(L"ntdll.dll");
	NTQUERYSYSTEMINFORMATION NtQuerySystemInformation =(NTQUERYSYSTEMINFORMATION)GetProcAddress(hNtDll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation <= 0)
	{
		return FALSE;
	}

	char *buf = new char[0x1000000];
	int buflen = 0x1000000;
	ret = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, buf, buflen, NULL);
	if (NT_SUCCESS(ret)) {

		SYSTEM_HANDLE_INFORMATION_EX *lpinfo = (SYSTEM_HANDLE_INFORMATION_EX*)buf;

		//微软设计让-1作为代表自身进程句柄
		HANDLE hthisproc = GetCurrentProcess();

		for (size_t i = 0; i < lpinfo->NumberOfHandles; i++ ) {

			if (lpinfo->Information[i].ProcessId <= 1000)
			{
				continue;
			}

			HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, lpinfo->Information[i].ProcessId);
			if (hproc)
			{
				HANDLE hdup = 0;

				ret = DuplicateHandle(hproc, (HANDLE)lpinfo->Information[i].Handle, hthisproc, &hdup, 0, FALSE, DUPLICATE_SAME_ACCESS);

				CloseHandle(hproc);
				if (ret == TRUE) {

					string FilePath = "";
					string FileType = "";
					

// #ifdef _DEBUG
// 					bool bRet = GetHandleName((HANDLE)my, FilePath);
// 					if (bRet == false)
// 					{
// 						continue;
// 					}
// 
// 					
// 					bRet = GetHandleType((HANDLE)my, FileType);
// 					if (bRet == false)
// 					{
// 						continue;
// 					}
// #else
					bool bRet = GetHandleName((HANDLE)hdup, FilePath);
					if (bRet == false)
					{
						continue;
					}

					bRet = GetHandleType((HANDLE)hdup, FileType);
					if (bRet == false)
					{
						continue;
					}
//#endif

					ProcessHandleInfor info = { 0 };

					info.ID = (DWORD)hdup;

					info.Name = FilePath;

					info.Type = FileType;

					m_processInfo.push_back(info);

					if (hdup == (HANDLE)my && info.Type == "Mutant" || 
						info.Name == "\\BaseNamedObjects\\{D390F0C7-BDBA-4fd2-B58D-146D5175334E}")
					{
						printf("ok");
					}

					//CloseHandle(hdup);
				}
				else {
					//printf("duplication handle error\r\n");
				}
			}
			else {
				//printf("open process id:%u error\r\n", lpinfo->Information[i].ProcessId);
			}
		}
	}
	else {
		printf("NtQuerySystemInformation error\r\n");
	}
	return true;
}

bool CHandleLook::GetHandleType(HANDLE hHandle, string &strType)
{
	DWORD dwSize = 0;
	NTSTATUS Status = NtQueryObject(hHandle, ObjectTypeInformation, NULL, NULL, &dwSize);
	if (NT_SUCCESS(Status)) {
		return false;
	}

	if (Status == STATUS_INFO_LENGTH_MISMATCH) {

		char *buf = new char[dwSize * 2];
		ZeroMemory(buf, sizeof(char)*dwSize * 2);
		Status = NtQueryObject(hHandle, ObjectTypeInformation, buf, dwSize * 2, &dwSize);
		if (NT_SUCCESS(Status)) {
			PUBLIC_OBJECT_TYPE_INFORMATION* typeInfor = (PUBLIC_OBJECT_TYPE_INFORMATION*)(buf);

			if (typeInfor->TypeName.Buffer)
			{
				char szmyname[1024] = { 0 };
				WideCharToMultiByte(CP_ACP, 0, typeInfor->TypeName.Buffer, wcslen(typeInfor->TypeName.Buffer), szmyname, 1024, 0, 0);
				strType = szmyname;
			}

			delete[]buf;

			return true;
		}
		delete[]buf;
	}

	return false;

}



bool CHandleLook::GetHandleName(HANDLE hFile, string &strFileName) {

	DWORD dwSize = 0;
	NTSTATUS Status = NtQueryObject(hFile, OBJECT_INFORMATION_CLASS(1), NULL, NULL, &dwSize);
	if (NT_SUCCESS(Status)) {

		return false;
	}

	if (STATUS_INFO_LENGTH_MISMATCH == Status) {

		char *buf = new char[dwSize * 2];

		ZeroMemory(buf, sizeof(char)*dwSize * 2);

		Status = NtQueryObject(hFile, OBJECT_INFORMATION_CLASS(1), buf, dwSize * 2, &dwSize);

		if (NT_SUCCESS(Status)) {

			POBJECT_NAME_INFORMATION pObjectName = (POBJECT_NAME_INFORMATION)buf;
			if (pObjectName->Name.Buffer)
			{
				char szmyname[1024] = { 0 };
				WideCharToMultiByte(CP_ACP, 0, pObjectName->Name.Buffer, wcslen(pObjectName->Name.Buffer), szmyname, 1024, 0, 0);
				strFileName = szmyname;
			}

			delete[]buf;

			return TRUE;

		}

		delete[]buf;

	}

	return FALSE;

}
