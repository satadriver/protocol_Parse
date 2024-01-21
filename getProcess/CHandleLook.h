#pragma once
#ifndef CHANDLELOOK_H
#define CHANDLELOOK_H

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <list>
#include <map>

using namespace std;

typedef NTSTATUS(WINAPI *pNtQueryInformationProcess)(HANDLE ProcessHandle, 
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation, 
	ULONG ProcessInformationLength, 
	PULONG ReturnLength);



typedef NTSTATUS(WINAPI *pNtQueryObject)(

	_In_opt_   HANDLE Handle,

	_In_       OBJECT_INFORMATION_CLASS ObjectInformationClass,

	_Out_opt_  PVOID ObjectInformation,

	_In_       ULONG ObjectInformationLength,

	_Out_opt_  PULONG ReturnLength);

typedef NTSTATUS(WINAPI *pRtlAppendUnicodeToString)(

	_Out_opt_  PUNICODE_STRING Destination,

	_In_       PCWSTR Source

	);

typedef NTSTATUS

(WINAPI *pNtOpenSymbolicLinkObject)(

	OUT PHANDLE  LinkHandle,

	IN ACCESS_MASK  DesiredAccess,

	IN POBJECT_ATTRIBUTES  ObjectAttributes

	);



typedef NTSTATUS

(WINAPI *pNtQuerySymbolicLinkObject)(

	IN HANDLE  LinkHandle,

	IN OUT PUNICODE_STRING  LinkTarget,

	OUT PULONG  ReturnedLength OPTIONAL

	);



typedef VOID

(WINAPI *pRtlInitUnicodeString)(

	IN OUT PUNICODE_STRING  DestinationString,

	IN PCWSTR  SourceString

	);

typedef VOID

(WINAPI *pRtlFreeUnicodeString)(

	IN PUNICODE_STRING  UnicodeString

	);

typedef NTSTATUS

(*pRtlVolumeDeviceToDosName)(

	IN  PVOID  VolumeDeviceObject,

	OUT PUNICODE_STRING  DosName

	);

typedef NTSTATUS

(WINAPI *pNtClose)(

	IN HANDLE Handle

	);





typedef struct ProcessHandle {
	DWORD ID;				//¾ä±ú
	string Name;			//Ãû³Æ
	string Type;			//ÀàÐÍ
}ProcessHandleInfor;



class CHandleLook {

public:

	CHandleLook();

	~CHandleLook();

	void Init();

	bool GetObjectFormHandle(HANDLE my);

	std::list< ProcessHandleInfor> *GetHandleList();

private:

	bool GetHandleType(HANDLE hHandle, string &strType);

	bool GetHandleName(HANDLE hFile, string &strFileName);

	HMODULE hNtdll;

	std::list< ProcessHandleInfor> m_processInfo;

	pNtQueryInformationProcess NtQueryInformationProcess;

	pNtQueryObject	NtQueryObject;

	pRtlAppendUnicodeToString RtlAppendUnicodeToString;

	pNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject;

	pNtQuerySymbolicLinkObject NtQuerySymbolicLinkObject;

	pRtlInitUnicodeString RtlInitUnicodeString;

	pRtlFreeUnicodeString RtlFreeUnicodeString;

	pNtClose NtClose;
};



typedef struct _OBJECT_BASIC_INFORMATION {

	ULONG                   Attributes;

	ACCESS_MASK             DesiredAccess;

	ULONG                   HandleCount;

	ULONG                   ReferenceCount;

	ULONG                   PagedPoolUsage;

	ULONG                   NonPagedPoolUsage;

	ULONG                   Reserved[3];

	ULONG                   NameInformationLength;

	ULONG                   TypeInformationLength;

	ULONG                   SecurityDescriptorLength;

	LARGE_INTEGER           CreationTime;

} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;//ObjectBasicInformation 0x38



typedef struct _OBJECT_NAME_INFORMATION {

	UNICODE_STRING          Name;

	WCHAR                   NameBuffer[1];

} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION; //ObjectNameInformation  0x08

#define POOL_TYPE ULONG

typedef struct _OBJECT_TYPE_INFORMATION {

	UNICODE_STRING          TypeName;

	ULONG                   TotalNumberOfHandles;

	ULONG                   TotalNumberOfObjects;

	WCHAR                   Unused1[8];

	ULONG                   HighWaterNumberOfHandles;

	ULONG                   HighWaterNumberOfObjects;

	WCHAR                   Unused2[8];

	ACCESS_MASK             InvalidAttributes;

	GENERIC_MAPPING         GenericMapping;

	ACCESS_MASK             ValidAttributes;

	BOOLEAN                 SecurityRequired;

	BOOLEAN                 MaintainHandleCount;

	USHORT                  MaintainTypeList;

	POOL_TYPE               PoolType;

	ULONG                   DefaultPagedPoolCharge;

	ULONG                   DefaultNonPagedPoolCharge;

} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;//ObjectTypeInformation	0x70



typedef struct _OBJECT_ALL_INFORMATION {

	ULONG                   NumberOfObjectsTypes;

	PUBLIC_OBJECT_TYPE_INFORMATION ObjectTypeInformation;

	//OBJECT_TYPE_INFORMATION ObjectTypeInformation[1];

} OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION; //ObjectAllInformation		0x04+



typedef struct _OBJECT_DATA_INFORMATION {

	BOOLEAN                 InheritHandle;

	BOOLEAN                 ProtectFromClose;

} OBJECT_DATA_INFORMATION, *POBJECT_DATA_INFORMATION; //ObjectDataInformation	0x02

#endif