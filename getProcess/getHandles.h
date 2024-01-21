#pragma once
#include <windows.h>



#define SystemHandleInformation 16



#define ObjectBasicInformation 0

#define ObjectNameInformation 1

#define ObjectTypeInformation 2



#define STATUS_SUCCESS 0x00000000

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004





typedef NTSTATUS(WINAPI *_NtQuerySystemInformation)(

	ULONG SystemInformationClass,

	PVOID SystemInformation,

	ULONG SystemInformationLength,

	PULONG ReturnLength

	);



typedef NTSTATUS(WINAPI *_NtQueryObject)(

	HANDLE ObjectHandle,

	ULONG ObjectInformationClass,

	PVOID ObjectInformation,

	ULONG ObjectInformationLength,

	PULONG ReturnLength

	);



/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */

typedef struct _SYSTEM_HANDLE

{

	ULONG ProcessId;

	BYTE ObjectTypeNumber;

	BYTE Flags;

	USHORT Handle;

	PVOID Object;

	ACCESS_MASK GrantedAccess;

} SYSTEM_HANDLE, *PSYSTEM_HANDLE;



typedef struct _SYSTEM_HANDLE_INFORMATION

{

	ULONG HandleCount; /* Or NumberOfHandles if you prefer. */

	SYSTEM_HANDLE Handles[1];

} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;



typedef struct _UNICODE_STRING

{

	USHORT Length;

	USHORT MaximumLength;

	PWSTR Buffer;

} UNICODE_STRING, *PUNICODE_STRING;



typedef struct _OBJECT_TYPE_INFORMATION

{

	UNICODE_STRING TypeName;

	ULONG TotalNumberOfObjects;

	ULONG TotalNumberOfHandles;

	ULONG TotalPagedPoolUsage;

	ULONG TotalNonPagedPoolUsage;

	ULONG TotalNamePoolUsage;

	ULONG TotalHandleTableUsage;

	ULONG HighWaterNumberOfObjects;

	ULONG HighWaterNumberOfHandles;

	ULONG HighWaterPagedPoolUsage;

	ULONG HighWaterNonPagedPoolUsage;

	ULONG HighWaterNamePoolUsage;

	ULONG HighWaterHandleTableUsage;

	ULONG InvalidAttributes;

	GENERIC_MAPPING GenericMapping;

	ULONG ValidAccessMask;

	BOOLEAN SecurityRequired;

	BOOLEAN MaintainHandleCount;

	ULONG PoolType;

	ULONG DefaultPagedPoolCharge;

	ULONG DefaultNonPagedPoolCharge;

} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;







class CProcHandles

{

public:

	CProcHandles(void);

	~CProcHandles(void);



public:

	BOOL GetUndocumentedFunctionAddress();

	BOOL QueryHandleInfomation(DWORD PID = -1);

private:

	_NtQuerySystemInformation m_pfunNtQuerySystemInformation;

	_NtQueryObject m_pfunNtQueryObject;

};


