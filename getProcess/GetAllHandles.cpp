
#include <windows.h>


typedef struct 
{
	ULONG ProcessId;//进程标识符 
	UCHAR ObjectTypeNumber;//打开的对象的类型
	UCHAR Flags;//句柄属性标志
	USHORT Handle;//句柄数值,在进程打开的句柄中唯一标识某个句柄
	PVOID Object;//这个就是句柄对应的EPROCESS的地址
	ACCESS_MASK GrantedAccess;//句柄对象的访问权限
}SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct 
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_INFORMATION Information[0x100000];
}SE_SYSTEM_EHT_INFORMATION_T, *SE_SYSTEM_EHT_INFORMATION_T;

int getAllHandles(int ProcessID){
	int Status = 0;
	HANDLE ProcessHandle = 0;
	if ((ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID)) == NULL)
	{
		return Status;
	}
	if (NtQuerySystemInformation == NULL || NtDuplicateObject == NULL || NtQueryObject == NULL || NtQuerySection == NULL)
	{
		return FALSE;
	}

	int BufferLength = 0x1000000;
	char * BufferData = (char*)VirtualAlloc(NULL, BufferLength, MEM_COMMIT, PAGE_READWRITE);
	if (BufferData = NULL)
	{
		return FALSE;
	}

	int ReturnLength = 0;
	Status = NtQuerySystemInformation(16, BufferData, BufferLength, &ReturnLength);

	SE_SYSTEM_EHT_INFORMATION_T* SystemEHTInfo = (SE_SYSTEM_EHT_INFORMATION_T*)BufferData;

	for (ULONG i = 0; i< SystemEHTInfo->NumberOfHandles; i++)
	{
		if (SystemEHTInfo->Information[i].ProcessID != ProcessID)
		{
			continue;
		}

		HANDLE DuplicatedHandle = 0;

		Status = __NtDuplicateObject(ProcessHandle, reinterpret_cast<HANDLE>(SystemEHTInfo->Information[i].Handle),
			GetCurrentProcess(), &DuplicatedHandle, 0, 0, DUPLICATE_SAME_ACCESS);
		if (!NT_SUCCESS(Status))
		{
			continue;
		}

		ObjectTypeInfo = (OBJECT_TYPE_INFORMATION_T*)malloc(0x1000);
		Status = __NtQueryObject(DuplicatedHandle, ObjectTypeInformation, ObjectTypeInfo, 0x1000, &ReturnLength);
		if (!NT_SUCCESS(Status))
		{
			CloseHandle(DuplicateHandle);
			continue;
		}
		ObjectNameInfo = malloc(0x1000);
		Status = __NtQueryObject(DuplicatedHandle, ObjectNameInformation, ObjectNameInfo, 0x1000, &ReturnLength);
		if (!NT_SUCCESS(Status))
		{
			if (Status == STATUS_INFO_LENGTH_MISMATCH)
			{
				ObjectNameInfo = realloc(ObjectNameInfo, ReturnLength);
				Status = __NtQueryObject(DuplicatedHandle, ObjectNameInformation, ObjectNameInfo, ReturnLength/*这儿有点意思*/, &ReturnLength);
				if (!NT_SUCCESS(Status))
				{
					goto Exit;
				}
			}
			else
			{
				goto Exit;
			}
		}

		ObjectName = *(_UNICODE_STRING_T<WCHAR*>*)ObjectNameInfo;
		//赋值到用户上
		v1.HandleValue = reinterpret_cast<HANDLE>(SystemEHTInfo->Items[i].HandleValue);
		v1.GrantedAccess = SystemEHTInfo->Items[i].GrantedAccess;
		v1.Flags = SystemEHTInfo->Items[i].Flags;
		v1.ObjectValue = SystemEHTInfo->Items[i].ObjectValue;
		//类型状态赋值
		if (ObjectTypeInfo->ObjectTypeName.BufferLength)
			v1.ObjectTypeName = (wchar_t*)ObjectTypeInfo->ObjectTypeName.BufferData;
		if (ObjectName.BufferLength)
			v1.ObjectName = ObjectName.BufferData;
		if (_wcsicmp(v1.ObjectTypeName.c_str(), L"Section") == 0)
		{
			SECTION_BASIC_INFORMATION_T SectionBasicInfo = { 0 };
			//结构提函数
			Status = __NtQuerySection(DuplicatedHandle, SectionBasicInformation, &SectionBasicInfo,
				(ULONG)sizeof(SectionBasicInfo), NULL);
			if (NT_SUCCESS(Status))
			{

				v1.SectionInfo.SectionSize = SectionBasicInfo.SectionSize/*T*/.QuadPart;
				v1.SectionInfo.SectionAttributes = SectionBasicInfo.Attributes;
			}
		}
		ProcessHandleInfo.push_back(v1);
}