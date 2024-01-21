


#include "getHandles.h"



#define ONEPAGESIZE 0x1000



CProcHandles::CProcHandles(void)

{

}





CProcHandles::~CProcHandles(void)

{

}



BOOL CProcHandles::GetUndocumentedFunctionAddress()

{

	m_pfunNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(

		GetModuleHandleA(("ntdll.dll")),

		"NtQuerySystemInformation");



	m_pfunNtQueryObject = (_NtQueryObject)GetProcAddress(

		GetModuleHandleA(("ntdll.dll")),

		"NtQueryObject");



	return (m_pfunNtQuerySystemInformation != NULL && m_pfunNtQueryObject != NULL);

}



BOOL CProcHandles::QueryHandleInfomation(DWORD PID)

{

	PSYSTEM_HANDLE_INFORMATION pSysHandleInfo = NULL;

	size_t HandleInfoSize = 0x1000;  //4K

	NTSTATUS NtStatus;

	pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(HandleInfoSize);



	do

	{

		NtStatus = m_pfunNtQuerySystemInformation(SystemHandleInformation,

			pSysHandleInfo, HandleInfoSize, NULL);



		if (NtStatus == STATUS_INFO_LENGTH_MISMATCH)

		{

			HandleInfoSize *= 2;

			pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(pSysHandleInfo, HandleInfoSize);

		}

		else

		{

			break;

		}

	} while (TRUE);



	for (int i = 0; i<pSysHandleInfo->HandleCount; i++)

	{

		PSYSTEM_HANDLE SystemHandle = &pSysHandleInfo->Handles[i];

		if (SystemHandle->ProcessId == PID)

		{

			//HANDLE DuplicatedHandle = NULL;

			//if(!DuplicateHandle(GetCurrentProcess(),

			//	(HANDLE)SystemHandle->Handle,

			//	GetCurrentProcess(),

			//	&DuplicatedHandle,0,FALSE,0))

			//{

			//	CString strMsg;

			//	strMsg.Format(_T("DuplicateHandle failed. code=%x\n"),GetLastError());

			//	::OutputDebugString((LPCTSTR)strMsg);

			//	continue;

			//}



			/* Query the object type. */

			POBJECT_TYPE_INFORMATION objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(ONEPAGESIZE);

			NtStatus = m_pfunNtQueryObject((HANDLE)SystemHandle->Handle,

				ObjectTypeInformation,

				objectTypeInfo,

				ONEPAGESIZE,

				NULL

			);



			if (NtStatus != STATUS_SUCCESS)

			{

				//string strMsg;

				//strMsg.Format(("[%#x] Error!, NtQueryObject return %x"), SystemHandle->Handle, NtStatus);

				//CloseHandle(DuplicatedHandle);

				continue;

			}



			/* Query the object name (unless it has an access of

			0x0012019f, on which NtQueryObject could hang. */

			if (SystemHandle->GrantedAccess == 0x0012019F)

			{

				/* We have the type, so display that. */

				//string strMsg;

				//strMsg.Format(("[%#x] %s: (did not get name)\n"), SystemHandle->Handle, objectTypeInfo->TypeName.Buffer);

				//::OutputDebugString((LPCTSTR)strMsg);

				free(objectTypeInfo);

				//CloseHandle(DuplicatedHandle);

				continue;

			}



			PVOID objectNameInfo;

			objectNameInfo = malloc(ONEPAGESIZE);

			ULONG retLength;

			if (m_pfunNtQueryObject((HANDLE)SystemHandle->Handle, ObjectNameInformation, objectNameInfo, ONEPAGESIZE, &retLength) != STATUS_SUCCESS)

			{

				objectNameInfo = realloc(objectNameInfo, retLength);



				if (m_pfunNtQueryObject((HANDLE)SystemHandle->Handle, ObjectNameInformation, objectNameInfo, ONEPAGESIZE, &retLength) != STATUS_SUCCESS)

				{

					/* We have the type name, so just display that. */

					//CString strMsg;

					//strMsg.Format(_T("[%#x] %s: (could not get name)\n"), SystemHandle->Handle, objectTypeInfo->TypeName.Buffer);

					//::OutputDebugString((LPCTSTR)strMsg);



					free(objectTypeInfo);

					free(objectNameInfo);

					//CloseHandle(DuplicatedHandle);

					continue;

				}

			}



			/* Cast our buffer into an UNICODE_STRING. */

			UNICODE_STRING objectName;

			objectName = *(PUNICODE_STRING)objectNameInfo;



			/* Print the information! */

			if (objectName.Length)

			{

				/* The object has a name. */

				//CString strMsg;

				//strMsg.Format(_T("[%#x] %s: %s\n"), SystemHandle->Handle, objectTypeInfo->TypeName.Buffer, objectName.Buffer);

				//::OutputDebugString((LPCTSTR)strMsg);

			}

			else

			{

				/* Print something else. */

				//CString strMsg;

				//strMsg.Format(_T("[%#x] %s: (unnamed)\n"), SystemHandle->Handle, objectTypeInfo->TypeName.Buffer);

				//::OutputDebugString((LPCTSTR)strMsg);

			}



			//CString strType = objectTypeInfo->TypeName.Buffer;

			//if (strType.CompareNoCase(_T("Key")) == 0)

			//{

				//CString strName=objectName.Buffer;

				//if (strName.CompareNoCase(_T("\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node"))==0)

				//{

				//	CloseHandle((HANDLE)SystemHandle->Handle);

				//}



				//CloseHandle((HANDLE)SystemHandle->Handle);

			//}



			free(objectTypeInfo);

			free(objectNameInfo);

			//CloseHandle(DuplicatedHandle);

		}

	}



	free(pSysHandleInfo);



	return TRUE;

}
