#include <winternl.h>
#include <windows.h>
#include <iostream>

#include <map>
//#include "CHandleLook.h"




#include <TlHelp32.h>


using namespace std;

typedef enum {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileCopyOnWriteInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileObjectIdInformation,
	FileTrackingInformation,
	FileOleDirectoryInformation,
	FileContentIndexInformation,
	FileInheritContentIndexInformation,
	FileOleInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE
{
	ULONG  uIdProcess;
	UCHAR  ObjectType;    // OB_TYPE_* (OB_TYPE_TYPE, etc.)
	UCHAR  Flags;         // HANDLE_FLAG_* (HANDLE_FLAG_INHERIT, etc.)
	USHORT  Handle;
	PVOID  pObject;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG   uCount;
	SYSTEM_HANDLE aSH[];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

HANDLE hHeap = 0;

typedef struct _FILE_NAME_INFORMATION {
	ULONG  FileNameLength;
	WCHAR  FileName[1];
} FILE_NAME_INFORMATION, *PFILE_NAME_INFORMATION;
typedef struct _NM_INFO
{
	HANDLE  hFile;
	FILE_NAME_INFORMATION Info;
	WCHAR Name[MAX_PATH];
} NM_INFO, *PNM_INFO;


typedef enum
{
	SystemBasicInformation,             // 0x002C
	SystemProcessorInformation,         // 0x000C
	SystemPerformanceInformation,       // 0x0138
	SystemTimeInformation,              // 0x0020
	SystemPathInformation,              // not implemented
	SystemProcessInformation,           // 0x00C8+ per process
	SystemCallInformation,              // 0x0018 + (n * 0x0004)
	SystemConfigurationInformation,     // 0x0018
	SystemProcessorCounters,            // 0x0030 per cpu
	SystemGlobalFlag,                   // 0x0004 (fails if size != 4)
	SystemCallTimeInformation,          // not implemented
	SystemModuleInformation,            // 0x0004 + (n * 0x011C)
	SystemLockInformation,              // 0x0004 + (n * 0x0024)
	SystemStackTraceInformation,        // not implemented
	SystemPagedPoolInformation,         // checked build only
	SystemNonPagedPoolInformation,      // checked build only
	SystemHandleInformation,            // 0x0004  + (n * 0x0010)
	SystemObjectTypeInformation,        // 0x0038+ + (n * 0x0030+)
	SystemPageFileInformation,          // 0x0018+ per page file
	SystemVdmInstemulInformation,       // 0x0088
	SystemVdmBopInformation,            // invalid info class
	SystemCacheInformation,             // 0x0024
	SystemPoolTagInformation,           // 0x0004 + (n * 0x001C)
	SystemInterruptInformation,         // 0x0000, or 0x0018 per cpu
	SystemDpcInformation,               // 0x0014
	SystemFullMemoryInformation,        // checked build only
	SystemLoadDriver,                   // 0x0018, set mode only
	SystemUnloadDriver,                 // 0x0004, set mode only
	SystemTimeAdjustmentInformation,    // 0x000C, 0x0008 writeable
	SystemSummaryMemoryInformation,     // checked build only
	SystemNextEventIdInformation,       // checked build only
	SystemEventIdsInformation,          // checked build only
	SystemCrashDumpInformation,         // 0x0004
	SystemExceptionInformation,         // 0x0010
	SystemCrashDumpStateInformation,    // 0x0004
	SystemDebuggerInformation,          // 0x0002
	SystemContextSwitchInformation,     // 0x0030
	SystemRegistryQuotaInformation,     // 0x000C
	SystemAddDriver,                    // 0x0008, set mode only
	SystemPrioritySeparationInformation,// 0x0004, set mode only
	SystemPlugPlayBusInformation,       // not implemented
	SystemDockInformation,              // not implemented
	SystemPowerInfo,             // 0x0060 (XP only!)
	SystemProcessorSpeedInformation,    // 0x000C (XP only!)
	SystemTimeZoneInformation,          // 0x00AC
	SystemLookasideInformation,         // n * 0x0020
	SystemSetTimeSlipEvent,
	SystemCreateSession,    // set mode only
	SystemDeleteSession,    // set mode only
	SystemInvalidInfoClass1,   // invalid info class
	SystemRangeStartInformation,   // 0x0004 (fails if size != 4)
	SystemVerifierInformation,
	SystemAddVerifier,
	SystemSessionProcessesInformation, // checked build only
	MaxSystemInfoClass
} SYSTEMINFOCLASS, *PSYSTEMINFOCLASS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef NTSTATUS(WINAPI *ZWQUERYSYSTEMINFORMATION)(unsigned long, PVOID, ULONG, PULONG);



typedef NTSTATUS(WINAPI *ZWQUERYINFORMATIONFILE)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG,
	FILE_INFORMATION_CLASS);

DWORD WINAPI GetFileNameThread(PVOID lpParameter)
{
	PNM_INFO NmInfo = (PNM_INFO)lpParameter;
	IO_STATUS_BLOCK IoStatus;
	HMODULE hNtDLL = LoadLibraryA("NTDLL.DLL");
	if (!hNtDLL)
	{
		return FALSE;
	}
	ZWQUERYINFORMATIONFILE ZwQueryInformationFile = (ZWQUERYINFORMATIONFILE)GetProcAddress(hNtDLL, "ZwQueryInformationFile");
	if (ZwQueryInformationFile == NULL)
	{
		return FALSE;
	}


	ZwQueryInformationFile(NmInfo->hFile, &IoStatus, &NmInfo->Info, sizeof(NM_INFO) - sizeof(HANDLE), FileNameInformation);
	return 0;
}

void GetFileName(HANDLE hFile, PCHAR TheName)
{
	HANDLE   hThread;
	PNM_INFO Info = (PNM_INFO)HeapAlloc(hHeap, 0, sizeof(NM_INFO));
	Info->hFile = hFile;
	hThread = CreateThread(NULL, 0, GetFileNameThread, Info, 0, NULL);
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_TIMEOUT) TerminateThread(hThread, 0);
	CloseHandle(hThread);
	memset(TheName, 0, MAX_PATH);
	WideCharToMultiByte(CP_ACP, 0, Info->Info.FileName, Info->Info.FileNameLength >> 1, TheName, MAX_PATH, NULL, NULL);
	HeapFree(hHeap, 0, Info);
}

PVOID GetInfoTable(IN ULONG ATableType)
{
	ULONG    mSize = 0x8000;
	PVOID    mPtr;
	NTSTATUS status;
	do
	{
		mPtr = HeapAlloc(hHeap, 0, mSize);
		if (!mPtr) return NULL;
		memset(mPtr, 0, mSize);

		HMODULE hNtDLL = LoadLibraryA("NTDLL.DLL");
		if (!hNtDLL)
		{
			return FALSE;
		}

		ZWQUERYSYSTEMINFORMATION ZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)GetProcAddress(hNtDLL, "ZwQuerySystemInformation");
		if (ZwQuerySystemInformation == NULL)
		{
			return FALSE;
		}

		status = ZwQuerySystemInformation(ATableType, mPtr, mSize, NULL);

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			HeapFree(hHeap, 0, mPtr);
			mSize = mSize * 2;
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);
	if (NT_SUCCESS(status))
		return mPtr;
	HeapFree(hHeap, 0, mPtr);
	return NULL;
}

void MyCloseHandle(DWORD pid)
{
	//获取进程中的句柄
	PSYSTEM_HANDLE_INFORMATION Info;
	ULONG r;
	CHAR Name[MAX_PATH];
	HANDLE hProcess, hFile;
	hHeap = GetProcessHeap();
	Info = (PSYSTEM_HANDLE_INFORMATION)GetInfoTable(SystemHandleInformation);
	if (Info)
	{
		for (r = 0; r < Info->uCount; r++)
		{
			if (Info->aSH[r].uIdProcess == pid)
			{
				hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Info->aSH[r].uIdProcess);
				if (hProcess)
				{
					if (DuplicateHandle(hProcess, (HANDLE)Info->aSH[r].Handle, GetCurrentProcess(), &hFile, 0, FALSE, DUPLICATE_SAME_ACCESS))
					{
						GetFileName(hFile, Name);
						if (strstr(Name, "Intel") != NULL)
						{
							printf("PID=%d FileHandle %d FileName=%s\n", Info->aSH[r].uIdProcess, Info->aSH[r].Handle, Name);
						}

						CloseHandle(hFile);
					}
					CloseHandle(hProcess);
				}
			}
		}
		HeapFree(hHeap, 0, Info);
	}
	printf("Duplicate Finish.\n");
}

