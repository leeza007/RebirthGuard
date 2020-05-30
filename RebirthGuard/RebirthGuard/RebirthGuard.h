
/********************************************
*											*
*	RebirthGuard/RebirthGuard.h - chztbby	*
*											*
********************************************/

#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <time.h>
#include <stdio.h>


//-----------------------------------------------------------------
//	RebirthGuard Compile Options
//-----------------------------------------------------------------
#define DISABLE									0x00000000
#define ENABLE									0x00000001
#define		LOG									0x00000002	
#define		POPUP								0x00000004
#define		KILL								0x00000008
//-----------------------------------------------------------------
#define PROCESS_POLICY							ENABLE
#define		MS_SIGNED_ONLY						DISABLE
#define		POLICY								PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE\
												| PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE\
												| PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE\
												| PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS\
												| PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON\
												| PROCESS_CREATION_MITIGATION_POLICY2_RESTRICT_INDIRECT_BRANCH_PREDICTION_ALWAYS_ON

#define FILE_CHECK								ENABLE | LOG | POPUP | KILL

#define THREAD_CHECK							ENABLE | LOG | POPUP | KILL

#define MEM_INFO_CHECK							ENABLE | LOG | POPUP

#define CRC_CHECK								ENABLE | LOG | POPUP | KILL
#define		USING_MIRROR_VIEW					ENABLE

#define ANTI_DLL_INJECTION						ENABLE | LOG | POPUP | KILL

#define ANTI_DEBUGGING							ENABLE | LOG | POPUP | KILL

#define EXCEPTION_HANDLING						ENABLE | LOG | POPUP

#define SECTION_LIST_ALLOC						0x010000000000
#define SECTION_LIST_SIZE						0x10000

#define XOR_KEY									0xAD


//-----------------------------------------------------------------
//	Whitelist (Remapping / File CheckSum)
//-----------------------------------------------------------------
static CONST WCHAR* Whitelist_Rebirth[] =
{
	L"nvoglv64.dll",
	L""
};
static CONST WCHAR* Whitelist_FileCheck[] =
{
	L"glew32.dll",
	L"assimp-vc140-mt.dll",
	L"freetype.dll",
	L"fmod64.dll",
	L""
};


//-----------------------------------------------------------------
//	Basic
//-----------------------------------------------------------------
#define EXCEPT_REBIRTH							0x00000001
#define EXCEPT_FILE_INTEGRITY					0x00000002
#define SEC_NO_CHANGE							0x00400000
#define STATUS_INVALID_PAGE_PROTECTION			0xC0000045
#define STATUS_WORKING_SET_QUOTA				0xC00000A1
#define PAGE_SIZE								0x1000
#define AllocationGranularity					0x10000
#define ViewUnmap								2
#define CURRENT_PROCESS							(HANDLE)-1
#define CURRENT_THREAD							(HANDLE)-2
#define LDR_DLL_NOTIFICATION_REASON_LOADED		1
#define	MemoryBasicInformation					0
#define	MemoryWorkingSetExList					4
#define ProcessQuotaLimits						1
#define ThreadQuerySetWin32StartAddress			9
#define	ThreadHideFromDebugger					0x11
#define SE_AUDIT_PRIVILEGE						0x21
#define PADDING(p, size)						p / size * size + (p % size ? size : 0)
#define GetNtHeader(base)						(PIMAGE_NT_HEADERS)((DWORD64)base + (DWORD64)((PIMAGE_DOS_HEADER)base)->e_lfanew)


//-----------------------------------------------------------------
//	InMemoryOrderModuleList Indices
//-----------------------------------------------------------------
#define EXE										0
#define ntdll									1
#define kernel32								2
#define kernelbase								3


//-----------------------------------------------------------------
//	RebirthGuard Report Codes
//-----------------------------------------------------------------
enum REBIRTHGUARD_REPORT_CODE
{
	Allocation_SectionList,
	THREAD_StartAddress,
	THREAD_Protection,
	DLL_INJECTION_Kernel32_LoadLibraryA,
	DLL_INJECTION_Kernel32_LoadLibraryW,
	DLL_INJECTION_Kernel32_LoadLibraryExA,
	DLL_INJECTION_Kernel32_LoadLibraryExW,
	DLL_INJECTION_KernelBase_LoadLibraryA,
	DLL_INJECTION_KernelBase_LoadLibraryW,
	DLL_INJECTION_KernelBase_LoadLibraryExA,
	DLL_INJECTION_KernelBase_LoadLibraryExW,
	DLL_INJECTION_Ntdll_LdrLoadDll,
	MEMORY_Image,
	MEMORY_Private_Execute,
	MEMORY_NotRebirthed,
	MEMORY_Execute_Write,
	MEMORY_Unlocked,
	MEMORY_Unlocked_2,
	CRCCheck_Section_Error,
	CRCCheck_Integrity,
	FILE_INTEGRITY_Fail,
	APICALL_Invalid_Module,
	APICALL_Invalid_API,
	EXCEPTION_HardwareBreakpoint,
	EXCEPTION_Debugging,
	EXCEPTION_Single_Step,
	EXCEPTION_Guarded_Page,
};


//-----------------------------------------------------------------
//	Section Handle List
//-----------------------------------------------------------------
struct Section
{
	HANDLE hSection;
	DWORD64 CRC;
};
static Section* SectionList = (Section*)SECTION_LIST_ALLOC;


//-----------------------------------------------------------------
//	Native API
//-----------------------------------------------------------------
typedef NTSTATUS	(NTAPI* _NtCreateSection)					(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS	(NTAPI* _NtMapViewOfSection)				(HANDLE, HANDLE, PDWORD64, DWORD64, DWORD64, PLARGE_INTEGER, PDWORD64, DWORD, DWORD, DWORD);
typedef NTSTATUS	(NTAPI* _NtUnmapViewOfSection)				(HANDLE, DWORD64);
typedef NTSTATUS	(NTAPI* _NtProtectVirtualMemory)			(HANDLE, PVOID*, PDWORD64, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtQueryVirtualMemory)				(HANDLE, PVOID, DWORD, PVOID, DWORD64, PDWORD64);
typedef NTSTATUS	(NTAPI* _NtLockVirtualMemory)				(HANDLE, PVOID, PDWORD64, ULONG);
typedef NTSTATUS	(NTAPI* _NtReadVirtualMemory)				(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtWriteVirtualMemory)				(HANDLE, PVOID, PVOID, DWORD64, PULONG);
typedef NTSTATUS	(NTAPI* _NtAllocateVirtualMemory)			(HANDLE, PVOID*, ULONG_PTR, PDWORD64, ULONG, ULONG);
typedef NTSTATUS	(NTAPI* _NtFreeVirtualMemory)				(HANDLE, PVOID*, PDWORD64, ULONG);
typedef NTSTATUS	(NTAPI* _NtResumeProcess)					(HANDLE);
typedef NTSTATUS	(NTAPI* _NtQueryInformationProcess)			(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtQueryInformationThread)			(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtSetInformationProcess)			(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS	(NTAPI* _NtSetInformationThread)			(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS	(NTAPI* _RtlAcquirePrivilege)				(PULONG, ULONG, ULONG, PVOID*);
typedef NTSTATUS	(NTAPI* _RtlReleasePrivilege)				(PVOID);
typedef NTSTATUS	(NTAPI* _NtCreateThreadEx)					(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, DWORD64, DWORD64, DWORD64, PVOID);
typedef NTSTATUS	(NTAPI* _NtTerminateProcess)				(HANDLE, NTSTATUS);
typedef NTSTATUS	(NTAPI* _NtTerminateThread)					(HANDLE, NTSTATUS);
typedef NTSTATUS	(NTAPI* _RtlAddVectoredExceptionHandler)	(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef NTSTATUS	(NTAPI* _LdrRegisterDllNotification)		(ULONG, PVOID, PVOID, PVOID);
typedef NTSTATUS	(NTAPI* _NtDuplicateObject)					(HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, ULONG, ULONG);
typedef HMODULE		(WINAPI* _LoadLibraryW)						(LPCWSTR lpLibFileName);


//-----------------------------------------------------------------
//	APICall Number
//-----------------------------------------------------------------
enum APICall_Number
{
	APICall_NtCreateSection,
	APICall_NtMapViewOfSection,
	APICall_NtUnmapViewOfSection,
	APICall_NtProtectVirtualMemory,
	APICall_NtQueryVirtualMemory,
	APICall_NtLockVirtualMemory,
	APICall_NtReadVirtualMemory,
	APICall_NtWriteVirtualMemory,
	APICall_NtAllocateVirtualMemory,
	APICall_NtFreeVirtualMemory,
	APICall_NtTerminateProcess,
	APICall_NtResumeProcess,
	APICall_NtQueryInformationProcess,
	APICall_NtSetInformationProcess,
	APICall_RtlUserThreadStart,
	APICall_NtCreateThreadEx,
	APICall_NtTerminateThread,
	APICall_NtQueryInformationThread,
	APICall_NtSetInformationThread,
	APICall_RtlAcquirePrivilege,
	APICall_RtlReleasePrivilege,
	APICall_RtlAddVectoredExceptionHandler,
	APICall_LdrRegisterDllNotification,
	APICall_NtDuplicateObject,
	APICall_LoadLibraryA,
	APICall_LoadLibraryW,
	APICall_LoadLibraryExA,
	APICall_LoadLibraryExW,
	APICall_LdrLoadDll,
};


//-----------------------------------------------------------------
//	DLL Load notification
//-----------------------------------------------------------------
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA
{
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA
{
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;


/* main.cpp */
VOID					RegisterCallbacks	(VOID);
VOID					Initialze			(VOID);

/* function.cpp */
PVOID					GetPEHeader			(HANDLE hProcess, PVOID ModuleBase);
WCHAR*					GetModulePath		(DWORD ModuleIndex);
PVOID					NextModule			(HANDLE hProcess, PLDR_DATA_TABLE_ENTRY pList);
HMODULE					myGetModuleHandleEx	(HANDLE hProcess, CONST WCHAR* ModulePath);
FARPROC					myGetProcAddress	(HMODULE hModule, LPCSTR lpProcName);
FARPROC					APICall				(DWORD ModuleIndex, APICall_Number API);
VOID					Report				(HANDLE hProcess, DWORD ErrorFlag, REBIRTHGUARD_REPORT_CODE ErrorCode, PVOID ErrorAddress, PVOID ErrorAddress2);

/* mapping.cpp */
PVOID					ManualMap			(HANDLE hProcess, CONST WCHAR* ModulePath);
VOID					ExtendWorkingSet	(HANDLE hProcess);
VOID					AddSection			(HANDLE hProcess, HANDLE hSection, DWORD64 CRC);
VOID					RemapModule			(HANDLE hProcess, CONST WCHAR* ModulePath);

/* verifying.cpp */
DWORD					IsExcepted			(CONST WCHAR* ModulePath);
BOOL					IsRebirthed			(HANDLE hProcess, PVOID ModuleBase);
DWORD64					IsInModule			(HANDLE hProcess, PVOID Address, DWORD Type);
BOOL					CompareByte			(PVOID Original, PVOID Target);
VOID					ThreadCheck			(PVOID StartAddress, DWORD Type);
VOID					DestoryModule		(HANDLE hProcess);
VOID					MemInfoCheck		(HANDLE hProcess, DWORD pid);
VOID					CRCCheck			(VOID);
WORD					CalculateCheckSum	(UINT CheckSum, PVOID FileBase, INT Length);
DWORD					GetFileCheckSum		(CONST WCHAR* ModulePath);

/* callback.cpp */
VOID					TLS_Callback		(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
VOID					Thread_Callback		(PTHREAD_START_ROUTINE Function, PVOID Parameter);
LONG					Exception_Callback	(EXCEPTION_POINTERS *pExceptionInfo);
VOID					DLL_Callback		(ULONG notification_reason, CONST LDR_DLL_NOTIFICATION_DATA* notification_data, PVOID context);

/* crypto.cpp */
VOID					DecryptXOR			(CHAR* Buffer, DWORD64 API);
DWORD64					CRC64				(PVOID ModuleBase);

/* string.cpp */
INT						mystrcmp			(CONST CHAR *p1, CONST CHAR *p2);
WCHAR*					mywcsistr			(CONST WCHAR* pszSrc, CONST WCHAR* pszSearch);
WCHAR*					mywcscpy			(WCHAR* s1, CONST WCHAR* s2);
WCHAR*					mywcscat			(WCHAR* s1, CONST WCHAR* s2);

