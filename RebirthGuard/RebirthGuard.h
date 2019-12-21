
/********************************************
*											*
*	RebirthGuard/RebirthGuard.h - chztbby	*
*											*
********************************************/

#include "Windows.h"
#include "Winternl.h"
#include "psapi.h"
#include "time.h"
#include "stdio.h"
#pragma comment (lib, "advapi32.lib")
#pragma comment (linker, "/LTCG")

//-----------------------------------------------------------------
//	Basic
//-----------------------------------------------------------------
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


//-----------------------------------------------------------------
//	Main options
//-----------------------------------------------------------------
#define PROCESS_POLICY							0x00000001
#define MS_SIGNED_ONLY							0x00000002
#define FILE_INTEGRITY							0x00000004
#define TLS_CALLBACK							0x00000008
#define THREAD_CHECK							0x00000010
#define MEMORY_CHECK							0x00000020
#define IMAGE_CHECK								0x00000040
#define ANTI_DLL_INJECTION						0x00000080
#define ANTI_DEBUGGING							0x00000100
#define CONSOLE									0x00000200


//-----------------------------------------------------------------
//	Sub Options (Checksum / Remapping)
//-----------------------------------------------------------------
#define EXCEPT_FILE_INTEGRITY					0x00000001
#define EXCEPT_REBIRTH							0x00000002


//-----------------------------------------------------------------
// Strings
//-----------------------------------------------------------------
static CONST WCHAR IniPath[] = L"RebirthGuard.ini";
static CONST CHAR* OptionStr[] =
{
	"[ RebirthGuard ]",
	"PROCESS_POLICY",
	"MS_SIGNED_ONLY",
	"FILE_INTEGRITY",
	"TLS_CALLBACK",
	"THREAD_CHECK",
	"MEMORY_CHECK",
	"IMAGE_CHECK",
	"ANTI_DLL_INJECTION",
	"ANTI_DEBUGGING",
	"CONSOLE = TRUE",
	" = EXCEPT_FILE_INTEGRITY",
	" = EXCEPT_REBIRTH",
};

//-----------------------------------------------------------------
//	InMemoryOrderModuleList Indices
//-----------------------------------------------------------------
#define EXE										0
#define ntdll									1
#define kernel32								2
#define kernelbase								3

//-----------------------------------------------------------------
//	Detection Codes
//-----------------------------------------------------------------
typedef enum _REBIRTHGUARD_CODE
{
	FileMissing,
	FileString,
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
	MEMORY_NotRemapped,
	MEMORY_Execute_Write,
	MEMORY_Unlocked,
	MEMORY_Unlocked_2,
	IMAGE_Fail,
	FILE_INTEGRITY_Fail,
	APICALL_Invalid_Module,
	APICALL_Invalid_API,
	EXCEPTION_Debugging,
	EXCEPTION_Single_Step,
	EXCEPTION_Guarded_Page
} REBIRTHGUARD_CODE;


//-----------------------------------------------------------------
//	Native API
//-----------------------------------------------------------------
typedef NTSTATUS	(NTAPI* _NtCreateSection)					(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS	(NTAPI* _NtMapViewOfSection)				(HANDLE, HANDLE, PSIZE_T, SIZE_T, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, DWORD, DWORD);
typedef NTSTATUS	(NTAPI* _NtUnmapViewOfSection)				(HANDLE, SIZE_T);
typedef NTSTATUS	(NTAPI* _NtProtectVirtualMemory)			(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtQueryVirtualMemory)				(HANDLE, PVOID, DWORD, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS	(NTAPI* _NtLockVirtualMemory)				(HANDLE, PVOID, PSIZE_T, ULONG);
typedef NTSTATUS	(NTAPI* _NtReadVirtualMemory)				(HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtWriteVirtualMemory)				(HANDLE, PVOID, PVOID, SIZE_T, PULONG);
typedef NTSTATUS	(NTAPI* _NtAllocateVirtualMemory)			(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS	(NTAPI* _NtFreeVirtualMemory)				(HANDLE, PVOID*, PSIZE_T, ULONG);
typedef NTSTATUS	(NTAPI* _NtResumeProcess)					(HANDLE);
typedef NTSTATUS	(NTAPI* _NtQueryInformationProcess)			(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtQueryInformationThread)			(HANDLE, DWORD, PVOID, ULONG, PULONG);
typedef NTSTATUS	(NTAPI* _NtSetInformationProcess)			(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS	(NTAPI* _NtSetInformationThread)			(HANDLE, DWORD, PVOID, ULONG);
typedef NTSTATUS	(NTAPI* _RtlAcquirePrivilege)				(PULONG, ULONG, ULONG, PVOID*);
typedef NTSTATUS	(NTAPI* _RtlReleasePrivilege)				(PVOID);
typedef NTSTATUS	(NTAPI* _NtCreateThreadEx)					(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS	(NTAPI* _NtTerminateProcess)				(HANDLE, NTSTATUS);
typedef NTSTATUS	(NTAPI* _NtTerminateThread)					(HANDLE, NTSTATUS);
typedef NTSTATUS	(NTAPI* _RtlAddVectoredExceptionHandler)	(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef NTSTATUS	(NTAPI* _LdrRegisterDllNotification)		(ULONG, PVOID, PVOID, PVOID);


//-----------------------------------------------------------------
//	DLL Load notification
//-----------------------------------------------------------------
typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
	ULONG Flags;
	PUNICODE_STRING FullDllName;
	PUNICODE_STRING BaseDllName;
	PVOID DllBase;
	ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
	LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
	LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;


/* main.cpp */
VOID		RegisterCallbacks				(VOID);
VOID		RebirthGuard					(VOID);

/* function.cpp */
VOID		GetOptions						(CONST WCHAR* ModulePath, DWORD* OptionFlag, CHAR* KillFlag, DWORD* ExceptFlag);
WCHAR*		GetModuleName					(DWORD order);
HMODULE		myGetModuleHandle				(LPCWSTR lpModuleName);
FARPROC		myGetProcAddress				(HMODULE hModule, LPCSTR lpProcName);
FARPROC		APICall							(DWORD Module, SIZE_T API);

/* crypto.cpp */
VOID		DecryptFileToMem				(BYTE* Buffer);
VOID		DecryptMem						(CHAR* Buffer, SIZE_T API);

/* mapping.cpp */
SIZE_T		ManualMap						(HANDLE hProcess, CONST WCHAR* ModulePath);
VOID		ExtendWorkingSet				(HANDLE hProcess);
VOID		RemapModule						(HANDLE hProcess, CONST WCHAR* ModulePath);

/* verification.cpp */
NTSTATUS	IsRemapped						(HANDLE hProcess, PVOID module);
SIZE_T		IsModuleRegion					(PVOID Address, DWORD type);
VOID		ThreadCheck						(PVOID StartAddress, DWORD type);
VOID		DestoryModule					(HANDLE hProcess);
VOID		MemoryCheck						(HANDLE hProcess, DWORD pid);
VOID		ImageCheck						(VOID);
WORD		CalculateCheckSum				(UINT CheckSum, PVOID FileBase, INT Length);
BOOL		VerifyCheckSum					(PVOID FileBase, UINT FileSize);
BOOL		FileIntegrity					(CONST WCHAR* ModuleName);

/* callback.cpp */
VOID		Detected						(HANDLE hProcess, CONST CHAR* ErrorType, REBIRTHGUARD_CODE ErrorCode, PVOID ErrorAddress, PVOID ErrorAddress2);
void		TLS_Callback					(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
VOID		Thread_Callback					(PTHREAD_START_ROUTINE Function, PVOID Parameter);
LONG		Exception_Callback				(EXCEPTION_POINTERS *pExceptionInfo);
VOID		DLL_Callback					(ULONG notification_reason, CONST LDR_DLL_NOTIFICATION_DATA* notification_data, PVOID context);

/* splash.cpp */
LRESULT		SplashProc						(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam);
VOID		SplashThread					(VOID);
