
/********************************************
*											*
*	RebirthGuard/callback.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"

//-----------------------------------------------------------------
//	Detected violation.
//-----------------------------------------------------------------
VOID Detected(HANDLE hProcess, CONST CHAR* ErrorType, REBIRTHGUARD_CODE ErrorCode, PVOID ErrorAddress, PVOID ErrorAddress2)
{
	// Time stamp.
	time_t t = time(NULL);
	tm tm;
	localtime_s(&tm, &t);

	// Get options.
	CHAR KillFlag[100];
	if (ErrorType)
	{
		strcpy_s(KillFlag, ErrorType);
		GetOptions(NULL, NULL, KillFlag, NULL);
	}

	// Address check
	SIZE_T order = IsModuleRegion(ErrorAddress, 2);
	SIZE_T order2 = IsModuleRegion(ErrorAddress2, 2);

	// If address is in module region, get full path.
	WCHAR ModulePath[MAX_PATH] = L"NULL";
	WCHAR ModulePath2[MAX_PATH] = L"NULL";
	LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
	for (SIZE_T i = 0; ModuleList.DllBase; i++)
	{
		if (order == i)		GetModuleFileName(myGetModuleHandle(ModuleList.FullDllName.Buffer), ModulePath, sizeof(ModulePath));
		if (order2 == i)	GetModuleFileName(myGetModuleHandle(ModuleList.FullDllName.Buffer), ModulePath2, sizeof(ModulePath2));

		ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);
	}

	// Print log to the console.
	printf("===================================================================================\n"
		"[ %04d-%02d-%02d %02d:%02d:%02d ]\n\n"
		"    Pid\t: %d\n"
		"    Code\t: 0x%08X\n\n"
		"    0x%p\t(%S)\n"
		"    0x%p\t(%S)\n\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, GetCurrentProcessId(), ErrorCode, ErrorAddress, ModulePath, ErrorAddress2, ModulePath2);

	// Print log to the file.
	FILE* log = NULL;
	fopen_s(&log, "RebirthGuard.log", "a+");
	fprintf(log, "===================================================================================\n"
					"[ %04d-%02d-%02d %02d:%02d:%02d ]\n\n"
					"    Pid\t: %d\n"
					"    Code\t: 0x%08X\n\n"
					"    0x%p\t(%S)\n"
					"    0x%p\t(%S)\n\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, GetCurrentProcessId(), ErrorCode, ErrorAddress, ModulePath, ErrorAddress2, ModulePath2);
	fclose(log);

	// Check kill option.
	if (ErrorType == NULL || strstr(KillFlag, "KILL"))
	{
		((_NtTerminateProcess)APICall(ntdll, 9))(hProcess, 0);
		((_NtTerminateProcess)APICall(ntdll, 9))(CURRENT_PROCESS, 0);
	}
	// Check stop option.
	else if (ErrorType == NULL || strstr(KillFlag, "STOP"))
		while (1)	Sleep(1000);
}

//-----------------------------------------------------------------
//	TLS Callback.
//-----------------------------------------------------------------
VOID TLS_Callback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	// Get options.
	DWORD Flag = 0xFFFFFFFF;
	GetOptions(NULL, &Flag, NULL, NULL);

	if (Flag & TLS_CALLBACK)
		printf("[ TLS_Callback ]  Entered\n");

	// Query information of thread.
	PVOID StartAddress = NULL;
	((_NtQueryInformationThread)APICall(ntdll, 21))(CURRENT_THREAD, ThreadQuerySetWin32StartAddress, &StartAddress, sizeof(StartAddress), 0);

	// Thread check.
	ThreadCheck(StartAddress, 0);

	// TLS Callback option is enabled.
	if ((Flag & TLS_CALLBACK) && dwReason == DLL_PROCESS_ATTACH && StartAddress != RegisterCallbacks)
		RebirthGuard();

	// Check the module is remapped.
	else if ((Flag & MEMORY_CHECK) && dwReason == DLL_THREAD_ATTACH)
		DestoryModule(CURRENT_PROCESS);
}

//-----------------------------------------------------------------
//	Hooked RtlUserThreadStart to this function.
//-----------------------------------------------------------------
VOID Thread_Callback(PTHREAD_START_ROUTINE StartAddress, PVOID Parameter)
{
	// Thread check.
	ThreadCheck(StartAddress, 0x10);

	((_NtTerminateThread)APICall(ntdll, 12))(CURRENT_THREAD, StartAddress(Parameter));
}

//-----------------------------------------------------------------
//	Vectored exception handler.
//-----------------------------------------------------------------
LONG WINAPI Exception_Callback(EXCEPTION_POINTERS *pExceptionInfo)
{
	// Debugging event
	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
		Detected(CURRENT_PROCESS, OptionStr[9], EXCEPTION_Debugging, (PVOID)0, (PVOID)0);

	// Trap flag is enabled.
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
		Detected(CURRENT_PROCESS, OptionStr[9], EXCEPTION_Single_Step, (PVOID)0, (PVOID)0);

	// This page protection is PAGE_GUARD.
	else if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
		Detected(CURRENT_PROCESS, OptionStr[9], EXCEPTION_Guarded_Page, (PVOID)0, (PVOID)0);

	return EXCEPTION_CONTINUE_SEARCH;
}

//-----------------------------------------------------------------
//	DLL notification callback.
//-----------------------------------------------------------------
VOID DLL_Callback(ULONG notification_reason, CONST LDR_DLL_NOTIFICATION_DATA* notification_data, PVOID context)
{
	if (notification_reason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		printf("[ DLL_Callback ]  Loaded : %S\n", notification_data->Loaded.FullDllName->Buffer);
		RemapModule(CURRENT_PROCESS, notification_data->Loaded.FullDllName->Buffer);
	}

	return;
}
