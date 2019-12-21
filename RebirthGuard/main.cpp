
/********************************************
*											*
*	RebirthGuard/main.cpp - chztbby			*
*											*
********************************************/

#include "RebirthGuard.h"

//-------------------------------------------------------
//	Register vectored handler and DLL notification.  
//-------------------------------------------------------
VOID RegisterCallbacks(VOID)
{
	// Register Vectored Exception Handler.
	((_RtlAddVectoredExceptionHandler)APICall(ntdll, 13))(1, Exception_Callback);

	printf("[ RegisterCallbacks ]  Registered : VEH\n");

	// Register DLL notificaton callback.
	PVOID cookie = NULL;
	((_LdrRegisterDllNotification)APICall(ntdll, 14))(0, DLL_Callback, NULL, &cookie);
	cookie = NULL;

	printf("[ RegisterCallbacks ]  Registered : DLL Notification\n");
}

//-------------------------------------------------------
//	Initialize RebirthGuard.    
//-------------------------------------------------------
VOID RebirthGuard(VOID)
{
	// Remap the ntdll.dll.
	WCHAR ntdllpath[MAX_PATH];
	wcscpy_s(ntdllpath, GetModuleName(ntdll));
	GetModuleFileName(myGetModuleHandle(ntdllpath), ntdllpath, sizeof(ntdllpath));
	RemapModule(CURRENT_PROCESS, ntdllpath);

	// Get options.
	DWORD Flag = 0xFFFFFFFF;
	GetOptions(NULL, &Flag, NULL, NULL);

	// Check the console print option.
	if (!(Flag & CONSOLE))
	{
		AllocConsole();
		FILE* f;
		freopen_s(&f, "CONOUT$", "w", stdout);
	}

	printf("[ RebirthGuard ]  Start\n");

	// Check this program is remapped.
	if (IsRemapped(CURRENT_PROCESS, myGetModuleHandle(NULL)) == NULL)
	{
		printf("[ RebirthGuard ]  This process is not remapped !\n");

		STARTUPINFOEX si = { sizeof(si) };
		PROCESS_INFORMATION pi;

		// Set process policy.
		if (Flag & PROCESS_POLICY)
		{
			UCHAR buffer[4096];
			LPPROC_THREAD_ATTRIBUTE_LIST attr = (LPPROC_THREAD_ATTRIBUTE_LIST)buffer;
			SIZE_T size = 0;

			InitializeProcThreadAttributeList(NULL, 1, 0, &size);
			
			attr = (LPPROC_THREAD_ATTRIBUTE_LIST)  new UCHAR[size];
			InitializeProcThreadAttributeList(attr, 1, 0, &size);

			DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE
				| PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE
				| PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE
				| PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS
				| PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON
				| PROCESS_CREATION_MITIGATION_POLICY2_RESTRICT_INDIRECT_BRANCH_PREDICTION_ALWAYS_ON
				;

			if (Flag & MS_SIGNED_ONLY)	policy |= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

			UpdateProcThreadAttribute(attr, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(policy), NULL, NULL);

			si.StartupInfo.cb = sizeof(si);
			si.lpAttributeList = attr;

			printf("[ RebirthGuard ]  Updated : Process policy\n");
		}

		// Restart process with CREATE_SUSPEND.
		if (Flag & PROCESS_POLICY)	CreateProcess(GetModuleName(EXE), GetCommandLine(),  NULL, NULL, NULL, CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si.StartupInfo, &pi);
		else						CreateProcess(GetModuleName(EXE), GetCommandLine(),  NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, (STARTUPINFO*)&si, &pi);
		printf("[ RebirthGuard ]  Created : child process\n");

		// Create remote thread in restarted process.
		HANDLE hThread = NULL;
		((_NtCreateThreadEx)APICall(ntdll, 11))(&hThread, MAXIMUM_ALLOWED, NULL, pi.hProcess, RegisterCallbacks, NULL, NULL, NULL, NULL, NULL, NULL);
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		printf("[ RebirthGuard ]  Created : Callback thread\n");

		// Get PEB address
		PROCESS_BASIC_INFORMATION pbi;
		((_NtQueryInformationProcess)APICall(ntdll, 7))(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);

		// Get module list of restarted process.
		PEB pPEB;
		PEB_LDR_DATA Ldr;
		LDR_DATA_TABLE_ENTRY List;
		((_NtReadVirtualMemory)APICall(ntdll, 6))(pi.hProcess, pbi.PebBaseAddress, &pPEB, sizeof(pPEB), NULL);
		((_NtReadVirtualMemory)APICall(ntdll, 6))(pi.hProcess, pPEB.Ldr, &Ldr, sizeof(Ldr), NULL);
		((_NtReadVirtualMemory)APICall(ntdll, 6))(pi.hProcess, Ldr.InMemoryOrderModuleList.Flink, &List, sizeof(List), NULL);
		printf("[ RebirthGuard ]  Read : PEB\n");

		// Remap all module of restarted process.
		while (List.DllBase)
		{
			WCHAR ModulePath[MAX_PATH];
			((_NtReadVirtualMemory)APICall(ntdll, 6))(pi.hProcess, List.FullDllName.Buffer, ModulePath, MAX_PATH, NULL);
			GetModuleFileName(myGetModuleHandle(ModulePath), ModulePath, sizeof(ModulePath));
			RemapModule(pi.hProcess, ModulePath);
			((_NtReadVirtualMemory)APICall(ntdll, 6))(pi.hProcess, (PVOID)*(SIZE_T*)&List, &List, sizeof(LDR_DATA_TABLE_ENTRY), NULL);
		}

		// Memory check
		if (Flag & MEMORY_CHECK)	MemoryCheck(pi.hProcess, pi.dwProcessId);

		// Resume the restarted process.
		((_NtResumeProcess)APICall(ntdll, 10))(pi.hProcess);

		// Terminate this process.
		((_NtTerminateProcess)APICall(ntdll, 9))(CURRENT_PROCESS, 0);
	}

	/*
		If this code is executed, this process has been successfully rebirthed.
	*/

	// Create splash image window.
	HANDLE hSplash = NULL;
	((_NtCreateThreadEx)APICall(ntdll, 11))(&hSplash, MAXIMUM_ALLOWED, NULL, CURRENT_PROCESS, SplashThread, NULL, NULL, NULL, NULL, NULL, NULL);

	// Splash image in.
	HWND splashwnd = FindWindow(0, L"RGsplash");
	while (!(splashwnd = FindWindow(0, L"RGsplash")));

	long style = GetWindowLong(splashwnd, GWL_EXSTYLE);
	style &= ~(WS_VISIBLE);
	style |= WS_EX_TOOLWINDOW | WS_EX_LAYERED;
	style &= ~(WS_EX_APPWINDOW);

	SetWindowLong(splashwnd, GWL_EXSTYLE, style);
	ShowWindow(splashwnd, SW_SHOW);

	for (int alpha = 0; alpha <= 255; alpha += 5)
	{
		SetWindowLong(splashwnd, GWL_EXSTYLE, style);
		SetLayeredWindowAttributes(splashwnd, 0, alpha, LWA_ALPHA);
		Sleep(5);
	}
	printf("[ RebirthGuard ]  Splash in\n");

	// Memory check
	if (Flag & MEMORY_CHECK)	MemoryCheck(CURRENT_PROCESS, GetCurrentProcessId());

	// Image check
	if (Flag & IMAGE_CHECK)		ImageCheck();

	// Splash image out.
	for (int alpha = 255; alpha >= 0; alpha -= 5)
	{
		SetWindowLong(splashwnd, GWL_EXSTYLE, style);
		SetLayeredWindowAttributes(splashwnd, 0, alpha, LWA_ALPHA);
		Sleep(5);
	}

	// Close splash image window.
	DestroyWindow(splashwnd);
	((_NtTerminateThread)APICall(ntdll, 12))(hSplash, 0);
	CloseHandle(hSplash);
	printf("[ RebirthGuard ]  Splash out\n");
}
