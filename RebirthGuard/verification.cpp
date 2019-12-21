
/********************************************
*											*
*	RebirthGuard/verification.cpp - chztbby	*
*											*
********************************************/

#include "RebirthGuard.h"

//-----------------------------------------------------------------
//	Check the image is remapped.
//-----------------------------------------------------------------
NTSTATUS IsRemapped(HANDLE hProcess, PVOID module)
{
	DWORD		Protect = 0;
	SIZE_T		Size = 1;
	NTSTATUS	result = ((_NtProtectVirtualMemory)APICall(ntdll, 3))(hProcess, &module, &Size, PAGE_EXECUTE_READWRITE, &Protect);

	if (result == STATUS_INVALID_PAGE_PROTECTION)	return result;																					  // This module is already remapped.
	else											return ((_NtProtectVirtualMemory)APICall(ntdll, 3))(hProcess, &module, &Size, Protect, &Protect); // This module is not remapped.
}

//-----------------------------------------------------------------
//	Check the address is in module region.
//
//  Type 0 : .text Section
//  Type 1 : Full range
//  Type 2 : Full range (return InMemoryOrderModuleList index.)
//-----------------------------------------------------------------
SIZE_T IsModuleRegion(PVOID Address, DWORD Type)
{
	LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;

	for (SIZE_T i = 0; ModuleList.DllBase; i++)
	{
		SIZE_T ModuleBase = (SIZE_T)myGetModuleHandle(ModuleList.FullDllName.Buffer);

		PIMAGE_NT_HEADERS		pNtHeader		= (PIMAGE_NT_HEADERS)((SIZE_T)ModuleBase + (SIZE_T)((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
		PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);

		SIZE_T ExecuteSize = 0;
		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
				ExecuteSize += PADDING(pSectionHeader[i].Misc.VirtualSize, pNtHeader->OptionalHeader.SectionAlignment);
			else
				break;
		}

		// The address is in .text section.
		if (Type == 0 && (SIZE_T)ModuleBase + (SIZE_T)pNtHeader->OptionalHeader.SectionAlignment <= (SIZE_T)Address && (SIZE_T)Address < (SIZE_T)ModuleBase + (SIZE_T)pNtHeader->OptionalHeader.SectionAlignment + ExecuteSize)
			return ModuleBase;

		// The address is in module. (return base address)
		else if (Type == 1 && (SIZE_T)ModuleBase <= (SIZE_T)Address && (SIZE_T)Address < (SIZE_T)ModuleBase + (SIZE_T)pNtHeader->OptionalHeader.SizeOfImage)
			return ModuleBase;

		// The address is in module. (return module's InMemoryOrderModuleList order)
		else if (Type == 2 && (SIZE_T)ModuleBase <= (SIZE_T)Address && (SIZE_T)Address < (SIZE_T)ModuleBase + (SIZE_T)pNtHeader->OptionalHeader.SizeOfImage)
			return i;

		ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);
	}
	// The address is invalid.
	return -1;
}

//-----------------------------------------------------------------
//	Check the start address of thread.
//-----------------------------------------------------------------
VOID ThreadCheck(PVOID StartAddress, DWORD type)
{
	// Get options.
	DWORD Flag = 0xFFFFFFFF;
	GetOptions(NULL, &Flag, NULL, NULL);

	// Set thread information.
	if (Flag & ANTI_DEBUGGING)
		((_NtSetInformationThread)APICall(ntdll, 8))(CURRENT_THREAD, ThreadHideFromDebugger, NULL, NULL);

	// Query memory information of thread start address.
	MEMORY_BASIC_INFORMATION mbi;
	((_NtQueryVirtualMemory)APICall(ntdll, 4))(CURRENT_PROCESS, StartAddress, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

	if (Flag & THREAD_CHECK)
	{
		// Start address is not module memory.
		if (IsModuleRegion(StartAddress, 0) == -1)
			Detected(CURRENT_PROCESS, OptionStr[5], THREAD_StartAddress, StartAddress, (PVOID)(SIZE_T)type);

		// Start address is writable.
		else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			Detected(CURRENT_PROCESS, OptionStr[5], THREAD_Protection, StartAddress, (PVOID)(SIZE_T)type);
	}

	if (Flag & ANTI_DLL_INJECTION)
	{
		// DLL Injection with LoadLibraryA in Kernel32.dll.
		if (StartAddress == APICall(kernel32, 15))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_Kernel32_LoadLibraryA, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryW in Kernel32.dll.
		else if (StartAddress == APICall(kernel32, 16))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_Kernel32_LoadLibraryW, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryExA in Kernel32.dll.
		else if (StartAddress == APICall(kernel32, 17))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_Kernel32_LoadLibraryExA, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryExW in Kernel32.dll.
		else if (StartAddress == APICall(kernel32, 18))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_Kernel32_LoadLibraryExW, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryA in KernelBase.dll.
		else if (StartAddress == APICall(kernelbase, 15))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_KernelBase_LoadLibraryA, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryW in KernelBase.dll.
		else if (StartAddress == APICall(kernelbase, 16))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_KernelBase_LoadLibraryW, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryExA in KernelBase.dll.
		else if (StartAddress == APICall(kernelbase, 17))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_KernelBase_LoadLibraryExA, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LoadLibraryExW in KernelBase.dll.
		else if (StartAddress == APICall(kernelbase, 18))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_KernelBase_LoadLibraryExW, StartAddress, (PVOID)(SIZE_T)type);

		// DLL Injection with LdrLoadDll in ntdll.dll.
		else if (StartAddress == APICall(ntdll, 19))
			Detected(CURRENT_PROCESS, OptionStr[8], DLL_INJECTION_Ntdll_LdrLoadDll, StartAddress, (PVOID)(SIZE_T)type);
	}	

	if (Flag & THREAD_CHECK)
		printf("[ ThreadCheck ]  0x%I64X [%d]\n", (SIZE_T)StartAddress, GetCurrentThreadId());
}

//-----------------------------------------------------------------
//	Destory the code section in module region.
//  If the module has been remapped, it will not be affected.
//-----------------------------------------------------------------
VOID DestoryModule(HANDLE hProcess)
{
	LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;

	while (ModuleList.DllBase)
	{
		// Get full path of module.
		WCHAR ModulePath[MAX_PATH];
		GetModuleFileName(myGetModuleHandle(ModuleList.FullDllName.Buffer), ModulePath, sizeof(ModulePath));

		// Get options.
		DWORD ExceptFlag = 0;
		GetOptions(ModulePath, NULL, NULL, &ExceptFlag);

		// Check this module is excepted.
		if (!(ExceptFlag & EXCEPT_REBIRTH))
		{
			PVOID					Base			= myGetModuleHandle(ModuleList.FullDllName.Buffer);
			DWORD					Protect			= 0;
			PVOID					mem				= NULL;
			PIMAGE_NT_HEADERS		pNtHeader		= (PIMAGE_NT_HEADERS)((SIZE_T)Base + (SIZE_T)((PIMAGE_DOS_HEADER)Base)->e_lfanew);
			PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);
			PVOID					Address			= (PVOID)((SIZE_T)Base + pNtHeader->OptionalHeader.SectionAlignment);
			SIZE_T					WriteSize		= 0;

			// Get size of (.text + .rdata) section.
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					WriteSize = pSectionHeader[i].VirtualAddress;
					break;
				}
			}

			// Destory memory.
			((_NtAllocateVirtualMemory)	APICall(ntdll, 26))	(CURRENT_PROCESS, &mem, NULL, &WriteSize, MEM_COMMIT, PAGE_READWRITE);
			((_NtProtectVirtualMemory)	APICall(ntdll, 3))	(hProcess, &Address, &WriteSize, PAGE_EXECUTE_READWRITE, &Protect);
			((_NtWriteVirtualMemory)	APICall(ntdll, 25))	(hProcess, Address, mem, WriteSize, NULL);
			WriteSize = NULL;
			((_NtFreeVirtualMemory)		APICall(ntdll, 27))	(CURRENT_PROCESS, &mem, &WriteSize, MEM_RELEASE);
		}

		ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);
	}
}

//-----------------------------------------------------------------
//	Check the all memory region.
//-----------------------------------------------------------------
VOID MemoryCheck(HANDLE hProcess, DWORD pid)
{
	// Destory module memory.
	DestoryModule(hProcess);

	// Scan all of memory regions.
	for (PVOID Address = 0; (SIZE_T)Address < 0x7FFFFFFF0000;)
	{
		// Query memory information of target address.
		MEMORY_BASIC_INFORMATION mbi;
		((_NtQueryVirtualMemory)APICall(ntdll, 4))(hProcess, Address, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		// This region is not remapped.
		if (mbi.Type == MEM_IMAGE)
			Detected(hProcess, OptionStr[6], MEMORY_Image, Address, (PVOID)0);

		// This region is private allocated, and WRITEABLE memory.
		else if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
			Detected(hProcess, OptionStr[6], MEMORY_Private_Execute, Address, (PVOID)0);

		// This region is not remapped.
		else if (mbi.Protect == PAGE_EXECUTE_WRITECOPY && IsRemapped(hProcess, Address) == FALSE)
			Detected(hProcess, OptionStr[6], MEMORY_NotRemapped, Address, (PVOID)0);

		// This region's page protection is not restored.
		else if (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
			Detected(hProcess, OptionStr[6], MEMORY_Execute_Write, Address, (PVOID)0);

		// This region is invalid.
		else if (mbi.Protect == PAGE_EXECUTE_READ || (IsModuleRegion(Address, 1) == (SIZE_T)myGetModuleHandle(NULL)))
		{
			PSAPI_WORKING_SET_EX_INFORMATION wsi;
			wsi.VirtualAddress = Address;
			((_NtQueryVirtualMemory)APICall(ntdll, 4))(hProcess, Address, MemoryWorkingSetExList, &wsi, sizeof(wsi), 0);

			if (wsi.VirtualAttributes.Locked == 0)
				Detected(hProcess, OptionStr[6], MEMORY_Unlocked, Address, (PVOID)0);

			else if (*((BYTE*)&wsi.VirtualAttributes.Flags + 2) != 0x40)
				Detected(hProcess, OptionStr[6], MEMORY_Unlocked_2, Address, (PVOID)0);
		}

		Address = (PVOID)((SIZE_T)Address + mbi.RegionSize);
	}

	printf("[ MemoryCheck ]  Checked : Memory\n");
}

//-----------------------------------------------------------------------
//	Check the integrity of .text and .rdata section.
//-----------------------------------------------------------------------
VOID ImageCheck(VOID)
{
	LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;

	while (ModuleList.DllBase)
	{
		// Get base address of module.
		SIZE_T ModuleBase = (SIZE_T)myGetModuleHandle(ModuleList.FullDllName.Buffer);

		// Get full path of module.
		WCHAR ModulePath[MAX_PATH];
		GetModuleFileName((HMODULE)ModuleBase, ModulePath, sizeof(ModulePath));
		
		// Manually map this module from file.
		SIZE_T MappedModule = ManualMap(CURRENT_PROCESS, ModulePath);
		
		PIMAGE_NT_HEADERS		pNtHeader		= (PIMAGE_NT_HEADERS)((SIZE_T)MappedModule + (SIZE_T)((PIMAGE_DOS_HEADER)MappedModule)->e_lfanew);
		PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);

		// Get size of (.text + .rdata) section.
		SIZE_T CheckSize = 0;
		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			{
				CheckSize = pSectionHeader[i].VirtualAddress;
				break;
			}
		}

		// Except RtlUserThreadStart
		SIZE_T RtlUserThreadStart_offset = (SIZE_T)APICall(ntdll, 20) - (SIZE_T)myGetModuleHandle(GetModuleName(ntdll));

		// Compare file data with image data.
		for (SIZE_T i = 0; i < CheckSize; i += sizeof(SIZE_T))
		{
			if (*(SIZE_T*)(ModuleBase + i) != *(SIZE_T*)(MappedModule + i)
				&& i != RtlUserThreadStart_offset
				&& i - sizeof(SIZE_T) != RtlUserThreadStart_offset)
				Detected(CURRENT_PROCESS, OptionStr[7], IMAGE_Fail, (PVOID)ModuleBase, (PVOID)0);
		}

		// Release memory of manually mapped module.
		SIZE_T ImageSize = NULL;
		((_NtFreeVirtualMemory)APICall(ntdll, 27))(CURRENT_PROCESS, (PVOID*)&MappedModule, &ImageSize, MEM_RELEASE);

		ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);
	}

	printf("[ ImageCheck ]  Checked : Image integrity\n");
}

//-----------------------------------------------------------------------
//	Check the checksum data.
//
//	PEChecksum
//		--> VerifyCheckSum
//			--> CalculateCheckSum
//-----------------------------------------------------------------------
WORD CalculateCheckSum(UINT CheckSum, PVOID FileBase, INT Length)
{
	INT* Data;
	INT sum;

	if (Length && FileBase != NULL)
	{
		Data = (INT *)FileBase;
		do
		{
			sum = *(WORD*)Data + CheckSum;
			Data = (INT*)((CHAR*)Data + 2);
			CheckSum = (WORD)sum + (sum >> 16);
		} while (--Length);
	}

	return CheckSum + (CheckSum >> 16);
}

BOOL VerifyCheckSum(PVOID FileBase, UINT FileSize)
{
	PVOID RemainData;
	INT RemainDataSize;
	SIZE_T PeHeaderSize;
	DWORD PeHeaderCheckSum;
	DWORD FileCheckSum;
	PIMAGE_NT_HEADERS NtHeaders;

	NtHeaders = (PIMAGE_NT_HEADERS)((SIZE_T)FileBase + ((PIMAGE_DOS_HEADER)FileBase)->e_lfanew);

	if (NtHeaders)
	{
		PeHeaderSize = (SIZE_T)NtHeaders - (SIZE_T)FileBase + ((SIZE_T)&NtHeaders->OptionalHeader.CheckSum - (SIZE_T)NtHeaders);
		RemainDataSize = (INT)((FileSize - PeHeaderSize - 4) >> 1);
		RemainData = &NtHeaders->OptionalHeader.Subsystem;
		PeHeaderCheckSum = CalculateCheckSum(0, FileBase, (INT)PeHeaderSize >> 1);
		FileCheckSum = CalculateCheckSum(PeHeaderCheckSum, RemainData, RemainDataSize);

		if (FileSize & 1)
			FileCheckSum += (WORD)*((CHAR*)FileBase + FileSize - 1);
	}
	else
		FileCheckSum = 0;

	return FileSize + FileCheckSum == NtHeaders->OptionalHeader.CheckSum;
}

BOOL FileIntegrity(CONST WCHAR* ModuleName)
{
	BOOL result = FALSE;

	HANDLE hFile = CreateFile(ModuleName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		HANDLE FileMapHandle = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

		if (FileMapHandle != NULL)
		{
			WORD* FileBase = (WORD*)MapViewOfFile(FileMapHandle, FILE_MAP_READ, 0, 0, 0);

			if (FileBase != NULL)
			{
				DWORD FileSize = GetFileSize(hFile, NULL);

				result = VerifyCheckSum(FileBase, FileSize);

				UnmapViewOfFile(FileBase);
			}
		}
		CloseHandle(FileMapHandle);
	}

	CloseHandle(hFile);

	if (result == TRUE)	printf("[ FileIntegrity ]  Checked : %S\n", ModuleName);

	return result;
}
