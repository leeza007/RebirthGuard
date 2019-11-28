
/********************************************
*											*
*	RebirthGuard/mapping.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"

//-------------------------------------------------------
//  1. Check the file integrity.
//	2. Load the file to memory.
//  2. Relocate image.
//  3. Resolve image imports.
//-------------------------------------------------------
SIZE_T ManualMap(HANDLE hProcess, CONST WCHAR* ModulePath)
{
	DWORD Flag = 0xFFFFFFFF, ExceptFlag = 0;
	GetOptions(ModulePath, &Flag, NULL, &ExceptFlag);

	// 1. Check the file integrity.
	if ((Flag & FILE_INTEGRITY) && !(ExceptFlag & EXCEPT_FILE_INTEGRITY) && !FileIntegrity(ModulePath))
		Detected(hProcess, OptionStr[6], FILE_INTEGRITY_Fail, (PVOID)myGetModuleHandle(ModulePath), (PVOID)0);

	// 2. Load the file to memory.
	HANDLE	hFile		= CreateFile(ModulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	DWORD	FileSize	= GetFileSize(hFile, NULL);
	HANDLE	hFileMap	= CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	PVOID	DataBuffer	= MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);

	CloseHandle(hFileMap);
	CloseHandle(hFile);

	PIMAGE_NT_HEADERS	pNtHeader	= (PIMAGE_NT_HEADERS)((LPBYTE)DataBuffer + ((PIMAGE_DOS_HEADER)DataBuffer)->e_lfanew);
	PVOID				ImageBase	= NULL;
	SIZE_T				ImageSize	= pNtHeader->OptionalHeader.SizeOfImage;
	((_NtAllocateVirtualMemory)APICall(ntdll, 26))(CURRENT_PROCESS, &ImageBase, NULL, &ImageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	for (SIZE_T i = 0; i < pNtHeader->OptionalHeader.SizeOfHeaders; i += sizeof(SIZE_T))
		*(SIZE_T*)((SIZE_T)ImageBase + i) = *(SIZE_T*)((SIZE_T)DataBuffer + i);

	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

	for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		for (SIZE_T j = 0; j < pSectionHeader[i].SizeOfRawData; j += sizeof(SIZE_T))
			*(SIZE_T*)((SIZE_T)ImageBase + pSectionHeader[i].VirtualAddress + j) = *(SIZE_T*)((SIZE_T)DataBuffer + pSectionHeader[i].PointerToRawData + j);

	PVOID OriginImageBase = myGetModuleHandle(ModulePath);

	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	SIZE_T delta = (SIZE_T)((LPBYTE)OriginImageBase - pNtHeader->OptionalHeader.ImageBase); // Calculate the delta

	// 3. Relocate Image.
	while (pBaseRelocation->VirtualAddress)
	{
		if (pBaseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			DWORD count = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* list = (PWORD)(pBaseRelocation + 1);

			for (SIZE_T i = 0; i < count; i++)
			{
				if (list[i])
				{
					PVOID ptr = ((LPBYTE)ImageBase + (pBaseRelocation->VirtualAddress + (list[i] & 0xFFF)));
					*(SIZE_T*)ptr += delta;
				}
			}
		}

		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}

	// 4. Resolve Image imports.
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImportDescriptor->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk	= (PIMAGE_THUNK_DATA)((LPBYTE)ImageBase + pImportDescriptor->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk		= (PIMAGE_THUNK_DATA)((LPBYTE)ImageBase + pImportDescriptor->FirstThunk);

		HMODULE hModule = LoadLibraryA((LPCSTR)((SIZE_T)ImageBase + pImportDescriptor->Name));

		if (!hModule)	break;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			// Import by ordinal
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				SIZE_T Function = (SIZE_T)myGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
				if (!Function)
					break;

				*(SIZE_T*)FirstThunk = Function;
			}
			// Import by name
			else
			{
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ImageBase + OrigFirstThunk->u1.AddressOfData);
				SIZE_T Function;
				HMODULE hkernel32	= myGetModuleHandle(GetModuleName(kernel32));
				HMODULE hkernelbase = myGetModuleHandle(GetModuleName(kernelbase));
				if (OriginImageBase == hkernel32 && myGetProcAddress(hkernelbase, (LPCSTR)pIBN->Name))
					Function = (SIZE_T)GetProcAddress(hkernelbase, (LPCSTR)pIBN->Name);
				else
					Function = (SIZE_T)GetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					break;

				*(SIZE_T*)FirstThunk = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pImportDescriptor++;
	}

	UnmapViewOfFile(DataBuffer);

	return (SIZE_T)ImageBase;
}

//-------------------------------------------------------
//	Extend WorkingSet size to lock memory.
//-------------------------------------------------------
VOID ExtendWorkingSet(HANDLE hProcess)
{
	QUOTA_LIMITS ql;
	DWORD PrivilegeValue = SE_AUDIT_PRIVILEGE;
	PVOID PrivilegeState = NULL;

	((_NtQueryInformationProcess)	APICall(ntdll, 7))	(hProcess, ProcessQuotaLimits, &ql, sizeof(ql), NULL);

	ql.MinimumWorkingSetSize += PAGE_SIZE;
	if (ql.MaximumWorkingSetSize < ql.MinimumWorkingSetSize)
		ql.MaximumWorkingSetSize = ql.MinimumWorkingSetSize;

	((_RtlAcquirePrivilege)			APICall(ntdll, 22))	(&PrivilegeValue, 1, 0, &PrivilegeState);

	((_NtSetInformationProcess)		APICall(ntdll, 23))	(hProcess, ProcessQuotaLimits, &ql, sizeof(ql));

	((_RtlReleasePrivilege)			APICall(ntdll, 24))	(PrivilegeState);
}

//-------------------------------------------------------
//  1. Load the file to memory manually.
//	2. Create section to remap the image.
//  3. Map view of section.
//  4. Copy memory.
//  5. Unmap the view.
//  6. Unmap the original image.
//  7. Remap with SEC_NO_CHANGE flag.
//  8. Lock memory.
//-------------------------------------------------------
VOID RemapModule(HANDLE hProcess, CONST WCHAR* ModulePath)
{
	// Get ntdll.dll path and address.
	WCHAR ntdllpath[MAX_PATH];
	wcscpy_s(ntdllpath, GetModuleName(ntdll));
	HMODULE origin_ntdll			= myGetModuleHandle(ntdllpath);
	HMODULE	proxy_ntdll				= NULL;

	// Get original native API.
	_NtCreateSection		NtCreateSection			= (_NtCreateSection)		APICall(ntdll, 0);
	_NtMapViewOfSection		NtMapViewOfSection		= (_NtMapViewOfSection)		APICall(ntdll, 1);
	_NtUnmapViewOfSection	NtUnmapViewOfSection	= (_NtUnmapViewOfSection)	APICall(ntdll, 2);
	_NtLockVirtualMemory	NtLockVirtualMemory		= (_NtLockVirtualMemory)	APICall(ntdll, 5);

	// If ntdll.dll is not remapped, use proxy ntdll.dll.
	if (IsRemapped(CURRENT_PROCESS, origin_ntdll) == NULL)
	{
		GetModuleFileName(origin_ntdll, ntdllpath, sizeof(ntdllpath));
		proxy_ntdll = (HMODULE)ManualMap(hProcess, ntdllpath);

		NtCreateSection			= (_NtCreateSection)		((SIZE_T)proxy_ntdll + (SIZE_T)NtCreateSection		- (SIZE_T)origin_ntdll);
		NtMapViewOfSection		= (_NtMapViewOfSection)		((SIZE_T)proxy_ntdll + (SIZE_T)NtMapViewOfSection	- (SIZE_T)origin_ntdll);
		NtUnmapViewOfSection	= (_NtUnmapViewOfSection)	((SIZE_T)proxy_ntdll + (SIZE_T)NtUnmapViewOfSection	- (SIZE_T)origin_ntdll);
	}
	
	SIZE_T ModuleBase = (SIZE_T)myGetModuleHandle(ModulePath);

	// Check this module is already remapped.
	if (IsRemapped(hProcess, (PVOID)ModuleBase) == NULL)
	{
		// 1. Load the file to memory manually.
		SIZE_T MappedModule = ManualMap(hProcess, ModulePath);

		PIMAGE_NT_HEADERS		pNtHeader		= (PIMAGE_NT_HEADERS)(MappedModule + ((PIMAGE_DOS_HEADER)MappedModule)->e_lfanew);
		PIMAGE_SECTION_HEADER	pSectionHeader	= IMAGE_FIRST_SECTION(pNtHeader);
		DWORD					SizeOfImage		= pNtHeader->OptionalHeader.SizeOfImage;
		HANDLE					hSection		= NULL;
		SIZE_T					ViewBase		= NULL;
		SIZE_T					ViewSize		= NULL;
		SIZE_T					LockSize		= 1;
		LARGE_INTEGER			SectionOffset;
		LARGE_INTEGER			SectionSize;

		for (SIZE_T i = 0; i < sizeof(LARGE_INTEGER); i += sizeof(SIZE_T))
			*(SIZE_T*)(&SectionOffset + i) = *(SIZE_T*)(&SectionSize + i) = 0;

		SectionSize.QuadPart = SizeOfImage;

		// If SectionAlignment is equal to  AllocationGranularity. (0x10000)
		if (pNtHeader->OptionalHeader.SectionAlignment == AllocationGranularity)
		{
			// 2. Create section to remap the image.
			NtCreateSection(&hSection, MAXIMUM_ALLOWED, NULL, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL);

			// 3. Map view of section.
			NtMapViewOfSection(hSection, CURRENT_PROCESS, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READWRITE);

			// 4. Copy memory. (PE Header)
			for (SIZE_T i = 0; i < PAGE_SIZE; i += sizeof(SIZE_T))
				*(SIZE_T*)(ViewBase + i) = *(SIZE_T*)(MappedModule + i);

			// 4. Copy memory. (Each section)
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
				for (SIZE_T j = 0; j < pSectionHeader[i].Misc.VirtualSize; j += sizeof(SIZE_T))
					*(SIZE_T*)(ViewBase + pSectionHeader[i].VirtualAddress + j) = *(SIZE_T*)(MappedModule + pSectionHeader[i].VirtualAddress + j);

			// 5. Unmap the view.
			NtUnmapViewOfSection(CURRENT_PROCESS, ViewBase);

			// 6. Unmap the original image.
			NtUnmapViewOfSection(hProcess, ModuleBase);

			// 7. Remap with SEC_NO_CHANGE flag. (PE Header)
			ViewBase = ModuleBase;
			ViewSize = AllocationGranularity;
			NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);

			// 8. Lock memory. (PE Header)
			while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(hProcess);

			for (DWORD i = 0, Protect; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				// Calculate size and get page protection.
				ViewBase = ModuleBase + pSectionHeader[i].VirtualAddress;
				ViewSize = PADDING(pSectionHeader[i].Misc.VirtualSize, AllocationGranularity);
				SectionOffset.QuadPart = pSectionHeader[i].VirtualAddress;
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)		Protect = PAGE_EXECUTE_READ;
				else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)	Protect = PAGE_READWRITE;
				else																Protect = PAGE_READONLY;

				// 7. Remap with SEC_NO_CHANGE flag. (Each section)
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, &SectionOffset, &ViewSize, ViewUnmap, SEC_NO_CHANGE, Protect);

				// 8. Lock memory. (Each section)
				while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
					ExtendWorkingSet(hProcess);
			}
		}
		// If SectionAlignment is equal to Page size. (0x1000)
		else
		{
			// 2. Create section to remap the image.
			NtCreateSection(&hSection, MAXIMUM_ALLOWED, NULL, &SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);

			// 3. Map view of section.
			NtMapViewOfSection(hSection, CURRENT_PROCESS, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_READWRITE);

			// 4. Copy memory.
			for (SIZE_T j = 0; j < SizeOfImage; j += sizeof(SIZE_T))
				*(SIZE_T*)(ViewBase + j) = *(SIZE_T*)(MappedModule + j);

			// Overwrite the writable section data.
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
				{
					((_NtReadVirtualMemory)APICall(ntdll, 6))(hProcess, (PVOID)(ModuleBase + pSectionHeader[i].VirtualAddress), (PVOID)(ViewBase + pSectionHeader[i].VirtualAddress), SizeOfImage - pSectionHeader[i].VirtualAddress, 0);
					break;
				}
			}

			// RtlUserThreadStart Hook
			if (ModuleBase == (SIZE_T)origin_ntdll)
			{
				SIZE_T offset = (SIZE_T)APICall(ntdll, 20) - (SIZE_T)origin_ntdll;
				BYTE jmp_myRtlUserThreadStart[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, };
				*(SIZE_T*)(jmp_myRtlUserThreadStart + 6) = (SIZE_T)Thread_Callback;
				for (SIZE_T i = 0; i < 14; i++)
					*(BYTE*)(ViewBase + offset + i) = jmp_myRtlUserThreadStart[i];
			}

			// Calculate size to map with PAGE_EXECUTE_READ protection.
			SIZE_T ExecuteSize = 0;
			SIZE_T ReadOnlySize = 0;
			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					ExecuteSize += PADDING(pSectionHeader[i].Misc.VirtualSize, PAGE_SIZE);
				else
				{
					ReadOnlySize = PADDING(pSectionHeader[i].Misc.VirtualSize, PAGE_SIZE);
					ExecuteSize += PAGE_SIZE;
					break;
				}
			}

			// Get options.
			DWORD ExceptFlag = 0;
			GetOptions(ModulePath, NULL, NULL, &ExceptFlag);

			// 5. Unmap the view.
			NtUnmapViewOfSection(CURRENT_PROCESS, ViewBase);

			// 6. Unmap the original image.
			NtUnmapViewOfSection(hProcess, ModuleBase);

			ViewBase = ModuleBase;
			ViewSize = SectionSize.QuadPart;
			
			// Check this module is excepted. (PAGE_EXECUTE_READWRITE)
			if (ExceptFlag & EXCEPT_REBIRTH)
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);

			// This module is not excepted and enough size to remap with PAGE_EXECUTE_READ.
			else if (ExecuteSize + ReadOnlySize >= AllocationGranularity && ExecuteSize + ReadOnlySize >= PADDING(ExecuteSize, AllocationGranularity))
			{
				// 7. Remap with SEC_NO_CHANGE flag and PAGE_EXECUTE_READ. (.text + .rdata section)
				ViewSize = PADDING(ExecuteSize, AllocationGranularity);
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READ);
				while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
					ExtendWorkingSet(hProcess);

				// 7. Remap with PAGE_READWRITE. (writable section)
				SectionOffset.QuadPart = ViewSize;
				ViewBase = ModuleBase + ViewSize;
				ViewSize = SizeOfImage - ViewSize;
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, &SectionOffset, &ViewSize, ViewUnmap, NULL, PAGE_READWRITE);
			}

			// This module is not excepted but too small size to remap with PAGE_EXECUTE_READ.
			else
				NtMapViewOfSection(hSection, hProcess, &ViewBase, NULL, NULL, NULL, &ViewSize, ViewUnmap, NULL, PAGE_EXECUTE_WRITECOPY);

			// Restore page protection.
			DWORD OldProtect = 0;
			SIZE_T Size = PAGE_SIZE;
			PVOID Address = (PVOID)ModuleBase;
			((_NtProtectVirtualMemory)APICall(ntdll, 3))(hProcess, &Address, &Size, PAGE_READONLY, &OldProtect);
			for (DWORD i = 0, Protect; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)		Protect = PAGE_EXECUTE_READ;
				else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)	Protect = PAGE_WRITECOPY;
				else																Protect = PAGE_READONLY;
				OldProtect = 0;
				Size = pSectionHeader[i].Misc.VirtualSize;
				Address = (PVOID)(ModuleBase + pSectionHeader[i].VirtualAddress);
				((_NtProtectVirtualMemory)APICall(ntdll, 3))(hProcess, &Address, &Size, Protect, &OldProtect);
			}

			// 8. Lock memory. (.text section)
			ViewBase += PAGE_SIZE;
			while (NtLockVirtualMemory(hProcess, &ViewBase, &LockSize, 1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(hProcess);
		}

		CloseHandle(hSection);

		SIZE_T ImageSize = NULL;
		((_NtFreeVirtualMemory)APICall(ntdll, 27))(CURRENT_PROCESS, (PVOID*)&MappedModule, &ImageSize, MEM_RELEASE);

		printf("[ RemapModule ]  Remapped : %S\n", ModulePath);
	}

	if (proxy_ntdll)
	{
		SIZE_T ImageSize = NULL;
		((_NtFreeVirtualMemory)APICall(ntdll, 27))(CURRENT_PROCESS, (PVOID*)&proxy_ntdll, &ImageSize, MEM_RELEASE);
	}
}