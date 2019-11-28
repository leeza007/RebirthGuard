
/********************************************
*											*
*	RebirthGuard/function.cpp - chztbby		*
*											*
********************************************/

#include "RebirthGuard.h"

DWORD Size = 0;

//-------------------------------------------------------
//	Get options and list of module to except.
//-------------------------------------------------------
VOID GetOptions(CONST WCHAR* ModulePath, DWORD* OptionFlag, CHAR* KillFlag, DWORD* ExceptFlag)
{
	// Read .ini file.
	if (Size == 0)
	{
		HANDLE hFile = CreateFile(IniPath, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
			Detected(CURRENT_PROCESS, NULL, FileMissing, (PVOID)0, (PVOID)0);
		Size = PADDING(GetFileSize(hFile, NULL), 16);
		CloseHandle(hFile);
	}

	// Decryption
	CHAR* File = (CHAR*)malloc(Size);
	DecryptFileToMem((BYTE*)File);

	// Check the file is successfully decrypted.
	if (!strstr(File, OptionStr[0]))
		Detected(CURRENT_PROCESS, NULL, FileString, (PVOID)0, (PVOID)0);

	// Check console option.
	if (OptionFlag && strstr(File, OptionStr[10]))
		*OptionFlag &= ~CONSOLE;

	// Check main options.
	if (OptionFlag)
	{
		for (DWORD i = 1; i <= 9; i++)
		{
			if ((strstr(File, OptionStr[i]) - 9)[0] == 'D')
			{
				DWORD Flag = 1;
				for (DWORD j = 1; j < i; j++, Flag *= 2);
				*OptionFlag &= ~Flag;
			}
		}
	}

	// Check sub options.
	if (KillFlag)
	{
		for (DWORD i = 4; i <= 9; i++)
			if (strstr(KillFlag, OptionStr[i]))	memcpy(KillFlag, strstr(File, OptionStr[i]) + strlen(OptionStr[i]) + 3, 4);
	}

	// Check excepted modules.
	if (ModulePath)
	{
		CHAR* Except_File_Integrity	= (CHAR*)malloc(Size + 1);
		CHAR* Except_Rebirth		= (CHAR*)malloc(Size + 1);

		LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;

		while (ModuleList.DllBase)
		{
			if (wcsstr(ModulePath, ModuleList.FullDllName.Buffer))
			{
				WideCharToMultiByte(CP_ACP, 0, ModuleList.FullDllName.Buffer, -1, Except_File_Integrity, (INT)wcslen(ModulePath), NULL, NULL);
				WideCharToMultiByte(CP_ACP, 0, ModuleList.FullDllName.Buffer, -1, Except_Rebirth,		 (INT)wcslen(ModulePath), NULL, NULL);

				strcat_s(Except_File_Integrity,	Size, OptionStr[11]);
				strcat_s(Except_Rebirth,		Size, OptionStr[11]);

				if (strstr(File, Except_File_Integrity))	*ExceptFlag |= EXCEPT_FILE_INTEGRITY;
				if (strstr(File, Except_Rebirth))			*ExceptFlag |= EXCEPT_REBIRTH;

				break;
			}

			ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);
		}

		free(Except_File_Integrity);
		free(Except_Rebirth);
	}

	memset(File, 0, Size);
	free(File);
}

//-------------------------------------------------------
//	Get module's name by InMemoryOrderModuleList index.
//-------------------------------------------------------
WCHAR* GetModuleName(DWORD order)
{
	LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;
	for(DWORD i = 0; i < order; i++)
		ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);

	return ModuleList.FullDllName.Buffer;
}

//-------------------------------------------------------
//	GetModuleHandle.
//-------------------------------------------------------
HMODULE myGetModuleHandle(LPCWSTR lpModuleName)
{
	LDR_DATA_TABLE_ENTRY ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(*reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)))->ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList.Flink;

	if (lpModuleName == NULL)
		return *(HMODULE*)((SIZE_T)&ModuleList + 0x20);

	while (ModuleList.DllBase)
	{
		WCHAR a[MAX_PATH];
		WCHAR b[MAX_PATH];
		wcscpy_s(a, MAX_PATH, lpModuleName);
		wcscpy_s(b, MAX_PATH, ModuleList.FullDllName.Buffer);
		_wcsupr_s(a, wcsnlen_s(a, MAX_PATH) + 1);
		_wcsupr_s(b, wcsnlen_s(b, MAX_PATH) + 1);
		if (wcsstr(a, b))
			return *(HMODULE*)((SIZE_T)&ModuleList + 0x20);

		ModuleList = *(LDR_DATA_TABLE_ENTRY*)(*(SIZE_T*)&ModuleList);
	}

	return NULL;
}

//-------------------------------------------------------
//	GetProcAddress.
//-------------------------------------------------------
FARPROC myGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
	PIMAGE_NT_HEADERS		pnh = (PIMAGE_NT_HEADERS)((SIZE_T)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	PIMAGE_DATA_DIRECTORY	pdd = &pnh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY ped = (PIMAGE_EXPORT_DIRECTORY)((SIZE_T)hModule + pdd->VirtualAddress);

	PDWORD	pFuncTbl = (PDWORD)((SIZE_T)hModule + ped->AddressOfFunctions);
	PWORD	pOrdnTbl = (PWORD)((SIZE_T)hModule + ped->AddressOfNameOrdinals);
	if ((DWORD_PTR)lpProcName <= 0xFFFF)
	{
		WORD wOrdinal = (WORD)IMAGE_ORDINAL((DWORD_PTR)lpProcName);
		wOrdinal -= (WORD)ped->Base;
		if (wOrdinal < ped->NumberOfFunctions)
			return (FARPROC)((SIZE_T)hModule + pFuncTbl[wOrdinal]);
	}
	else
	{
		PDWORD pFuncNameTbl = (PDWORD)((SIZE_T)hModule + ped->AddressOfNames);
		for (DWORD	dwFuncIdx = 0; dwFuncIdx < ped->NumberOfNames; dwFuncIdx++)
		{
			PCSTR pFuncName = (PCSTR)((SIZE_T)hModule + pFuncNameTbl[dwFuncIdx]);
			if (!strcmp(lpProcName, pFuncName))
			{
				WORD wOrdinal = pOrdnTbl[dwFuncIdx];
				return (FARPROC)((SIZE_T)hModule + pFuncTbl[wOrdinal]);
			}
		}
	}
	return NULL;
}

//-------------------------------------------------------
//	Call native API by encrypted data.
//-------------------------------------------------------
FARPROC APICall(DWORD Module, SIZE_T API)
{
	if (Module > 3) 
		Detected(CURRENT_PROCESS, NULL, APICALL_Invalid_Module, (PVOID)(SIZE_T)Module, (PVOID)0);

	CHAR* APIName = (CHAR*)malloc(100);
	
	DecryptMem(APIName, API);

	FARPROC result = myGetProcAddress(myGetModuleHandle(GetModuleName(Module)), APIName);

	free(APIName);

	return result;
}