
#include "Windows.h"
#include "Stdio.h"
#include "AES.h"

#define PADDING(p, size)	p / size * size + (p % size ? size : 0)

int main(void)
{
	BYTE IV[16]	= { 0x88, 0xCA, 0x61, 0xAF, 0xFF, 0x05, 0x0D, 0x96, 0x8F, 0x12, 0x27, 0xD0, 0x8B, 0xEC, 0x25, 0xE8 };
	BYTE Key[16]	= { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

	HANDLE hSourceFile = CreateFile(L"RebirthGuard.ini", GENERIC_READ | GENERIC_WRITE, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hSourceFile != INVALID_HANDLE_VALUE)
	{
		DWORD Length = PADDING(GetFileSize(hSourceFile, 0), 16);

		BYTE* Source = (BYTE*)malloc(Length);
		BYTE* Buffer = (BYTE*)malloc(Length);

		if (ReadFile(hSourceFile, Source, Length, NULL, NULL))
		{
			if (strstr((CHAR*)Source, "[ RebirthGuard ]"))	
				AES_CBC_Encrypt(Buffer, Source, Length, Key, IV);

			else											
				AES_CBC_Decrypt(Buffer, Source, Length, Key, IV);

			SetFilePointer(hSourceFile, 0, 0, 0);
			WriteFile(hSourceFile, Buffer, Length, NULL, NULL);
		}

		CloseHandle(hSourceFile);
		memset(Source, 0, Length);
		memset(Buffer, 0, Length);
		free(Source);
		free(Buffer);
	}

	return 0;
}
