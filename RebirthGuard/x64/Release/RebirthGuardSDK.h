
/********************************************
*											*
*			RebirthGuard - chztbby			*
*											*
********************************************/

#include "Windows.h"

#pragma comment(linker, "/RELEASE")
#pragma comment(linker, "/ALIGN:0x10000")

VOID	TLS_Callback	(PVOID, DWORD, PVOID);
VOID	MemCheck		(HANDLE hProcess, DWORD pid);
VOID	CRCCheck		(VOID);

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_TLS_CALLBACK")
EXTERN_C
#pragma const_seg (".CRT$XLB")
const

PIMAGE_TLS_CALLBACK _TLS_CALLBACK = TLS_Callback;
#pragma data_seg ()
#pragma const_seg ()

