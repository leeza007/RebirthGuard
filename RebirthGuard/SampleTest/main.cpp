
#include <stdio.h>
#include <RebirthGuardSDK.h>
#pragma comment (lib, "RebirthGuard.lib")

int main(void)
{
	printf("RebirthGuard Test\n\n");

	for (int i = 0;; i++)
	{
		printf("%d\n", i);

		MemInfoCheck(GetCurrentProcess(), GetCurrentProcessId());

		CRCCheck();

		Sleep(3000);
	}

	return 0;
}
