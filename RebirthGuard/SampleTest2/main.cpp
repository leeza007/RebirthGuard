
#include "Engine.h"
#include "RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

void CRCThread()
{
	while (1)
	{
		Sleep(1000);
		MemCheck(GetCurrentProcess(), GetCurrentProcessId());
		CRCCheck();
	}
}

int main(int argc, char* argv[])
{
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)CRCThread, 0, 0, 0);

	Engine engine;
	engine.Run();
	return 0;
} 