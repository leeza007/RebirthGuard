
#include "Engine.h"
#include "RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

void CRCThread()
{
	while (1)
	{
		Sleep(3000);
		MemCheck(GetCurrentProcess());
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