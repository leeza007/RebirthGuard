
#include "Engine.h"
#include "RebirthGuardSDK.h"
#pragma comment (lib, "RebirthGuard.lib")

void ddd()
{
	while (1)
	{
		Sleep(1000);
		MemInfoCheck(GetCurrentProcess(), GetCurrentProcessId());
		CRCCheck();
	}
}

int main(int argc, char* argv[])
{
	CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ddd, 0, 0, 0);

	Engine engine;
	engine.Run();
	return 0;
} 