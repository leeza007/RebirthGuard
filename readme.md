# RebirthGuard

## Windows EXE Runtime Protection Library (x64)

RebirthGuard is a Windows User-level protection library written on C.

This library is based on *__Section remapping__* and *__Manual mapping__* technique.

In this project, *__Rebirth__* means *__Section remap__* and *__Force page protection__*.

Developed using Windows 10 version 1909 / Visual Studio Community 2017.

## :bulb: Motive
PUBG Anti-cheat : Xenuine 

## :page_facing_up: Capabilites:
* __Module remapping__ (Force page protection)
* __Process policy__
* __File integrity check__
* __Thread filtering__
* __Memory check__
* __CRC check__ (Hide from debugger)
* __Anti-DLL Injection__
* __Anti-Debugging__
* __Exception handling__
* __Whitelist__


## :wrench: How to use:
1. Set RebirthGuard Options in `Settings.h`
2. Complie RebirthGuard.
3. Include `RebirthGuardSDK.h` and `RebirthGuard.lib` in your project.
4. Add linker option : `/RELEASE` (If `FILE_CHECK` option is enabled)
5. Compile your project.

## :memo: Example :
```CPP
#include <Windows.h>
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
```


## :mag: References
* [Self-Remapping-Code](https://github.com/changeofpace/Self-Remapping-Code)

## :pencil2: Sample Test 2
* [Titan-Voyager-Custom-Game-Engine](https://github.com/TheFearlessHobbit/Titan-Voyager-Custom-Game-Engine)
