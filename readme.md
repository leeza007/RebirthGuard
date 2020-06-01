# RebirthGuard

## The Windows EXE Runtime Protection Library (x64)


RebirthGuard is a Windows User-level protection library written on C.

This library is based on *__Section remapping__* technique.

In this project, *__Rebirth__* means *__Section remap__* and *__Force page protection__*.

Developed using Windows 10 version 1909 / Visual Studio Community 2017.


## Capabilites:
* __Module remapping__
* __Process policy__
* __File integrity check__
* __Thread filtering__
* __Memory status check__
* __CRC check__
* __Anti-DLL Injection__
* __Anti-Debugging__
* __Exception handling__


## How to use:
1. Set RebirthGuard Options in *__Settings.h__*
2. Complie RebirthGuard.
3. Include *__RebirthGuardSDK.h__* and *__RebirthGuard.lib__* in your project.
4. Add linker option : *__/RELEASE__*
5. Compile your project.

## Example :
```C
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


## References
https://github.com/changeofpace/Self-Remapping-Code

## Sample Test 2
https://github.com/TheFearlessHobbit/Titan-Voyager-Custom-Game-Engine
