# RebirthGuard

## The Windows EXE Runtime Protection Library (x64)


RebirthGuard is the Windows user-level protection library written on C.

This library is based on *__Section remapping__* technique.

In this project, *__Rebirth__* means *__Section remap__* and *__Force page protection__*.

Developed with Windows 10 version 1909 / Visual Studio Community 2017.


## Capabilites:
* Module remapping
* Process policy
* File integrity check
* Thread filtering
* Memory status check
* CRC check
* Anti-DLL Injection
* Anti-Debugging
* Exception handling


## How to use:
1. Set RebirthGuard Options in *__Setting.h__*
2. Include *__RebirthGuard.h__* and *__RebirthGuard.lib__*
3. Call *__MemInfoCheck__* and *__CRCCheck__* functions when you want.
4. Compile your project.


## References
https://github.com/changeofpace/Self-Remapping-Code

## Sample Test2
https://github.com/TheFearlessHobbit/Titan-Voyager-Custom-Game-Engine
