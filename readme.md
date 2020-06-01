# RebirthGuard

## The Windows EXE Runtime Protection Library (x64)


RebirthGuard is a Windows user-level protection library written on C.

This library is based on *__Section remapping__* technique.

In this project, *__Rebirth__* means *__Section remap__* and *__Force page protection__*.

Developed using Windows 10 version 1909 / Visual Studio Community 2017.


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
1. Set RebirthGuard Options in *__Settings.h__*
2. Complie RebirthGuard.
3. Include *__RebirthGuardSDK.h__* and *__RebirthGuard.lib__* in your project.
4. Add linker option : *__/RELEASE__*
5. Compile your project.


## References
https://github.com/changeofpace/Self-Remapping-Code

## Sample Test 2
https://github.com/TheFearlessHobbit/Titan-Voyager-Custom-Game-Engine
