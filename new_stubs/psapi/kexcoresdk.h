/* minimal kexcoresdk.h for building KernelEx psapi.c with MinGW (build 131) */
#pragma once
__declspec(dllimport) PROC kexGetProcAddress(HMODULE hModule, PCSTR lpProcName);
