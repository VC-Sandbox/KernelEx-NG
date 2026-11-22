/* gmh.c - GMH.EXE <out>: GetModuleHandle("ntdll") in a process that does not import NTDLL (NT 5.1 program) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); HMODULE w, a, l;
    SetLastError(0); w = GetModuleHandleW(L"ntdll"); fprintf(o, "GetModuleHandleW(ntdll) %p err %lu\n", w, GetLastError());
    SetLastError(0); a = GetModuleHandleA("ntdll.dll"); fprintf(o, "GetModuleHandleA(ntdll.dll) %p err %lu\n", a, GetLastError());
    l = LoadLibraryA("ntdll.dll"); fprintf(o, "LoadLibrary(ntdll.dll) %p\n", l);
    if (l) fprintf(o, "RtlGetVersion %p  RtlNtStatusToDosError %p\n", GetProcAddress(l, "RtlGetVersion"), GetProcAddress(l, "RtlNtStatusToDosError"));
    fclose(o); return 0;
}
