#include <windows.h>
#include <stdio.h>
typedef DWORD (WINAPI *T_FA)(PVOID);
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w");
    T_FA f = (T_FA)(void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "FlsAlloc");
    fprintf(o, "FlsAlloc %p\n", (void *)f); fflush(o);
    if (f) { DWORD i = f(NULL); fprintf(o, "-> %lu err %lu\n", i, GetLastError()); }
    fclose(o); return 0;
}
