/* ver4.c - VER4.EXE <out>: GetVersion / GetVersionExA / GetVersionExW as a Windows 9x (subsystem 4.0) program sees
 * them - checks which KernelEx setting a program (or the child of one) gets. */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argc > 1 ? argv[1] : "C:\\VER4.TXT", "w"); OSVERSIONINFOA a = { sizeof(a) }; OSVERSIONINFOW w = { sizeof(w) }; DWORD v = GetVersion();
    char me[MAX_PATH]; GetModuleFileNameA(NULL, me, MAX_PATH);
    GetVersionExA(&a); GetVersionExW(&w);
    fprintf(o, "%s\nGetVersion %08lx\nGetVersionExA %lu.%lu.%lu platform %lu\nGetVersionExW %lu.%lu.%lu\n", me, v, a.dwMajorVersion, a.dwMinorVersion,
            a.dwBuildNumber, a.dwPlatformId, w.dwMajorVersion, w.dwMinorVersion, w.dwBuildNumber);
    fclose(o); return 0;
}
