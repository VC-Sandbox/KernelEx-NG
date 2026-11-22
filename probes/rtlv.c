/* rtlv.c - RTLV.EXE <out>: RtlGetVersion (GetProcAddress on ntdll) and GetVersionExW as this program sees them */
#include <windows.h>
#include <stdio.h>
typedef LONG (WINAPI *T_RGV)(OSVERSIONINFOW *);
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "w"); HMODULE n = GetModuleHandleA("ntdll"); T_RGV r = n ? (T_RGV)GetProcAddress(n, "RtlGetVersion") : NULL;
    OSVERSIONINFOW v = { sizeof(v) }, w = { sizeof(w) };
    fprintf(o, "ntdll %p RtlGetVersion %p\n", n, r);
    if (r) { LONG s = r(&v); fprintf(o, "  RtlGetVersion %08lx -> %lu.%lu.%lu\n", s, v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber); }
    GetVersionExW(&w); fprintf(o, "GetVersionExW %lu.%lu.%lu\n", w.dwMajorVersion, w.dwMinorVersion, w.dwBuildNumber);
    fclose(o); return 0;
}
