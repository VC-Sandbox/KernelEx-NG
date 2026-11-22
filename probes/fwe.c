#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
int main(void)
{
    CRITICAL_SECTION cs; FILE *o = fopen("C:\\FWE.TXT", "w");
    MEMORY_BASIC_INFORMATION m; char f[MAX_PATH] = "?"; void *p = (void *)InitializeCriticalSectionEx;
    if (VirtualQuery(p, &m, sizeof(m))) GetModuleFileNameA((HMODULE)m.AllocationBase, f, MAX_PATH);
    fprintf(o, "started; InitializeCriticalSectionEx %p in %s -> %d\n", p, f, InitializeCriticalSectionEx(&cs, 4000, 0));
    fclose(o); return 0;
}
