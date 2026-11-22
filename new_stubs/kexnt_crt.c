/* kexnt_crt.c - the few C library functions kexnt.dll needs, so it links WITHOUT msvcrt.dll.
 *
 * Why: KernelEx initializes api libraries (FLoadTreeNotify on each) BEFORE the program's own DLLs.
 * If kexnt.dll imported msvcrt.dll, msvcrt's DllMain would run during kexnt's init, call TlsAlloc,
 * and get KernelEx's kexbasen TlsAlloc_new before kexbasen's own init has set its TlsLock ->
 * _EnterSysLevel(NULL) page fault in KERNEL32 (seen on Win98 SE, 86Box + VMware, 2026-10-31).
 * kexnt.dll must therefore import only KERNEL32/ADVAPI32 (shared-arena DLLs, never re-routed). */
#include <stddef.h>

size_t strlen(const char *s)
{
    const char *p = s;
    while (*p) p++;
    return (size_t)(p - s);
}

int strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}

char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    do { if (*s == (char)c) last = s; } while (*s++);
    return (char *)last;
}

/* GCC may emit calls to these for struct copies / zero-initialised locals even without a CRT. */
void *memcpy(void *d, const void *s, size_t n)
{
    unsigned char *dp = d; const unsigned char *sp = s;
    while (n--) *dp++ = *sp++;
    return d;
}

void *memmove(void *d, const void *s, size_t n)
{
    unsigned char *dp = d; const unsigned char *sp = s;
    if (dp < sp) while (n--) *dp++ = *sp++;
    else { dp += n; sp += n; while (n--) *--dp = *--sp; }
    return d;
}

void *memset(void *d, int c, size_t n)
{
    unsigned char *dp = d;
    while (n--) *dp++ = (unsigned char)c;
    return d;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = a, *y = b;
    for (; n; n--, x++, y++) if (*x != *y) return *x - *y;
    return 0;
}
