/*
 * msvcrt_ext.c - KernelEx-NG: the Windows Vista/7 additions to MSVCRT.DLL that Windows 10 system DLLs
 * import (2026-11-02, for the user's own DWrite.dll / TextShaping.dll). Windows 98 SE ships MSVCRT 6.
 * Routed under MSVCRT (kexnt_targets.txt); cdecl, so they are listed in kexnt_cdecl.txt rather than
 * exported by decoration. Written from the public documentation of each function.
 *
 *   - the "_s" string/memory functions and _snprintf_s & co. (on top of MSVCRT 6 _vsnprintf)
 *   - _libm_sse2_*_precise: the SSE2 math entry points (argument/result in XMM0) -> MSVCRT 6 x87 math
 *   - _ftol2 -> _ftol, operator delete[] -> operator delete, exception(const char *const &, int)
 *   - __CxxFrameHandler3: the VC8+ C++ exception tables (magic 0x19930522) handed to MSVCRT 6's
 *     __CxxFrameHandler as a copy marked 0x19930520 - the fields up to the IP-to-state map are the same
 *   - _except_handler4_common: the SEH4 scope tables of /GS code (__try/__except/__finally)
 */
#include "kexnt_common.h"
#include <stdarg.h>

#define K_EINVAL 22
#define K_ERANGE 34
#define K_STRUNCATE 80
#define K_TRUNCATE ((size_t)-1)

static FARPROC crtp(const char *n)
{
    static HMODULE h;
    if (!h) { h = GetModuleHandleA("MSVCRT.DLL"); if (!h) h = LoadLibraryA("MSVCRT.DLL"); }
    return h ? GetProcAddress(h, n) : NULL;
}

/* ---------------------------------------------------------------- strings and memory */
size_t __cdecl kex_c_strnlen(const char *s, size_t n) { size_t i = 0; if (!s) return 0; while (i < n && s[i]) i++; return i; }
size_t __cdecl kex_c_wcsnlen(const WCHAR *s, size_t n) { size_t i = 0; if (!s) return 0; while (i < n && s[i]) i++; return i; }

int __cdecl kex_c_memcpy_s(void *d, size_t dsz, const void *s, size_t n)
{
    if (!n) return 0;
    if (!d) return K_EINVAL;
    if (!s || dsz < n) { memset(d, 0, dsz); return s ? K_ERANGE : K_EINVAL; }
    memcpy(d, s, n);
    return 0;
}
int __cdecl kex_c_memmove_s(void *d, size_t dsz, const void *s, size_t n)
{
    if (!n) return 0;
    if (!d || !s) return K_EINVAL;
    if (dsz < n) return K_ERANGE;
    memmove(d, s, n);
    return 0;
}
int __cdecl kex_c_strcpy_s(char *d, size_t size, const char *s)
{
    size_t n;
    if (!d || !size) return K_EINVAL;
    if (!s) { d[0] = 0; return K_EINVAL; }
    n = strlen(s);
    if (n >= size) { d[0] = 0; return K_ERANGE; }
    memcpy(d, s, n + 1);
    return 0;
}
int __cdecl kex_c_strcat_s(char *d, size_t size, const char *s)
{
    size_t dl, sl;
    if (!d || !size) return K_EINVAL;
    if (!s) { d[0] = 0; return K_EINVAL; }
    dl = kex_c_strnlen(d, size);
    if (dl == size) { d[0] = 0; return K_EINVAL; }
    sl = strlen(s);
    if (dl + sl >= size) { d[0] = 0; return K_ERANGE; }
    memcpy(d + dl, s, sl + 1);
    return 0;
}
int __cdecl kex_c_strncpy_s(char *d, size_t size, const char *s, size_t count)
{
    size_t n;
    if (!count && !d && !size) return 0;
    if (!d || !size) return K_EINVAL;
    if (!count) { d[0] = 0; return 0; }
    if (!s) { d[0] = 0; return K_EINVAL; }
    if (count == K_TRUNCATE) {
        n = kex_c_strnlen(s, size);
        if (n == size) { memcpy(d, s, size - 1); d[size - 1] = 0; return K_STRUNCATE; }
    } else {
        n = kex_c_strnlen(s, count);
        if (n >= size) { d[0] = 0; return K_ERANGE; }
    }
    memcpy(d, s, n); d[n] = 0;
    return 0;
}

static int xtow_s(unsigned long v, int neg, WCHAR *buf, size_t size, int radix)
{
    WCHAR t[40]; int n = 0; size_t need;
    if (!buf || !size) return K_EINVAL;
    if (radix < 2 || radix > 36) { buf[0] = 0; return K_EINVAL; }
    do { int dg = (int)(v % (unsigned)radix); t[n++] = (WCHAR)(dg < 10 ? '0' + dg : 'a' + dg - 10); v /= (unsigned)radix; } while (v);
    need = (size_t)n + (neg ? 1 : 0) + 1;
    if (need > size) { buf[0] = 0; return K_ERANGE; }
    if (neg) *buf++ = '-';
    while (n) *buf++ = t[--n];
    *buf = 0;
    return 0;
}
int __cdecl kex_c_itow_s(int v, WCHAR *buf, size_t size, int radix)
{ return (radix == 10 && v < 0) ? xtow_s(0UL - (unsigned long)v, 1, buf, size, radix) : xtow_s((unsigned long)v, 0, buf, size, radix); }
int __cdecl kex_c_ultow_s(unsigned long v, WCHAR *buf, size_t size, int radix) { return xtow_s(v, 0, buf, size, radix); }

/* ---------------------------------------------------------------- printf family */
typedef int (__cdecl *T_VSNP)(char *, size_t, const char *, va_list);
int __cdecl kex_c_vsnprintf_s(char *buf, size_t size, size_t count, const char *fmt, va_list ap)
{
    static T_VSNP vsnp; size_t max; int r;
    if (!vsnp) vsnp = (T_VSNP)(void *)crtp("_vsnprintf");
    if (!buf || !size || !fmt || !vsnp) { if (buf && size) buf[0] = 0; return -1; }
    max = (count == K_TRUNCATE || count >= size) ? size - 1 : count;
    r = vsnp(buf, max, fmt, ap);
    if (r < 0 || (size_t)r > max) {                           /* did not fit */
        if (count == K_TRUNCATE || count < size) { buf[max] = 0; return -1; }
        buf[0] = 0; return -1;
    }
    buf[r] = 0;
    return r;
}
int __cdecl kex_c_snprintf_s(char *buf, size_t size, size_t count, const char *fmt, ...)
{ va_list ap; int r; va_start(ap, fmt); r = kex_c_vsnprintf_s(buf, size, count, fmt, ap); va_end(ap); return r; }
int __cdecl kex_c_vsprintf_s(char *buf, size_t size, const char *fmt, va_list ap)
{ return kex_c_vsnprintf_s(buf, size, size, fmt, ap); }
int __cdecl kex_c_sprintf_s(char *buf, size_t size, const char *fmt, ...)
{ va_list ap; int r; va_start(ap, fmt); r = kex_c_vsnprintf_s(buf, size, size, fmt, ap); va_end(ap); return r; }

/* ---------------------------------------------------------------- C++ exception tables */
typedef struct { DWORD magic, maxState; PVOID pUnwindMap; DWORD nTryBlocks; PVOID pTryBlockMap; DWORD nIPMap; PVOID pIPtoState; } FI6;
#define NFI 1024
static struct { const DWORD *orig; FI6 copy; } g_fi[NFI];
static volatile LONG g_filock;
void *g_cxxfh;
const void *__cdecl kex_cxx_funcinfo(const DWORD *fi)
{
    DWORD h, i; const void *r = fi;
    if (!g_cxxfh) g_cxxfh = (void *)crtp("__CxxFrameHandler");
    if (!fi || fi[0] <= 0x19930520UL) return fi;
    h = ((DWORD)(ULONG_PTR)fi >> 3) & (NFI - 1);
    kex_spin_acquire((volatile LONG *)&g_filock);
    for (i = 0; i < NFI; i++, h = (h + 1) & (NFI - 1)) {
        if (g_fi[h].orig == fi) { r = &g_fi[h].copy; break; }
        if (!g_fi[h].orig) {
            memcpy(&g_fi[h].copy, fi, sizeof(FI6));
            g_fi[h].copy.magic = 0x19930520UL;
            g_fi[h].orig = fi;
            r = &g_fi[h].copy;
            break;
        }
    }
    g_filock = 0;
    return r;
}

/* lazily resolved MSVCRT 6 entry points for the assembly stubs below */
void *g_ftol, *g_sscanf, *g_delete, *g_excctor, *g_log, *g_log10, *g_exp, *g_pow;
void *__cdecl kex_crt_resolve(int which)
{
    static const char *const names[] = { "_ftol", "sscanf", "??3@YAXPAX@Z", "??0exception@@QAE@XZ", "log", "log10", "exp", "pow" };
    void **slots[] = { &g_ftol, &g_sscanf, &g_delete, &g_excctor, &g_log, &g_log10, &g_exp, &g_pow };
    if (!*slots[which]) *slots[which] = (void *)crtp(names[which]);
    return *slots[which];
}

__asm__(
    ".text\n"
    /* __CxxFrameHandler3: EAX = FuncInfo */
    ".globl _kex_c_CxxFrameHandler3\n_kex_c_CxxFrameHandler3:\n"
    "  pushl %eax\n  call _kex_cxx_funcinfo\n  addl $4, %esp\n  jmp *_g_cxxfh\n"
    /* _ftol2: ST0 -> EDX:EAX (same contract as MSVCRT 6 _ftol) */
    ".globl _kex_c_ftol2\n_kex_c_ftol2:\n"
    "  movl _g_ftol, %eax\n  testl %eax, %eax\n  jnz 1f\n  pushl $0\n  call _kex_crt_resolve\n  addl $4, %esp\n1: jmp *%eax\n"
    /* sscanf_s -> sscanf (callers here pass numeric formats only) */
    ".globl _kex_c_sscanf_s\n_kex_c_sscanf_s:\n"
    "  movl _g_sscanf, %eax\n  testl %eax, %eax\n  jnz 1f\n  pushl $1\n  call _kex_crt_resolve\n  addl $4, %esp\n1: jmp *%eax\n"
    /* operator delete[] -> operator delete */
    ".globl _kex_c_delete_arr\n_kex_c_delete_arr:\n"
    "  movl _g_delete, %eax\n  testl %eax, %eax\n  jnz 1f\n  pushl $2\n  call _kex_crt_resolve\n  addl $4, %esp\n1: jmp *%eax\n"
    /* exception::exception(char const * const &, int) - thiscall, keeps the pointer (no copy) */
    ".globl _kex_c_exc_ctor_noalloc\n_kex_c_exc_ctor_noalloc:\n"
    "  pushl %ecx\n  pushl $3\n  call _kex_crt_resolve\n  addl $4, %esp\n  popl %ecx\n"
    "  pushl %ecx\n  call *%eax\n  popl %ecx\n"
    "  movl 4(%esp), %edx\n  movl (%edx), %edx\n  movl %edx, 4(%ecx)\n  movl $0, 8(%ecx)\n  movl %ecx, %eax\n  ret $8\n"
    /* _libm_sse2_*_precise: argument(s) in XMM0 (XMM1), result in XMM0 */
    ".globl _kex_c_libm_sqrt\n_kex_c_libm_sqrt:\n  sqrtsd %xmm0, %xmm0\n  ret\n"
    ".globl _kex_c_libm_log\n_kex_c_libm_log:\n  pushl $4\n  jmp 2f\n"
    ".globl _kex_c_libm_log10\n_kex_c_libm_log10:\n  pushl $5\n  jmp 2f\n"
    ".globl _kex_c_libm_exp\n_kex_c_libm_exp:\n  pushl $6\n"
    "2: call _kex_crt_resolve\n  addl $4, %esp\n"
    "  subl $8, %esp\n  movsd %xmm0, (%esp)\n  call *%eax\n  fstpl (%esp)\n  movsd (%esp), %xmm0\n  addl $8, %esp\n  ret\n"
    ".globl _kex_c_libm_pow\n_kex_c_libm_pow:\n"
    "  pushl $7\n  call _kex_crt_resolve\n  addl $4, %esp\n"
    "  subl $16, %esp\n  movsd %xmm0, (%esp)\n  movsd %xmm1, 8(%esp)\n  call *%eax\n  fstpl (%esp)\n  movsd (%esp), %xmm0\n  addl $16, %esp\n  ret\n"
);

/* ---------------------------------------------------------------- SEH4 (_except_handler4_common) */
typedef struct { DWORD Enclosing; PVOID Filter; PVOID Handler; } EH4REC;
typedef struct { DWORD GSOff, GSXor, EHOff, EHXor; EH4REC r[1]; } EH4SCOPE;
typedef struct { PVOID SavedEsp; PEXCEPTION_POINTERS Ptrs; PVOID Next, Handler; DWORD EncScope; DWORD TryLevel; } EH4FRAME;
#define EH4_TOP 0xFFFFFFFEUL

int __cdecl eh4_call(PVOID fn, DWORD fp);                    /* calls fn with EBP = fp */
void __cdecl eh4_jump(PVOID fn, DWORD fp);                   /* jumps to fn with EBP = fp, never returns */
void __cdecl eh4_unwind(PVOID frame, PEXCEPTION_RECORD rec, PVOID rtlunwind);
__asm__(
    ".text\n"
    "_eh4_call:\n  pushl %ebp\n  pushl %ebx\n  pushl %esi\n  pushl %edi\n"
    "  movl 20(%esp), %eax\n  movl 24(%esp), %ebp\n"
    "  xorl %ebx, %ebx\n  xorl %ecx, %ecx\n  xorl %edx, %edx\n  xorl %esi, %esi\n  xorl %edi, %edi\n"
    "  call *%eax\n  popl %edi\n  popl %esi\n  popl %ebx\n  popl %ebp\n  ret\n"
    "_eh4_jump:\n  movl 4(%esp), %eax\n  movl 8(%esp), %ebp\n"
    "  xorl %ebx, %ebx\n  xorl %ecx, %ecx\n  xorl %edx, %edx\n  xorl %esi, %esi\n  xorl %edi, %edi\n  jmp *%eax\n"
    "_eh4_unwind:\n  pushl %ebp\n  movl %esp, %ebp\n  pushl %ebx\n  pushl %esi\n  pushl %edi\n"
    "  pushl $0\n  pushl 12(%ebp)\n  pushl $1f\n  pushl 8(%ebp)\n  call *16(%ebp)\n"
    "1: popl %edi\n  popl %esi\n  popl %ebx\n  popl %ebp\n  ret\n");

static void eh4_local_unwind(EH4FRAME *f, const EH4SCOPE *st, DWORD target, DWORD fp)
{
    while (f->TryLevel != target && f->TryLevel != EH4_TOP) {
        const EH4REC *r = &st->r[f->TryLevel];
        f->TryLevel = r->Enclosing;
        if (!r->Filter) eh4_call(r->Handler, fp);               /* __finally block */
    }
}
int __cdecl kex_c_except_handler4_common(UINT_PTR *cookie, PVOID check, PEXCEPTION_RECORD rec, PVOID est,
                                         PCONTEXT ctx, PVOID disp)
{
    static PVOID rtlunwind;
    EH4FRAME *f = (EH4FRAME *)((BYTE *)est - 8);
    const EH4SCOPE *st = (const EH4SCOPE *)(f->EncScope ^ *cookie);
    DWORD fp = (DWORD)(ULONG_PTR)est + 16, lvl;
    EXCEPTION_POINTERS ep;
    (void)check; (void)disp;
    if (rec->ExceptionFlags & 6) {                            /* unwinding */
        if (f->TryLevel != EH4_TOP) eh4_local_unwind(f, st, EH4_TOP, fp);
        return ExceptionContinueSearch;
    }
    ep.ExceptionRecord = rec; ep.ContextRecord = ctx;
    f->Ptrs = &ep;
    for (lvl = f->TryLevel; lvl != EH4_TOP; ) {
        const EH4REC *r = &st->r[lvl];
        if (r->Filter) {
            int v = eh4_call(r->Filter, fp);
            if (v < 0) return ExceptionContinueExecution;
            if (v > 0) {
                if (!rtlunwind) rtlunwind = (PVOID)kex_sysproc("KERNEL32.DLL", "RtlUnwind");
                eh4_unwind(est, rec, rtlunwind);
                if (f->TryLevel != lvl) eh4_local_unwind(f, st, lvl, fp);
                f->TryLevel = r->Enclosing;
                eh4_jump(r->Handler, fp);
            }
        }
        lvl = r->Enclosing;
    }
    return ExceptionContinueSearch;
}
