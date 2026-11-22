/*
 * fwdload_pic.c - KernelEx-NG build 132: forwarders whose target DLL is not loaded yet (bundled-DLL rule, part 2).
 *
 * A program's own api-ms-win-crt-*.dll forward to ucrtbase ("terminate=ucrtbase.terminate"), which nothing imports
 * directly. NT loads the target while resolving the forwarder. KernelEx's forwarder branch (KernelEx.dll 0xBFA05236)
 * only calls GetModuleHandleA, so Mypal stopped at start: "The VCRUNTIME140.DLL file is linked to missing export
 * API-MS-WIN-CRT-RUNTIME-L1-1-0.DLL:terminate".
 * Measured (2026-11-21): loading the target THERE - with LoadLibraryA, and also the way KernelEx maps its own API
 * libraries (MRLoadTree + its ModuleInitializer) - deadlocks Windows 98 during a new process's import resolution
 * (whole system idle in HLT). GetProcAddress at that point is fine (probe fwe.c: a static import through Mypal's
 * forwarder DLL resolved to kexnt at process start). So the target is loaded LATER, on first use:
 *   kxpic_fwd_gmh  (replaces KernelEx's GetModuleHandleA call): target not loaded and the forwarding DLL built for
 *                  NT 5+ -> return a marker record (per-process pool) that remembers the module name;
 *   kxpic_fwd_gpa  (our GetProcAddress stub, veh_ext.c): marker -> a 10-byte thunk "push thunk / jmp resolver"
 *                  that remembers module + function; anything else -> GetProcAddress, called from here (no module ->
 *                  KernelEx uses the EXE's configuration, as a direct kernel32 import would);
 *   kxpic_fwd_resolve (first call through a thunk, outside the loader): GetModuleHandleA / LoadLibraryA (normal
 *                  search: the program's folder first) + GetProcAddress, then the thunk becomes "jmp function".
 * Limitation: a forwarded DATA export imported before its target is loaded would get the thunk's address. Microsoft's
 * api-ms-win-crt-* forward 2 data exports (_mbcasemap, __dcrt_initial_narrow_environment); no Mypal module imports
 * them (programs use the __p_ accessor functions).
 *
 * These functions are COPIED into a shared page (they run in every process, also before kexnt is set up), so they
 * must be position independent: no globals, no string literals, no library calls; calls between them are relative.
 * Sections .text$kxpic0 (start marker) .. .text$kxpic2 (end marker); the build fails (check_pic.py) if the linked
 * kexnt.dll has a base relocation in between.
 */
#include <windows.h>

typedef struct fwd_ctx {
    DWORD magic;
    DWORD gmh_iat, gpa_iat;                          /* KernelEx.dll's import slots: GetModuleHandleA, GetProcAddress */
    LPVOID (WINAPI *valloc)(LPVOID, SIZE_T, DWORD, DWORD);
    HMODULE (WINAPI *loadlib)(LPCSTR);
    void *(__cdecl *psget)(int);
    int (__cdecl *psset)(int, void *);
    int ps_slot;                                     /* KernelEx process-storage index of this process's pool */
    BYTE *resolver;                                  /* resolver glue in the shared page */
    volatile LONG markers, thunks, resolved, unresolved, loads;   /* diagnostics (all processes) */
} fwd_ctx;

#define FWD_POOL  0x10000
#define MOD_MAGIC 0x314D584BUL                       /* "KXM1" */
typedef struct { DWORD used; DWORD pad[3]; } fwd_pool;
typedef struct { DWORD magic; char mod[60]; } fwd_mod;
typedef struct { BYTE code[12]; fwd_mod *mod; char fn[1]; } fwd_thunk;

#define PIC __attribute__((section(".text$kxpic1"), used, noinline))

/* start marker: .text$kxpic0 sorts before .text$kxpic1, so the copy starts here */
__attribute__((section(".text$kxpic0"), used, noinline))
void kxpic_section_start(void) { }

static PIC fwd_pool *pool_get(fwd_ctx *c, BOOL make)
{
    fwd_pool *p = (fwd_pool *)c->psget(c->ps_slot);
    if (!p && make) {
        p = (fwd_pool *)c->valloc(NULL, FWD_POOL, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (p) { p->used = sizeof(fwd_pool); c->psset(c->ps_slot, p); }
    }
    return p;
}

static PIC void *pool_alloc(fwd_pool *p, DWORD n)
{
    DWORD at;
    n = (n + 15) & ~15UL;
    at = __sync_fetch_and_add(&p->used, n);
    if (at + n > FWD_POOL) return NULL;
    return (BYTE *)p + at;
}

static PIC DWORD slen(const char *s) { volatile DWORD n = 0; while (s[n]) n++; return n; }

HMODULE WINAPI PIC kxpic_fwd_gmh(fwd_ctx *c, LPCSTR name, const IMAGE_NT_HEADERS32 *fwd)
{
    HMODULE (WINAPI *gmh)(LPCSTR) = *(HMODULE (WINAPI **)(LPCSTR))(ULONG_PTR)c->gmh_iat;
    HMODULE h = gmh(name);
    fwd_pool *p; fwd_mod *m; DWORD i, n;
    if (h || !fwd || fwd->OptionalHeader.MajorSubsystemVersion < 5) return h;
    n = slen(name);
    if (!n || n >= sizeof(m->mod) || !(p = pool_get(c, TRUE)) || !(m = (fwd_mod *)pool_alloc(p, sizeof(fwd_mod)))) return NULL;
    for (i = 0; i <= n; i++) ((volatile char *)m->mod)[i] = name[i];
    m->magic = MOD_MAGIC;
    c->markers++;
    return (HMODULE)m;
}

FARPROC WINAPI PIC kxpic_fwd_gpa(fwd_ctx *c, HMODULE h, LPCSTR name)
{
    FARPROC (WINAPI *gpa)(HMODULE, LPCSTR) = *(FARPROC (WINAPI **)(HMODULE, LPCSTR))(ULONG_PTR)c->gpa_iat;
    fwd_pool *p = pool_get(c, FALSE);
    fwd_mod *m = (fwd_mod *)h; fwd_thunk *t; DWORD i, n; BYTE *k;
    if (!p || (BYTE *)m < (BYTE *)p || (BYTE *)m >= (BYTE *)p + FWD_POOL || m->magic != MOD_MAGIC)
        return gpa(h, name);                       /* called from this page: KernelEx uses the EXE's configuration */
    if ((ULONG_PTR)name < 0x10000) return NULL;     /* forwarder by ordinal: not supported here */
    n = slen(name);
    if (!(t = (fwd_thunk *)pool_alloc(p, sizeof(fwd_thunk) + n))) return NULL;
    for (i = 0; i <= n; i++) ((volatile char *)t->fn)[i] = name[i];
    t->mod = m;
    k = t->code;
    k[0] = 0x68; *(DWORD *)(k + 1) = (DWORD)(ULONG_PTR)t;                         /* push thunk */
    k[5] = 0xE9; *(LONG *)(k + 6) = (LONG)(c->resolver - (k + 10));               /* jmp resolver */
    k[10] = k[11] = 0x90;
    c->thunks++;
    return (FARPROC)t;
}

/* stdcall(ctx, thunk) -> the function; called by the resolver glue with all registers saved */
FARPROC WINAPI PIC kxpic_fwd_resolve(fwd_ctx *c, fwd_thunk *t)
{
    HMODULE (WINAPI *gmh)(LPCSTR) = *(HMODULE (WINAPI **)(LPCSTR))(ULONG_PTR)c->gmh_iat;
    FARPROC (WINAPI *gpa)(HMODULE, LPCSTR) = *(FARPROC (WINAPI **)(HMODULE, LPCSTR))(ULONG_PTR)c->gpa_iat;
    HMODULE h = gmh(t->mod->mod);
    FARPROC f;
    if (!h) { h = c->loadlib(t->mod->mod); if (h) c->loads++; }
    f = h ? gpa(h, t->fn) : NULL;
    if (!f) { c->unresolved++; return NULL; }
    {   ULONGLONG oldv = *(volatile ULONGLONG *)t->code, newv; BYTE nb[8]; DWORD i;
        for (i = 0; i < 8; i++) nb[i] = ((BYTE *)&oldv)[i];
        nb[0] = 0xE9; *(LONG *)(nb + 1) = (LONG)((BYTE *)f - (t->code + 5)); nb[5] = nb[6] = nb[7] = 0x90;
        for (i = 0; i < 8; i++) ((BYTE *)&newv)[i] = nb[i];
        __sync_bool_compare_and_swap((volatile ULONGLONG *)t->code, oldv, newv);
    }
    c->resolved++;
    return f;
}

__attribute__((section(".text$kxpic2"), used, noinline))
void kxpic_fwd_end(void) { }
