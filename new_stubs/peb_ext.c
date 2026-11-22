/*
 * peb_ext.c - KernelEx-NG: NT process environment block (PEB) for Windows 10 binaries on Windows 98 SE.
 *
 * Windows NT code reads the PEB directly: `mov reg, fs:[30h]` then fields such as
 * ProcessParameters (+0x10), ProcessHeap (+0x18), NtGlobalFlag (+0x68), OS version (+0xA4..).
 * On Windows 9x fs:[30h] is the process database (PDB98) instead; e.g. PDB+0x10 is
 * TerminationStatus (0x103 = STILL_ACTIVE), so ucrtbase's thread start dereferenced 0x10B.
 *
 * fs:[30h] cannot simply be re-pointed: KernelEx itself (get_pdb() = `mov eax, fs:30h`) and
 * Win98 KERNEL32 (AllocConsole reads TDB->tib.pProcess) depend on it. Instead every module that
 * targets Windows NT 6+ (OptionalHeader.MajorOperatingSystemVersion or MajorSubsystemVersion >= 6)
 * is patched once, before its code runs:
 *     64 A1 30 00 00 00        mov eax, fs:[30h]      ->  E8 <kex_peb_eax>  90
 *     64 8B xx 30 00 00 00     mov r32, fs:[30h]      ->  E8 <kex_peb_r32>  90 90
 *     64 A1 18 00 00 00 8B 40 30   mov eax, fs:[18h] ; mov eax, [eax+30h]  ->  E8 <kex_peb_eax> 90 x4
 *     (and the same with any register, when both instructions use the same one; clang emits only
 *      this two-step TEB->PEB form, so it is the one Chromium uses)
 * The helpers load the address of the emulated PEB below (no flags touched, like the original mov).
 * Rare forms (cmp/push with fs:[30h], fs:[18h] -> [other reg+30h]) are counted, not patched yet.
 *
 * Who calls the patcher: every api-ms-win-*.dll shell in its DLL_PROCESS_ATTACH (it runs before the
 * DllMain of any module that imports it), plus kexnt's own process attach.
 * Win98 modules, KernelEx and anything in the shared arena (>= 0x80000000) are never touched.
 */
#include "kexnt_common.h"
#include <tlhelp32.h>
#include <string.h>

/* ---- emulated x86 PEB / PEB_LDR_DATA / RTL_USER_PROCESS_PARAMETERS (Windows 10 layouts) ---- */
static BYTE  g_peb[0x480]    __attribute__((aligned(16)));
static BYTE  g_ldr[0x30]     __attribute__((aligned(8)));
static BYTE  g_params[0x400] __attribute__((aligned(8)));
static HANDLE g_heaps[1];
static BYTE  g_loaderlock[0x18] __attribute__((aligned(8)));
void kex_crashlog_arm(void);
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c: KEXCRASH.LOG for NT 6+ programs */
static CRITICAL_SECTION g_peb_lock;
void *kex_peb_ptr = g_peb;                /* read by the helpers */

#define P8(b, o)  (*(BYTE  *)((b) + (o)))
#define P16(b, o) (*(WORD  *)((b) + (o)))
#define P32(b, o) (*(DWORD *)((b) + (o)))
#define PPTR(b, o) (*(void **)((b) + (o)))

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } KUS;

static void set_us(BYTE *at, const char *a)
{
    KUS *u = (KUS *)at;
    int n = a ? MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0) : 0;
    WCHAR *w;
    if (n <= 0) { u->Length = u->MaximumLength = 0; u->Buffer = NULL; return; }
    w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
    if (!w) return;
    MultiByteToWideChar(CP_ACP, 0, a, -1, w, n);
    u->Buffer = w;
    u->Length = (USHORT)((n - 1) * sizeof(WCHAR));
    u->MaximumLength = (USHORT)(n * sizeof(WCHAR));
}

static WCHAR *wide_environment(void)
{
    char *e = GetEnvironmentStrings(), *p;
    int len;
    WCHAR *w;
    if (!e) return NULL;
    for (p = e; *p; p += strlen(p) + 1) ;
    len = (int)(p - e) + 1;                               /* include the final NUL */
    w = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR));
    if (w && !MultiByteToWideChar(CP_ACP, 0, e, len, w, len)) { HeapFree(GetProcessHeap(), 0, w); w = NULL; }
    FreeEnvironmentStringsA(e);
    return w;
}

static void build_peb(void)
{
    char buf[MAX_PATH];
    STARTUPINFOA si;
    HMODULE exe = GetModuleHandleA(NULL);
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)((BYTE *)exe + ((IMAGE_DOS_HEADER *)exe)->e_lfanew);
    int i;

    /* PEB_LDR_DATA: valid, empty module lists (self-linked) */
    P32(g_ldr, 0x00) = sizeof(g_ldr);
    P8(g_ldr, 0x04) = 1;                                  /* Initialized */
    for (i = 0x0C; i <= 0x1C; i += 8) { PPTR(g_ldr, i) = g_ldr + i; PPTR(g_ldr, i + 4) = g_ldr + i; }

    /* RTL_USER_PROCESS_PARAMETERS (normalized: pointers, not offsets) */
    P32(g_params, 0x00) = sizeof(g_params);
    P32(g_params, 0x04) = sizeof(g_params);
    P32(g_params, 0x08) = 0x00000001;                     /* RTL_USER_PROC_PARAMS_NORMALIZED */
    PPTR(g_params, 0x18) = GetStdHandle(STD_INPUT_HANDLE);
    PPTR(g_params, 0x1C) = GetStdHandle(STD_OUTPUT_HANDLE);
    PPTR(g_params, 0x20) = GetStdHandle(STD_ERROR_HANDLE);
    if (GetCurrentDirectoryA(sizeof(buf), buf)) set_us(g_params + 0x24, buf);   /* CurrentDirectory.DosPath */
    if (GetModuleFileNameA(NULL, buf, sizeof(buf))) set_us(g_params + 0x38, buf); /* ImagePathName */
    set_us(g_params + 0x40, GetCommandLineA());                                  /* CommandLine */
    PPTR(g_params, 0x48) = wide_environment();                                    /* Environment */
    si.cb = sizeof(si); GetStartupInfoA(&si);
    P32(g_params, 0x4C) = si.dwX;  P32(g_params, 0x50) = si.dwY;
    P32(g_params, 0x54) = si.dwXSize; P32(g_params, 0x58) = si.dwYSize;
    P32(g_params, 0x5C) = si.dwXCountChars; P32(g_params, 0x60) = si.dwYCountChars;
    P32(g_params, 0x64) = si.dwFillAttribute; P32(g_params, 0x68) = si.dwFlags;
    P32(g_params, 0x6C) = si.wShowWindow;
    set_us(g_params + 0x70, si.lpTitle);                                          /* WindowTitle */
    set_us(g_params + 0x78, si.lpDesktop);                                        /* DesktopInfo */

    /* PEB */
    P8(g_peb, 0x02) = (BYTE)(IsDebuggerPresent() ? 1 : 0);
    PPTR(g_peb, 0x08) = exe;                              /* ImageBaseAddress */
    PPTR(g_peb, 0x0C) = g_ldr;                            /* Ldr */
    PPTR(g_peb, 0x10) = g_params;                         /* ProcessParameters */
    PPTR(g_peb, 0x18) = GetProcessHeap();                 /* ProcessHeap (== PDB98 DefaultHeap) */
    InitializeCriticalSection(&g_peb_lock);
    PPTR(g_peb, 0x1C) = &g_peb_lock;                      /* FastPebLock */
    /* LoaderLock (+0xA0): an NT-layout RTL_CRITICAL_SECTION that is never held (LockCount -1, owner 0).
     * Chromium's "is the loader lock held" test reads LoaderLock->OwningThread (+0x0C). */
    P32(g_loaderlock, 0x04) = 0xFFFFFFFF;
    PPTR(g_peb, 0xA0) = g_loaderlock;
    P32(g_peb, 0x64) = 1;                                 /* NumberOfProcessors */
    P32(g_peb, 0x68) = 0;                                 /* NtGlobalFlag */
    *(LONGLONG *)(g_peb + 0x70) = -25920000000000LL;      /* CriticalSectionTimeout: 30 days */
    P32(g_peb, 0x78) = 0x100000; P32(g_peb, 0x7C) = 0x2000; /* HeapSegmentReserve/Commit */
    P32(g_peb, 0x80) = 0x10000;  P32(g_peb, 0x84) = 0x1000; /* HeapDeCommit thresholds */
    g_heaps[0] = GetProcessHeap();
    P32(g_peb, 0x88) = 1; P32(g_peb, 0x8C) = 16; PPTR(g_peb, 0x90) = g_heaps;
    /* OSMajorVersion/OSMinorVersion/OSBuildNumber: set by ensure_built() from the process's profile */
    P16(g_peb, 0xAE) = 0;                                 /* OSCSDVersion */
    P32(g_peb, 0xB0) = VER_PLATFORM_WIN32_NT;             /* OSPlatformId */
    P32(g_peb, 0xB4) = nt->OptionalHeader.Subsystem;
    P32(g_peb, 0xB8) = nt->OptionalHeader.MajorSubsystemVersion;
    P32(g_peb, 0xBC) = nt->OptionalHeader.MinorSubsystemVersion;
    P32(g_peb, 0xC0) = 1;                                 /* ActiveProcessAffinityMask */
    P32(g_peb, 0x1D4) = 0;                                /* SessionId */
}

/* ---- helpers called from patched code: load the PEB address into one register ---- */
__asm__(
    ".text\n"
    "_kex_peb_r0: movl _kex_peb_ptr, %eax\n\tret\n"
    "_kex_peb_r1: movl _kex_peb_ptr, %ecx\n\tret\n"
    "_kex_peb_r2: movl _kex_peb_ptr, %edx\n\tret\n"
    "_kex_peb_r3: movl _kex_peb_ptr, %ebx\n\tret\n"
    "_kex_peb_r4: movl _kex_peb_ptr, %esp\n\tret\n"    /* never generated by compilers; kept for the table */
    "_kex_peb_r5: movl _kex_peb_ptr, %ebp\n\tret\n"
    "_kex_peb_r6: movl _kex_peb_ptr, %esi\n\tret\n"
    "_kex_peb_r7: movl _kex_peb_ptr, %edi\n\tret\n");
extern void kex_peb_r0(void), kex_peb_r1(void), kex_peb_r2(void), kex_peb_r3(void),
            kex_peb_r5(void), kex_peb_r6(void), kex_peb_r7(void);
static void (*const g_helper[8])(void) = { kex_peb_r0, kex_peb_r1, kex_peb_r2, kex_peb_r3,
                                            NULL, kex_peb_r5, kex_peb_r6, kex_peb_r7 };

/* ---- patcher + PEB loader lists ---- */
typedef struct {
    BYTE *base;
    char  name[MAX_PATH];
    BYTE *ldr;                      /* LDR_DATA_TABLE_ENTRY (0xB0 bytes), never freed (readers may hold it) */
    BOOL  seen;
} mod_rec;
#define MAX_MODS 512
static mod_rec g_mods[MAX_MODS];
static int     g_nmods;
static CRITICAL_SECTION g_patch_cs;
static BOOL  g_ready, g_built;
static DWORD g_stat_modules, g_stat_sites, g_stat_unhandled;
static DWORD g_ver_major = 10, g_ver_minor = 0, g_ver_build = 19044;   /* until a profile says otherwise */
static BOOL g_ver_set;                                                     /* a profile reported an NT version */

static BOOL eligible(BYTE *base, const char *name)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt;
    if ((ULONG_PTR)base >= 0x80000000UL) return FALSE;     /* shared arena: Win98/KernelEx system code */
    {   /* no C runtime in kexnt: compare with kernel32 only */
        char pre[12];
        lstrcpynA(pre, name, sizeof(pre));            /* first 11 chars */
        if (!lstrcmpiA(pre, "api-ms-win-") || !lstrcmpiA(name, "kexnt.dll") || !lstrcmpiA(name, "kexver.dll"))
            return FALSE;
    }
    if (IsBadReadPtr(dos, sizeof(*dos)) || dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (IsBadReadPtr(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    return nt->OptionalHeader.MajorOperatingSystemVersion >= 6 || nt->OptionalHeader.MajorSubsystemVersion >= 6;
}

/* Write a few bytes of code. Only the page(s) under the bytes are made writable, and only for the write:
 * the first version made each whole code section writable while it scanned - for chrome.dll that is one
 * VirtualProtect over 246 MB of image pages (all turned copy-on-write at once), issued from inside chrome.dll's
 * DllMain when it delay-loads bcryptprimitives, and Windows 98 blue-screened (0028:BFF713DB / BFF94649). */
static BOOL g_patch_big;                  /* the module being patched is larger than 256 MB (big-file hook) */
/* Sites in images larger than 256 MB (chrome.dll) are NOT written: every page-permission change on such an image
 * through Windows 98 (VirtualProtect, WriteProcessMemory: both VWIN32) blue-screens - 0028:BFF94649 "called from
 * VWIN32(05)+3243" (2026-11-02 00:00, the WriteProcessMemory attempt), and VMM _PageModifyPermissions leaves its
 * code pages read-only. Instead the site is remembered; the code then reads the 9x process database where it
 * expects the PEB. When a field read through it faults (PDB+10h = TerminationStatus 103h, so
 * ProcessParameters->x reads near 0), the exception handler below redoes it: the site's register gets the
 * emulated PEB and execution continues right after the site. Reads that do not fault get 9x values
 * (chrome.dll site 1eac6555 reads PDB+68h, the process critical section's owner - normally 0, like
 * NtGlobalFlag's bit it tests). */
#define MAX_LAZY 64
static struct { BYTE *site; BYTE *resume; int reg; } g_lazy[MAX_LAZY];
static volatile LONG g_nlazy;
static LONG CALLBACK lazy_handler(PEXCEPTION_POINTERS ep);
PVOID KEXAPI kex_AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn);
static void lazy_site(BYTE *site, int len, int reg)
{
    static LONG registered;
    LONG i;
    if (!InterlockedExchange(&registered, 1)) kex_AddVectoredExceptionHandler(1, lazy_handler);
    i = InterlockedIncrement(&g_nlazy) - 1;
    if (i >= MAX_LAZY) { g_nlazy = MAX_LAZY; return; }
    g_lazy[i].site = site; g_lazy[i].resume = site + len; g_lazy[i].reg = reg;
    kex_trace("peb patch: site left as is (big image), handled on fault", (DWORD)(ULONG_PTR)site, len, reg, 0);
}
static LONG CALLBACK lazy_handler(PEXCEPTION_POINTERS ep)
{
    PEXCEPTION_RECORD r = ep->ExceptionRecord; PCONTEXT c = ep->ContextRecord; LONG i, n = g_nlazy;
    BYTE *eip = (BYTE *)(ULONG_PTR)c->Eip;
    /* Windows 98 reports some of these faults with address FFFFFFFF (build 32: YouTube, thread start in ucrt's
     * begin-thread policy check, PDB+10h = 103h -> [10Bh]): accept that too - the EIP check below is the real test */
    if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION || r->NumberParameters < 2 ||
        (r->ExceptionInformation[1] >= 0x10000 && r->ExceptionInformation[1] != 0xFFFFFFFFUL)) return EXCEPTION_CONTINUE_SEARCH;
    if (n > MAX_LAZY) n = MAX_LAZY;
    for (i = 0; i < n; i++) {
        if (eip < g_lazy[i].resume || eip > g_lazy[i].resume + 24) continue;
        switch (g_lazy[i].reg) {
        case 0: c->Eax = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        case 1: c->Ecx = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        case 2: c->Edx = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        case 3: c->Ebx = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        case 5: c->Ebp = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        case 6: c->Esi = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        case 7: c->Edi = (DWORD)(ULONG_PTR)kex_peb_ptr; break;
        default: return EXCEPTION_CONTINUE_SEARCH;
        }
        c->Eip = (DWORD)(ULONG_PTR)g_lazy[i].resume;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* build 131: the SPLIT two-step form - mov r, fs:[18h] ; (a few instructions not touching r) ; mov r, [r+30h].
 * Supermium 150's XP wrapper pwrp_k32.dll does it once in its DllMain (10001471 .. 10001483, reading the OS version
 * and ProcessParameters->ImagePathName); unpatched it read the Windows 98 process database and called wcsstr on a
 * pointer from it (access violation, chrome.exe exit -1). The TEB load must stay (r is used as the TEB in between),
 * and "mov r, [r+30h]" is only 3 bytes - too short for a call. Found by decoding forward from the fs:[18h] load
 * (simple, common instructions only; anything else, a jump, or any other use of r ends the search), so r is not
 * read or written in between: the PEB is loaded at the TEB load and the [r+30h] read becomes NOPs. */
/* length of a ModRM operand (ModRM byte + SIB + displacement), or 0 */
static int modrm_len(const BYTE *m)
{
    int mod = m[0] >> 6, rm = m[0] & 7, n = 1;
    if (mod == 3) return 1;
    if (rm == 4) { n++; if (mod == 0 && (m[1] & 7) == 5) n += 4; }
    else if (mod == 0 && rm == 5) return 5;
    if (mod == 1) n += 1; else if (mod == 2) n += 4;
    return n;
}
/* Does this ModRM operand use register r (as reg, as a register operand, or in the address)? */
static BOOL modrm_uses(const BYTE *m, int r)
{
    int mod = m[0] >> 6, rm = m[0] & 7;
    if (((m[0] >> 3) & 7) == r) return TRUE;
    if (mod == 3) return rm == r;
    if (rm == 4) { int base = m[1] & 7, idx = (m[1] >> 3) & 7; return (base == r && !(mod == 0 && base == 5)) || (idx == r && idx != 4); }
    return rm == r && !(mod == 0 && rm == 5);
}
/* p = first byte after "mov r, fs:[18h]". Returns the address of "mov r, [r+30h]" or NULL. */
static BYTE *find_split(BYTE *p, BYTE *end, int r)
{
    int k;
    for (k = 0; k < 8 && p + 3 <= end; k++) {
        BYTE op = p[0]; int len;
        if (op == 0x8B && (p[1] >> 6) == 1 && (p[1] & 7) == r && ((p[1] >> 3) & 7) == r && p[2] == 0x30) return p;
        if (op == 0x68) len = 5;                                         /* push imm32 */
        else if (op == 0x6A) len = 2;                                    /* push imm8 */
        else if ((op >= 0x50 && op <= 0x57) && (op & 7) != r) len = 1;   /* push other register */
        else if ((op == 0xA1 || op == 0xA3) && r != 0) len = 5;          /* mov eax, [abs] / mov [abs], eax */
        else if (op >= 0xB8 && op <= 0xBF && (op & 7) != r) len = 5;     /* mov other, imm32 */
        else if (op == 0x8B || op == 0x89 || op == 0x8D || op == 0x3B || op == 0x39 || op == 0x85 || op == 0x33 ||
                 op == 0x31 || op == 0x03 || op == 0x01 || op == 0x2B || op == 0x29 || op == 0x23 || op == 0x21 ||
                 op == 0x0B || op == 0x09) {
            if (modrm_uses(p + 1, r)) return NULL;
            len = 1 + modrm_len(p + 1);
        } else if (op == 0x83 || op == 0xC7 || op == 0x81) {
            if (modrm_uses(p + 1, r)) return NULL;
            len = 1 + modrm_len(p + 1) + (op == 0x83 ? 1 : 4);
        } else return NULL;                                              /* anything else: stop */
        p += len;
    }
    return NULL;
}
static void write_code(BYTE *p, const BYTE *code, int n)
{
    DWORD old = 0, o2; int k; BOOL ok;
    kex_trace("peb patch: site", (DWORD)(ULONG_PTR)p, n, 0, 0);
    ok = VirtualProtect(p, n, PAGE_EXECUTE_READWRITE, &old);
    if (!ok) return;
    for (k = 0; k < n; k++) p[k] = code[k];
    VirtualProtect(p, n, old, &o2);
}

static void patch_module(BYTE *base)
{
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    IMAGE_SECTION_HEADER *s = IMAGE_FIRST_SECTION(nt);
    int i;
    g_patch_big = nt->OptionalHeader.SizeOfImage > 0x0FFFF000UL;
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, s++) {
        BYTE *p, *end;
        DWORD size = s->Misc.VirtualSize ? s->Misc.VirtualSize : s->SizeOfRawData;
        if (!(s->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE)) || size < 7) continue;
        p = base + s->VirtualAddress;
        end = p + size - 6;
        for (; p < end; p++) {
            int reg, len;
            if (p[0] != 0x64) continue;
            /* two-step form (clang/Chromium):  mov r, fs:[18h] ; mov r, [r+30h]   (TEB->ProcessEnvironmentBlock)
             * Only when both use the same register, so no other register loses its TEB value. */
            {
                int src = -1, l1 = 0;
                if (p[1] == 0xA1 && *(DWORD *)(p + 2) == 0x18) { src = 0; l1 = 6; }
                else if (p[1] == 0x8B && (p[2] & 0xC7) == 0x05 && *(DWORD *)(p + 3) == 0x18) { src = (p[2] >> 3) & 7; l1 = 7; }
                if (src >= 0 && src != 4 && !g_patch_big && p + l1 + 3 <= end + 6 &&
                    !(p[l1] == 0x8B && (p[l1 + 1] >> 6) == 1 && (p[l1 + 1] & 7) == src && p[l1 + 2] == 0x30)) {
                    BYTE *t = find_split(p + l1, end + 6, src);       /* build 131: split form */
                    if (t && g_helper[src]) {
                        /* nothing in between uses r: load the PEB into r where the TEB was loaded, and the
                         * "mov r, [r+30h]" becomes NOPs (an INT3 there was tried first: on Windows 98 the
                         * breakpoint never reached the vectored handler and the program ran on with the PDB) */
                        BYTE code[8], nops[3] = { 0x90, 0x90, 0x90 }; int k;
                        code[0] = 0xE8; *(DWORD *)(code + 1) = (DWORD)((BYTE *)g_helper[src] - (p + 5));
                        for (k = 5; k < l1; k++) code[k] = 0x90;
                        write_code(p, code, l1); write_code(t, nops, 3);
                        kex_trace("peb patch: split TEB->PEB read moved to the TEB load", (DWORD)(ULONG_PTR)p, (DWORD)(ULONG_PTR)t, src, 0);
                        { BYTE chk[8]; memcpy(chk, p, 8); kex_trace("peb patch: split bytes now", *(DWORD *)chk, *(DWORD *)(chk + 4), *(DWORD *)t, 0); }
                        g_stat_sites++; p += l1 - 1; continue;
                    }
                }
                if (src >= 0 && p + l1 + 3 <= end + 6) {
                    BYTE *q = p + l1;
                    if (q[0] == 0x8B && (q[1] >> 6) == 1 && (q[1] & 7) == src && src != 4 && q[2] == 0x30) {
                        int dst = (q[1] >> 3) & 7, k;
                        BYTE code[16];
                        if (dst != src || !g_helper[dst]) { g_stat_unhandled++; continue; }
                        if (g_patch_big) { lazy_site(p, l1 + 3, dst); g_stat_sites++; p += l1 + 2; continue; }
                        code[0] = 0xE8;
                        *(DWORD *)(code + 1) = (DWORD)((BYTE *)g_helper[dst] - (p + 5));
                        for (k = 5; k < l1 + 3; k++) code[k] = 0x90;
                        write_code(p, code, l1 + 3);
                        g_stat_sites++;
                        p += l1 + 2;
                        continue;
                    }
                }
            }
            if (p[1] == 0xA1 && *(DWORD *)(p + 2) == 0x30) { reg = 0; len = 6; }
            else if (p[1] == 0x8B && (p[2] & 0xC7) == 0x05 && p + 7 <= end + 6 && *(DWORD *)(p + 3) == 0x30)
                { reg = (p[2] >> 3) & 7; len = 7; }
            else {
                if ((p[1] == 0xFF && p[2] == 0x35 && *(DWORD *)(p + 3) == 0x30) ||
                    (p[1] == 0x39 && (p[2] & 0xC7) == 0x05 && *(DWORD *)(p + 3) == 0x30))
                    g_stat_unhandled++;
                continue;
            }
            if (!g_helper[reg]) { g_stat_unhandled++; continue; }
            if (g_patch_big) { lazy_site(p, len, reg); g_stat_sites++; p += len - 1; continue; }
            {
                BYTE code[8];
                code[0] = 0xE8;
                *(DWORD *)(code + 1) = (DWORD)((BYTE *)g_helper[reg] - (p + 5));
                code[5] = 0x90; code[6] = 0x90;
                write_code(p, code, len);
            }
            g_stat_sites++;
            p += len - 1;
        }
    }

    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
}

/* LIST_ENTRY helpers on raw memory */
static void list_tail(BYTE *head, BYTE *e)
{
    BYTE *last = *(BYTE **)(head + 4);
    *(BYTE **)(e + 0) = head; *(BYTE **)(e + 4) = last;
    *(BYTE **)(last + 0) = e; *(BYTE **)(head + 4) = e;
}
static void list_head(BYTE *head, BYTE *e)
{
    BYTE *first = *(BYTE **)head;
    *(BYTE **)(e + 0) = first; *(BYTE **)(e + 4) = head;
    *(BYTE **)(first + 4) = e; *(BYTE **)head = e;
}
static void list_unlink(BYTE *e)
{
    BYTE *f = *(BYTE **)e, *b = *(BYTE **)(e + 4);
    *(BYTE **)(b + 0) = f; *(BYTE **)(f + 4) = b;
    *(BYTE **)(e + 0) = *(BYTE **)(e + 4) = e;
}

/* LDR_DATA_TABLE_ENTRY (x86 Windows 10): links 0/8/10h, DllBase 18h, EntryPoint 1Ch, SizeOfImage 20h,
 * FullDllName 24h, BaseDllName 2Ch, Flags 34h, LoadCount 38h, TlsIndex 3Ah, HashLinks 3Ch, TimeDateStamp 44h */
static BYTE *make_ldr_entry(BYTE *base, DWORD size, const char *full, const char *name, BOOL is_exe)
{
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    BYTE *e = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0xB0);
    if (!e) return NULL;
    PPTR(e, 0x18) = base;
    PPTR(e, 0x1C) = nt->OptionalHeader.AddressOfEntryPoint ? base + nt->OptionalHeader.AddressOfEntryPoint : NULL;
    P32(e, 0x20) = size ? size : nt->OptionalHeader.SizeOfImage;
    set_us(e + 0x24, full);
    set_us(e + 0x2C, name);
    P32(e, 0x34) = (is_exe ? 0 : 0x00000004 /* LDRP_IMAGE_DLL */) | 0x00004000 /* ENTRY_PROCESSED */;
    P16(e, 0x38) = 0xFFFF;                    /* "static" load count, as Windows reports for most modules */
    PPTR(e, 0x3C) = e + 0x3C; PPTR(e, 0x40) = e + 0x3C;  /* HashLinks: empty */
    P32(e, 0x44) = nt->FileHeader.TimeDateStamp;
    if (is_exe) {
        list_head(g_ldr + 0x0C, e + 0x00);   /* the exe is first in load and memory order */
        list_head(g_ldr + 0x14, e + 0x08);
        PPTR(e, 0x10) = e + 0x10; PPTR(e, 0x14) = e + 0x10;   /* exe is not in initialization order */
    } else {
        list_tail(g_ldr + 0x0C, e + 0x00);
        list_tail(g_ldr + 0x14, e + 0x08);
        list_tail(g_ldr + 0x1C, e + 0x10);
    }
    return e;
}

/* One pass: patch new NT6+ modules, keep PEB->Ldr in sync with the loaded module set. */
static void scan_modules(void)
{
    HANDLE snap;
    MODULEENTRY32 me;
    HMODULE exe = GetModuleHandleA(NULL);
    int i;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    for (i = 0; i < g_nmods; i++) g_mods[i].seen = FALSE;
    me.dwSize = sizeof(me);
    if (Module32First(snap, &me)) do {
        BYTE *base = me.modBaseAddr;
        mod_rec *r = NULL;
        for (i = 0; i < g_nmods; i++)
            if (g_mods[i].base == base && !lstrcmpiA(g_mods[i].name, me.szExePath)) { r = &g_mods[i]; break; }
        if (r) { r->seen = TRUE; continue; }
        if (g_nmods >= MAX_MODS) continue;
        r = &g_mods[g_nmods++];
        r->base = base; r->seen = TRUE;
        lstrcpynA(r->name, me.szExePath, MAX_PATH);
        if (eligible(base, me.szModule)) {
            DWORD before = g_stat_sites;
            kex_crashlog_arm();
            kex_trace("peb patch: scanning", (DWORD)(ULONG_PTR)base, me.modBaseSize, 0, 0);
            patch_module(base); g_stat_modules++;
            kex_trace("peb patch", (DWORD)(ULONG_PTR)base, g_stat_sites - before, g_stat_unhandled, 0);
        }
        r->ldr = make_ldr_entry(base, me.modBaseSize, me.szExePath, me.szModule, base == (BYTE *)exe);
    } while (Module32Next(snap, &me));
    CloseHandle(snap);
    /* modules that went away: unlink from the Ldr lists, forget them (entry memory is kept) */
    for (i = 0; i < g_nmods; ) {
        if (g_mods[i].seen) { i++; continue; }
        if (g_mods[i].ldr) {
            list_unlink(g_mods[i].ldr + 0x00); list_unlink(g_mods[i].ldr + 0x08); list_unlink(g_mods[i].ldr + 0x10);
        }
        g_mods[i] = g_mods[--g_nmods];
    }
}

static void ensure_built(void)
{
    if (!g_built) {
        build_peb();
        P32(g_peb, 0xA4) = g_ver_major; P32(g_peb, 0xA8) = g_ver_minor; P16(g_peb, 0xAC) = (WORD)g_ver_build;
        g_built = TRUE;
    }
}

/* Patch every eligible module currently loaded in this process and refresh PEB->Ldr.
 * Called by every api-ms shell's DllMain and after LoadLibrary* (see loader_ext.c). */
VOID KEXAPI kex_KexPatchNtModules(void)
{
    DWORD le = GetLastError();
    if (!g_ready) {
        /* build 131: an api-ms shell loaded into a Windows 98 program (the MSVC runtime of K-Lite's VSFilter looks up
         * FlsAlloc in api-ms-win-core-fibers-l1-1-1 while regsvr32 registers it): those exports go straight to kexnt,
         * not through the gate, so kexnt must start up now */
        void kex_full_init(void); kex_full_init();
        if (!g_ready) { SetLastError(le); return; }
    }
    { void kex_ent_ensure(void); kex_ent_ensure(); }   /* build 132: later DLLs patched before their DllMain too */
    EnterCriticalSection(&g_patch_cs);
    ensure_built();                  /* lazily: never during KernelEx's api-library init */
    kex_trace("peb: module scan", g_nmods, 0, 0, 0);
    scan_modules();
    kex_trace("peb: module scan done", g_nmods, g_stat_sites, 0, 0);
    LeaveCriticalSection(&g_patch_cs);
    SetLastError(le);
}

/* The api-ms shells pass what GetVersionEx reports to this process (its KernelEx profile), so the PEB
 * OS version agrees with the APIs. Non-NT answers (default 9x mode) leave the default 10.0.19044. */
VOID KEXAPI kex_KexSetNtVersion(DWORD major, DWORD minor, DWORD build)
{
    if (!g_ready || major < 5) return;
    EnterCriticalSection(&g_patch_cs);
    g_ver_major = major; g_ver_minor = minor; g_ver_build = build & 0xFFFF; g_ver_set = TRUE;
    if (g_built) { P32(g_peb, 0xA4) = major; P32(g_peb, 0xA8) = minor; P16(g_peb, 0xAC) = (WORD)(build & 0xFFFF); }
    LeaveCriticalSection(&g_patch_cs);
}

BOOL kex_peb_active(void) { return g_built; }

/* The NT version this process's KernelEx profile reports, once an api-ms shell passed it (else FALSE). */
BOOL kex_profile_nt_version(PDWORD major, PDWORD minor, PDWORD build)
{
    if (!g_ver_set) return FALSE;
    *major = g_ver_major; *minor = g_ver_minor; *build = g_ver_build;
    return TRUE;
}

/* For tests/diagnostics: emulated PEB address and patch counters. */
PVOID KEXAPI kex_KexGetNtPeb(PDWORD modules, PDWORD sites, PDWORD unhandled)
{
    if (g_ready) { EnterCriticalSection(&g_patch_cs); ensure_built(); LeaveCriticalSection(&g_patch_cs); }
    if (modules) *modules = g_stat_modules;
    if (sites) *sites = g_stat_sites;
    if (unhandled) *unhandled = g_stat_unhandled;
    return g_peb;
}

BOOL kex_peb_init(void)
{
    InitializeCriticalSection(&g_patch_cs);
    g_ready = TRUE;
    return TRUE;
}
