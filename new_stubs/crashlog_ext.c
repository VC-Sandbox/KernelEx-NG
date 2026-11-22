/*
 * crashlog_ext.c - KernelEx-NG crash log for NT 6+ programs on Windows 98 SE (no debugger needed).
 *
 * Why: under a debugger Win98 hands out debug thunks for system-DLL exports and KernelEx's dynamic
 * GetProcAddress resolution breaks (it finds the caller at a fixed stack offset), so KEXDBG changes what
 * Chromium does. This logger runs inside the process instead: kexnt registers it as the first vectored
 * exception handler the first time it prepares an NT 6+ module (peb_ext.c), and it only observes - it
 * always returns EXCEPTION_CONTINUE_SEARCH, so the normal 9x path (SEH, crash box) is unchanged.
 *
 * Output: <program folder>\KEXCRASH.LOG (appended). Per exception: code, address as module+offset,
 * registers, the EBP frame chain, stack values that point into modules and readable text on the stack
 * (Chromium copies its CHECK / LOG(FATAL) message there before crashing).
 * Logged: breakpoint, illegal/privileged instruction, access violation, divide by zero, stack overflow
 * (short form). Not logged: exceptions inside the shared arena (Win98 system DLLs probe memory with
 * handled faults, e.g. IsBadReadPtr), and nothing after 16 reports per process.
 * No C runtime and no USER32 (kexnt rule): own hex/decimal formatting, KERNEL32 only.
 */
#include "kexnt_common.h"
#include "kexng_build.h"
#define KEXNG_S2(x) #x
#define KEXNG_S1(x) KEXNG_S2(x)
#define KEXNG_BUILD_S KEXNG_S1(KEXNG_BUILD)
#include <tlhelp32.h>

PVOID KEXAPI kex_AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn);

FARPROC kex_prev_impl(const char *dll, const char *name);
static volatile LONG g_reports, g_armed, g_lock;
static LONG g_trace_on;
void kex_prof_report(const char *why);         /* prof_ext.c */
void kex_prof_start(const char *exe_path);          /* KEXTRACE + VxD trace: off unless KexNG\\Trace = 1 (read_trace_setting) */
static char  g_path[MAX_PATH];
static char  g_buf[24 * 1024];
static int   g_len;

/* ---------------------------------------------------------------- tiny formatter */
static void put(const char *s) { while (*s && g_len < (int)sizeof(g_buf) - 2) g_buf[g_len++] = *s++; }
static void putn(const char *s, int n) { while (n-- > 0 && *s && g_len < (int)sizeof(g_buf) - 2) g_buf[g_len++] = *s++; }
static void hex(DWORD v, int digits)
{
    char t[9]; int i;
    for (i = digits - 1; i >= 0; i--) { t[i] = "0123456789abcdef"[v & 15]; v >>= 4; }
    t[digits] = 0; put(t);
}
static void hexmin(DWORD v) { int d = 1; DWORD t = v; while (t >>= 4) d++; hex(v, d); }
static void dec(DWORD v) { char t[12]; int i = 11; t[i] = 0; do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v); put(t + i); }

static BOOL readable(const void *p, DWORD n) { return p && !IsBadReadPtr(p, n); }

/* Win98's VirtualQuery reports every region as MEM_PRIVATE, so a module is recognised by the MZ header
 * at its allocation base (Win98 maps an image as one allocation at its base). */
static BOOL is_image(PVOID base)
{
    const BYTE *b = (const BYTE *)base;
    return b && readable(b, 2) && b[0] == 'M' && b[1] == 'Z';
}

/* "module+offset" if addr lies in a mapped image, else 8 hex digits */
static void where(DWORD a)
{
    MEMORY_BASIC_INFORMATION m; char path[MAX_PATH]; const char *b, *s;
    if (a >= 0x10000 && VirtualQuery((LPCVOID)a, &m, sizeof(m)) && is_image(m.AllocationBase) &&
        GetModuleFileNameA((HMODULE)m.AllocationBase, path, sizeof(path))) {
        for (b = s = path; *s; s++) if (*s == '\\') b = s + 1;
        put(b); put("+"); hexmin(a - (DWORD)m.AllocationBase);
        return;
    }
    hex(a, 8);
}
static BOOL in_module(DWORD a)
{
    MEMORY_BASIC_INFORMATION m;
    return a >= 0x10000 && VirtualQuery((LPCVOID)a, &m, sizeof(m)) && is_image(m.AllocationBase) &&
           m.State == MEM_COMMIT && (m.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                                   PAGE_EXECUTE_WRITECOPY | PAGE_READONLY));
}

static void flush(void)
{
    HANDLE f = CreateFileA(g_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD w;
    if (f != INVALID_HANDLE_VALUE) {
        SetFilePointer(f, 0, NULL, FILE_END);
        WriteFile(f, g_buf, g_len, &w, NULL);
        CloseHandle(f);
    }
    g_len = 0;
}

static const char *code_name(DWORD c)
{
    switch (c) {
    case EXCEPTION_BREAKPOINT: return "breakpoint (int3: CHECK / LOG(FATAL) / __debugbreak)";
    case EXCEPTION_ACCESS_VIOLATION: return "access violation";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal instruction";
    case EXCEPTION_PRIV_INSTRUCTION: return "privileged instruction";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "integer divide by zero";
    case EXCEPTION_STACK_OVERFLOW: return "stack overflow";
    }
    return NULL;
}

static void stack_text(DWORD esp)
{
    const BYTE *b = (const BYTE *)esp; DWORD len = 0x3000, i = 0; int shown = 0;
    while (len && !readable(b, len)) len -= 0x400;               /* stop at the end of the stack */
    put("  text on the stack:\r\n");
    while (i < len && shown < 60) {
        DWORD j = i;
        while (j < len && b[j] >= 32 && b[j] < 127) j++;
        if (j - i >= 6) { put("    +"); hex(i, 4); put(" \""); putn((const char *)b + i, (int)(j - i > 400 ? 400 : j - i)); put("\"\r\n"); shown++; i = j; continue; }
        j = i;
        while (j + 1 < len && b[j] >= 32 && b[j] < 127 && b[j + 1] == 0) j += 2;
        if ((j - i) / 2 >= 6) {
            DWORD k; put("    +"); hex(i, 4); put(" L\"");
            for (k = i; k < j && k < i + 800; k += 2) { char c[2] = { (char)b[k], 0 }; put(c); }
            put("\"\r\n"); shown++; i = j; continue;
        }
        i++;
    }
}

/* build 87: text the stack POINTS to (heap strings: Chromium passes std::u16string / std::string by pointer).
 * The YouTube CHECK (LcidAndFirstDayOfWeek refused: a locale string longer than 85 characters) needs exactly
 * that string, which lives on the heap. Printable UTF-16 runs of 12+ characters and ASCII runs of 20+. */
static void pointed_text(DWORD esp)
{
    const DWORD *s = (const DWORD *)esp; DWORD n = 0x3000 / 4, i, seen[40]; int ns = 0, shown = 0;
    while (n && !readable(s, n * 4)) n -= 0x100;
    put("  text the stack points to:\r\n");
    for (i = 0; i < n && shown < 40; i++) {
        const BYTE *b = (const BYTE *)s[i]; DWORD k, j; int dup = 0;
        if ((DWORD)(ULONG_PTR)b < 0x10000 || (DWORD)(ULONG_PTR)b >= 0xC0000000UL || (((DWORD)(ULONG_PTR)b - esp) < 0x3000)) continue;
        for (k = 0; k < (DWORD)ns; k++) if (seen[k] == (DWORD)(ULONG_PTR)b) dup = 1;
        if (dup || !readable(b, 48)) continue;
        for (j = 0; j + 1 < 1024 && readable(b + j, 2) && b[j] >= 32 && b[j] < 127 && b[j + 1] == 0; j += 2) ;
        if (j / 2 >= 12) {
            DWORD q; put("    [+"); hex(i * 4, 4); put("] ");  hex((DWORD)(ULONG_PTR)b, 8); put(" ("); hex(j / 2, 4); put(" chars) L\"");
            for (q = 0; q < j && q < 1000; q += 2) { char c[2] = { (char)b[q], 0 }; put(c); }
            put("\"\r\n"); shown++; if (ns < 40) seen[ns++] = (DWORD)(ULONG_PTR)b; continue;
        }
        for (j = 0; j < 600 && readable(b + j, 1) && b[j] >= 32 && b[j] < 127; j++) ;
        if (j >= 20) {
            put("    [+"); hex(i * 4, 4); put("] "); hex((DWORD)(ULONG_PTR)b, 8); put(" \""); putn((const char *)b, (int)(j > 400 ? 400 : j)); put("\"\r\n");
            shown++; if (ns < 40) seen[ns++] = (DWORD)(ULONG_PTR)b;
        }
    }
}

/* raw code bytes around an address (for disassembly offline: we do not have every program's binaries) */
static void code_bytes(const char *what, DWORD a, DWORD before, DWORD after)
{
    DWORD s = a - before, i;
    static const char hx[] = "0123456789abcdef";
    put("  code "); put(what); put(" "); where(a); put(" (from -"); hex(before, 2); put("):\r\n");
    for (i = 0; i < before + after; i++) {
        const BYTE *p = (const BYTE *)(s + i);
        char b[4];
        if ((i & 31) == 0) { put("    "); hex(s + i, 8); put(" "); }
        if (!readable(p, 1)) { b[0] = b[1] = '?'; } else { b[0] = hx[*p >> 4]; b[1] = hx[*p & 15]; }
        b[2] = (s + i == a) ? '|' : ' '; b[3] = 0;
        put(b);
        if ((i & 31) == 31 || i + 1 == before + after) put("\r\n");
    }
}

/* Text that code near an address refers to: "push imm32" (68), "mov r32,imm32" (B8-BF), "mov [m],imm32"
 * (C7 05) whose value points at readable text. A MOZ_CRASH / CHECK / NS_DebugBreak passes its message that
 * way, so the reason a program gave up shows up in the log without its binaries. */
static void ref_strings(const char *what, DWORD a, DWORD before, DWORD after)
{
    DWORD i, shown = 0, seen[16]; int ns = 0;
    for (i = 0; i + 5 <= before + after && shown < 8; i++) {
        const BYTE *p = (const BYTE *)(a - before + i); DWORD v, k, len; int dup = 0;
        if (!readable(p, 10)) continue;
        if (p[0] == 0x68 || (p[0] >= 0xB8 && p[0] <= 0xBF)) v = *(const DWORD *)(p + 1);
        else if (p[0] == 0xC7 && p[1] == 0x05) v = *(const DWORD *)(p + 6);
        else continue;
        if (v < 0x10000 || !readable((const void *)v, 8)) continue;
        for (len = 0; len < 300 && readable((const BYTE *)v + len, 1) && ((const BYTE *)v)[len] >= 32 && ((const BYTE *)v)[len] < 127; len++) ;
        if (len < 4 || (len < 300 && readable((const BYTE *)v + len, 1) && ((const BYTE *)v)[len] != 0)) continue;
        for (k = 0; k < (DWORD)ns; k++) if (seen[k] == v) dup = 1;
        if (dup) continue;
        if (ns < 16) seen[ns++] = v;
        if (!shown++) { put("  text used by the code "); put(what); put(":\r\n"); }
        put("    "); hex(v, 8); put(" \""); putn((const char *)v, (int)len); put("\"\r\n");
    }
}


/* build 36: address-space map for out-of-memory reports (Chromium raises E0000008 when an allocation fails; the
 * webstore crash asked for 4 MB with 287 MB of page file free -> address space, not memory, ran out?).
 * Per arena: free total, largest free block, reserved and committed totals; then the 16 largest allocations
 * (allocation base, size, committed, owner module if an image). Only flushes in pieces (24 KB buffer). */
void kex_shm_counts(DWORD v[13]);                      /* shm_ext.c */
BOOL kex_shm_view(int i, DWORD out[10]);
int kex_shm_nviews(void);
DWORD kex_shm_alias_of(DWORD a);
typedef struct { DWORD base, total, commit; } MTOP;
static void top_add(MTOP *top, int max, int *nt, DWORD base, DWORD tot, DWORD com)
{
    int k = -1, j;
    if (!base || !tot) return;
    if (*nt < max) k = (*nt)++;
    else { for (j = 0, k = 0; j < max; j++) if (top[j].total < top[k].total) k = j; if (top[k].total >= tot) k = -1; }
    if (k >= 0) { top[k].base = base; top[k].total = tot; top[k].commit = com; }
}
static void top_sort(MTOP *top, int nt)
{
    int i, j;
    for (i = 0; i < nt; i++) for (j = i + 1; j < nt; j++) if (top[j].total > top[i].total) { MTOP t = top[i]; top[i] = top[j]; top[j] = t; }
}
BOOL kex_shm_section_at(DWORD a, DWORD out[10]);
DWORD kex_shm_dib_at(DWORD a, DWORD n, DWORD *count);
/* build 37: who holds the shared arena. Each shared-arena allocation is put in one class: */
enum { C_IMAGE, C_VIEW, C_ALIAS, C_SEC_OPEN, C_SEC_CLOSED, C_DIB, C_PARTIAL, C_UNKNOWN, C_N };
static const char *c_name[C_N] = {
    "module images", "sections mapped by this process (live kexnt views)", "KEXALIAS second views",
    "sections still open here, not mapped", "sections CLOSED and UNMAPPED here, memory still there",
    "GDI DIB section pixels", "partly committed (heaps, reservations)", "unknown (other processes, drivers, system)" };
static int classify(DWORD base, DWORD tot, DWORD com, DWORD info[11])
{
    DWORD w[10]; int j, nv = kex_shm_nviews(); DWORD c;
    info[10] = 0;
    if (is_image((PVOID)(ULONG_PTR)base)) return C_IMAGE;
    for (j = 0; j < nv; j++) if (kex_shm_view(j, w) && w[0] >= base && w[0] < base + tot) { memcpy(info, w, 40); return C_VIEW; }
    if ((info[0] = kex_shm_alias_of(base)) != 0) return C_ALIAS;
    if (kex_shm_section_at(base, info)) return (LONG)info[1] > 0 ? C_SEC_OPEN : C_SEC_CLOSED;
    if (kex_shm_dib_at(base, tot, &c)) { info[0] = c; return C_DIB; }
    if (com < tot) return C_PARTIAL;
    return C_UNKNOWN;
}
static void put_stack(const DWORD *st) { int j; for (j = 0; j < 6 && st[j]; j++) { put(" "); where(st[j]); } }
static void shm_breakdown(MTOP *stop, int nst)
{
    DWORD v[13], w[10], info[11], csum[C_N], ccnt[C_N], p = 0x80000000UL, cur = 0, tot = 0, com = 0, n = 0, now = GetTickCount();
    int i, j, nv = kex_shm_nviews();
    static struct { DWORD st[6]; DWORD n, bytes; int cls; } g[64]; int ng = 0;
    MEMORY_BASIC_INFORMATION m;
    kex_shm_counts(v);
    put("    kexnt shared memory: "); dec(v[0]); put(" live views ("); dec(v[1] >> 20); put(" MB, "); dec(v[2]); put(" at their own address), ");
    dec(v[3]); put(" aliases ("); dec(v[4] >> 20); put(" MB, "); dec(v[5] >> 10); put(" MB reserved), ");
    dec(v[6]); put(" section handles open\r\n      pagefile sections created "); dec(v[7]); put(", views mapped "); dec(v[8]);
    put(", unmapped "); dec(v[9]); put(", unmaps FAILED "); dec(v[10]); put(", views untracked "); dec(v[11]);
    put(", aliases failed "); dec(v[12]);
    { int kex_shm_refcounted(void); put(", Windows counts views: "); dec((DWORD)kex_shm_refcounted()); }
    put("\r\n");
    /* whole shared arena, one entry per allocation */
    for (i = 0; i < C_N; i++) csum[i] = ccnt[i] = 0;
    for (;;) {
        BOOL more = p < 0xC0000000UL && n < 200000 && VirtualQuery((LPCVOID)p, &m, sizeof(m)) == sizeof(m) && m.RegionSize;
        DWORD ab = more && m.State != MEM_FREE ? (DWORD)(ULONG_PTR)m.AllocationBase : 0;
        if (!more || ab != cur) {
            if (cur && tot) {
                int c = classify(cur, tot, com, info);
                csum[c] += com; ccnt[c]++;
                if (c == C_SEC_OPEN || c == C_SEC_CLOSED || c == C_VIEW) {
                    const DWORD *st = info + 4;
                    for (j = 0; j < ng; j++) if (g[j].cls == c && !memcmp(g[j].st, st, 24)) break;
                    if (j == ng && ng < 64) { memcpy(g[ng].st, st, 24); g[ng].n = 0; g[ng].bytes = 0; g[ng].cls = c; ng++; }
                    if (j < ng) { g[j].n++; g[j].bytes += com; }
                }
            }
            if (!more) break;
            cur = ab; tot = com = 0;
        }
        if (ab) { tot += (DWORD)m.RegionSize; if (m.State == MEM_COMMIT) com += (DWORD)m.RegionSize; }
        p += (DWORD)m.RegionSize; n++;
    }
    put("    shared arena committed memory by owner (MB, allocations):\r\n");
    for (i = 0; i < C_N; i++) { put("      "); dec(csum[i] >> 20); put(" MB  "); dec(ccnt[i]); put("  "); put(c_name[i]); put("\r\n"); }
    flush();
    put("    largest shared allocations (base size-KB committed-KB, what it is):\r\n");
    for (i = 0; i < nst; i++) {
        int c = classify(stop[i].base, stop[i].total, stop[i].commit, info);
        put("      "); hex(stop[i].base, 8); put(" "); dec(stop[i].total >> 10); put(" "); dec(stop[i].commit >> 10); put(" ");
        switch (c) {
        case C_IMAGE: put("image "); where(stop[i].base); break;
        case C_VIEW: put("view x"); dec(info[1]); put(info[2] ? " own-address" : " aliased"); put(" from"); put_stack(info + 4); break;
        case C_ALIAS: put("alias of "); hex(info[0], 8); break;
        case C_SEC_OPEN: case C_SEC_CLOSED:
            put(c == C_SEC_OPEN ? "section OPEN (" : "section CLOSED+unmapped (");
            if (c == C_SEC_OPEN) { dec(info[1]); put(" handles, "); } else { dec((now - info[3]) / 1000); put(" s ago, "); }
            put("made "); dec((now - info[2]) / 1000); put(" s ago) from"); put_stack(info + 4); break;
        case C_DIB: put("DIB pixels ("); dec(info[0]); put(" bitmaps)"); break;
        case C_PARTIAL: put("partly committed"); break;
        default: put("unknown");
        }
        put("\r\n");
    }
    flush();
    for (i = 0; i < ng; i++) for (j = i + 1; j < ng; j++) if (g[j].bytes > g[i].bytes) { char t[sizeof(g[0])]; memcpy(t, &g[i], sizeof(t)); memcpy(&g[i], &g[j], sizeof(t)); memcpy(&g[j], t, sizeof(t)); }
    put("    sections by the code that created/mapped them (class, count, KB, callers):\r\n");
    for (i = 0; i < ng && i < 16; i++) {
        put("      "); put(g[i].cls == C_VIEW ? "mapped " : g[i].cls == C_SEC_OPEN ? "open   " : "CLOSED ");
        dec(g[i].n); put(" x "); dec(g[i].bytes >> 10); put(" KB:"); put_stack(g[i].st); put("\r\n");
    }
    (void)w; (void)nv;
    flush();
}
static void mem_summary(void)
{
    static MTOP top[2][24]; int nt[2] = {0, 0}, i, a;
    static const DWORD lo[2] = { 0x00010000UL, 0x80000000UL }, hi[2] = { 0x80000000UL, 0xC0000000UL };
    static const char *nm[2] = { "private arena (00010000-7FFFFFFF)", "shared arena  (80000000-BFFFFFFF)" };
    ZeroMemory(top, sizeof(top));
    put("  address space:\r\n");
    for (a = 0; a < 2; a++) {
        DWORD p = lo[a], fr = 0, big = 0, res = 0, com = 0, cur_base = 0, cur_tot = 0, cur_com = 0, n = 0;
        MEMORY_BASIC_INFORMATION m;
        while (p < hi[a] && n < 200000 && VirtualQuery((LPCVOID)p, &m, sizeof(m)) == sizeof(m)) {
            DWORD sz = (DWORD)m.RegionSize, ab = (DWORD)(ULONG_PTR)m.AllocationBase;
            if (!sz) break;
            if (p + sz > hi[a] || p + sz < p) sz = hi[a] - p;
            n++;
            if (m.State == MEM_FREE) { fr += sz; if (sz > big) big = sz; ab = 0; }
            else { res += sz; if (m.State == MEM_COMMIT) com += sz; }
            if (ab != cur_base) { top_add(top[a], a ? 24 : 16, &nt[a], cur_base, cur_tot, cur_com); cur_base = ab; cur_tot = 0; cur_com = 0; }
            if (ab) { cur_tot += sz; if (m.State == MEM_COMMIT) cur_com += sz; }
            p += sz;
        }
        top_add(top[a], a ? 24 : 16, &nt[a], cur_base, cur_tot, cur_com);
        put("    "); put(nm[a]); put(": free "); dec(fr >> 20); put(" MB, largest free "); dec(big >> 10);
        put(" KB, reserved "); dec(res >> 20); put(" MB, committed "); dec(com >> 20); put(" MB, "); dec(n); put(" regions\r\n");
    }
    top_sort(top[0], nt[0]); top_sort(top[1], nt[1]);
    put("    largest private allocations (base size-KB committed-KB):\r\n");
    for (i = 0; i < nt[0]; i++) {
        put("      "); hex(top[0][i].base, 8); put(" "); dec(top[0][i].total >> 10); put(" "); dec(top[0][i].commit >> 10);
        if (is_image((PVOID)(ULONG_PTR)top[0][i].base)) { put(" "); where(top[0][i].base); }
        put("\r\n");
    }
    {
        MEMORYSTATUS ms; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms);
        put("    GlobalMemoryStatus: load "); dec(ms.dwMemoryLoad); put("% phys free "); dec((DWORD)(ms.dwAvailPhys >> 10));
        put(" KB, page file free "); dec((DWORD)(ms.dwAvailPageFile >> 20)); put(" MB, virtual free "); dec((DWORD)(ms.dwAvailVirtual >> 20)); put(" MB\r\n");
    }
    flush();
    shm_breakdown(top[1], nt[1]);
}

static DWORD g_lock_owner;

/* One report. kind: "exception" (first chance, from the vectored logger) or "UNHANDLED exception" (it reached
 * the program's unhandled-exception filter: what Chromium's crash reporter saw before it ended the process). */
static void report(PEXCEPTION_POINTERS ep, const char *kind)
{
    PEXCEPTION_RECORD r = ep->ExceptionRecord; PCONTEXT c = ep->ContextRecord;
    const char *name = code_name(r->ExceptionCode);
    DWORD addr = (DWORD)r->ExceptionAddress, i, ebp, *st, me = GetCurrentThreadId();
    int n;
    if (g_lock_owner == me) return;                 /* fault inside our own reporting */
    kex_spin_acquire((volatile LONG *)&g_lock);
    g_lock_owner = me;

    put("=== "); put(kind); put(" "); hex(r->ExceptionCode, 8); put(" "); put(name ? name : "(code)");
    put("  thread "); hex(GetCurrentThreadId(), 8); put("  tick "); dec(GetTickCount()); put("\r\n");
    put("  at "); where(addr);
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && r->NumberParameters >= 2) {
        put(r->ExceptionInformation[0] ? "  writing " : "  reading "); hex(r->ExceptionInformation[1], 8);
    }
    if (r->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION && readable((void *)addr, 1)) {
        /* build 130: Chrome's Opus voice encoder (celt/x86/pitch_avx.c) chooses AVX2 from CPUID alone; Windows 98
         * never switches AVX on (CR4.OSXSAVE), so every VEX-encoded instruction (first byte C4/C5) faults. */
        BYTE b0 = *(BYTE *)addr;
        if (b0 == 0xC4 || b0 == 0xC5)
            put("\r\n  <- an AVX (VEX) instruction: the CPU advertises AVX but Windows 98 cannot run it; hide AVX/FMA from the VM"
                " (VMware .vmx: cpuid.1.ecx = \"--00:----:----:----:---0:----:----:----\") - kextest [CPU] checks it");
    }
    put("\r\n  EAX="); hex(c->Eax, 8); put(" EBX="); hex(c->Ebx, 8); put(" ECX="); hex(c->Ecx, 8);
    put(" EDX="); hex(c->Edx, 8); put(" ESI="); hex(c->Esi, 8); put(" EDI="); hex(c->Edi, 8);
    put("\r\n  EIP="); hex(c->Eip, 8); put(" ESP="); hex(c->Esp, 8); put(" EBP="); hex(c->Ebp, 8);
    put(" EFL="); hex(c->EFlags, 8); put("\r\n");
    {   /* segment registers; a CS other than ours = the fault is in 16-bit code (GDI.EXE/USER.EXE thunks) */
        WORD mycs; __asm__ volatile("mov %%cs, %0" : "=r"(mycs));
        put("  CS="); hex(c->SegCs & 0xFFFF, 4); put(" DS="); hex(c->SegDs & 0xFFFF, 4); put(" SS="); hex(c->SegSs & 0xFFFF, 4);
        put(" ES="); hex(c->SegEs & 0xFFFF, 4); put(" FS="); hex(c->SegFs & 0xFFFF, 4); put(" GS="); hex(c->SegGs & 0xFFFF, 4);
        if ((c->SegCs & 0xFFFF) != mycs) put("  <- not the 32-bit code segment: 16-bit Windows code");
        else if (c->Eip < 0x10000) put("  <- 32-bit code jumped to a bad address (corrupt pointer / return)");
        put("\r\n");
    }
    {   /* 32 bytes at every register that points to readable program memory (2026-11-02: Mypal died in 16-bit
         * GDI inside SelectObject; EDI held the BITMAPINFO of the DIB being selected) */
        static const char *rn[6] = { "EAX", "EBX", "ECX", "EDX", "ESI", "EDI" };
        DWORD rv[6], k, j; rv[0] = c->Eax; rv[1] = c->Ebx; rv[2] = c->Ecx; rv[3] = c->Edx; rv[4] = c->Esi; rv[5] = c->Edi;
        for (k = 0; k < 6; k++) {
            if (rv[k] < 0x10000 || rv[k] >= 0x80000000UL || !readable((void *)rv[k], 32)) continue;
            put("  ["); put(rn[k]); put("]");
            for (j = 0; j < 8; j++) { put(" "); hex(((DWORD *)rv[k])[j], 8); }
            put("\r\n");
        }
    }
    if (readable((void *)c->Esp, 64)) {   /* raw top of stack: a return into garbage leaves its trail here */
        DWORD j, *sp = (DWORD *)c->Esp;
        put("  stack at ESP:");
        for (j = 0; j < 16 && readable(sp + j, 4); j++) { if (j == 8) put("\r\n               "); put(" "); hex(sp[j], 8); }
        put("\r\n");
    }
    if (r->NumberParameters && r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION) {
        DWORD k; put("  parameters:");
        for (k = 0; k < r->NumberParameters && k < 6; k++) { put(" "); hex(r->ExceptionInformation[k], 8); }
        put("\r\n");
    }
    if (r->ExceptionCode == EXCEPTION_STACK_OVERFLOW) {
        /* little stack left: no big work. Walk the EBP chain (static tables only) and print the return addresses
         * that repeat most - a recursion shows up as a few addresses with large counts (2026-11-02, Mypal on
         * YouTube ran out of its 1 MB main-thread stack). */
        static DWORD ra[64], cnt[64]; DWORD e = c->Ebp, frames = 0; int nra = 0, i, k;
        put("  stack: top "); hex(c->Esp, 8); put("\r\n");
        while (frames < 20000 && readable((void *)e, 8)) {
            DWORD *f = (DWORD *)e, a = f[1];
            for (i = 0; i < nra; i++) if (ra[i] == a) { cnt[i]++; break; }
            if (i == nra && nra < 64) { ra[nra] = a; cnt[nra] = 1; nra++; }
            frames++;
            if (f[0] <= e) break;
            e = f[0];
        }
        put("  "); dec(frames); put(" EBP frames; most repeated return addresses:\r\n");
        for (k = 0; k < 12; k++) {
            int b = -1;
            for (i = 0; i < nra; i++) if (cnt[i] && (b < 0 || cnt[i] > cnt[b])) b = i;
            if (b < 0) break;
            put("    "); dec(cnt[b]); put(" x "); where(ra[b]); put("\r\n");
            cnt[b] = 0;
        }
        put("\r\n"); flush(); g_lock_owner = 0; InterlockedExchange((LONG *)&g_lock, 0); return;
    }

    code_bytes("at EIP", c->Eip, 0x80, 0x20);
    ref_strings("at EIP", c->Eip, 0x80, 0x20);
    put("  EBP frames:\r\n");
    for (ebp = c->Ebp, n = 0; n < 48 && readable((void *)ebp, 8); n++) {
        DWORD *f = (DWORD *)ebp;
        put("    "); where(f[1]); put("\r\n");
        if (f[0] <= ebp) break;
        ebp = f[0];
    }
    for (ebp = c->Ebp, n = 0; n < 3 && readable((void *)ebp, 8); n++) {   /* the call sites of the first frames */
        DWORD *f = (DWORD *)ebp;
        code_bytes("before return", f[1], 0x40, 0x08);
        ref_strings("before return", f[1], 0x40, 0x08);
        if (f[0] <= ebp) break;
        ebp = f[0];
    }
    put("  stack values pointing into modules:\r\n");
    st = (DWORD *)c->Esp; n = 0;
    for (i = 0; i < 1024 && n < 80 && readable(st + i, 4); i++)
        if (in_module(st[i])) { put("    +"); hex(i * 4, 3); put(" "); where(st[i]); put("\r\n"); n++; }
    stack_text(c->Esp);
    pointed_text(c->Esp);
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {   /* build 109: gdiguard_ext.c focus history */
        int kex_focus_history(DWORD (*out)[8], int max); const char *kex_focus_msgname(DWORD m);
        static DWORD ev[96][8]; int k, ne = kex_focus_history(ev, 96);
        if (ne) {
            put("  focus history, oldest first (tick, message, window, wParam, lParam, window exstyle, thread, class atom; now ");
            dec(GetTickCount()); put("):\r\n");
            for (k = 0; k < ne; k++) {
                put("    "); dec(ev[k][0]); put(" "); put(kex_focus_msgname(ev[k][1])); put(" "); hex(ev[k][1], 4);
                put(" "); hex(ev[k][2], 8); put(" "); hex(ev[k][3], 8); put(" "); hex(ev[k][4], 8); put(" "); hex(ev[k][5], 8);
                put(" "); hex(ev[k][6], 8); put(" "); hex(ev[k][7], 4); put("\r\n");
                if (g_len > (int)sizeof(g_buf) - 400) flush();
            }
        }
    }
    if (r->ExceptionCode == 0xE0000008UL) { static LONG once; if (!InterlockedExchange(&once, 1)) mem_summary(); }   /* Chromium out of memory */
    put("\r\n");
    flush();
    g_lock_owner = 0;
    InterlockedExchange((LONG *)&g_lock, 0);
}

static LONG CALLBACK crash_logger(PEXCEPTION_POINTERS ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode, addr = (DWORD)ep->ExceptionRecord->ExceptionAddress;
    /* not worth a report: thread naming, debug output; faults inside KERNEL32 (IsBadReadPtr & co. probe
     * memory that way and handle it themselves) */
    if (code == 0x406D1388 || code == 0x40010006 || code == 0x4001000A) return EXCEPTION_CONTINUE_SEARCH;
    if (code == EXCEPTION_ACCESS_VIOLATION && addr >= 0x80000000UL) return EXCEPTION_CONTINUE_SEARCH;
    if (InterlockedIncrement((LONG *)&g_reports) > 24) return EXCEPTION_CONTINUE_SEARCH;
    report(ep, "exception");
    return EXCEPTION_CONTINUE_SEARCH;
}

/* SetUnhandledExceptionFilter: the program's filter is wrapped so that the exception that reaches it is logged
 * (Chromium's crash reporter ends the process with 0xFFFF7001 when it cannot write a dump - nothing else would
 * show what happened). Behaviour for the program is unchanged: its filter is called, the previous program
 * filter is returned. */
static LPTOP_LEVEL_EXCEPTION_FILTER g_app_filter;
static LONG g_filter_wrapped;
static LONG WINAPI unhandled_wrapper(PEXCEPTION_POINTERS ep)
{
    if (g_armed) {
        report(ep, "UNHANDLED exception (reached the program's filter)");
        {   void kex_pipe_recent(void (*put)(const char *));   /* pipe_ext.c, build 80 */
            DWORD me = GetCurrentThreadId();
            kex_spin_acquire((volatile LONG *)&g_lock); g_lock_owner = me;
            put("  last pipe writes of this process (oldest first):\r\n"); kex_pipe_recent(put); put("\r\n"); flush();
            g_lock_owner = 0; InterlockedExchange((LONG *)&g_lock, 0); }
        kex_prof_report("crash");
    }
    return g_app_filter ? g_app_filter(ep) : EXCEPTION_CONTINUE_SEARCH;
}
LPTOP_LEVEL_EXCEPTION_FILTER KEXAPI kex_SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER fn)
{
    LPTOP_LEVEL_EXCEPTION_FILTER prev;
    if (!InterlockedExchange(&g_filter_wrapped, 1)) {
        prev = SetUnhandledExceptionFilter(unhandled_wrapper);      /* Windows' (or an earlier) filter */
        if (prev == unhandled_wrapper) prev = NULL;
        g_app_filter = fn;
        return prev;
    }
    prev = g_app_filter;
    g_app_filter = fn;
    return prev;
}

/* ---------------------------------------------------------------- thread snapshots (build 28)
 * A program that hangs without crashing leaves no report. With TRACEON, a helper thread writes where every
 * thread of the process is, 60, 120 and 180 s after start, to KEXCRASH_<program>.LOG: thread id and name
 * (SetThreadDescription), EIP, the EBP call chain and the return addresses on its stack, plus the state of
 * kexnt's completion ports. Each thread is stopped only for GetThreadContext (Suspend, read registers,
 * Resume - no locks, no heap, as the profiler does); a blocked thread does not move, so its stack is then
 * read while it runs on. */
#define NNAMES 128
static struct { DWORD tid; char name[40]; } g_names[NNAMES];
static volatile LONG g_nnames;
HRESULT KEXAPI kex_SetThreadDescription(HANDLE h, PCWSTR name)
{
    DWORD tid; LONG i; int k;
    if (h != GetCurrentThread() || !name) return S_OK;       /* only the calling thread's own name is noted */
    tid = GetCurrentThreadId();
    for (i = 0; i < g_nnames && i < NNAMES; i++) if (g_names[i].tid == tid) break;
    if (i >= g_nnames) { i = InterlockedIncrement(&g_nnames) - 1; if (i >= NNAMES) return S_OK; }
    for (k = 0; k < 39 && name[k]; k++) g_names[i].name[k] = name[k] < 128 ? (char)name[k] : '?';
    g_names[i].name[k] = 0;
    g_names[i].tid = tid;
    return S_OK;
}
static const char *thread_name(DWORD tid)
{
    LONG i;
    for (i = 0; i < g_nnames && i < NNAMES; i++) if (g_names[i].tid == tid && g_names[i].name[0]) return g_names[i].name;
    return NULL;
}
const char *kex_thread_name(DWORD tid) { return thread_name(tid); }   /* prof_ext.c */
int kex_iocp_stat(int i, DWORD v[7]);               /* iocp_ext.c */
typedef HANDLE (WINAPI *T_OPENTHREAD)(DWORD, BOOL, DWORD);
static void snapshot(int nr)
{
    T_OPENTHREAD ot = (T_OPENTHREAD)(void *)kex_prev_impl("KERNEL32.DLL", "OpenThread");
    HANDLE s; THREADENTRY32 te; DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId(); int i;
    kex_spin_acquire((volatile LONG *)&g_lock); g_lock_owner = me;
    put("=== THREAD SNAPSHOT "); dec(nr); put("  tick "); dec(GetTickCount()); put("\r\n  completion ports (handle queued waiting posted last-post taken last-take):\r\n");
    for (i = 0; ; i++) {
        DWORD v[7]; int r = kex_iocp_stat(i, v), k;
        if (r < 0) break;
        if (!r) continue;
        put("   "); for (k = 0; k < 7; k++) { put(" "); if (k == 4 || k == 6) dec(v[k]); else hex(v[k], k ? 1 : 8); }
        put("\r\n");
    }
    flush();
    g_lock_owner = 0; InterlockedExchange((LONG *)&g_lock, 0);
    if (!ot) return;
    s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (s == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof(te);
    if (Thread32First(s, &te)) do {
        HANDLE h; CONTEXT c; DWORD ok, ebp, *st; const char *nm; int n;
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) { te.dwSize = sizeof(te); continue; }
        h = ot(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
        if (!h) { te.dwSize = sizeof(te); continue; }
        c.ContextFlags = CONTEXT_FULL; ok = 0;
        if (SuspendThread(h) != 0xFFFFFFFF) { ok = GetThreadContext(h, &c); ResumeThread(h); }
        CloseHandle(h);
        kex_spin_acquire((volatile LONG *)&g_lock); g_lock_owner = me;
        put("--- thread "); hex(te.th32ThreadID, 8);
        if ((nm = thread_name(te.th32ThreadID)) != NULL) { put(" \""); put(nm); put("\""); }
        put("  priority "); dec((DWORD)(te.tpBasePri + te.tpDeltaPri));
        if (!ok) { put("  (no context)\r\n"); flush(); g_lock_owner = 0; InterlockedExchange((LONG *)&g_lock, 0); te.dwSize = sizeof(te); continue; }
        put("\r\n  at "); where(c.Eip); put("  ESP="); hex(c.Esp, 8); put(" EBP="); hex(c.Ebp, 8);
        put(" EAX="); hex(c.Eax, 8); put(" ECX="); hex(c.Ecx, 8); put(" EDX="); hex(c.Edx, 8); put("\r\n  EBP frames:\r\n");
        ebp = c.Ebp;
        for (n = 0; n < 24 && readable((void *)ebp, 8); n++) {
            DWORD *f = (DWORD *)ebp;
            put("    "); where(f[1]); put("\r\n");
            if (f[0] <= ebp) break;
            ebp = f[0];
        }
        put("  stack values pointing into modules:\r\n");
        st = (DWORD *)c.Esp; n = 0;
        for (i = 0; i < 2048 && n < 40 && readable(st + i, 4); i++)
            if (in_module(st[i])) { put("    +"); hex(i * 4, 3); put(" "); where(st[i]); put("\r\n"); n++; }
        flush();
        g_lock_owner = 0; InterlockedExchange((LONG *)&g_lock, 0);
        te.dwSize = sizeof(te);
    } while (Thread32Next(s, &te));
    CloseHandle(s);
    kex_spin_acquire((volatile LONG *)&g_lock); put("=== end of snapshot\r\n\r\n"); flush(); InterlockedExchange((LONG *)&g_lock, 0);
}
static DWORD WINAPI snapshot_thread(LPVOID p)
{
    int k;
    (void)p;
    for (k = 1; k <= 3; k++) { Sleep(60000); snapshot(k); }
    return 0;
}

/* KEXTRACE.LOG beside the program: one line per loader step kexnt takes, written through to disk at once
 * (a blue screen loses whatever Windows still caches). Only in armed (NT 6+) processes. */
static char g_trace_path[MAX_PATH];
void kex_trace_raw(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
int kex_trace_enabled(void) { return g_trace_on != 0; }   /* build 39c: costly diagnostics only with TRACEON */
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d)
{
    { void kex_vxd_drain(void); kex_vxd_drain(); }      /* veh_ext.c: VxD first sightings queued so far, oldest first */
    kex_trace_raw(what, a, b, c, d);
}
void kex_trace_raw(const char *what, DWORD a, DWORD b, DWORD c, DWORD d)
{
    char line[400]; int n = 0; const char *s; HANDLE f; DWORD w, v[4], i, t = GetTickCount(), le = GetLastError();
    static const char hx[] = "0123456789abcdef";
    static volatile LONG budget = 30000;
    if (!g_armed || !g_trace_path[0] || !g_trace_on) return;
    if (InterlockedDecrement((LONG *)&budget) < 0) return;
    v[0] = a; v[1] = b; v[2] = c; v[3] = d;
    for (i = 0; i < 8; i++) line[n++] = hx[(t >> (28 - 4 * i)) & 15];
    line[n++] = ' ';
    for (i = 0; i < 8; i++) line[n++] = hx[(GetCurrentThreadId() >> (28 - 4 * i)) & 15];
    line[n++] = ' ';
    for (s = what; *s && n < 300; ) line[n++] = *s++;
    for (i = 0; i < 4; i++) { int k; line[n++] = ' '; for (k = 0; k < 8; k++) line[n++] = hx[(v[i] >> (28 - 4 * k)) & 15]; }
    line[n++] = '\r'; line[n++] = '\n';
    /* build 28: one writer at a time (two threads opening the file at once lost lines).
     * build 31: and cheap - the file stays open and lines go through Windows' cache. Build 30's per-line
     * open + write-through + flush, serialised, made a page-loading Chrome queue for seconds on this lock
     * (Winsock calls on the network thread measured up to 37 s, all of it waiting to trace). The cache is
     * written out by Windows even when the program crashes; only a blue screen loses the newest lines. */
    {
        static volatile LONG tlock; static volatile DWORD towner; static HANDLE tf = INVALID_HANDLE_VALUE;
        DWORD me = GetCurrentThreadId(); int mine = towner != me;
        if (mine) {   /* build 131: bounded - the owner may be a terminated or suspended thread (see kex_spin_try) */
            if (!kex_spin_try(&tlock, 500)) { SetLastError(le); return; }
            towner = me;
        }
        if (tf == INVALID_HANDLE_VALUE) {
            tf = CreateFileA(g_trace_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (tf != INVALID_HANDLE_VALUE) SetFilePointer(tf, 0, NULL, FILE_END);
        }
        if (tf != INVALID_HANDLE_VALUE) WriteFile(tf, line, n, &w, NULL);
        (void)f;
        if (mine) { towner = 0; InterlockedExchange((LONG *)&tlock, 0); }
    }
    SetLastError(le);
}

/* KEXTRACE_<program>.LOG and the VxDCall trace cost time (a file open + write-through per line, a hook on every
 * VxD call). Since 2026-11-02 they are OFF unless HKLM\Software\KernelEx\KexNG "Trace" (DWORD) is 1 - TRACEON.REG
 * on the test CD sets it, TRACEOFF.REG clears it. The crash log (KEXCRASH_<program>.LOG) stays on: it only writes
 * when something goes wrong. */
static void read_trace_setting(void)
{
    HKEY k; DWORD v = 0, t, n = sizeof(v);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "Trace", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 0;
        RegCloseKey(k);
    }
    g_trace_on = v ? 1 : 0;
}

/* one line of text for the log (no-op unless armed) */
void kex_crashlog_text(const char *s)
{
    if (!g_armed) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put(s); put("\r\n"); flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}

/* shm_ext.c: the first time a second view cannot be made (the shared arena is full) - the memory map at that moment */
void kex_crashlog_memreport(const char *why)
{
    static LONG once;
    if (!g_armed || !g_path[0] || InterlockedExchange(&once, 1)) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("--- memory report: "); put(why); put("  tick "); dec(GetTickCount()); put("\r\n");
    mem_summary();
    flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}

/* Called by the PEB patcher when it prepares an NT 6+ process (once per process). */
void kex_crashlog_arm(void)
{
    char *p, *slash = NULL; SYSTEMTIME t;
    if (InterlockedExchange((LONG *)&g_armed, 1)) return;
    read_trace_setting();
    if (!GetModuleFileNameA(NULL, g_path, sizeof(g_path) - 48)) return;
    kex_prof_start(g_path);
    for (p = g_path; *p; p++) if (*p == '\\') slash = p;
    if (!slash) return;
    {   /* KEXCRASH_<program>.LOG / KEXTRACE_<program>.LOG next to the program (e.g. KEXCRASH_chrome.LOG) */
        char prog[33]; int n = 0; const char *q = slash + 1;
        while (*q && *q != '.' && n < (int)sizeof(prog) - 1) { char c = *q++; prog[n++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }
        prog[n] = 0;
        if (!n) lstrcpyA(prog, "program");
        lstrcpyA(g_trace_path, g_path);
        lstrcpyA(slash + 1, "KEXCRASH_"); lstrcatA(slash + 1, prog); lstrcatA(slash + 1, ".LOG");
        { char *t = g_trace_path + (slash + 1 - g_path); lstrcpyA(t, "KEXTRACE_"); lstrcatA(t, prog); lstrcatA(t, ".LOG"); }
    }
    GetLocalTime(&t);
    put("##### kexnt build " KEXNG_BUILD_S ", process "); hex(GetCurrentProcessId(), 8); put(" started ");
    dec(t.wYear); put("-"); if (t.wMonth < 10) put("0"); dec(t.wMonth); put("-"); if (t.wDay < 10) put("0"); dec(t.wDay);
    put(" "); if (t.wHour < 10) put("0"); dec(t.wHour); put(":"); if (t.wMinute < 10) put("0"); dec(t.wMinute);
    put(":"); if (t.wSecond < 10) put("0"); dec(t.wSecond);
    put("  cmd: "); putn(GetCommandLineA(), 300); put("\r\n");
    flush();
    { void kex_hang_arm(const char *p); kex_hang_arm(g_path); }   /* hang_ext.c (build 48): KEXHANG_<program>.LOG if nothing is drawn */
    kex_AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)crash_logger);
    /* Build 131: the VxD-call trace runs kexnt code on every thread at arbitrary points inside KERNEL32 (holding its
     * locks), and the profiler's sampler suspends threads every 25 ms: together they froze Windows 98 (full kextest at
     * [DirectWrite], Trace=1 + Profile=1; Trace=1 + Profile=1 + KEXNG_NOVXDTRACE=1 passed, and so did either alone).
     * With the profiler on, the VxD-call trace stays off; KEXTRACE keeps every other line. */
    if (g_trace_on) {
        int kex_prof_running(void);
        if (kex_prof_running()) kex_trace("vxd trace off: the profiler (KexNG Profile=1) is running", 0, 0, 0, 0);
        else { void kex_vxdtrace_activate(void); kex_vxdtrace_activate(); }
    }
    if (g_trace_on) { DWORD tid; HANDLE h = CreateThread(NULL, 0, snapshot_thread, NULL, 0, &tid); if (h) CloseHandle(h); }   /* veh_ext.c: VxDCall first-sighting trace */
}

/* ---------------------------------------------------------------- process exit logging
 * Chromium that gives up does not crash: it returns a result code (ExitProcess) or ends itself at once
 * (TerminateProcess on its own process). Both are logged with the exit code and the call chain, only in
 * processes where the logger is armed (NT 6+ programs). */
BYTE *kex_k32_object(HANDLE h, int type);    /* chrome_ext.c */

static void log_exit(const char *what, DWORD code, DWORD ebp)
{
    int n;
    kex_prof_report(what);
    if (!g_armed || !g_path[0]) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("=== "); put(what); put(" exit code "); hex(code, 8); put(" ("); dec(code); put(")  thread ");
    hex(GetCurrentThreadId(), 8); put("  tick "); dec(GetTickCount());
    {   /* build 79: wall clock + process id, so an exit can be matched to "the page went blank at 20:12" */
        SYSTEMTIME t; GetLocalTime(&t);
        put("  time "); if (t.wHour < 10) put("0"); dec(t.wHour); put(":"); if (t.wMinute < 10) put("0"); dec(t.wMinute);
        put(":"); if (t.wSecond < 10) put("0"); dec(t.wSecond); put("  process "); hex(GetCurrentProcessId(), 8);
    }
    put("\r\n  called from:\r\n");
    for (n = 0; n < 40 && readable((void *)ebp, 8); n++) {
        DWORD *f = (DWORD *)ebp;
        put("    "); where(f[1]); put("\r\n");
        if (f[0] <= ebp) break;
        ebp = f[0];
    }
    put("\r\n");
    {   /* VxD trace health (veh_ext.c): state, hook calls, first sightings, written, flusher threads started/alive */
        void kex_vxd_stats(DWORD v[6]); DWORD v[6]; int k;
        kex_vxd_stats(v);
        put("  vxd trace: state/calls/new/written/flushers/alive");
        for (k = 0; k < 6; k++) { put(" "); hex(v[k], 8); }
        put("\r\n\r\n");
    }
    flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}

/* KernelEx 4.5 ExitProcess_fix behaviour kept (kexbases/Kernel32/process.c): an already terminating process
 * fails silently instead of crashing; the exiting thread gets idle priority so other threads finish first and
 * DLL process-detach runs in an NT-like order. PDB98: Flags at +0x20, fTerminating = 0x10000000. */
VOID KEXAPI kex_ExitProcess(UINT code)
{
    BYTE *pdb; __asm__ volatile("movl %%fs:0x30, %0" : "=r"(pdb));
    { void kex_laa_exit_note(void); kex_laa_exit_note(); }          /* build 123 */
    { void kex_msicompat_exit(void); kex_msicompat_exit(); }        /* build 125 */
    log_exit("ExitProcess", code, (DWORD)__builtin_frame_address(0));
    { void kex_job_process_exit(void); kex_job_process_exit(); }   /* job_ext.c: kill-on-close jobs end with us */
    if (pdb && (*(DWORD *)(pdb + 0x20) & 0x10000000UL)) {
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
    ExitProcess(code);
}

BOOL KEXAPI kex_TerminateProcess(HANDLE h, UINT code)
{
    BYTE *pdb; __asm__ volatile("movl %%fs:0x30, %0" : "=r"(pdb));
    if (h == GetCurrentProcess() || (pdb && kex_k32_object(h, 6) == pdb)) {
        { void kex_laa_exit_note(void); kex_laa_exit_note(); }      /* build 123 */
        { void kex_msicompat_exit(void); kex_msicompat_exit(); }    /* build 125 */
        log_exit("TerminateProcess(self)", code, (DWORD)__builtin_frame_address(0));
        { void kex_job_process_exit(void); kex_job_process_exit(); }   /* job_ext.c */
        return TerminateProcess(h, code);
    }
    {   /* build 121: the Web Store tabs that died with "out of memory" right after the browser closed their channel -
         * did the browser try to end them (Chromium's fast shutdown) and did that work? */
        DWORD kex_pid_of(HANDLE ph); void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
        DWORD pid = kex_pid_of(h); BOOL r = TerminateProcess(h, code); DWORD le = GetLastError();
        static LONG k; if (InterlockedIncrement(&k) <= 40)
            kex_crashnote("TerminateProcess of another process (process, exit code, ok, error)", pid, code, (DWORD)r, r ? 0 : le);
        if (r) { void kex_laa_process_ended(HANDLE ph, DWORD pid); kex_laa_process_ended(h, pid); }   /* build 123: its blocks above 2 GB */
        SetLastError(le); return r;
    }
}

/* Failed LoadLibrary calls (loader_ext.c). A program's own start shows Win98's "linked to missing export"
 * box, but LoadLibrary just returns NULL - chrome.exe then quits quietly with an error code. */
static volatile LONG g_loadfails;
const char *kex_k32_load_message(void);     /* veh_ext.c */
void kex_crashlog_loadfail(LPCSTR name, DWORD flags, DWORD err)
{
    const char *msg = err == 31 ? kex_k32_load_message() : NULL;
    if (!g_armed || !g_path[0] || InterlockedIncrement((LONG *)&g_loadfails) > 64) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("--- LoadLibrary failed: "); putn(name ? name : "(null)", 260); put("  flags "); hex(flags, 8);
    put("  error "); dec(err);
    switch (err) {
    case ERROR_MOD_NOT_FOUND: put(" (module not found)"); break;
    case ERROR_PROC_NOT_FOUND: put(" (an import of it or of a DLL it needs is missing)"); break;
    case ERROR_DLL_INIT_FAILED: put(" (a DllMain returned FALSE)"); break;
    case ERROR_BAD_EXE_FORMAT: put(" (not a valid Win32 image for this system)"); break;
    case ERROR_NOT_ENOUGH_MEMORY: case ERROR_OUTOFMEMORY: put(" (out of memory / address space)"); break;
    case 31: put(" (Windows 98: the DLL or one it needs could not be linked)"); break;
    }
    put("\r\n");
    if (msg) { put("    Windows says: "); putn(msg, 400); put("\r\n"); }
    flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}

/* shm_ext.c: a second live MapViewOfFile of the same address in one process (Windows 98 maps a section once per
 * process; Chromium's SharedMemoryTracker then CHECKs at shared_memory_tracker.cc:62). Logged with the callers
 * (EBP chain of the MapViewOfFile caller) so the Chromium feature that maps a region twice can be identified. */
static volatile LONG g_dupviews;
void kex_crashlog_dupview(void *a, LONG count, DWORD h, DWORD off, DWORD n, DWORD ebp)
{
    int i;
    if (!g_armed || !g_path[0] || InterlockedIncrement((LONG *)&g_dupviews) > 16) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("--- MapViewOfFile: same address as a view this process already has: "); hex((DWORD)(ULONG_PTR)a, 8);
    put("  views "); dec((DWORD)count); put("  handle "); hexmin(h); put("  offset "); hexmin(off); put("  size "); hexmin(n);
    put("\r\n    mapped from:");
    for (i = 0; i < 24 && ebp >= 0x10000 && !IsBadReadPtr((void *)ebp, 8); i++) {
        DWORD ret = ((DWORD *)ebp)[1], next = ((DWORD *)ebp)[0];
        put("\r\n      "); where(ret);
        if (next <= ebp) break;
        ebp = next;
    }
    put("\r\n");
    flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}

/* build 91: a note plus the EBP chain of its caller (who closes a tab's pipe end, and why) */
void kex_crashlog_callers(const char *what, DWORD ebp, int max)
{
    int i;
    if (!g_armed || !g_path[0]) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("--- "); put(what); put("  thread "); hex(GetCurrentThreadId(), 8);
    put("\r\n    called from:");
    for (i = 0; i < max && ebp >= 0x10000 && !IsBadReadPtr((void *)ebp, 8); i++) {
        DWORD ret = ((DWORD *)ebp)[1], next = ((DWORD *)ebp)[0];
        put("\r\n      "); where(ret);
        if (next <= ebp) break;
        ebp = next;
    }
    put("\r\n");
    flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}

/* build 48: Chromium's downloads fail without a word in its log - the first file calls that fail for a reason
 * other than "not found" go to KEXCRASH (at most 40 lines per process). */
/* build 55: one line in KEXCRASH for things that must be seen without TRACEON (guard anomalies, ...) */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d)
{
    static volatile LONG n;
    if (!g_armed || !g_path[0] || InterlockedIncrement(&n) > 1200) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("--- "); put(what); put(" "); hex(a, 8); put(" "); hex(b, 8); put(" "); hex(c, 8); put(" "); hex(d, 8);
    put("  thread "); hex(GetCurrentThreadId(), 8); put("\r\n"); flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}
void kex_filefail(const char *api, const char *path, DWORD err, DWORD a, DWORD b)
{
    static volatile LONG n;
    if (!g_armed || !g_path[0] || InterlockedIncrement(&n) > 80) return;
    kex_spin_acquire((volatile LONG *)&g_lock);
    put("--- file call failed: "); put(api); put(" error "); dec(err); put(" ("); hex(a, 8); put(" "); hex(b, 8); put(") ");
    if (path) putn(path, 260);
    put("\r\n"); flush();
    InterlockedExchange((LONG *)&g_lock, 0);
}
