/*
 * prof_ext.c - KernelEx-NG: "where does the time go" for a slow program (2026-11-02, Mypal on YouTube).
 *
 * Switched on by HKLM\Software\KernelEx\KexNG "Profile" (DWORD) = 1 (PROFON.REG / PROFOFF.REG on the test CD).
 * A sampler thread wakes every 25 ms (10 ms until build 104: it then cost up to 16-19% of the time), stops each thread of the process for a moment (SuspendThread +
 * GetThreadContext, as Mozilla's own hang monitor does), notes where it was (EIP) and lets it go on. When the
 * program exits (or crashes), KEXPROF_<program>.LOG next to it gets:
 *   - time per module (xul.dll = page layout/scripts, js JIT code shows as "(no module)", GDI32/USER32 and the
 *     16-bit GDI.EXE/USER.EXE = Windows drawing, KEXBASES/KEXBASEN/KEXNT = KernelEx itself, ...)
 *   - time per thread (main thread vs Compositor vs decoders ...)
 *   - the 60 hottest code addresses (module + offset, 16-byte buckets)
 *   - every GDI32/USER32 call that went through kexnt's guard: count and CPU cycles (RDTSC).
 * Between Suspend and Resume the sampler only calls GetThreadContext - no heap, no locks.
 */
#include "kexnt_common.h"
#include <tlhelp32.h>
#include <x86intrin.h>   /* __rdtsc: built into clang, needs the header with GCC */

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
FARPROC kex_prev_impl(const char *dll, const char *name);

#define NB 65536                       /* EIP buckets (open addressing) */
#define NT 160                         /* threads */
typedef struct { DWORD key; DWORD n; } BK;
typedef struct { DWORD tid; HANDLE h; DWORD n, busy, idle, kern, last_eip, last_esp, streak, skip; DWORD wa[8], wn[8]; } TH;
static BK *g_b; static TH g_t[NT]; static int g_nt;
static volatile LONG g_prof_on, g_samples, g_lost, g_busy, g_kern;

/* Windows 98 KERNEL32 enters the system (VWIN32/VMM: waits, Sleep, blocking on a taken critical section,
 * memory services) through VxDCall0 = its export #1. A thread stopped there shows an EIP right after a
 * "call VxDCall0" in KERNEL32 and, when it keeps waking and blocking again, an EIP/ESP that moved since the
 * last look - the first profile counted that as running (KERNEL32 39%, "129% of one CPU"). Such samples are
 * now "in Windows kernel services" and kept out of the running figures. */
static DWORD g_vxd, g_k32lo, g_k32hi;
static void find_vxdcall(void)
{
    BYTE *b = (BYTE *)GetModuleHandleA("KERNEL32.DLL"); IMAGE_NT_HEADERS *nt; IMAGE_EXPORT_DIRECTORY *ed; DWORD rva;
    if (!b || *(WORD *)b != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return;
    ed = (IMAGE_EXPORT_DIRECTORY *)(b + rva);
    if (ed->Base > 1 || ed->NumberOfFunctions < 2 - ed->Base) return;
    g_vxd = (DWORD)(ULONG_PTR)b + ((DWORD *)(b + ed->AddressOfFunctions))[1 - ed->Base];   /* ordinal 1 */
    g_k32lo = (DWORD)(ULONG_PTR)b; g_k32hi = g_k32lo + nt->OptionalHeader.SizeOfImage;
}
static int in_kernel_service(DWORD eip)
{
    DWORD k;
    if (!g_vxd || eip < g_k32lo || eip >= g_k32hi) return 0;
    if (eip >= g_vxd && eip < g_vxd + 0x40) return 1;
    for (k = 5; k <= 24; k++) {
        const BYTE *p = (const BYTE *)(ULONG_PTR)(eip - k);
        if (p[0] == 0xE8 && eip - k + 5 + *(const DWORD *)(p + 1) == g_vxd) return 1;
    }
    return 0;
}

/* real CPU load from Windows 98's own counter (HKEY_DYN_DATA\PerfStats, "KERNEL\CPUUsage" - what System
 * Monitor shows), read once a second: tells "the CPU is full" apart from "everyone is waiting" */
static DWORD g_cpu_h[11], g_cpu_sum, g_cpu_n, g_cpu_last;
static void perfstat(const char *key, DWORD *v)
{
    HKEY k; DWORD t, n = sizeof(DWORD), d = 0;
    if (RegOpenKeyExA(HKEY_DYN_DATA, key, 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    if (RegQueryValueExA(k, "KERNEL\\CPUUsage", NULL, &t, (BYTE *)&d, &n) == ERROR_SUCCESS && v) *v = d;
    RegCloseKey(k);
}
static void cpu_tick(void)
{
    DWORD v = 0xFFFFFFFF;
    perfstat("PerfStats\\StatData", &v);
    if (v > 100) return;
    g_cpu_h[v / 10]++; g_cpu_sum += v; g_cpu_n++; g_cpu_last = v;
}

/* build 104: Windows 98's own memory-manager counters (what System Monitor shows under "Memory Manager" and
 * "Disk Cache"), read once a second: free pages, disk cache, swap file in use, page-ins/outs. The Discord run of
 * build 103 had 0 MB free and the swap file "nearly full" while the CPU sat at 100% for 75 s although the sampled
 * threads ran only ~45 s - these counters tell whether the rest was Windows paging. */
#define NPS 64
typedef struct { char name[40]; DWORD first, last, mn, mx; } PSV;
static PSV g_ps[NPS]; static int g_nps;
static const char *const g_ps_known[] = {
    "VMM\\cpgFree", "VMM\\cpgDiskcache", "VMM\\cpgDiskcacheMin", "VMM\\cpgSwapfile", "VMM\\cpgSwapfileInUse",
    "VMM\\cpgSwapfileDefective", "VMM\\cpgCommit", "VMM\\cpgLocked", "VMM\\cpgLockedNoncache", "VMM\\cpgOther",
    "VMM\\cpgSharedPages", "VMM\\cpgSwap", "VMM\\cpgFile", "VMM\\cPageFaults", "VMM\\cPageIns", "VMM\\cPageOuts",
    "VMM\\cDiscards", "VMM\\cInstanceFaults", "VMM\\cpgMapped", "VCACHE\\cCurPages", "VCACHE\\cMinPages",
    "VCACHE\\cMacPages", "VCACHE\\cHits", "VCACHE\\cMisses", NULL };
static int ps_wanted(const char *n)
{
    return !memcmp(n, "VMM\\", 4) || !memcmp(n, "VCACHE\\", 7);
}
static void ps_note(const char *n, DWORD v)
{
    int i;
    for (i = 0; i < g_nps; i++) if (!lstrcmpA(g_ps[i].name, n)) break;
    if (i == g_nps) {
        if (g_nps >= NPS || lstrlenA(n) >= (int)sizeof(g_ps[0].name)) return;
        lstrcpyA(g_ps[i].name, n); g_ps[i].first = g_ps[i].mn = g_ps[i].mx = v; g_nps++;
    }
    g_ps[i].last = v;
    if (v < g_ps[i].mn) g_ps[i].mn = v;
    if (v > g_ps[i].mx) g_ps[i].mx = v;
}
/* key "PerfStats\\StartStat" switches every counter on (each value read starts it), "StatData" reads them */
static void ps_walk(const char *key, int keep)
{
    HKEY k; DWORD i, found = 0;
    if (RegOpenKeyExA(HKEY_DYN_DATA, key, 0, KEY_READ, &k) != ERROR_SUCCESS) return;
    for (i = 0; i < 400; i++) {
        char n[64]; DWORD nl = sizeof(n), t, d = 0, dl = sizeof(d);
        LONG r = RegEnumValueA(k, i, n, &nl, NULL, &t, (BYTE *)&d, &dl);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS || dl != sizeof(DWORD)) continue;
        found++;
        if (keep && ps_wanted(n)) ps_note(n, d);
    }
    if (!found)                                  /* enumeration not offered: ask for the known names */
        for (i = 0; g_ps_known[i]; i++) {
            DWORD t, d = 0, dl = sizeof(d);
            if (RegQueryValueExA(k, g_ps_known[i], NULL, &t, (BYTE *)&d, &dl) == ERROR_SUCCESS && dl == sizeof(DWORD) && keep) ps_note(g_ps_known[i], d);
        }
    RegCloseKey(k);
}
static volatile unsigned __int64 g_self_cyc, g_tsc0;   /* the sampler's own work (cycles), and when it began */

/* network connections: connect -> first send (TCP connected; NSPR/Gecko connect without blocking and send
 * right away, e.g. the TLS hello) -> first data back, bytes, how many are open at once; name lookups */
typedef struct { DWORD s, t_conn, t_send, t_recv, rx; } CN;
#define NCN 256
static CN g_cn[NCN]; static volatile LONG g_cn_lock;
static DWORD g_nconn, g_open, g_open_max, g_h_tcp[8], g_h_first[8], g_n_tcp, g_n_first, g_sum_tcp, g_sum_first;
static DWORD g_dns_n, g_dns_sum, g_dns_max, g_h_dns[8], g_big_rx, g_big_ms;
static int hbin(DWORD ms) { static const DWORD lim[7] = { 50, 100, 200, 500, 1000, 2000, 5000 }; int i; for (i = 0; i < 7 && ms >= lim[i]; i++) {} return i; }
static void cn_end(CN *c)
{
    if (c->rx >= 100000 && c->t_recv) { g_big_rx += c->rx; g_big_ms += GetTickCount() - c->t_recv; }
    c->s = 0; if (g_open) g_open--;
}
void kex_prof_sock(int kind, UINT_PTR s, LONG v)
{
    DWORD now = GetTickCount(); int i, f = -1;
    if (!g_prof_on) return;
    if (kind == 5) { g_dns_n++; g_dns_sum += (DWORD)v; if ((DWORD)v > g_dns_max) g_dns_max = (DWORD)v; g_h_dns[hbin((DWORD)v)]++; return; }
    kex_spin_acquire((volatile LONG *)&g_cn_lock);
    for (i = 0; i < NCN; i++) { if (g_cn[i].s == (DWORD)s) { f = i; break; } }
    if (kind == 3) {
        if (f >= 0) cn_end(&g_cn[f]);
        for (i = 0; i < NCN && f < 0; i++) if (!g_cn[i].s) f = i;
        if (f >= 0) { CN *c = &g_cn[f]; c->s = (DWORD)s; c->t_conn = now; c->t_send = c->t_recv = 0; c->rx = 0;
                      g_nconn++; if (++g_open > g_open_max) g_open_max = g_open; }
    } else if (f >= 0) {
        CN *c = &g_cn[f];
        if (kind == 4) cn_end(c);
        else if (kind == 1 && v > 0 && !c->t_send) { c->t_send = now; g_h_tcp[hbin(now - c->t_conn)]++; g_n_tcp++; g_sum_tcp += now - c->t_conn; }
        else if (kind == 0 && v > 0) {
            c->rx += (DWORD)v;
            if (!c->t_recv) { DWORD from = c->t_send ? c->t_send : c->t_conn; c->t_recv = now; g_h_first[hbin(now - from)]++; g_n_first++; g_sum_first += now - from; }
        }
    }
    g_cn_lock = 0;
}
static char g_prof_path[MAX_PATH];
static DWORD g_t0;

typedef struct { const char *name; DWORD calls; unsigned __int64 cyc; } GC;
#define NG 2048
static GC g_gc[NG];

LONG kex_prof_enabled(void) { return g_prof_on; }

/* called by the guard (gdiguard_ext.c) when profiling: one GDI/USER call and its cycles */
void kex_prof_call(const char *name, unsigned __int64 cyc)
{
    DWORD h = ((DWORD)(ULONG_PTR)name >> 2) & (NG - 1), i;
    for (i = 0; i < 16; i++, h = (h + 1) & (NG - 1)) {
        if (g_gc[h].name == name || (!g_gc[h].name && InterlockedCompareExchange((LONG *)&g_gc[h].name, (LONG)(ULONG_PTR)name, 0) == 0)) {
            if (g_gc[h].name != name) continue;
            InterlockedIncrement((LONG *)&g_gc[h].calls);
            g_gc[h].cyc += cyc;          /* not atomic: a rare lost update only blurs a profile */
            return;
        }
    }
}

static void add_to(BK *b, DWORD nb, DWORD eip)
{
    DWORD key = (eip & ~0xFUL) | 1, h = ((eip >> 4) * 2654435761UL) & (nb - 1), i;
    for (i = 0; i < 64; i++, h = (h + 1) & (nb - 1)) {
        if (b[h].key == key) { b[h].n++; return; }
        if (!b[h].key) { b[h].key = key; b[h].n = 1; return; }
    }
    g_lost++;
}
static void add(DWORD eip) { add_to(g_b, NB, eip); }

/* the program's main thread (the one that armed the crash log at start-up) over the last 30 seconds:
 * what a frozen window is doing shows up here in the report written just before it was killed */
#define NMI 4096
static BK g_tgc[1024]; static DWORD g_tg_lo, g_tg_n;   /* build 63: who calls Windows 98's own timeGetTime */
static BK g_mi[NMI]; static TH g_mw; static DWORD g_main_tid, g_mi_busy, g_mi_idle, g_mi_kern;

typedef HANDLE (WINAPI *T_OT)(DWORD, BOOL, DWORD);
static volatile LONG g_tlock;
static volatile LONG g_d_refresh, g_d_snapfail, g_d_openfail, g_d_attach, g_d_suspfail, g_d_ctxfail;   /* build 40: profiler health */
static void add_thread(DWORD tid, HANDLE h)              /* lock held */
{
    int i;
    for (i = 0; i < g_nt; i++) if (g_t[i].tid == tid) { if (h) CloseHandle(h); return; }
    if (g_nt >= NT) { if (h) CloseHandle(h); return; }
    g_t[g_nt].tid = tid; g_t[g_nt].h = h; g_t[g_nt].n = 0; g_nt++;
}
/* build 39c: Toolhelp's thread snapshot found only 8 of Chromium's ~40 threads (every profile said "8 threads" and
 * ~0 running while Windows reported 80-90% CPU), so the busy threads were never sampled. kexnt's DllMain now hands
 * every new thread to the profiler (DLL_THREAD_ATTACH, a real handle duplicated from GetCurrentThread). */
void kex_prof_thread_attach(void)
{
    HANDLE h = NULL;
    if (!g_prof_on) return;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS)) return;
    InterlockedIncrement(&g_d_attach);
    kex_spin_acquire(&g_tlock);
    add_thread(GetCurrentThreadId(), h);
    InterlockedExchange(&g_tlock, 0);
}
static void refresh_threads(T_OT ot)
{
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te; DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId(); int i;
    InterlockedIncrement(&g_d_refresh);
    if (s == INVALID_HANDLE_VALUE) { InterlockedIncrement(&g_d_snapfail); return; }
    te.dwSize = sizeof(te);
    if (Thread32First(s, &te)) do {
        /* build 40: dwSize is reset before EVERY Thread32Next (the "continue"s skipped it - the walk could stop early) */
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) { te.dwSize = sizeof(te); continue; }
        for (i = 0; i < g_nt; i++) if (g_t[i].tid == te.th32ThreadID) break;
        if (i < g_nt || g_nt >= NT || !ot) { te.dwSize = sizeof(te); continue; }
        {
            HANDLE h = ot(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (h) { kex_spin_acquire(&g_tlock); add_thread(te.th32ThreadID, h); InterlockedExchange(&g_tlock, 0); }
            else InterlockedIncrement(&g_d_openfail);
        }
        te.dwSize = sizeof(te);
    } while (Thread32Next(s, &te));
    CloseHandle(s);
}

static int not_ours(DWORD a)                     /* a return address that is the program's own code */
{
    return a >= 0x10000 && a < 0x80000000UL && !(a >= 0x6A000000UL && a < 0x6B000000UL) && !(a >= 0x7D000000UL && a < 0x7D100000UL);
}
static void note_wait(TH *t, DWORD site, DWORD w)
{
    int i, lo = 0;
    for (i = 0; i < 8; i++) { if (t->wa[i] == site) { t->wn[i] += w; return; } if (t->wn[i] < t->wn[lo]) lo = i; }
    if (t->wn[lo] <= w) { t->wa[lo] = site; t->wn[lo] = w; }
}

/* A thread whose EIP and ESP did not move since the last look is waiting (or spinning in one place): its
 * time is "idle", and where it waits (first return address in the program's own code) is noted. Threads idle
 * for a while are looked at only every 10th round (each look then counts for the rounds skipped), so 60+
 * sleeping helper threads don't cost 6000 Suspend/Resume pairs a second. */
/* ---- build 127: per-second timeline, KEXTL_<program>[_<type>].LOG (the Discord click diagnosis)
 * One line a second: local time with ms, CPU load, page-ins in that second, what the main thread did in that
 * second (samples running / waiting / in kernel services) and where it was last, and the process's pipe IPC in
 * that second (bytes in/out, the longest time data waited in a pipe before this process read it, the longest wait
 * for the pipes' global lock). Events (clicks the window thread dispatched) go into the same file with the same
 * clock, so a click can be followed: browser dispatch -> IPC -> renderer main thread -> page (CHRVAR15 page log). */
static HANDLE g_tl = INVALID_HANDLE_VALUE; static char g_tl_path[MAX_PATH]; static volatile LONG g_tl_lock;
static DWORD g_tl_pagein_prev, g_tl_mb, g_tl_mi, g_tl_mk;
void kex_pipe_tl_stats(DWORD *in, DWORD *out, DWORD *maxwait, DWORD *lockmax, DWORD *slow);   /* pipe_ext.c */
static int tl_time(char *o)
{
    SYSTEMTIME t; int k = 0; WORD v[4]; int i;
    GetLocalTime(&t); v[0] = t.wHour; v[1] = t.wMinute; v[2] = t.wSecond; v[3] = t.wMilliseconds;
    for (i = 0; i < 3; i++) { o[k++] = (char)('0' + v[i] / 10); o[k++] = (char)('0' + v[i] % 10); o[k++] = i < 2 ? ':' : '.'; }
    o[k++] = (char)('0' + v[3] / 100); o[k++] = (char)('0' + v[3] / 10 % 10); o[k++] = (char)('0' + v[3] % 10); o[k++] = ' '; o[k] = 0;
    return k;
}
static void tl_open(void)
{
    char *p;
    if (g_tl != INVALID_HANDLE_VALUE || !g_prof_path[0]) return;
    lstrcpyA(g_tl_path, g_prof_path);
    for (p = g_tl_path; *p && !(p[0] == 'K' && p[1] == 'E' && p[2] == 'X' && p[3] == 'P' && p[4] == 'R' && p[5] == 'O' && p[6] == 'F' && p[7] == '_'); p++) {}
    if (*p) { p[3] = 'T'; p[4] = 'L'; memmove(p + 5, p + 7, lstrlenA(p + 7) + 1); }   /* KEXPROF_x -> KEXTL_x */
    g_tl = CreateFileA(g_tl_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    if (g_tl != INVALID_HANDLE_VALUE) SetFilePointer(g_tl, 0, NULL, FILE_END);
}
static void tl_write(const char *s) { DWORD x; if (g_tl != INVALID_HANDLE_VALUE) WriteFile(g_tl, s, lstrlenA(s), &x, NULL); }
static int tl_dec(char *o, DWORD v) { char t[12]; int i = 11, k = 0; t[i] = 0; do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v); while (t[i]) o[k++] = t[i++]; o[k] = 0; return k; }
static int tl_hex(char *o, DWORD v) { int i; for (i = 0; i < 8; i++) o[i] = "0123456789abcdef"[(v >> (28 - 4 * i)) & 15]; o[8] = 0; return 8; }
static DWORD mod_of(DWORD a, char *name, int cb);
/* any thread: one event line (works only while the profiler runs - KexNG\Profile = 1) */
void kex_tl_event(const char *what, DWORD a, DWORD b, DWORD c)
{
    char l[300]; int k;
    if (!g_prof_on) return;
    kex_spin_acquire(&g_tl_lock);
    tl_open();
    k = tl_time(l); lstrcpynA(l + k, what, 200); k = lstrlenA(l);
    l[k++] = ' '; k += tl_hex(l + k, a); l[k++] = ' '; k += tl_hex(l + k, b); l[k++] = ' '; k += tl_hex(l + k, c);
    l[k++] = ' '; lstrcpyA(l + k, "tick "); k += 5; k += tl_dec(l + k, GetTickCount()); l[k++] = '\r'; l[k++] = '\n'; l[k] = 0;
    tl_write(l);
    InterlockedExchange(&g_tl_lock, 0);
}
static void tl_second(DWORD cpu, DWORD pagein, DWORD main_eip)
{
    char l[400], mn[64]; int k; DWORD in, out, mw, lm, slow, base, db, di, dk;
    kex_pipe_tl_stats(&in, &out, &mw, &lm, &slow);
    db = g_mi_busy - g_tl_mb; di = g_mi_idle - g_tl_mi; dk = g_mi_kern - g_tl_mk;
    g_tl_mb = g_mi_busy; g_tl_mi = g_mi_idle; g_tl_mk = g_mi_kern;
    base = mod_of(main_eip, mn, sizeof(mn));
    kex_spin_acquire(&g_tl_lock);
    tl_open();
    k = tl_time(l);
    lstrcpyA(l + k, "cpu "); k += 4; k += tl_dec(l + k, cpu); lstrcpyA(l + k, "% pagein/s "); k += 11; k += tl_dec(l + k, pagein);
    lstrcpyA(l + k, " | main run "); k += 12; k += tl_dec(l + k, db); lstrcpyA(l + k, " wait "); k += 6; k += tl_dec(l + k, di);
    lstrcpyA(l + k, " kern "); k += 6; k += tl_dec(l + k, dk); lstrcpyA(l + k, " at "); k += 4; lstrcpynA(l + k, mn, 40); k = lstrlenA(l);
    l[k++] = '+'; k += tl_hex(l + k, main_eip - base);
    lstrcpyA(l + k, " | ipc in "); k += 10; k += tl_dec(l + k, in); lstrcpyA(l + k, " out "); k += 5; k += tl_dec(l + k, out);
    lstrcpyA(l + k, " waited max "); k += 12; k += tl_dec(l + k, mw); lstrcpyA(l + k, " ms (>300 ms: "); k += 14; k += tl_dec(l + k, slow);
    lstrcpyA(l + k, "), lock wait max "); k += 17; k += tl_dec(l + k, lm); lstrcpyA(l + k, " ms\r\n"); k += 5;
    tl_write(l);
    InterlockedExchange(&g_tl_lock, 0);
}

static void write_report(const char *why);
static DWORD WINAPI sampler(LPVOID p)
{
    T_OT ot = (T_OT)(void *)kex_prev_impl("KERNEL32.DLL", "OpenThread");
    DWORD round = 0, me = GetCurrentThreadId(); int i;
    (void)p;
    find_vxdcall();
    perfstat("PerfStats\\StartStat", NULL);
    ps_walk("PerfStats\\StartStat", 0);
    g_tsc0 = __rdtsc();
    while (g_prof_on) {
        unsigned __int64 c0 = __rdtsc();
        if ((round++ % 40) == 0) {
            refresh_threads(ot); cpu_tick(); ps_walk("PerfStats\\StatData", 1);
            {   DWORD pi = 0, cpu = g_cpu_n ? g_cpu_last : 0, me2 = 0; int q;           /* build 127: timeline line */
                for (q = 0; q < g_nps; q++) if (!lstrcmpA(g_ps[q].name, "VMM\\cPageIns")) pi = g_ps[q].last;
                for (q = 0; q < g_nt; q++) if (g_t[q].tid == g_main_tid) me2 = g_t[q].last_eip;
                if (round > 1) tl_second(cpu, g_tl_pagein_prev && pi >= g_tl_pagein_prev ? pi - g_tl_pagein_prev : 0, me2);
                g_tl_pagein_prev = pi;
            }
            if (!g_tg_lo) { HMODULE wm = GetModuleHandleA("WINMM.DLL"); if (wm) g_tg_lo = (DWORD)(ULONG_PTR)GetProcAddress(wm, "timeGetTime"); }
        }   /* new threads, CPU load: once a second */
        for (i = 0; i < g_nt; i++) {
            TH *t = &g_t[i]; CONTEXT c; DWORD r, site = 0, wgt;
            if (!t->h || t->tid == me) continue;              /* build 40: never itself (DLL_THREAD_ATTACH registered the sampler too) */
            if (t->skip) { t->skip--; continue; }
            wgt = t->streak > 20 ? 10 : 1;
            r = SuspendThread(t->h);
            if (r == 0xFFFFFFFF) { CloseHandle(t->h); t->h = NULL; InterlockedIncrement(&g_d_suspfail); continue; }   /* thread ended */
            c.ContextFlags = CONTEXT_CONTROL;
            r = GetThreadContext(t->h, &c);
            if (r && ((c.Eip == t->last_eip && c.Esp == t->last_esp) || in_kernel_service(c.Eip))) {   /* waiting: find the caller */
                DWORD e = c.Ebp, k;
                if (not_ours(c.Eip)) site = c.Eip;
                for (k = 0; k < 10 && !site && e && !IsBadReadPtr((void *)e, 8); k++) {
                    DWORD *f = (DWORD *)e;
                    if (not_ours(f[1])) site = f[1];
                    if (f[0] <= e) break;
                    e = f[0];
                }
            }
            ResumeThread(t->h);
            if (!r) { InterlockedIncrement(&g_d_ctxfail); continue; }
            t->n += wgt;
            InterlockedExchangeAdd(&g_samples, (LONG)wgt);
            if (c.Eip == t->last_eip && c.Esp == t->last_esp) {
                t->idle += wgt; t->streak++;
                if (site) note_wait(t, site, wgt);
                if (t->streak > 20) t->skip = 9;
            } else if (in_kernel_service(c.Eip)) {          /* woke and blocked again, or in a VxD service */
                t->idle += wgt; t->kern += wgt; t->streak = 0;
                if (site) note_wait(t, site, wgt);
                InterlockedExchangeAdd(&g_kern, (LONG)wgt);
            } else {
                t->busy += wgt; t->streak = 0;
                add(c.Eip);
                if (g_tg_lo && c.Eip - g_tg_lo < 0x60 && !IsBadReadPtr((void *)c.Esp, 12)) {   /* inside timeGetTime: */
                    DWORD *sp = (DWORD *)c.Esp;                 /* the return address is one of the top words */
                    add_to(g_tgc, 1024, sp[0]); add_to(g_tgc, 1024, sp[1]); add_to(g_tgc, 1024, sp[2]); g_tg_n += wgt;
                }
                InterlockedExchangeAdd(&g_busy, (LONG)wgt);
            }
            if (t->tid == g_main_tid) {
                if (c.Eip == t->last_eip && c.Esp == t->last_esp) { g_mi_idle += wgt; if (site) note_wait(&g_mw, site, wgt); }
                else if (in_kernel_service(c.Eip)) { g_mi_kern += wgt; if (site) note_wait(&g_mw, site, wgt); }
                else { g_mi_busy += wgt; add_to(g_mi, NMI, c.Eip); }
            }
            t->last_eip = c.Eip; t->last_esp = c.Esp;
        }
        g_self_cyc += __rdtsc() - c0;
        if ((round % 1200) == 0 && g_prof_on) write_report("still running - rewritten every 30 s");
        Sleep(25);
    }
    return 0;
}

/* network counters (ws_ext.c calls these for WSOCK32 recv/send/select when profiling) */
static volatile LONG g_rx, g_tx, g_nrecv, g_nsend, g_nsel; static unsigned __int64 g_selcyc;
void kex_prof_net(int kind, LONG bytes, unsigned __int64 cyc)
{
    if (!g_prof_on) return;
    if (kind == 0) { InterlockedIncrement(&g_nrecv); if (bytes > 0) InterlockedExchangeAdd(&g_rx, bytes); }
    else if (kind == 1) { InterlockedIncrement(&g_nsend); if (bytes > 0) InterlockedExchangeAdd(&g_tx, bytes); }
    else { InterlockedIncrement(&g_nsel); g_selcyc += cyc; }
}

/* build 131: crashlog_ext.c - the VxD-call trace (veh_ext.c) is not installed while the sampler runs */
int kex_prof_running(void) { return g_prof_on != 0; }

void kex_prof_start(const char *exe_path)
{
    HKEY k; DWORD v = 0, t, n = sizeof(v), tid; const char *s, *slash = NULL; char prog[33]; int m = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "Profile", NULL, &t, (BYTE *)&v, &n) != ERROR_SUCCESS || t != REG_DWORD) v = 0;
        RegCloseKey(k);
    }
    {   /* KexNG "UiBoost" = 1: the program's main (window) thread runs above normal priority, so on a single
         * CPU the page/window work goes ahead of decoders and helper threads (2026-11-02 experiment) */
        DWORD b = 0, bn = sizeof(b);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "UiBoost", NULL, &t, (BYTE *)&b, &bn) != ERROR_SUCCESS || t != REG_DWORD) b = 0;
            RegCloseKey(k);
        }
        if (b) { SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL); kex_trace("UiBoost: main thread above normal", GetCurrentThreadId(), 0, 0, 0); }
    }
    if (!v || g_prof_on) return;
    for (s = exe_path; *s; s++) if (*s == '\\') slash = s;
    if (!slash || slash - exe_path > MAX_PATH - 72) return;
    for (s = slash + 1; *s && *s != '.' && m < 32; s++) prog[m++] = (*s >= 'A' && *s <= 'Z') ? (char)(*s + 32) : *s;
    prog[m] = 0;
    lstrcpynA(g_prof_path, exe_path, (int)(slash - exe_path) + 2);
    lstrcatA(g_prof_path, "KEXPROF_"); lstrcatA(g_prof_path, prog);
    {   /* build 41: one file per kind of process - Chromium's helpers (--type=crashpad-handler, renderer, gpu-process)
         * run the same chrome.exe; the one that exited last overwrote the main process's profile */
        const char *c = GetCommandLineA(), *t = NULL; char ty[24]; int q = 0;
        for (; c && *c; c++) if (c[0] == '-' && c[1] == '-' && c[2] == 't' && c[3] == 'y' && c[4] == 'p' && c[5] == 'e' && c[6] == '=') { t = c + 7; break; }
        if (t) {
            for (; *t && *t != ' ' && *t != '"' && q < 22; t++) ty[q++] = (*t >= 'a' && *t <= 'z') || (*t >= 'A' && *t <= 'Z') || (*t >= '0' && *t <= '9') ? *t : '_';
            ty[q] = 0;
            if (q) { lstrcatA(g_prof_path, "_"); lstrcatA(g_prof_path, ty); }
        }
    }
    lstrcatA(g_prof_path, ".LOG");
    if (!(g_b = (BK *)VirtualAlloc(NULL, NB * sizeof(BK), MEM_COMMIT, PAGE_READWRITE))) return;
    g_t0 = GetTickCount();
    g_main_tid = GetCurrentThreadId();
    g_prof_on = 1;
    {
        HANDLE h = CreateThread(NULL, 0x10000, sampler, NULL, 0, &tid);
        if (h) { SetThreadPriority(h, THREAD_PRIORITY_TIME_CRITICAL); CloseHandle(h); }
        else g_prof_on = 0;
    }
}

/* ---- report */
static HANDLE g_f;
static void w(const char *s) { DWORD x; WriteFile(g_f, s, lstrlenA(s), &x, NULL); }
static void wd(DWORD v, int width) { char t[12]; int i = 11; t[i] = 0; do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v); while (11 - i < width) t[--i] = ' '; w(t + i); }
static void wx(DWORD v) { char t[9]; int i; for (i = 7; i >= 0; i--) { t[i] = "0123456789abcdef"[v & 15]; v >>= 4; } t[8] = 0; w(t); }
static void wpct(DWORD part, DWORD all) { DWORD p = all ? (DWORD)(((unsigned __int64)part * 1000) / all) : 0; wd(p / 10, 3); w("."); wd(p % 10, 1); w("%"); }

static DWORD mod_of(DWORD a, char *name, int cb)
{
    MEMORY_BASIC_INFORMATION m; char path[MAX_PATH]; const char *b, *s;
    lstrcpyA(name, "(no module: JIT code / heap)");
    if (a >= 0x80000000UL && a < 0xC0000000UL) lstrcpyA(name, "(shared arena: 16-bit Windows / VxD thunks)");
    if (a >= 0xC0000000UL) lstrcpyA(name, "(kernel)");
    if (!VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) || !m.AllocationBase) return 0;
    if (IsBadReadPtr(m.AllocationBase, 2) || *(WORD *)m.AllocationBase != IMAGE_DOS_SIGNATURE) return 0;
    if (!GetModuleFileNameA((HMODULE)m.AllocationBase, path, sizeof(path))) return 0;
    for (b = s = path; *s; s++) if (*s == '\\') b = s + 1;
    lstrcpynA(name, b, cb);
    return (DWORD)(ULONG_PTR)m.AllocationBase;
}

static BK *g_bc;                                        /* report works on copies: the sampler goes on */
static GC g_gcc[NG];
static volatile LONG g_rep_lock;
static const char *prio_name(int p)
{
    switch (p) {
    case THREAD_PRIORITY_IDLE: return "idle"; case THREAD_PRIORITY_LOWEST: return "lowest";
    case THREAD_PRIORITY_BELOW_NORMAL: return "below normal"; case THREAD_PRIORITY_NORMAL: return "normal";
    case THREAD_PRIORITY_ABOVE_NORMAL: return "above normal"; case THREAD_PRIORITY_HIGHEST: return "highest";
    case THREAD_PRIORITY_TIME_CRITICAL: return "time critical"; default: return "?";
    }
}
static void top_blocks(BK *b, DWORD nb, int count, DWORD total)
{
    int k; DWORD i;
    for (k = 0; k < count; k++) {
        int best = -1;
        for (i = 0; i < nb; i++) if (b[i].key && b[i].n && (best < 0 || b[i].n > b[best].n)) best = (int)i;
        if (best < 0) break;
        {
            char name[64]; DWORD a = b[best].key & ~0xFUL, base = mod_of(a, name, sizeof(name));
            w("  "); wpct(b[best].n, total); w("  "); wd(b[best].n, 6); w("  "); w(name);
            if (base) { w("+"); wx(a - base); } else { w(" "); wx(a); }
            w("\r\n");
            b[best].n = 0;
        }
    }
}
/* build 104: where this process's memory is (VirtualQuery walk), and Windows 98's memory counters over the run */
static void wmb(DWORD bytes) { wd(bytes >> 20, 6); w("."); wd(((bytes >> 10) & 1023) * 10 / 1024, 1); w(" MB"); }
static void mem_report(void)
{
    typedef struct { DWORD base, commit, reserve; } AB;
    static AB top[16], rtop[16]; int nt = 0, nrt = 0, i, k;
    static DWORD hcnt[7], hres[7], hcom[7];   /* build 110: allocations by reserved size: <64K <1M <2M <4M <16M <256M >=256M */
    DWORD a = 0x10000, priv = 0, img = 0, resv = 0, fre = 0, largest = 0, regions = 0, sh_commit = 0, sh_free = 0;
    DWORD cur_base = 0, cur_commit = 0, cur_reserve = 0, cur_img = 0;
    MEMORY_BASIC_INFORMATION m; MEMORYSTATUS gs;
    for (;;) {
        DWORD next, size;
        BOOL more = a < 0x80000000UL && VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) && m.RegionSize;
        DWORD ab = more ? (DWORD)(ULONG_PTR)m.AllocationBase : 0;
        if (!more || m.State == MEM_FREE || ab != cur_base) {    /* one allocation finished: keep the largest */
            if (cur_base && !cur_img && cur_commit) {
                int slot = -1;
                if (nt < 16) slot = nt++;
                else { int lo = 0; for (k = 1; k < 16; k++) if (top[k].commit < top[lo].commit) lo = k; if (top[lo].commit < cur_commit) slot = lo; }
                if (slot >= 0) { top[slot].base = cur_base; top[slot].commit = cur_commit; top[slot].reserve = cur_reserve; }
            }
            if (cur_base && !cur_img && cur_reserve) {           /* build 110: who holds the address space */
                int slot = -1, h = cur_reserve < 0x10000 ? 0 : cur_reserve < 0x100000 ? 1 : cur_reserve < 0x200000 ? 2 :
                                   cur_reserve < 0x400000 ? 3 : cur_reserve < 0x1000000 ? 4 : cur_reserve < 0x10000000 ? 5 : 6;
                hcnt[h]++; hres[h] += cur_reserve; hcom[h] += cur_commit;
                if (nrt < 16) slot = nrt++;
                else { int lo = 0; for (k = 1; k < 16; k++) if (rtop[k].reserve < rtop[lo].reserve) lo = k; if (rtop[lo].reserve < cur_reserve) slot = lo; }
                if (slot >= 0) { rtop[slot].base = cur_base; rtop[slot].commit = cur_commit; rtop[slot].reserve = cur_reserve; }
            }
            cur_base = 0; cur_commit = cur_reserve = 0; cur_img = 0;
            if (more && m.State != MEM_FREE) {
                cur_base = ab;
                cur_img = ab && !IsBadReadPtr((void *)(ULONG_PTR)ab, 2) && *(WORD *)(ULONG_PTR)ab == IMAGE_DOS_SIGNATURE;
            }
        }
        if (!more) break;
        size = (DWORD)m.RegionSize; regions++;
        if (m.State == MEM_FREE) { fre += size; if (size > largest) largest = size; }
        else if (m.State == MEM_RESERVE) { resv += size; cur_reserve += size; }
        else { if (cur_img) img += size; else priv += size; cur_commit += size; cur_reserve += size; }
        next = a + size;
        if (next <= a) break;
        a = next;
    }
    for (a = 0x80000000UL; a < 0xC0000000UL; ) {                 /* shared arena: the same for every process */
        DWORD next;
        if (!VirtualQuery((LPCVOID)(ULONG_PTR)a, &m, sizeof(m)) || !m.RegionSize) break;
        if (m.State == MEM_COMMIT) sh_commit += (DWORD)m.RegionSize;
        else if (m.State == MEM_FREE) sh_free += (DWORD)m.RegionSize;
        next = a + (DWORD)m.RegionSize;
        if (next <= a) break;
        a = next;
    }
    gs.dwLength = sizeof(gs); GlobalMemoryStatus(&gs);
    w("\r\nMEMORY OF THIS PROCESS NOW (private arena 00010000-7FFFFFFF)\r\n");
    w("  committed, not in a module (heaps, V8, buffers):"); wmb(priv); w("\r\n");
    w("  committed in modules (EXE/DLL images):         "); wmb(img); w("\r\n");
    w("  reserved only (address space, no memory):      "); wmb(resv); w("\r\n");
    w("  free address space:                            "); wmb(fre); w(", largest free block"); wmb(largest); w(", "); wd(regions, 1); w(" regions\r\n");
    w("  largest allocations outside modules (base, committed, reserved):\r\n");
    for (i = 0; i < nt; i++) {
        int b = -1;
        for (k = 0; k < nt; k++) if (top[k].commit && (b < 0 || top[k].commit > top[b].commit)) b = k;
        if (b < 0) break;
        w("    "); wx(top[b].base); wmb(top[b].commit); wmb(top[b].reserve); w("\r\n");
        top[b].commit = 0;
    }
    w("  largest address-space holders outside modules (base, committed, reserved):\r\n");
    for (i = 0; i < nrt; i++) {
        int b = -1;
        for (k = 0; k < nrt; k++) if (rtop[k].reserve && (b < 0 || rtop[k].reserve > rtop[b].reserve)) b = k;
        if (b < 0) break;
        w("    "); wx(rtop[b].base); wmb(rtop[b].commit); wmb(rtop[b].reserve); w("\r\n");
        rtop[b].reserve = 0;
    }
    {   static const char *hn[7] = { "under 64 KB  ", "64 KB-1 MB   ", "1-2 MB       ", "2-4 MB       ", "4-16 MB      ", "16-256 MB    ", "256 MB and up" };
        w("  allocations outside modules by reserved size (count, committed, reserved):\r\n");
        for (i = 0; i < 7; i++) if (hcnt[i]) { w("    "); w(hn[i]); wd(hcnt[i], 7); wmb(hcom[i]); wmb(hres[i]); w("\r\n"); }
        for (i = 0; i < 7; i++) hcnt[i] = hres[i] = hcom[i] = 0;
    }
    w("  shared arena 80000000-BFFFFFFF (all processes' shared memory, Windows DLLs): committed"); wmb(sh_commit); w(", free"); wmb(sh_free); w("\r\n");
    w("  Windows 98 GlobalMemoryStatus: load "); wd(gs.dwMemoryLoad, 1); w("%, physical free"); wmb((DWORD)gs.dwAvailPhys);
    w(" of"); wmb((DWORD)gs.dwTotalPhys); w(", page file free"); wmb((DWORD)gs.dwAvailPageFile); w(" of"); wmb((DWORD)gs.dwTotalPageFile); w("\r\n");
    if (g_nps) {
        w("\r\nWINDOWS 98 MEMORY COUNTERS DURING THE RUN (System Monitor's numbers, read once a second;\r\n");
        w("  cpg... = amounts of memory, c... = running totals - their change is what happened in this run)\r\n");
        for (i = 0; i < g_nps; i++) {
            PSV *v = &g_ps[i]; const char *b = v->name; const char *p;
            for (p = v->name; *p; p++) if (*p == '\\') b = p + 1;
            w("  "); w(v->name);
            for (k = lstrlenA(v->name); k < 28; k++) w(" ");
            if (b[0] == 'c' && b[1] == 'p' && b[2] == 'g') {       /* build 105: Windows 98 gives these in BYTES */
                w(" first"); wmb(v->first); w("  last"); wmb(v->last); w("  lowest"); wmb(v->mn); w("  highest"); wmb(v->mx);
            } else if (v->last < v->first) {                  /* a level, not a running total */
                w(" first "); wd(v->first, 10); w("  last "); wd(v->last, 10); w("  lowest "); wd(v->mn, 10); w("  highest "); wd(v->mx, 10);
            } else {
                w(" first "); wd(v->first, 10); w("  last "); wd(v->last, 10); w("  change "); wd(v->last - v->first, 10);
                if (g_cpu_n) { w(" = "); wd((v->last - v->first) / g_cpu_n, 1); w(" a second"); }
            }
            w("\r\n");
        }
    }
}

static void write_report(const char *why)
{
    typedef struct { char name[64]; DWORD base, n; } MS;
    static MS ms[96]; static char done[NT]; int nm = 0, i, j, k; DWORD total = g_samples, tsec;
    if (!g_bc && !(g_bc = (BK *)VirtualAlloc(NULL, NB * sizeof(BK), MEM_COMMIT, PAGE_READWRITE))) return;
    if (InterlockedExchange(&g_rep_lock, 1)) return;
    CopyMemory(g_bc, g_b, NB * sizeof(BK));
    CopyMemory(g_gcc, g_gc, sizeof(g_gcc));
    g_f = CreateFileA(g_prof_path, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
    if (g_f == INVALID_HANDLE_VALUE) { g_rep_lock = 0; return; }
    tsec = (GetTickCount() - g_t0) / 1000;
    w("KernelEx-NG profile ("); w(why); w("): "); wd(tsec, 1); w(" s, "); wd(g_nt, 1); w(" threads, every 25 ms;\r\n");
    w("  "); wd(total, 1); w(" thread-samples, "); wd(g_busy, 1); w(" of them RUNNING (the rest waiting)");
    if (g_lost) { w(", "); wd(g_lost, 1); w(" not stored"); } w("\r\n");
    w("  RUNNING = the thread had moved on since the last look (an upper bound on its CPU use);\r\n");
    w("  "); wd(g_kern, 1); w(" more samples were inside Windows kernel services (waits, Sleep, a taken critical section)\r\n");
    w("  profiler health: thread lists "); wd(g_d_refresh, 1); w(" (failed "); wd(g_d_snapfail, 1); w("), open failed "); wd(g_d_openfail, 1);
    w(", threads announced "); wd(g_d_attach, 1); w(", suspend failed "); wd(g_d_suspfail, 1); w(", context failed "); wd(g_d_ctxfail, 1); w("\r\n");
    if (g_cpu_n) {
        w("  CPU load (Windows 98's own counter, once a second): average "); wd(g_cpu_sum / g_cpu_n, 1); w("%; seconds at\r\n   ");
        for (i = 0; i < 11; i++) { w(" "); wd(i * 10, 1); w(i == 10 ? "%: " : "s: "); wd(g_cpu_h[i], 1); }
        w("\r\n");
    } else w("  CPU load counter not available\r\n");
    {   unsigned __int64 all = __rdtsc() - g_tsc0;
        w("  the profiler's own work (suspend/look/resume, counters): "); wpct((DWORD)(g_self_cyc >> 10), (DWORD)(all >> 10) ? (DWORD)(all >> 10) : 1);
        w(" of the time (an upper bound: includes waiting for a thread to stop)\r\n"); }
    w("\r\n");
    total = g_busy;
    for (i = 0; i < NB; i++) {                                   /* per module */
        char name[64]; DWORD base;
        if (!g_bc[i].key) continue;
        base = mod_of(g_bc[i].key & ~0xFUL, name, sizeof(name));
        for (j = 0; j < nm; j++) if (!lstrcmpA(ms[j].name, name)) break;
        if (j == nm) { if (nm >= 96) continue; lstrcpyA(ms[nm].name, name); ms[nm].base = base; ms[nm].n = 0; nm++; }
        ms[j].n += g_bc[i].n;
    }
    w("RUNNING TIME PER MODULE\r\n");
    for (k = 0; k < nm; k++) {                                   /* print by count, largest first */
        int best = -1;
        for (j = 0; j < nm; j++) if (ms[j].n && (best < 0 || ms[j].n > ms[best].n)) best = j;
        if (best < 0) break;
        w("  "); wpct(ms[best].n, total); w("  "); wd(ms[best].n, 7); w("  "); w(ms[best].name); w("\r\n");
        ms[best].n = 0;
    }
    w("\r\nTHREADS (running share of all running time; waiting share of its own life; priority; where it waits most)\r\n");
    for (i = 0; i < NT; i++) done[i] = 0;
    for (k = 0; k < g_nt; k++) {
        int b = -1, q;
        for (i = 0; i < g_nt; i++) if (!done[i] && g_t[i].n && (b < 0 || g_t[i].busy > g_t[b].busy)) b = i;
        if (b < 0) break;
        done[b] = 1;
        {
            TH *t = &g_t[b]; int wi = 0; char name[64]; DWORD base;
            for (q = 1; q < 8; q++) if (t->wn[q] > t->wn[wi]) wi = q;
            w("  thread "); wx(t->tid); w(t->tid == g_main_tid ? " MAIN" : "     ");
            w("  running "); wpct(t->busy, total ? total : 1); w("  waiting "); wpct(t->idle, t->n);
            if (t->kern) { w(" (kernel "); wpct(t->kern, t->n); w(")"); }
            if (t->h) { w("  "); w(prio_name(GetThreadPriority(t->h))); } else w("  ended");
            if (t->wn[wi]) { base = mod_of(t->wa[wi], name, sizeof(name)); w("  in "); w(name); if (base) { w("+"); wx(t->wa[wi] - base); } }
            { const char *kex_thread_name(DWORD tid); const char *tn = kex_thread_name(t->tid); if (tn) { w("  \""); w(tn); w("\""); } }
            w("\r\n");
        }
    }
    w("\r\nMAIN THREAD, LAST 30 SECONDS: running "); wd(g_mi_busy, 1); w(", waiting "); wd(g_mi_idle, 1);
    w(", in kernel services "); wd(g_mi_kern, 1); w(" samples\r\n");
    {
        int q; char name[64]; DWORD base;
        for (q = 0; q < 8; q++) if (g_mw.wn[q]) {
            base = mod_of(g_mw.wa[q], name, sizeof(name));
            w("  waits in "); w(name); if (base) { w("+"); wx(g_mw.wa[q] - base); } w(" ("); wd(g_mw.wn[q], 1); w(")\r\n");
        }
        top_blocks(g_mi, NMI, 25, g_mi_busy ? g_mi_busy : 1);
        ZeroMemory(g_mi, sizeof(g_mi)); ZeroMemory(&g_mw, sizeof(g_mw)); g_mi_busy = g_mi_idle = g_mi_kern = 0;
    }
    if (g_tg_n) {
        w("\r\nWINDOWS 98's OWN timeGetTime: "); wd(g_tg_n, 1);
        w(" running samples; words on top of the stack there (return addresses = its callers):\r\n");
        top_blocks(g_tgc, 1024, 12, g_tg_n * 3);
    }
    w("\r\nHOTTEST RUNNING CODE (16-byte blocks, all threads, whole run)\r\n");
    top_blocks(g_bc, NB, 60, total);
    w("\r\nGDI32 / USER32 / WINMM CALLS THROUGH THE GUARD (million CPU cycles incl. everything they call back -\r\n");
    w("  DispatchMessage includes the window procedure, MsgWait*/GetMessage include waiting; then calls)\r\n");
    for (k = 0; k < 80; k++) {
        int best = -1;
        for (i = 0; i < NG; i++) if (g_gcc[i].name && g_gcc[i].calls && (best < 0 || g_gcc[i].cyc > g_gcc[best].cyc)) best = i;
        if (best < 0) break;
        w("  "); wd((DWORD)(g_gcc[best].cyc / 1000000), 8); w(" Mcyc "); wd(g_gcc[best].calls, 9); w(" calls  "); w(g_gcc[best].name); w("\r\n");
        g_gcc[best].calls = 0;
    }
    w("\r\nNETWORK (WSOCK32): received "); wd((DWORD)g_rx / 1024, 1); w(" KB in "); wd(g_nrecv, 1); w(" recv calls, sent ");
    wd((DWORD)g_tx / 1024, 1); w(" KB in "); wd(g_nsend, 1); w(" send calls; "); wd(g_nsel, 1); w(" select calls, ");
    wd((DWORD)(g_selcyc / 1000000), 1); w(" million cycles inside select\r\n");
    {
        static const char *const lab[8] = { "<50ms", "<100", "<200", "<500", "<1s", "<2s", "<5s", ">=5s" };
        w("  connections "); wd(g_nconn, 1); w(", most open at once "); wd(g_open_max, 1); w("\r\n");
        w("  TCP connect (connect -> first send): "); if (g_n_tcp) { w("average "); wd(g_sum_tcp / g_n_tcp, 1); w(" ms;"); }
        for (i = 0; i < 8; i++) { w(" "); w(lab[i]); w(":"); wd(g_h_tcp[i], 1); } w("\r\n");
        w("  first data back (first send -> first recv): "); if (g_n_first) { w("average "); wd(g_sum_first / g_n_first, 1); w(" ms;"); }
        for (i = 0; i < 8; i++) { w(" "); w(lab[i]); w(":"); wd(g_h_first[i], 1); } w("\r\n");
        w("  name lookups (gethostbyname): "); wd(g_dns_n, 1); if (g_dns_n) { w(", average "); wd(g_dns_sum / g_dns_n, 1); w(" ms, longest "); wd(g_dns_max, 1); w(" ms;"); }
        for (i = 0; i < 8; i++) { w(" "); w(lab[i]); w(":"); wd(g_h_dns[i], 1); } w("\r\n");
        if (g_big_ms) { w("  connections that received 100 KB or more (closed): "); wd(g_big_rx / 1024, 1); w(" KB in "); wd(g_big_ms, 1);
                        w(" ms = "); wd((DWORD)((unsigned __int64)g_big_rx * 1000 / 1024 / g_big_ms), 1); w(" KB/s while open\r\n"); }
    }
    mem_report();
    CloseHandle(g_f);
    g_rep_lock = 0;
}

void kex_prof_report(const char *why)
{
    if (!InterlockedExchange(&g_prof_on, 0) || !g_b) return;
    Sleep(30);                                               /* let the sampler finish its round */
    while (g_rep_lock) Sleep(10);                            /* a periodic report in progress */
    write_report(why);
    perfstat("PerfStats\\StopStat", NULL);
}
