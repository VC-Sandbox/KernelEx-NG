/*
 * kexdbg.c - minimal Win32 debugger / crash logger for Windows 98 (KernelEx-NG test tool).
 *
 *   KEXDBG [-all] program [arguments...]
 *
 * Starts the program under the debug API (only that process) and writes KEXDBG.LOG in the current
 * folder: every module with its load address and size (name read from the module's own export
 * directory, because Win98 rarely fills lpImageName), OutputDebugString text, every exception
 * (code, address as module+offset), and for breakpoints / unhandled exceptions the registers, the
 * bytes around EIP, an EBP frame walk and every stack value that points into a loaded module.
 * Breakpoints other than the loader's initial one are logged (Chromium's IMMEDIATE_CRASH is int3;ud2).
 * -all also dumps a full report for every first-chance exception (default: one line each).
 *
 *   KEXDBG -attach <program name or hex process id> [-log file]       (build 55d)
 * Attaches to an already running program (e.g. EXPLORER.EXE) instead of starting one. Every access
 * violation / illegal instruction then gets the full report, plus a raw stack dump around ESP and the
 * bytes before EIP, so a call that came back with the stack or registers wrong can be seen. Windows 98
 * cannot detach a debugger: closing KEXDBG ends the attached program too.
 *
 * Logging breakpoints: if KEXDBG.BP exists in the current folder (or -bp <file> is given), each line
 *   <hex address> <label> [[@]<reg>+<hexoff>|[@]<reg>-<hexoff> <hexlen>]   (@ = dump where that dword points)
 * puts an int3 at that absolute address once its module is loaded. Each hit (up to 200 per breakpoint)
 * logs the registers, 8 stack dwords and optionally a memory dump at register+offset, then the original
 * byte is put back, one instruction is single-stepped and the breakpoint is re-armed. The program is not
 * otherwise disturbed. Lines starting with '#' are comments.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <intrin.h>

typedef struct { DWORD base, size; char name[64]; } MOD;
static MOD   g_mod[512];
static int   g_nmod;
static struct { DWORD id; HANDLE h; } g_thr[256];
static int   g_nthr;
static HANDLE g_proc;
static FILE  *g_log;
static int   g_all;

typedef struct { DWORD a; char label[64]; char reg[4]; LONG off; DWORD mlen; BYTE orig; int armed, hits, deref; } BP;
static BP    g_bp[128];
static int   g_nbp;
static struct { DWORD tid; int bp; } g_step[64];
static int   g_nstep;

static void L(const char *fmt, ...)
{
    va_list a;
    va_start(a, fmt); vfprintf(g_log, fmt, a); va_end(a);
    fflush(g_log);
}

static BOOL rd(DWORD addr, void *buf, DWORD n)
{
    DWORD got = 0;
    return ReadProcessMemory(g_proc, (LPCVOID)addr, buf, n, &got) && got == n;
}

/* module name from the export directory, else the PE file name we were given */
static BOOL wr(DWORD addr, const void *buf, DWORD n)
{
    DWORD got = 0, old = 0;
    typedef BOOL (WINAPI *VPEX)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
    static VPEX vpex;
    if (WriteProcessMemory(g_proc, (LPVOID)addr, buf, n, &got) && got == n) return TRUE;
    if (!vpex) vpex = (VPEX)(void *)GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "VirtualProtectEx");
    if (vpex && vpex(g_proc, (LPVOID)addr, n, PAGE_EXECUTE_READWRITE, &old)) {
        BOOL ok = WriteProcessMemory(g_proc, (LPVOID)addr, buf, n, &got) && got == n;
        vpex(g_proc, (LPVOID)addr, n, old, &old);
        return ok;
    }
    return FALSE;
}

static void bp_load(const char *file)
{
    FILE *f = fopen(file, "r"); char line[256];
    if (!f) return;
    while (fgets(line, sizeof(line), f) && g_nbp < 128) {
        BP *b = &g_bp[g_nbp]; char mem[32] = ""; unsigned long a = 0, len = 0;
        if (line[0] == '#' || line[0] == ';') continue;
        memset(b, 0, sizeof(*b));
        if (sscanf(line, "%lx %63s %31s %lx", &a, b->label, mem, &len) < 2 || !a) continue;
        b->a = a;
        if (mem[0] && len) {
            char *pm;
            if (mem[0] == '@') { b->deref = 1; memmove(mem, mem + 1, strlen(mem)); }
            pm = strpbrk(mem, "+-");
            if (pm) { b->off = (LONG)strtoul(pm + 1, NULL, 16); if (*pm == '-') b->off = -b->off; *pm = 0; }
            lstrcpynA(b->reg, mem, sizeof(b->reg)); b->mlen = len > 256 ? 256 : len;
        }
        g_nbp++;
    }
    fclose(f);
    L("kexdbg: %d breakpoint(s) from %s\n", g_nbp, file);
}

static const MOD *mod_of(DWORD a);
static const char *where(DWORD a);

static void bp_arm_all(void)
{
    int i; BYTE cc = 0xCC;
    for (i = 0; i < g_nbp; i++) {
        BP *b = &g_bp[i];
        if (b->armed || b->hits >= 200 || !mod_of(b->a)) continue;
        if (!b->orig && !rd(b->a, &b->orig, 1)) continue;
        if (wr(b->a, &cc, 1)) { b->armed = 1; FlushInstructionCache(g_proc, (LPCVOID)b->a, 1); }
        else { L("BP %s at %s: cannot write (error %lu)\n", b->label, where(b->a), GetLastError()); b->hits = 200; }
    }
}

static DWORD reg_of(const CONTEXT *c, const char *r)
{
    if (!lstrcmpiA(r, "eax")) return c->Eax; if (!lstrcmpiA(r, "ebx")) return c->Ebx;
    if (!lstrcmpiA(r, "ecx")) return c->Ecx; if (!lstrcmpiA(r, "edx")) return c->Edx;
    if (!lstrcmpiA(r, "esi")) return c->Esi; if (!lstrcmpiA(r, "edi")) return c->Edi;
    if (!lstrcmpiA(r, "ebp")) return c->Ebp; return c->Esp;
}

static HANDLE thr_of(DWORD id);

/* returns TRUE if the breakpoint exception was ours */
static BOOL bp_hit(DWORD tid, DWORD addr)
{
    int i; HANDLE h = thr_of(tid); CONTEXT c; DWORD st[8]; BYTE m[256];
    for (i = 0; i < g_nbp; i++) if (g_bp[i].armed && g_bp[i].a == addr) break;
    if (i == g_nbp || !h) return FALSE;
    memset(&c, 0, sizeof(c)); c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(h, &c)) return FALSE;
    g_bp[i].hits++;
    L("BP %s #%d thread %08lx  EAX=%08lx EBX=%08lx ECX=%08lx EDX=%08lx ESI=%08lx EDI=%08lx EBP=%08lx ESP=%08lx\n",
      g_bp[i].label, g_bp[i].hits, tid, c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi, c.Ebp, c.Esp);
    if (mod_of(c.Eax)) L("   EAX -> %s\n", where(c.Eax));
    else if (c.Eax >= 0x10000) {                      /* e.g. a Win9x debug thunk: show where it leads */
        BYTE t[24]; DWORD k;
        if (rd(c.Eax, t, sizeof(t))) {
            L("   EAX bytes:"); for (k = 0; k < sizeof(t); k++) L(" %02x", t[k]); L("\n");
            if (t[0] == 0x68 && t[5] == 0xE9) {       /* push imm32 ; jmp rel32 */
                DWORD tgt = c.Eax + 10 + *(DWORD *)(t + 6);
                L("   push %08lx (%s) ; jmp %08lx (%s)\n", *(DWORD *)(t + 1), where(*(DWORD *)(t + 1)), tgt, where(tgt));
            }
            for (k = 0; k + 5 <= sizeof(t); k++)        /* any absolute pointer into a module */
                if (mod_of(*(DWORD *)(t + k))) L("   +%lu -> %s\n", k, where(*(DWORD *)(t + k)));
        }
    }
    if (rd(c.Esp, st, sizeof(st)))
        L("   [esp] %08lx %08lx %08lx %08lx %08lx %08lx %08lx %08lx\n", st[0], st[1], st[2], st[3], st[4], st[5], st[6], st[7]);
    if (g_bp[i].mlen) {
        DWORD at = reg_of(&c, g_bp[i].reg) + g_bp[i].off, k;
        if (g_bp[i].deref && !rd(at, &at, 4)) at = 0;
        if (at && rd(at, m, g_bp[i].mlen)) {
            L("   [%s%s%+ld] @%08lx:", g_bp[i].deref ? "@" : "", g_bp[i].reg, g_bp[i].off, at);
            for (k = 0; k + 4 <= g_bp[i].mlen; k += 4) L(" %08lx", *(DWORD *)(m + k));
            L("  \"");
            for (k = 0; k < g_bp[i].mlen; k++) L("%c", (m[k] >= 32 && m[k] < 127) ? m[k] : '.');
            L("\"\n");
        } else L("   [%s%+ld] @%08lx unreadable\n", g_bp[i].reg, g_bp[i].off, at);
    }
    wr(addr, &g_bp[i].orig, 1); FlushInstructionCache(g_proc, (LPCVOID)addr, 1);
    g_bp[i].armed = 0;
    c.Eip = addr; c.EFlags |= 0x100;
    SetThreadContext(h, &c);
    if (g_nstep < 64) { g_step[g_nstep].tid = tid; g_step[g_nstep].bp = i; g_nstep++; }
    return TRUE;
}

/* single-step after a breakpoint: re-arm it */
static BOOL bp_step(DWORD tid)
{
    int k;
    for (k = 0; k < g_nstep; k++) if (g_step[k].tid == tid) {
        g_step[k] = g_step[--g_nstep];
        bp_arm_all();
        return TRUE;
    }
    return FALSE;
}

static void mod_add(DWORD base, const char *hint)
{
    BYTE hdr[0x400]; DWORD pe, size = 0, exprva = 0, nameptr = 0; char nm[64] = "";
    int i;
    if (g_nmod >= 512) return;
    if (rd(base, hdr, sizeof(hdr)) && hdr[0] == 'M' && hdr[1] == 'Z') {
        pe = *(DWORD *)(hdr + 0x3C);
        if (pe < sizeof(hdr) - 0x100) {
            size = *(DWORD *)(hdr + pe + 0x50);
            exprva = *(DWORD *)(hdr + pe + 0x78);
            if (exprva && rd(base + exprva + 12, &nameptr, 4) && nameptr) {
                rd(base + nameptr, nm, sizeof(nm) - 1); nm[sizeof(nm) - 1] = 0;
                for (i = 0; nm[i]; i++) if ((BYTE)nm[i] < 32) { nm[i] = 0; break; }
            }
        }
    }
    if (!nm[0] && hint) lstrcpynA(nm, hint, sizeof(nm));
    if (!nm[0]) lstrcpyA(nm, "?");
    for (i = 0; i < g_nmod; i++) if (g_mod[i].base == base) { g_mod[i].size = size; lstrcpyA(g_mod[i].name, nm); return; }
    g_mod[g_nmod].base = base; g_mod[g_nmod].size = size; lstrcpyA(g_mod[g_nmod].name, nm); g_nmod++;
    L("LOAD %08lx %08lx %s\n", base, size, nm);
}

static void mod_del(DWORD base)
{
    int i;
    for (i = 0; i < g_nmod; i++) if (g_mod[i].base == base) {
        L("UNLOAD %08lx %s\n", base, g_mod[i].name); g_mod[i] = g_mod[--g_nmod]; return;
    }
}

static const MOD *mod_of(DWORD a)
{
    int i;
    for (i = 0; i < g_nmod; i++) if (a >= g_mod[i].base && a - g_mod[i].base < g_mod[i].size) return &g_mod[i];
    return NULL;
}

static const char *where(DWORD a)
{
    static char b[4][96]; static int k;
    const MOD *m = mod_of(a); char *s = b[k++ & 3];
    if (m) sprintf(s, "%s+%lx", m->name, a - m->base); else sprintf(s, "%08lx", a);
    return s;
}

static HANDLE thr_of(DWORD id)
{
    int i;
    for (i = 0; i < g_nthr; i++) if (g_thr[i].id == id) return g_thr[i].h;
    return NULL;
}

/* readable text on the stack: CHECK / LOG(FATAL) messages are copied there before the crash */
static void strings_from(const BYTE *b, int len, DWORD at)
{
    int i = 0, shown = 0;
    L("  text on the stack (ESP+offset):\n");
    while (i < len && shown < 80) {
        int j = i;
        while (j < len && b[j] >= 32 && b[j] < 127) j++;
        if (j - i >= 6) { L("    +%03x A \"%.*s\"\n", i, (j - i) > 300 ? 300 : j - i, (const char *)b + i); shown++; i = j; continue; }
        j = i;
        while (j + 1 < len && b[j] >= 32 && b[j] < 127 && b[j + 1] == 0) j += 2;
        if ((j - i) / 2 >= 6) {
            char t[301]; int k, m = 0;
            for (k = i; k < j && m < 300; k += 2) t[m++] = (char)b[k];
            t[m] = 0; L("    +%03x W \"%s\"\n", i, t); shown++; i = j; continue;
        }
        i++;
    }
    (void)at;
}

static int g_stall;   /* build 131: -stall N = no debug event for N s -> report every thread once per stall */
static void report(DWORD tid);
static void report_all(const char *why)
{
    int i;
    L("=== %s: all %d known threads\n", why, g_nthr);
    for (i = 0; i < g_nthr; i++) { L("--- thread %08lx\n", g_thr[i].id); report(g_thr[i].id); }
    fflush(g_log);
}
static void report(DWORD tid)
{
    CONTEXT c; HANDLE h = thr_of(tid); BYTE code[48]; DWORD st[1024], ebp, fr[2]; int i, n;
    if (!h) { L("  (no thread handle)\n"); return; }
    memset(&c, 0, sizeof(c));
    c.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(h, &c)) { L("  GetThreadContext failed %lu\n", GetLastError()); return; }
    L("  EAX=%08lx EBX=%08lx ECX=%08lx EDX=%08lx ESI=%08lx EDI=%08lx\n", c.Eax, c.Ebx, c.Ecx, c.Edx, c.Esi, c.Edi);
    L("  EIP=%08lx (%s) ESP=%08lx EBP=%08lx EFL=%08lx\n", c.Eip, where(c.Eip), c.Esp, c.Ebp, c.EFlags);
    if (rd(c.Eip - 16, code, sizeof(code))) {
        L("  code @EIP-16:");
        for (i = 0; i < 48; i++) L("%s%02x", i == 16 ? " |" : " ", code[i]);
        L("\n");
    }
    L("  EBP frames:\n");
    ebp = c.Ebp;
    for (i = 0; i < 64 && ebp && rd(ebp, fr, 8); i++) {
        L("    %08lx  ret %s\n", ebp, where(fr[1]));
        if (i < 12 && !strchr(where(fr[1]), '+')) {   /* 2026-11-27: generated code (no module): the bytes before the return */
            BYTE cb[768]; int j, nb = i < 2 ? 768 : (i < 3 ? 256 : 64);
            if (rd(fr[1] - nb, cb, nb)) { L("      code before:"); for (j = 0; j < nb; j++) L(" %02x", cb[j]); L("\n"); }
        }
        if (fr[0] <= ebp) break;
        ebp = fr[0];
    }
    {   /* raw stack around ESP: shows return addresses / saved registers one slot off */
        DWORD w[96]; int k;
        if (rd(c.Esp - 0x80, w, sizeof(w))) {
            L("  raw stack ESP-80 .. ESP+17c:\n");
            for (k = 0; k < 96; k += 4)
                L("    %08lx%s %08lx %08lx %08lx %08lx\n", c.Esp - 0x80 + k * 4, k == 32 ? "*" : " ", w[k], w[k + 1], w[k + 2], w[k + 3]);
        }
        if (c.Ebp > c.Esp && c.Ebp - c.Esp < 0x4000 && rd(c.Ebp - 0x40, w, 0x60)) {
            L("  raw stack EBP-40 .. EBP+1c:\n");
            for (k = 0; k < 24; k += 4) L("    %08lx %08lx %08lx %08lx %08lx\n", c.Ebp - 0x40 + k * 4, w[k], w[k + 1], w[k + 2], w[k + 3]);
        }
        if (rd(c.Eip - 64, code, 48)) {
            L("  code @EIP-64:"); for (k = 0; k < 48; k++) L(" %02x", code[k]); L("\n");
        }
    }
    n = 0;
    while (n < 1024 && rd(c.Esp + n * 4, &st[n], 4)) n++;
    L("  stack values pointing into modules (ESP+offset):\n");
    for (i = 0; i < n; i++) if (mod_of(st[i])) L("    +%03x %08lx %s\n", i * 4, st[i], where(st[i]));
    strings_from((const BYTE *)st, n * 4, c.Esp);
}

int main(int argc, char **argv)
{
    char cmd[2048] = ""; STARTUPINFOA si; PROCESS_INFORMATION pi; DEBUG_EVENT ev;
    int i, a = 1, nexc = 0; BOOL first_bp = TRUE, done = FALSE;

    const char *bpfile = "KEXDBG.BP", *attach = NULL, *logname = "KEXDBG.LOG";
    for (;;) {
        if (a + 1 < argc && !lstrcmpiA(argv[a], "-attach")) { attach = argv[a + 1]; g_all = 1; a += 2; continue; }
        if (a + 1 < argc && !lstrcmpiA(argv[a], "-stall")) { g_stall = atoi(argv[a + 1]); a += 2; continue; }   /* build 131 */
        if (a + 1 < argc && !lstrcmpiA(argv[a], "-log")) { logname = argv[a + 1]; a += 2; continue; }
        if (a < argc && !lstrcmpiA(argv[a], "-all")) { g_all = 1; a++; continue; }
        if (a + 1 < argc && !lstrcmpiA(argv[a], "-bp")) { bpfile = argv[a + 1]; a += 2; continue; }
        break;
    }
    if (a >= argc && !attach) { printf("usage: KEXDBG [-all] [-bp file] program [arguments...]\n       KEXDBG -attach EXPLORER.EXE [-log file]\n"); return 1; }
    for (i = a; i < argc; i++) {
        if (i > a) lstrcatA(cmd, " ");
        if (strchr(argv[i], ' ')) { lstrcatA(cmd, "\""); lstrcatA(cmd, argv[i]); lstrcatA(cmd, "\""); }
        else lstrcatA(cmd, argv[i]);
    }
    if (!(g_log = fopen(logname, "a"))) { printf("cannot create %s\n", logname); return 1; }
    {
        SYSTEMTIME t; OSVERSIONINFOA ov; int r[4]; char vend[13];
        GetLocalTime(&t); ov.dwOSVersionInfoSize = sizeof(ov); GetVersionExA(&ov);
        __cpuid(r, 0); memcpy(vend, &r[1], 4); memcpy(vend + 4, &r[3], 4); memcpy(vend + 8, &r[2], 4); vend[12] = 0;
        __cpuid(r, 1);
        L("\n##### kexdbg %04d-%02d-%02d %02d:%02d:%02d  Windows %lu.%lu.%lu  CPU %s family/model/stepping %08x\n",
          t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, ov.dwMajorVersion, ov.dwMinorVersion, ov.dwBuildNumber & 0xFFFF, vend, r[0]);
    }
    if (attach) {
        DWORD pid = 0; HANDLE sn; PROCESSENTRY32 pe;
        sn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pe.dwSize = sizeof(pe);
        if (sn != INVALID_HANDLE_VALUE && Process32First(sn, &pe)) do {
            const char *b = pe.szExeFile, *q;
            for (q = pe.szExeFile; *q; q++) if (*q == '\\') b = q + 1;
            if (!lstrcmpiA(b, attach)) { pid = pe.th32ProcessID; break; }
        } while (Process32Next(sn, &pe));
        if (sn != INVALID_HANDLE_VALUE) CloseHandle(sn);
        if (!pid) pid = strtoul(attach, NULL, 16);
        L("kexdbg: attach to %s (process %08lx)\n", attach, pid);
        if (!pid || !DebugActiveProcess(pid)) {
            L("attach failed %lu\n", GetLastError()); printf("cannot attach to %s (error %lu)\n", attach, GetLastError()); return 1;
        }
        printf("attached to %s - leave this window open (closing it ends %s).\nlog: %s\n", attach, attach, logname);
        first_bp = TRUE;
    } else {
    L("kexdbg: %s\n", cmd);
    bp_load(bpfile);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        L("CreateProcess failed %lu\n", GetLastError()); printf("CreateProcess failed %lu\n", GetLastError()); return 1;
    }
    g_proc = pi.hProcess;
    printf("running under kexdbg - log goes to %s\n", logname);
    }

    for (;;) {
        DWORD cont = DBG_CONTINUE;
        static DWORD quiet, stalled;
        if (done) break;
        if (!WaitForDebugEvent(&ev, g_stall ? 1000 : INFINITE)) {
            if (!g_stall || GetLastError() != ERROR_SEM_TIMEOUT && GetLastError() != WAIT_TIMEOUT) { if (!g_stall) break; }
            if (++quiet == (DWORD)g_stall && !stalled) { stalled = 1; report_all("STALL (no debug event)"); }
            continue;
        }
        quiet = 0; stalled = 0;
        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            if (ev.u.CreateProcessInfo.hProcess) g_proc = ev.u.CreateProcessInfo.hProcess;
            g_thr[g_nthr].id = ev.dwThreadId; g_thr[g_nthr++].h = ev.u.CreateProcessInfo.hThread;
            mod_add((DWORD)ev.u.CreateProcessInfo.lpBaseOfImage, "EXE");
            bp_arm_all();
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (g_nthr < 256) { g_thr[g_nthr].id = ev.dwThreadId; g_thr[g_nthr++].h = ev.u.CreateThread.hThread; }
            L("THREAD+ %08lx start %s\n", ev.dwThreadId, where((DWORD)ev.u.CreateThread.lpStartAddress));
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            L("THREAD- %08lx exit %lu\n", ev.dwThreadId, ev.u.ExitThread.dwExitCode);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            mod_add((DWORD)ev.u.LoadDll.lpBaseOfDll, NULL);
            bp_arm_all();
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            mod_del((DWORD)ev.u.UnloadDll.lpBaseOfDll);
            break;
        case OUTPUT_DEBUG_STRING_EVENT: {
            char s[1024]; DWORD n = ev.u.DebugString.nDebugStringLength;
            if (n >= sizeof(s)) n = sizeof(s) - 1;
            if (!ev.u.DebugString.fUnicode && n && rd((DWORD)ev.u.DebugString.lpDebugStringData, s, n)) {
                s[n] = 0; L("ODS: %s%s", s, (n && s[n - 1] == '\n') ? "" : "\n");
            }
            break;
        }
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD *er = &ev.u.Exception.ExceptionRecord;
            DWORD code = er->ExceptionCode, addr = (DWORD)er->ExceptionAddress;
            BOOL fc = ev.u.Exception.dwFirstChance != 0;
            if (code == EXCEPTION_BREAKPOINT && first_bp) { first_bp = FALSE; L("initial breakpoint at %s\n", where(addr)); bp_arm_all(); break; }
            if (code == EXCEPTION_BREAKPOINT && bp_hit(ev.dwThreadId, addr)) break;
            if (code == EXCEPTION_SINGLE_STEP && bp_step(ev.dwThreadId)) break;
            {   /* 2026-11-27: first-chance faults are logged 3 times per (code, address) - a probing loop (Windows 98's
                 * IsBadReadPtr at KERNEL32+ba0b: hundreds per .NET start) no longer fills the 500-line budget */
                static DWORD site_code[256], site_addr[256], site_n[256]; static int nsite; int k, show = !fc;
                if (fc) {
                    for (k = 0; k < nsite; k++) if (site_code[k] == code && site_addr[k] == addr) break;
                    if (k == nsite && nsite < 256) { site_code[k] = code; site_addr[k] = addr; site_n[k] = 0; nsite++; }
                    if (k < 256 && ++site_n[k] <= 3 && nexc++ < 500) show = 1;
                    if (k < 256 && site_n[k] == 4) L("EXC first %08lx at %s: further ones not logged\n", code, where(addr));
                }
                if (show) {
                    L("EXC %s %08lx at %s thread %08lx", fc ? "first" : "SECOND", code, where(addr), ev.dwThreadId);
                    if (code == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
                        L(" (%s %08lx)", er->ExceptionInformation[0] ? "write" : "read", er->ExceptionInformation[1]);
                    else if (er->NumberParameters) {
                        DWORD j; L(" params");
                        for (j = 0; j < er->NumberParameters && j < 4; j++) L(" %08lx", er->ExceptionInformation[j]);
                    }
                    L("\n");
                }
            }
            if (!fc || code == EXCEPTION_BREAKPOINT || code == EXCEPTION_ILLEGAL_INSTRUCTION || g_all) report(ev.dwThreadId);
            cont = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            L("EXIT process code %08lx\n", ev.u.ExitProcess.dwExitCode);
            done = TRUE;
            break;
        case RIP_EVENT:
            L("RIP error %lu type %lu\n", ev.u.RipInfo.dwError, ev.u.RipInfo.dwType);
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
    }
    L("kexdbg: done\n");
    fclose(g_log);
    printf("done - see %s\n", logname);
    return 0;
}
