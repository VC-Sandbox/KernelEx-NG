/*
 * gdiguard_ext.c - KernelEx-NG: stack/register guard around a few GDI32 calls Mypal's drawing code makes.
 *
 * Mypal (cairo in gkmedias.dll) crashed at the same instruction three times (2026-11-02, YouTube): right after
 * _cairo_win32_surface_create_for_dc - CreateCompatibleDC, CreateDIBSection, GdiFlush, SelectObject - its
 * ESI/EDI held garbage (2, 0x332a). That function saves and restores them correctly; its epilogue pops them with
 * ESP-relative pops, so one of the GDI calls in between must have come back with ESP off (one earlier crash even
 * returned to 000016FB right after SelectObject). kexnt now makes these calls through a guard: it calls the
 * implementation that would have run anyway (KernelEx's own fix in kexbasen/kexbases if there is one, else
 * GDI32 itself), then puts ESP, EBX, ESI, EDI and EBP back as the caller left them and writes a line to
 * KEXTRACE_<program>.LOG ("gdi guard: <name> ...") whenever the callee had changed them.
 */
#include "kexnt_common.h"

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
LONG kex_prof_enabled(void);                                   /* prof_ext.c */
void kex_prof_call(const char *name, unsigned __int64 cyc);
#include <intrin.h>

typedef struct { DWORD ebp, esp_before, esp_after, result, old14, ebx, esi, edi, ebx2, esi2, edi2, ebp2;
                 DWORD magic, retries; const char *name; DWORD seh, seh2; } GSAVE;   /* 55c: magic/retries/name for guard_recover; 108: FS:[0] before/after */
#define GSAVE_MAGIC 0x4452474Bu   /* "KGRD" */

/* cdecl DWORD guard_call(void *fn, int nargs, const DWORD *args, GSAVE *s): pushes the args (stdcall callee),
 * calls, then restores everything from TIB+0x14 (pvArbitrary), which survives a wrecked stack and registers. */
DWORD guard_call(void *fn, int nargs, const DWORD *args, GSAVE *s);
__asm__(
    ".text\n.globl _guard_call\n_guard_call:\n"
    "  pushl %ebp\n  movl %esp, %ebp\n  pushl %ebx\n  pushl %esi\n  pushl %edi\n"
    "  movl 20(%ebp), %eax\n"
    "  movl %fs:0x14, %ecx\n  movl %ecx, 16(%eax)\n  movl %eax, %fs:0x14\n"
    "  movl %ebp, 0(%eax)\n  movl %ebx, 20(%eax)\n  movl %esi, 24(%eax)\n  movl %edi, 28(%eax)\n"
    "  movl %fs:0, %edx\n  movl %edx, 60(%eax)\n"            /* build 108: exception-frame chain head on entry (a retry keeps it) */
    "  movl 12(%ebp), %ecx\n  movl 16(%ebp), %edx\n"
    "1: testl %ecx, %ecx\n  jz 2f\n  pushl -4(%edx,%ecx,4)\n  decl %ecx\n  jmp 1b\n"
    "2: movl %esp, 4(%eax)\n"
    "  call *8(%ebp)\n"
    "  jmp 5f\n"
    /* build 55c: guard_recover() resumes here (EBP = this frame, ESP = EBP-12, TIB+0x14 = our save area) when
     * the call jumped to a junk address: push the arguments again and call once more */
    ".globl _guard_retry\n_guard_retry:\n"
    "  movl %fs:0x14, %eax\n  movl 12(%ebp), %ecx\n  movl 16(%ebp), %edx\n  jmp 1b\n"
    "5:\n"
    "  movl %fs:0x14, %ecx\n"
    /* skip save areas left behind by inner guarded calls that an exception unwound past: they lie below the
     * current ESP, ours lies above it (in guarded_in's frame) */
    "3: cmpl %esp, %ecx\n  jae 4f\n  testl %ecx, %ecx\n  jz 4f\n  movl 16(%ecx), %ecx\n  jmp 3b\n"
    "4:\n"
    "  movl %esp, 8(%ecx)\n  movl %eax, 12(%ecx)\n"
    "  movl %ebx, 32(%ecx)\n  movl %esi, 36(%ecx)\n  movl %edi, 40(%ecx)\n  movl %ebp, 44(%ecx)\n"
    /* build 108: a stdcall callee always leaves FS:[0] as it found it; a 16-bit thunk that came back abnormally
     * (ESP off) may leave it at a frame below our restored ESP -> the next thunk's unlink crashes (build 91:
     * GDI32+4b79 "pop fs:[0]" in CreateRectRgnIndirect right after three bad GetWindowDC). Put it back. */
    "  movl %fs:0, %edx\n  movl %edx, 64(%ecx)\n  movl 60(%ecx), %edx\n  movl %edx, %fs:0\n"
    "  movl 0(%ecx), %ebp\n"
    "  movl 16(%ecx), %edx\n  movl %edx, %fs:0x14\n"
    "  leal -12(%ebp), %esp\n  popl %edi\n  popl %esi\n  popl %ebx\n  popl %ebp\n  ret\n");

/* the implementation that would run without kexnt: an earlier KernelEx api library's entry (kexbasen, then
 * kexbases), else the system DLL's own export. Also used by tls_ext.c (TlsAlloc). */
typedef struct { const char *name; unsigned long addr; } NAPI;
typedef struct { const char *lib; const NAPI *named; int nnamed; const void *ord; int nord; } ATAB;
typedef const ATAB *(*T_GAT)(void);

FARPROC kex_prev_impl(const char *dll, const char *name)
{
    static const char *libs[] = { "KEXBASEN.DLL", "KEXBASES.DLL" };
    char path[MAX_PATH], *slash; int l, i, k;
    for (l = 0; l < 2; l++) {
        HMODULE h = GetModuleHandleA(libs[l]);
        T_GAT gat;
        if (!h) {   /* KernelEx's folder from its InstallDir (kexnt may be a test copy elsewhere, e.g. C:\\KEXTEST) */
            HKEY k; DWORD t, n = MAX_PATH - 16;
            path[0] = 0;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx", 0, KEY_READ, &k) == ERROR_SUCCESS) {
                if (RegQueryValueExA(k, "InstallDir", NULL, &t, (BYTE *)path, &n) != ERROR_SUCCESS || t != REG_SZ) path[0] = 0;
                RegCloseKey(k);
            }
            if (!path[0]) continue;
            path[MAX_PATH - 17] = 0;
            for (slash = NULL, i = 0; path[i]; i++) slash = path + i;
            if (slash && *slash != '\\') lstrcatA(path, "\\");
            lstrcatA(path, libs[l]);
            h = LoadLibraryA(path);
        }
        if (!h || !(gat = (T_GAT)(void *)GetProcAddress(h, "get_api_table"))) continue;
        {
            const ATAB *t = gat();
            for (; t && t->lib; t++) {
                if (lstrcmpiA(t->lib, dll)) continue;
                for (k = 0; k < t->nnamed; k++)
                    if (t->named[k].name && !lstrcmpA(t->named[k].name, name) && t->named[k].addr)
                        return (FARPROC)t->named[k].addr;
            }
        }
    }
    return kex_sysproc(dll, name);
}

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
/* ---- build 55c: recovery. Windows 98's 16-bit USER thunks sometimes come back with EBP/ESP wrong; when the
 * code that made the call then returns through the wrong slot it jumps to a junk address (CHRVAR 5, build 55b:
 * KernelEx's GetAncestor wrapper (KEXBASES+8490) -> USER32 GetAncestor came back 8 bytes low -> "ret 8" took the
 * caller's saved ESI = 2 -> EIP 00000002). If that happens inside a guarded call, this vectored handler puts the
 * thread back into guard_call's frame and makes the call again (at most twice per call), with a KEXCRASH line. */
void guard_retry(void);
static LONG CALLBACK guard_recover(PEXCEPTION_POINTERS ep)
{
    PCONTEXT c = ep->ContextRecord; GSAVE *s; DWORD top, eip = c->Eip; MEMORY_BASIC_INFORMATION m;
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        ep->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION) return EXCEPTION_CONTINUE_SEARCH;
    if (eip >= 0x10000 && VirtualQuery((LPCVOID)(ULONG_PTR)eip, &m, sizeof(m)) && m.State == MEM_COMMIT) return EXCEPTION_CONTINUE_SEARCH;
    s = (GSAVE *)(ULONG_PTR)__readfsdword(0x14);
    top = __readfsdword(0x04);
    while (s && (DWORD)(ULONG_PTR)s < c->Esp && !IsBadReadPtr(s, sizeof(*s))) s = (GSAVE *)(ULONG_PTR)s->old14;   /* areas below ESP are dead */
    if (!s || IsBadReadPtr(s, sizeof(*s)) || s->magic != GSAVE_MAGIC || (DWORD)(ULONG_PTR)s >= top || s->ebp <= c->Esp || s->ebp >= top)
        return EXCEPTION_CONTINUE_SEARCH;
    if (s->retries >= 2) { kex_crashnote("guard: call jumped to a junk address again - not retried (EIP, ESP, EBP, name follows)", eip, c->Esp, c->Ebp, 0); if (s->name) kex_crashnote(s->name, 0, 0, 0, 0); return EXCEPTION_CONTINUE_SEARCH; }
    s->retries++;
    {
        static LONG n; if (InterlockedIncrement(&n) <= 30) {
            kex_crashnote("guard RECOVERED: Windows call came back to a junk address, made again (EIP, ESP, guard EBP, try)", eip, c->Esp, s->ebp, s->retries);
            if (s->name) kex_crashnote(s->name, 0, 0, 0, 0);
        }
    }
    __writefsdword(0x14, (DWORD)(ULONG_PTR)s);
    c->Ebp = s->ebp; c->Esp = s->ebp - 12; c->Eip = (DWORD)(ULONG_PTR)guard_retry;
    return EXCEPTION_CONTINUE_EXECUTION;
}
PVOID KEXAPI kex_AddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER fn);
static void guard_recover_register(void) { kex_AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)guard_recover); }

static void stat_tick(void);
extern volatile LONG kex_st_paint;
static LONG g_guard_logs;
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
static DWORD guarded_at(const char *dll, const char *name, FARPROC *cache, int nargs, const DWORD *args, DWORD caller);
static DWORD guarded_in(const char *dll, const char *name, FARPROC *cache, int nargs, const DWORD *args)
{
    return guarded_at(dll, name, cache, nargs, args, 0);
}
/* ---- build 109: focus history. Chrome's browser crashed at chrome.dll+c2c3064 (build 108, 21:55:51): ui::InputMethod
 * handed a key to its TextInputClient, and that client had already been freed (0xEF fill). Which window had the
 * keyboard focus, and in what order did activation / focus / show / destroy messages arrive? Each GUI thread gets a
 * WH_CALLWNDPROC hook (in-process, on that thread only) at its first DispatchMessage; activation and focus messages
 * and key / button messages go into a 96-entry ring that the crash report prints ("focus history"), and the first
 * 300 activation / focus messages are also KEXCRASH notes. Records only - nothing is changed. */
typedef struct { DWORD tick, msg, hwnd, wp, lp, ex, tid, atom; } KFEV;
static KFEV g_fev[96]; static volatile LONG g_fev_n;
static DWORD g_fev_tid[32]; static volatile LONG g_fev_ntid;
typedef LONG (WINAPI *T_GWL)(HWND, int); typedef DWORD (WINAPI *T_GCL)(HWND, int);
static T_GWL g_fev_gwl; static T_GCL g_fev_gcl;
static void fev_add(DWORD msg, DWORD hwnd, DWORD wp, DWORD lp)
{
    LONG i = InterlockedIncrement(&g_fev_n) - 1; KFEV *e = &g_fev[i % 96];
    if (!g_fev_gwl) { g_fev_gwl = (T_GWL)(void *)kex_sysproc("USER32.DLL", "GetWindowLongA"); g_fev_gcl = (T_GCL)(void *)kex_sysproc("USER32.DLL", "GetClassLongA"); }
    e->tick = GetTickCount(); e->msg = msg; e->hwnd = hwnd; e->wp = wp; e->lp = lp; e->tid = GetCurrentThreadId();
    e->ex = (g_fev_gwl && hwnd) ? (DWORD)g_fev_gwl((HWND)(ULONG_PTR)hwnd, GWL_EXSTYLE) : 0;
    e->atom = (g_fev_gcl && hwnd) ? (g_fev_gcl((HWND)(ULONG_PTR)hwnd, -32 /* GCW_ATOM */) & 0xFFFF) : 0;
}
static const char *fev_name(DWORD m)
{
    switch (m) {
    case 0x0001: return "WM_CREATE"; case 0x0002: return "WM_DESTROY"; case 0x0006: return "WM_ACTIVATE";
    case 0x0007: return "WM_SETFOCUS"; case 0x0008: return "WM_KILLFOCUS"; case 0x0018: return "WM_SHOWWINDOW";
    case 0x001C: return "WM_ACTIVATEAPP"; case 0x0021: return "WM_MOUSEACTIVATE"; case 0x0086: return "WM_NCACTIVATE";
    case 0x0281: return "WM_IME_SETCONTEXT"; case 0x0100: return "WM_KEYDOWN"; case 0x0101: return "WM_KEYUP";
    case 0x0102: return "WM_CHAR"; case 0x0104: return "WM_SYSKEYDOWN"; case 0x0105: return "WM_SYSKEYUP";
    case 0x0201: return "WM_LBUTTONDOWN"; case 0x0202: return "WM_LBUTTONUP"; case 0x0204: return "WM_RBUTTONDOWN";
    }
    return "message";
}
/* build 113: the hook handles of each thread, passed on to CallNextHookEx (Windows 95/98 use the handle to find
 * the next hook in the chain; build 109-112 passed NULL) */
static HHOOK g_fev_hk[32][2];
static HHOOK fev_my_hook(int which)
{
    DWORD t = GetCurrentThreadId(); LONG i, n = g_fev_ntid;
    for (i = 0; i < n && i < 32; i++) if (g_fev_tid[i] == t) return g_fev_hk[i][which];
    return NULL;
}
/* build 132: a top-level window Windows is moving/sizing right now (between WM_WINDOWPOSCHANGING and ..CHANGED,
 * seen by fev_hook before the window procedure). Measured (Basilisk, WinPosTrace): its compositor thread keeps
 * blitting into the window during the move; Windows 98 does not serialise other threads' drawing against a move
 * (NT does), so a blit that lands between the move's copy of the window pixels and the new visible region leaves
 * stale pixels at the window's old edges - the "smearing" on Restore and drag. Such blits now wait for the move. */
static volatile LONG g_mv_hwnd, g_mv_tick, g_mv_tid;
static LRESULT CALLBACK fev_hook(int code, WPARAM wp, LPARAM lp)
{
    typedef LRESULT (WINAPI *T_CNH)(HHOOK, int, WPARAM, LPARAM);
    static T_CNH cnh;
    if (code >= 0 && lp) {
        const DWORD *c = (const DWORD *)lp;                   /* CWPSTRUCT: lParam, wParam, message, hwnd */
        DWORD m = c[2];
        if (m == WM_WINDOWPOSCHANGING && c[0] && (((const WINDOWPOS *)(ULONG_PTR)c[0])->flags & (SWP_NOMOVE | SWP_NOSIZE)) != (SWP_NOMOVE | SWP_NOSIZE)) {
            InterlockedExchange(&g_mv_tick, (LONG)GetTickCount()); InterlockedExchange(&g_mv_tid, (LONG)GetCurrentThreadId());
            InterlockedExchange(&g_mv_hwnd, (LONG)c[3]);
        } else if (m == WM_WINDOWPOSCHANGED && (LONG)c[3] == g_mv_hwnd) InterlockedExchange(&g_mv_hwnd, 0);
        if ((m == 0x0201 || m == 0x0202) && c[3]) {          /* build 115: a button message SENT to a window (the legacy child forwards to the frame) */
            static LONG ns2; DWORD le = GetLastError();
            if (InterlockedIncrement(&ns2) <= 300)
                kex_crashnote(m == 0x0201 ? "click: WM_LBUTTONDOWN sent (window, x|y<<16, tick, wParam)" : "click: WM_LBUTTONUP sent (window, x|y<<16, tick, wParam)",
                              c[3], c[0], GetTickCount(), c[1]);
            SetLastError(le);
        }
        if (m == 0x0002 || m == 0x0006 || m == 0x0007 || m == 0x0008 || m == 0x0018 || m == 0x001C || m == 0x0021 || m == 0x0086 || m == 0x0281) {
            DWORD le = GetLastError();
            fev_add(m, c[3], c[1], c[0]);
            if (m != 0x0002 && m != 0x0018) {
                static LONG nn; char t[96];
                if (InterlockedIncrement(&nn) <= 300) {
                    lstrcpyA(t, "focus: "); lstrcatA(t, fev_name(m)); lstrcatA(t, " (window, wParam, window exstyle, tick)");
                    kex_crashnote(t, c[3], c[1], g_fev[(g_fev_n - 1) % 96].ex, GetTickCount());
                }
            }
            SetLastError(le);
        }
    }
    if (!cnh) cnh = (T_CNH)(void *)kex_sysproc("USER32.DLL", "CallNextHookEx");
    return cnh ? cnh(fev_my_hook(0), code, wp, lp) : 0;
}
/* ---- build 112: WS_EX_NOACTIVATE (0x08000000, Windows 2000+). Windows 98 drops the bit: a window that asked
 * for it still becomes the active window when clicked. On NT a click on such a top-level window does not
 * activate it (programmatic SetActiveWindow / SetForegroundWindow still do). Build 111's focus history: a
 * layered tool window (exstyle 80080080 as Windows 98 reports it) took activation and keyboard focus from
 * Chrome's frame on a click. kexnt remembers every window created with the bit, and a per-thread WH_CBT hook
 * refuses HCBT_ACTIVATE for such a window when the activation comes from the mouse (CBTACTIVATESTRUCT.fMouse),
 * as NT does. Only windows whose creator asked for the bit are affected. */
static volatile LONG g_noact[64]; static volatile LONG g_noact_n;
static void noact_record(DWORD hwnd, DWORD exstyle, DWORD caller)
{
    LONG i;
    if (!hwnd || !(exstyle & 0x08000000UL)) return;
    for (i = 0; i < 64; i++) if (g_noact[i] == 0 || g_noact[i] == (LONG)hwnd) { g_noact[i] = (LONG)hwnd; break; }
    if (i == 64) g_noact[(InterlockedIncrement(&g_noact_n) - 1) & 63] = (LONG)hwnd;
    { static LONG n; if (InterlockedIncrement(&n) <= 40) kex_crashnote("WS_EX_NOACTIVATE window made (window, exstyle asked, caller)", hwnd, exstyle, caller, 0); }
}
static int noact_has(DWORD hwnd) { int i; for (i = 0; i < 64; i++) if (g_noact[i] == (LONG)hwnd) return 1; return 0; }
static LRESULT CALLBACK cbt_hook(int code, WPARAM wp, LPARAM lp)
{
    typedef LRESULT (WINAPI *T_CNH)(HHOOK, int, WPARAM, LPARAM);
    static T_CNH cnh;
    if (code == 5 /* HCBT_ACTIVATE */ && lp && noact_has((DWORD)wp)) {
        const DWORD *a = (const DWORD *)lp;                  /* CBTACTIVATESTRUCT: fMouse, hWndActive */
        if (a[0]) {
            static LONG n; if (InterlockedIncrement(&n) <= 40) kex_crashnote("WS_EX_NOACTIVATE: click activation refused as on NT (window, active window)", (DWORD)wp, a[1], 0, 0);
            return 1;
        }
    }
    if (!cnh) cnh = (T_CNH)(void *)kex_sysproc("USER32.DLL", "CallNextHookEx");
    return cnh ? cnh(fev_my_hook(1), code, wp, lp) : 0;
}

/* build 132: KexNG "WinPosTrace" (DWORD 1): window moves of top-level windows, AFTER the window procedure ran
 * (WH_CALLWNDPROCRET: the WINDOWPOS the program may have changed in WM_WINDOWPOSCHANGING) -> KEXCRASH, first 600.
 * Basilisk investigation: the desktop it uncovers on Restore / drag is not repainted (stale edge lines). */
static HHOOK g_pos_hk[32]; static LONG g_pos_on = -1, g_pos_n;
static volatile LONG g_pos_moving;   /* hwnd between WM_WINDOWPOSCHANGING (after the proc) and WM_WINDOWPOSCHANGED */
static LRESULT CALLBACK pos_hook(int code, WPARAM wp, LPARAM lp)
{
    typedef LRESULT (WINAPI *T_CNH)(HHOOK, int, WPARAM, LPARAM);
    typedef HWND (WINAPI *T_GP)(HWND); typedef LONG (WINAPI *T_GWL)(HWND, int);
    static T_CNH cnh; static T_GP gp; static T_GWL gwl;
    DWORD t = GetCurrentThreadId(); LONG i; HHOOK me = NULL;
    for (i = 0; i < 32; i++) if (g_fev_tid[i] == t) { me = g_pos_hk[i]; break; }
    if (!cnh) { cnh = (T_CNH)(void *)kex_sysproc("USER32.DLL", "CallNextHookEx"); gp = (T_GP)(void *)kex_sysproc("USER32.DLL", "GetParent");
                gwl = (T_GWL)(void *)kex_sysproc("USER32.DLL", "GetWindowLongA"); }
    if (code >= 0 && lp && gwl) {
        const CWPRETSTRUCT *c = (const CWPRETSTRUCT *)lp;
        UINT m = c->message;
        if ((m == WM_WINDOWPOSCHANGING || m == WM_WINDOWPOSCHANGED || m == WM_NCCALCSIZE || m == 0x231 || m == 0x232 ||
             m == WM_SYSCOMMAND || m == WM_ERASEBKGND || m == WM_NCPAINT || m == WM_MOVE || m == WM_SIZE) &&
            !(gwl(c->hwnd, GWL_STYLE) & WS_CHILD) && InterlockedIncrement(&g_pos_n) <= 600) {
            DWORD le = GetLastError();
            if (m == WM_WINDOWPOSCHANGING && c->lParam && !(((const WINDOWPOS *)c->lParam)->flags & SWP_NOMOVE & SWP_NOSIZE))
                InterlockedExchange(&g_pos_moving, (LONG)(ULONG_PTR)c->hwnd);
            if (m == WM_WINDOWPOSCHANGED) InterlockedExchange(&g_pos_moving, 0);
            if ((m == WM_WINDOWPOSCHANGING || m == WM_WINDOWPOSCHANGED) && c->lParam) {
                const WINDOWPOS *p = (const WINDOWPOS *)c->lParam;
                kex_crashnote(m == WM_WINDOWPOSCHANGING ? "winpos: CHANGING after proc (hwnd, flags, x|y<<16, cx|cy<<16)"
                                                        : "winpos: CHANGED (hwnd, flags, x|y<<16, cx|cy<<16)",
                              (DWORD)(ULONG_PTR)c->hwnd, p->flags, (DWORD)(p->x & 0xFFFF) | ((DWORD)p->y << 16), (DWORD)(p->cx & 0xFFFF) | ((DWORD)p->cy << 16));
            } else if (m == WM_NCCALCSIZE && c->lParam) {
                const RECT *r = (const RECT *)c->lParam;           /* rgrc[0] = the new client rect, after the proc */
                kex_crashnote("winpos: NCCALCSIZE result (hwnd, wParam|result<<8, left|top<<16, right|bottom<<16)", (DWORD)(ULONG_PTR)c->hwnd,
                              (DWORD)c->wParam | ((DWORD)c->lResult << 8), (DWORD)(r->left & 0xFFFF) | ((DWORD)r->top << 16), (DWORD)(r->right & 0xFFFF) | ((DWORD)r->bottom << 16));
            } else
                kex_crashnote("winpos: message (hwnd, msg, wParam, result)", (DWORD)(ULONG_PTR)c->hwnd, m, (DWORD)c->wParam, (DWORD)c->lResult);
            SetLastError(le);
        }
    }
    return cnh ? cnh(me, code, wp, lp) : 0;
}
static void pos_trace_thread(LONG slot, DWORD t)
{
    typedef HHOOK (WINAPI *T_SWH)(int, HOOKPROC, HINSTANCE, DWORD);
    if (g_pos_on < 0) {
        HKEY k; DWORD v = 0, n = sizeof(v);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "WinPosTrace", NULL, NULL, (BYTE *)&v, &n) != ERROR_SUCCESS) v = 0;
            RegCloseKey(k);
        }
        g_pos_on = v == 1;
    }
    if (g_pos_on == 1) { T_SWH swh = (T_SWH)(void *)kex_sysproc("USER32.DLL", "SetWindowsHookExA"); if (swh) g_pos_hk[slot] = swh(12 /* WH_CALLWNDPROCRET */, pos_hook, NULL, t); }
}

static void fev_thread(void)
{
    DWORD t = GetCurrentThreadId(); LONG i, n = g_fev_ntid;
    for (i = 0; i < n && i < 32; i++) if (g_fev_tid[i] == t) return;
    i = InterlockedIncrement(&g_fev_ntid) - 1;
    if (i >= 32) return;
    g_fev_tid[i] = t;
    {   typedef HHOOK (WINAPI *T_SWH)(int, HOOKPROC, HINSTANCE, DWORD);
        T_SWH swh = (T_SWH)(void *)kex_sysproc("USER32.DLL", "SetWindowsHookExA");
        DWORD le = GetLastError();
        if (swh) { g_fev_hk[i][0] = swh(4 /* WH_CALLWNDPROC */, fev_hook, NULL, t); g_fev_hk[i][1] = swh(5 /* WH_CBT */, cbt_hook, NULL, t); }
        pos_trace_thread(i, t);                                   /* build 132: optional, registry WinPosTrace */
        SetLastError(le);
    }
}
/* crashlog_ext.c: the ring, oldest first; returns how many */
int kex_focus_history(DWORD (*out)[8], int max)
{
    LONG n = g_fev_n, first = n > 96 ? n - 96 : 0, i; int k = 0;
    for (i = first; i < n && k < max; i++, k++) {
        const KFEV *e = &g_fev[i % 96];
        out[k][0] = e->tick; out[k][1] = e->msg; out[k][2] = e->hwnd; out[k][3] = e->wp; out[k][4] = e->lp; out[k][5] = e->ex; out[k][6] = e->tid; out[k][7] = e->atom;
    }
    return k;
}
const char *kex_focus_msgname(DWORD m) { return fev_name(m); }

/* build 132 (WinPosTrace): a frame drawn into a top-level window - does the DC still match the window (origin = the
 * client area's screen position, clip box inside the client)? A stale DC paints where the window no longer is. */
static void pos_check_dc(const char *name, HDC dc)
{
    typedef HWND (WINAPI *T_WFDC)(HDC); typedef BOOL (WINAPI *T_GDO)(HDC, LPPOINT); typedef int (WINAPI *T_GCB)(HDC, LPRECT);
    typedef BOOL (WINAPI *T_CTS)(HWND, LPPOINT); typedef BOOL (WINAPI *T_GCR)(HWND, LPRECT); typedef LONG (WINAPI *T_GWL)(HWND, int);
    static T_WFDC wfdc; static T_GDO gdo; static T_GCB gcb; static T_CTS cts; static T_GCR gcr; static T_GWL gwl; static LONG nok, nbad;
    HWND w; POINT o = {0, 0}, c = {0, 0}; RECT cb, cr; DWORD le;
    if (!wfdc) { wfdc = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC"); gdo = (T_GDO)(void *)kex_sysproc("GDI32.DLL", "GetDCOrgEx");
                 gcb = (T_GCB)(void *)kex_sysproc("GDI32.DLL", "GetClipBox"); cts = (T_CTS)(void *)kex_sysproc("USER32.DLL", "ClientToScreen");
                 gcr = (T_GCR)(void *)kex_sysproc("USER32.DLL", "GetClientRect"); gwl = (T_GWL)(void *)kex_sysproc("USER32.DLL", "GetWindowLongA"); }
    if (!wfdc || !gdo || !gcb || !cts || !gcr || !gwl || !dc) return;
    le = GetLastError();
    if ((w = wfdc(dc)) != NULL && g_pos_moving == (LONG)(ULONG_PTR)w) {   /* drawn while Windows is moving/sizing it */
        static LONG nm; RECT b = {0, 0, 0, 0}; POINT oo = {0, 0}; gdo(dc, &oo); gcb(dc, &b);
        if (InterlockedIncrement(&nm) <= 60) kex_crashnote("winpos: DRAWN DURING MOVE (hwnd, DC origin x|y<<16, clip right|bottom<<16, call)",
            (DWORD)(ULONG_PTR)w, (DWORD)(oo.x & 0xFFFF) | ((DWORD)oo.y << 16), (DWORD)(b.right & 0xFFFF) | ((DWORD)b.bottom << 16), (DWORD)name[0] | ((DWORD)name[1] << 8));
    }
    if ((w = wfdc(dc)) != NULL && !(gwl(w, GWL_STYLE) & WS_CHILD) && gdo(dc, &o) && cts(w, &c) && gcr(w, &cr) && gcb(dc, &cb) != ERROR) {
        BOOL bad = o.x != c.x || o.y != c.y || cb.right > cr.right || cb.bottom > cr.bottom;
        if (bad ? InterlockedIncrement(&nbad) <= 60 : InterlockedIncrement(&nok) <= 6)
            kex_crashnote(bad ? "winpos: STALE DC drawn into (hwnd, DC origin x|y<<16, client origin x|y<<16, clip right|bottom<<16)"
                              : "winpos: DC matches window (hwnd, DC origin x|y<<16, client origin x|y<<16, clip right|bottom<<16)",
                          (DWORD)(ULONG_PTR)w, (DWORD)(o.x & 0xFFFF) | ((DWORD)o.y << 16), (DWORD)(c.x & 0xFFFF) | ((DWORD)c.y << 16),
                          (DWORD)(cb.right & 0xFFFF) | ((DWORD)cb.bottom << 16));
        if (bad && nbad <= 60) kex_crashnote(name, (DWORD)(ULONG_PTR)dc, (DWORD)(cr.right & 0xFFFF) | ((DWORD)cr.bottom << 16), 0, 0);
    }
    SetLastError(le);
}

/* build 132: KexNG "TextTrace" (DWORD 1): what a program asks GDI to draw / measure as text (first 400 calls) ->
 * KEXCRASH. Basilisk investigation: every UI label lost its last character ("Cu" for "Cut"). */
static LONG g_txt_on = -1, g_txt_n;
static void txt_init(void)
{
    HKEY k; DWORD v = 0, n = sizeof(v);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExA(k, "TextTrace", NULL, NULL, (BYTE *)&v, &n) != ERROR_SUCCESS) v = 0;
        RegCloseKey(k);
    }
    g_txt_on = v == 1;
}
/* "text": the UTF-16 string as ASCII ('?' for others), or the glyph indices as hex */
static void txt_note(const char *what, const WCHAR *w, int n, BOOL glyphs, DWORD a, DWORD b, DWORD c)
{
    char t[200]; int i, l;
    if (InterlockedIncrement(&g_txt_n) > 400) return;
    lstrcpynA(t, what, 60); l = lstrlenA(t); t[l++] = ' '; t[l++] = '"';
    for (i = 0; w && i < n && l < 180; i++) {
        if (glyphs) { static const char hx[] = "0123456789abcdef"; WORD g = w[i]; if (l > 170) break;
            t[l++] = hx[(g >> 12) & 15]; t[l++] = hx[(g >> 8) & 15]; t[l++] = hx[(g >> 4) & 15]; t[l++] = hx[g & 15]; t[l++] = ' '; }
        else t[l++] = (w[i] >= 32 && w[i] < 127) ? (char)w[i] : '?';
    }
    t[l++] = '"'; t[l] = 0;
    kex_crashnote(t, (DWORD)n, a, b, c);
}
static void txt_before(const char *name, const DWORD *args, int nargs)
{
    if (!lstrcmpA(name, "ExtTextOutW") && nargs == 8) {   /* hdc, x, y, options, rect, string, count, dx */
        const RECT *rc = (const RECT *)(ULONG_PTR)args[4]; const INT *dx = (const INT *)(ULONG_PTR)args[7]; int i, sum = 0, n = (int)args[6];
        if (dx && n > 0 && n < 4096 && !IsBadReadPtr(dx, n * sizeof(INT))) for (i = 0; i < n; i++) sum += dx[i];
        txt_note((args[3] & 0x10) ? "text: ExtTextOutW glyphs (count, x|y<<16, options|clipright<<16, sum of dx)" : "text: ExtTextOutW (count, x|y<<16, options|clipright<<16, sum of dx)",
                 (const WCHAR *)(ULONG_PTR)args[5], n, (args[3] & 0x10) != 0, (args[1] & 0xFFFF) | (args[2] << 16),
                 (args[3] & 0xFFFF) | (rc && !IsBadReadPtr(rc, sizeof(RECT)) ? ((DWORD)rc->right << 16) : 0), (DWORD)sum);
        if (dx && n > 0 && n < 4096 && !IsBadReadPtr(dx, n * sizeof(INT))) {   /* the advances themselves */
            char t[200]; int l, k; lstrcpyA(t, "text:   dx"); l = lstrlenA(t);
            for (k = 0; k < n && l < 185; k++) { int v = dx[k]; t[l++] = ' '; if (v < 0) { t[l++] = '-'; v = -v; } if (v >= 100) t[l++] = (char)('0' + v / 100 % 10); if (v >= 10) t[l++] = (char)('0' + v / 10 % 10); t[l++] = (char)('0' + v % 10); }
            t[l] = 0; if (g_txt_n <= 400) kex_crashnote(t, 0, 0, 0, 0);
        }
        {   typedef int (WINAPI *T_GTF)(HDC, int, LPSTR); typedef BOOL (WINAPI *T_GTM)(HDC, LPTEXTMETRICA);
            T_GTF gtf = (T_GTF)(void *)kex_sysproc("GDI32.DLL", "GetTextFaceA"); T_GTM gtm = (T_GTM)(void *)kex_sysproc("GDI32.DLL", "GetTextMetricsA");
            char face[64] = "", t[100]; TEXTMETRICA tm; memset(&tm, 0, sizeof(tm));
            if (gtf) gtf((HDC)(ULONG_PTR)args[0], sizeof(face), face);
            if (gtm) gtm((HDC)(ULONG_PTR)args[0], &tm);
            lstrcpyA(t, "text:   font (height, avg width, pitch|family, charset) "); lstrcatA(t, face);
            if (g_txt_n <= 400) kex_crashnote(t, (DWORD)tm.tmHeight, (DWORD)tm.tmAveCharWidth, tm.tmPitchAndFamily, tm.tmCharSet);
        }
    }
}
static void txt_after(const char *name, const DWORD *args, int nargs, DWORD r)
{
    if (!lstrcmpA(name, "GetTextExtentPoint32W") && nargs == 4 && r) {
        const SIZE *sz = (const SIZE *)(ULONG_PTR)args[3];
        txt_note("text: GetTextExtentPoint32W (count, cx, cy, -)", (const WCHAR *)(ULONG_PTR)args[1], (int)args[2], FALSE, sz ? (DWORD)sz->cx : 0, sz ? (DWORD)sz->cy : 0, 0);
    } else if (!lstrcmpA(name, "GetTextExtentExPointW") && nargs == 7 && r) {   /* hdc, str, n, max, fit*, dx*, size* */
        const INT *fit = (const INT *)(ULONG_PTR)args[4]; const SIZE *sz = (const SIZE *)(ULONG_PTR)args[6];
        txt_note("text: GetTextExtentExPointW (count, max, fit, cx)", (const WCHAR *)(ULONG_PTR)args[1], (int)args[2], FALSE, args[3], fit ? (DWORD)*fit : 0xFFFFFFFF, sz ? (DWORD)sz->cx : 0);
    }
}

/* build 132: KexNG "DrawTrace" (DWORD 1): classic-theme drawing calls that touch the top 32 pixels of their target
 * (title bar investigation, Basilisk) -> KEXCRASH, first 500: call, target (window / memory bitmap WxH), rect, extra. */
static LONG g_drw_on = -1, g_drw_n;
static void drw_note(const char *name, const DWORD *a, int nargs)
{
    typedef DWORD (WINAPI *T_GOT)(HGDIOBJ); typedef HGDIOBJ (WINAPI *T_GCO)(HDC, UINT); typedef int (WINAPI *T_GOA)(HGDIOBJ, int, LPVOID);
    typedef HWND (WINAPI *T_WFDC)(HDC);
    static T_GOT got; static T_GCO gco; static T_GOA goa; static T_WFDC wfdc;
    HDC dc; int x = 0, y = 0, w = 0, h = 0; DWORD extra = 0; const RECT *rc = NULL; char t[160], *p; DWORD kind; BITMAP bm;
    if (!got) { got = (T_GOT)(void *)kex_sysproc("GDI32.DLL", "GetObjectType"); gco = (T_GCO)(void *)kex_sysproc("GDI32.DLL", "GetCurrentObject");
                goa = (T_GOA)(void *)kex_sysproc("GDI32.DLL", "GetObjectA"); wfdc = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC"); }
    if (!got || !gco || !goa || !wfdc) return;
    if (!lstrcmpA(name, "DrawCaption")) { dc = (HDC)(ULONG_PTR)a[1]; rc = (const RECT *)(ULONG_PTR)a[2]; extra = a[3]; }
    else if (!lstrcmpA(name, "DrawFrameControl") || !lstrcmpA(name, "DrawEdge")) { dc = (HDC)(ULONG_PTR)a[0]; rc = (const RECT *)(ULONG_PTR)a[1]; extra = a[2] | (a[3] << 16); }
    else if (!lstrcmpA(name, "FillRect")) { dc = (HDC)(ULONG_PTR)a[0]; rc = (const RECT *)(ULONG_PTR)a[1]; extra = a[2]; }
    else { dc = (HDC)(ULONG_PTR)a[0]; x = (int)a[1]; y = (int)a[2]; w = (int)a[3]; h = (int)a[4];
           extra = !lstrcmpA(name, "PatBlt") ? a[5] : !lstrcmpA(name, "BitBlt") ? a[8] : !lstrcmpA(name, "StretchBlt") ? a[10] : a[nargs - 1]; }
    if (rc) { if (IsBadReadPtr(rc, sizeof(RECT))) return; x = rc->left; y = rc->top; w = rc->right - rc->left; h = rc->bottom - rc->top; }
    if (y >= 32) return;
    if (InterlockedIncrement(&g_drw_n) > 500) return;
    kind = got(dc);
    lstrcpyA(t, "draw: "); lstrcatA(t, name);
    p = t + lstrlenA(t);
    if (kind == OBJ_MEMDC) { HGDIOBJ b = gco(dc, OBJ_BITMAP); memset(&bm, 0, sizeof(bm)); if (b) goa(b, sizeof(bm), &bm);
        lstrcpyA(p, " -> memory bitmap (x|y<<16, w|h<<16, extra, bitmap w|h<<16)");
        kex_crashnote(t, (DWORD)(x & 0xFFFF) | ((DWORD)y << 16), (DWORD)(w & 0xFFFF) | ((DWORD)h << 16), extra, (DWORD)(bm.bmWidth & 0xFFFF) | ((DWORD)bm.bmHeight << 16));
    } else {
        lstrcpyA(p, " -> window DC (x|y<<16, w|h<<16, extra, hwnd)");
        kex_crashnote(t, (DWORD)(x & 0xFFFF) | ((DWORD)y << 16), (DWORD)(w & 0xFFFF) | ((DWORD)h << 16), extra, (DWORD)(ULONG_PTR)wfdc(dc));
    }
}

static DWORD guarded_at(const char *dll, const char *name, FARPROC *cache, int nargs, const DWORD *args, DWORD caller)
{
    GSAVE s; DWORD r; FARPROC fn = *cache;
    { void kex_hang_note_call(const char *n); LONG kex_hang_drawn(void); if (!kex_hang_drawn()) kex_hang_note_call(name); }
    if (g_mv_hwnd && args && nargs >= 1 && (DWORD)g_mv_tid != GetCurrentThreadId() &&
        (!lstrcmpA(name, "BitBlt") || !lstrcmpA(name, "StretchDIBits") || !lstrcmpA(name, "SetDIBitsToDevice"))) {
        typedef HWND (WINAPI *T_WFDC)(HDC); static T_WFDC wfdc;     /* build 132: wait for a move of this window */
        DWORD le = GetLastError(), t0 = GetTickCount(); static LONG nw;
        if (!wfdc) wfdc = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC");
        if (wfdc && (LONG)(ULONG_PTR)wfdc((HDC)(ULONG_PTR)args[0]) == g_mv_hwnd && GetTickCount() - (DWORD)g_mv_tick < 1000) {
            while (g_mv_hwnd && GetTickCount() - t0 < 200) Sleep(1);
            if (g_pos_on == 1 && InterlockedIncrement(&nw) <= 40) kex_crashnote("winpos: blit from another thread waited for a move (ms, -, -, -)", GetTickCount() - t0, 0, 0, 0);
        }
        SetLastError(le);
    }
    if (g_pos_on == 1 && args && nargs >= 1 && (!lstrcmpA(name, "BitBlt") || !lstrcmpA(name, "StretchDIBits") || !lstrcmpA(name, "SetDIBitsToDevice")))
        pos_check_dc(name, (HDC)(ULONG_PTR)args[0]);              /* build 132: WinPosTrace */
    { extern volatile LONG kex_glass_pending; void kex_glass_apply_pending(void); if (kex_glass_pending) kex_glass_apply_pending(); }   /* layered_ext.c (build 51) */
    if (!fn) { fn = kex_prev_impl(dll, name); if (!fn) { SetLastError(ERROR_PROC_NOT_FOUND); return 0; } *cache = fn; }
    if (name[0] == 'D' && nargs == 1 && args && (!lstrcmpA(name, "DispatchMessageW") || !lstrcmpA(name, "DispatchMessageA"))) {
        const MSG *m = (const MSG *)(ULONG_PTR)args[0];
        if (m && m->message == WM_PAINT) InterlockedIncrement(&kex_st_paint);
        stat_tick();
        fev_thread();
        if (m && ((m->message >= 0x0100 && m->message <= 0x0105) || m->message == 0x0201 || m->message == 0x0202 || m->message == 0x0204))
            fev_add(m->message, (DWORD)(ULONG_PTR)m->hwnd, (DWORD)m->wParam, (DWORD)m->lParam);
        if (m && (m->message == 0x0201 || m->message == 0x0202 || m->message == 0x0204)) {   /* build 127: timeline (prof_ext.c) */
            void kex_tl_event(const char *what, DWORD a, DWORD b, DWORD c);
            kex_tl_event(m->message == 0x0201 ? "CLICK left down dispatched (window, x|y<<16, message age ms)" :
                         m->message == 0x0202 ? "CLICK left up dispatched (window, x|y<<16, message age ms)" : "CLICK right down dispatched (window, x|y<<16, message age ms)",
                         (DWORD)(ULONG_PTR)m->hwnd, (DWORD)m->lParam, GetTickCount() - m->time);
        }
        if (m && (m->message == 0x0201 || m->message == 0x0202)) {   /* build 114: every left click Chrome dispatches */
            static LONG nc; if (InterlockedIncrement(&nc) <= 400)
                kex_crashnote(m->message == 0x0201 ? "click: WM_LBUTTONDOWN dispatched (window, x|y<<16, tick, thread)" : "click: WM_LBUTTONUP dispatched (window, x|y<<16, tick, thread)",
                              (DWORD)(ULONG_PTR)m->hwnd, (DWORD)m->lParam, GetTickCount(), GetCurrentThreadId());
        }
    }
    s.ebx = s.esi = s.edi = 0; s.magic = GSAVE_MAGIC; s.retries = 0; s.name = name; s.seh = s.seh2 = 0;
    { static volatile LONG reg; if (!reg && !InterlockedExchange(&reg, 1)) guard_recover_register(); }
    if (g_drw_on < 0) {                                       /* build 132: DrawTrace */
        HKEY k; DWORD v = 0, n = sizeof(v);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_QUERY_VALUE, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "DrawTrace", NULL, NULL, (BYTE *)&v, &n) != ERROR_SUCCESS) v = 0;
            RegCloseKey(k);
        }
        g_drw_on = v == 1;
    }
    if (g_drw_on == 1 && args && (!lstrcmpA(name, "DrawCaption") || !lstrcmpA(name, "DrawFrameControl") || !lstrcmpA(name, "DrawEdge") ||
        !lstrcmpA(name, "FillRect") || !lstrcmpA(name, "PatBlt") || !lstrcmpA(name, "BitBlt") || !lstrcmpA(name, "StretchBlt") ||
        !lstrcmpA(name, "StretchDIBits") || !lstrcmpA(name, "SetDIBitsToDevice"))) { DWORD le = GetLastError(); drw_note(name, args, nargs); SetLastError(le); }
    if (g_txt_on < 0) txt_init();
    if (g_txt_on == 1 && args && name[0] == 'E') txt_before(name, args, nargs);   /* build 132: TextTrace */
    /* build 132: ETO_PDY (0x2000, Windows 2000+): lpDx holds an x AND a y advance per glyph. Windows 98 does not know
     * the flag and reads the pairs as x advances - every second glyph got the y value (0) as its advance: Basilisk /
     * Pale Moon drew "7 0 5 0 4 0 ..." -> tab titles in pieces ("Restore   S"), labels without their last character
     * ("Cop"), and Windows 98 does not draw a bitmap-font glyph whose advance is 0 at all (probe etog.c). Measured
     * with KexNG\TextTrace: options 0x2010 (glyph indices + ETO_PDY). The pairs become plain x advances and the flag is
     * cleared; a non-zero y advance (vertical offsets, rare in horizontal text) is noted, its x part is kept. */
    if (args && nargs == 8 && (args[3] & 0x2000) && args[7] && (int)args[6] > 0 && (int)args[6] <= 4096 && name[0] == 'E' &&
        (!lstrcmpA(name, "ExtTextOutW") || !lstrcmpA(name, "ExtTextOutA"))) {
        const INT *pdx = (const INT *)(ULONG_PTR)args[7]; int n = (int)args[6], k, ny = 0; DWORD le = GetLastError();
        if (!IsBadReadPtr(pdx, 2 * n * sizeof(INT))) {
            INT *dx = (INT *)HeapAlloc(GetProcessHeap(), 0, n * sizeof(INT));
            if (dx) {
                DWORD a2[8];
                for (k = 0; k < n; k++) { dx[k] = pdx[2 * k]; if (pdx[2 * k + 1]) ny++; }
                if (ny) { static LONG nn; if (InterlockedIncrement(&nn) <= 10) kex_crashnote("ExtTextOut ETO_PDY with y advances - x kept, y dropped (glyphs, with y, -, -)", (DWORD)n, (DWORD)ny, 0, 0); }
                memcpy(a2, args, sizeof(a2)); a2[3] &= ~0x2000UL; a2[7] = (DWORD)(ULONG_PTR)dx;
                SetLastError(le);
                r = guarded_at(dll, name, cache, nargs, a2, caller);
                le = GetLastError(); HeapFree(GetProcessHeap(), 0, dx); SetLastError(le);
                return r;
            }
        }
        SetLastError(le);
    }
    /* build 132: plain x advances (after the ETO_PDY conversion above) whose LAST value is 0: NT draws the last glyph
     * whole (the last advance only moves the pen afterwards); Windows 98 does not draw a bitmap-font glyph whose
     * advance is 0 (probe etog.c: MS Serif "Copy", dx 7 5 5 0 -> ink ends after "Cop"; TrueType is not affected).
     * Gecko ends every run with 0 -> labels in bitmap fonts lost their last character ("Cop", "Restore Sessio").
     * Raster fonts only; the last advance becomes the font's widest character in a private copy (not with TA_UPDATECP,
     * where it moves the current position); every glyph stays where the program put it. */
    if (args && nargs == 8 && !(args[3] & 0x2000) && args[7] && (int)args[6] > 0 && (int)args[6] <= 4096 && name[0] == 'E' &&
        (!lstrcmpA(name, "ExtTextOutW") || !lstrcmpA(name, "ExtTextOutA"))) {
        typedef UINT (WINAPI *T_GTA)(HDC); typedef BOOL (WINAPI *T_GTM)(HDC, LPTEXTMETRICA);
        static T_GTA gta; static T_GTM gtm; const INT *dx = (const INT *)(ULONG_PTR)args[7]; int n = (int)args[6];
        if (!gta) { gta = (T_GTA)(void *)kex_sysproc("GDI32.DLL", "GetTextAlign"); gtm = (T_GTM)(void *)kex_sysproc("GDI32.DLL", "GetTextMetricsA"); }
        if (gta && gtm && !IsBadReadPtr(dx, n * sizeof(INT)) && dx[n - 1] == 0) {
            DWORD le = GetLastError(); TEXTMETRICA tm;
            if (!(gta((HDC)(ULONG_PTR)args[0]) & TA_UPDATECP) && gtm((HDC)(ULONG_PTR)args[0], &tm) &&
                !(tm.tmPitchAndFamily & (TMPF_TRUETYPE | TMPF_VECTOR)) && tm.tmMaxCharWidth > 0) {
                INT *ndx = (INT *)HeapAlloc(GetProcessHeap(), 0, n * sizeof(INT));
                if (ndx) {
                    DWORD a2[8]; memcpy(ndx, dx, n * sizeof(INT)); ndx[n - 1] = tm.tmMaxCharWidth;
                    memcpy(a2, args, sizeof(a2)); a2[7] = (DWORD)(ULONG_PTR)ndx;
                    SetLastError(le);
                    r = guarded_at(dll, name, cache, nargs, a2, caller);
                    le = GetLastError(); HeapFree(GetProcessHeap(), 0, ndx); SetLastError(le);
                    return r;
                }
            }
            SetLastError(le);
        }
    }
    if (kex_prof_enabled()) {
        unsigned __int64 t0 = __rdtsc();
        r = guard_call((void *)fn, nargs, args, &s);
        kex_prof_call(name, __rdtsc() - t0);
    } else r = guard_call((void *)fn, nargs, args, &s);
    if (g_txt_on == 1 && args && name[0] == 'G' && name[1] == 'e' && name[3] == 'T') { DWORD le = GetLastError(); txt_after(name, args, nargs, r); SetLastError(le); }
    if (s.seh2 != s.seh) {
        static LONG n3; DWORD le = GetLastError();
        if (InterlockedIncrement(&n3) <= 20) {
            kex_crashnote("guard repaired: exception-frame chain (FS:[0]) the call left / the caller had / caller", s.seh2, s.seh, caller, 0);
            kex_crashnote(name, 0, 0, 0, 0);
        }
        SetLastError(le);
    }
    if (s.esp_after != s.esp_before + 4UL * nargs || s.ebx2 != s.ebx || s.esi2 != s.esi || s.edi2 != s.edi || s.ebp2 != s.ebp) {
        if (InterlockedIncrement(&g_guard_logs) <= 50) {
            DWORD le = GetLastError();
            kex_trace(name, (DWORD)(s.esp_after - s.esp_before), 4UL * nargs, 0, 0);
            kex_trace("guard: ESP moved by / should; ESI EDI EBX after", (DWORD)(s.esp_after - s.esp_before), s.esi2, s.edi2, s.ebx2);
            SetLastError(le);
        }
        /* build 55: always in KEXCRASH - Windows 98 USER/GDI calls that came back with the stack or registers
         * changed are the suspects of the GPU-mode crashes (OPENGL32 after GetDC / WindowFromDC) */
        {
            static LONG n2; DWORD le = GetLastError();
            if (InterlockedIncrement(&n2) <= 40) {
                kex_crashnote(name, (DWORD)(s.esp_after - s.esp_before), 4UL * nargs, caller, 0);
                kex_crashnote("  guard repaired: ESP moved by / should be, ESI EDI EBX the call left", (DWORD)(s.esp_after - s.esp_before), s.esi2, s.edi2, s.ebx2);
                kex_crashnote("  guard repaired: ESI EDI EBX EBP the caller had", s.esi, s.edi, s.ebx, s.ebp);
            }
            SetLastError(le);
        }
    }
    return r;
}

#define guarded(name, cache, n, a) guarded_in("GDI32.DLL", name, cache, n, a)
static FARPROC c_sel, c_dib, c_flush, c_cdc;
HGDIOBJ KEXAPI kex_SelectObject(HDC dc, HGDIOBJ o)
{ DWORD a[2]; a[0] = (DWORD)(ULONG_PTR)dc; a[1] = (DWORD)(ULONG_PTR)o; return (HGDIOBJ)(ULONG_PTR)guarded("SelectObject", &c_sel, 2, a); }
HBITMAP KEXAPI kex_CreateDIBSection(HDC dc, const BITMAPINFO *bi, UINT use, VOID **bits, HANDLE sec, DWORD off)
{ DWORD a[6]; a[0] = (DWORD)(ULONG_PTR)dc; a[1] = (DWORD)(ULONG_PTR)bi; a[2] = use; a[3] = (DWORD)(ULONG_PTR)bits; a[4] = (DWORD)(ULONG_PTR)sec; a[5] = off;
  { HBITMAP r = (HBITMAP)(ULONG_PTR)guarded("CreateDIBSection", &c_dib, 6, a);
    void kex_shm_note_dib(HBITMAP b, const BITMAPINFO *bi, void *bits, HANDLE sec);   /* shm_ext.c (build 37) */
    /* build 132: NT hands out a new DIB section's pixels zero-filled; Windows 98 does not for small ones (probe
     * probes/dibz.c: 16x16 and 24x24 32-bit DIBs came back full of old data, 64x64+ zeroed). Gecko/cairo
     * draw an icon into a fresh 32-bit DIB and take the untouched pixels as transparent (premultiplied 0): on 98 they
     * carried leftover colour, added by AlphaBlend - white / noise around Basilisk's "+" tab button, grey lines at the
     * tab-strip edge. Pixels GDI allocated (no section handle) are zeroed here; a caller's own section is untouched. */
    if (r && bits && *bits && !sec && bi && !IsBadReadPtr(bi, sizeof(BITMAPINFOHEADER))) {
        const BITMAPINFOHEADER *h = &bi->bmiHeader;
        LONG w = h->biWidth, ht = h->biHeight < 0 ? -h->biHeight : h->biHeight;
        if ((h->biCompression == BI_RGB || h->biCompression == BI_BITFIELDS) && w > 0 && ht > 0 && h->biBitCount && h->biBitCount <= 32) {
            DWORD stride = (((DWORD)w * h->biBitCount + 31) / 32) * 4, size = stride * (DWORD)ht;
            if (size / stride == (DWORD)ht && !IsBadWritePtr(*bits, size)) memset(*bits, 0, size);
        }
    }
    if (r && bits) kex_shm_note_dib(r, bi, *bits, sec);
    return r; } }
BOOL KEXAPI kex_GdiFlush(void) { return (BOOL)guarded("GdiFlush", &c_flush, 0, NULL); }
HDC KEXAPI kex_CreateCompatibleDC(HDC dc) { DWORD a[1]; a[0] = (DWORD)(ULONG_PTR)dc; return (HDC)(ULONG_PTR)guarded("CreateCompatibleDC", &c_cdc, 1, a); }

/* ---- USER32 message functions (2026-11-02): Mypal's main thread crashed at XUL+14c8305 - first seen while dragging
 * the window, now after five minutes of YouTube - right after nsAppShell::ProcessNextNativeEvent returned with EBX
 * pointing into nss3's code: the same "callee came back with a register changed" pattern the GDI guard caught in
 * CreateCompatibleDC (ESP not popped, 2026-11-02 trace). The message calls it makes go through the guard too. */
#define UG(ret, name, n, params, ...) \
    static FARPROC c_##name; \
    ret KEXAPI kex_##name params { DWORD a[n + 1] = { __VA_ARGS__ }; return (ret)(ULONG_PTR)guarded_in("USER32.DLL", #name, &c_##name, n, a); }
#define D(x) (DWORD)(ULONG_PTR)(x)
/* build 63: Windows 98 knows wake bits 0x00FF only. NT 5.1+ headers make QS_ALLINPUT 0x1CFF (QS_RAWINPUT 0x400,
 * QS_TOUCH 0x800, QS_POINTER 0x1000) - Chromium's COM thread-pool threads wait with
 * MsgWaitForMultipleObjectsEx(1, &wake_event, ..., QS_ALLINPUT, 0); the Save As thread never woke up for its task.
 * The extra bits are dropped (they can never be set on 98 anyway); PM_QS_* in PeekMessage's high word likewise. */
#define QS98(x) ((x) & 0x00FFu)
#define PM98(x) ((x) & 0x00FFFFFFu)
UG(BOOL, PeekMessageW, 5, (LPMSG m, HWND w, UINT a1, UINT a2, UINT r), D(m), D(w), a1, a2, PM98(r))
UG(BOOL, PeekMessageA, 5, (LPMSG m, HWND w, UINT a1, UINT a2, UINT r), D(m), D(w), a1, a2, PM98(r))
UG(BOOL, GetMessageW, 4, (LPMSG m, HWND w, UINT a1, UINT a2), D(m), D(w), a1, a2)
UG(BOOL, GetMessageA, 4, (LPMSG m, HWND w, UINT a1, UINT a2), D(m), D(w), a1, a2)
UG(LRESULT, DispatchMessageW, 1, (const MSG *m), D(m))
UG(LRESULT, DispatchMessageA, 1, (const MSG *m), D(m))
UG(BOOL, TranslateMessage, 1, (const MSG *m), D(m))
UG(DWORD, MsgWaitForMultipleObjects, 5, (DWORD n, const HANDLE *h, BOOL all, DWORD ms, DWORD mask), n, D(h), all, ms, QS98(mask))
/* build 64: the Save As thread ("ThreadPoolSingleThreadCOMSTAForeground...", Chromium's dedicated COM runner)
 * sits in this wait and never calls CoCreateInstance. kextest proved Windows 98 wakes such a wait fine. So: for
 * threads with that name, every wait and its result goes to KEXCRASH (first 60) - does it ever wake after the
 * click, and does it go straight back to sleep? */
static FARPROC c_MsgWaitForMultipleObjectsEx;
DWORD KEXAPI kex_MsgWaitForMultipleObjectsEx(DWORD n, const HANDLE *h, DWORD ms, DWORD mask, DWORD fl)
{
    DWORD a[5], r, t0 = 0; int watch = 0;
    const char *kex_thread_name(DWORD tid);
    static LONG notes;
    a[0] = n; a[1] = D(h); a[2] = ms; a[3] = QS98(mask); a[4] = fl & 7u;
    if (notes < 60) {
        const char *nm = kex_thread_name(GetCurrentThreadId());
        static const char want[] = "ThreadPoolSingleThreadCOMSTAForeground";
        int i = 0;
        if (nm) { while (want[i] && nm[i] == want[i]) i++; }
        if (nm && !want[i]) { watch = 1; t0 = GetTickCount(); }
    }
    r = (DWORD)guarded_in("USER32.DLL", "MsgWaitForMultipleObjectsEx", &c_MsgWaitForMultipleObjectsEx, 5, a);
    if (watch && InterlockedIncrement(&notes) <= 60) {
        DWORD le = GetLastError();
        kex_crashnote("COM dialog thread: MsgWaitForMultipleObjectsEx (result, waited ms, timeout, first handle)",
                      r, GetTickCount() - t0, ms, (n && h) ? (DWORD)(ULONG_PTR)h[0] : 0);
        SetLastError(le);
    }
    return r;
}
UG(LRESULT, SendMessageW, 4, (HWND w, UINT m, WPARAM wp, LPARAM lp), D(w), m, wp, lp)
UG(LRESULT, DefWindowProcW, 4, (HWND w, UINT m, WPARAM wp, LPARAM lp), D(w), m, wp, lp)
UG(LRESULT, CallWindowProcW, 5, (WNDPROC f, HWND w, UINT m, WPARAM wp, LPARAM lp), D(f), D(w), m, wp, lp)
UG(BOOL, PostMessageW, 4, (HWND w, UINT m, WPARAM wp, LPARAM lp), D(w), m, wp, lp)

/* ---- every other GDI32 export of Windows 98 (guard_gen.c, generated by gen_guard.py), 2026-11-02.
 * Extended the same day to every USER32 and WINMM export: Mypal's main thread came back from UpdateWindow
 * with ESI holding a value from the painting code it had run (kex_GetDeviceCaps) and a return address one
 * byte short; a WINMM thread jumped into a WAVEHDR. All three DLLs reach 16-bit code through thunks, the
 * place the CreateCompatibleDC misbehaviour also comes from.
 * CreateCompatibleDC came back twice without removing its argument (caught by the guard), and the latest
 * crashes show GDI handle values (0x1DB6, 0x1DCA, 0x1DD2) where a pointer belonged - what a caller with a
 * shifted stack would write. The same misbehaviour in any other GDI call would go unseen, so all of them now
 * go through the guard. Each generated stub pushes its index and jumps here. */
extern const char *const kexg_names[];
extern const char *const kexg_dlls[];
extern const unsigned char kexg_dll[];
extern const unsigned short kexg_nargs[];
extern FARPROC kexg_cache[];
/* HWND_MESSAGE (Windows 2000+ message-only windows) does not exist on Windows 98: CreateWindowEx with that
 * parent fails, which stopped Chrome at window_impl.cc:250 (gfx::SingletonHwnd, 2026-11-02). kexnt turns
 * such a window into a hidden top-level tool window (no WS_VISIBLE/WS_CHILD, WS_POPUP, WS_EX_TOOLWINDOW);
 * SetParent(h, HWND_MESSAGE) hides the window instead, FindWindowEx(HWND_MESSAGE, ...) searches top level. */
#define K_HWND_MESSAGE 0xFFFFFFFDUL
extern const int kexg_count;
static int g_ix_setcap = -1, g_ix_relcap = -1, g_ix_gmei = -1;
static int g_ix_bblt = -1, g_ix_sblt = -1;
static int g_ix_enw = -1, g_ix_gqs = -1, g_ix_liw = -1, g_ix_lia = -1, g_ix_gwdc = -1, g_ix_gdc = -1, g_ix_gdcx = -1;
static int g_ix_cwa = -2, g_ix_cww, g_ix_setp, g_ix_fwa, g_ix_fww, g_ix_rcw, g_ix_rcxw, g_ix_rca, g_ix_rcxa, g_ix_eds[4];
static void ix_init(void)
{
    int i;
    g_ix_cww = g_ix_setp = g_ix_fwa = g_ix_fww = g_ix_rcw = g_ix_rcxw = g_ix_rca = g_ix_rcxa = -1;
    g_ix_eds[0] = g_ix_eds[1] = g_ix_eds[2] = g_ix_eds[3] = -1;
    for (i = 0; i < kexg_count; i++) {
        const char *n = kexg_names[i];
        if (!lstrcmpA(n, "CreateWindowExA")) g_ix_cwa = i;
        else if (!lstrcmpA(n, "EnableWindow")) g_ix_enw = i;
        else if (!lstrcmpA(n, "GetQueueStatus")) g_ix_gqs = i;
        else if (!lstrcmpA(n, "BitBlt")) g_ix_bblt = i;
        else if (!lstrcmpA(n, "StretchBlt")) g_ix_sblt = i;
        else if (!lstrcmpA(n, "GetWindowDC")) g_ix_gwdc = i;
        else if (!lstrcmpA(n, "GetDC")) g_ix_gdc = i;
        else if (!lstrcmpA(n, "GetDCEx")) g_ix_gdcx = i;
        else if (!lstrcmpA(n, "LoadImageW")) g_ix_liw = i;
        else if (!lstrcmpA(n, "LoadImageA")) g_ix_lia = i;
        else if (!lstrcmpA(n, "CreateWindowExW")) g_ix_cww = i;
        else if (!lstrcmpA(n, "SetParent")) g_ix_setp = i;
        else if (!lstrcmpA(n, "FindWindowExA")) g_ix_fwa = i;
        else if (!lstrcmpA(n, "FindWindowExW")) g_ix_fww = i;
        else if (!lstrcmpA(n, "RegisterClassW")) g_ix_rcw = i;
        else if (!lstrcmpA(n, "RegisterClassExW")) g_ix_rcxw = i;
        else if (!lstrcmpA(n, "RegisterClassA")) g_ix_rca = i;
        else if (!lstrcmpA(n, "RegisterClassExA")) g_ix_rcxa = i;
        else if (!lstrcmpA(n, "EnumDisplaySettingsA")) g_ix_eds[0] = i;
        else if (!lstrcmpA(n, "EnumDisplaySettingsW")) g_ix_eds[1] = i;
        else if (!lstrcmpA(n, "EnumDisplaySettingsExA")) g_ix_eds[2] = i;
        else if (!lstrcmpA(n, "EnumDisplaySettingsExW")) g_ix_eds[3] = i;
        else if (!lstrcmpA(n, "SetCapture")) g_ix_setcap = i;
        else if (!lstrcmpA(n, "ReleaseCapture")) g_ix_relcap = i;
        else if (!lstrcmpA(n, "GetMessageExtraInfo")) g_ix_gmei = i;
    }
    if (g_ix_cwa == -2) g_ix_cwa = -1;
}
static LONG g_create_logs;
/* Window classes and the module that registered them (2026-11-02). Chrome registers its window classes with
 * the instance of chrome.dll and then calls CreateWindowEx with hInstance NULL. Windows NT finds a local class
 * whatever instance is passed when the caller gives none; Windows 98 looks the class up under the program's
 * own instance, finds nothing and fails before the window procedure sees a single message (Chrome's first
 * browser window: class c2a0, error 0, no messages). kexnt remembers each registration and fills in the
 * registering module when CreateWindowEx gets no instance for a class registered by a DLL of the process. */
typedef struct { DWORD atom, hinst; WCHAR name[64]; } KCLS;
static KCLS g_cls[160]; static LONG g_cls_n; static CRITICAL_SECTION g_cls_cs; static volatile LONG g_cls_init;
static void cls_lock(void)
{
    if (InterlockedCompareExchange(&g_cls_init, 1, 0) == 0) { InitializeCriticalSection(&g_cls_cs); g_cls_init = 2; }
    while (g_cls_init != 2) Sleep(1);
    EnterCriticalSection(&g_cls_cs);
}
static void cls_name(WCHAR *d, const void *src, int wide)
{
    int i;
    if (wide) { const WCHAR *w = (const WCHAR *)src; for (i = 0; i < 63 && w[i]; i++) d[i] = w[i]; }
    else { const unsigned char *a = (const unsigned char *)src; for (i = 0; i < 63 && a[i]; i++) d[i] = a[i]; }
    d[i] = 0;
    for (i = 0; d[i]; i++) if (d[i] >= 'A' && d[i] <= 'Z') d[i] += 32;
}
static int cls_eq(const WCHAR *a, const WCHAR *b) { while (*a && *a == *b) a++, b++; return *a == *b; }
static void cls_record(DWORD atom, DWORD hinst, const void *name, int wide)
{
    WCHAR nm[64]; LONG i;
    atom &= 0xFFFF;
    if (!atom) return;
    nm[0] = 0;
    if ((DWORD)(ULONG_PTR)name > 0xFFFF) cls_name(nm, name, wide);
    cls_lock();
    for (i = 0; i < g_cls_n; i++) if (g_cls[i].atom == atom || (nm[0] && cls_eq(g_cls[i].name, nm))) break;
    if (i == g_cls_n && g_cls_n < 160) g_cls_n++;
    if (i < 160) { g_cls[i].atom = atom; g_cls[i].hinst = hinst; memcpy(g_cls[i].name, nm, sizeof(nm)); }
    LeaveCriticalSection(&g_cls_cs);
}
static DWORD cls_find(const void *cls, int wide)
{
    WCHAR nm[64]; LONG i; DWORD a = (DWORD)(ULONG_PTR)cls, h = 0;
    if (!g_cls_n) return 0;
    if (a > 0xFFFF) { cls_name(nm, cls, wide); a = 0; } else nm[0] = 0;
    cls_lock();
    for (i = 0; i < g_cls_n; i++)
        if ((a && g_cls[i].atom == a) || (!a && nm[0] && cls_eq(g_cls[i].name, nm))) { h = g_cls[i].hinst; break; }
    LeaveCriticalSection(&g_cls_cs);
    return h;
}
/* What the window procedure answered while a CreateWindowEx ran (WH_CALLWNDPROCRET hook on this thread):
 * a window procedure that returns FALSE for WM_NCCREATE or -1 for WM_CREATE makes CreateWindowEx fail with
 * no error code - Chrome's first browser window, 2026-11-02. Written to KEXTRACE only when the call failed. */
typedef struct { DWORD msg, res, hwnd; } KWREC;
static KWREC g_wrec[48]; static volatile LONG g_wrec_n, g_wrec_owner;
static HHOOK g_wret_hk;
static LRESULT CALLBACK wret_hook(int code, WPARAM wp, LPARAM lp)
{
    typedef LRESULT (WINAPI *T_CNH)(HHOOK, int, WPARAM, LPARAM);
    static T_CNH cnh;
    if (code >= 0 && lp && (DWORD)g_wrec_owner == GetCurrentThreadId() && g_wrec_n < 48) {
        const DWORD *c = (const DWORD *)lp;                   /* CWPRETSTRUCT: lResult, lParam, wParam, message, hwnd */
        g_wrec[g_wrec_n].res = c[0]; g_wrec[g_wrec_n].msg = c[3]; g_wrec[g_wrec_n].hwnd = c[4]; g_wrec_n++;
    }
    if (!cnh) cnh = (T_CNH)(void *)kex_sysproc("USER32.DLL", "CallNextHookEx");
    return cnh ? cnh(g_wret_hk, code, wp, lp) : 0;
}
/* EnumDisplaySettings on Windows 98 leaves the display part of DEVMODE's union (dmPosition, dmDisplayOrientation,
 * dmDisplayFixedOutput - Windows 2000+ fields) as the driver or the caller left it. Chrome maps
 * dmDisplayOrientation to a rotation and stops on any value other than 0-3 (ui/display/win/screen_win.cc:176,
 * 2026-11-02). Fields the call did not report (dmFields bits DM_POSITION 0x20, DM_DISPLAYORIENTATION 0x80,
 * DM_DISPLAYFIXEDOUTPUT 0x20000000) are set to the Windows 2000 defaults: position 0,0, DMDO_DEFAULT, DMDFO_DEFAULT. */
static void devmode_fix(BYTE *dm, int wide)
{
    DWORD *f = (DWORD *)(dm + (wide ? 72 : 40));                 /* dmFields; the union follows it */
    LONG *u = (LONG *)(f + 1);                                   /* dmPosition.x, .y, dmDisplayOrientation, dmDisplayFixedOutput */
    if (IsBadWritePtr(dm, wide ? 92 : 60)) return;
    if (!(*f & 0x20)) { u[0] = 0; u[1] = 0; }
    if (!(*f & 0x80) || (DWORD)u[2] > 3) u[2] = 0;
    if (!(*f & 0x20000000) || (DWORD)u[3] > 2) u[3] = 0;
}
/* ---- build 56: what Chromium calls per second (flashing hunt). For the first 16 x 5 s after the first
 * DispatchMessage, KEXCRASH gets "--- calls in 5 s:" with the 24 most-called guarded USER/GDI functions, the
 * WM_PAINT / WM_ERASEBKGND-relevant counters, SwapBuffers per DC (with its window) and SetWindowRgn by the
 * program vs by kexnt. Cheap: one increment per call. */
extern const int kexg_count;
static volatile LONG g_st_cnt[1200];
volatile LONG kex_st_swr_prog, kex_st_swr_kex, kex_st_paint, kex_st_swap, kex_st_glass_read;
static struct { HDC dc; HWND w; volatile LONG n; } g_st_dc[8];
static DWORD g_st_t0; static volatile LONG g_st_dumps, g_st_lock;
void kex_stat_swap(HDC dc)
{
    int i;
    InterlockedIncrement(&kex_st_swap);
    for (i = 0; i < 8; i++) {
        if (g_st_dc[i].dc == dc) { InterlockedIncrement(&g_st_dc[i].n); return; }
        if (!g_st_dc[i].dc && InterlockedCompareExchange((LONG *)&g_st_dc[i].dc, (LONG)(ULONG_PTR)dc, 0) == 0) {
            typedef HWND (WINAPI *T_WFDC)(HDC); T_WFDC f = (T_WFDC)(void *)kex_sysproc("USER32.DLL", "WindowFromDC");
            g_st_dc[i].w = f ? f(dc) : NULL; InterlockedIncrement(&g_st_dc[i].n); return;
        }
    }
}
static void stat_tick(void)
{
    DWORD now = GetTickCount(); int i, k, top[24], nt = 0;
    if (!g_st_t0) { g_st_t0 = now ? now : 1; return; }
    if (now - g_st_t0 < 5000 || g_st_dumps >= 16 || InterlockedExchange(&g_st_lock, 1)) return;
    if (now - g_st_t0 >= 5000 && g_st_dumps < 16) {
        DWORD le = GetLastError();
        g_st_t0 = now; InterlockedIncrement(&g_st_dumps);
        for (i = 0; i < kexg_count && i < 1200; i++) {
            LONG c = g_st_cnt[i]; if (!c) continue;
            if (nt < 24) top[nt++] = i;
            else { int m = 0; for (k = 1; k < 24; k++) if (g_st_cnt[top[k]] < g_st_cnt[top[m]]) m = k; if (c > g_st_cnt[top[m]]) top[m] = i; }
        }
        for (i = 0; i < nt; i++) for (k = i + 1; k < nt; k++) if (g_st_cnt[top[k]] > g_st_cnt[top[i]]) { int t = top[i]; top[i] = top[k]; top[k] = t; }
        kex_crashnote("calls in 5 s: SwapBuffers, WM_PAINT dispatched, SetWindowRgn by program / by kexnt", (DWORD)InterlockedExchange(&kex_st_swap, 0),
                      (DWORD)InterlockedExchange(&kex_st_paint, 0), (DWORD)InterlockedExchange(&kex_st_swr_prog, 0), (DWORD)InterlockedExchange(&kex_st_swr_kex, 0));
        for (i = 0; i < 8; i++) if (g_st_dc[i].dc) kex_crashnote("  SwapBuffers on DC, window, count", (DWORD)(ULONG_PTR)g_st_dc[i].dc, (DWORD)(ULONG_PTR)g_st_dc[i].w, (DWORD)InterlockedExchange(&g_st_dc[i].n, 0), 0);
        for (i = 0; i < nt; i++) kex_crashnote(kexg_names[top[i]], (DWORD)g_st_cnt[top[i]], 0, 0, 0);
        for (i = 0; i < kexg_count && i < 1200; i++) g_st_cnt[i] = 0;
        SetLastError(le);
    }
    InterlockedExchange(&g_st_lock, 0);
}

DWORD kexg_dispatch(int idx, const DWORD *args)
{
    const char *n = kexg_names[idx];
    DWORD fixed[12], r, caller = args ? args[-1] : 0;   /* kexg_common: the return address lies just below the arguments */
    if (idx < 1200) InterlockedIncrement(&g_st_cnt[idx]);
    if (g_ix_cwa == -2) ix_init();
    if ((idx == g_ix_liw || idx == g_ix_lia) && (args[0] & 3)) {   /* build 85: icons of data-file modules (res_ext.c) */
        int kex_res_load_image(const DWORD *args, BOOL wide, DWORD *out);
        DWORD out;
        if (kex_res_load_image(args, idx == g_ix_liw, &out)) return out;
    }
    /* build 108: a DC for a window that no longer exists (Chromium's HWNDMessageHandler paints the frame while the
     * window is being destroyed): NT returns NULL; Windows 98's 16-bit USER came back WITHOUT popping its argument
     * (build 91, three times, then the GDI crash). Answer like NT and do not enter the thunk. */
    if ((idx == g_ix_gwdc || idx == g_ix_gdc || idx == g_ix_gdcx) && args[0]) {
        typedef BOOL (WINAPI *T_IW)(HWND); static T_IW iw;
        if (!iw) iw = (T_IW)(void *)kex_sysproc("USER32.DLL", "IsWindow");
        if (iw && !iw((HWND)(ULONG_PTR)args[0])) {
            static LONG n4; if (InterlockedIncrement(&n4) <= 20) kex_crashnote("DC for a window that no longer exists: NULL as on NT (window, caller)", args[0], caller, 0, 0);
            SetLastError(ERROR_INVALID_WINDOW_HANDLE);
            return 0;
        }
    }
    if (idx == g_ix_gqs && (args[0] & ~0xFFu)) { fixed[0] = args[0] & 0xFFu; args = fixed; }   /* build 63: 98 wake bits only */
    /* build 128: CAPTUREBLT (0x40000000, "include layered windows") and NOMIRRORBITMAP (0x80000000) are 2000+ flags in
     * the raster operation. Windows 98's BitBlt returns TRUE for such a rop but copies NOTHING (measured: 0 of 307200
     * pixels from the screen DC with SRCCOPY|CAPTUREBLT, 175197 with plain SRCCOPY) - Chrome's/WebRTC's GDI screen
     * capturer uses SRCCOPY|CAPTUREBLT, so shared screens were black. 98 has no layered windows to include anyway. */
    if ((idx == g_ix_bblt && (args[8] & 0xC0000000UL)) || (idx == g_ix_sblt && (args[10] & 0xC0000000UL))) {
        int k, na = idx == g_ix_bblt ? 9 : 11;
        for (k = 0; k < na; k++) fixed[k] = args[k];
        fixed[na - 1] &= 0x3FFFFFFFUL; args = fixed;
    }
    if (idx == g_ix_enw) { void kex_hang_note_enable(HWND w, BOOL on); kex_hang_note_enable((HWND)(ULONG_PTR)args[0], (BOOL)args[1]); }
    if ((idx == g_ix_cwa || idx == g_ix_cww) && args[8] == K_HWND_MESSAGE) {
        memcpy(fixed, args, sizeof(fixed));
        fixed[8] = 0;                                         /* no parent */
        fixed[3] = (fixed[3] & ~(WS_VISIBLE | WS_CHILD)) | WS_POPUP;
        fixed[0] |= WS_EX_TOOLWINDOW;
        args = fixed;
    }
    if ((idx == g_ix_cwa || idx == g_ix_cww) && args[10] == 0) {
        DWORD h = cls_find((const void *)(ULONG_PTR)args[1], idx == g_ix_cww);
        if (h && h != (DWORD)(ULONG_PTR)GetModuleHandleA(NULL)) {
            static LONG logged;
            if (args != fixed) { memcpy(fixed, args, sizeof(fixed)); args = fixed; }
            fixed[10] = h;
            if (InterlockedIncrement(&logged) <= 8) kex_trace("CreateWindowEx: no instance given, using the class's module", args[1], h, 0, 0);
        }
    }
    if (idx == g_ix_setp && args[1] == K_HWND_MESSAGE) {
        fixed[0] = args[0]; fixed[1] = 0; args = fixed;
        { typedef BOOL (WINAPI *T_SW)(HWND, int); T_SW sw = (T_SW)(void *)kex_sysproc("USER32.DLL", "ShowWindow");
          if (sw) sw((HWND)(ULONG_PTR)fixed[0], SW_HIDE); }
    } else if ((idx == g_ix_fwa || idx == g_ix_fww) && args[0] == K_HWND_MESSAGE) {
        memcpy(fixed, args, 4 * 4); fixed[0] = 0; args = fixed;
    }
    if ((idx == g_ix_cww || idx == g_ix_cwa) && g_create_logs < 40
            && InterlockedCompareExchange(&g_wrec_owner, (LONG)GetCurrentThreadId(), 0) == 0) {
        typedef HHOOK (WINAPI *T_SWH)(int, HOOKPROC, HINSTANCE, DWORD);
        typedef BOOL (WINAPI *T_UWH)(HHOOK);
        T_SWH swh = (T_SWH)(void *)kex_sysproc("USER32.DLL", "SetWindowsHookExA");
        T_UWH uwh = (T_UWH)(void *)kex_sysproc("USER32.DLL", "UnhookWindowsHookEx");
        HHOOK hk = swh ? swh(12 /* WH_CALLWNDPROCRET */, wret_hook, NULL, GetCurrentThreadId()) : NULL;
        g_wret_hk = hk;
        DWORD le, i;
        g_wrec_n = 0;
        r = guarded_in(kexg_dlls[kexg_dll[idx]], n, &kexg_cache[idx], kexg_nargs[idx], args);
        le = GetLastError();
        if (hk && uwh) uwh(hk);
        InterlockedIncrement(&g_create_logs);
        noact_record(r, args[0], caller);
        if (r) kex_trace("CreateWindowEx ok: hwnd exstyle class style", r, args[0], args[1], args[3]);
        else {
            kex_trace("CreateWindowEx FAILED exstyle class style err", args[0], args[1], args[3], le);
            kex_trace("CreateWindowEx FAILED x y w|h<<16 parent", args[4], args[5], (args[6] & 0xFFFF) | (args[7] << 16), args[8]);
            kex_trace("CreateWindowEx FAILED hInstance lpParam hook messages", args[10], args[11], hk ? 1 : 0, (DWORD)g_wrec_n);
            for (i = 0; i < (DWORD)g_wrec_n; i++) kex_trace("  window proc: msg result hwnd", g_wrec[i].msg, g_wrec[i].res, g_wrec[i].hwnd, 0);
        }
        g_wrec_owner = 0;
        SetLastError(le);
        return r;
    }
    r = guarded_at(kexg_dlls[kexg_dll[idx]], n, &kexg_cache[idx], kexg_nargs[idx], args, caller);
    /* build 115: what Chrome's window code does with a click (Discord: the button press reaches Chrome's frame but
     * never the page). Mouse capture taken / given up, and what GetMessageExtraInfo answered: Chromium drops a
     * mouse message whose extra info carries the touch/pen signature (0xFF515700 in the top 24 bits). */
    if (idx == g_ix_setcap || idx == g_ix_relcap) {
        static LONG nc; DWORD le = GetLastError();
        if (InterlockedIncrement(&nc) <= 300)
            kex_crashnote(idx == g_ix_setcap ? "click: SetCapture (window, previous capture, tick, caller)" : "click: ReleaseCapture (result, -, tick, caller)",
                          idx == g_ix_setcap ? args[0] : r, idx == g_ix_setcap ? r : 0, GetTickCount(), caller);
        SetLastError(le);
    } else if (idx == g_ix_gmei && r) {
        static DWORD seen[16]; static LONG ns, ntouch; LONG i2, k2 = ns;
        DWORD le = GetLastError();
        if ((r & 0xFFFFFF00UL) == 0xFF515700UL && InterlockedIncrement(&ntouch) <= 60)
            kex_crashnote("click: GetMessageExtraInfo has the touch/pen signature - Chromium ignores this mouse message (value, tick, caller)", r, GetTickCount(), caller, 0);
        for (i2 = 0; i2 < k2 && i2 < 16; i2++) if (seen[i2] == r) break;
        if (i2 == k2 && k2 < 16) { seen[k2] = r; ns = k2 + 1; kex_crashnote("click: GetMessageExtraInfo new non-zero value (value, tick, caller)", r, GetTickCount(), caller, 0); }
        SetLastError(le);
    }
    if (r && (idx == g_ix_cww || idx == g_ix_cwa)) noact_record(r, args[0], caller);
    if (r && args) {
        const DWORD *wc = (const DWORD *)(ULONG_PTR)args[0];
        if (idx == g_ix_rcw || idx == g_ix_rca) { if (wc) cls_record(r, wc[4], (const void *)(ULONG_PTR)wc[9], idx == g_ix_rcw); }
        else if (idx == g_ix_rcxw || idx == g_ix_rcxa) { if (wc) cls_record(r, wc[5], (const void *)(ULONG_PTR)wc[10], idx == g_ix_rcxw); }
    }
    if (r && (idx == g_ix_eds[0] || idx == g_ix_eds[1] || idx == g_ix_eds[2] || idx == g_ix_eds[3]) && args[2])
        devmode_fix((BYTE *)(ULONG_PTR)args[2], idx == g_ix_eds[1] || idx == g_ix_eds[3]);
    if (!r && (idx == g_ix_rcw || idx == g_ix_rcxw) && InterlockedIncrement(&g_create_logs) <= 40) {
        DWORD le = GetLastError();
        kex_trace(n, args[0], le, 0, 0);
        SetLastError(le);
    }
    return r;
}
/* ---- build 55: GLDirect A/B test. Both GPU-mode crashes (CHRVAR 1 and 2, build 54) happened in Windows 98's
 * OPENGL32.DLL right after it called USER32 (GetDC/ReleaseDC/GetDeviceCaps in its window hook, WindowFromDC in
 * wglSwapBuffers) - and those calls went through this guard, because KernelEx gives OPENGL32 (a private DLL)
 * kexnt's imports too. With HKLM\Software\KernelEx\KexNG "GLDirect" = 1 (CHRVAR 6 sets it) calls made from
 * OPENGL32.DLL or the OpenGL driver jump straight to the same implementation, with no guard frame, no TIB+0x14
 * chain and nothing of kexnt on the stack. Crash with 0 but not with 1 -> the guard is at fault; crash with
 * both -> Windows 98 / the driver. Read once per process. */
volatile LONG kexg_gl_direct = -1;
static void *g_glmod[8], *g_notgl[64]; static volatile LONG g_nglmod, g_nnotgl;
static int is_gl_name(const char *nm)
{
    char t[16]; int k;
    for (k = 0; k < 15 && nm[k]; k++) t[k] = (char)((nm[k] >= 'a' && nm[k] <= 'z') ? nm[k] - 32 : nm[k]);
    t[k] = 0;
    return !lstrcmpA(t, "OPENGL32.DLL") || !lstrcmpA(t, "VMWSGL32.DLL") || !lstrcmpA(t, "MESA3D.DLL") ||
           (t[0] == 'M' && t[1] == 'E' && t[2] == 'S' && t[3] == 'A');
}
FARPROC kexg_direct_target(int idx, DWORD ret)
{
    MEMORY_BASIC_INFORMATION m; BYTE *b; int i, n;
    if (kexg_gl_direct < 0) {
        HKEY k; DWORD v = 0, t, sz = sizeof(v);
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx\\KexNG", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            if (RegQueryValueExA(k, "GLDirect", NULL, &t, (BYTE *)&v, &sz) != ERROR_SUCCESS || t != REG_DWORD) v = 0;
            RegCloseKey(k);
        }
        InterlockedExchange(&kexg_gl_direct, v ? 1 : 0);
        if (v) kex_crashnote("GLDirect on: USER32/GDI32 calls from OPENGL32 and the GL driver bypass the guard", v, 0, 0, 0);
    }
    if (kexg_gl_direct != 1 || !kexg_cache[idx]) return NULL;
    if (ret < 0x10000 || !VirtualQuery((LPCVOID)(ULONG_PTR)ret, &m, sizeof(m)) || m.State != MEM_COMMIT) return NULL;
    b = (BYTE *)m.AllocationBase;
    n = g_nglmod; for (i = 0; i < n && i < 8; i++) if (g_glmod[i] == b) return kexg_cache[idx];
    n = g_nnotgl; for (i = 0; i < n && i < 64; i++) if (g_notgl[i] == b) return NULL;
    if (b && !IsBadReadPtr(b, 0x40) && b[0] == 'M' && b[1] == 'Z') {
        IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
        const char *nm = NULL;
        if (!IsBadReadPtr(nt, sizeof(*nt)) && nt->Signature == IMAGE_NT_SIGNATURE &&
            nt->OptionalHeader.NumberOfRvaAndSizes > 0 && nt->OptionalHeader.DataDirectory[0].VirtualAddress) {
            IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
            if (!IsBadReadPtr(ed, sizeof(*ed)) && ed->Name && !IsBadStringPtrA((const char *)b + ed->Name, 64)) nm = (const char *)b + ed->Name;
        }
        if (nm && is_gl_name(nm)) {
            i = InterlockedIncrement(&g_nglmod) - 1;
            if (i < 8) { g_glmod[i] = b; kex_crashnote("GLDirect: module whose calls go straight through (base, first call)", (DWORD)(ULONG_PTR)b, ret, (DWORD)idx, 0); }
            return kexg_cache[idx];
        }
    }
    i = InterlockedIncrement(&g_nnotgl) - 1;
    if (i < 64) g_notgl[i] = b;
    return NULL;
}

/* [esp] = index, [esp+4] = return address, arguments above. Calls kexg_dispatch, then returns past the
 * arguments (stdcall). ECX/EDX are free (caller-saved); EBX/ESI/EDI/EBP are kept by kexg_dispatch.
 * Build 55: with GLDirect, a call from OPENGL32 / the GL driver drops the index and jumps to the real function
 * with the stack exactly as its caller built it. */
__asm__(
    ".text\n.globl _kexg_common\n_kexg_common:\n"
    "  cmpl $0, _kexg_gl_direct\n  je 9f\n"
    "  pushl 4(%esp)\n  pushl 4(%esp)\n  call _kexg_direct_target\n  addl $8, %esp\n"
    "  testl %eax, %eax\n  jz 9f\n  addl $4, %esp\n  jmp *%eax\n"
    "9:\n"
    "  pushl %ebp\n  movl %esp, %ebp\n"
    "  pushl 4(%ebp)\n  pushl 8(%ebp)\n"               /* own copies of index and return address */
    "  leal 12(%ebp), %eax\n  pushl %eax\n  pushl 4(%ebp)\n"
    "  call _kexg_dispatch\n"
    "  movl -4(%ebp), %ecx\n  movzwl _kexg_nargs(,%ecx,2), %ecx\n"
    "  movl -8(%ebp), %edx\n"
    "  movl %ebp, %esp\n  popl %ebp\n"
    "  leal 8(%esp,%ecx,4), %esp\n"
    "  jmp *%edx\n");

/* ---- build 42: the desktop window's process. Chromium initialises ANGLE with GetDC(NULL). ANGLE's OpenGL backend
 * (DisplayWGL) needs WindowFromDC(that DC) != NULL (Display::isValidNativeDisplay), then compares the window's process
 * (GetWindowThreadProcessId) with its own: another process -> render through DXGI swap chains, which needs
 * WGL_NV_DX_interop2 + Direct3D 11 - neither exists on Windows 98, eglInitialize failed and Chromium died in
 * gl_factory_win.cc. On 9x the desktop window is reported as belonging to the asking process (its thread id stays
 * real): ANGLE then draws straight into the program's own window with WGL. Helps every ANGLE program (Electron, Qt,
 * CEF). (build 41's "screen DC has no window" failed ANGLE's display validation instead.) */
static FARPROC c_gwtp, c_gdw;
DWORD KEXAPI kex_GetWindowThreadProcessId(HWND w, LPDWORD pid)
{
    DWORD a[2], r;
    a[0] = (DWORD)(ULONG_PTR)w; a[1] = (DWORD)(ULONG_PTR)pid;
    r = guarded_in("USER32.DLL", "GetWindowThreadProcessId", &c_gwtp, 2, a);
    if (pid && w && w == (HWND)(ULONG_PTR)guarded_in("USER32.DLL", "GetDesktopWindow", &c_gdw, 0, NULL))
        *pid = GetCurrentProcessId();
    { DWORD kex_pid_nt(DWORD real); if (pid) *pid = kex_pid_nt(*pid); }   /* build 131: NT-style id (pid_ext.c) */
    return r;
}

/* ---- build 45: SwapBuffers - shape "glass" windows (DwmExtendFrameIntoClientArea) from their alpha first */
static FARPROC c_swap;
BOOL KEXAPI kex_SwapBuffers(HDC dc)
{
    DWORD a[1]; void kex_glass_before_swap(HDC dc);   /* layered_ext.c */
    kex_glass_before_swap(dc);
    { void kex_stat_swap(HDC); kex_stat_swap(dc); }
    { BOOL kex_gl_present_gdi(HDC); if (kex_gl_present_gdi(dc)) return TRUE; }   /* build 57: GLPresent */
    a[0] = (DWORD)(ULONG_PTR)dc;
    {   BOOL r = (BOOL)guarded("SwapBuffers", &c_swap, 1, a);
        void kex_gl_keep_back(HDC dc);                                 /* layered_ext.c (build 53) */
        if (r) { DWORD le = GetLastError(); kex_gl_keep_back(dc); SetLastError(le); }
        return r; }
}

/* ---- build 48: Unicode text on the Windows 98 clipboard.
 * NT converts between CF_UNICODETEXT and CF_TEXT by itself; Windows 98 stores CF_UNICODETEXT like any private
 * format and never converts. Chromium puts only CF_UNICODETEXT on the clipboard ("copy" then pasted nowhere:
 * Notepad and every 9x program ask for CF_TEXT), and reads only CF_UNICODETEXT (text copied in 9x programs could
 * not be pasted into it). kexnt does the conversion NT does, in both directions, with the system code page. */
static FARPROC c_setcd, c_getcd, c_isfa;
static HGLOBAL g_clip_made;                      /* last CF_UNICODETEXT made from CF_TEXT (freed on the next one) */
static HGLOBAL text_convert(HGLOBAL src, BOOL to_unicode)
{
    SIZE_T n = GlobalSize(src); const void *p = GlobalLock(src); HGLOBAL d = NULL; int need;
    if (!p) return NULL;
    if (to_unicode) {
        int len = 0; while ((SIZE_T)len < n && ((const char *)p)[len]) len++;
        need = MultiByteToWideChar(CP_ACP, 0, (const char *)p, len, NULL, 0);
        if ((d = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, (need + 1) * sizeof(WCHAR))) != NULL) {
            WCHAR *w = (WCHAR *)GlobalLock(d);
            if (w) { MultiByteToWideChar(CP_ACP, 0, (const char *)p, len, w, need); w[need] = 0; GlobalUnlock(d); }
        }
    } else {
        int len = 0; while ((SIZE_T)(len + 1) * 2 <= n && ((const WCHAR *)p)[len]) len++;
        need = WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)p, len, NULL, 0, NULL, NULL);
        if ((d = GlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, need + 1)) != NULL) {
            char *a = (char *)GlobalLock(d);
            if (a) { WideCharToMultiByte(CP_ACP, 0, (const WCHAR *)p, len, a, need, NULL, NULL); a[need] = 0; GlobalUnlock(d); }
        }
    }
    GlobalUnlock(src);
    return d;
}
HANDLE KEXAPI kex_SetClipboardData(UINT fmt, HANDLE h)
{
    DWORD a[2]; HANDLE r;
    a[0] = fmt; a[1] = (DWORD)(ULONG_PTR)h;
    r = (HANDLE)(ULONG_PTR)guarded_in("USER32.DLL", "SetClipboardData", &c_setcd, 2, a);
    if (r && h && fmt == CF_UNICODETEXT) {
        DWORD b[1]; b[0] = CF_TEXT;
        if (!guarded_in("USER32.DLL", "IsClipboardFormatAvailable", &c_isfa, 1, b)) {
            HGLOBAL t = text_convert((HGLOBAL)h, FALSE);
            if (t) { a[0] = CF_TEXT; a[1] = (DWORD)(ULONG_PTR)t; if (!guarded_in("USER32.DLL", "SetClipboardData", &c_setcd, 2, a)) GlobalFree(t); }
        }
    }
    return r;
}
HANDLE KEXAPI kex_GetClipboardData(UINT fmt)
{
    DWORD a[1]; HANDLE r;
    a[0] = fmt;
    r = (HANDLE)(ULONG_PTR)guarded_in("USER32.DLL", "GetClipboardData", &c_getcd, 1, a);
    if (!r && fmt == CF_UNICODETEXT) {
        HANDLE t; a[0] = CF_TEXT;
        if ((t = (HANDLE)(ULONG_PTR)guarded_in("USER32.DLL", "GetClipboardData", &c_getcd, 1, a)) != NULL) {
            HGLOBAL u = text_convert((HGLOBAL)t, TRUE), old;
            if (u) { old = (HGLOBAL)InterlockedExchange((LONG *)&g_clip_made, (LONG)(ULONG_PTR)u); if (old) GlobalFree(old); r = u; }
        }
    }
    return r;
}
BOOL KEXAPI kex_IsClipboardFormatAvailable(UINT fmt)
{
    DWORD a[1]; BOOL r;
    a[0] = fmt;
    r = (BOOL)guarded_in("USER32.DLL", "IsClipboardFormatAvailable", &c_isfa, 1, a);
    if (!r && fmt == CF_UNICODETEXT) { a[0] = CF_TEXT; r = (BOOL)guarded_in("USER32.DLL", "IsClipboardFormatAvailable", &c_isfa, 1, a); }
    return r;
}

/* ---- build 50: a NULL region on a glass window keeps the shape kexnt gave it (layered_ext.c kex_glass_region) */
static FARPROC c_swrgn;
int KEXAPI kex_SetWindowRgn(HWND w, HRGN r, BOOL redraw)
{
    DWORD a[3];
    InterlockedIncrement(&kex_st_swr_prog);
    if (!r) { HRGN kex_glass_region(HWND h); HRGN g = kex_glass_region(w); if (g) r = g; }
    a[0] = (DWORD)(ULONG_PTR)w; a[1] = (DWORD)(ULONG_PTR)r; a[2] = (DWORD)redraw;
    return (int)guarded_in("USER32.DLL", "SetWindowRgn", &c_swrgn, 3, a);
}

/* ---- build 55: guard OPENGL32.DLL's own USER32/GDI32 calls.
 * CHRVAR 6 (GLDirect) proved OPENGL32's calls never came through kexnt at all (only the driver, VMWSGL32 at
 * 69500000, did), yet it crashed exactly as before: OPENGL32+bb91, WM_MOVE in its window hook, after a helper doing
 * GetDC(0)/GetDeviceCaps/ReleaseDC came back with ESP 4 bytes low (EBX held the ESI value, ESI/EDI the next slots).
 * The same run caught Windows 98's MonitorFromWindow (8 bytes of arguments) returning with ESP not moved at all, in
 * Chrome's own code - there the guard put it right. So Windows 98's USER32/GDI32 sometimes return without removing
 * their arguments (seen before in Mypal: CreateCompatibleDC), and OPENGL32 (a Windows DLL loaded privately, which
 * KernelEx leaves bound to the real USER32/GDI32) had no guard. kex_guard_imports() points such a module's
 * USER32/GDI32/WINMM import slots at kexnt's guarded stubs (same implementation behind them, ESP and EBX/ESI/EDI/EBP
 * restored after the call). Called before the module's DllMain (DLL entry hook) and after kexnt's LoadLibrary. */
extern const void *const kexg_stubs[];
extern const int kexg_count;
static int dll_index(const char *n)
{
    int i;
    for (i = 0; i < 3; i++) {                                    /* "USER32.dll" vs "USER32.DLL" */
        const char *a = n, *b = kexg_dlls[i];
        while (*a && *b && ((*a | 32) == (*b | 32))) a++, b++;
        if (!*a && !*b) return i;
    }
    return -1;
}
int kex_guard_imports(HMODULE mod)
{
    BYTE *b = (BYTE *)mod; IMAGE_NT_HEADERS32 *nt; IMAGE_IMPORT_DESCRIPTOR *d; DWORD rva; int n = 0, seen = 0;
    if (!b || IsBadReadPtr(b, 0x40) || b[0] != 'M' || b[1] != 'Z') return -1;
    nt = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
    if (IsBadReadPtr(nt, sizeof(*nt)) || nt->Signature != IMAGE_NT_SIGNATURE) return -1;
    rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!rva) return 0;
    for (d = (IMAGE_IMPORT_DESCRIPTOR *)(b + rva); !IsBadReadPtr(d, sizeof(*d)) && d->Name; d++) {
        int di = dll_index((const char *)b + d->Name);
        DWORD *iat = (DWORD *)(b + d->FirstThunk), *ilt;
        if (di < 0 || !d->OriginalFirstThunk) continue;          /* no name table: cannot tell the slots apart */
        for (ilt = (DWORD *)(b + d->OriginalFirstThunk); !IsBadReadPtr(ilt, 4) && *ilt; ilt++, iat++) {
            const char *fn; int k;
            if (*ilt & 0x80000000) continue;                      /* by ordinal */
            fn = (const char *)b + *ilt + 2;
            seen++;
            {   /* guarded calls kexnt writes by hand (not in the generated lists) */
                static const struct { int dll; const char *n; const void *f; } hand[] = {
                    { 0, "SelectObject", (const void *)kex_SelectObject }, { 0, "CreateDIBSection", (const void *)kex_CreateDIBSection },
                    { 0, "GdiFlush", (const void *)kex_GdiFlush }, { 0, "CreateCompatibleDC", (const void *)kex_CreateCompatibleDC },
                    { 1, "GetMessageA", (const void *)kex_GetMessageA }, { 1, "DispatchMessageA", (const void *)kex_DispatchMessageA },
                    { 1, "TranslateMessage", (const void *)kex_TranslateMessage } };
                int h, done = 0;
                for (h = 0; h < (int)(sizeof(hand) / sizeof(hand[0])); h++) {
                    if (hand[h].dll != di || lstrcmpA(hand[h].n, fn)) continue;
                    if (*iat != (DWORD)(ULONG_PTR)hand[h].f) {
                        DWORD old;
                        if (VirtualProtect(iat, 4, PAGE_READWRITE, &old)) { *iat = (DWORD)(ULONG_PTR)hand[h].f; n++; VirtualProtect(iat, 4, old, &old); }
                    }
                    done = 1; break;
                }
                if (done) continue;
            }
            for (k = 0; k < kexg_count; k++) {
                if (kexg_dll[k] != di || lstrcmpA(kexg_names[k], fn)) continue;
                if (*iat != (DWORD)(ULONG_PTR)kexg_stubs[k]) {
                    DWORD old;
                    if (VirtualProtect(iat, 4, PAGE_READWRITE, &old)) {
                        *iat = (DWORD)(ULONG_PTR)kexg_stubs[k]; n++;
                        VirtualProtect(iat, 4, old, &old);
                    }
                }
                break;
            }
        }
    }
    if (n) kex_crashnote("guarded imports of a Windows DLL (base, slots now guarded, named imports looked at)", (DWORD)(ULONG_PTR)b, (DWORD)n, (DWORD)seen, 0);
    return n;
}
/* which modules: Windows 98's OPENGL32.DLL (and GLU32.DLL, same kind) */
void kex_guard_imports_if_gl(HMODULE mod, const char *path)
{
    const char *s, *base = path; char t[16]; int k;
    if (!mod || !path || IsBadStringPtrA(path, MAX_PATH)) return;
    for (s = path; *s; s++) if (*s == '\\' || *s == '/' || *s == ':') base = s + 1;
    for (k = 0; k < 15 && base[k]; k++) t[k] = (char)((base[k] >= 'a' && base[k] <= 'z') ? base[k] - 32 : base[k]);
    t[k] = 0;
    if (!lstrcmpA(t, "OPENGL32.DLL") || !lstrcmpA(t, "OPENGL32") || !lstrcmpA(t, "GLU32.DLL"))
        kex_guard_imports(mod);
}

/* build 132 (TextTrace investigation): glyph functions Gecko's GDI font backend measures with. Plain pass-through to
 * the previous implementation (KernelEx kexbasen UberGDI.c); with KexNG\TextTrace=1 arguments and results are noted. */
typedef DWORD (WINAPI *T_GGIW)(HDC, LPCWSTR, int, LPWORD, DWORD);
typedef BOOL (WINAPI *T_GCWI)(HDC, UINT, UINT, LPWORD, LPINT);
typedef BOOL (WINAPI *T_GCABCI)(HDC, UINT, UINT, LPWORD, LPABC);
DWORD KEXAPI kex_GetGlyphIndicesW(HDC dc, LPCWSTR s, int n, LPWORD gi, DWORD fl)
{
    static T_GGIW prev; DWORD r;
    if (!prev) prev = (T_GGIW)(void *)kex_prev_impl("GDI32.DLL", "GetGlyphIndicesW");
    if (!prev || (void *)prev == (void *)kex_GetGlyphIndicesW) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return GDI_ERROR; }
    r = prev(dc, s, n, gi, fl);
    if (g_txt_on < 0) txt_init();
    if (g_txt_on == 1 && s && n > 0) { DWORD le = GetLastError(); txt_note("text: GetGlyphIndicesW (count, result, flags, first index)", s, n, FALSE, r, fl, gi ? gi[0] : 0); SetLastError(le); }
    return r;
}
BOOL KEXAPI kex_GetCharWidthI(HDC dc, UINT first, UINT cnt, LPWORD gi, LPINT w)
{
    static T_GCWI prev; BOOL r;
    if (!prev) prev = (T_GCWI)(void *)kex_prev_impl("GDI32.DLL", "GetCharWidthI");
    if (!prev || (void *)prev == (void *)kex_GetCharWidthI) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = prev(dc, first, cnt, gi, w);
    if (g_txt_on < 0) txt_init();
    if (g_txt_on == 1 && r && w && cnt > 0 && InterlockedIncrement(&g_txt_n) <= 400) {
        DWORD le = GetLastError(); typedef int (WINAPI *T_GTF)(HDC, int, LPSTR); T_GTF gtf = (T_GTF)(void *)kex_sysproc("GDI32.DLL", "GetTextFaceA");
        char t[120] = "text: GetCharWidthI (glyph, width, count, first) "; char face[48] = "";
        if (gtf) gtf(dc, sizeof(face), face);
        lstrcatA(t, face);
        kex_crashnote(t, gi ? gi[0] : first, (DWORD)w[0], cnt, first);
        SetLastError(le);
    }
    return r;
}

/* build 132 (DrawTrace investigation, Basilisk title bar): AlphaBlend pass-through to the previous implementation
 * (KernelEx's msimg32); with KexNG\DrawTrace=1 the call, the blend function and the destination's top-left pixel
 * before/after (plus the source's) are noted. No behaviour change. */
typedef BOOL (WINAPI *T_ALB)(HDC, int, int, int, int, HDC, int, int, int, int, BLENDFUNCTION);
BOOL KEXAPI kex_AlphaBlend(HDC d, int dx, int dy, int dw, int dh, HDC s, int sx, int sy, int sw, int sh, BLENDFUNCTION bf)
{
    static T_ALB prev; typedef COLORREF (WINAPI *T_GPX)(HDC, int, int); static T_GPX gpx; BOOL r; COLORREF before = 0, src = 0;
    if (!prev) prev = (T_ALB)(void *)kex_prev_impl("MSIMG32.DLL", "AlphaBlend");
    if (!prev || (void *)prev == (void *)kex_AlphaBlend) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    if (g_drw_on == 1) { if (!gpx) gpx = (T_GPX)(void *)kex_sysproc("GDI32.DLL", "GetPixel"); if (gpx) { before = gpx(d, dx, dy); src = gpx(s, sx, sy); } }
    r = prev(d, dx, dy, dw, dh, s, sx, sy, sw, sh, bf);
    if (g_drw_on == 1 && gpx && dy < 40 && InterlockedIncrement(&g_drw_n) <= 500) {
        DWORD le = GetLastError(); COLORREF after = gpx(d, dx, dy);
        kex_crashnote("draw: AlphaBlend (dx|dy<<16, dw|dh<<16, op|flags<<8|const<<16|format<<24, result)", (DWORD)(dx & 0xFFFF) | ((DWORD)dy << 16),
                      (DWORD)(dw & 0xFFFF) | ((DWORD)dh << 16), (DWORD)bf.BlendOp | ((DWORD)bf.BlendFlags << 8) | ((DWORD)bf.SourceConstantAlpha << 16) | ((DWORD)bf.AlphaFormat << 24), (DWORD)r);
        kex_crashnote("draw:   pixels at dest top-left (before, after, source, -)", before, after, src, 0);
        SetLastError(le);
    }
    return r;
}
