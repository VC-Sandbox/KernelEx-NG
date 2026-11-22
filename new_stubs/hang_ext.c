/*
 * hang_ext.c - KernelEx-NG: "where is every thread" dump for a program that starts but never draws.
 *
 * Build 48: Chrome stopped coming up (builds 46 and 47) without crashing, so KEXCRASH had nothing to say. The
 * build-28 thread snapshots exist but need TRACEON, take the log lock (a hung thread may hold it), use
 * Toolhelp and GetModuleFileName (both take KERNEL32's own lock - a thread hung inside the loader holds that).
 *
 * This one is always on in the main process of an NT 6+ program (command line without "--type="): 30 s and
 * 75 s after start, if nothing has been drawn yet (no SwapBuffers / BitBlt / StretchDIBits / SetDIBitsToDevice
 * went through the GDI guard), it writes KEXHANG_<program>.LOG next to the program. Threads come from kexnt's
 * own list (DLL_THREAD_ATTACH + the thread that armed the logger), each stopped only for GetThreadContext.
 * Module names come from the image's own export directory, found through VirtualQuery - no KERNEL32 lock is
 * taken. Only at the very end does it ask Toolhelp for threads it did not know (that call may block; by then
 * the file has everything else).
 */
#include "kexnt_common.h"
#include <tlhelp32.h>

#define HT_MAX 256
static struct { DWORD tid; HANDLE h; } g_ht[HT_MAX];
static volatile LONG g_nht, g_htlock, g_hang_on;
static volatile LONG g_drawn;
static char g_hpath[MAX_PATH];
static char g_hb[48 * 1024];
static int  g_hl;
const char *kex_thread_name(DWORD tid);   /* crashlog_ext.c (SetThreadDescription names) */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */

/* gdiguard_ext.c: every guarded call until the first drawing call */
void kex_hang_note_call(const char *name)
{
    if (g_drawn || !name) return;
    if (!lstrcmpA(name, "SwapBuffers") || !lstrcmpA(name, "BitBlt") || !lstrcmpA(name, "StretchDIBits") ||
        !lstrcmpA(name, "SetDIBitsToDevice"))
        InterlockedExchange(&g_drawn, 1);
}
LONG kex_hang_drawn(void) { return g_drawn; }

/* build 59: "Save As shows nothing, every click dings" = the program disabled its window for a dialog that never
 * came up. gdiguard_ext.c reports every EnableWindow; the watcher thread looks once a second and, when a window
 * of this process has been disabled for 5 s with no enabled popup of its own (GW_ENABLEDPOPUP), writes a thread
 * dump (number 200 and up) to KEXHANG_<program>.LOG and a line to KEXCRASH - no KEXDUMP needed. */
static volatile HWND g_dis_hwnd;
static volatile DWORD g_dis_tick;
static volatile LONG g_dis_dumped, g_dis_dumps;
void kex_hang_note_enable(HWND w, BOOL on)
{
    if (!g_hang_on || !w) return;
    if (!on) { g_dis_tick = GetTickCount(); g_dis_dumped = 0; g_dis_hwnd = w; }
    else if (w == g_dis_hwnd) g_dis_hwnd = NULL;
}

static void add_thread(DWORD tid, HANDLE h)
{
    LONG i;
    kex_spin_acquire(&g_htlock);
    for (i = 0; i < g_nht; i++) if (g_ht[i].tid == tid) break;
    if (i == g_nht && g_nht < HT_MAX) { g_ht[i].tid = tid; g_ht[i].h = h; g_nht++; h = NULL; }
    InterlockedExchange(&g_htlock, 0);
    if (h) CloseHandle(h);
}
static void add_self(void)
{
    HANDLE h = NULL;
    if (DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &h, 0, FALSE, DUPLICATE_SAME_ACCESS))
        add_thread(GetCurrentThreadId(), h);
}
void kex_hang_thread_attach(void) { if (g_hang_on) add_self(); }
/* build 52: threads are listed for the whole run now (KEXDUMP can ask for a dump at any time), so ended ones go */
void kex_hang_thread_detach(void)
{
    DWORD me = GetCurrentThreadId(); LONG i; HANDLE h = NULL;
    if (!g_hang_on) return;
    kex_spin_acquire(&g_htlock);
    for (i = 0; i < g_nht; i++) if (g_ht[i].tid == me) { h = g_ht[i].h; g_ht[i] = g_ht[g_nht - 1]; g_nht--; break; }
    InterlockedExchange(&g_htlock, 0);
    if (h) CloseHandle(h);
}

/* ---- writer (own buffer, own file: never the KEXCRASH lock) */
static void hput(const char *s) { while (*s && g_hl < (int)sizeof(g_hb) - 2) g_hb[g_hl++] = *s++; }
static void hhex(DWORD v, int d) { char t[9]; int i; for (i = d - 1; i >= 0; i--) { t[i] = "0123456789abcdef"[v & 15]; v >>= 4; } t[d] = 0; hput(t); }
static void hdec(DWORD v) { char t[12]; int i = 11; t[i] = 0; do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v); hput(t + i); }
static void hsdec(LONG v) { if (v < 0) { hput("-"); hdec((DWORD)-v); } else hdec((DWORD)v); }
static void hflush(void)
{
    HANDLE f = CreateFileA(g_hpath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD w;
    if (f != INVALID_HANDLE_VALUE) { SetFilePointer(f, 0, NULL, FILE_END); WriteFile(f, g_hb, (DWORD)g_hl, &w, NULL); CloseHandle(f); }
    g_hl = 0;
}

/* module name without any loader call: VirtualQuery -> allocation base -> MZ/PE -> export directory name */
static BOOL rd(const void *p, DWORD n) { return p && !IsBadReadPtr(p, n); }
static BYTE *image_of(DWORD a, BOOL code_only)
{
    MEMORY_BASIC_INFORMATION m; BYTE *b;
    if (a < 0x10000 || !VirtualQuery((LPCVOID)a, &m, sizeof(m)) || m.State != MEM_COMMIT) return NULL;
    b = (BYTE *)m.AllocationBase;
    if (!rd(b, 0x40) || b[0] != 'M' || b[1] != 'Z') return NULL;
    if (code_only && !(m.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READONLY))) return NULL;
    return b;
}
static void hwhere(DWORD a)
{
    BYTE *b = image_of(a, FALSE);
    if (b) {
        IMAGE_NT_HEADERS32 *nt = (IMAGE_NT_HEADERS32 *)(b + *(LONG *)(b + 0x3C));
        const char *nm = NULL;
        if (rd(nt, sizeof(*nt)) && nt->Signature == IMAGE_NT_SIGNATURE &&
            nt->OptionalHeader.NumberOfRvaAndSizes > 0 && nt->OptionalHeader.DataDirectory[0].VirtualAddress) {
            IMAGE_EXPORT_DIRECTORY *ed = (IMAGE_EXPORT_DIRECTORY *)(b + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
            if (rd(ed, sizeof(*ed)) && ed->Name && rd(b + ed->Name, 1) && !IsBadStringPtrA((const char *)b + ed->Name, 64)) nm = (const char *)b + ed->Name;
        }
        if (nm) { int k; char t[40]; for (k = 0; k < 39 && nm[k]; k++) t[k] = nm[k]; t[k] = 0; hput(t); }
        else { hput("image@"); hhex((DWORD)(ULONG_PTR)b, 8); }
        hput("+"); hhex(a - (DWORD)(ULONG_PTR)b, 1 + (a - (DWORD)(ULONG_PTR)b > 0xF) + (a - (DWORD)(ULONG_PTR)b > 0xFF) +
                       (a - (DWORD)(ULONG_PTR)b > 0xFFF) + (a - (DWORD)(ULONG_PTR)b > 0xFFFF) + (a - (DWORD)(ULONG_PTR)b > 0xFFFFF) +
                       (a - (DWORD)(ULONG_PTR)b > 0xFFFFFF) + (a - (DWORD)(ULONG_PTR)b > 0xFFFFFFF));
        return;
    }
    hhex(a, 8);
}

static void dump_thread(DWORD tid, HANDLE h)
{
    CONTEXT c; DWORD ok = 0, ebp, *st; const char *nm; int n, i;
    c.ContextFlags = CONTEXT_FULL;
    if (SuspendThread(h) != 0xFFFFFFFF) { ok = GetThreadContext(h, &c); ResumeThread(h); }
    hput("--- thread "); hhex(tid, 8);
    if ((nm = kex_thread_name(tid)) != NULL) { hput(" \""); hput(nm); hput("\""); }
    if (!ok) { hput("  (no context - ended?)\r\n"); hflush(); return; }
    hput("\r\n  at "); hwhere(c.Eip); hput("  ESP="); hhex(c.Esp, 8); hput(" EBP="); hhex(c.Ebp, 8);
    hput(" EAX="); hhex(c.Eax, 8); hput(" ECX="); hhex(c.Ecx, 8); hput(" EDX="); hhex(c.Edx, 8);
    hput(" ESI="); hhex(c.Esi, 8); hput(" EDI="); hhex(c.Edi, 8); hput("\r\n  EBP frames:\r\n");
    ebp = c.Ebp;
    for (n = 0; n < 32 && rd((void *)ebp, 8); n++) {
        DWORD *f = (DWORD *)ebp;
        hput("    "); hwhere(f[1]); hput("\r\n");
        if (f[0] <= ebp) break;
        ebp = f[0];
    }
    hput("  stack values pointing into modules:\r\n");
    st = (DWORD *)c.Esp; n = 0;
    for (i = 0; i < 4096 && n < 48 && rd(st + i, 4); i++)
        if (image_of(st[i], TRUE)) { hput("    +"); hhex(i * 4, 4); hput(" "); hwhere(st[i]); hput("\r\n"); n++; }
    hflush();
}

int kex_iocp_stat(int i, DWORD v[7]);   /* iocp_ext.c */
static void hang_dump(int nr)
{
    LONG i, n; DWORD me = GetCurrentThreadId();
    hput("##### THREAD DUMP "); hdec((DWORD)nr); hput(nr >= 200 ? ": a window stayed disabled 5 s with no dialog showing, tick " : nr >= 100 ? ": asked for by KEXDUMP, tick " : ": nothing drawn yet, tick "); hdec(GetTickCount());
    hput(", process "); hhex(GetCurrentProcessId(), 8); hput(", "); hdec((DWORD)g_nht); hput(" known threads\r\n");
    {   /* build 132: completion ports - a thread parked in GetQueuedCompletionStatus with packets posted but not taken
         * (or nothing queued although its program believes a wake-up is pending) shows here. No lock (read only). */
        int i; DWORD v[7], now = GetTickCount();
        for (i = 0; kex_iocp_stat(i, v) >= 0; i++) {
            if (!v[0]) continue;
            hput("  completion port "); hhex(v[0], 8); hput(": queued "); hdec(v[1]); hput(", waiting threads "); hdec(v[2]);
            hput(", posted "); hdec(v[3]); hput(" (last "); hdec(now - v[4]); hput(" ms ago), taken "); hdec(v[5]);
            hput(" (last "); hdec(now - v[6]); hput(" ms ago)\r\n");
        }
    }
    hflush();
    {   /* build 69: single-process Chromium runs one "utility" service at a time; which one holds the slot? Its
         * name is the crash key "service-name" (set by the last utility that got in). Chromium 159 (Win_1731910)
         * keeps the key object's pointer at chrome.dll+109ae68c - used only if the build matches (the key's
         * name literal sits at +f7ecc70). Pure diagnostics: read-only. */
        BYTE *cb = (BYTE *)GetModuleHandleA("chrome.dll");
        if (cb && rd(cb + 0xf7ecc70, 13) && !memcmp(cb + 0xf7ecc70, "service-name", 13) && rd(cb + 0x109ae68c, 4)) {
            BYTE *o = *(BYTE **)(cb + 0x109ae68c); int k; char t[2];
            hput("  last utility service started (crash key service-name): ");
            if (o && rd(o, 160)) {
                t[1] = 0;
                for (k = 0; k < 160; k++) { t[0] = (o[k] >= 32 && o[k] < 127) ? (char)o[k] : '.'; hput(t); }
            } else hput("(not set yet)");
            hput("\r\n"); hflush();
        }
    }
    {   /* copies of the handles: a thread may end (and its entry move) while we walk */
        static struct { DWORD tid; HANDLE h; } l[HT_MAX];
        kex_spin_acquire(&g_htlock);
        n = g_nht;
        for (i = 0; i < n; i++) { l[i].tid = g_ht[i].tid; l[i].h = NULL;
            DuplicateHandle(GetCurrentProcess(), g_ht[i].h, GetCurrentProcess(), &l[i].h, 0, FALSE, DUPLICATE_SAME_ACCESS); }
        InterlockedExchange(&g_htlock, 0);
        for (i = 0; i < n; i++) { if (l[i].tid != me && l[i].h) dump_thread(l[i].tid, l[i].h); if (l[i].h) CloseHandle(l[i].h); }
    }
    hput("--- (threads kexnt did not see start, from Toolhelp:)\r\n"); hflush();
    {
        typedef HANDLE (WINAPI *T_OT)(DWORD, BOOL, DWORD);
        FARPROC kex_prev_impl(const char *dll, const char *name);
        T_OT ot = (T_OT)(void *)kex_prev_impl("KERNEL32.DLL", "OpenThread");
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); THREADENTRY32 te; DWORD pid = GetCurrentProcessId();
        if (s != INVALID_HANDLE_VALUE && ot) {
            te.dwSize = sizeof(te);
            if (Thread32First(s, &te)) do {
                if (te.th32OwnerProcessID == pid && te.th32ThreadID != me) {
                    LONG k, nn = g_nht; for (k = 0; k < nn && g_ht[k].tid != te.th32ThreadID; k++) ;
                    if (k == nn) { HANDLE h = ot(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                                  if (h) { dump_thread(te.th32ThreadID, h); CloseHandle(h); } }
                }
                te.dwSize = sizeof(te);
            } while (Thread32Next(s, &te));
        }
        if (s != INVALID_HANDLE_VALUE) CloseHandle(s);
    }
    hput("##### end of hang dump\r\n\r\n"); hflush();
}

typedef BOOL (WINAPI *T_IW)(HWND); typedef HWND (WINAPI *T_GW)(HWND, UINT);
typedef DWORD (WINAPI *T_GWTP)(HWND, DWORD *); typedef int (WINAPI *T_GCN)(HWND, LPSTR, int);
typedef LONG (WINAPI *T_GWL)(HWND, int); typedef BOOL (WINAPI *T_GWR)(HWND, RECT *);
typedef BOOL (WINAPI *T_EW)(WNDENUMPROC, LPARAM);
static T_IW u_is_enabled, u_is_window, u_is_visible; static T_GW u_get_window; static T_GWTP u_gwtp;
static T_GCN u_gcn; static T_GWL u_gwl; static T_GWR u_gwr; static T_EW u_enum;
/* one line per top-level window of this process: which window owns it, style, shown or not, where, class */
static BOOL CALLBACK list_window(HWND h, LPARAM dis)
{
    DWORD pid = 0; char cls[64]; RECT r; LONG st, ex;
    u_gwtp(h, &pid);
    if (pid != GetCurrentProcessId()) return TRUE;
    cls[0] = 0; u_gcn(h, cls, sizeof(cls));
    st = u_gwl(h, GWL_STYLE); ex = u_gwl(h, GWL_EXSTYLE);
    r.left = r.top = r.right = r.bottom = 0; u_gwr(h, &r);
    hput("  window "); hhex((DWORD)(ULONG_PTR)h, 8); hput(" owner "); hhex((DWORD)(ULONG_PTR)u_get_window(h, 4 /* GW_OWNER */), 8);
    hput((HWND)dis == h ? " (THE DISABLED ONE)" : "");
    hput(u_is_visible(h) ? " shown" : " hidden"); hput(u_is_enabled(h) ? " enabled" : " disabled");
    hput(" style "); hhex((DWORD)st, 8); hput(" ex "); hhex((DWORD)ex, 8);
    hput(" at "); hsdec(r.left); hput(","); hsdec(r.top); hput(" size "); hdec((DWORD)(r.right - r.left)); hput("x"); hdec((DWORD)(r.bottom - r.top));
    hput(" thread "); hhex(u_gwtp(h, NULL), 8); hput(" \""); hput(cls); hput("\"\r\n");
    return TRUE;
}
/* build 77: Chromium shows Save As in a helper process (utility "UtilWin") and disables its own window meanwhile.
 * Windows 98 lets only the foreground process bring a window to the front - the helper's own tries failed
 * ("brought to the front" ok 0), the dialog stayed behind until the user clicked Chrome. The browser IS the
 * foreground process, so it does it: a visible dialog (#32770) of a process that this process started.
 * Found -> SetForegroundWindow once per dialog, noted in KEXCRASH; and then no hang dump (a dialog is up). */
typedef BOOL (WINAPI *T_SFW)(HWND); typedef HWND (WINAPI *T_GFW)(void);
static T_SFW u_sfw, u_btt; static T_GFW u_gfw;
static HWND g_helper_dlg, g_fronted;
static DWORD g_child_pid[16]; static int g_nchild; static DWORD g_child_tick;
static BOOL is_my_child(DWORD pid)
{
    int i; DWORD now = GetTickCount();
    for (i = 0; i < g_nchild; i++) if (g_child_pid[i] == pid) return TRUE;
    if (now - g_child_tick < 500) return FALSE;          /* a new helper: look again at most twice a second */
    g_child_tick = now;
    {   HANDLE sn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32 pe; DWORD me = GetCurrentProcessId();
        if (sn == INVALID_HANDLE_VALUE) return FALSE;
        g_nchild = 0; pe.dwSize = sizeof(pe);
        if (Process32First(sn, &pe)) do {
            if (pe.th32ParentProcessID == me && g_nchild < 16) g_child_pid[g_nchild++] = pe.th32ProcessID;
        } while (Process32Next(sn, &pe));
        CloseHandle(sn); }
    for (i = 0; i < g_nchild; i++) if (g_child_pid[i] == pid) return TRUE;
    return FALSE;
}
static BOOL CALLBACK find_helper_dialog(HWND h, LPARAM unused)
{
    DWORD pid = 0; char cls[16];
    (void)unused;
    if (!u_is_visible(h)) return TRUE;
    cls[0] = 0; u_gcn(h, cls, sizeof(cls));
    if (lstrcmpA(cls, "#32770")) return TRUE;
    u_gwtp(h, &pid);
    if (pid == GetCurrentProcessId() || !is_my_child(pid)) return TRUE;
    g_helper_dlg = h;
    return FALSE;
}
static BOOL helper_dialog_up(void)
{
    if (!u_sfw) {
        u_sfw = (T_SFW)(void *)kex_sysproc("USER32.DLL", "SetForegroundWindow");
        u_btt = (T_SFW)(void *)kex_sysproc("USER32.DLL", "BringWindowToTop");
        u_gfw = (T_GFW)(void *)kex_sysproc("USER32.DLL", "GetForegroundWindow");
        if (!u_sfw || !u_btt || !u_gfw) return FALSE;
    }
    g_helper_dlg = NULL;
    u_enum(find_helper_dialog, 0);
    if (!g_helper_dlg) return FALSE;
    if (g_helper_dlg != g_fronted) {
        HWND fg = u_gfw(); BOOL ok;
        g_fronted = g_helper_dlg;
        ok = fg == g_helper_dlg || u_sfw(g_helper_dlg);
        if (ok) u_btt(g_helper_dlg);
        {   /* build 90: whose dialog and what it says (build 89: one came up, the system "froze", no text known) */
            typedef int (WINAPI *T_GWT)(HWND, LPSTR, int); typedef HWND (WINAPI *T_GW)(HWND, UINT);
            T_GWT gwt = (T_GWT)(void *)kex_sysproc("USER32.DLL", "GetWindowTextA");
            T_GW gw = (T_GW)(void *)kex_sysproc("USER32.DLL", "GetWindow");
            DWORD pid = 0; char t[300], line[360]; HWND c; int k = 0;
            u_gwtp(g_helper_dlg, &pid);
            kex_crashnote("dialog of a helper process brought to the front by the browser (dialog, ok, foreground before, its process)",
                          (DWORD)(ULONG_PTR)g_helper_dlg, (DWORD)ok, (DWORD)(ULONG_PTR)fg, pid);
            if (gwt) {
                t[0] = 0; gwt(g_helper_dlg, t, sizeof(t)); lstrcpyA(line, "  title: "); lstrcatA(line, t); kex_crashnote(line, 0, 0, 0, 0);
                for (c = gw ? gw(g_helper_dlg, 5 /* GW_CHILD */) : NULL; c && k < 12; c = gw(c, 2 /* GW_HWNDNEXT */), k++) {
                    t[0] = 0; gwt(c, t, sizeof(t));
                    if (t[0]) { lstrcpyA(line, "  text: "); lstrcatA(line, t); kex_crashnote(line, 0, 0, 0, 0); }
                }
            }
        }
    }
    return TRUE;
}
static void disabled_check(void)
{
    HWND w = g_dis_hwnd, pop;
    BOOL fast = w && GetTickCount() - g_dis_tick >= 200 && GetTickCount() - g_dis_tick < 60000;
    /* build 61: a second dump 30 s into the same wait - at 5 s Chrome's Save As thread did not exist yet */
    if (!w || (!fast && (g_dis_dumped >= 2 || GetTickCount() - g_dis_tick < (g_dis_dumped ? 30000u : 5000u) || g_dis_dumps >= 4))) return;
    if (!u_is_enabled) {
        u_is_enabled = (T_IW)(void *)kex_sysproc("USER32.DLL", "IsWindowEnabled");
        u_is_window = (T_IW)(void *)kex_sysproc("USER32.DLL", "IsWindow");
        u_is_visible = (T_IW)(void *)kex_sysproc("USER32.DLL", "IsWindowVisible");
        u_get_window = (T_GW)(void *)kex_sysproc("USER32.DLL", "GetWindow");
        u_gwtp = (T_GWTP)(void *)kex_sysproc("USER32.DLL", "GetWindowThreadProcessId");
        u_gcn = (T_GCN)(void *)kex_sysproc("USER32.DLL", "GetClassNameA");
        u_gwl = (T_GWL)(void *)kex_sysproc("USER32.DLL", "GetWindowLongA");
        u_gwr = (T_GWR)(void *)kex_sysproc("USER32.DLL", "GetWindowRect");
        u_enum = (T_EW)(void *)kex_sysproc("USER32.DLL", "EnumWindows");
        if (!u_is_enabled || !u_is_window || !u_is_visible || !u_get_window || !u_gwtp || !u_gcn || !u_gwl || !u_gwr || !u_enum) { g_dis_dumps = 99; return; }
    }
    if (!u_is_window(w) || u_is_enabled(w)) { g_dis_hwnd = NULL; g_fronted = NULL; return; }
    pop = u_get_window(w, 6 /* GW_ENABLEDPOPUP */);
    if (pop && pop != w && u_is_visible(pop)) return;          /* a dialog is up - all fine */
    if (helper_dialog_up()) return;                             /* build 77: the helper's dialog is up */
    if (g_dis_dumped >= 2 || GetTickCount() - g_dis_tick < (g_dis_dumped ? 30000u : 5000u) || g_dis_dumps >= 4) return;
    g_dis_dumped++;
    kex_crashnote("window disabled for 5 s (or 30 s) and no dialog of it showing - windows + thread dump written to KEXHANG (window, dump nr)",
                  (DWORD)(ULONG_PTR)w, 200 + (DWORD)g_dis_dumps, 0, 0);
    hput("##### WINDOWS OF THIS PROCESS (window "); hhex((DWORD)(ULONG_PTR)w, 8); hput(" disabled since tick "); hdec(g_dis_tick);
    hput(", now "); hdec(GetTickCount()); hput(")\r\n"); hflush();
    u_enum(list_window, (LPARAM)w); hflush();
    hang_dump(200 + (int)InterlockedIncrement(&g_dis_dumps) - 1);
}

/* build 81: "bring this window to the front" requests from helper processes. Windows 98 lets the foreground
 * process (the browser) do it, not the helper whose Save dialog it is. The browser keeps a named event
 * "KexNG_Front_<pid>" and a 4-byte named mapping "KexNG_FrontW_<pid>"; a helper writes the window there and
 * sets the event (kex_hang_ask_front); the browser's watcher thread brings it up. In build 80 the browser-side
 * search did not run: Chromium had not disabled a window of its own (COMDLG32 in the helper disabled it). */
static HANDLE g_front_ev, g_front_map; static volatile DWORD *g_front_w;
static void front_name(char *out, const char *pre, DWORD pid)
{
    static const char hx[] = "0123456789ABCDEF"; int i = lstrlenA(pre), k;
    lstrcpyA(out, pre);
    for (k = 28; k >= 0; k -= 4) out[i++] = hx[(pid >> k) & 15];
    out[i] = 0;
}
static void front_serve_init(void)
{
    char n[40];
    front_name(n, "KexNG_Front_", GetCurrentProcessId()); g_front_ev = CreateEventA(NULL, FALSE, FALSE, n);
    front_name(n, "KexNG_FrontW_", GetCurrentProcessId());
    g_front_map = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4, n);
    if (g_front_map) g_front_w = (volatile DWORD *)MapViewOfFile(g_front_map, FILE_MAP_ALL_ACCESS, 0, 0, 4);
}
static void front_serve(void)
{
    typedef BOOL (WINAPI *T_SFW2)(HWND); typedef HWND (WINAPI *T_GFW2)(void);
    T_SFW2 sfw = (T_SFW2)(void *)kex_sysproc("USER32.DLL", "SetForegroundWindow");
    T_SFW2 btt = (T_SFW2)(void *)kex_sysproc("USER32.DLL", "BringWindowToTop");
    T_GFW2 gfw = (T_GFW2)(void *)kex_sysproc("USER32.DLL", "GetForegroundWindow");
    HWND w = g_front_w ? (HWND)(ULONG_PTR)*g_front_w : NULL, fg = gfw ? gfw() : NULL; BOOL ok = FALSE;
    if (!w || !sfw) return;
    ok = fg == w || sfw(w);
    if (btt) btt(w);
    kex_crashnote("file dialog of a helper process brought to the front by the browser on its request (window, ok, foreground before)",
                  (DWORD)(ULONG_PTR)w, (DWORD)ok, (DWORD)(ULONG_PTR)fg, 0);
}
/* filedlg_ext.c, in a helper: ask the process that started this one */
void kex_hang_ask_front(HWND w)
{
    HANDLE sn, ev, m; PROCESSENTRY32 pe; DWORD me = GetCurrentProcessId(), pp = 0; char n[40]; volatile DWORD *v;
    sn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (sn == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    if (Process32First(sn, &pe)) do { if (pe.th32ProcessID == me) { pp = pe.th32ParentProcessID; break; } } while (Process32Next(sn, &pe));
    CloseHandle(sn);
    if (!pp) return;
    front_name(n, "KexNG_FrontW_", pp);
    if (!(m = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, n))) { kex_crashnote("file dialog: parent process has no front-request channel (parent)", pp, 0, 0, 0); return; }
    if ((v = (volatile DWORD *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 4)) != NULL) { *v = (DWORD)(ULONG_PTR)w; UnmapViewOfFile((void *)v); }
    CloseHandle(m);
    front_name(n, "KexNG_Front_", pp);
    if ((ev = OpenEventA(EVENT_MODIFY_STATE, FALSE, n)) != NULL) { SetEvent(ev); CloseHandle(ev); }
    kex_crashnote("file dialog: asked the parent process to bring it to the front (window, parent)", (DWORD)(ULONG_PTR)w, pp, 0, 0);
}

static DWORD WINAPI hang_watch(LPVOID p)
{
    (void)p;
    /* build 52: KEXDUMP.EXE pulses this event - "the program is stuck right now, write where every thread is"
     * (a Save As dialog that never appeared while the window stayed disabled, for example) */
    HANDLE ev = CreateEventA(NULL, TRUE, FALSE, "KexNG_ThreadDump"); int k = 100;
    front_serve_init();
    DWORD t0 = GetTickCount(); int stage = 0;
    for (;;) {
        DWORD now = GetTickCount() - t0, wait = stage == 0 ? (now < 30000 ? 30000 - now : 0) : stage == 1 ? (now < 75000 ? 75000 - now : 0) : INFINITE;
        DWORD r;
        if (wait > 1000) wait = 1000;                  /* build 59: look at a disabled window once a second */
        if (g_dis_hwnd && wait > 250) wait = 250;      /* build 77: 4 times a second while one is disabled (dialog to the front) */
        if (ev && g_front_ev) { HANDLE w2[2]; w2[0] = ev; w2[1] = g_front_ev; r = WaitForMultipleObjects(2, w2, FALSE, wait); }
        else r = ev ? WaitForSingleObject(ev, wait) : (Sleep(wait), WAIT_TIMEOUT);
        if (r == WAIT_OBJECT_0 + 1) { front_serve(); continue; }
        if (r == WAIT_OBJECT_0) { hang_dump(k++); Sleep(1500); continue; }
        disabled_check();
        now = GetTickCount() - t0;
        if ((stage == 0 && now < 30000) || (stage == 1 && now < 75000) || stage == 2) continue;
        if (stage == 0) { stage = g_drawn ? 2 : 1; if (!g_drawn) hang_dump(1); }
        else if (stage == 1) { stage = 2; if (!g_drawn) hang_dump(2); }
    }
}

/* build 76: helper processes of a Chromium-style program (command line with "--type=") end themselves when the
 * process that started them is gone. After a browser crash on Windows 98 the helpers kept running (and kept
 * C:\CHRUD and the logs open - "write-protected" until a reboot). The helper looks up its parent with Toolhelp,
 * waits on it, gives it 3 s, notes it in KEXCRASH and terminates itself. */
#include <tlhelp32.h>
static DWORD WINAPI orphan_watch(LPVOID p)
{
    HANDLE parent = (HANDLE)p;
    WaitForSingleObject(parent, INFINITE);
    CloseHandle(parent);
    Sleep(3000);
    kex_crashnote("helper process: the process that started it ended - ending this one too", GetCurrentProcessId(), 0, 0, 0);
    TerminateProcess(GetCurrentProcess(), 0);
    return 0;
}
static void orphan_arm(void)
{
    HANDLE sn = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), par = NULL, th; PROCESSENTRY32 pe; DWORD me = GetCurrentProcessId(), pp = 0, tid;
    if (sn == INVALID_HANDLE_VALUE) return;
    pe.dwSize = sizeof(pe);
    if (Process32First(sn, &pe)) do { if (pe.th32ProcessID == me) { pp = pe.th32ParentProcessID; break; } } while (Process32Next(sn, &pe));
    CloseHandle(sn);
    if (!pp || pp == me || !(par = OpenProcess(SYNCHRONIZE, FALSE, pp))) return;
    th = CreateThread(NULL, 0x4000, orphan_watch, par, 0, &tid);
    if (th) CloseHandle(th); else CloseHandle(par);
}

/* crashlog_ext.c kex_crashlog_arm, on the thread that prepares the program (the main thread) */
void kex_hang_arm(const char *crash_log_path)
{
    const char *cl = GetCommandLineA(), *s, *slash = NULL; int i;
    DWORD tid; HANDLE h;
    if (!cl || !crash_log_path || InterlockedExchange(&g_hang_on, 1)) return;
    for (s = cl; *s; s++) if (s[0] == '-' && s[1] == '-' && s[2] == 't' && s[3] == 'y' && s[4] == 'p' && s[5] == 'e' && s[6] == '=') { orphan_arm(); return; }
    for (s = crash_log_path; *s; s++) if (*s == '\\') slash = s;
    if (!slash || lstrlenA(crash_log_path) >= MAX_PATH - 4) return;
    for (i = 0; crash_log_path + i <= slash; i++) g_hpath[i] = crash_log_path[i];
    g_hpath[i] = 0;
    lstrcatA(g_hpath, "KEXHANG_"); lstrcatA(g_hpath, slash + 1 + 9 /* skip "KEXCRASH_" */);
    DeleteFileA(g_hpath);
    add_self();
    h = CreateThread(NULL, 0, hang_watch, NULL, 0, &tid);
    if (h) CloseHandle(h);
}
