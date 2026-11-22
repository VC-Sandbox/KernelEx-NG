/*
 * w10_ext.c - KernelEx-NG: what genuine Windows 10 DLLs need from Windows 98 (2026-11-02).
 *
 * First users: DWrite.dll and TextShaping.dll copied from a Windows 10 installation (the
 * "bring your own Windows 10 DLL" model; we never ship them). Their imports were listed with
 * tools/re_scripts/win10_dropin.py (docs/dwrite_dropin_gaps.md). Everything here is written from
 * the public documentation of each function; nothing is taken from Microsoft's code.
 *
 *   - CreateMutexEx / CreateSemaphoreEx / CreateEventEx: the classic calls (names: "Local\" and
 *     "Global\" stripped, Windows 98 has one namespace and no '\' in object names)
 *   - thread-pool timers (CreateThreadpoolTimer & co.): one timer thread per process
 *   - ResolveDelayLoadedAPI: the delay-load resolver Windows 8+ DLLs call from their delay-load stubs
 *   - NtQueryInformationThread (basic information), RtlCaptureStackBackTrace (EBP chain)
 *   - ALPC: the font-cache-service connection fails cleanly (DirectWrite then builds its font cache
 *     inside the process, as it does when the FontCache service is stopped)
 *   - NotifyServiceStatusChangeW, WerRegisterMemoryBlock, GDI's GetFontFile* (FALSE: no GDI font files)
 *   - the NT font list: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts is kept equal to
 *     Windows 98's HKLM\Software\Microsoft\Windows\CurrentVersion\Fonts (DirectWrite reads the NT key)
 */
#include "kexnt_common.h"

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
DWORD KEXAPI kex_GetThreadId(HANDLE thread);

/* ---------------------------------------------------------------- named objects */
static const char *ns_name(LPCWSTR w, char *a, int cb)
{
    int i, n = 0; const char *p;
    if (!w) return NULL;
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, a, cb, NULL, NULL)) { a[0] = 0; return a; }
    a[cb - 1] = 0;
    p = a;                                                    /* strip Local\ / Global\ */
    if ((p[0] | 32) == 'l' && (p[1] | 32) == 'o' && (p[2] | 32) == 'c' && (p[3] | 32) == 'a' && (p[4] | 32) == 'l' && p[5] == '\\') p += 6;
    else if ((p[0] | 32) == 'g' && (p[1] | 32) == 'l' && (p[2] | 32) == 'o' && (p[3] | 32) == 'b' && (p[4] | 32) == 'a' && (p[5] | 32) == 'l' && p[6] == '\\') p += 7;
    for (i = 0; p[i]; i++) a[n++] = p[i] == '\\' ? '_' : p[i];
    a[n] = 0;
    return a;
}
static const char *ns_nameA(LPCSTR s, char *a, int cb)
{
    WCHAR w[MAX_PATH];
    if (!s) return NULL;
    if (!MultiByteToWideChar(CP_ACP, 0, s, -1, w, MAX_PATH)) w[0] = 0;
    w[MAX_PATH - 1] = 0;
    return ns_name(w, a, cb);
}
HANDLE KEXAPI kex_CreateMutexExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{ char n[MAX_PATH]; (void)access; return CreateMutexA(sa, (flags & 1) != 0, ns_name(name, n, sizeof(n))); }
HANDLE KEXAPI kex_CreateMutexExA(LPSECURITY_ATTRIBUTES sa, LPCSTR name, DWORD flags, DWORD access)
{ char n[MAX_PATH]; (void)access; return CreateMutexA(sa, (flags & 1) != 0, ns_nameA(name, n, sizeof(n))); }
HANDLE KEXAPI kex_CreateSemaphoreExW(LPSECURITY_ATTRIBUTES sa, LONG init, LONG max, LPCWSTR name, DWORD flags, DWORD access)
{ char n[MAX_PATH]; (void)flags; (void)access; return CreateSemaphoreA(sa, init, max, ns_name(name, n, sizeof(n))); }
HANDLE KEXAPI kex_CreateEventExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{ char n[MAX_PATH]; (void)access; return CreateEventA(sa, (flags & 1) != 0, (flags & 2) != 0, ns_name(name, n, sizeof(n))); }
HANDLE KEXAPI kex_CreateEventExA(LPSECURITY_ATTRIBUTES sa, LPCSTR name, DWORD flags, DWORD access)
{ char n[MAX_PATH]; (void)access; return CreateEventA(sa, (flags & 1) != 0, (flags & 2) != 0, ns_nameA(name, n, sizeof(n))); }

/* ---------------------------------------------------------------- thread-pool timers */
typedef VOID (CALLBACK *T_TIMERCB)(PVOID inst, PVOID ctx, PVOID timer);
typedef struct KTPT { struct KTPT *next; T_TIMERCB fn; PVOID ctx; ULONGLONG due; DWORD period; LONG armed, running, closed; } KTPT;
static CRITICAL_SECTION g_tcs; static volatile LONG g_tstate; static HANDLE g_twake; static KTPT *g_tlist; static DWORD g_ttid;
static DWORD g_dummy_instance[16];

static ULONGLONG tick64(void)
{
    static DWORD last, high; DWORD t = GetTickCount();
    if (t < last) high++;
    last = t;
    return ((ULONGLONG)high << 32) | t;
}
static void tp_unlink(KTPT *t)
{
    KTPT **pp;
    for (pp = &g_tlist; *pp; pp = &(*pp)->next) if (*pp == t) { *pp = t->next; break; }
    HeapFree(GetProcessHeap(), 0, t);
}
static DWORD WINAPI tp_thread(LPVOID p)
{
    (void)p;
    for (;;) {
        KTPT *t, *fire = NULL; DWORD wait = INFINITE; ULONGLONG now;
        EnterCriticalSection(&g_tcs);
        now = tick64();
        for (t = g_tlist; t; t = t->next) {
            if (!t->armed || t->closed) continue;
            if (t->due <= now) { fire = t; break; }
            if (t->due - now < wait) wait = (DWORD)(t->due - now);
        }
        if (fire) {
            fire->running++;
            if (fire->period) fire->due = now + fire->period; else fire->armed = 0;
        }
        LeaveCriticalSection(&g_tcs);
        if (fire) {
            fire->fn((PVOID)g_dummy_instance, fire->ctx, (PVOID)fire);
            EnterCriticalSection(&g_tcs);
            if (!--fire->running && fire->closed) tp_unlink(fire);
            LeaveCriticalSection(&g_tcs);
            continue;
        }
        WaitForSingleObject(g_twake, wait);
    }
}
static BOOL tp_init(void)
{
    while (g_tstate != 2) {
        if (InterlockedCompareExchange(&g_tstate, 1, 0) == 0) {
            HANDLE h;
            InitializeCriticalSection(&g_tcs);
            g_twake = CreateEventA(NULL, FALSE, FALSE, NULL);
            h = CreateThread(NULL, 0x100000, tp_thread, NULL, 0, &g_ttid);   /* callbacks run here: full-size stack */
            if (h) CloseHandle(h);
            g_tstate = 2;
        } else Sleep(0);
    }
    return g_twake != NULL;
}
PVOID KEXAPI kex_CreateThreadpoolTimer(T_TIMERCB fn, PVOID ctx, PVOID env)
{
    KTPT *t;
    (void)env;
    if (!fn) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    if (!tp_init() || !(t = (KTPT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*t)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    t->fn = fn; t->ctx = ctx;
    EnterCriticalSection(&g_tcs); t->next = g_tlist; g_tlist = t; LeaveCriticalSection(&g_tcs);
    return t;
}
VOID KEXAPI kex_SetThreadpoolTimer(PVOID pt, const FILETIME *due, DWORD period, DWORD window)
{
    KTPT *t = (KTPT *)pt; ULONGLONG ms = 0;
    (void)window;
    if (!t) return;
    if (due) {
        LONGLONG v = (LONGLONG)(((ULONGLONG)due->dwHighDateTime << 32) | due->dwLowDateTime);
        if (v < 0) ms = (ULONGLONG)(-v) / 10000;
        else if (v > 0) {
            FILETIME n; LONGLONG nv;
            GetSystemTimeAsFileTime(&n);
            nv = (LONGLONG)(((ULONGLONG)n.dwHighDateTime << 32) | n.dwLowDateTime);
            ms = v > nv ? (ULONGLONG)(v - nv) / 10000 : 0;
        }
    }
    EnterCriticalSection(&g_tcs);
    if (due) { t->due = tick64() + ms; t->period = period; t->armed = 1; } else t->armed = 0;
    LeaveCriticalSection(&g_tcs);
    SetEvent(g_twake);
}
BOOL KEXAPI kex_IsThreadpoolTimerSet(PVOID pt) { return pt && ((KTPT *)pt)->armed; }
VOID KEXAPI kex_WaitForThreadpoolTimerCallbacks(PVOID pt, BOOL cancel)
{
    KTPT *t = (KTPT *)pt;
    if (!t) return;
    if (cancel) { EnterCriticalSection(&g_tcs); t->armed = 0; LeaveCriticalSection(&g_tcs); }
    if (GetCurrentThreadId() == g_ttid) return;            /* from inside its own callback */
    while (t->running) Sleep(1);
}
VOID KEXAPI kex_CloseThreadpoolTimer(PVOID pt)
{
    KTPT *t = (KTPT *)pt;
    if (!t) return;
    EnterCriticalSection(&g_tcs);
    t->closed = 1; t->armed = 0;
    if (!t->running) tp_unlink(t);
    LeaveCriticalSection(&g_tcs);
}

/* ---------------------------------------------------------------- delay loading (Windows 8+ DLLs) */
typedef struct { DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA,
                 BoundImportAddressTableRVA, UnloadInformationTableRVA, TimeDateStamp; } KDLDESC;
typedef struct { ULONG Size; const KDLDESC *Desc; PIMAGE_THUNK_DATA Thunk; LPCSTR Dll;
                 struct { ULONG ByName; ULONG_PTR NameOrOrd; } Api; PVOID TargetBase; PVOID Unused; ULONG LastError; } KDLINFO;
typedef PVOID (WINAPI *T_DLLHOOK)(ULONG reason, KDLINFO *info);
typedef PVOID (WINAPI *T_SYSHOOK)(LPCSTR dll, LPCSTR proc);

PVOID KEXAPI kex_ResolveDelayLoadedAPI(PVOID base, const KDLDESC *d, T_DLLHOOK dllhook, T_SYSHOOK syshook,
                                       PIMAGE_THUNK_DATA thunk, ULONG flags)
{
    BYTE *b = (BYTE *)base;
    HMODULE *ph = (HMODULE *)(b + d->ModuleHandleRVA), h = *ph;
    PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(b + d->ImportAddressTableRVA);
    PIMAGE_THUNK_DATA in = (PIMAGE_THUNK_DATA)(b + d->ImportNameTableRVA);
    DWORD idx = (DWORD)(thunk - iat);
    KDLINFO info; PVOID p = NULL; LPCSTR proc; DWORD code;
    (void)flags;
    ZeroMemory(&info, sizeof(info));
    info.Size = sizeof(info); info.Desc = d; info.Thunk = thunk; info.Dll = (LPCSTR)(b + d->DllNameRVA);
    if (IMAGE_SNAP_BY_ORDINAL(in[idx].u1.Ordinal)) { info.Api.NameOrOrd = IMAGE_ORDINAL(in[idx].u1.Ordinal); proc = (LPCSTR)info.Api.NameOrOrd; }
    else { info.Api.ByName = 1; proc = (LPCSTR)((PIMAGE_IMPORT_BY_NAME)(b + in[idx].u1.AddressOfData))->Name; info.Api.NameOrOrd = (ULONG_PTR)proc; }
    if (!h) {
        h = LoadLibraryA(info.Dll);
        if (!h) {
            info.LastError = GetLastError();
            kex_trace("delay-load: cannot load", (DWORD)(ULONG_PTR)base, info.LastError, 0, 0);
            if (dllhook) h = (HMODULE)dllhook(3, &info);            /* dliFailLoadLib */
        }
        if (h) {
            HMODULE old = (HMODULE)InterlockedCompareExchange((LONG *)ph, (LONG)(ULONG_PTR)h, 0);
            if (old) { FreeLibrary(h); h = old; }
        }
    }
    if (h) {
        p = (PVOID)GetProcAddress(h, proc);
        if (!p) {
            info.LastError = GetLastError(); info.TargetBase = h;
            if (dllhook) p = dllhook(4, &info);                    /* dliFailGetProc */
        }
    }
    if (!p && syshook) p = syshook(info.Dll, proc);
    if (!p) {
        ULONG_PTR arg = (ULONG_PTR)&info;
        kex_trace(info.Dll, info.Api.ByName ? 0 : (DWORD)info.Api.NameOrOrd, h ? 1 : 0, (DWORD)(ULONG_PTR)base, 0);
        code = h ? 0xC06D007FUL : 0xC06D007EUL;                 /* VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC/MOD_NOT_FOUND) */
        RaiseException(code, 0, 1, &arg);
        return NULL;
    }
    thunk->u1.Function = (DWORD)(ULONG_PTR)p;
    return p;
}

/* ---------------------------------------------------------------- NT thread information, stack */
NTSTATUS KEXAPI kex_NtQueryInformationThread(HANDLE h, ULONG cls, PVOID buf, ULONG len, PULONG ret)
{
    DWORD tid = (h == GetCurrentThread()) ? GetCurrentThreadId() : kex_GetThreadId(h);
    if (cls == 0) {                                           /* ThreadBasicInformation */
        struct { LONG ExitStatus; PVOID Teb; HANDLE Pid, Tid; DWORD_PTR Affinity; LONG Prio, BasePrio; } *bi = buf;
        DWORD code = 0;
        if (len < sizeof(*bi)) return STATUS_INFO_LENGTH_MISMATCH;
        if (!GetExitCodeThread(h, &code)) return STATUS_INVALID_HANDLE_K;
        ZeroMemory(bi, sizeof(*bi));
        bi->ExitStatus = code == STILL_ACTIVE ? 0x103 : (LONG)code;
        if (tid == GetCurrentThreadId()) { PVOID t; __asm__ volatile("movl %%fs:0x18, %0" : "=r"(t)); bi->Teb = t; }
        { DWORD kex_pid_nt(DWORD real); bi->Pid = (HANDLE)(ULONG_PTR)kex_pid_nt(GetCurrentProcessId()); }   /* build 131 */
        bi->Tid = (HANDLE)(ULONG_PTR)tid;
        bi->Affinity = 1;
        bi->Prio = bi->BasePrio = 8 + GetThreadPriority(h);
        if (ret) *ret = sizeof(*bi);
        return STATUS_SUCCESS;
    }
    if (cls == 9) {                                           /* ThreadQuerySetWin32StartAddress */
        if (len < sizeof(PVOID)) return STATUS_INFO_LENGTH_MISMATCH;
        *(PVOID *)buf = NULL;
        if (ret) *ret = sizeof(PVOID);
        return STATUS_SUCCESS;
    }
    if (cls == 20) {                                          /* ThreadIsTerminated */
        DWORD code = 0;
        if (len < sizeof(ULONG)) return STATUS_INFO_LENGTH_MISMATCH;
        if (!GetExitCodeThread(h, &code)) return STATUS_INVALID_HANDLE_K;
        *(ULONG *)buf = code != STILL_ACTIVE;
        if (ret) *ret = sizeof(ULONG);
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_INFO_CLASS;
}

USHORT KEXAPI kex_RtlCaptureStackBackTrace(ULONG skip, ULONG count, PVOID *back, PULONG hash)
{
    DWORD *fp, lo, hi, sum = 0; USHORT n = 0;
    __asm__ volatile("movl %%ebp, %0" : "=r"(fp));
    __asm__ volatile("movl %%fs:0x08, %0" : "=r"(lo));
    __asm__ volatile("movl %%fs:0x04, %0" : "=r"(hi));
    skip++;                                                   /* not ourselves */
    while (n < count && (DWORD)(ULONG_PTR)fp >= lo && (DWORD)(ULONG_PTR)fp + 8 <= hi) {
        DWORD ra = fp[1], *next = (DWORD *)(ULONG_PTR)fp[0];
        if (!ra) break;
        if (skip) skip--; else { back[n++] = (PVOID)(ULONG_PTR)ra; sum += ra; }
        if (next <= fp) break;
        fp = next;
    }
    if (hash) *hash = sum;
    return n;
}

/* ---------------------------------------------------------------- ALPC: no font cache service here */
NTSTATUS KEXAPI kex_AlpcInitializeMessageAttribute(ULONG attrs, PVOID buf, SIZE_T size, PSIZE_T need)
{
    SIZE_T req = 8; ULONG a;
    for (a = attrs; a; a &= a - 1) req += 16;
    if (need) *need = req;
    if (!buf || size < req) return STATUS_BUFFER_TOO_SMALL;
    ZeroMemory(buf, req);
    ((ULONG *)buf)[0] = attrs;
    return STATUS_SUCCESS;
}
/* the attribute's slot in a buffer laid out by kex_AlpcInitializeMessageAttribute: header, then 16 bytes per
 * allocated attribute, highest flag bit first. DirectWrite writes into it without checking for NULL. */
PVOID KEXAPI kex_AlpcGetMessageAttribute(PVOID buf, ULONG attr)
{
    ULONG alloc, bit; SIZE_T off = 8;
    if (!buf || !attr) return NULL;
    alloc = ((ULONG *)buf)[0];
    if (!(alloc & attr)) return NULL;
    for (bit = 0x80000000UL; bit; bit >>= 1) {
        if (!(alloc & bit)) continue;
        if (bit == attr) return (BYTE *)buf + off;
        off += 16;
    }
    return NULL;
}
NTSTATUS KEXAPI kex_NtAlpcConnectPort(PHANDLE port, PVOID name, PVOID oa, PVOID pa, ULONG flags, PVOID sid,
                                      PVOID msg, PSIZE_T len, PVOID oattr, PVOID iattr, PLARGE_INTEGER timeout)
{
    (void)name; (void)oa; (void)pa; (void)flags; (void)sid; (void)msg; (void)len; (void)oattr; (void)iattr; (void)timeout;
    if (port) *port = NULL;
    return (NTSTATUS)0xC0000034L;                             /* STATUS_OBJECT_NAME_NOT_FOUND */
}
NTSTATUS KEXAPI kex_NtAlpcSendWaitReceivePort(HANDLE port, ULONG flags, PVOID smsg, PVOID sattr, PVOID rmsg,
                                              PSIZE_T rlen, PVOID rattr, PLARGE_INTEGER timeout)
{
    (void)port; (void)flags; (void)smsg; (void)sattr; (void)rmsg; (void)rlen; (void)rattr; (void)timeout;
    return (NTSTATUS)0xC0000037L;                             /* STATUS_PORT_DISCONNECTED */
}

/* ---------------------------------------------------------------- small ones */
DWORD KEXAPI kex_NotifyServiceStatusChangeW(SC_HANDLE s, DWORD mask, PVOID notify)
{ (void)s; (void)mask; (void)notify; return ERROR_CALL_NOT_IMPLEMENTED; }
HRESULT KEXAPI kex_WerRegisterMemoryBlock(PVOID p, DWORD n) { (void)p; (void)n; return S_OK; }
HRESULT KEXAPI kex_WerUnregisterMemoryBlock(PVOID p) { (void)p; return S_OK; }
BOOL KEXAPI kex_GetFontRealizationInfo(HDC dc, PVOID info) { (void)dc; (void)info; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetFontFileInfo(DWORD id, DWORD idx, PVOID info, SIZE_T size, SIZE_T *need)
{ (void)id; (void)idx; (void)info; (void)size; if (need) *need = 0; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetFontFileData(DWORD id, DWORD idx, ULONGLONG off, PVOID buf, SIZE_T size)
{ (void)id; (void)idx; (void)off; (void)buf; (void)size; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }

/* ---------------------------------------------------------------- NT font list */
void kex_w10_fonts_sync(void)
{
    HKEY k9, knt; DWORD n9 = 0, nnt = 0xFFFFFFFF, i;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Fonts", 0, KEY_READ, &k9) != ERROR_SUCCESS) return;
    if (RegQueryInfoKeyA(k9, NULL, NULL, NULL, NULL, NULL, NULL, &n9, NULL, NULL, NULL, NULL) != ERROR_SUCCESS || !n9) { RegCloseKey(k9); return; }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0, KEY_READ, &knt) == ERROR_SUCCESS) {
        if (RegQueryInfoKeyA(knt, NULL, NULL, NULL, NULL, NULL, NULL, &nnt, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) nnt = 0xFFFFFFFF;
        RegCloseKey(knt);
    }
    if (nnt == n9) { RegCloseKey(k9); return; }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &knt, NULL) != ERROR_SUCCESS) { RegCloseKey(k9); return; }
    for (i = 0;; i++) {
        char name[256], data[MAX_PATH]; DWORD nl = sizeof(name), dl = sizeof(data), t;
        if (RegEnumValueA(k9, i, name, &nl, NULL, &t, (BYTE *)data, &dl) != ERROR_SUCCESS) break;
        if (t == REG_SZ) RegSetValueExA(knt, name, 0, REG_SZ, (const BYTE *)data, dl);
    }
    kex_trace("NT font list synchronised (values)", n9, nnt, 0, 0);
    RegCloseKey(knt); RegCloseKey(k9);
}

/* ---------------------------------------------------------------- CreateWellKnownSid
 * KernelEx 4.5's version is a stub that never reports the size; DirectWrite asks for the size first
 * (ERROR_INSUFFICIENT_BUFFER expected) to build the LocalService SID of the font cache service. The SIDs
 * below are the documented well-known SID values (WELL_KNOWN_SID_TYPE). */
typedef struct { BYTE type, auth, n; DWORD sub[2]; } KWKS;
static const KWKS g_wks[] = {
    { 0, 0, 1, { 0 } }, { 1, 1, 1, { 0 } }, { 2, 2, 1, { 0 } }, { 3, 3, 1, { 0 } }, { 4, 3, 1, { 1 } },
    { 5, 3, 1, { 2 } }, { 6, 3, 1, { 3 } }, { 7, 5, 0, { 0 } }, { 8, 5, 1, { 1 } }, { 9, 5, 1, { 2 } },
    { 10, 5, 1, { 3 } }, { 11, 5, 1, { 4 } }, { 12, 5, 1, { 6 } }, { 13, 5, 1, { 7 } }, { 14, 5, 1, { 8 } },
    { 15, 5, 1, { 9 } }, { 16, 5, 1, { 10 } }, { 17, 5, 1, { 11 } }, { 18, 5, 1, { 12 } }, { 19, 5, 1, { 13 } },
    { 20, 5, 1, { 14 } }, { 22, 5, 1, { 18 } }, { 23, 5, 1, { 19 } }, { 24, 5, 1, { 20 } }, { 25, 5, 1, { 32 } },
    { 26, 5, 2, { 32, 544 } }, { 27, 5, 2, { 32, 545 } }, { 28, 5, 2, { 32, 546 } }, { 29, 5, 2, { 32, 547 } },
    { 30, 5, 2, { 32, 548 } }, { 31, 5, 2, { 32, 549 } }, { 32, 5, 2, { 32, 550 } }, { 33, 5, 2, { 32, 551 } },
    { 34, 5, 2, { 32, 552 } }, { 35, 5, 2, { 32, 554 } }, { 36, 5, 2, { 32, 555 } }, { 37, 5, 2, { 32, 556 } },
    { 65, 16, 1, { 0 } }, { 66, 16, 1, { 4096 } }, { 67, 16, 1, { 8192 } }, { 68, 16, 1, { 12288 } },
    { 69, 16, 1, { 16384 } }, { 84, 15, 2, { 2, 1 } },
};
BOOL KEXAPI kex_CreateWellKnownSid(DWORD type, PSID domain, PSID sid, DWORD *cb)
{
    unsigned i; DWORD need; BYTE *p = (BYTE *)sid;
    (void)domain;
    if (!cb) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < sizeof(g_wks) / sizeof(g_wks[0]); i++) if (g_wks[i].type == type) break;
    if (i == sizeof(g_wks) / sizeof(g_wks[0])) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    need = 8 + 4 * g_wks[i].n;
    if (!sid || *cb < need) { *cb = need; SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    ZeroMemory(p, need);
    p[0] = 1; p[1] = g_wks[i].n; p[7] = g_wks[i].auth;
    for (type = 0; type < g_wks[i].n; type++) ((DWORD *)(p + 8))[type] = g_wks[i].sub[type];
    *cb = need;
    return TRUE;
}
