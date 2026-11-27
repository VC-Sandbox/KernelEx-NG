/*
 * setupapi_ext.c - the Unicode INF and cabinet functions of SETUPAPI for modern programs (build 132).
 *
 * Windows 98's SETUPAPI.DLL exports the W functions, but they fail with ERROR_CALL_NOT_IMPLEMENTED (120). Measured with
 * probes/infw.c on the .NET Framework 3.5 SP1 setup's setup.sdb (a UTF-16 INF): SetupOpenInfFileW -> INVALID_HANDLE_VALUE,
 * error 120; an ANSI copy of the same text opens with SetupOpenInfFileA (its "$Windows NT$" signature accepted) and
 * SetupFindFirstLineA/SetupGetStringFieldA read it. The setup's engine (SITSETUP.DLL, LoadSetupDatabase) loads
 * SETUPAPI and opens setup.sdb with SetupOpenInfFileW -> "The .sdb file is either missing, corrupt, or the signiture
 * portion is missing" and the setup stopped. Its other modules (setup.exe, vs_setup.dll, ...) use SetupIterateCabinetW.
 *
 * Here the W functions go through the A ones:
 *   SetupOpenInfFileW      a UTF-16 INF (FF FE) is opened from an ANSI copy in %TEMP% (deleted by SetupCloseInfFile);
 *                          any other file by its ANSI name
 *   SetupFindFirstLineW, SetupGetLineTextW, SetupGetStringFieldW   strings converted (CP_ACP); buffer rules as NT:
 *                          NULL buffer -> size only; too small -> ERROR_INSUFFICIENT_BUFFER, required size set
 *   SetupCloseInfFile      closes, removes the ANSI copy
 *   SetupIterateCabinetW   SetupIterateCabinetA with a callback that hands the program W notifications
 *                          (FILE_IN_CABINET_INFO, CABINET_INFO, FILEPATHS) and copies its target path back
 * Text that does not exist in the ANSI code page cannot pass through the A functions (as with every W->A layer).
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef PVOID HINF_K;
typedef struct { PVOID Inf, CurrentInf; UINT Section, Line; } KINFCTX;
typedef HINF_K (WINAPI *T_OIA)(PCSTR, PCSTR, DWORD, PUINT);
typedef BOOL (WINAPI *T_FFLA)(HINF_K, PCSTR, PCSTR, KINFCTX *);
typedef BOOL (WINAPI *T_GLTA)(KINFCTX *, HINF_K, PCSTR, PCSTR, PSTR, DWORD, PDWORD);
typedef BOOL (WINAPI *T_GSFA)(KINFCTX *, DWORD, PSTR, DWORD, PDWORD);
typedef VOID (WINAPI *T_CIF)(HINF_K);
typedef UINT (CALLBACK *T_MSGW)(PVOID, UINT, UINT_PTR, UINT_PTR);
typedef BOOL (WINAPI *T_ICA)(PCSTR, DWORD, T_MSGW, PVOID);

static FARPROC sa(const char *name) { return kex_sysproc("SETUPAPI.DLL", name); }

/* W string -> new ANSI string (NULL stays NULL); free with HeapFree */
static char *a_dup(LPCWSTR w)
{
    int n; char *a;
    if (!w) return NULL;
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0 || !(a = (char *)HeapAlloc(GetProcessHeap(), 0, n))) return NULL;
    WideCharToMultiByte(CP_ACP, 0, w, -1, a, n, NULL, NULL);
    return a;
}
static void a_free(char *a) { if (a) HeapFree(GetProcessHeap(), 0, a); }

/* ANSI result (with its terminating zero, na bytes) -> caller's W buffer under NT's size rules */
static BOOL put_w(const char *a, PWSTR buf, DWORD size, PDWORD req)
{
    int n = MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0);
    if (n <= 0) n = 1;
    if (req) *req = (DWORD)n;
    if (!buf) { if (size) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } SetLastError(ERROR_SUCCESS); return TRUE; }
    if (size < (DWORD)n) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    MultiByteToWideChar(CP_ACP, 0, a, -1, buf, (int)size);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/* ---- INF handles opened from an ANSI copy: the copy is removed when the INF is closed */
#define NCOPY 32
static struct { HINF_K inf; char path[MAX_PATH]; } g_copy[NCOPY];
static volatile LONG g_lock;

static BOOL utf16_copy(const char *src, char *dst)
{
    HANDLE f = CreateFileA(src, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD size, got = 0, put = 0; BYTE *b = NULL; char *a = NULL, tmp[MAX_PATH]; int n; BOOL ok = FALSE;
    if (f == INVALID_HANDLE_VALUE) return FALSE;
    size = GetFileSize(f, NULL);
    if (size >= 2 && size != 0xFFFFFFFF && size < 64 * 1024 * 1024 && (b = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size)) &&
        ReadFile(f, b, size, &got, NULL) && got == size && b[0] == 0xFF && b[1] == 0xFE) {
        n = WideCharToMultiByte(CP_ACP, 0, (WCHAR *)(b + 2), (int)((size - 2) / 2), NULL, 0, NULL, NULL);
        if (n >= 0 && (a = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1))) {
            WideCharToMultiByte(CP_ACP, 0, (WCHAR *)(b + 2), (int)((size - 2) / 2), a, n, NULL, NULL);
            if (GetTempPathA(MAX_PATH, tmp) && GetTempFileNameA(tmp, "KXI", 0, dst)) {
                HANDLE o = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (o != INVALID_HANDLE_VALUE) { ok = WriteFile(o, a, (DWORD)n, &put, NULL) && put == (DWORD)n; CloseHandle(o); }
                if (!ok) DeleteFileA(dst);
            }
        }
    }
    CloseHandle(f);
    if (b) HeapFree(GetProcessHeap(), 0, b);
    if (a) HeapFree(GetProcessHeap(), 0, a);
    return ok;
}

HINF_K KEXAPI kex_SetupOpenInfFileW(PCWSTR name, PCWSTR cls, DWORD style, PUINT errline)
{
    static T_OIA p; char *an = a_dup(name), *ac = a_dup(cls), copy[MAX_PATH]; HINF_K r; BOOL is_copy; DWORD e; int i;
    if (!p) p = (T_OIA)(void *)sa("SetupOpenInfFileA");
    if (!p || !an) { a_free(an); a_free(ac); SetLastError(p ? ERROR_INVALID_PARAMETER : ERROR_CALL_NOT_IMPLEMENTED); return (HINF_K)INVALID_HANDLE_VALUE; }
    is_copy = utf16_copy(an, copy);
    r = p(is_copy ? copy : an, ac, style, errline);
    e = GetLastError();
    if (is_copy) {
        if (r == (HINF_K)INVALID_HANDLE_VALUE) DeleteFileA(copy);
        else {
            kex_spin_acquire(&g_lock);
            for (i = 0; i < NCOPY; i++) if (!g_copy[i].inf) { g_copy[i].inf = r; lstrcpynA(g_copy[i].path, copy, MAX_PATH); break; }
            InterlockedExchange((LONG *)&g_lock, 0);
            if (i == NCOPY) DeleteFileA(copy);      /* SETUPAPI has read the whole file already */
        }
        {   static LONG k; if (InterlockedIncrement(&k) <= 10) kex_crashnote("SetupOpenInfFileW: UTF-16 INF opened from an ANSI copy (handle, error, -, -)", (DWORD)(ULONG_PTR)r, e, 0, 0); }
    }
    a_free(an); a_free(ac);
    SetLastError(e);
    return r;
}

VOID KEXAPI kex_SetupCloseInfFile(HINF_K inf)
{
    static T_CIF p; int i; char path[MAX_PATH]; path[0] = 0;
    if (!p) p = (T_CIF)(void *)sa("SetupCloseInfFile");
    if (p) p(inf);
    kex_spin_acquire(&g_lock);
    for (i = 0; i < NCOPY; i++) if (g_copy[i].inf && g_copy[i].inf == inf) { lstrcpyA(path, g_copy[i].path); g_copy[i].inf = NULL; break; }
    InterlockedExchange((LONG *)&g_lock, 0);
    if (path[0]) DeleteFileA(path);
}

BOOL KEXAPI kex_SetupFindFirstLineW(HINF_K inf, PCWSTR sec, PCWSTR key, KINFCTX *ctx)
{
    static T_FFLA p; char *as = a_dup(sec), *ak = a_dup(key); BOOL r; DWORD e;
    if (!p) p = (T_FFLA)(void *)sa("SetupFindFirstLineA");
    if (!p) { a_free(as); a_free(ak); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(inf, as, ak, ctx); e = GetLastError();
    a_free(as); a_free(ak);
    SetLastError(e);
    return r;
}

BOOL KEXAPI kex_SetupGetLineTextW(KINFCTX *ctx, HINF_K inf, PCWSTR sec, PCWSTR key, PWSTR buf, DWORD size, PDWORD req)
{
    static T_GLTA p; char *as = a_dup(sec), *ak = a_dup(key), *a; DWORD n = 0; BOOL r;
    if (!p) p = (T_GLTA)(void *)sa("SetupGetLineTextA");
    if (!p) { a_free(as); a_free(ak); SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(ctx, inf, as, ak, NULL, 0, &n);
    if (r && n && (a = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1))) {
        r = p(ctx, inf, as, ak, a, n + 1, &n);
        if (r) r = put_w(a, buf, size, req);
        HeapFree(GetProcessHeap(), 0, a);
    } else if (r) r = put_w("", buf, size, req);
    a_free(as); a_free(ak);
    return r;
}

BOOL KEXAPI kex_SetupGetStringFieldW(KINFCTX *ctx, DWORD field, PWSTR buf, DWORD size, PDWORD req)
{
    static T_GSFA p; char *a; DWORD n = 0; BOOL r;
    if (!p) p = (T_GSFA)(void *)sa("SetupGetStringFieldA");
    if (!p) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    r = p(ctx, field, NULL, 0, &n);
    if (!r) return FALSE;
    if (!n) return put_w("", buf, size, req);
    if (!(a = (char *)HeapAlloc(GetProcessHeap(), 0, n + 1))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    r = p(ctx, field, a, n + 1, &n);
    if (r) r = put_w(a, buf, size, req);
    HeapFree(GetProcessHeap(), 0, a);
    return r;
}

/* ---- SetupIterateCabinetW */
typedef struct { LPCSTR NameInCabinet; DWORD FileSize, Win32Error; WORD DosDate, DosTime, DosAttribs; CHAR FullTargetName[MAX_PATH]; } KFICA;
typedef struct { LPCWSTR NameInCabinet; DWORD FileSize, Win32Error; WORD DosDate, DosTime, DosAttribs; WCHAR FullTargetName[MAX_PATH]; } KFICW;
typedef struct { LPCSTR CabinetPath, CabinetFile, DiskName; USHORT SetId, CabinetNumber; } KCIA;
typedef struct { LPCWSTR CabinetPath, CabinetFile, DiskName; USHORT SetId, CabinetNumber; } KCIW;
typedef struct { LPCSTR Target, Source; UINT Win32Error; DWORD Flags; } KFPA;
typedef struct { LPCWSTR Target, Source; UINT Win32Error; DWORD Flags; } KFPW;
#define N_CABINETINFO    0x10
#define N_FILEINCABINET  0x11
#define N_NEEDNEWCABINET 0x12
#define N_FILEEXTRACTED  0x13
typedef struct { T_MSGW handler; PVOID ctx; } KCAB;

static void w_of(LPCSTR a, WCHAR *w, int cch) { if (!a) { w[0] = 0; return; } if (!MultiByteToWideChar(CP_ACP, 0, a, -1, w, cch)) w[0] = 0; }

static UINT CALLBACK cab_cb(PVOID context, UINT n, UINT_PTR p1, UINT_PTR p2)
{
    KCAB *c = (KCAB *)context; UINT r;
    switch (n) {
    case N_FILEINCABINET: {
        KFICA *a = (KFICA *)p1; KFICW w; WCHAR name[MAX_PATH], cab[MAX_PATH];
        w_of(a->NameInCabinet, name, MAX_PATH); w_of((LPCSTR)p2, cab, MAX_PATH);
        w.NameInCabinet = name; w.FileSize = a->FileSize; w.Win32Error = a->Win32Error;
        w.DosDate = a->DosDate; w.DosTime = a->DosTime; w.DosAttribs = a->DosAttribs; w_of(a->FullTargetName, w.FullTargetName, MAX_PATH);
        r = c->handler(c->ctx, n, (UINT_PTR)&w, (UINT_PTR)cab);
        if (!WideCharToMultiByte(CP_ACP, 0, w.FullTargetName, -1, a->FullTargetName, MAX_PATH, NULL, NULL)) a->FullTargetName[0] = 0;
        a->Win32Error = w.Win32Error;
        return r;
    }
    case N_CABINETINFO: case N_NEEDNEWCABINET: {
        KCIA *a = (KCIA *)p1; KCIW w; WCHAR path[MAX_PATH], file[MAX_PATH], disk[MAX_PATH], newpath[MAX_PATH];
        w_of(a->CabinetPath, path, MAX_PATH); w_of(a->CabinetFile, file, MAX_PATH); w_of(a->DiskName, disk, MAX_PATH);
        w.CabinetPath = path; w.CabinetFile = file; w.DiskName = disk; w.SetId = a->SetId; w.CabinetNumber = a->CabinetNumber;
        newpath[0] = 0;
        r = c->handler(c->ctx, n, (UINT_PTR)&w, n == N_NEEDNEWCABINET ? (UINT_PTR)newpath : p2);
        if (n == N_NEEDNEWCABINET && p2) { if (!WideCharToMultiByte(CP_ACP, 0, newpath, -1, (LPSTR)p2, MAX_PATH, NULL, NULL)) ((LPSTR)p2)[0] = 0; }
        return r;
    }
    case N_FILEEXTRACTED: {
        KFPA *a = (KFPA *)p1; KFPW w; WCHAR t[MAX_PATH], s[MAX_PATH];
        w_of(a->Target, t, MAX_PATH); w_of(a->Source, s, MAX_PATH);
        w.Target = t; w.Source = s; w.Win32Error = a->Win32Error; w.Flags = a->Flags;
        return c->handler(c->ctx, n, (UINT_PTR)&w, p2);
    }
    default:
        {   static LONG k; if (InterlockedIncrement(&k) <= 10) kex_crashnote("SetupIterateCabinetW: notification passed through unchanged (code, -, -, -)", n, 0, 0, 0); }
        return c->handler(c->ctx, n, p1, p2);
    }
}

BOOL KEXAPI kex_SetupIterateCabinetW(PCWSTR cab, DWORD reserved, T_MSGW handler, PVOID context)
{
    static T_ICA p; char *a = a_dup(cab); KCAB c; BOOL r; DWORD e;
    if (!p) p = (T_ICA)(void *)sa("SetupIterateCabinetA");
    if (!p || !a || !handler) { a_free(a); SetLastError(p ? ERROR_INVALID_PARAMETER : ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    c.handler = handler; c.ctx = context;
    r = p(a, reserved, cab_cb, &c); e = GetLastError();
    a_free(a);
    SetLastError(e);
    return r;
}
