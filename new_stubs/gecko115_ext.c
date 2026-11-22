/*
 * gecko115_ext.c - KernelEx-NG build 131: what Firefox 115 ESR's binaries import beyond Windows 98 + KernelEx 4.5
 * (measured with the import checker over the installed C:\Program Files\Firefox ESR, 2026-11-19):
 *   firefox.exe / mozglue.dll / plugin-container.exe (NTDLL): NtQueryVirtualMemory, NtReadVirtualMemory,
 *     RtlDuplicateUnicodeString, RtlGetLastWin32Error, RtlSetLastWin32Error, RtlQueryPerformanceCounter,
 *     RtlRunOnceExecuteOnce
 *   mozglue.dll (KERNEL32): WerUnregisterRuntimeExceptionModule; (CRYPT32): CryptBinaryToStringW
 *   default-browser-agent.exe (ADVAPI32): RegDeleteKeyValueW, RegDeleteTreeW, RegSetKeyValueW
 *     (the setup ends by starting it: "linked to missing export ADVAPI32.DLL:RegDeleteKeyValueW")
 * Registry functions go through the ANSI calls: Windows 98's own W registry functions are stubs.
 */
#include "kexnt_common.h"

typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } K_USTR;

/* ------------------------------------------------------------------ NTDLL */
SIZE_T KEXAPI kex_VirtualQueryEx(HANDLE h, LPCVOID a, PMEMORY_BASIC_INFORMATION m, SIZE_T n);   /* mem_ext.c */
DWORD KEXAPI kex_K32GetMappedFileNameW(HANDLE hp, LPVOID a, LPWSTR b, DWORD n);                    /* sysinfo_ext.c */
BOOL KEXAPI kex_InitOnceExecuteOnce(PINIT_ONCE o, PINIT_ONCE_FN fn, PVOID param, LPVOID *ctx);      /* sync_ext.c */

/* class 0 MemoryBasicInformation, class 2 MemoryMappedFilenameInformation (UNICODE_STRING + its buffer) */
NTSTATUS KEXAPI kex_NtQueryVirtualMemory(HANDLE h, PVOID a, ULONG cls, PVOID out, SIZE_T len, PSIZE_T ret)
{
    if (cls == 0) {
        if (len < sizeof(MEMORY_BASIC_INFORMATION)) { if (ret) *ret = sizeof(MEMORY_BASIC_INFORMATION); return (NTSTATUS)0xC0000004L; }
        if (!kex_VirtualQueryEx(h, a, (PMEMORY_BASIC_INFORMATION)out, len)) return (NTSTATUS)0xC000000DL;   /* STATUS_INVALID_PARAMETER */
        if (ret) *ret = sizeof(MEMORY_BASIC_INFORMATION);
        return 0;
    }
    if (cls == 2) {
        WCHAR w[MAX_PATH * 2]; DWORD n = kex_K32GetMappedFileNameW(h, a, w, MAX_PATH * 2); SIZE_T need;
        K_USTR *u = (K_USTR *)out;
        if (!n) return (NTSTATUS)0xC0000141L;                       /* STATUS_INVALID_ADDRESS */
        need = sizeof(K_USTR) + (n + 1) * sizeof(WCHAR);
        if (ret) *ret = need;
        if (len < need) return (NTSTATUS)0x80000005L;                /* STATUS_BUFFER_OVERFLOW */
        u->Buffer = (PWSTR)(u + 1);
        memcpy(u->Buffer, w, (n + 1) * sizeof(WCHAR));
        u->Length = (USHORT)(n * sizeof(WCHAR)); u->MaximumLength = (USHORT)((n + 1) * sizeof(WCHAR));
        return 0;
    }
    return (NTSTATUS)0xC0000003L;                                    /* STATUS_INVALID_INFO_CLASS */
}

NTSTATUS KEXAPI kex_NtReadVirtualMemory(HANDLE h, PVOID a, PVOID buf, SIZE_T n, PSIZE_T done)
{
    BOOL KEXAPI kex_ReadProcessMemory(HANDLE h, LPCVOID a, LPVOID buf, SIZE_T n, SIZE_T *done);    /* mem_ext.c */
    SIZE_T got = 0; BOOL ok = kex_ReadProcessMemory(h, a, buf, n, &got);
    if (done) *done = got;
    return ok ? 0 : (NTSTATUS)0x8000000DL;                           /* STATUS_PARTIAL_COPY */
}

/* flags: 1 = add a terminating NUL, 2 = allocate even for an empty/NULL string */
NTSTATUS KEXAPI kex_RtlDuplicateUnicodeString(ULONG flags, const K_USTR *src, K_USTR *dst)
{
    USHORT len = src ? src->Length : 0; SIZE_T cb;
    if (!dst || flags > 3 || (src && (src->Length & 1))) return (NTSTATUS)0xC000000DL;
    if (!len && !(flags & 2)) { dst->Length = dst->MaximumLength = 0; dst->Buffer = NULL; return 0; }
    cb = (SIZE_T)len + ((flags & 1) ? sizeof(WCHAR) : 0);
    if (cb > 0xFFFF) return (NTSTATUS)0xC000000DL;
    if (!(dst->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), 0, cb ? cb : sizeof(WCHAR)))) return (NTSTATUS)0xC0000017L;
    if (len) memcpy(dst->Buffer, src->Buffer, len);
    if (flags & 1) dst->Buffer[len / 2] = 0;
    dst->Length = len; dst->MaximumLength = (USHORT)cb;
    return 0;
}

DWORD KEXAPI kex_RtlGetLastWin32Error(void) { return GetLastError(); }
VOID KEXAPI kex_RtlSetLastWin32Error(DWORD e) { SetLastError(e); }
BOOLEAN KEXAPI kex_RtlQueryPerformanceCounter(PLARGE_INTEGER c) { return (BOOLEAN)(QueryPerformanceCounter(c) != 0); }

/* RTL_RUN_ONCE is INIT_ONCE, and its init function has the same shape (BOOL fn(once, parameter, &context)) */
NTSTATUS KEXAPI kex_RtlRunOnceExecuteOnce(PINIT_ONCE once, PINIT_ONCE_FN fn, PVOID param, PVOID *ctx)
{
    return kex_InitOnceExecuteOnce(once, fn, param, ctx) ? 0 : (NTSTATUS)0xC0000001L;   /* STATUS_UNSUCCESSFUL */
}

/* ------------------------------------------------------------------ KERNEL32 */
HRESULT KEXAPI kex_WerUnregisterRuntimeExceptionModule(PCWSTR dll, PVOID ctx) { return E_NOTIMPL; }   /* as the Register call */

/* ------------------------------------------------------------------ CRYPT32: CryptBinaryToStringW */
#define K_STR_BASE64HEADER 0x0
#define K_STR_BASE64       0x1
#define K_STR_HEX          0x4
#define K_STR_HEXRAW       0xC
#define K_STR_NOCRLF       0x40000000
#define K_STR_NOCR         0x80000000
BOOL KEXAPI kex_CryptBinaryToStringW(const BYTE *bin, DWORD n, DWORD flags, LPWSTR out, DWORD *cch)
{
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    static const char hx[] = "0123456789abcdef";
    DWORD type = flags & 0xFFFF, need = 0, i, k = 0, col = 0;
    BOOL nocrlf = (flags & K_STR_NOCRLF) != 0, nocr = (flags & K_STR_NOCR) != 0;
    const DWORD eol = nocrlf ? 0 : (nocr ? 1 : 2);
    if (!cch || (!bin && n)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (type == K_STR_BASE64) {
        DWORD chars = (n + 2) / 3 * 4;
        need = chars + (chars ? ((chars + 63) / 64) * eol : 0) + 1;
    } else if (type == K_STR_HEXRAW) {
        need = n * 2 + eol + 1;
    } else { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!out) { *cch = need; return TRUE; }
    if (*cch < need) { *cch = need; SetLastError(ERROR_MORE_DATA); return FALSE; }
    if (type == K_STR_BASE64) {
        for (i = 0; i < n; i += 3) {
            DWORD v = (DWORD)bin[i] << 16 | (i + 1 < n ? (DWORD)bin[i + 1] << 8 : 0) | (i + 2 < n ? bin[i + 2] : 0);
            out[k++] = (WCHAR)b64[(v >> 18) & 63]; out[k++] = (WCHAR)b64[(v >> 12) & 63];
            out[k++] = (WCHAR)(i + 1 < n ? b64[(v >> 6) & 63] : '=');
            out[k++] = (WCHAR)(i + 2 < n ? b64[v & 63] : '=');
            col += 4;
            if (col == 64 || i + 3 >= n) { if (eol == 2) out[k++] = L'\r'; if (eol) out[k++] = L'\n'; col = 0; }
        }
    } else {
        for (i = 0; i < n; i++) { out[k++] = (WCHAR)hx[bin[i] >> 4]; out[k++] = (WCHAR)hx[bin[i] & 15]; }
        if (eol == 2) out[k++] = L'\r';
        if (eol) out[k++] = L'\n';
    }
    out[k] = 0;
    *cch = k;                                                        /* without the terminator */
    return TRUE;
}

/* ------------------------------------------------------------------ ADVAPI32 */
static BOOL to_a(LPCWSTR w, char *a, int n)
{
    if (!w) { a[0] = 0; return TRUE; }
    return WideCharToMultiByte(CP_ACP, 0, w, -1, a, n, NULL, NULL) != 0;
}

LONG KEXAPI kex_RegDeleteKeyValueW(HKEY k, LPCWSTR sub, LPCWSTR value)
{
    char s[MAX_PATH], v[MAX_PATH]; HKEY h = k; LONG r;
    if (!to_a(sub, s, sizeof(s)) || !to_a(value, v, sizeof(v))) return ERROR_INVALID_PARAMETER;
    if (sub && s[0] && (r = RegOpenKeyExA(k, s, 0, KEY_SET_VALUE, &h)) != ERROR_SUCCESS) return r;
    r = RegDeleteValueA(h, value ? v : NULL);
    if (h != k) RegCloseKey(h);
    return r;
}

/* Windows 98's RegDeleteKey already deletes a key with everything below it */
LONG KEXAPI kex_RegDeleteTreeW(HKEY k, LPCWSTR sub)
{
    char s[MAX_PATH], name[MAX_PATH]; LONG r; DWORD n;
    if (!to_a(sub, s, sizeof(s))) return ERROR_INVALID_PARAMETER;
    if (sub && s[0]) return RegDeleteKeyA(k, s);
    for (;;) {                                                       /* NULL subkey: empty k itself */
        n = sizeof(name);
        if (RegEnumKeyExA(k, 0, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if ((r = RegDeleteKeyA(k, name)) != ERROR_SUCCESS) return r;
    }
    for (;;) {
        n = sizeof(name);
        if (RegEnumValueA(k, 0, name, &n, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if ((r = RegDeleteValueA(k, name)) != ERROR_SUCCESS) return r;
    }
    return ERROR_SUCCESS;
}

LONG KEXAPI kex_RegSetKeyValueW(HKEY k, LPCWSTR sub, LPCWSTR value, DWORD type, LPCVOID data, DWORD cb)
{
    char s[MAX_PATH], v[MAX_PATH]; HKEY h = k; LONG r; DWORD disp;
    if (!to_a(sub, s, sizeof(s)) || !to_a(value, v, sizeof(v))) return ERROR_INVALID_PARAMETER;
    if (sub && s[0] && (r = RegCreateKeyExA(k, s, 0, NULL, 0, KEY_SET_VALUE, NULL, &h, &disp)) != ERROR_SUCCESS) return r;
    if ((type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ) && data) {
        int wc = (int)(cb / sizeof(WCHAR)), na;
        char *a;
        na = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)data, wc, NULL, 0, NULL, NULL);
        a = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)na + 2);
        if (!a) { r = ERROR_NOT_ENOUGH_MEMORY; goto done; }
        if (na) WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)data, wc, a, na, NULL, NULL);
        a[na] = 0; a[na + 1] = 0;
        if (na == 0 || a[na - 1]) na++;                              /* make sure it ends with a NUL */
        r = RegSetValueExA(h, value ? v : NULL, 0, type, (const BYTE *)a, (DWORD)na);
        HeapFree(GetProcessHeap(), 0, a);
    } else r = RegSetValueExA(h, value ? v : NULL, 0, type, (const BYTE *)data, cb);
done:
    if (h != k) RegCloseKey(h);
    return r;
}

/* ------------------------------------------------------------------ NtOpenFile (Firefox 115's firefox.exe imports it) */
typedef struct { ULONG Length; HANDLE RootDirectory; K_USTR *ObjectName; ULONG Attributes; PVOID Sd, Qos; } K_OA;
typedef struct { union { NTSTATUS Status; PVOID Pointer; } u; ULONG_PTR Information; } K_IOSB;
NTSTATUS kex_status_from_win32(DWORD e);                                                          /* chrome_ext.c */
DWORD KEXAPI kex_QueryDosDeviceA(LPCSTR name, LPSTR buf, DWORD cap);                              /* installer_ext.c */
HANDLE KEXAPI kex_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE tmpl);
BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb);                                                 /* fpath_ext.c */

static int wpre(const WCHAR *s, const WCHAR *p, int n)        /* case-insensitive ASCII prefix compare */
{
    int i; for (i = 0; i < n; i++) { WCHAR a = s[i], b = p[i]; if (a >= 'A' && a <= 'Z') a |= 32; if (b >= 'A' && b <= 'Z') b |= 32; if (a != b) return 1; }
    return 0;
}
/* NT object path -> Win32 path: \??\C:\x, \??\UNC\srv\share, \DosDevices\C:\x, \Device\HarddiskVolumeN\x */
static BOOL nt_to_win32(const K_OA *oa, WCHAR *out, int cap)
{
    const WCHAR *s; int n, k = 0;
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer) return FALSE;
    s = oa->ObjectName->Buffer; n = oa->ObjectName->Length / 2;
    if (oa->RootDirectory) {                                  /* relative to an open directory */
        char d[MAX_PATH];
        if (!kex_fpath_get(oa->RootDirectory, d, MAX_PATH)) return FALSE;
        k = MultiByteToWideChar(CP_ACP, 0, d, -1, out, cap) - 1;
        if (k < 0) return FALSE;
        if (k && out[k - 1] != L'\\') out[k++] = L'\\';
    } else if (n >= 4 && s[0] == L'\\' && (s[1] == L'?' || s[1] == L'\\') && s[2] == L'?' && s[3] == L'\\') {
        s += 4; n -= 4;
        if (n >= 4 && (s[0] | 32) == L'u' && (s[1] | 32) == L'n' && (s[2] | 32) == L'c' && s[3] == L'\\') { out[0] = out[1] = L'\\'; k = 2; s += 4; n -= 4; }
    } else if (n >= 12 && !wpre(s, L"\\DosDevices\\", 12)) { s += 12; n -= 12; }
    else if (n >= 8 && !wpre(s, L"\\Device\\", 8)) {      /* \Device\HarddiskVolumeN -> its drive letter */
        char dev[64], drv[3] = "A:"; int i, m;
        for (i = 0; i < 26; i++) {
            drv[0] = (char)('A' + i);
            if (!kex_QueryDosDeviceA(drv, dev, sizeof(dev))) continue;
            m = lstrlenA(dev);
            if (n > m && s[m] == L'\\') {
                int j; for (j = 0; j < m && (WCHAR)(BYTE)dev[j] == s[j]; j++) ;
                if (j == m) { out[0] = (WCHAR)drv[0]; out[1] = L':'; k = 2; s += m; n -= m; break; }
            }
        }
        if (!k) return FALSE;
    } else return FALSE;
    if (k + n + 1 > cap) return FALSE;
    memcpy(out + k, s, n * sizeof(WCHAR)); out[k + n] = 0;
    return TRUE;
}

NTSTATUS KEXAPI kex_NtOpenFile(PHANDLE h, ACCESS_MASK acc, K_OA *oa, K_IOSB *io, ULONG share, ULONG opts)
{
    WCHAR p[MAX_PATH + 8]; HANDLE r; DWORD fl = 0, a = acc;
    if (!h || !oa) return (NTSTATUS)0xC000000DL;
    *h = NULL;
    if (!nt_to_win32(oa, p, MAX_PATH + 8)) return (NTSTATUS)0xC0000033L;                   /* OBJECT_NAME_INVALID */
    if (opts & 0x1) fl |= FILE_FLAG_BACKUP_SEMANTICS;                                        /* FILE_DIRECTORY_FILE */
    if (!(opts & 0x30)) fl |= FILE_FLAG_OVERLAPPED;                                          /* not SYNCHRONOUS_IO_* */
    if (opts & 0x1000) fl |= FILE_FLAG_DELETE_ON_CLOSE;
    if (a & 0x10000000) a = GENERIC_ALL;                                                     /* generic rights pass */
    r = kex_CreateFileW(p, a, share, NULL, OPEN_EXISTING, fl, NULL);
    if (r == INVALID_HANDLE_VALUE) {
        NTSTATUS st = kex_status_from_win32(GetLastError());
        if (io) { io->u.Status = st; io->Information = 0; }
        return st;
    }
    *h = r;
    if (io) { io->u.Status = 0; io->Information = 1; /* FILE_OPENED */ }
    return 0;
}

/* ------------------------------------------------------------------ build 131: the rest of the NT functions Chromium's
 * sandbox intercepts in its children (Firefox 115 content processes) - each is also a real NT function programs call */
typedef struct { HANDLE UniqueProcess, UniqueThread; } K_CID;
HANDLE KEXAPI kex_OpenProcess(DWORD access, BOOL inherit, DWORD pid);                                     /* chrome_ext.c */
BOOL KEXAPI kex_SetFileInformationByHandle(HANDLE h, int cls, LPVOID buf, DWORD size);                   /* chrome_ext.c */
HANDLE KEXAPI kex_CreateFileMappingA(HANDLE f, LPSECURITY_ATTRIBUTES sa, DWORD prot, DWORD hi, DWORD lo, LPCSTR name);
FARPROC kex_prev_impl(const char *dll, const char *name);
#define ST_OBJECT_NAME_EXISTS ((NTSTATUS)0x40000000L)
#define ST_INVALID_PARAMETER  ((NTSTATUS)0xC000000DL)
#define ST_INVALID_CID        ((NTSTATUS)0xC000000BL)
#define ST_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)
#define ST_NOT_SUPPORTED      ((NTSTATUS)0xC00000BBL)
#define ST_NAME_INVALID       ((NTSTATUS)0xC0000033L)
#define ST_FILE_IS_A_DIRECTORY ((NTSTATUS)0xC00000BAL)

static NTSTATUS st_last(void) { DWORD e = GetLastError(); return kex_status_from_win32(e ? e : ERROR_INVALID_PARAMETER); }
static BOOL oa_inherit(const K_OA *oa) { return oa && (oa->Attributes & 2) != 0; }          /* OBJ_INHERIT */
static BOOL path_a(const K_OA *oa, char *out, int cap)
{
    WCHAR w[MAX_PATH + 8];
    if (!nt_to_win32(oa, w, MAX_PATH + 8)) return FALSE;
    return WideCharToMultiByte(CP_ACP, 0, w, -1, out, cap, NULL, NULL) > 0;
}
/* the Win32 name of a named kernel object: \BaseNamedObjects\X, \Sessions\N\BaseNamedObjects\X, or X relative to a
 * BaseNamedObjects directory handle -> "X"; *named FALSE = no name; FALSE = a name in a namespace 98 does not have */
static BOOL obj_name(const K_OA *oa, char *out, int cap, BOOL *named)
{
    const WCHAR *s; int n, k;
    *named = FALSE;
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer || !oa->ObjectName->Length) return TRUE;
    s = oa->ObjectName->Buffer; n = oa->ObjectName->Length / 2;
    if (!oa->RootDirectory) {
        if (n > 18 && !wpre(s, L"\\BaseNamedObjects\\", 18)) { s += 18; n -= 18; }
        else if (n > 10 && !wpre(s, L"\\Sessions\\", 10)) {
            int i; for (i = 10; i + 18 <= n && wpre(s + i, L"\\BaseNamedObjects\\", 18); i++) ;
            if (i + 18 > n) return FALSE;
            s += i + 18; n -= i + 18;
        } else if (s[0] == L'\\') return FALSE;
    }
    k = WideCharToMultiByte(CP_ACP, 0, s, n, out, cap - 1, NULL, NULL);
    if (k <= 0) return FALSE;
    out[k] = 0; *named = TRUE;
    return TRUE;
}

NTSTATUS KEXAPI kex_NtCreateFile(PHANDLE h, ACCESS_MASK acc, K_OA *oa, K_IOSB *io, PLARGE_INTEGER alloc, ULONG attrs,
                                 ULONG share, ULONG disp, ULONG opts, PVOID ea, ULONG ealen)
{
    static const DWORD cd[6] = { CREATE_ALWAYS, OPEN_EXISTING, CREATE_NEW, OPEN_ALWAYS, TRUNCATE_EXISTING, CREATE_ALWAYS };
    WCHAR p[MAX_PATH + 8]; char pa[MAX_PATH]; HANDLE r; DWORD fl = attrs & 0x7FA7, a = acc, before; ULONG_PTR info;
    (void)alloc; (void)ea; (void)ealen;
    if (!h || !oa || disp > 5) return ST_INVALID_PARAMETER;
    *h = NULL;
    if (!nt_to_win32(oa, p, MAX_PATH + 8)) return ST_NAME_INVALID;
    WideCharToMultiByte(CP_ACP, 0, p, -1, pa, sizeof(pa), NULL, NULL); pa[sizeof(pa) - 1] = 0;
    before = GetFileAttributesA(pa);
    if (opts & 0x1) {                                                     /* FILE_DIRECTORY_FILE */
        if (before == 0xFFFFFFFF && (disp == 2 || disp == 3) && !CreateDirectoryA(pa, NULL)) return st_last();
        if (before != 0xFFFFFFFF && disp == 2) return kex_status_from_win32(ERROR_ALREADY_EXISTS);
        fl |= FILE_FLAG_BACKUP_SEMANTICS;
    } else if ((opts & 0x40) && before != 0xFFFFFFFF && (before & FILE_ATTRIBUTE_DIRECTORY)) return ST_FILE_IS_A_DIRECTORY;
    if (!(opts & 0x30)) fl |= FILE_FLAG_OVERLAPPED;                                       /* not SYNCHRONOUS_IO_* */
    if (opts & 0x2) fl |= FILE_FLAG_WRITE_THROUGH;
    if (opts & 0x4) fl |= FILE_FLAG_SEQUENTIAL_SCAN;
    if (opts & 0x800) fl |= FILE_FLAG_RANDOM_ACCESS;
    if (opts & 0x1000) fl |= FILE_FLAG_DELETE_ON_CLOSE;
    if (a & 0x10000000) a = GENERIC_ALL;
    r = kex_CreateFileW(p, a, share, NULL, (opts & 0x1) ? OPEN_EXISTING : cd[disp], fl, NULL);
    if (r == INVALID_HANDLE_VALUE) { NTSTATUS st = st_last(); if (io) { io->u.Status = st; io->Information = 0; } return st; }
    *h = r;
    info = before == 0xFFFFFFFF ? 2 /* CREATED */ : (disp == 0 ? 0 /* SUPERSEDED */ : (disp == 4 || disp == 5) ? 3 /* OVERWRITTEN */ : 1);
    if (io) { io->u.Status = 0; io->Information = info; }
    return 0;
}

static NTSTATUS attrs_of(const K_OA *oa, WIN32_FILE_ATTRIBUTE_DATA *d)
{
    char pa[MAX_PATH];
    if (!path_a(oa, pa, sizeof(pa))) return ST_NAME_INVALID;
    if (!GetFileAttributesExA(pa, GetFileExInfoStandard, d)) return st_last();
    return 0;
}
static void put_ft(BYTE *dst, const FILETIME *t) { memcpy(dst, t, 8); }
NTSTATUS KEXAPI kex_NtQueryAttributesFile(K_OA *oa, PVOID out)        /* FILE_BASIC_INFORMATION (40 bytes) */
{
    WIN32_FILE_ATTRIBUTE_DATA d; NTSTATUS st; BYTE *b = (BYTE *)out;
    if (!out) return ST_INVALID_PARAMETER;
    if ((st = attrs_of(oa, &d))) return st;
    memset(b, 0, 40);
    put_ft(b, &d.ftCreationTime); put_ft(b + 8, &d.ftLastAccessTime); put_ft(b + 16, &d.ftLastWriteTime); put_ft(b + 24, &d.ftLastWriteTime);
    *(DWORD *)(b + 32) = d.dwFileAttributes;
    return 0;
}
NTSTATUS KEXAPI kex_NtQueryFullAttributesFile(K_OA *oa, PVOID out)    /* FILE_NETWORK_OPEN_INFORMATION (56 bytes) */
{
    WIN32_FILE_ATTRIBUTE_DATA d; NTSTATUS st; BYTE *b = (BYTE *)out;
    if (!out) return ST_INVALID_PARAMETER;
    if ((st = attrs_of(oa, &d))) return st;
    memset(b, 0, 56);
    put_ft(b, &d.ftCreationTime); put_ft(b + 8, &d.ftLastAccessTime); put_ft(b + 16, &d.ftLastWriteTime); put_ft(b + 24, &d.ftLastWriteTime);
    *(DWORD *)(b + 32) = (d.nFileSizeLow + 4095) & ~4095UL; *(DWORD *)(b + 36) = d.nFileSizeHigh;   /* AllocationSize */
    *(DWORD *)(b + 40) = d.nFileSizeLow; *(DWORD *)(b + 44) = d.nFileSizeHigh;                     /* EndOfFile */
    *(DWORD *)(b + 48) = d.dwFileAttributes;
    return 0;
}
NTSTATUS KEXAPI kex_NtSetInformationFile(HANDLE h, K_IOSB *io, PVOID buf, ULONG len, ULONG cls)
{
    int wcls; BOOL ok;
    if (!buf) return ST_INVALID_PARAMETER;
    switch (cls) {
    case 4:  wcls = 0; break;                                             /* FileBasicInformation -> FileBasicInfo */
    case 13: wcls = 4; break;                                             /* FileDispositionInformation */
    case 64: wcls = 21; break;                                            /* FileDispositionInformationEx */
    case 19: wcls = 5; break;                                             /* FileAllocationInformation */
    case 20: wcls = 6; break;                                             /* FileEndOfFileInformation */
    case 14: {                                                            /* FilePositionInformation */
        LONG hi; DWORD lo;
        if (len < 8) return (NTSTATUS)0xC0000004L;
        hi = ((LONG *)buf)[1]; lo = SetFilePointer(h, ((LONG *)buf)[0], &hi, FILE_BEGIN);
        if (lo == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) return st_last();
        if (io) { io->u.Status = 0; io->Information = 0; }
        return 0;
    }
    case 10: return ST_NOT_SUPPORTED;                                     /* FileRenameInformation: no path rename of an open file on 98 */
    default: return ST_INVALID_INFO_CLASS;
    }
    ok = kex_SetFileInformationByHandle(h, wcls, buf, len);
    if (!ok) return st_last();
    if (io) { io->u.Status = 0; io->Information = 0; }
    return 0;
}

NTSTATUS KEXAPI kex_NtOpenProcess(PHANDLE h, ACCESS_MASK acc, K_OA *oa, K_CID *cid)
{
    HANDLE r;
    if (!h || !cid || !cid->UniqueProcess) return ST_INVALID_PARAMETER;
    r = kex_OpenProcess(acc, oa_inherit(oa), (DWORD)(ULONG_PTR)cid->UniqueProcess);
    if (!r) { NTSTATUS st = st_last(); return st == ST_INVALID_PARAMETER ? ST_INVALID_CID : st; }
    *h = r;
    return 0;
}
NTSTATUS KEXAPI kex_NtOpenThread(PHANDLE h, ACCESS_MASK acc, K_OA *oa, K_CID *cid)
{
    typedef HANDLE (WINAPI *T_OT)(DWORD, BOOL, DWORD); static T_OT ot; HANDLE r;
    if (!ot) ot = (T_OT)(void *)kex_prev_impl("KERNEL32.DLL", "OpenThread");
    if (!h || !cid || !cid->UniqueThread) return ST_INVALID_PARAMETER;
    if (!ot) return ST_NOT_SUPPORTED;
    r = ot(acc, oa_inherit(oa), (DWORD)(ULONG_PTR)cid->UniqueThread);
    if (!r) { NTSTATUS st = st_last(); return st == ST_INVALID_PARAMETER ? ST_INVALID_CID : st; }
    *h = r;
    return 0;
}
NTSTATUS KEXAPI kex_NtCreateEvent(PHANDLE h, ACCESS_MASK acc, K_OA *oa, ULONG type, BOOLEAN initial)
{
    char nm[MAX_PATH]; BOOL named; SECURITY_ATTRIBUTES sa; HANDLE r; DWORD e;
    (void)acc;
    if (!h || type > 1) return ST_INVALID_PARAMETER;
    if (!obj_name(oa, nm, sizeof(nm), &named)) return ST_NAME_INVALID;
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = oa_inherit(oa);
    SetLastError(0);
    r = CreateEventA(&sa, type == 0 /* NotificationEvent = manual reset */, initial != 0, named ? nm : NULL);
    e = GetLastError();
    if (!r) return st_last();
    *h = r;
    return e == ERROR_ALREADY_EXISTS ? ST_OBJECT_NAME_EXISTS : 0;
}
NTSTATUS KEXAPI kex_NtOpenEvent(PHANDLE h, ACCESS_MASK acc, K_OA *oa)
{
    char nm[MAX_PATH]; BOOL named; HANDLE r;
    if (!h) return ST_INVALID_PARAMETER;
    if (!obj_name(oa, nm, sizeof(nm), &named)) return ST_NAME_INVALID;
    if (!named) return ST_NAME_INVALID;
    r = OpenEventA((acc & 0x10000000) ? EVENT_ALL_ACCESS : (acc | SYNCHRONIZE), oa_inherit(oa), nm);
    if (!r) return st_last();
    *h = r;
    return 0;
}
NTSTATUS KEXAPI kex_NtCreateSection(PHANDLE h, ACCESS_MASK acc, K_OA *oa, PLARGE_INTEGER max, ULONG prot, ULONG attrs, HANDLE file)
{
    char nm[MAX_PATH]; BOOL named; SECURITY_ATTRIBUTES sa; HANDLE r; DWORD e;
    (void)acc;
    if (!h) return ST_INVALID_PARAMETER;
    if (!obj_name(oa, nm, sizeof(nm), &named)) return ST_NAME_INVALID;
    sa.nLength = sizeof(sa); sa.lpSecurityDescriptor = NULL; sa.bInheritHandle = oa_inherit(oa);
    SetLastError(0);
    r = kex_CreateFileMappingA(file ? file : INVALID_HANDLE_VALUE, &sa, prot | (attrs & 0xFF000000UL),
                               max ? (DWORD)(max->QuadPart >> 32) : 0, max ? (DWORD)max->QuadPart : 0, named ? nm : NULL);
    e = GetLastError();
    if (!r) return st_last();
    *h = r;
    return e == ERROR_ALREADY_EXISTS ? ST_OBJECT_NAME_EXISTS : 0;
}

/* ---- build 131: NTDLL functions Chromium's sandbox hands to its children (policy_broker.cc InitGlobalNt / g_nt) */
LPVOID KEXAPI kex_VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);                                   /* mem_ext.c */
BOOL KEXAPI kex_VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
BOOL KEXAPI kex_VirtualProtectEx(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
#define ST_TIMEOUT    ((NTSTATUS)0x00000102L)
#define ST_ABANDONED  ((NTSTATUS)0x00000080L)
#define ST_USER_APC   ((NTSTATUS)0x000000C0L)
NTSTATUS KEXAPI kex_NtFreeVirtualMemory(HANDLE proc, PVOID *base, PSIZE_T size, ULONG type)
{
    if (!base || !size) return ST_INVALID_PARAMETER;
    if (!kex_VirtualFreeEx(proc, *base, (type & MEM_RELEASE) ? 0 : *size, type)) return st_last();
    return 0;
}
NTSTATUS KEXAPI kex_NtProtectVirtualMemory(HANDLE proc, PVOID *base, PSIZE_T size, ULONG prot, PULONG old)
{
    DWORD o = 0;
    if (!base || !size) return ST_INVALID_PARAMETER;
    if (!kex_VirtualProtectEx(proc, *base, *size, prot, &o)) return st_last();
    if (old) *old = o;
    return 0;
}
static DWORD nt_ms(const LARGE_INTEGER *t)          /* NT timeout: NULL forever, < 0 relative 100 ns, >= 0 absolute */
{
    LONGLONG v; FILETIME now; ULONGLONG n;
    if (!t) return INFINITE;
    v = t->QuadPart;
    if (v < 0) { v = -v; return (DWORD)(v / 10000 > 0xFFFFFFFEULL ? 0xFFFFFFFEUL : v / 10000); }
    GetSystemTimeAsFileTime(&now); n = ((ULONGLONG)now.dwHighDateTime << 32) | now.dwLowDateTime;
    return (ULONGLONG)v <= n ? 0 : (DWORD)(((ULONGLONG)v - n) / 10000);
}
static NTSTATUS st_wait(DWORD r)
{
    if (r == WAIT_OBJECT_0) return 0;
    if (r == WAIT_TIMEOUT) return ST_TIMEOUT;
    if (r == WAIT_ABANDONED) return ST_ABANDONED;
    if (r == WAIT_IO_COMPLETION) return ST_USER_APC;
    return st_last();
}
NTSTATUS KEXAPI kex_NtWaitForSingleObject(HANDLE h, BOOLEAN alertable, PLARGE_INTEGER t)
{
    return st_wait(WaitForSingleObjectEx(h, nt_ms(t), alertable));
}
/* Windows 98 has no SignalObjectAndWait: signal (event, mutex or semaphore - whichever the object is), then wait */
NTSTATUS KEXAPI kex_NtSignalAndWaitForSingleObject(HANDLE sig, HANDLE w, BOOLEAN alertable, PLARGE_INTEGER t)
{
    if (!SetEvent(sig) && !ReleaseMutex(sig) && !ReleaseSemaphore(sig, 1, NULL)) return st_last();
    return st_wait(WaitForSingleObjectEx(w, nt_ms(t), alertable));
}
PVOID KEXAPI kex_RtlAllocateHeap(HANDLE heap, ULONG flags, SIZE_T n) { return HeapAlloc(heap, flags & ~0x10000000UL, n); }
BOOLEAN KEXAPI kex_RtlFreeHeap(HANDLE heap, ULONG flags, PVOID p) { return p ? (BOOLEAN)(HeapFree(heap, flags, p) != 0) : TRUE; }
PVOID KEXAPI kex_RtlCreateHeap(ULONG flags, PVOID base, SIZE_T reserve, SIZE_T commit, PVOID lock, PVOID params)
{
    (void)base; (void)lock; (void)params;            /* a caller-supplied base or lock: not on 98 */
    return HeapCreate(flags & (HEAP_NO_SERIALIZE | HEAP_GENERATE_EXCEPTIONS), commit, (flags & 2 /* HEAP_GROWABLE */) ? 0 : reserve);
}
PVOID KEXAPI kex_RtlDestroyHeap(HANDLE heap) { return HeapDestroy(heap) ? NULL : heap; }
typedef struct { USHORT Length, MaximumLength; PCHAR Buffer; } K_ASTR;
NTSTATUS KEXAPI kex_RtlAnsiStringToUnicodeString(K_USTR *dst, const K_ASTR *src, BOOLEAN alloc)
{
    int n;
    if (!dst || !src) return ST_INVALID_PARAMETER;
    n = src->Length ? MultiByteToWideChar(CP_ACP, 0, src->Buffer, src->Length, NULL, 0) : 0;
    if (n * 2 + 2 > 0xFFFF) return (NTSTATUS)0xC000000DL;
    if (alloc) {
        if (!(dst->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)n * 2 + 2))) return (NTSTATUS)0xC0000017L;   /* NO_MEMORY */
        dst->MaximumLength = (USHORT)(n * 2 + 2);     /* freed by RtlFreeUnicodeString (HeapFree on the process heap) */
    } else if ((DWORD)n * 2 > dst->MaximumLength) return (NTSTATUS)0x80000005L;   /* BUFFER_OVERFLOW */
    if (n) MultiByteToWideChar(CP_ACP, 0, src->Buffer, src->Length, dst->Buffer, n);
    dst->Length = (USHORT)(n * 2);
    if (dst->MaximumLength > dst->Length) dst->Buffer[n] = 0;
    return 0;
}
NTSTATUS KEXAPI kex_RtlCreateUserThread(HANDLE proc, PVOID sd, BOOLEAN suspended, ULONG zerobits, SIZE_T maxstack,
                                        SIZE_T commit, LPTHREAD_START_ROUTINE start, PVOID param, PHANDLE th, K_CID *cid)
{
    typedef HANDLE (WINAPI *T_CRT)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    static T_CRT crt; HANDLE h; DWORD tid = 0;
    (void)sd; (void)zerobits; (void)maxstack;
    if (!start) return ST_INVALID_PARAMETER;
    if (proc == GetCurrentProcess()) h = CreateThread(NULL, commit, start, param, suspended ? CREATE_SUSPENDED : 0, &tid);
    else {
        if (!crt) crt = (T_CRT)(void *)kex_prev_impl("KERNEL32.DLL", "CreateRemoteThread");   /* KernelEx's */
        h = crt ? crt(proc, NULL, commit, start, param, suspended ? CREATE_SUSPENDED : 0, &tid) : NULL;
    }
    if (!h) return st_last();
    if (th) *th = h; else CloseHandle(h);
    if (cid) { cid->UniqueProcess = (HANDLE)(ULONG_PTR)GetCurrentProcessId(); cid->UniqueThread = (HANDLE)(ULONG_PTR)tid; }
    return 0;
}

/* RtlCompareUnicodeString / RtlEqualUnicodeString (firefox.exe; case-insensitive = upcase like NT's RtlUpcaseUnicodeChar
 * for the ASCII + Latin-1 range, CharUpperW-free: kexnt imports only KERNEL32/ADVAPI32) */
static WCHAR up1(WCHAR c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 0xE0 && c <= 0xFE && c != 0xF7)) return (WCHAR)(c - 32);
    if (c == 0xFF) return 0x178;
    return c;
}
LONG KEXAPI kex_RtlCompareUnicodeString(const K_USTR *a, const K_USTR *b, BOOLEAN ci)
{
    int na = a->Length / 2, nb = b->Length / 2, n = na < nb ? na : nb, i;
    for (i = 0; i < n; i++) {
        WCHAR x = a->Buffer[i], y = b->Buffer[i];
        if (ci) { x = up1(x); y = up1(y); }
        if (x != y) return (LONG)x - (LONG)y;
    }
    return na - nb;
}
BOOLEAN KEXAPI kex_RtlEqualUnicodeString(const K_USTR *a, const K_USTR *b, BOOLEAN ci)
{
    if (a->Length != b->Length) return FALSE;
    return kex_RtlCompareUnicodeString(a, b, ci) == 0;
}

/* ------------------------------------------------------------------ USER32 per-monitor DPI (Windows 10 1607+)
 * Google's Chrome standalone setup (Omaha, subsystem 10.0) imports GetDpiForWindow / GetSystemMetricsForDpi statically.
 * Windows 98 has one system DPI: report it, and the plain metrics. */
static int sys_dpi(void)
{
    typedef HDC (WINAPI *T_GDC)(HWND); typedef int (WINAPI *T_RDC)(HWND, HDC); typedef int (WINAPI *T_GDCAPS)(HDC, int);
    static int dpi; T_GDC gdc; T_RDC rdc; T_GDCAPS caps; HDC dc;
    if (dpi) return dpi;
    gdc = (T_GDC)(void *)kex_sysproc("USER32.DLL", "GetDC"); rdc = (T_RDC)(void *)kex_sysproc("USER32.DLL", "ReleaseDC");
    caps = (T_GDCAPS)(void *)kex_sysproc("GDI32.DLL", "GetDeviceCaps");
    if (gdc && rdc && caps && (dc = gdc(NULL))) { dpi = caps(dc, 88 /* LOGPIXELSX */); rdc(NULL, dc); }
    if (dpi <= 0) dpi = 96;
    return dpi;
}
UINT KEXAPI kex_GetDpiForWindow(HWND w) { return (UINT)sys_dpi(); }
UINT KEXAPI kex_GetDpiForSystem(void) { return (UINT)sys_dpi(); }
int KEXAPI kex_GetSystemMetricsForDpi(int idx, UINT dpi)
{
    typedef int (WINAPI *T_GSM)(int); static T_GSM f;
    if (!f) f = (T_GSM)(void *)kex_sysproc("USER32.DLL", "GetSystemMetrics");
    return f ? f(idx) : 0;
}
BOOL KEXAPI kex_AdjustWindowRectExForDpi(LPRECT r, DWORD style, BOOL menu, DWORD exstyle, UINT dpi)
{
    typedef BOOL (WINAPI *T_AWR)(LPRECT, DWORD, BOOL, DWORD); static T_AWR f;
    if (!f) f = (T_AWR)(void *)kex_sysproc("USER32.DLL", "AdjustWindowRectEx");
    return f ? f(r, style, menu, exstyle) : FALSE;
}

/* ------------------------------------------------------------------ the rest of Firefox 115's xul.dll imports */
NTSTATUS KEXAPI kex_NtCancelIoFileEx(HANDLE f, K_IOSB *req, K_IOSB *io) { return (NTSTATUS)0xC0000225L; }   /* STATUS_NOT_FOUND */
NTSTATUS KEXAPI kex_NtDeviceIoControlFile(HANDLE f, HANDLE ev, PVOID apc, PVOID ctx, K_IOSB *io, ULONG code,
                                         PVOID in, ULONG nin, PVOID out, ULONG nout)
{ return (NTSTATUS)0xC0000010L; }                                                   /* STATUS_INVALID_DEVICE_REQUEST */
NTSTATUS KEXAPI kex_NtOpenDirectoryObject(PHANDLE h, ACCESS_MASK a, K_OA *oa) { if (h) *h = NULL; return (NTSTATUS)0xC0000034L; }  /* OBJECT_NAME_NOT_FOUND */
NTSTATUS KEXAPI kex_NtQueryDirectoryObject(HANDLE h, PVOID buf, ULONG len, BOOLEAN single, BOOLEAN restart, PULONG ctx, PULONG ret)
{ if (ret) *ret = 0; return (NTSTATUS)0x8000001AL; }                                /* STATUS_NO_MORE_ENTRIES */

/* Credential Manager (Windows XP+): nothing is stored on 98 */
BOOL KEXAPI kex_CredReadA(LPCSTR target, DWORD type, DWORD flags, PVOID *cred) { if (cred) *cred = NULL; SetLastError(1168 /* ERROR_NOT_FOUND */); return FALSE; }
BOOL KEXAPI kex_CredWriteA(PVOID cred, DWORD flags) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_CredDeleteA(LPCSTR target, DWORD type, DWORD flags) { SetLastError(1168); return FALSE; }
VOID KEXAPI kex_CredFree(PVOID p) { }
LONG KEXAPI kex_RegCreateKeyTransactedW(HKEY k, LPCWSTR sub, DWORD r, LPWSTR cls, DWORD opt, REGSAM sam, PVOID sa,
                                       PHKEY out, LPDWORD disp, HANDLE tx, PVOID ext)
{ if (out) *out = NULL; return ERROR_CALL_NOT_IMPLEMENTED; }

BOOL KEXAPI kex_CancelSynchronousIo(HANDLE t) { SetLastError(1168 /* ERROR_NOT_FOUND: no synchronous I/O to cancel */); return FALSE; }
/* low-memory notification: an event nobody sets (Windows 98 has no such signal) */
HANDLE KEXAPI kex_CreateMemoryResourceNotification(int type) { return CreateEventA(NULL, TRUE, FALSE, NULL); }
HRESULT KEXAPI kex_RegisterApplicationRestart(PCWSTR cmd, DWORD flags) { return S_OK; }
HRESULT KEXAPI kex_UnregisterApplicationRestart(void) { return S_OK; }
HRESULT KEXAPI kex_GetApplicationRestartSettings(HANDLE p, PWSTR cmd, PDWORD n, PDWORD flags) { return (HRESULT)0x80070490L; } /* ERROR_NOT_FOUND */
BOOL KEXAPI kex_SetThreadErrorMode(DWORD mode, LPDWORD old)
{
    UINT o = SetErrorMode(mode);          /* Windows 98: one error mode per process */
    if (old) *old = o;
    return TRUE;
}

/* WS2_32 WSCGetProviderInfo (Windows 7+; xul.dll asks for the LSP category of the Winsock providers):
 * Windows 98's Winsock has no provider categories - "no such provider", the documented failure */
int KEXAPI kex_WSCGetProviderInfo(const GUID *id, int type, PBYTE info, size_t *size, DWORD flags, LPINT err)
{
    if (err) *err = 10105;            /* WSAEINVALIDPROVIDER */
    return -1;                        /* SOCKET_ERROR */
}

/* USER32 touch input and gestures (Windows 7; xul.dll delay-loads them, RegisterTouchWindow failing as
 * "procedure not found" ended Firefox 115 with exception C06D007F). Windows 98 has no touch screens. */
BOOL KEXAPI kex_RegisterTouchWindow(HWND w, ULONG flags) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetTouchInputInfo(HANDLE h, UINT n, PVOID in, int cb) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
BOOL KEXAPI kex_GetGestureInfo(HANDLE h, PVOID info) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
BOOL KEXAPI kex_CloseGestureInfoHandle(HANDLE h) { return TRUE; }
BOOL KEXAPI kex_SetGestureConfig(HWND w, DWORD r, UINT n, PVOID cfg, UINT cb) { return TRUE; }
/* SHLWAPI PathUnExpandEnvStringsW: "no environment string could be substituted" */
BOOL KEXAPI kex_PathUnExpandEnvStringsW(LPCWSTR path, LPWSTR buf, UINT n) { return FALSE; }

/* KERNEL32 GetThreadUILanguage (Vista+). Inno Setup 6's setup stub (K-Lite 20.2) takes it with GetProcAddress
 * once Windows reports 6.0 or newer and calls it unchecked - a NULL pointer, executed as garbage from address 0
 * on Windows 98 ("illegal instruction at 0000:00000017"). */
LANGID KEXAPI kex_GetThreadUILanguage(void) { return GetUserDefaultLangID(); }

/* NTDLL's 64-bit integer helpers (MSVC runtime names, exported by every NT NTDLL). Inno Setup 6.4's setup program
 * (K-Lite 20.2: is-XXXXX.tmp\*.tmp, error 31 "Unable to execute file in the temporary directory") imports
 * _allshl/_aullshr. Shifts: value in EDX:EAX, count in CL. Mul/div/rem: two 64-bit arguments on the stack,
 * the callee removes them (= stdcall @16). */
__asm__(
".globl _kex_allshl\n_kex_allshl:\n"
"    cmpb $64, %cl\n    jae 2f\n    cmpb $32, %cl\n    jae 1f\n    shldl %cl, %eax, %edx\n    shll %cl, %eax\n    ret\n"
"1:  movl %eax, %edx\n    xorl %eax, %eax\n    andb $31, %cl\n    shll %cl, %edx\n    ret\n"
"2:  xorl %eax, %eax\n    xorl %edx, %edx\n    ret\n"
".globl _kex_aullshr\n_kex_aullshr:\n"
"    cmpb $64, %cl\n    jae 2f\n    cmpb $32, %cl\n    jae 1f\n    shrdl %cl, %edx, %eax\n    shrl %cl, %edx\n    ret\n"
"1:  movl %edx, %eax\n    xorl %edx, %edx\n    andb $31, %cl\n    shrl %cl, %eax\n    ret\n"
"2:  xorl %eax, %eax\n    xorl %edx, %edx\n    ret\n"
".globl _kex_allshr\n_kex_allshr:\n"
"    cmpb $64, %cl\n    jae 2f\n    cmpb $32, %cl\n    jae 1f\n    shrdl %cl, %edx, %eax\n    sarl %cl, %edx\n    ret\n"
"1:  movl %edx, %eax\n    sarl $31, %edx\n    andb $31, %cl\n    sarl %cl, %eax\n    ret\n"
"2:  sarl $31, %edx\n    movl %edx, %eax\n    ret\n"
);
LONGLONG KEXAPI kex_allmul(LONGLONG a, LONGLONG b) { return a * b; }

/* delay-loaded by Inno Setup 6.4's setup program */
BOOL KEXAPI kex_GetSystemTimes(PFILETIME idle, PFILETIME kern, PFILETIME user)
{
    /* Windows 98 keeps no per-CPU idle time: report the uptime as kernel time, nothing idle */
    ULONGLONG t = (ULONGLONG)GetTickCount() * 10000;
    if (idle) { idle->dwLowDateTime = 0; idle->dwHighDateTime = 0; }
    if (kern) { kern->dwLowDateTime = (DWORD)t; kern->dwHighDateTime = (DWORD)(t >> 32); }
    if (user) { user->dwLowDateTime = 0; user->dwHighDateTime = 0; }
    return TRUE;
}
BOOL KEXAPI kex_GetTimeZoneInformationForYear(USHORT year, PVOID dyn, LPTIME_ZONE_INFORMATION tz)
{
    if (!tz) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return GetTimeZoneInformation(tz) != TIME_ZONE_ID_INVALID;     /* one rule set on 98: the current one */
}
BOOL KEXAPI kex_AreDpiAwarenessContextsEqual(HANDLE a, HANDLE b) { return a == b; }
HANDLE KEXAPI kex_GetWindowDpiAwarenessContext(HWND w) { return (HANDLE)(LONG_PTR)-1; }   /* DPI_AWARENESS_CONTEXT_UNAWARE */
BOOL KEXAPI kex_PhysicalToLogicalPoint(HWND w, LPPOINT p) { return TRUE; }               /* one DPI: the same point */

/* ------------------------------------------------------------------ Firefox 160 (import check of C:\Program Files\FF160) */
BOOL KEXAPI kex_DuplicateHandle(HANDLE sp, HANDLE h, HANDLE tp, LPHANDLE out, DWORD access, BOOL inherit, DWORD opts);   /* shm_ext.c */
BOOL KEXAPI kex_SleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l, DWORD ms, ULONG flags);                    /* sync_ext.c */
NTSTATUS KEXAPI kex_NtDuplicateObject(HANDLE sp, HANDLE h, HANDLE tp, PHANDLE out, ACCESS_MASK acc, ULONG attr, ULONG opts)
{
    HANDLE r = NULL;
    if (!kex_DuplicateHandle(sp, h, tp, out ? out : &r, acc, (attr & 0x2 /* OBJ_INHERIT */) != 0, opts)) return kex_status_from_win32(GetLastError());
    return 0;
}
/* timeout: NULL = infinite, else 100 ns units (negative = relative, as NT callers pass it) */
NTSTATUS KEXAPI kex_RtlSleepConditionVariableSRW(PCONDITION_VARIABLE c, PSRWLOCK l, const LARGE_INTEGER *to, ULONG flags)
{
    DWORD ms = INFINITE;
    if (to) { LONGLONG t = to->QuadPart; if (t < 0) t = -t; else t = 0; ms = (DWORD)((t + 9999) / 10000); }
    if (kex_SleepConditionVariableSRW(c, l, ms, flags)) return 0;
    return GetLastError() == ERROR_TIMEOUT ? (NTSTATUS)0x00000102L : (NTSTATUS)0xC0000001L;   /* STATUS_TIMEOUT */
}
NTSTATUS KEXAPI kex_RtlDosPathNameToNtPathName_U_WithStatus(LPCWSTR dos, K_USTR *nt, PWSTR *part, PVOID rel)
{
    WCHAR full[MAX_PATH + 8]; WCHAR *fp = NULL; DWORD n;
    if (!dos || !nt) return (NTSTATUS)0xC000000DL;
    { char a[MAX_PATH * 2], f[MAX_PATH]; char *fpa = NULL;
      if (!WideCharToMultiByte(CP_ACP, 0, dos, -1, a, sizeof(a), NULL, NULL)) return (NTSTATUS)0xC0000033L;
      n = GetFullPathNameA(a, MAX_PATH, f, &fpa);
      if (!n || n >= MAX_PATH) return (NTSTATUS)0xC0000033L;
      full[0] = L'\\'; full[1] = L'?'; full[2] = L'?'; full[3] = L'\\';
      n = (DWORD)MultiByteToWideChar(CP_ACP, 0, f, -1, full + 4, MAX_PATH + 4);
      if (!n) return (NTSTATUS)0xC0000033L;
      if (fpa) fp = full + 4 + MultiByteToWideChar(CP_ACP, 0, f, (int)(fpa - f), NULL, 0); }
    n = (DWORD)lstrlenW(full);
    if (!(nt->Buffer = (PWSTR)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR)))) return (NTSTATUS)0xC0000017L;
    memcpy(nt->Buffer, full, (n + 1) * sizeof(WCHAR));
    nt->Length = (USHORT)(n * 2); nt->MaximumLength = (USHORT)((n + 1) * 2);
    if (part) *part = fp ? nt->Buffer + (fp - full) : NULL;
    if (rel) memset(rel, 0, 16);                                   /* RTL_RELATIVE_NAME_U: none */
    return 0;
}
LONG KEXAPI kex_GetCurrentPackageFullName(UINT32 *len, PWSTR name) { if (len) *len = 0; return 15700; }      /* APPMODEL_ERROR_NO_PACKAGE */
LONG KEXAPI kex_GetCurrentApplicationUserModelId(UINT32 *len, PWSTR id) { if (len) *len = 0; return 15703; } /* ..._NO_APPLICATION */
HANDLE KEXAPI kex_CreateWaitableTimerExA(LPSECURITY_ATTRIBUTES sa, LPCSTR name, DWORD flags, DWORD access)
{ return CreateWaitableTimerA(sa, (flags & 1) != 0 /* CREATE_WAITABLE_TIMER_MANUAL_RESET */, name); }
BOOL KEXAPI kex_SetWaitableTimerEx(HANDLE t, const LARGE_INTEGER *due, LONG period, PTIMERAPCROUTINE apc, LPVOID arg, PVOID wake, ULONG delay)
{ return SetWaitableTimer(t, due, period, apc, arg, FALSE); }
BOOL KEXAPI kex_GetOverlappedResultEx(HANDLE h, LPOVERLAPPED ov, LPDWORD n, DWORD ms, BOOL alertable)
{
    if (ov && ov->hEvent && ms != INFINITE) {
        DWORD w = alertable ? WaitForSingleObjectEx(ov->hEvent, ms, TRUE) : WaitForSingleObject(ov->hEvent, ms);
        if (w == WAIT_TIMEOUT) { SetLastError(WAIT_TIMEOUT); return FALSE; }
        if (w == WAIT_IO_COMPLETION) { SetLastError(WAIT_IO_COMPLETION); return FALSE; }
    }
    return GetOverlappedResult(h, ov, n, ms == INFINITE);
}
BOOL KEXAPI kex_GetSystemCpuSetInformation(PVOID info, ULONG len, PULONG ret, HANDLE p, ULONG flags)
{ if (ret) *ret = 0; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }   /* callers fall back to the processor count */
HANDLE KEXAPI kex_ReOpenFile(HANDLE h, DWORD access, DWORD share, DWORD flags)
{
    char p[MAX_PATH];
    if (!kex_fpath_get(h, p, MAX_PATH)) { SetLastError(ERROR_INVALID_HANDLE); return INVALID_HANDLE_VALUE; }
    return CreateFileA(p, access, share, NULL, OPEN_EXISTING, flags, NULL);
}
BOOL KEXAPI kex_CreatePrivateObjectSecurityEx(PVOID parent, PVOID creator, PVOID *out, GUID *t, BOOL dir, ULONG f, HANDLE tok, PVOID map)
{ if (out) *out = NULL; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
LONG KEXAPI kex_RegRenameKey(HKEY k, LPCWSTR sub, LPCWSTR newname) { return ERROR_CALL_NOT_IMPLEMENTED; }
int KEXAPI kex_WSASendMsg(UINT_PTR s, PVOID msg, DWORD flags, LPDWORD sent, LPOVERLAPPED ov, PVOID cr)
{
    typedef void (WINAPI *T_SE)(int); T_SE se = (T_SE)(void *)kex_sysproc("WS2_32.DLL", "WSASetLastError");
    if (se) se(10045 /* WSAEOPNOTSUPP */);
    return -1;
}
/* delay-loaded by Firefox 160's xul.dll */
HRESULT KEXAPI kex_SHGetKnownFolderItem(const GUID *id, DWORD flags, HANDLE tok, REFIID riid, void **out) { if (out) *out = NULL; return E_NOTIMPL; }
PVOID KEXAPI kex_ILCreateFromPathW(LPCWSTR path)
{
    /* the desktop folder parses the path into an item id list (Windows 98 SHELL32 has no wide ILCreateFromPath) */
    typedef HRESULT (WINAPI *T_GDF)(void **); typedef HRESULT (WINAPI *T_PDN)(void *, HWND, void *, LPWSTR, ULONG *, PVOID *, ULONG *);
    typedef ULONG (WINAPI *T_REL)(void *);
    T_GDF gdf = (T_GDF)(void *)kex_sysproc("SHELL32.DLL", "SHGetDesktopFolder"); void *df = NULL; PVOID pidl = NULL; ULONG eaten = 0;
    WCHAR buf[MAX_PATH];
    if (!path || !gdf || gdf(&df) != S_OK || !df) return NULL;
    lstrcpynW(buf, path, MAX_PATH);
    ((T_PDN)(*(void ***)df)[3])(df, NULL, NULL, buf, &eaten, &pidl, NULL);
    ((T_REL)(*(void ***)df)[2])(df);
    return pidl;
}
VOID KEXAPI kex_ILFree(PVOID pidl)
{
    typedef VOID (WINAPI *T_ILF)(PVOID); T_ILF f = (T_ILF)(void *)kex_sysproc("SHELL32.DLL", (LPCSTR)155);   /* ILFree is ordinal 155 */
    if (pidl && f) f(pidl);
}
HANDLE KEXAPI kex_CreateSyntheticPointerDevice(int type, ULONG max, int mode) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
BOOL KEXAPI kex_GetAutoRotationState(PVOID state) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetPointerFrameTouchInfo(UINT32 id, UINT32 *n, PVOID info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_InjectSyntheticPointerInput(HANDLE dev, PVOID info, UINT32 n) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
BOOL KEXAPI kex_IsOS(DWORD os)
{
    typedef BOOL (WINAPI *T_ISOS)(DWORD); T_ISOS f = (T_ISOS)(void *)kex_sysproc("SHLWAPI.DLL", (LPCSTR)437);   /* IsOS is ordinal 437 */
    return f ? f(os) : FALSE;
}

/* ------------------------------------------------------------------ api-ms-win-core-path-l1-1-0 (Windows 8): PathCch*
 * through SHLWAPI's ANSI path functions (Windows 98 + IE5); paths longer than MAX_PATH are refused as on NT without
 * PATHCCH_ALLOW_LONG_PATHS. */
#define HR_SMALL ((HRESULT)0x8007007AL)          /* HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) */
typedef BOOL (WINAPI *T_P2)(LPSTR, LPCSTR); typedef LPSTR (WINAPI *T_PC)(LPSTR, LPCSTR, LPCSTR); typedef LPSTR (WINAPI *T_P1)(LPSTR);
typedef BOOL (WINAPI *T_PB)(LPSTR);
static HRESULT path_out(const char *a, PWSTR out, size_t cch)
{
    int n = MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0);
    if (!out || !cch) return E_INVALIDARG;
    if ((size_t)n > cch) { out[0] = 0; return HR_SMALL; }
    MultiByteToWideChar(CP_ACP, 0, a, -1, out, (int)cch);
    return S_OK;
}
HRESULT KEXAPI kex_PathCchCanonicalizeEx(PWSTR out, size_t cch, PCWSTR in, ULONG flags)
{
    char a[MAX_PATH], r[MAX_PATH]; T_P2 f = (T_P2)(void *)kex_sysproc("SHLWAPI.DLL", "PathCanonicalizeA");
    if (!in || !f || !to_a(in, a, sizeof(a))) return E_INVALIDARG;
    if (!f(r, a)) return E_INVALIDARG;
    return path_out(r, out, cch);
}
HRESULT KEXAPI kex_PathCchCanonicalize(PWSTR out, size_t cch, PCWSTR in) { return kex_PathCchCanonicalizeEx(out, cch, in, 0); }
HRESULT KEXAPI kex_PathCchCombineEx(PWSTR out, size_t cch, PCWSTR a1, PCWSTR a2, ULONG flags)
{
    char a[MAX_PATH], b[MAX_PATH], r[MAX_PATH]; T_PC f = (T_PC)(void *)kex_sysproc("SHLWAPI.DLL", "PathCombineA");
    if (!f || (!a1 && !a2) || !to_a(a1, a, sizeof(a)) || !to_a(a2, b, sizeof(b))) return E_INVALIDARG;
    if (!f(r, a1 ? a : NULL, a2 ? b : NULL)) return E_INVALIDARG;
    return path_out(r, out, cch);
}
HRESULT KEXAPI kex_PathCchCombine(PWSTR out, size_t cch, PCWSTR a1, PCWSTR a2) { return kex_PathCchCombineEx(out, cch, a1, a2, 0); }
HRESULT KEXAPI kex_PathCchAppend(PWSTR path, size_t cch, PCWSTR more)
{
    char a[MAX_PATH], b[MAX_PATH]; T_P2 f = (T_P2)(void *)kex_sysproc("SHLWAPI.DLL", "PathAppendA");
    if (!path || !f || !to_a(path, a, sizeof(a)) || !to_a(more, b, sizeof(b))) return E_INVALIDARG;
    if (!f(a, b)) return E_INVALIDARG;
    return path_out(a, path, cch);
}
HRESULT KEXAPI kex_PathCchAddBackslash(PWSTR path, size_t cch)
{
    size_t n; if (!path) return E_INVALIDARG;
    n = (size_t)lstrlenW(path);
    if (n && path[n - 1] == L'\\') return S_FALSE;
    if (n + 2 > cch) return HR_SMALL;
    path[n] = L'\\'; path[n + 1] = 0;
    return S_OK;
}
HRESULT KEXAPI kex_PathCchRemoveFileSpec(PWSTR path, size_t cch)
{
    char a[MAX_PATH], before[MAX_PATH]; T_PB f = (T_PB)(void *)kex_sysproc("SHLWAPI.DLL", "PathRemoveFileSpecA");
    if (!path || !f || !to_a(path, a, sizeof(a))) return E_INVALIDARG;
    lstrcpyA(before, a);
    f(a);
    if (!lstrcmpA(a, before)) return S_FALSE;
    return path_out(a, path, cch);
}

/* CFGMGR32 (Firefox 160 xul.dll): device-interface notifications do not exist on 98 */
DWORD KEXAPI kex_CM_Get_Device_Interface_List_SizeW(PULONG len, LPGUID cls, PWSTR dev, ULONG flags) { if (len) *len = 1; return 0; } /* empty list */
DWORD KEXAPI kex_CM_Get_Device_Interface_ListW(LPGUID cls, PWSTR dev, PWSTR buf, ULONG len, ULONG flags)
{ if (!buf || !len) return 0x1F; /* CR_INVALID_POINTER */ buf[0] = 0; if (len > 1) buf[1] = 0; return 0; }
DWORD KEXAPI kex_CM_Register_Notification(PVOID filter, PVOID ctx, PVOID cb, PVOID *out) { if (out) *out = NULL; return 0x34; } /* CR_CALL_NOT_IMPLEMENTED */
DWORD KEXAPI kex_CM_Unregister_Notification(PVOID h) { return 0; }

/* Google Chrome standalone setup (Omaha): no service manager on Windows 98; one foreground rule */
BOOL KEXAPI kex_ChangeServiceConfig2W(HANDLE svc, DWORD level, LPVOID info) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_ChangeServiceConfig2A(HANDLE svc, DWORD level, LPVOID info) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_AllowSetForegroundWindow(DWORD pid) { return TRUE; }   /* Windows 98 has no foreground lock */
