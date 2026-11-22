/*
 * sysdll_ext.c - NT6+/NT10 functions of Windows DLLs that exist on Windows 98 SE but lack them
 * (ADVAPI32, CRYPT32, OLE32, SHELL32, WS2_32, USER32, GDI32, IPHLPAPI, NETAPI32, SECUR32, PDH,
 * USERENV, SETUPAPI, CFGMGR32, WINTRUST), plus the WinRT string/activation basics, shcore DPI
 * scaling and power-setting api sets. KernelEx publishes each one under its DLL (kexnt_targets.txt).
 *
 * kexnt.dll may import only KERNEL32/ADVAPI32 (it is a KernelEx api library), so everything else is
 * reached with kex_sysproc() at call time.
 * Where Win98 has the data the function works (RegGetValue, known folders, DPI, inet_ntop/pton,
 * HSTRINGs, random numbers); otherwise it fails with the code NT returns when the feature is absent.
 */
#include "kexnt_common.h"
#include <string.h>
#include <shlobj.h>
#ifdef __clang__
#pragma clang diagnostic ignored "-Wcast-function-type-mismatch"   /* GetProcAddress results */
#endif

#define HR_NOTIMPL      ((HRESULT)0x80004001L)
#define HR_FAIL         ((HRESULT)0x80004005L)
#define HR_INVALIDARG   ((HRESULT)0x80070057L)
#define HR_OUTOFMEMORY  ((HRESULT)0x8007000EL)
#define HR_W32(e)       ((HRESULT)(((e) & 0xFFFF) | 0x80070000L))
#define REGDB_CLASSNOTREG ((HRESULT)0x80040154L)
#define CO_NOTINIT      ((HRESULT)0x800401F0L)

typedef void *(WINAPI *TASKALLOC)(SIZE_T);
static void *co_alloc(SIZE_T n)
{
    TASKALLOC f = (TASKALLOC)kex_sysproc("OLE32.DLL", "CoTaskMemAlloc");
    return f ? f(n) : NULL;
}

static char *w2a_heap(LPCWSTR w)                    /* NULL -> NULL; caller HeapFree()s */
{
    int n; char *a;
    if (!w) return NULL;
    n = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0, NULL, NULL);
    if (!n || !(a = HeapAlloc(GetProcessHeap(), 0, n))) return NULL;
    WideCharToMultiByte(CP_ACP, 0, w, -1, a, n, NULL, NULL);
    return a;
}
static void hfree(void *p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

/* =========================================== random numbers ===========================================
 * ChaCha20 keystream generator, seeded from CryptoAPI's CryptGenRandom (Win98 SE has the base RSA
 * provider) mixed with timer/cpu counters, re-keyed every 1 MB and from its own output (forward secrecy).
 * Exported as KexGenRandom (used by our bcryptprimitives/bcrypt) and ADVAPI32!SystemFunction036
 * (RtlGenRandom). */
#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) (a += b, d ^= a, d = ROTL(d, 16), c += d, b ^= c, b = ROTL(b, 12), \
                        a += b, d ^= a, d = ROTL(d, 8),  c += d, b ^= c, b = ROTL(b, 7))
static void chacha_block(const DWORD in[16], DWORD out[16])
{
    DWORD x[16]; int i;
    for (i = 0; i < 16; i++) x[i] = in[i];
    for (i = 0; i < 10; i++) {
        QR(x[0], x[4], x[8], x[12]); QR(x[1], x[5], x[9], x[13]); QR(x[2], x[6], x[10], x[14]); QR(x[3], x[7], x[11], x[15]);
        QR(x[0], x[5], x[10], x[15]); QR(x[1], x[6], x[11], x[12]); QR(x[2], x[7], x[8], x[13]); QR(x[3], x[4], x[9], x[14]);
    }
    for (i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

static DWORD g_rng[16]; static DWORD g_rng_used; static BOOL g_rng_seeded; static DWORD g_rng_pid;
static volatile LONG g_rng_lock;

typedef BOOL (WINAPI *CACQ)(ULONG_PTR *, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI *CGEN)(ULONG_PTR, DWORD, BYTE *);
typedef BOOL (WINAPI *CREL)(ULONG_PTR, DWORD);

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
static void rng_seed(void)
{
    DWORD seed[16]; LARGE_INTEGER q; ULONG_PTR prov = 0; int i;
    CACQ acq; CGEN gen; CREL rel;
    kex_trace("rng seed: looking up CryptoAPI", 0, 0, 0, 0);
    acq = (CACQ)kex_sysproc("ADVAPI32.DLL", "CryptAcquireContextA");
    gen = (CGEN)kex_sysproc("ADVAPI32.DLL", "CryptGenRandom");
    rel = (CREL)kex_sysproc("ADVAPI32.DLL", "CryptReleaseContext");
    memset(seed, 0, sizeof(seed));
    kex_trace("rng seed: CryptAcquireContextA", (DWORD)(ULONG_PTR)acq, (DWORD)(ULONG_PTR)gen, 0, 0);
    if (acq && gen && acq(&prov, NULL, NULL, 1 /*PROV_RSA_FULL*/, 0xF0000000 /*CRYPT_VERIFYCONTEXT*/)) {
        gen(prov, sizeof(seed), (BYTE *)seed);
        if (rel) rel(prov, 0);
    }
    /* mix in what differs per boot / process / moment even if CryptoAPI is missing */
    QueryPerformanceCounter(&q);
    seed[0] ^= q.LowPart; seed[1] ^= q.HighPart; seed[2] ^= GetTickCount(); seed[3] ^= GetCurrentProcessId();
    seed[4] ^= GetCurrentThreadId(); seed[5] ^= (DWORD)(ULONG_PTR)&q;
    kex_trace("rng seed: CryptoAPI done", (DWORD)prov, 0, 0, 0);
    { DWORD lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); seed[6] ^= lo; seed[7] ^= hi; }
    { MEMORYSTATUS ms; ms.dwLength = sizeof(ms); GlobalMemoryStatus(&ms); seed[8] ^= (DWORD)ms.dwAvailPhys; seed[9] ^= (DWORD)ms.dwAvailPageFile; }
    { FILETIME ft; GetSystemTimeAsFileTime(&ft); seed[10] ^= ft.dwLowDateTime; seed[11] ^= ft.dwHighDateTime; }
    g_rng[0] = 0x61707865; g_rng[1] = 0x3320646e; g_rng[2] = 0x79622d32; g_rng[3] = 0x6b206574;
    for (i = 0; i < 8; i++) g_rng[4 + i] ^= seed[i] ^ seed[8 + (i & 3)];
    g_rng[12] = 0; g_rng[13] = 0; g_rng[14] ^= seed[12] ^ seed[14]; g_rng[15] ^= seed[13] ^ seed[15];
    memset(seed, 0, sizeof(seed));
    g_rng_used = 0; g_rng_seeded = TRUE; g_rng_pid = GetCurrentProcessId();
}

BOOL KEXAPI kex_KexGenRandom(PVOID buf, SIZE_T len)
{
    BYTE *p = buf; DWORD blk[16]; int i;
    static volatile LONG calls;
    if (InterlockedIncrement((LONG *)&calls) <= 3)              /* breadcrumb: Chrome 2026-11-01 blue screen hunt */
        kex_trace("KexGenRandom", (DWORD)(ULONG_PTR)buf, (DWORD)len, (DWORD)(ULONG_PTR)__builtin_return_address(0), g_rng_seeded);
    kex_spin_acquire((volatile LONG *)&g_rng_lock);
    if (!g_rng_seeded || g_rng_pid != GetCurrentProcessId() || g_rng_used > (1UL << 20)) rng_seed();
    while (len) {
        SIZE_T n = len < 64 ? len : 64;
        chacha_block(g_rng, blk);
        if (!++g_rng[12]) g_rng[13]++;
        memcpy(p, blk, n); p += n; len -= n; g_rng_used += 64;
    }
    chacha_block(g_rng, blk);                                   /* re-key from fresh output */
    for (i = 0; i < 8; i++) g_rng[4 + i] = blk[i];
    if (!++g_rng[12]) g_rng[13]++;
    memset(blk, 0, sizeof(blk));
    InterlockedExchange((LONG *)&g_rng_lock, 0);
    return TRUE;
}

BOOLEAN KEXAPI kex_SystemFunction036(PVOID buf, ULONG len) { return (BOOLEAN)kex_KexGenRandom(buf, len); }

/* ============================================== ADVAPI32 ============================================== */
/* Event Tracing for Windows: there is no ETW on 9x. Providers register successfully (so callers keep
 * running) and are simply never enabled; writes are accepted and dropped. */
static volatile LONG g_etw_next;

ULONG KEXAPI kex_EventRegister(const GUID *id, PVOID cb, PVOID ctx, PULONGLONG handle)
{
    if (!handle) return ERROR_INVALID_PARAMETER;
    *handle = (ULONGLONG)(InterlockedIncrement((LONG *)&g_etw_next)) | 0x4B580000ULL;
    return ERROR_SUCCESS;
}
ULONG KEXAPI kex_EventUnregister(ULONGLONG h) { return ERROR_SUCCESS; }
ULONG KEXAPI kex_EventWrite(ULONGLONG h, PVOID desc, ULONG n, PVOID data) { return ERROR_SUCCESS; }
ULONG KEXAPI kex_EventWriteTransfer(ULONGLONG h, PVOID desc, const GUID *act, const GUID *rel, ULONG n, PVOID data) { return ERROR_SUCCESS; }
ULONG KEXAPI kex_EventWriteEx(ULONGLONG h, PVOID desc, ULONG64 filter, ULONG flags, const GUID *act, const GUID *rel, ULONG n, PVOID data) { return ERROR_SUCCESS; }
ULONG KEXAPI kex_EventWriteString(ULONGLONG h, UCHAR level, ULONGLONG kw, PCWSTR s) { return ERROR_SUCCESS; }
ULONG KEXAPI kex_EventSetInformation(ULONGLONG h, int cls, PVOID info, ULONG len) { return ERROR_SUCCESS; }
BOOLEAN KEXAPI kex_EventEnabled(ULONGLONG h, PVOID desc) { return FALSE; }
BOOLEAN KEXAPI kex_EventProviderEnabled(ULONGLONG h, UCHAR level, ULONGLONG kw) { return FALSE; }
ULONG KEXAPI kex_EventActivityIdControl(ULONG code, GUID *id)
{
    if (id && (code == 3 /*CREATE_ID*/ || code == 4 /*GET_SET_ID*/ || code == 5 /*CREATE_SET_ID*/)) kex_KexGenRandom(id, sizeof(*id));
    return ERROR_SUCCESS;
}
ULONG KEXAPI kex_RegisterTraceGuidsW(PVOID cb, PVOID ctx, const GUID *g, ULONG n, PVOID reg, LPCWSTR mof, LPCWSTR res, PULONGLONG h)
{
    if (!h) return ERROR_INVALID_PARAMETER;
    *h = (ULONGLONG)(InterlockedIncrement((LONG *)&g_etw_next)) | 0x4B580000ULL;
    return ERROR_SUCCESS;
}
ULONG KEXAPI kex_RegisterTraceGuidsA(PVOID cb, PVOID ctx, const GUID *g, ULONG n, PVOID reg, LPCSTR mof, LPCSTR res, PULONGLONG h)
{
    return kex_RegisterTraceGuidsW(cb, ctx, g, n, reg, NULL, NULL, h);
}
ULONG KEXAPI kex_UnregisterTraceGuids(ULONGLONG h) { return ERROR_SUCCESS; }
ULONG KEXAPI kex_TraceEvent(ULONGLONG h, PVOID hdr) { return ERROR_INVALID_HANDLE; }
ULONG KEXAPI kex_GetTraceEnableFlags(ULONGLONG h) { return 0; }
UCHAR KEXAPI kex_GetTraceEnableLevel(ULONGLONG h) { return 0; }
ULONGLONG KEXAPI kex_GetTraceLoggerHandle(PVOID buf) { SetLastError(ERROR_INVALID_HANDLE); return (ULONGLONG)-1; }

BOOL KEXAPI kex_CreateProcessWithTokenW(HANDLE tok, DWORD logon, LPCWSTR app, LPWSTR cmd, DWORD flags,
                                       LPVOID env, LPCWSTR dir, LPVOID si, LPVOID pi)
{
    /* build 131: no tokens on 9x - started like any program (see procspawn_ext.c kex_CreateProcessAsUserW) */
    BOOL KEXAPI kex_CreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                                   LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    (void)tok; (void)logon;
    return kex_CreateProcessW(app, cmd, NULL, NULL, FALSE, flags, env, dir, (LPSTARTUPINFOW)si, (LPPROCESS_INFORMATION)pi);
}
BOOL KEXAPI kex_AddConditionalAce(PACL acl, DWORD rev, DWORD flags, UCHAR type, DWORD mask, PSID sid, PWCHAR cond, DWORD *ret)
{ SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_AddMandatoryAce(PACL acl, DWORD rev, DWORD flags, DWORD policy, PSID sid)
{ SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_ImpersonateAnonymousToken(HANDLE thread) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
NTSTATUS KEXAPI kex_LsaAddAccountRights(HANDLE pol, PSID sid, PVOID rights, ULONG n) { return STATUS_NOT_IMPLEMENTED; }

LONG KEXAPI kex_RegDeleteKeyExA(HKEY key, LPCSTR sub, REGSAM sam, DWORD res)
{
    return RegDeleteKeyA(key, sub);                              /* WOW64 view flags: one view on 9x */
}
LONG KEXAPI kex_RegDeleteKeyExW(HKEY key, LPCWSTR sub, REGSAM sam, DWORD res)
{
    char *a; LONG r;
    if (!sub) return ERROR_INVALID_PARAMETER;
    if (!(a = w2a_heap(sub))) return ERROR_NOT_ENOUGH_MEMORY;
    r = RegDeleteKeyA(key, a); hfree(a); return r;
}

/* RegGetValue: RRF_RT_* type filter, REG_EXPAND_SZ expansion, guaranteed string termination. */
#define RRF_NOEXPAND       0x10000000
#define RRF_ZEROONFAILURE  0x20000000
static DWORD rrf_bit(DWORD type)
{
    switch (type) {
    case REG_NONE: return 0x01; case REG_SZ: return 0x02; case REG_EXPAND_SZ: return 0x04;
    case REG_BINARY: return 0x08; case REG_DWORD: return 0x10; case REG_MULTI_SZ: return 0x20;
    case 11 /*REG_QWORD*/: return 0x40; default: return 0;
    }
}
static BOOL is_str(DWORD t) { return t == REG_SZ || t == REG_EXPAND_SZ || t == REG_MULTI_SZ; }

static LONG reg_get(HKEY key, LPCSTR sub, LPCSTR val, DWORD flags, LPDWORD ptype, PVOID data, LPDWORD pcb, BOOL wide)
{
    HKEY k = key; LONG r; DWORD type = 0, asz = 0, need, cap = pcb ? *pcb : 0;
    BYTE *a = NULL; WCHAR *w = NULL; BYTE *out; DWORD outsz;
    if ((data && !pcb) || !(flags & 0xFFFF)) return ERROR_INVALID_PARAMETER;
    if (sub && *sub && (r = RegOpenKeyExA(key, sub, 0, KEY_QUERY_VALUE, &k)) != ERROR_SUCCESS) goto fail;
    r = RegQueryValueExA(k, val, NULL, &type, NULL, &asz);
    if (r != ERROR_SUCCESS) goto out;
    if (!(a = HeapAlloc(GetProcessHeap(), 0, asz + 2))) { r = ERROR_NOT_ENOUGH_MEMORY; goto out; }
    if ((r = RegQueryValueExA(k, val, NULL, &type, a, &asz)) != ERROR_SUCCESS) goto out;
    a[asz] = a[asz + 1] = 0;
    if (type == REG_EXPAND_SZ && !(flags & RRF_NOEXPAND)) {     /* expand, report REG_SZ */
        DWORD n = ExpandEnvironmentStringsA((char *)a, NULL, 0);
        BYTE *e = n ? HeapAlloc(GetProcessHeap(), 0, n + 2) : NULL;
        if (!e) { r = ERROR_NOT_ENOUGH_MEMORY; goto out; }
        ExpandEnvironmentStringsA((char *)a, (char *)e, n);
        hfree(a); a = e; asz = n; type = REG_SZ;
        if (!(flags & 0x02) && !(flags & 0x04)) { r = ERROR_UNSUPPORTED_TYPE; goto out; }
    } else if (!(rrf_bit(type) & flags)) { r = ERROR_UNSUPPORTED_TYPE; goto out; }
    if (type == REG_DWORD && asz != 4) { r = ERROR_DATATYPE_MISMATCH; goto out; }
    if (type == 11 && asz != 8) { r = ERROR_DATATYPE_MISMATCH; goto out; }
    out = a; outsz = asz;
    if (is_str(type)) {
        /* make sure the ANSI data ends with the terminator(s) the type needs, then convert */
        DWORD alen = asz;
        while (alen && !a[alen - 1]) alen--;
        a[alen] = 0; a[alen + 1] = 0;
        alen += (type == REG_MULTI_SZ) ? 2 : 1;
        if (wide) {
            int n = MultiByteToWideChar(CP_ACP, 0, (char *)a, (int)alen, NULL, 0);
            if (!(w = HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR)))) { r = ERROR_NOT_ENOUGH_MEMORY; goto out; }
            MultiByteToWideChar(CP_ACP, 0, (char *)a, (int)alen, w, n);
            out = (BYTE *)w; outsz = n * sizeof(WCHAR);
        } else outsz = alen;
    }
    need = outsz;
    if (ptype) *ptype = type;
    if (pcb) *pcb = need;
    if (data) {
        if (cap < need) { r = ERROR_MORE_DATA; goto out; }
        memcpy(data, out, need);
    }
    r = ERROR_SUCCESS;
out:
    if (k != key) RegCloseKey(k);
fail:
    if (r != ERROR_SUCCESS && r != ERROR_MORE_DATA && (flags & RRF_ZEROONFAILURE) && data && cap) memset(data, 0, cap);
    hfree(a); hfree(w);
    return r;
}

LONG KEXAPI kex_RegGetValueA(HKEY key, LPCSTR sub, LPCSTR val, DWORD flags, LPDWORD type, PVOID data, LPDWORD cb)
{
    return reg_get(key, sub, val, flags, type, data, cb, FALSE);
}
LONG KEXAPI kex_RegGetValueW(HKEY key, LPCWSTR sub, LPCWSTR val, DWORD flags, LPDWORD type, PVOID data, LPDWORD cb)
{
    char *s = w2a_heap(sub), *v = w2a_heap(val); LONG r;
    if ((sub && !s) || (val && !v)) r = ERROR_NOT_ENOUGH_MEMORY;
    else r = reg_get(key, s, v, flags, type, data, cb, TRUE);
    hfree(s); hfree(v); return r;
}

/* ============================================== CRYPT32 =============================================== */
/* CryptProtectMemory: in-place, symmetric. SAME_PROCESS uses a per-process random key; CROSS_PROCESS /
 * SAME_LOGON use a key derived from this machine (9x has one user session). This is obfuscation of
 * memory contents, as on NT; it is not a protection boundary on 9x. */
static DWORD g_cpm_key[8]; static DWORD g_cpm_pid;
static void cpm_xor(BYTE *p, DWORD n, DWORD flags)
{
    DWORD st[16], blk[16], i, j;
    if (flags == 0 && g_cpm_pid != GetCurrentProcessId()) { kex_KexGenRandom(g_cpm_key, sizeof(g_cpm_key)); g_cpm_pid = GetCurrentProcessId(); }
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (i = 0; i < 8; i++) st[4 + i] = flags == 0 ? g_cpm_key[i] : 0x4B584D50UL * (i + 1);
    if (flags != 0) {
        DWORD serial = 0; GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
        st[4] ^= serial; st[5] ^= flags;
    }
    st[12] = 0; st[13] = 0; st[14] = 0x43505254; st[15] = flags;
    for (i = 0; i < n; i += 64, st[12]++) {
        chacha_block(st, blk);
        for (j = 0; j < 64 && i + j < n; j++) p[i + j] ^= ((BYTE *)blk)[j];
    }
}
BOOL KEXAPI kex_CryptProtectMemory(LPVOID p, DWORD n, DWORD flags)
{
    if (!p || (n & 15) || flags > 2) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    cpm_xor(p, n, flags); return TRUE;
}
BOOL KEXAPI kex_CryptUnprotectMemory(LPVOID p, DWORD n, DWORD flags) { return kex_CryptProtectMemory(p, n, flags); }

BOOL KEXAPI kex_CryptVerifyCertificateSignatureEx(ULONG_PTR prov, DWORD enc, DWORD stype, void *subj,
                                                  DWORD itype, void *issuer, DWORD flags, void *extra)
{
    SetLastError(0x80090006 /*NTE_BAD_SIGNATURE*/); return FALSE;
}

/* =============================================== OLE32 ================================================ */
HRESULT KEXAPI kex_CoRegisterInitializeSpy(void *spy, ULARGE_INTEGER *cookie)
{
    static volatile LONG next;
    if (!spy || !cookie) return HR_INVALIDARG;
    cookie->QuadPart = (ULONGLONG)InterlockedIncrement((LONG *)&next);   /* spies are never called */
    return S_OK;
}
HRESULT KEXAPI kex_CoRevokeInitializeSpy(ULARGE_INTEGER cookie) { return S_OK; }
HRESULT KEXAPI kex_CoAllowSetForegroundWindow(void *unk, void *res) { return S_OK; }
/* GUIDs. Win98's CoCreateGuid / UuidCreate build time+MAC UUIDs from the network card through NetBIOS; with no
 * card (most VMs) UuidCreate returns RPC_S_UUID_NO_ADDRESS and CoCreateGuid fails - Mypal's null principal
 * (caps/nsNullPrincipalURI.cpp, CoCreateGuid) then aborted the browser (2026-11-01). Windows 2000+ make random
 * version-4 UUIDs; so do these, from KexGenRandom. */
static void random_uuid(BYTE *g)
{
    kex_KexGenRandom(g, 16);
    g[7] = (BYTE)((g[7] & 0x0F) | 0x40);        /* Data3 high nibble (little-endian WORD at 6..7): version 4 */
    g[8] = (BYTE)((g[8] & 0x3F) | 0x80);        /* Data4[0]: RFC 4122 variant */
}
HRESULT KEXAPI kex_CoCreateGuid(GUID *g)
{
    if (!g) return E_INVALIDARG;
    random_uuid((BYTE *)g);
    return S_OK;
}
LONG KEXAPI kex_UuidCreate(GUID *g)
{
    if (!g) return 1783;                         /* RPC_S_INVALID_ARG... (callers never pass NULL) */
    random_uuid((BYTE *)g);
    return 0;                                    /* RPC_S_OK */
}

HRESULT KEXAPI kex_CoGetApartmentType(int *type, int *qual)
{
    /* build 131: found out with CoInitializeEx(MULTITHREADED), undone at once. Firefox 115 MOZ_CRASHes when this
     * fails (mscom apartment assertion, XUL.DLL+245af99). A thread without COM gets what Windows reports when the
     * process has an MTA: MTA, APTTYPEQUALIFIER_IMPLICIT_MTA. */
    typedef HRESULT (WINAPI *T_CIE)(LPVOID, DWORD); typedef void (WINAPI *T_CU)(void);
    static T_CIE cie; static T_CU cu; HRESULT h;
    if (!type || !qual) return HR_INVALIDARG;
    if (!cie) { cu = (T_CU)(void *)kex_sysproc("OLE32.DLL", "CoUninitialize"); cie = (T_CIE)(void *)kex_sysproc("OLE32.DLL", "CoInitializeEx"); }
    *type = 1; *qual = 0;
    if (!cie || !cu) { *qual = 1; return S_OK; }
    h = cie(NULL, 0 /* COINIT_MULTITHREADED */);
    if (h == (HRESULT)0x80010106L) { *type = 0; return S_OK; }   /* RPC_E_CHANGED_MODE: a single-threaded apartment */
    if (h == S_OK) *qual = 1;                                    /* COM was not initialized on this thread */
    if (SUCCEEDED(h)) cu();
    return S_OK;
}
HRESULT KEXAPI kex_RoGetAgileReference(int opts, REFIID riid, void *unk, void **out)
{
    if (out) *out = NULL;
    return HR_NOTIMPL;
}

/* ============================================== SHELL32 =============================================== */
static const struct { GUID id; int csidl; int fallback; const char *sub; } g_kf[] = {
    { {0x3EB685DB,0x65F9,0x4CF6,{0xA0,0x3A,0xE3,0xEF,0x65,0x72,0x9F,0x3D}}, 0x1A, -1, NULL },      /* RoamingAppData */
    { {0xF1B32785,0x6FBA,0x4FCF,{0x9D,0x55,0x7B,0x8E,0x7F,0x15,0x70,0x91}}, 0x1C, 0x1A, NULL },    /* LocalAppData */
    { {0xA520A1A4,0x1780,0x4FF6,{0xBD,0x18,0x16,0x73,0x43,0xC5,0xAF,0x16}}, 0x1C, 0x1A, NULL },    /* LocalAppDataLow */
    { {0x62AB5D82,0xFDC1,0x4DC3,{0xA9,0xDD,0x07,0x0D,0x1D,0x49,0x5D,0x97}}, 0x23, 0x1A, NULL },    /* ProgramData */
    { {0xB4BFCC3A,0xDB2C,0x424C,{0xB0,0x29,0x7F,0xE9,0x9A,0x87,0xC6,0x41}}, 0x10, -1, NULL },      /* Desktop */
    { {0xFDD39AD0,0x238F,0x46AF,{0xAD,0xB4,0x6C,0x85,0x48,0x03,0x69,0xC7}}, 0x05, -1, NULL },      /* Documents */
    { {0x374DE290,0x123F,0x4565,{0x91,0x64,0x39,0xC4,0x92,0x5E,0x46,0x7B}}, 0x05, -1, "Downloads" },/* Downloads */
    { {0x33E28130,0x4E1E,0x4676,{0x83,0x5A,0x98,0x39,0x5C,0x3B,0xC3,0xBB}}, 0x27, 0x05, NULL },    /* Pictures */
    { {0x4BD8D571,0x6D19,0x48D3,{0xBE,0x97,0x42,0x22,0x20,0x08,0x0E,0x43}}, 0x0D, 0x05, NULL },    /* Music */
    { {0x18989B1D,0x99B5,0x455B,{0x84,0x1C,0xAB,0x7C,0x74,0xE4,0xDD,0xFC}}, 0x0E, 0x05, NULL },    /* Videos */
    { {0x1777F761,0x68AD,0x4D8A,{0x87,0xBD,0x30,0xB7,0x59,0xFA,0x33,0xDD}}, 0x06, -1, NULL },      /* Favorites */
    { {0xFD228CB7,0xAE11,0x4AE3,{0x86,0x4C,0x16,0xF3,0x91,0x0A,0xB8,0xFE}}, 0x14, -1, NULL },      /* Fonts */
    { {0xA77F5D77,0x2E2B,0x44C3,{0xA6,0xA2,0xAB,0xA6,0x01,0x05,0x4A,0x51}}, 0x02, -1, NULL },      /* Programs */
    { {0x625B53C3,0xAB48,0x4EC1,{0xBA,0x1F,0xA1,0xEF,0x41,0x46,0xFC,0x19}}, 0x0B, -1, NULL },      /* StartMenu */
    { {0xB97D20BB,0xF46A,0x4C97,{0xBA,0x10,0x5E,0x36,0x08,0x43,0x08,0x54}}, 0x07, -1, NULL },      /* Startup */
    { {0x0139D44E,0x6AFE,0x49F2,{0x86,0x90,0x3D,0xAF,0xCA,0xE6,0xFF,0xB8}}, 0x17, 0x02, NULL },    /* CommonPrograms */
    { {0xA4115719,0xD62E,0x491D,{0xAA,0x7C,0xE7,0x4B,0x8B,0xE3,0xB0,0x67}}, 0x16, 0x0B, NULL },    /* CommonStartMenu */
    { {0xC4AA340D,0xF20F,0x4863,{0xAF,0xEF,0xF8,0x7E,0xF2,0xE6,0xBA,0x25}}, 0x19, 0x10, NULL },    /* PublicDesktop */
    { {0x352481E8,0x33BE,0x4251,{0xBA,0x85,0x60,0x07,0xCA,0xED,0xCF,0x9D}}, 0x20, -1, NULL },      /* InternetCache */
    { {0x2B0F765D,0xC0E9,0x4171,{0x90,0x8E,0x08,0xA6,0x11,0xB8,0x4F,0xF6}}, 0x21, -1, NULL },      /* Cookies */
    { {0xD9DC8A3B,0xB784,0x432E,{0xA7,0x81,0x5A,0x11,0x30,0xA7,0x59,0x63}}, 0x22, -1, NULL },      /* History */
    { {0xA63293E8,0x664E,0x48DB,{0xA0,0x79,0xDF,0x75,0x9E,0x05,0x09,0xF7}}, 0x15, -1, NULL },      /* Templates */
    { {0x8983036C,0x27C0,0x404B,{0x8F,0x08,0x10,0x2D,0x10,0xDC,0xFD,0x74}}, 0x09, -1, NULL },      /* SendTo */
    { {0xAE50C081,0xEBD2,0x438A,{0x86,0x55,0x8A,0x09,0x2E,0x34,0x98,0x7A}}, 0x08, -1, NULL },      /* Recent */
    { {0x52A4F021,0x7B75,0x48A9,{0x9F,0x6B,0x4B,0x87,0xA2,0x10,0xBC,0x8F}}, 0x1A, -1, "Microsoft\\Internet Explorer\\Quick Launch" },
    { {0x905E63B6,0xC1BF,0x494E,{0xB2,0x9C,0x65,0xB7,0x32,0xD3,0xD2,0x1A}}, 0x26, -2, NULL },      /* ProgramFiles */
    { {0x7C5A40EF,0xA0FB,0x4BFC,{0x87,0x4A,0xC0,0xF2,0xE0,0xB9,0xFA,0x8E}}, 0x26, -2, NULL },      /* ProgramFilesX86 */
    { {0x6D809377,0x6AF0,0x444B,{0x89,0x57,0xA3,0x77,0x3F,0x02,0x20,0x0E}}, 0x26, -2, NULL },      /* ProgramFilesX64 */
    { {0xF7F1ED05,0x9F6D,0x47A2,{0xAA,0xAE,0x29,0xD3,0x17,0xC6,0xF0,0x66}}, -2, -2, "Common Files" },   /* ProgramFilesCommon */
    { {0xF38BF404,0x1D43,0x42F2,{0x93,0x05,0x67,0xDE,0x0B,0x28,0xFC,0x23}}, -3, -3, NULL },        /* Windows */
    { {0x1AC14E77,0x02E7,0x4E5D,{0xB7,0x44,0x2E,0xB1,0xAE,0x51,0x98,0xB7}}, -4, -4, NULL },        /* System */
    { {0xD65231B0,0xB2F1,0x4857,{0xA4,0xCE,0xA8,0xE7,0xC6,0xEA,0x7D,0x27}}, -4, -4, NULL },        /* SystemX86 */
    { {0x5E6C858F,0x0E22,0x4760,{0x9A,0xFE,0xEA,0x33,0x17,0xB6,0x71,0x73}}, -5, -5, NULL },        /* Profile */
};

typedef BOOL (WINAPI *SHSPECIAL)(HWND, LPSTR, int, BOOL);

static BOOL special_path(int csidl, char *out, BOOL create)
{
    SHSPECIAL f;
    if (csidl == -3) return GetWindowsDirectoryA(out, MAX_PATH) != 0;
    if (csidl == -4) return GetSystemDirectoryA(out, MAX_PATH) != 0;
    if (csidl == -5) {
        DWORD n = GetEnvironmentVariableA("USERPROFILE", out, MAX_PATH);
        return (n && n < MAX_PATH) || GetWindowsDirectoryA(out, MAX_PATH);
    }
    if (csidl == -2) {                                          /* Program Files from the registry */
        HKEY k; DWORD sz = MAX_PATH, t; BOOL ok = FALSE;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            ok = RegQueryValueExA(k, "ProgramFilesDir", NULL, &t, (BYTE *)out, &sz) == ERROR_SUCCESS;
            RegCloseKey(k);
        }
        if (!ok) { lstrcpyA(out, "C:\\Program Files"); ok = TRUE; }
        return ok;
    }
    f = (SHSPECIAL)kex_sysproc("SHELL32.DLL", "SHGetSpecialFolderPathA");
    if (!f) return FALSE;
    out[0] = 0;
    return f(NULL, out, csidl, create) && out[0];
}

HRESULT KEXAPI kex_SHGetKnownFolderPath(const GUID *id, DWORD flags, HANDLE token, PWSTR *path)
{
    char p[MAX_PATH + 64]; unsigned i; int n; PWSTR w; BOOL create = (flags & 0x8000) != 0;
    if (!path) return HR_INVALIDARG;
    *path = NULL;
    if (!id) return HR_INVALIDARG;
    for (i = 0; i < sizeof(g_kf) / sizeof(g_kf[0]); i++)
        if (!memcmp(&g_kf[i].id, id, sizeof(GUID))) break;
    if (i == sizeof(g_kf) / sizeof(g_kf[0])) return HR_W32(ERROR_FILE_NOT_FOUND);
    if (!special_path(g_kf[i].csidl, p, create)) {
        if (g_kf[i].fallback == -1 || !special_path(g_kf[i].fallback, p, create)) {
            /* last resort for application data: <Windows>\Application Data */
            if (g_kf[i].csidl != 0x1A && g_kf[i].fallback != 0x1A) return HR_W32(ERROR_FILE_NOT_FOUND);
            GetWindowsDirectoryA(p, MAX_PATH); lstrcatA(p, "\\Application Data");
            if (create) CreateDirectoryA(p, NULL);
        }
    }
    if (g_kf[i].sub) {
        if (lstrlenA(p) + lstrlenA(g_kf[i].sub) + 2 > (int)sizeof(p)) return HR_W32(ERROR_FILENAME_EXCED_RANGE);
        lstrcatA(p, "\\"); lstrcatA(p, g_kf[i].sub);
        if (create) CreateDirectoryA(p, NULL);
    }
    n = lstrlenA(p);
    if (n > 3 && p[n - 1] == '\\') p[--n] = 0;
    if (!(w = co_alloc((n + 1) * sizeof(WCHAR)))) return HR_OUTOFMEMORY;
    MultiByteToWideChar(CP_ACP, 0, p, -1, w, n + 1);
    *path = w;
    return S_OK;
}

/* build 131: Windows 98's SHELL32/SHFOLDER do not know the Windows 2000+ folder ids for Program Files:
 * CSIDL_PROGRAM_FILES (0x26) is refused by SHELL32 (E_INVALIDARG), CSIDL_PROGRAM_FILESX86 (0x2A) and
 * CSIDL_PROGRAM_FILES_COMMONX86 (0x2C) also by SHFOLDER. On 32-bit Windows the X86 ids mean the same folders.
 * Firefox 115's NSIS setup takes $PROGRAMFILES32 from CSIDL 0x2A (registry fallback "ProgramFilesDir (x86)",
 * absent on 98) and offered "\Mozilla Firefox\" as the install folder. */
static int pf_path(int csidl, char *out)
{
    int c = csidl & 0xFF;
    if (c == 0x26 || c == 0x2A) return special_path(-2, out, FALSE);
    if (c == 0x2B || c == 0x2C) {
        HKEY k; DWORD sz = MAX_PATH, t; BOOL ok = FALSE;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0, KEY_READ, &k) == ERROR_SUCCESS) {
            ok = RegQueryValueExA(k, "CommonFilesDir", NULL, &t, (BYTE *)out, &sz) == ERROR_SUCCESS && out[0];
            RegCloseKey(k);
        }
        if (!ok) { special_path(-2, out, FALSE); if (lstrlenA(out) + 14 < MAX_PATH) lstrcatA(out, "\\Common Files"); }
        return 1;
    }
    if (c == 0x29) return GetSystemDirectoryA(out, MAX_PATH) != 0;      /* CSIDL_SYSTEMX86 */
    return 0;
}
typedef HRESULT (WINAPI *T_SGFPW)(HWND, int, HANDLE, DWORD, LPWSTR);
typedef HRESULT (WINAPI *T_SGFPA)(HWND, int, HANDLE, DWORD, LPSTR);
typedef BOOL (WINAPI *T_SGSPW)(HWND, LPWSTR, int, BOOL);
HRESULT KEXAPI kex_SHGetFolderPathW(HWND w, int csidl, HANDLE tok, DWORD flags, LPWSTR path)
{
    char p[MAX_PATH]; static T_SGFPW f;
    if (pf_path(csidl, p)) {
        if (!path) return HR_INVALIDARG;
        if ((csidl & 0x8000) && GetFileAttributesA(p) == 0xFFFFFFFF) CreateDirectoryA(p, NULL);
        MultiByteToWideChar(CP_ACP, 0, p, -1, path, MAX_PATH);
        return S_OK;
    }
    if (!f) f = (T_SGFPW)(void *)kex_sysproc("SHELL32.DLL", "SHGetFolderPathW");
    if (!f) f = (T_SGFPW)(void *)kex_sysproc("SHFOLDER.DLL", "SHGetFolderPathW");
    return f ? f(w, csidl, tok, flags, path) : HR_NOTIMPL;
}
HRESULT KEXAPI kex_SHGetFolderPathA(HWND w, int csidl, HANDLE tok, DWORD flags, LPSTR path)
{
    static T_SGFPA f;
    if (path && pf_path(csidl, path)) {
        if ((csidl & 0x8000) && GetFileAttributesA(path) == 0xFFFFFFFF) CreateDirectoryA(path, NULL);
        return S_OK;
    }
    if (!f) f = (T_SGFPA)(void *)kex_sysproc("SHELL32.DLL", "SHGetFolderPathA");
    if (!f) f = (T_SGFPA)(void *)kex_sysproc("SHFOLDER.DLL", "SHGetFolderPathA");
    return f ? f(w, csidl, tok, flags, path) : HR_NOTIMPL;
}
BOOL KEXAPI kex_SHGetSpecialFolderPathW(HWND w, LPWSTR path, int csidl, BOOL create)
{
    char p[MAX_PATH]; static T_SGSPW f;
    if (path && pf_path(csidl, p)) {
        if (create && GetFileAttributesA(p) == 0xFFFFFFFF) CreateDirectoryA(p, NULL);
        MultiByteToWideChar(CP_ACP, 0, p, -1, path, MAX_PATH);
        return TRUE;
    }
    if (!f) f = (T_SGSPW)(void *)kex_sysproc("SHELL32.DLL", "SHGetSpecialFolderPathW");
    return f ? f(w, path, csidl, create) : FALSE;
}
BOOL KEXAPI kex_SHGetSpecialFolderPathA(HWND w, LPSTR path, int csidl, BOOL create)
{
    SHSPECIAL f = (SHSPECIAL)kex_sysproc("SHELL32.DLL", "SHGetSpecialFolderPathA");
    if (path && pf_path(csidl, path)) {
        if (create && GetFileAttributesA(path) == 0xFFFFFFFF) CreateDirectoryA(path, NULL);
        return TRUE;
    }
    return f ? f(w, path, csidl, create) : FALSE;
}

HRESULT KEXAPI kex_SHCreateAssociationRegistration(REFIID riid, void **out) { if (out) *out = NULL; return HR_NOTIMPL; }
HRESULT KEXAPI kex_SHGetPropertyStoreForWindow(HWND h, REFIID riid, void **out) { if (out) *out = NULL; return HR_NOTIMPL; }
HRESULT KEXAPI kex_SHGetStockIconInfo(int id, UINT flags, void *info) { return HR_NOTIMPL; }
HRESULT KEXAPI kex_SHOpenWithDialog(HWND h, const void *info) { return HR_NOTIMPL; }
HRESULT KEXAPI kex_SHQueryUserNotificationState(int *state) { if (!state) return HR_INVALIDARG; *state = 5; /* QUNS_ACCEPTS_NOTIFICATIONS */ return S_OK; }
HRESULT KEXAPI kex_SetCurrentProcessExplicitAppUserModelID(PCWSTR id) { return S_OK; }
HRESULT KEXAPI kex_GetCurrentProcessExplicitAppUserModelID(PWSTR *id) { if (id) *id = NULL; return HR_FAIL; }

/* =============================================== WS2_32 =============================================== */
#define K_AF_INET 2
#define K_AF_INET6 23
#define K_WSAEAFNOSUPPORT 10047
#define K_WSAEINVAL 10022
#define K_WSAEOPNOTSUPP 10045
#define K_ENOSPC 28

typedef void (WINAPI *WSASETERR)(int);
static void wsa_err(int e)
{
    WSASETERR f = (WSASETERR)kex_sysproc("WS2_32.DLL", "WSASetLastError");
    if (f) f(e); else SetLastError(e);
}


/* kexnt may not import USER32 (no wsprintf): tiny number formatters */
static int kx_utoa(char *s, unsigned long v, unsigned base)
{
    char t[12]; int n = 0, i;
    do { unsigned d = (unsigned)(v % base); t[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); v /= base; } while (v);
    for (i = 0; i < n; i++) s[i] = t[n - 1 - i];
    s[n] = 0; return n;
}

static int fmt_ntop(int af, const BYTE *a, char *s)
{
    if (af == K_AF_INET) {
        int i, n = 0;
        for (i = 0; i < 4; i++) { n += kx_utoa(s + n, a[i], 10); if (i < 3) s[n++] = '.'; }
        s[n] = 0; return n;
    }
    if (af == K_AF_INET6) {
        WORD w[8]; int i, best = -1, bestlen = 0, cur = -1, curlen = 0; char *p = s;
        for (i = 0; i < 8; i++) w[i] = (WORD)((a[2 * i] << 8) | a[2 * i + 1]);
        for (i = 0; i < 8; i++) {                                 /* longest run of zero words (>= 2) */
            if (!w[i]) { if (cur < 0) { cur = i; curlen = 1; } else curlen++;
                         if (curlen > bestlen) { best = cur; bestlen = curlen; } }
            else cur = -1;
        }
        if (bestlen < 2) best = -1;
        for (i = 0; i < 8; i++) {
            if (i == best) { *p++ = ':'; if (i == 0) *p++ = ':'; i += bestlen - 1; continue; }
            if (i == 6 && best == 0 && (bestlen == 6 || (bestlen == 5 && w[5] == 0xFFFF))) {
                p += fmt_ntop(K_AF_INET, a + 12, p); break;              /* v4-mapped */
            }
            p += kx_utoa(p, w[i], 16);
            if (i < 7) *p++ = ':';
        }
        *p = 0;
        return (int)(p - s);
    }
    return -1;
}

PCSTR KEXAPI kex_inet_ntop(INT af, const void *addr, PSTR buf, SIZE_T size)
{
    char tmp[64]; int n;
    if (!addr || !buf) { wsa_err(K_WSAEINVAL); return NULL; }
    if ((n = fmt_ntop(af, addr, tmp)) < 0) { wsa_err(K_WSAEAFNOSUPPORT); return NULL; }
    if ((SIZE_T)n + 1 > size) { wsa_err(K_WSAEINVAL); SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    lstrcpyA(buf, tmp); return buf;
}

PCWSTR KEXAPI kex_InetNtopW(INT af, const void *addr, PWSTR buf, SIZE_T size)
{
    char tmp[64]; int n, i;
    if (!addr || !buf) { wsa_err(K_WSAEINVAL); return NULL; }
    if ((n = fmt_ntop(af, addr, tmp)) < 0) { wsa_err(K_WSAEAFNOSUPPORT); return NULL; }
    if ((SIZE_T)n + 1 > size) { wsa_err(K_WSAEINVAL); return NULL; }
    for (i = 0; i <= n; i++) buf[i] = (WCHAR)tmp[i];
    return buf;
}

static int hexv(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static int pton4(const char *s, BYTE *out)
{
    int i; for (i = 0; i < 4; i++) {
        int v = 0, d = 0;
        while (*s >= '0' && *s <= '9') { v = v * 10 + (*s++ - '0'); if (++d > 3 || v > 255) return 0; }
        if (!d) return 0;
        out[i] = (BYTE)v;
        if (i < 3) { if (*s++ != '.') return 0; }
    }
    return *s == 0;
}
static int pton6(const char *s, BYTE *out)
{
    WORD w[8]; int n = 0, gap = -1, i;
    if (s[0] == ':') { if (s[1] != ':') return 0; s += 2; gap = 0; if (!*s) goto done; }
    for (;;) {
        int v = 0, d = 0; const char *start = s;
        while (hexv(*s) >= 0) { v = v * 16 + hexv(*s++); if (++d > 4) return 0; }
        if (*s == '.' && n <= 6) {                              /* trailing dotted IPv4 */
            BYTE v4[4]; if (!pton4(start, v4)) return 0;
            w[n++] = (WORD)(v4[0] << 8 | v4[1]); w[n++] = (WORD)(v4[2] << 8 | v4[3]); break;
        }
        if (!d) return 0;
        if (n == 8) return 0;
        w[n++] = (WORD)v;
        if (!*s) break;
        if (*s++ != ':') return 0;
        if (*s == ':') { if (gap >= 0) return 0; gap = n; s++; if (!*s) break; }
    }
done:
    if (gap < 0 ? n != 8 : n > 7) return 0;
    memset(out, 0, 16);
    if (gap < 0) gap = n;
    for (i = 0; i < gap; i++) { out[2 * i] = (BYTE)(w[i] >> 8); out[2 * i + 1] = (BYTE)w[i]; }
    for (i = gap; i < n; i++) { int j = 8 - (n - i); out[2 * j] = (BYTE)(w[i] >> 8); out[2 * j + 1] = (BYTE)w[i]; }
    return 1;
}

INT KEXAPI kex_inet_pton(INT af, PCSTR s, PVOID out)
{
    if (!s || !out) { wsa_err(K_WSAEINVAL); return -1; }
    if (af == K_AF_INET) return pton4(s, out);
    if (af == K_AF_INET6) return pton6(s, out);
    wsa_err(K_WSAEAFNOSUPPORT); return -1;
}
INT KEXAPI kex_InetPtonW(INT af, PCWSTR s, PVOID out)
{
    char a[64]; int i;
    if (!s || !out) { wsa_err(K_WSAEINVAL); return -1; }
    for (i = 0; i < 63 && s[i]; i++) { if (s[i] > 127) return 0; a[i] = (char)s[i]; }
    if (s[i]) return 0;
    a[i] = 0; return kex_inet_pton(af, a, out);
}

/* GetAddrInfoExW (asynchronous resolver, Win8+): not available; callers fall back to getaddrinfo. */
INT KEXAPI kex_GetAddrInfoExW(PCWSTR name, PCWSTR svc, DWORD ns, LPGUID nsid, const void *hints, void **result,
                              void *timeout, LPOVERLAPPED ov, PVOID done, LPHANDLE cancel)
{
    if (result) *result = NULL;
    if (cancel) *cancel = NULL;
    wsa_err(K_WSAEOPNOTSUPP); return K_WSAEOPNOTSUPP;
}
INT KEXAPI kex_GetAddrInfoExA(PCSTR name, PCSTR svc, DWORD ns, LPGUID nsid, const void *hints, void **result,
                              void *timeout, LPOVERLAPPED ov, PVOID done, LPHANDLE cancel)
{
    return kex_GetAddrInfoExW(NULL, NULL, ns, nsid, hints, result, timeout, ov, done, cancel);
}
INT KEXAPI kex_GetAddrInfoExCancel(LPHANDLE h) { return 6 /* WSA_INVALID_HANDLE */; }
VOID KEXAPI kex_FreeAddrInfoExW(void *p) { }
VOID KEXAPI kex_FreeAddrInfoEx(void *p) { }

/* ================================================= PDH ================================================ */
LONG KEXAPI kex_PdhAddEnglishCounterW(HANDLE q, LPCWSTR path, DWORD_PTR user, HANDLE *ctr) { if (ctr) *ctr = NULL; return (LONG)0xC0000BB8; /* PDH_CSTATUS_NO_OBJECT */ }
LONG KEXAPI kex_PdhAddEnglishCounterA(HANDLE q, LPCSTR path, DWORD_PTR user, HANDLE *ctr) { if (ctr) *ctr = NULL; return (LONG)0xC0000BB8; }

/* ============================================== USER32 ================================================ */
BOOL KEXAPI kex_SetProcessDPIAware(void) { return TRUE; }
BOOL KEXAPI kex_AddClipboardFormatListener(HWND h) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_RemoveClipboardFormatListener(HWND h) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_CloseTouchInputHandle(HANDLE h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
LONG KEXAPI kex_DisplayConfigGetDeviceInfo(void *hdr) { return ERROR_NOT_SUPPORTED; }
LONG KEXAPI kex_GetDisplayConfigBufferSizes(UINT32 flags, UINT32 *np, UINT32 *nm)
{
    if (np) *np = 0;
    if (nm) *nm = 0;
    return ERROR_NOT_SUPPORTED;
}
LONG KEXAPI kex_QueryDisplayConfig(UINT32 flags, UINT32 *np, void *paths, UINT32 *nm, void *modes, void *topo) { return ERROR_NOT_SUPPORTED; }
BOOL KEXAPI kex_GetLayeredWindowAttributes(HWND h, COLORREF *key, BYTE *alpha, DWORD *flags) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_GetPointerDevice(HANDLE dev, void *info) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_GetPointerDevices(UINT32 *count, void *devs) { if (count) *count = 0; return TRUE; }
BOOL KEXAPI kex_GetPointerPenInfo(UINT32 id, void *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_GetPointerType(UINT32 id, int *type) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_GetPointerInfo(UINT32 id, void *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_GetPointerTouchInfo(UINT32 id, void *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_GetPointerFrameInfo(UINT32 id, UINT32 *n, void *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
BOOL KEXAPI kex_RegisterPointerDeviceNotifications(HWND h, BOOL range) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_EnableMouseInPointer(BOOL e) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_IsMouseInPointerEnabled(void) { return FALSE; }
BOOL KEXAPI kex_GetWindowDisplayAffinity(HWND h, DWORD *a) { if (!a) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; } *a = 0; return TRUE; }
BOOL KEXAPI kex_SetWindowDisplayAffinity(HWND h, DWORD a) { if (a == 0) return TRUE; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_IsWindowArranged(HWND h) { return FALSE; }
HANDLE KEXAPI kex_RegisterPowerSettingNotification(HANDLE recipient, const GUID *g, DWORD flags) { return (HANDLE)(ULONG_PTR)0x4B500001; }
BOOL KEXAPI kex_UnregisterPowerSettingNotification(HANDLE h) { return TRUE; }
HANDLE KEXAPI kex_RegisterSuspendResumeNotification(HANDLE recipient, DWORD flags) { return (HANDLE)(ULONG_PTR)0x4B500002; }
BOOL KEXAPI kex_UnregisterSuspendResumeNotification(HANDLE h) { return TRUE; }

typedef HRGN (WINAPI *CRR)(int, int, int, int);
typedef int (WINAPI *GWR)(HWND, HRGN);
typedef int (WINAPI *GRB)(HRGN, LPRECT);
typedef BOOL (WINAPI *DOB)(HGDIOBJ);
int KEXAPI kex_GetWindowRgnBox(HWND h, LPRECT rc)
{
    CRR crr = (CRR)kex_sysproc("GDI32.DLL", "CreateRectRgn");
    GWR gwr = (GWR)kex_sysproc("USER32.DLL", "GetWindowRgn");
    GRB grb = (GRB)kex_sysproc("GDI32.DLL", "GetRgnBox");
    DOB dob = (DOB)kex_sysproc("GDI32.DLL", "DeleteObject");
    HRGN r; int t = 0 /* ERROR */;
    if (!rc || !crr || !gwr || !grb || !dob || !(r = crr(0, 0, 0, 0))) return 0;
    if (gwr(h, r) != 0) t = grb(r, rc);
    dob(r);
    return t;
}

/* ================================================ GDI32 =============================================== */
typedef BOOL (WINAPI *ALPHABLEND)(HDC, int, int, int, int, HDC, int, int, int, int, DWORD);
BOOL KEXAPI kex_GdiAlphaBlend(HDC d, int x, int y, int w, int h, HDC s, int sx, int sy, int sw, int sh, DWORD bf)
{
    ALPHABLEND f = (ALPHABLEND)kex_sysproc("MSIMG32.DLL", "AlphaBlend");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return f(d, x, y, w, h, s, sx, sy, sw, sh, bf);
}
typedef BOOL (WINAPI *GRADFILL)(HDC, void *, ULONG, void *, ULONG, ULONG);
BOOL KEXAPI kex_GdiGradientFill(HDC d, void *v, ULONG nv, void *m, ULONG nm, ULONG mode)
{
    GRADFILL f = (GRADFILL)kex_sysproc("MSIMG32.DLL", "GradientFill");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return f(d, v, nv, m, nm, mode);
}
typedef BOOL (WINAPI *TRANSBLT)(HDC, int, int, int, int, HDC, int, int, int, int, UINT);
BOOL KEXAPI kex_GdiTransparentBlt(HDC d, int x, int y, int w, int h, HDC s, int sx, int sy, int sw, int sh, UINT c)
{
    TRANSBLT f = (TRANSBLT)kex_sysproc("MSIMG32.DLL", "TransparentBlt");
    if (!f) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
    return f(d, x, y, w, h, s, sx, sy, sw, sh, c);
}

/* =============================================== IPHLPAPI ============================================= */
/* GetAdaptersAddresses, if_indextoname, if_nametoindex: net_ext.c (build 128) */
VOID KEXAPI kex_FreeMibTable(PVOID p) { }
DWORD KEXAPI kex_GetIfTable2(PVOID *t) { if (t) *t = NULL; return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_GetIfTable2Ex(int level, PVOID *t) { if (t) *t = NULL; return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_GetIfEntry2(PVOID row) { return ERROR_NOT_SUPPORTED; }
BOOL KEXAPI kex_CancelIPChangeNotify(LPOVERLAPPED ov) { SetLastError(ERROR_NOT_FOUND); return FALSE; }
DWORD KEXAPI kex_NotifyIpInterfaceChange(USHORT fam, PVOID cb, PVOID ctx, BOOLEAN init, HANDLE *h) { if (h) *h = NULL; return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_CancelMibChangeNotify2(HANDLE h) { return ERROR_SUCCESS; }

/* =============================================== SHELL32 ============================================== */
/* SHParseDisplayName (XP+): parse a path or shell name into an absolute PIDL through the desktop folder's
 * IShellFolder::ParseDisplayName (Windows 98's shell has that, with a wide-character name). */
typedef HRESULT (WINAPI *SHGETDESK)(IShellFolder **);
HRESULT KEXAPI kex_SHParseDisplayName(PCWSTR name, IBindCtx *bc, LPITEMIDLIST *pidl, ULONG sfgaoIn, ULONG *sfgaoOut)
{
    SHGETDESK gd = (SHGETDESK)kex_sysproc("SHELL32.DLL", "SHGetDesktopFolder");
    IShellFolder *desk = NULL; ULONG attrs = sfgaoIn, eaten = 0; HRESULT hr;
    if (pidl) *pidl = NULL;
    if (sfgaoOut) *sfgaoOut = 0;
    if (!name || !pidl) return HR_INVALIDARG;
    if (!gd) return HR_NOTIMPL;
    if (FAILED(hr = gd(&desk)) || !desk) return FAILED(hr) ? hr : HR_FAIL;
    hr = desk->lpVtbl->ParseDisplayName(desk, NULL, bc, (LPWSTR)name, &eaten, pidl, sfgaoOut ? &attrs : NULL);
    desk->lpVtbl->Release(desk);
    if (SUCCEEDED(hr) && sfgaoOut) *sfgaoOut = attrs & sfgaoIn;
    return hr;
}

/* SHOpenFolderAndSelectItems (XP+): Chrome's "Show in folder" for a download. KernelEx 4.5 only had a stub that
 * fails, so nothing opened (build 74 user report). Windows 98's Explorer knows "explorer /select,<file>" (opens the
 * folder with the file highlighted); without a usable item we open the folder itself. Chromium passes the folder
 * PIDL and the file's PIDL(s) from SHParseDisplayName (absolute). */
typedef BOOL (WINAPI *SHGPFIDL)(LPCITEMIDLIST, LPSTR);
void kex_crashlog_text(const char *s);
HRESULT KEXAPI kex_SHOpenFolderAndSelectItems(LPCITEMIDLIST folder, UINT n, LPCITEMIDLIST *items, DWORD flags)
{
    SHGPFIDL gp = (SHGPFIDL)kex_sysproc("SHELL32.DLL", "SHGetPathFromIDListA");
    char path[MAX_PATH], cmd[MAX_PATH + 40], l[MAX_PATH + 80]; UINT r;
    if (!gp) return HR_NOTIMPL;
    path[0] = 0;
    if (n && items && items[0] && gp(items[0], path) && path[0] && GetFileAttributesA(path) != 0xFFFFFFFF) {
        lstrcpyA(cmd, "explorer.exe /select,\""); lstrcatA(cmd, path); lstrcatA(cmd, "\"");
    } else {
        path[0] = 0;
        if (!folder || !gp(folder, path) || !path[0]) return HR_INVALIDARG;
        lstrcpyA(cmd, "explorer.exe \""); lstrcatA(cmd, path); lstrcatA(cmd, "\"");
    }
    r = WinExec(cmd, SW_SHOWNORMAL);
    lstrcpyA(l, r > 31 ? "--- show in folder: " : "--- show in folder FAILED: "); lstrcatA(l, cmd);
    kex_crashlog_text(l);
    return r > 31 ? S_OK : HR_FAIL;
}

/* build 79: CertControlStore - Windows 98's CRYPT32 answers ERROR_CALL_NOT_IMPLEMENTED (0x78) for
 * CERT_STORE_CTRL_AUTO_RESYNC (4) / CERT_STORE_CTRL_CANCEL_NOTIFY (5). Chromium (trust_store_win.cc:430) logs an
 * ERROR for each store it opens - 776 lines in 20 minutes, two per certificate check. Neither has anything to do
 * on Windows 98 (stores are read fresh when opened), so those two succeed; everything else is Windows' answer. */
typedef BOOL (WINAPI *CCS)(void *, DWORD, DWORD, const void *);
BOOL KEXAPI kex_CertControlStore(void *store, DWORD flags, DWORD ctrl, const void *para)
{
    CCS real = (CCS)kex_sysproc("CRYPT32.DLL", "CertControlStore");
    {   /* build 121: Discord's scripts failed with ERR_CERT_DATABASE_CHANGED (246 requests at two moments) - which
         * certificate-store controls does Chrome use, and what does Windows 98 answer? */
        static LONG k; void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
        if (InterlockedIncrement(&k) <= 12) {
            BOOL r = real ? real(store, flags, ctrl, para) : FALSE; DWORD le = GetLastError();
            kex_crashnote("CertControlStore (control, flags, Windows 98 ok, error)", ctrl, flags, (DWORD)r, r ? 0 : le);
            if (r) return TRUE;
            if (ctrl == 4 || ctrl == 5) { SetLastError(0); return TRUE; }
            SetLastError(real ? le : ERROR_CALL_NOT_IMPLEMENTED); return FALSE;
        }
    }
    if (real && real(store, flags, ctrl, para)) return TRUE;
    if (ctrl == 4 || ctrl == 5) { SetLastError(0); return TRUE; }
    if (!real) SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

/* =============================================== NETAPI32 ============================================= */
DWORD KEXAPI kex_NetGetJoinInformation(LPCWSTR server, LPWSTR *name, int *status)
{
    if (name) *name = NULL;
    if (status) *status = 0;                                      /* NetSetupUnknownStatus */
    return ERROR_NOT_SUPPORTED;
}
DWORD KEXAPI kex_NetApiBufferFree(PVOID p) { return 0; }        /* we never hand out buffers */
DWORD KEXAPI kex_DsRoleGetPrimaryDomainInformation(LPCWSTR server, int level, PBYTE *buf) { if (buf) *buf = NULL; return ERROR_NOT_SUPPORTED; }
VOID KEXAPI kex_DsRoleFreeMemory(PVOID p) { }
HRESULT KEXAPI kex_NetGetAadJoinInformation(LPCWSTR tenant, PVOID *info) { if (info) *info = NULL; return S_OK; }   /* not joined */
VOID KEXAPI kex_NetFreeAadJoinInformation(PVOID info) { }
DWORD KEXAPI kex_NetUserGetInfo(LPCWSTR server, LPCWSTR user, DWORD level, LPBYTE *buf) { if (buf) *buf = NULL; return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_NetWkstaGetInfo(LPWSTR server, DWORD level, LPBYTE *buf) { if (buf) *buf = NULL; return ERROR_NOT_SUPPORTED; }

/* =============================================== SECUR32 ============================================== */
#define K_SEC_NOPKG  ((LONG)0x80090305L)   /* SEC_E_SECPKG_NOT_FOUND */
#define K_SEC_BADH   ((LONG)0x80090301L)   /* SEC_E_INVALID_HANDLE */
LONG KEXAPI kex_AcquireCredentialsHandleW(LPWSTR p, LPWSTR pkg, ULONG use, PVOID luid, PVOID auth, PVOID fn, PVOID arg, PVOID cred, PVOID exp) { return K_SEC_NOPKG; }
LONG KEXAPI kex_InitializeSecurityContextW(PVOID cred, PVOID ctx, LPWSTR target, ULONG req, ULONG r1, ULONG rep, PVOID in, ULONG r2, PVOID newctx, PVOID out, PULONG attr, PVOID exp) { return K_SEC_BADH; }
LONG KEXAPI kex_QueryContextAttributesW(PVOID ctx, ULONG attr, PVOID buf) { return K_SEC_BADH; }
/* no Unicode SSPI on 9x: callers (Mozilla's NTLM/Negotiate auth) treat NULL as "SSPI unavailable" */
PVOID KEXAPI kex_InitSecurityInterfaceW(void) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
LONG KEXAPI kex_QuerySecurityPackageInfoW(LPWSTR pkg, PVOID *info) { if (info) *info = NULL; return K_SEC_NOPKG; }
BOOLEAN KEXAPI kex_GetUserNameExW(int fmt, LPWSTR name, PULONG size) { SetLastError(1332 /*ERROR_NONE_MAPPED*/); return FALSE; }
BOOLEAN KEXAPI kex_GetUserNameExA(int fmt, LPSTR name, PULONG size) { SetLastError(1332); return FALSE; }
NTSTATUS KEXAPI kex_LsaConnectUntrusted(PHANDLE h) { if (h) *h = NULL; return STATUS_NOT_IMPLEMENTED; }
NTSTATUS KEXAPI kex_LsaDeregisterLogonProcess(HANDLE h) { return STATUS_SUCCESS; }
NTSTATUS KEXAPI kex_LsaFreeReturnBuffer(PVOID p) { return STATUS_SUCCESS; }
NTSTATUS KEXAPI kex_LsaLogonUser(HANDLE h, PVOID origin, int type, ULONG pkg, PVOID auth, ULONG authlen, PVOID groups,
                                 PVOID src, PVOID *prof, PULONG proflen, PVOID luid, PHANDLE tok, PVOID quotas, NTSTATUS *sub)
{ return STATUS_NOT_IMPLEMENTED; }

/* =========================================== USERENV / SETUPAPI / CFGMGR32 / WINTRUST ================== */
HRESULT KEXAPI kex_DeriveAppContainerSidFromAppContainerName(PCWSTR name, PSID *sid) { if (sid) *sid = NULL; return HR_NOTIMPL; }
HANDLE KEXAPI kex_EnterCriticalPolicySection(BOOL machine) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
BOOL KEXAPI kex_LeaveCriticalPolicySection(HANDLE h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
BOOL KEXAPI kex_SetupDiGetDevicePropertyW(PVOID set, PVOID data, const void *key, PULONG type, PBYTE buf, DWORD size, PDWORD req, DWORD flags)
{ SetLastError(ERROR_NOT_FOUND); return FALSE; }
/* SETUPAPI on NT exports the CM_* functions (Mozilla's xul.dll imports CM_Get_Device_IDW from there);
 * Win98 has them in CFGMGR32 as ANSI: forward to CM_Get_Device_IDA and widen. */
typedef DWORD (WINAPI *CMGETIDA)(DWORD, PSTR, ULONG, ULONG);
DWORD KEXAPI kex_CM_Get_Device_IDW(DWORD dev, PWSTR buf, ULONG len, ULONG flags)
{
    char a[512]; DWORD cr;
    CMGETIDA f = (CMGETIDA)kex_sysproc("CFGMGR32.DLL", "CM_Get_Device_IDA");
    if (!buf || !len) return 0x03;                                   /* CR_INVALID_POINTER */
    if (!f) return 0x13;                                             /* CR_FAILURE */
    if ((cr = f(dev, a, sizeof(a), flags)) != 0) return cr;
    if (!MultiByteToWideChar(CP_ACP, 0, a, -1, buf, (int)len)) return 0x1A;   /* CR_BUFFER_SMALL */
    return 0;
}
DWORD KEXAPI kex_CM_Get_DevNode_PropertyW(DWORD dev, const void *key, PULONG type, PBYTE buf, PULONG size, ULONG flags) { return 0x25; /* CR_NO_SUCH_VALUE */ }
BOOL KEXAPI kex_CryptCATAdminAcquireContext(HANDLE *h, const GUID *sub, DWORD flags) { if (h) *h = NULL; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_CryptCATAdminAcquireContext2(HANDLE *h, const GUID *sub, PCWSTR alg, const void *pol, DWORD flags) { if (h) *h = NULL; SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_CryptCATAdminCalcHashFromFileHandle(HANDLE f, DWORD *n, BYTE *hash, DWORD flags) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
BOOL KEXAPI kex_CryptCATAdminCalcHashFromFileHandle2(HANDLE a, HANDLE f, DWORD *n, BYTE *hash, DWORD flags) { SetLastError(ERROR_NOT_SUPPORTED); return FALSE; }
HANDLE KEXAPI kex_CryptCATAdminEnumCatalogFromHash(HANDLE a, BYTE *hash, DWORD n, DWORD flags, HANDLE *prev) { SetLastError(ERROR_NOT_FOUND); return NULL; }
BOOL KEXAPI kex_CryptCATAdminReleaseCatalogContext(HANDLE a, HANDLE c, DWORD flags) { return TRUE; }
BOOL KEXAPI kex_CryptCATAdminReleaseContext(HANDLE a, DWORD flags) { return TRUE; }
BOOL KEXAPI kex_CryptCATCatalogInfoFromContext(HANDLE c, PVOID info, DWORD flags) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }

/* ================================================ WinRT ===============================================
 * HSTRING: our header {flags, length, refcount, buffer, reserved} fits the caller-provided
 * HSTRING_HEADER (5 pointers) used by fast-pass references. */
typedef struct { DWORD flags; UINT32 len; LONG ref; const WCHAR *buf; DWORD pad; } KHSTR;
#define HS_REF 1
static const WCHAR g_empty[1] = { 0 };

HRESULT KEXAPI kex_WindowsCreateString(const WCHAR *src, UINT32 len, KHSTR **out)
{
    KHSTR *h; WCHAR *b;
    if (!out) return HR_INVALIDARG;
    *out = NULL;
    if (!len) return S_OK;                                         /* NULL HSTRING == empty string */
    if (!src) return HR_INVALIDARG;
    if (len > 0x7FFFFFF0 / 2 || !(h = HeapAlloc(GetProcessHeap(), 0, sizeof(*h) + (len + 1) * sizeof(WCHAR)))) return HR_OUTOFMEMORY;
    b = (WCHAR *)(h + 1);
    memcpy(b, src, len * sizeof(WCHAR)); b[len] = 0;
    h->flags = 0; h->len = len; h->ref = 1; h->buf = b; h->pad = 0;
    *out = h; return S_OK;
}
HRESULT KEXAPI kex_WindowsCreateStringReference(const WCHAR *src, UINT32 len, KHSTR *hdr, KHSTR **out)
{
    if (!out || !hdr) return HR_INVALIDARG;
    *out = NULL;
    if (!len) return S_OK;
    if (!src || src[len] != 0) return HR_INVALIDARG;               /* must be NUL terminated at len */
    hdr->flags = HS_REF; hdr->len = len; hdr->ref = 0; hdr->buf = src; hdr->pad = 0;
    *out = hdr; return S_OK;
}
HRESULT KEXAPI kex_WindowsDeleteString(KHSTR *h)
{
    if (h && !(h->flags & HS_REF) && InterlockedDecrement(&h->ref) == 0) HeapFree(GetProcessHeap(), 0, h);
    return S_OK;
}
HRESULT KEXAPI kex_WindowsDuplicateString(KHSTR *h, KHSTR **out)
{
    if (!out) return HR_INVALIDARG;
    if (!h) { *out = NULL; return S_OK; }
    if (h->flags & HS_REF) return kex_WindowsCreateString(h->buf, h->len, out);
    InterlockedIncrement(&h->ref); *out = h; return S_OK;
}
PCWSTR KEXAPI kex_WindowsGetStringRawBuffer(KHSTR *h, UINT32 *len)
{
    if (len) *len = h ? h->len : 0;
    return h ? h->buf : g_empty;
}
UINT32 KEXAPI kex_WindowsGetStringLen(KHSTR *h) { return h ? h->len : 0; }
BOOL KEXAPI kex_WindowsIsStringEmpty(KHSTR *h) { return !h || !h->len; }
HRESULT KEXAPI kex_WindowsCompareStringOrdinal(KHSTR *a, KHSTR *b, INT32 *res)
{
    UINT32 la = a ? a->len : 0, lb = b ? b->len : 0, i, n = la < lb ? la : lb;
    if (!res) return HR_INVALIDARG;
    for (i = 0; i < n; i++) if (a->buf[i] != b->buf[i]) { *res = a->buf[i] < b->buf[i] ? -1 : 1; return S_OK; }
    *res = la == lb ? 0 : la < lb ? -1 : 1; return S_OK;
}

typedef HRESULT (WINAPI *COINITEX)(LPVOID, DWORD);
typedef HRESULT (WINAPI *K_COINITFN)(LPVOID);
typedef void (WINAPI *COUNINIT)(void);
HRESULT KEXAPI kex_RoInitialize(int type)
{
    COINITEX ex = (COINITEX)kex_sysproc("OLE32.DLL", "CoInitializeEx");
    K_COINITFN in = (K_COINITFN)kex_sysproc("OLE32.DLL", "CoInitialize");
    if (ex) return ex(NULL, type == 1 ? 0 /*COINIT_MULTITHREADED*/ : 2 /*APARTMENTTHREADED*/);
    return in ? in(NULL) : HR_NOTIMPL;
}
VOID KEXAPI kex_RoUninitialize(void)
{
    COUNINIT f = (COUNINIT)kex_sysproc("OLE32.DLL", "CoUninitialize");
    if (f) f();
}
HRESULT KEXAPI kex_RoActivateInstance(KHSTR *cls, void **out) { if (out) *out = NULL; return REGDB_CLASSNOTREG; }
HRESULT KEXAPI kex_RoGetActivationFactory(KHSTR *cls, REFIID iid, void **out) { if (out) *out = NULL; return REGDB_CLASSNOTREG; }
HRESULT KEXAPI kex_RoOriginateLanguageException(HRESULT e, KHSTR *msg, void *unk) { return FALSE; }
BOOL KEXAPI kex_RoOriginateErrorW(HRESULT e, UINT len, PCWSTR msg) { return FALSE; }

/* ============================================ shcore scaling ========================================== */
typedef HDC (WINAPI *GETDC)(HWND);
typedef int (WINAPI *RELDC)(HWND, HDC);
typedef int (WINAPI *GDC)(HDC, int);
/* build 81: the browser main thread died executing the stack (c000001d at 0160e2e4, EBP = KEXNT+19603 = the
 * return address into kex_GetDpiForMonitor): screen_dpi's stack came back one DWORD off from one of the GetDC /
 * GetDeviceCaps / ReleaseDC calls (Chromium's screen_win.cc calls GetDpiForMonitor for every window/monitor
 * update - thousands of times; it failed once after 5 minutes). Windows 98 cannot change the DPI without a
 * restart, so it is read once and kept: those calls happen once per process. */
static volatile LONG g_dpi;
static UINT screen_dpi_read(void);
static UINT screen_dpi(void)
{
    LONG d = g_dpi;
    if (d > 0) return (UINT)d;
    d = (LONG)screen_dpi_read();
    InterlockedExchange(&g_dpi, d);
    return (UINT)d;
}
static UINT screen_dpi_read(void)
{
    GETDC gdc = (GETDC)kex_sysproc("USER32.DLL", "GetDC");
    RELDC rdc = (RELDC)kex_sysproc("USER32.DLL", "ReleaseDC");
    GDC caps = (GDC)kex_sysproc("GDI32.DLL", "GetDeviceCaps");
    UINT dpi = 96; HDC dc;
    if (gdc && rdc && caps && (dc = gdc(NULL))) { int v = caps(dc, 88 /*LOGPIXELSX*/); if (v > 0) dpi = (UINT)v; rdc(NULL, dc); }
    return dpi;
}
HRESULT KEXAPI kex_GetDpiForMonitor(HANDLE mon, int type, UINT *x, UINT *y)
{
    UINT d;
    if (!x || !y || type < 0 || type > 2) return HR_INVALIDARG;
    d = screen_dpi(); *x = *y = d; return S_OK;
}
HRESULT KEXAPI kex_GetScaleFactorForMonitor(HANDLE mon, int *scale)
{
    UINT d, pct;
    if (!scale) return HR_INVALIDARG;
    d = screen_dpi(); pct = d * 100 / 96;
    *scale = pct >= 450 ? 500 : pct >= 375 ? 400 : pct >= 330 ? 350 : pct >= 290 ? 300 : pct >= 230 ? 250 :
             pct >= 190 ? 200 : pct >= 170 ? 180 : pct >= 155 ? 160 : pct >= 145 ? 150 : pct >= 130 ? 140 :
             pct >= 122 ? 125 : pct >= 110 ? 120 : 100;
    return S_OK;
}
HRESULT KEXAPI kex_SetProcessDpiAwareness(int v) { return (v < 0 || v > 2) ? HR_INVALIDARG : S_OK; }
HRESULT KEXAPI kex_GetProcessDpiAwareness(HANDLE p, int *v) { if (!v) return HR_INVALIDARG; *v = 0; return S_OK; }

/* ================================================ power =============================================== */
NTSTATUS KEXAPI kex_CallNtPowerInformation(int level, PVOID in, ULONG inlen, PVOID out, ULONG outlen) { return STATUS_NOT_IMPLEMENTED; }
DWORD KEXAPI kex_PowerDeterminePlatformRoleEx(ULONG ver) { return 1; /* PlatformRoleDesktop */ }
DWORD KEXAPI kex_PowerDeterminePlatformRole(void) { return 1; }
DWORD KEXAPI kex_PowerGetActiveScheme(HKEY root, GUID **scheme) { if (scheme) *scheme = NULL; return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_PowerReadACValue(HKEY root, const GUID *s, const GUID *sub, const GUID *set, PULONG type, LPBYTE buf, LPDWORD size) { return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_PowerReadDCValue(HKEY root, const GUID *s, const GUID *sub, const GUID *set, PULONG type, LPBYTE buf, LPDWORD size) { return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_PowerReadACValueIndex(HKEY root, const GUID *s, const GUID *sub, const GUID *set, LPDWORD idx) { return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_PowerReadDCValueIndex(HKEY root, const GUID *s, const GUID *sub, const GUID *set, LPDWORD idx) { return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_PowerRegisterSuspendResumeNotification(DWORD flags, HANDLE recipient, PVOID *reg) { if (reg) *reg = NULL; return ERROR_NOT_SUPPORTED; }
DWORD KEXAPI kex_PowerUnregisterSuspendResumeNotification(PVOID reg) { return ERROR_SUCCESS; }

/* QueryInterruptTime (api-ms-win-core-realtime-l1-1-1): 100 ns units since boot. */
BOOL KEXAPI kex_QueryUnbiasedInterruptTime(PULONGLONG t);
VOID KEXAPI kex_QueryInterruptTime(PULONGLONG t) { if (t) kex_QueryUnbiasedInterruptTime(t); }

/* ======================================== DHCPCSVC / CRYPTUI ========================================= */
DWORD KEXAPI kex_DhcpCApiInitialize(LPDWORD version) { if (version) *version = 2; return ERROR_NOT_SUPPORTED; }
VOID KEXAPI kex_DhcpCApiCleanup(void) { }
DWORD KEXAPI kex_DhcpRequestParams(DWORD flags, LPVOID res, LPWSTR adapter, LPVOID cid, LPVOID send, LPVOID recd,
                                   LPBYTE buf, LPDWORD size, LPWSTR tag, DWORD a, DWORD b)
{ return ERROR_NOT_SUPPORTED; }
BOOL KEXAPI kex_CryptUIDlgCertMgr(const void *info) { SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_CryptUIDlgViewCertificateW(const void *info, BOOL *changed) { if (changed) *changed = FALSE; SetLastError(ERROR_CALL_NOT_IMPLEMENTED); return FALSE; }
BOOL KEXAPI kex_RoOriginateError(HRESULT e, void *msg) { return FALSE; }   /* no error reporting service */

