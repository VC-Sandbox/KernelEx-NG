/*
 * kexver.c - KernelEx-NG version profiles (api library KEXVER.DLL).
 *
 * Works exactly like KernelEx's own version spoofing (apilibs/kexbases/Kernel32/version.c + CORE.INI):
 * the api table holds several implementations of the same name, and a configuration picks one by index:
 *     KERNEL32.GetVersionExA=kexver.4      ; -> the 5th GetVersionExA = Windows 8.1
 * Every profile index is the same for all functions, see PROFILES below and kexver_core.ini.
 *
 * Functions per profile:
 *   KERNEL32: GetVersion, GetVersionExA, GetVersionExW, VerifyVersionInfoA, VerifyVersionInfoW, GetProductInfo
 *   NTDLL:    RtlGetVersion, RtlVerifyVersionInfo, RtlGetNtVersionNumbers
 * The values are those of the real releases (RTM build of each version; Windows 11 / Server 2025 = 24H2 26100).
 * Build 132: profile 15 = Windows XP SP3 (5.1.2600 SP 3.0). KernelEx's own WINXP reports Service Pack 2, and the
 * .NET Framework 4.0 setup (SetupEngine, ParameterInfo.xml) then requires the Windows Imaging Component
 * ("WICNotFound_x86": TargetOS 5.1.0-5.1.2 and no windowscodecs.dll) -> exit 5100; with SP3 that rule does not apply.
 * Like KernelEx, the profile is reported to every caller: no Windows 8.1+ "manifest lie" (6.2).
 * Imports: KERNEL32 only (rule for api libraries, see kexnt_crt.c).
 */
#include "kexnt_common.h"

typedef struct {
    DWORD major, minor, build;
    WORD  sp_major, sp_minor;
    BYTE  product_type;              /* VER_NT_WORKSTATION 1 / VER_NT_SERVER 3 */
    WORD  suite;
    DWORD product_info;              /* GetProductInfo */
    const char *csd;
} kex_profile;

#define WS VER_NT_WORKSTATION
#define SV VER_NT_SERVER
#define SUITE_WS 0x0100                         /* VER_SUITE_SINGLEUSERTS */
#define SUITE_SV 0x0110                         /* VER_SUITE_SINGLEUSERTS | VER_SUITE_TERMINAL */
/* index:                major minor  build  SP          type suite     product (GetProductInfo)    CSD */
static const kex_profile PROFILES[] = {
    /*  0 WIN7       */ { 6, 1,  7601, 1, 0, WS, SUITE_WS, 0x00000030 /* PROFESSIONAL */,    "Service Pack 1" },
    /*  1 WIN2K8R2   */ { 6, 1,  7601, 1, 0, SV, SUITE_SV, 0x00000007 /* STANDARD_SERVER */, "Service Pack 1" },
    /*  2 WIN8       */ { 6, 2,  9200, 0, 0, WS, SUITE_WS, 0x00000030, "" },
    /*  3 WIN2K12    */ { 6, 2,  9200, 0, 0, SV, SUITE_SV, 0x00000007, "" },
    /*  4 WIN81      */ { 6, 3,  9600, 0, 0, WS, SUITE_WS, 0x00000030, "" },
    /*  5 WIN2K12R2  */ { 6, 3,  9600, 0, 0, SV, SUITE_SV, 0x00000007, "" },
    /*  6 WIN10_1511 */ { 10, 0, 10586, 0, 0, WS, SUITE_WS, 0x00000030, "" },
    /*  7 WIN10_1607 */ { 10, 0, 14393, 0, 0, WS, SUITE_WS, 0x00000030, "" },
    /*  8 WIN2K16    */ { 10, 0, 14393, 0, 0, SV, SUITE_SV, 0x00000007, "" },
    /*  9 WIN10_1809 */ { 10, 0, 17763, 0, 0, WS, SUITE_WS, 0x00000030, "" },
    /* 10 WIN2K19    */ { 10, 0, 17763, 0, 0, SV, SUITE_SV, 0x00000007, "" },
    /* 11 WIN10_21H2 */ { 10, 0, 19044, 0, 0, WS, SUITE_WS, 0x00000030, "" },
    /* 12 WIN2K22    */ { 10, 0, 20348, 0, 0, SV, SUITE_SV, 0x00000007, "" },
    /* 13 WIN11      */ { 10, 0, 26100, 0, 0, WS, SUITE_WS, 0x00000030, "" },   /* 24H2 */
    /* 14 WIN2K25    */ { 10, 0, 26100, 0, 0, SV, SUITE_SV, 0x00000007, "" },
    /* 15 WINXPSP3   */ { 5, 1,  2600, 3, 0, WS, SUITE_WS, 0x00000000 /* no GetProductInfo on XP */, "Service Pack 3" },
};
#define NPROF (sizeof(PROFILES) / sizeof(PROFILES[0]))

#define STATUS_REVISION_MISMATCH_K ((NTSTATUS)0xC0000059L)

/* ---------------------------------------------------------------- common implementations */
static DWORD get_version(const kex_profile *p)
{
    return (p->build << 16) | (p->minor << 8) | p->major;       /* NT: bit 31 clear */
}

static BOOL get_version_ex(const kex_profile *p, void *vi, BOOL wide)
{
    DWORD size;
    if (!vi || IsBadWritePtr(vi, sizeof(DWORD))) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    size = *(DWORD *)vi;
    if (wide) {
        OSVERSIONINFOEXW *v = (OSVERSIONINFOEXW *)vi;
        if (size != sizeof(OSVERSIONINFOW) && size != sizeof(OSVERSIONINFOEXW)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        v->dwMajorVersion = p->major; v->dwMinorVersion = p->minor; v->dwBuildNumber = p->build;
        v->dwPlatformId = VER_PLATFORM_WIN32_NT;
        memset(v->szCSDVersion, 0, sizeof(v->szCSDVersion));
        MultiByteToWideChar(CP_ACP, 0, p->csd, -1, v->szCSDVersion, 128);
        if (size == sizeof(OSVERSIONINFOEXW)) {
            v->wServicePackMajor = p->sp_major; v->wServicePackMinor = p->sp_minor;
            v->wSuiteMask = p->suite; v->wProductType = p->product_type; v->wReserved = 0;
        }
    } else {
        OSVERSIONINFOEXA *v = (OSVERSIONINFOEXA *)vi;
        if (size != sizeof(OSVERSIONINFOA) && size != sizeof(OSVERSIONINFOEXA)) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        v->dwMajorVersion = p->major; v->dwMinorVersion = p->minor; v->dwBuildNumber = p->build;
        v->dwPlatformId = VER_PLATFORM_WIN32_NT;
        memset(v->szCSDVersion, 0, sizeof(v->szCSDVersion));
        lstrcpynA(v->szCSDVersion, p->csd, 128);
        if (size == sizeof(OSVERSIONINFOEXA)) {
            v->wServicePackMajor = p->sp_major; v->wServicePackMinor = p->sp_minor;
            v->wSuiteMask = p->suite; v->wProductType = p->product_type; v->wReserved = 0;
        }
    }
    return TRUE;
}

static int cmp_values(DWORD left, DWORD right, BYTE cond)
{
    switch (cond) {
    case VER_EQUAL:         return left == right;
    case VER_GREATER:       return left > right;
    case VER_GREATER_EQUAL: return left >= right;
    case VER_LESS:          return left < right;
    case VER_LESS_EQUAL:    return left <= right;
    }
    return -1;                                   /* invalid condition */
}

static BYTE field_cond(ULONGLONG mask, DWORD type_bit)
{
    int i = 0;
    while (!(type_bit & 1)) { type_bit >>= 1; i++; }
    return (BYTE)((mask >> (i * 3)) & 7);
}

/* RtlVerifyVersionInfo semantics (as documented and as implemented by Wine/ReactOS). Input fields are
 * the common prefix of OSVERSIONINFOEXA/W (dwMajor..dwPlatformId, then wSP*, wSuite, wProductType). */
static NTSTATUS verify_version(const kex_profile *p, DWORD major, DWORD minor, DWORD build, DWORD platform,
                               WORD spmaj, WORD spmin, WORD suite, BYTE ptype, DWORD type, ULONGLONG mask)
{
    BYTE c;
    if (!type || !mask) return STATUS_INVALID_PARAMETER;
    if (type & VER_PRODUCT_TYPE) {
        c = field_cond(mask, VER_PRODUCT_TYPE);
        if (cmp_values(p->product_type, ptype, c) <= 0) return STATUS_REVISION_MISMATCH_K;
    }
    if (type & VER_SUITENAME) {
        c = field_cond(mask, VER_SUITENAME);
        if (c == VER_AND) { if ((p->suite & suite) != suite) return STATUS_REVISION_MISMATCH_K; }
        else if (c == VER_OR) { if (!(p->suite & suite) && suite) return STATUS_REVISION_MISMATCH_K; }
        else return STATUS_INVALID_PARAMETER;
    }
    if (type & VER_PLATFORMID) {
        c = field_cond(mask, VER_PLATFORMID);
        if (cmp_values(VER_PLATFORM_WIN32_NT, platform, c) <= 0) return STATUS_REVISION_MISMATCH_K;
    }
    if (type & VER_BUILDNUMBER) {
        c = field_cond(mask, VER_BUILDNUMBER);
        if (cmp_values(p->build, build, c) <= 0) return STATUS_REVISION_MISMATCH_K;
    }
    if (type & (VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR)) {
        /* hierarchical: major, then minor, then SP major, then SP minor; each with its own condition
         * (a field without one uses the previous field's), stop at the first field that differs */
        static const DWORD bits[4] = { VER_MAJORVERSION, VER_MINORVERSION, VER_SERVICEPACKMAJOR, VER_SERVICEPACKMINOR };
        DWORD sysv[4], reqv[4];
        BYTE last = 0;
        int i, r;
        sysv[0] = p->major; sysv[1] = p->minor; sysv[2] = p->sp_major; sysv[3] = p->sp_minor;
        reqv[0] = major; reqv[1] = minor; reqv[2] = spmaj; reqv[3] = spmin;
        for (i = 0; i < 4; i++) {
            if (!(type & bits[i])) continue;
            c = field_cond(mask, bits[i]);
            if (!c) c = last;
            last = c;
            r = cmp_values(sysv[i], reqv[i], c);
            if (r < 0) return STATUS_INVALID_PARAMETER;
            if (!r) return STATUS_REVISION_MISMATCH_K;
            if (sysv[i] != reqv[i] || c == VER_GREATER || c == VER_LESS) break;   /* decided at this level */
        }
    }
    return STATUS_SUCCESS;
}

static BOOL verify_version_ex(const kex_profile *p, const void *vi, BOOL wide, DWORD type, ULONGLONG mask)
{
    NTSTATUS s;
    if (!vi) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (wide) {
        const OSVERSIONINFOEXW *v = (const OSVERSIONINFOEXW *)vi;
        s = verify_version(p, v->dwMajorVersion, v->dwMinorVersion, v->dwBuildNumber, v->dwPlatformId,
                           v->wServicePackMajor, v->wServicePackMinor, v->wSuiteMask, v->wProductType, type, mask);
    } else {
        const OSVERSIONINFOEXA *v = (const OSVERSIONINFOEXA *)vi;
        s = verify_version(p, v->dwMajorVersion, v->dwMinorVersion, v->dwBuildNumber, v->dwPlatformId,
                           v->wServicePackMajor, v->wServicePackMinor, v->wSuiteMask, v->wProductType, type, mask);
    }
    if (s == STATUS_SUCCESS) return TRUE;
    SetLastError(s == STATUS_REVISION_MISMATCH_K ? ERROR_OLD_WIN_VERSION : ERROR_BAD_ARGUMENTS);
    return FALSE;
}

static NTSTATUS rtl_get_version(const kex_profile *p, void *vi)
{
    DWORD size = vi ? *(DWORD *)vi : 0;
    if (size != sizeof(OSVERSIONINFOW) && size != sizeof(OSVERSIONINFOEXW)) return STATUS_INVALID_PARAMETER;
    get_version_ex(p, vi, TRUE);
    return STATUS_SUCCESS;
}

static BOOL get_product_info(const kex_profile *p, DWORD maj, DWORD min, DWORD spmaj, DWORD spmin, PDWORD type)
{
    if (!type) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    *type = maj >= 6 ? p->product_info : 0 /* PRODUCT_UNDEFINED */;
    return TRUE;
}

/* ---------------------------------------------------------------- one stdcall set per profile */
#define PROFILE_FUNCS(i)                                                                                         \
static DWORD WINAPI GetVersion_##i(void) { return get_version(&PROFILES[i]); }                                  \
static BOOL WINAPI GetVersionExA_##i(LPOSVERSIONINFOA v) { return get_version_ex(&PROFILES[i], v, FALSE); }     \
static BOOL WINAPI GetVersionExW_##i(LPOSVERSIONINFOW v) { return get_version_ex(&PROFILES[i], v, TRUE); }      \
static BOOL WINAPI VerifyVersionInfoA_##i(LPOSVERSIONINFOEXA v, DWORD t, ULONGLONG m)                           \
    { return verify_version_ex(&PROFILES[i], v, FALSE, t, m); }                                                  \
static BOOL WINAPI VerifyVersionInfoW_##i(LPOSVERSIONINFOEXW v, DWORD t, ULONGLONG m)                           \
    { return verify_version_ex(&PROFILES[i], v, TRUE, t, m); }                                                   \
static BOOL WINAPI GetProductInfo_##i(DWORD a, DWORD b, DWORD c, DWORD d, PDWORD t)                             \
    { return get_product_info(&PROFILES[i], a, b, c, d, t); }                                                    \
static NTSTATUS WINAPI RtlGetVersion_##i(PVOID v) { return rtl_get_version(&PROFILES[i], v); }                  \
static NTSTATUS WINAPI RtlVerifyVersionInfo_##i(PVOID v, ULONG t, ULONGLONG m)                                  \
{                                                                                                                \
    const OSVERSIONINFOEXW *w = (const OSVERSIONINFOEXW *)v;                                                    \
    if (!w) return STATUS_INVALID_PARAMETER;                                                                     \
    return verify_version(&PROFILES[i], w->dwMajorVersion, w->dwMinorVersion, w->dwBuildNumber,                  \
        w->dwPlatformId, w->wServicePackMajor, w->wServicePackMinor, w->wSuiteMask, w->wProductType, t, m);     \
}                                                                                                                \
static VOID WINAPI RtlGetNtVersionNumbers_##i(PDWORD maj, PDWORD min, PDWORD build)                            \
{                                                                                                                \
    if (maj) *maj = PROFILES[i].major;                                                                           \
    if (min) *min = PROFILES[i].minor;                                                                           \
    if (build) *build = PROFILES[i].build | 0xF0000000UL;   /* free build flag, as on real NT */            \
}
PROFILE_FUNCS(0) PROFILE_FUNCS(1) PROFILE_FUNCS(2) PROFILE_FUNCS(3) PROFILE_FUNCS(4)
PROFILE_FUNCS(5) PROFILE_FUNCS(6) PROFILE_FUNCS(7) PROFILE_FUNCS(8) PROFILE_FUNCS(9)
PROFILE_FUNCS(10) PROFILE_FUNCS(11) PROFILE_FUNCS(12) PROFILE_FUNCS(13) PROFILE_FUNCS(14) PROFILE_FUNCS(15)

/* ---------------------------------------------------------------- KernelEx api table */
/* Layout must match common/kexcoresdk.h (apilib_named_api / apilib_api_table). Names sorted (strcmp);
 * equal names are consecutive and ordered by profile index = the ".N" in core.ini. */
typedef struct { const char *name; unsigned long addr; } apilib_named_api;
typedef struct { unsigned short ord; unsigned long addr; } apilib_unnamed_api;
typedef struct { const char *target_library; const apilib_named_api *named_apis; int named_apis_count;
                 const apilib_unnamed_api *ordinal_apis; int ordinal_apis_count; } apilib_api_table;

#define E(n, i) { #n, (unsigned long)n##_##i }
#define ALL(n) E(n,0), E(n,1), E(n,2), E(n,3), E(n,4), E(n,5), E(n,6), E(n,7), E(n,8), E(n,9), \
               E(n,10), E(n,11), E(n,12), E(n,13), E(n,14), E(n,15)
static const apilib_named_api k32_apis[] = {
    ALL(GetProductInfo), ALL(GetVersion), ALL(GetVersionExA), ALL(GetVersionExW),
    ALL(VerifyVersionInfoA), ALL(VerifyVersionInfoW),
};
static const apilib_named_api ntdll_apis[] = {
    ALL(RtlGetNtVersionNumbers), ALL(RtlGetVersion), ALL(RtlVerifyVersionInfo),
};
static const apilib_api_table api_table[] = {
    { "KERNEL32.DLL", k32_apis, sizeof(k32_apis) / sizeof(k32_apis[0]), NULL, 0 },
    { "NTDLL.DLL", ntdll_apis, sizeof(ntdll_apis) / sizeof(ntdll_apis[0]), NULL, 0 },
    { NULL, NULL, 0, NULL, 0 }
};

__declspec(dllexport) const apilib_api_table *get_api_table(void) { return api_table; }

/* For tests: the profile table size and a direct call into one profile without KernelEx. */
__declspec(dllexport) DWORD WINAPI KexVerProfileCount(void) { return NPROF; }
__declspec(dllexport) PVOID WINAPI KexVerProfileFunc(DWORD profile, LPCSTR target, LPCSTR name)
{
    const apilib_api_table *t;
    int i, k = 0;
    for (t = api_table; t->target_library; t++) {
        if (lstrcmpiA(t->target_library, target)) continue;
        for (i = 0; i < t->named_apis_count; i++)
            if (!lstrcmpA(t->named_apis[i].name, name) && k++ == (int)profile) return (PVOID)t->named_apis[i].addr;
    }
    return NULL;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(inst);
    return TRUE;
}
