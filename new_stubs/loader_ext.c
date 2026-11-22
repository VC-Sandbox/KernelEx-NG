/*
 * loader_ext.c - KernelEx-NG: LoadLibrary* for NT6+/Windows 10 callers on Windows 98 SE.
 *
 *  1. Windows 7+ flags. Win98's LoadLibraryExA knows DONT_RESOLVE_DLL_REFERENCES (1), AS_DATAFILE (2) and
 *     WITH_ALTERED_SEARCH_PATH (8). Newer flags are mapped:
 *        LOAD_LIBRARY_AS_IMAGE_RESOURCE (0x20), AS_DATAFILE_EXCLUSIVE (0x40)  -> AS_DATAFILE
 *        LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800) with a bare name               -> <system dir>\name first
 *        LOAD_LIBRARY_SEARCH_APPLICATION_DIR (0x200) with a bare name        -> <exe dir>\name first
 *        other LOAD_LIBRARY_SEARCH_* / REQUIRE_SIGNED / SAFE_CURRENT_DIRS    -> dropped (normal search)
 *  2. Modules mapped later by LoadLibrary get the NT PEB patch and appear in PEB->Ldr (peb_ext.c) -
 *     only in processes where the PEB emulation is active (an api-ms shell started it), so ordinary
 *     Win9x programs see a plain pass-through.
 *  3. Static TLS of DLLs loaded here is set up like Vista+ does (tls_ext.c); Windows 98 skips it.
 *  5. (build 132) A program's own api-ms-win-*.dll are NOT redirected to ours: the reasons Windows 98 could not use them
 *     are fixed in the loader (veh_ext.c kex_KexLoaderFix, fwdload_pic.c).
 *  4. DLLs with section data past 256 MB in the file: the KERNEL32 section-mapping hook is activated for this
 *     process first (veh_ext.c, kex_bigsec_prepare).
 * W variants convert like KernelEx's LoadLibraryExW_new (file API code page) and use the native A loader.
 */
#include "kexnt_common.h"

BOOL kex_peb_active(void);
VOID WINAPI kex_KexPatchNtModules(void);

#define LL_SEARCH_APPDIR   0x00000200
#define LL_SEARCH_SYSTEM32 0x00000800
#define LL_NATIVE_MASK     0x0000000B   /* 1 | 2 | 8 */

static BOOL bare_name(LPCSTR n)
{
    for (; *n; n++) if (*n == '\\' || *n == '/' || *n == ':') return FALSE;
    return TRUE;
}

/* path = directory + name; like the loader, a name without extension means ".dll" */
static HMODULE try_dir(char *path, HANDLE f, DWORD flags)
{
    const char *p = path + lstrlenA(path);
    while (p > path && p[-1] != '\\' && p[-1] != '.') p--;
    if (p == path || p[-1] != '.') { if (lstrlenA(path) + 4 >= MAX_PATH) return NULL; lstrcatA(path, ".dll"); }
    return GetFileAttributesA(path) == 0xFFFFFFFF ? NULL : LoadLibraryExA(path, f, flags);
}

static HMODULE load_ex_a(LPCSTR name, HANDLE file, DWORD flags)
{
    DWORD native = flags & LL_NATIVE_MASK;
    HMODULE h = NULL;
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    if (flags & 0x60) native |= LOAD_LIBRARY_AS_DATAFILE;
    if ((flags & (LL_SEARCH_SYSTEM32 | LL_SEARCH_APPDIR)) && bare_name(name)) {
        char path[MAX_PATH + 1];
        int n = 0;
        /* build 132: a bare name that is already loaded resolves to that module whatever the LOAD_LIBRARY_SEARCH_* flags
         * ask (NT's search order: the loaded-module list comes before any directory). Measured: Supermium's DWrite.dll
         * (DWriteCore relinked against its pwrp_k32.dll) calls LoadLibraryExW("pwrp_k32.dll", SEARCH_SYSTEM32) for a
         * module it already imports; we searched SYSTEM only -> 126 -> DWRITE_E_UNEXPECTED (0x88985001). */
        if (!(native & LOAD_LIBRARY_AS_DATAFILE)) {
            HMODULE h0 = GetModuleHandleA(name);
            if (h0 && GetModuleFileNameA(h0, path, MAX_PATH)) { h = LoadLibraryExA(path, file, native); if (h) return h; }
        }
        if (flags & LL_SEARCH_APPDIR) {
            char *bs;
            GetModuleFileNameA(NULL, path, MAX_PATH);
            if ((bs = strrchr(path, '\\'))) { bs[1] = 0; n = lstrlenA(path); }
            if (n && n + lstrlenA(name) < MAX_PATH) { lstrcatA(path, name); h = try_dir(path, file, native); }
        }
        if (!h && (flags & LL_SEARCH_SYSTEM32)) {
            n = (int)GetSystemDirectoryA(path, MAX_PATH);
            if (n && n + 1 + lstrlenA(name) < MAX_PATH) {
                lstrcatA(path, "\\"); lstrcatA(path, name);
                h = try_dir(path, file, native);
            }
        }
        if (h) return h;
        /* Only SYSTEM32 and/or APPLICATION_DIR were allowed (no DEFAULT_DIRS 0x1000, DLL_LOAD_DIR 0x100,
         * USER_DIRS 0x400): NT would not search further, so neither do we. */
        if (!(flags & 0x1500)) { SetLastError(ERROR_MOD_NOT_FOUND); return NULL; }
    }
    h = LoadLibraryExA(name, file, native);
    if (!h && !bare_name(name) && !(native & (LOAD_WITH_ALTERED_SEARCH_PATH | LOAD_LIBRARY_AS_DATAFILE))) {
        /* build 131: a DLL loaded by its full path whose own DLLs lie next to it. Windows XP+ finds them through the
         * DLL's manifest (private side-by-side assembly: LAV Filters' "LAVFilters.Dependencies" = avcodec-lav etc.);
         * Windows 98 has no side-by-side loader -> error 1157 (registering K-Lite's LAV filters). Searching the DLL's
         * own folder first (LOAD_WITH_ALTERED_SEARCH_PATH, which Windows 98 has) gives the same result. */
        DWORD e = GetLastError();
        if (e == ERROR_DLL_NOT_FOUND || e == ERROR_MOD_NOT_FOUND) {
            h = LoadLibraryExA(name, file, native | LOAD_WITH_ALTERED_SEARCH_PATH);
            if (!h) SetLastError(e);
            else { void kex_crashnote(const char *w, DWORD a, DWORD b, DWORD c, DWORD d);
                   kex_crashnote("LoadLibrary: loaded only with the DLL's own folder searched first (module, -, -, -)", (DWORD)(ULONG_PTR)h, 0, 0, 0); }
        }
    }
    return h;
}

void kex_crashlog_loadfail(LPCSTR name, DWORD flags, DWORD err);   /* crashlog_ext.c */
void kex_tls_before_load(void);                                     /* tls_ext.c */
void kex_tls_after_load(HMODULE h);
void kex_bigsec_prepare(LPCSTR name);                               /* veh_ext.c */
void kex_tls_enter(void);
void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
void kex_k32_clear_load_message(void);
void kex_tls_leave(void);

/* Chrome hunt (2026-11-01): Windows blue-screens right after chrome.dll (277 MB, sections past 256 MB mapped by
 * our big-file hook) is loaded, before any traced call. Once per process, for an image larger than 256 MB: list
 * its memory regions (VirtualQuery) and read one byte of every page, with a trace line per section and every
 * 16 MB, so a page Windows cannot bring in shows up as the last line before a blue screen. */
void kex_probe_big_image(HMODULE h)
{
    static LONG done;
    BYTE *b = (BYTE *)h; IMAGE_NT_HEADERS *nt; IMAGE_SECTION_HEADER *sec; DWORD i, size, bad = 0;
    MEMORY_BASIC_INFORMATION m; BYTE *p; int n;
    if (IsBadReadPtr(b, 0x400) || ((IMAGE_DOS_HEADER *)b)->e_magic != IMAGE_DOS_SIGNATURE) return;
    nt = (IMAGE_NT_HEADERS *)(b + ((IMAGE_DOS_HEADER *)b)->e_lfanew);
    size = nt->OptionalHeader.SizeOfImage;
    if (size <= 0x0FFFF000UL || InterlockedExchange(&done, 1)) return;
    kex_trace("probe image", (DWORD)(ULONG_PTR)b, size, nt->FileHeader.NumberOfSections, 0);
    for (p = b, n = 0; p < b + size && n < 64 && VirtualQuery(p, &m, sizeof(m)); p = (BYTE *)m.BaseAddress + m.RegionSize, n++)
        kex_trace("probe region", (DWORD)(ULONG_PTR)m.BaseAddress, (DWORD)m.RegionSize, m.State, m.Protect);
    sec = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        DWORD vs = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData, off;
        kex_trace("probe section", (DWORD)(ULONG_PTR)(b + sec->VirtualAddress), vs, sec->SizeOfRawData, sec->Characteristics);
        for (off = 0; off < vs; off += 0x1000) {
            volatile BYTE *q = b + sec->VirtualAddress + off;
            if (off && !(off & 0xFFFFFF)) kex_trace("probe at", (DWORD)(ULONG_PTR)q, bad, 0, 0);
            if (IsBadReadPtr((const void *)q, 1)) { if (!bad++) kex_trace("probe unreadable", (DWORD)(ULONG_PTR)q, 0, 0, 0); continue; }
            (void)*q;
        }
    }
    kex_trace("probe done", bad, 0, 0, 0);
}

static HMODULE after_load(HMODULE h, DWORD flags, LPCSTR name)
{
    if (h && !(flags & 0x63) && name) { void kex_guard_imports_if_gl(HMODULE, const char *); DWORD e = GetLastError(); kex_guard_imports_if_gl(h, name); SetLastError(e); }   /* build 55 */
    if (h && !(flags & 0x63)) { DWORD e = GetLastError(); kex_tls_after_load(h); SetLastError(e); kex_trace("  after load: TLS done", (DWORD)(ULONG_PTR)h, 0, 0, 0); }
    if (h && !(flags & 0x62) && kex_peb_active()) kex_KexPatchNtModules();
    if (h) kex_trace("  after load: done", (DWORD)(ULONG_PTR)h, 0, 0, 0);
    if (!h) { DWORD e = GetLastError(); kex_crashlog_loadfail(name, flags, e); SetLastError(e); }
    return h;
}

static LPSTR w_to_a(LPCWSTR w, char *buf, int cb)
{
    UINT cp = AreFileApisANSI() ? CP_ACP : CP_OEMCP;
    if (!w) return NULL;
    if (!WideCharToMultiByte(cp, 0, w, -1, buf, cb, NULL, NULL)) return NULL;
    return buf;
}


/* build 125-131 loaded a moved temp copy of a DLL without relocations here (load_unrelocatable). Removed in build 132:
 * Windows 98's refusal to move such a DLL is fixed in KERNEL32 itself (veh_ext.c, kex_KexLoaderFix). */

HMODULE KEXAPI kex_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
    HMODULE h;
    kex_trace(name ? name : "LoadLibraryExA(null)", flags, 0, 0, 0);
    kex_tls_before_load();
    if (!(flags & 0x62)) kex_bigsec_prepare(name);
    kex_k32_clear_load_message();
    kex_tls_enter();
    h = load_ex_a(name, file, flags);
    kex_tls_leave();
    kex_trace(h ? "  -> loaded" : "  -> failed", (DWORD)(ULONG_PTR)h, GetLastError(), 0, 0);
    return after_load(h, flags, name);
}

HMODULE KEXAPI kex_LoadLibraryA(LPCSTR name)
{
    HMODULE h;
    kex_trace(name ? name : "LoadLibraryA(null)", 0, 0, 0, 0);
    kex_tls_before_load();
    kex_bigsec_prepare(name);
    kex_k32_clear_load_message();
    kex_tls_enter();
    h = LoadLibraryA(name);
    kex_tls_leave();
    kex_trace(h ? "  -> loaded" : "  -> failed", (DWORD)(ULONG_PTR)h, GetLastError(), 0, 0);
    return after_load(h, 0, name);
}

HMODULE KEXAPI kex_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    char a[MAX_PATH * 2];
    if (!name) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    if (!w_to_a(name, a, sizeof(a))) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return NULL; }
    return kex_LoadLibraryExA(a, file, flags);
}

HMODULE KEXAPI kex_LoadLibraryW(LPCWSTR name)
{
    return kex_LoadLibraryExW(name, NULL, 0);
}
