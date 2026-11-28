/*
 * climg_ext.c - LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES) of .NET assemblies, as on NT (build 132).
 *
 * NT maps a DLL loaded with DONT_RESOLVE_DLL_REFERENCES as an image and neither resolves its imports nor calls its entry
 * point. Windows 98 calls the entry point anyway. Measured (probes/llxdr.c, .NET 2.0's mscorlib.dll and System.dll):
 * flags 1, 9 and 0 all fail with 1114 ("a DllMain returned FALSE": an assembly's entry point is mscoree!_CorDllMain,
 * which refuses outside the runtime); only LOAD_LIBRARY_AS_DATAFILE loads. The .NET 2.0 runtime loads its assemblies
 * with flags 9 (KEXCRASH_min2.LOG: "LoadLibrary failed: ...\mscorlib.dll flags 00000009 error 1114") and stopped there.
 *
 * Here, in a .NET process (gate_ext.c), such a load of a file with a CLR header gets the image layout NT would give:
 * a private allocation of SizeOfImage, 64 KB aligned, the headers at 0 and every section at its RVA (raw data, the rest
 * zero), no relocations applied, no imports resolved, no entry point called. FreeLibrary counts it down and frees it;
 * GetModuleFileName returns its path. A file that is already loaded as a module is returned as that module.
 */
#include "kexnt_common.h"

int kex_gate_is_clr(void);                                    /* gate_ext.c */
void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

#define NIMG 64
static struct { BYTE *base; DWORD refs; char path[MAX_PATH]; } g_img[NIMG];
static volatile LONG g_lock;

static BOOL rd(HANDLE f, DWORD off, void *b, DWORD n)
{
    DWORD got = 0;
    if (!n) return TRUE;
    return SetFilePointer(f, (LONG)off, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER && ReadFile(f, b, n, &got, NULL) && got == n;
}

/* full path of name as LoadLibrary would find it (path given, or the search path) */
static BOOL find_path(const char *name, char *out)
{
    char *fp;
    if (SearchPathA(NULL, name, ".dll", MAX_PATH, out, &fp)) return TRUE;
    return GetFullPathNameA(name, MAX_PATH, out, &fp) && GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES;
}

/* NULL = not ours (caller loads normally); else the image (error set to 0) */
HMODULE kex_climg_load(const char *name, DWORD flags)
{
    char path[MAX_PATH]; HANDLE f; BYTE h[0x1000]; IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *s;
    DWORD size, hs, i, fsz; BYTE *v; BOOL ok = TRUE; HMODULE m; int k;
    if (!(flags & DONT_RESOLVE_DLL_REFERENCES) || (flags & (LOAD_LIBRARY_AS_DATAFILE | 0x40 | 0x20)) || !name || !kex_gate_is_clr()) return NULL;
    if (!find_path(name, path)) return NULL;
    if ((m = GetModuleHandleA(path))) return NULL;            /* loaded for real already: Windows 98's own answer */
    kex_spin_acquire(&g_lock);
    for (k = 0; k < NIMG; k++) if (g_img[k].base && !lstrcmpiA(g_img[k].path, path)) { g_img[k].refs++; v = g_img[k].base; InterlockedExchange(&g_lock, 0); SetLastError(0); return (HMODULE)v; }
    InterlockedExchange(&g_lock, 0);
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    fsz = GetFileSize(f, NULL);
    if (!rd(f, 0, h, fsz < sizeof(h) ? fsz : sizeof(h)) || ((IMAGE_DOS_HEADER *)h)->e_magic != IMAGE_DOS_SIGNATURE ||
        (DWORD)((IMAGE_DOS_HEADER *)h)->e_lfanew > sizeof(h) - sizeof(IMAGE_NT_HEADERS32)) { CloseHandle(f); return NULL; }
    nt = (IMAGE_NT_HEADERS32 *)(h + ((IMAGE_DOS_HEADER *)h)->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ||
        !nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress) { CloseHandle(f); return NULL; }   /* not an assembly */
    size = nt->OptionalHeader.SizeOfImage; hs = nt->OptionalHeader.SizeOfHeaders;
    if (!size || size > 0x10000000UL || hs > size || hs > fsz) { CloseHandle(f); return NULL; }
    if (!(v = (BYTE *)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) { CloseHandle(f); return NULL; }
    ok = rd(f, 0, v, hs);
    nt = (IMAGE_NT_HEADERS32 *)(v + ((IMAGE_DOS_HEADER *)v)->e_lfanew);
    s = IMAGE_FIRST_SECTION(nt);
    for (i = 0; ok && i < nt->FileHeader.NumberOfSections; i++) {
        DWORD raw = s[i].SizeOfRawData, va = s[i].VirtualAddress, vs = s[i].Misc.VirtualSize;
        if (vs && raw > vs) raw = vs;
        if (va >= size) continue;
        if (raw > size - va) raw = size - va;
        if (raw && s[i].PointerToRawData) ok = rd(f, s[i].PointerToRawData, v + va, raw);
    }
    CloseHandle(f);
    if (!ok) { VirtualFree(v, 0, MEM_RELEASE); return NULL; }
    kex_spin_acquire(&g_lock);
    for (k = 0; k < NIMG; k++) if (!g_img[k].base) { g_img[k].base = v; g_img[k].refs = 1; lstrcpynA(g_img[k].path, path, MAX_PATH); break; }
    InterlockedExchange(&g_lock, 0);
    if (k == NIMG) { VirtualFree(v, 0, MEM_RELEASE); return NULL; }
    {   static LONG n; if (InterlockedIncrement(&n) <= 20) kex_crashnote("CLR: assembly mapped as an image without its entry point (DONT_RESOLVE_DLL_REFERENCES, as NT) (base, SizeOfImage, flags, -)", (DWORD)(ULONG_PTR)v, size, flags, 0); }
    SetLastError(0);
    return (HMODULE)v;
}

static int find(HMODULE h)
{
    int k;
    if (!h) return -1;
    for (k = 0; k < NIMG; k++) if (g_img[k].base && (HMODULE)g_img[k].base == h) return k;
    return -1;
}

/* FreeLibrary: TRUE and *done if h is one of ours */
BOOL kex_climg_free(HMODULE h)
{
    int k; BYTE *v = NULL;
    kex_spin_acquire(&g_lock);
    if ((k = find(h)) >= 0 && !--g_img[k].refs) { v = g_img[k].base; g_img[k].base = NULL; }
    InterlockedExchange(&g_lock, 0);
    if (v) VirtualFree(v, 0, MEM_RELEASE);
    return k >= 0;
}

/* GetModuleFileName: length copied (like Windows), or (DWORD)-1 if h is not ours */
DWORD kex_climg_name(HMODULE h, char *buf, DWORD len)
{
    int k; char p[MAX_PATH]; DWORD n;
    kex_spin_acquire(&g_lock);
    if ((k = find(h)) >= 0) lstrcpyA(p, g_img[k].path);
    InterlockedExchange(&g_lock, 0);
    if (k < 0) return (DWORD)-1;
    if (!buf || !len) return 0;
    n = (DWORD)lstrlenA(p);
    if (n >= len) { memcpy(buf, p, len - 1); buf[len - 1] = 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return len; }
    lstrcpyA(buf, p);
    return n;
}
