/*
 * imgsec_ext.c - image sections (CreateFileMapping with SEC_IMAGE) for modern programs on Windows 98 (build 132).
 *
 * NT: CreateFileMapping(file, PAGE_READONLY | SEC_IMAGE) makes an IMAGE section - a view has the PE headers at 0 and
 * every section at its RVA, exactly as the loader would lay the file out; a file that is not a valid PE image is
 * refused (ERROR_BAD_EXE_FORMAT). Windows 98 accepts the flag and makes an ordinary FLAT mapping (section data at its
 * file offset). Measured with probes/secimg.c on ISymWrapper.dll: "data at RVA differs from the section's file bytes
 * -> FLAT layout". The .NET 4 runtime reads assemblies through such views; with the flat layout it found no manifest:
 * the .NET Framework 4.0 setup's InstallAssembly custom action got IAssemblyCache->InstallAssembly() = 0x80131018
 * (COR_E_ASSEMBLYEXPECTED) for the first assembly and the install ended with 1603.
 *
 * Here: such a mapping is remembered with its file's path; a view of it is built in private memory - headers and the
 * raw data of each section at its RVA, the rest zero, 64 KB aligned like an NT view; read-only unless a writable or
 * copy view was asked for. No relocations are applied (NT XP does not relocate a data view of an image section
 * either). Unmap frees it, CloseHandle of the mapping forgets it. Only programs that go through kexnt (modern ones).
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);
BOOL kex_fpath_get(HANDLE h, char *buf, DWORD cb);       /* fpath_ext.c */

#define NIMG 64
#define NIMGV 128
typedef struct { HANDLE sec; char path[MAX_PATH]; DWORD size; } IMGSEC;
typedef struct { void *view; HANDLE sec; } IMGVIEW;
static IMGSEC g_img[NIMG];
static IMGVIEW g_imgv[NIMGV];
static volatile LONG g_lock;
static void lk(void) { while (InterlockedExchange((LONG *)&g_lock, 1)) Sleep(0); }
static void ulk(void) { InterlockedExchange((LONG *)&g_lock, 0); }

/* headers of a PE file through a handle; TRUE and SizeOfImage if it is an image the loader would accept */
static BOOL pe_size(HANDLE f, DWORD *size)
{
    BYTE h[0x400]; DWORD got = 0; LONG hi = 0; DWORD pos = SetFilePointer(f, 0, &hi, FILE_CURRENT);
    IMAGE_NT_HEADERS32 *nt; BOOL ok = FALSE;
    if (SetFilePointer(f, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) return FALSE;
    if (ReadFile(f, h, sizeof(h), &got, NULL) && got >= 0x100 && ((IMAGE_DOS_HEADER *)h)->e_magic == IMAGE_DOS_SIGNATURE &&
        (DWORD)((IMAGE_DOS_HEADER *)h)->e_lfanew <= got - sizeof(IMAGE_NT_HEADERS32)) {
        nt = (IMAGE_NT_HEADERS32 *)(h + ((IMAGE_DOS_HEADER *)h)->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE && nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
            nt->OptionalHeader.SizeOfImage && nt->OptionalHeader.SizeOfImage < 0x40000000UL) { *size = nt->OptionalHeader.SizeOfImage; ok = TRUE; }
    }
    SetFilePointer(f, (LONG)pos, &hi, FILE_BEGIN);
    return ok;
}

/* called by kex_CreateFileMappingA for a successful mapping: 0 = not ours, 1 = remembered, -1 = refuse (not an image) */
int kex_imgsec_created(HANDLE sec, HANDLE file, DWORD protect)
{
    DWORD size; int i; char path[MAX_PATH];
    if (!(protect & SEC_IMAGE) || !file || file == INVALID_HANDLE_VALUE) return 0;
    if (!pe_size(file, &size)) return -1;
    if (!kex_fpath_get(file, path, MAX_PATH)) return 0;          /* cannot reopen it: leave Windows' flat mapping */
    lk();
    for (i = 0; i < NIMG; i++) if (!g_img[i].sec) { g_img[i].sec = sec; lstrcpynA(g_img[i].path, path, MAX_PATH); g_img[i].size = size; break; }
    ulk();
    {   static LONG n; if (InterlockedIncrement(&n) <= 20) kex_crashnote("SEC_IMAGE mapping: views will get the image layout (mapping, SizeOfImage, -, -)", (DWORD)(ULONG_PTR)sec, size, 0, 0); }
    return i < NIMG ? 1 : 0;
}

static BOOL rd(HANDLE f, DWORD off, void *b, DWORD n)
{
    DWORD got = 0;
    if (!n) return TRUE;
    return SetFilePointer(f, (LONG)off, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER && ReadFile(f, b, n, &got, NULL) && got == n;
}

/* MapViewOfFile(Ex) of a remembered image mapping: the view, or NULL (not ours / failed - error set) */
LPVOID kex_imgsec_map(HANDLE sec, DWORD access, DWORD hi, DWORD lo, SIZE_T n, LPVOID base, BOOL *ours)
{
    char path[MAX_PATH]; DWORD size = 0, i, old; HANDLE f; BYTE *v; IMAGE_NT_HEADERS32 *nt; IMAGE_SECTION_HEADER *s; BOOL ok = TRUE;
    *ours = FALSE;
    lk();
    for (i = 0; i < NIMG; i++) if (g_img[i].sec == sec) { lstrcpyA(path, g_img[i].path); size = g_img[i].size; break; }
    ulk();
    if (!size) return NULL;
    *ours = TRUE;
    if (hi || lo) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }       /* NT: image views start at 0 */
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return NULL;
    v = (BYTE *)VirtualAlloc(base, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!v) { DWORD e = GetLastError(); CloseHandle(f); SetLastError(e ? e : ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    {   BYTE h[0x1000]; DWORD hs;
        ok = rd(f, 0, h, sizeof(h) < size ? sizeof(h) : size) || rd(f, 0, h, 0x400);
        nt = (IMAGE_NT_HEADERS32 *)(h + ((IMAGE_DOS_HEADER *)h)->e_lfanew);
        hs = nt->OptionalHeader.SizeOfHeaders; if (hs > size) hs = size;
        ok = ok && rd(f, 0, v, hs < GetFileSize(f, NULL) ? hs : GetFileSize(f, NULL));
    }
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
    if (!ok) { VirtualFree(v, 0, MEM_RELEASE); SetLastError(ERROR_BAD_EXE_FORMAT); return NULL; }
    VirtualProtect(v, size, (access & (FILE_MAP_WRITE | FILE_MAP_COPY)) ? PAGE_READWRITE : PAGE_READONLY, &old);
    lk();
    for (i = 0; i < NIMGV; i++) if (!g_imgv[i].view) { g_imgv[i].view = v; g_imgv[i].sec = sec; break; }
    ulk();
    (void)n;
    return v;
}

BOOL kex_imgsec_unmap(LPCVOID a)
{
    int i; void *v = NULL;
    if (!a) return FALSE;
    lk();
    for (i = 0; i < NIMGV; i++) if (g_imgv[i].view == a) { v = g_imgv[i].view; g_imgv[i].view = NULL; break; }
    ulk();
    if (!v) return FALSE;
    VirtualFree(v, 0, MEM_RELEASE);
    return TRUE;
}

void kex_imgsec_forget(HANDLE sec)                       /* sec_ext.c kex_CloseHandle */
{
    int i;
    if (!sec) return;
    lk();
    for (i = 0; i < NIMG; i++) if (g_img[i].sec == sec) { g_img[i].sec = NULL; break; }
    ulk();
}
