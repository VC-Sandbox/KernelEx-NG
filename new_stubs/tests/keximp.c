/*
 * keximp.c - KEXIMP: which imports of a DLL/EXE cannot be resolved on THIS system, under THIS KernelEx profile.
 *
 *   KEXIMP file.dll [more files...]        -> console + KEXIMP.LOG (current folder)
 *
 * Win98's loader shows "linked to missing export" only for a program's own start; a LoadLibrary that fails
 * just returns NULL (chrome.exe then quits with an error code). This tool reads the import tables (normal and
 * delay-load) directly from the file - the DLL is never loaded or run - and checks every imported function:
 *   - DLLs found next to the file are opened with DONT_RESOLVE_DLL_REFERENCES (no DllMain) and checked in
 *     turn (recursively), because the loader would load them too;
 *   - everything else is loaded with LoadLibrary (system DLLs, api-ms-win-* shells, stubs).
 * GetProcAddress from this program goes through KernelEx's tables for THIS program's settings, so give
 * KEXIMP.EXE the same KernelEx compatibility mode as the program you are checking (e.g. Windows 10 21H2).
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static FILE *g_log;
static int g_hdr, g_load;
static void L(const char *fmt, ...)
{
    va_list a;
    va_start(a, fmt); vprintf(fmt, a); va_end(a);
    if (g_log) { va_start(a, fmt); vfprintf(g_log, fmt, a); va_end(a); fflush(g_log); }
}

typedef struct { DWORD va, vsize, raw, rawsize; } SEC;
typedef struct { HANDLE f; SEC s[96]; int ns; } PEF;

static BOOL rd(PEF *p, DWORD off, void *buf, DWORD n)
{
    DWORD got = 0;
    return SetFilePointer(p->f, off, NULL, FILE_BEGIN) != INVALID_SET_FILE_POINTER &&
           ReadFile(p->f, buf, n, &got, NULL) && got == n;
}
static DWORD r2o(PEF *p, DWORD rva)
{
    int i;
    for (i = 0; i < p->ns; i++) {
        DWORD sz = p->s[i].vsize > p->s[i].rawsize ? p->s[i].vsize : p->s[i].rawsize;
        if (rva >= p->s[i].va && rva < p->s[i].va + sz) return p->s[i].raw + rva - p->s[i].va;
    }
    return 0;
}
static BOOL rstr(PEF *p, DWORD rva, char *out, int n)
{
    DWORD o = r2o(p, rva); int i;
    if (!o || !rd(p, o, out, n - 1)) { out[0] = 0; return FALSE; }
    out[n - 1] = 0;
    for (i = 0; i < n - 1 && out[i]; i++) ;
    return TRUE;
}

/* queue of files to check */
static char g_queue[64][MAX_PATH];
static int g_nq, g_done;
static int g_static_missing, g_delay_missing;

static void enqueue(const char *path)
{
    int i;
    for (i = 0; i < g_nq; i++) if (!lstrcmpiA(g_queue[i], path)) return;
    if (g_nq < 64) lstrcpynA(g_queue[g_nq++], path, MAX_PATH);
}

static HMODULE get_module(const char *dir, const char *dll, BOOL *local)
{
    char path[MAX_PATH]; HMODULE h;
    *local = FALSE;
    lstrcpyA(path, dir); lstrcatA(path, dll);
    if (GetFileAttributesA(path) != 0xFFFFFFFF) {             /* next to the file: don't run its DllMain */
        *local = TRUE;
        enqueue(path);
        if ((h = GetModuleHandleA(path))) return h;
        return LoadLibraryExA(path, NULL, DONT_RESOLVE_DLL_REFERENCES);
    }
    if ((h = GetModuleHandleA(dll))) return h;
    return LoadLibraryA(dll);
}

/* one import descriptor list (normal: 20-byte descriptors; delay: 32-byte, RVA based) */
static void check_imports(PEF *p, const char *dir, DWORD dir_rva, BOOL delay, const char *file)
{
    DWORD o = r2o(p, dir_rva);
    int desc;
    if (!dir_rva || !o) return;
    for (desc = 0; desc < 512; desc++) {
        DWORD d[8], name_rva, int_rva, n; char dll[260]; HMODULE h; BOOL local; int missing = 0, total = 0;
        if (!rd(p, o + desc * (delay ? 32 : 20), d, delay ? 32 : 20)) break;
        if (delay) { name_rva = d[1]; int_rva = d[4]; }          /* ImgDelayDescr: attrs, DllName, hmod, IAT, INT (RVAs) */
        else { name_rva = d[3]; int_rva = d[0] ? d[0] : d[4]; }
        if (!name_rva) break;
        rstr(p, name_rva, dll, sizeof(dll));
        h = get_module(dir, dll, &local);
        if (!h) {
            DWORD e = GetLastError();
            L("  %s %-40s CANNOT BE LOADED (error %lu)\n", delay ? "delay " : "static", dll, e);
            if (delay) g_delay_missing++; else g_static_missing++;
            continue;
        }
        for (n = 0; n < 65536; n++) {
            DWORD t; FARPROC f; char fn[256];
            if (!rd(p, r2o(p, int_rva) + n * 4, &t, 4) || !t) break;
            total++;
            if (t & 0x80000000UL) { f = GetProcAddress(h, (LPCSTR)(ULONG_PTR)(t & 0xFFFF)); sprintf(fn, "#%lu", t & 0xFFFF); }
            else { rstr(p, t + 2, fn, sizeof(fn)); f = GetProcAddress(h, fn); }
            if (!f) {
                L("  %s MISSING %s!%s\n", delay ? "delay " : "static", dll, fn);
                missing++;
                if (delay) g_delay_missing++; else g_static_missing++;
            }
        }
        if (!missing) L("  %s ok      %-40s %d functions%s\n", delay ? "delay " : "static", dll, total, local ? " (local)" : "");
    }
}

static void check_file(const char *path)
{
    PEF p; BYTE hdr[4096]; DWORD pe, opt, nsec, i, imp, dimp; char dir[MAX_PATH], *bs;
    IMAGE_FILE_HEADER *fh; IMAGE_OPTIONAL_HEADER32 *oh;
    memset(&p, 0, sizeof(p));
    L("\n== %s\n", path);
    p.f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (p.f == INVALID_HANDLE_VALUE) { L("  cannot open (error %lu)\n", GetLastError()); return; }
    if (!rd(&p, 0, hdr, sizeof(hdr)) || hdr[0] != 'M' || hdr[1] != 'Z') { L("  not a PE file\n"); CloseHandle(p.f); return; }
    pe = *(DWORD *)(hdr + 0x3C);
    if (pe > sizeof(hdr) - 0x200 || *(DWORD *)(hdr + pe) != IMAGE_NT_SIGNATURE) { L("  not a PE file\n"); CloseHandle(p.f); return; }
    fh = (IMAGE_FILE_HEADER *)(hdr + pe + 4);
    oh = (IMAGE_OPTIONAL_HEADER32 *)(hdr + pe + 24);
    if (oh->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) { L("  not a 32-bit image\n"); CloseHandle(p.f); return; }
    opt = pe + 24 + fh->SizeOfOptionalHeader;
    nsec = fh->NumberOfSections;
    for (i = 0; i < nsec && i < 96 && opt + (i + 1) * 40 <= sizeof(hdr); i++) {
        IMAGE_SECTION_HEADER *s = (IMAGE_SECTION_HEADER *)(hdr + opt + i * 40);
        p.s[i].va = s->VirtualAddress; p.s[i].vsize = s->Misc.VirtualSize;
        p.s[i].raw = s->PointerToRawData; p.s[i].rawsize = s->SizeOfRawData;
    }
    p.ns = i;
    L("  image size %lu KB, preferred base %08lx, subsystem %u.%u, OS %u.%u\n",
      oh->SizeOfImage / 1024, oh->ImageBase, oh->MajorSubsystemVersion, oh->MinorSubsystemVersion,
      oh->MajorOperatingSystemVersion, oh->MinorOperatingSystemVersion);
    if (g_hdr) {
        static const char *dn[16] = { "export", "import", "resource", "exception", "security", "basereloc", "debug",
            "arch", "globalptr", "TLS", "loadconfig", "boundimport", "IAT", "delayimport", "CLR", "reserved" };
        L("  machine %04x  characteristics %04x  DllCharacteristics %04x  sections %u\n",
          fh->Machine, fh->Characteristics, oh->DllCharacteristics, fh->NumberOfSections);
        L("  SectionAlignment %lx  FileAlignment %lx  SizeOfHeaders %lx  SizeOfImage %lx  entry %lx  linker %u.%u\n",
          oh->SectionAlignment, oh->FileAlignment, oh->SizeOfHeaders, oh->SizeOfImage, oh->AddressOfEntryPoint,
          oh->MajorLinkerVersion, oh->MinorLinkerVersion);
        L("  stack %lx/%lx  heap %lx/%lx  LoaderFlags %lx  RvaAndSizes %lu\n", oh->SizeOfStackReserve,
          oh->SizeOfStackCommit, oh->SizeOfHeapReserve, oh->SizeOfHeapCommit, oh->LoaderFlags, oh->NumberOfRvaAndSizes);
        for (i = 0; i < oh->NumberOfRvaAndSizes && i < 16; i++)
            if (oh->DataDirectory[i].VirtualAddress || oh->DataDirectory[i].Size)
                L("  dir %-12s rva %08lx size %08lx\n", dn[i], oh->DataDirectory[i].VirtualAddress, oh->DataDirectory[i].Size);
        for (i = 0; i < nsec && i < 96 && opt + (i + 1) * 40 <= sizeof(hdr); i++) {
            IMAGE_SECTION_HEADER *s = (IMAGE_SECTION_HEADER *)(hdr + opt + i * 40);
            L("  section %-8.8s va %08lx vsize %08lx raw %08lx rawsize %08lx flags %08lx\n", (char *)s->Name,
              s->VirtualAddress, s->Misc.VirtualSize, s->PointerToRawData, s->SizeOfRawData, s->Characteristics);
        }
        if (oh->NumberOfRvaAndSizes > 9 && oh->DataDirectory[9].VirtualAddress) {
            DWORD t[6], cb, k = 0;
            if (rd(&p, r2o(&p, oh->DataDirectory[9].VirtualAddress), t, sizeof(t))) {
                L("  TLS: data %08lx-%08lx index@%08lx callbacks@%08lx zerofill %lx flags %lx\n", t[0], t[1], t[2], t[3], t[4], t[5]);
                while (t[3] && k < 32 && rd(&p, r2o(&p, t[3] - oh->ImageBase) + k * 4, &cb, 4) && cb) {
                    L("    callback %lu: %08lx (rva %lx)\n", k, cb, cb - oh->ImageBase); k++;
                }
            }
        }
    }
    if (g_load) {
        static const DWORD fl[2] = { LOAD_LIBRARY_AS_DATAFILE, DONT_RESOLVE_DLL_REFERENCES };
        static const char *fn[2] = { "LOAD_LIBRARY_AS_DATAFILE", "DONT_RESOLVE_DLL_REFERENCES" };
        for (i = 0; i < 2; i++) {
            HMODULE h; SetLastError(0);
            h = LoadLibraryExA(path, NULL, fl[i]);
            L("  LoadLibraryEx(%s): %s, handle %08lx, error %lu\n", fn[i], h ? "OK" : "FAILED", (DWORD)h, h ? 0 : GetLastError());
            if (h) FreeLibrary(h);
        }
    }
    imp  = oh->NumberOfRvaAndSizes > 1  ? oh->DataDirectory[1].VirtualAddress : 0;
    dimp = oh->NumberOfRvaAndSizes > 13 ? oh->DataDirectory[13].VirtualAddress : 0;
    lstrcpyA(dir, path);
    if ((bs = strrchr(dir, '\\'))) bs[1] = 0; else dir[0] = 0;
    check_imports(&p, dir, imp, FALSE, path);
    check_imports(&p, dir, dimp, TRUE, path);
    CloseHandle(p.f);
}

int main(int argc, char **argv)
{
    int i; OSVERSIONINFOA vi;
    if (argc < 2) { printf("usage: KEXIMP [-hdr] [-load] file.dll [more files...]   (log: KEXIMP.LOG)\n"); return 1; }
    g_log = fopen("KEXIMP.LOG", "w");
    vi.dwOSVersionInfoSize = sizeof(vi); GetVersionExA(&vi);
    L("keximp: this program sees Windows %lu.%lu build %lu - set KEXIMP.EXE's KernelEx mode like the program you check\n",
      vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber & 0xFFFF);
    for (i = 1; i < argc; i++) {
        char full[MAX_PATH], *fp;
        if (!lstrcmpiA(argv[i], "-hdr")) { g_hdr = 1; continue; }
        if (!lstrcmpiA(argv[i], "-load")) { g_load = 1; continue; }
        if (GetFullPathNameA(argv[i], MAX_PATH, full, &fp)) enqueue(full); else enqueue(argv[i]);
    }
    for (g_done = 0; g_done < g_nq; g_done++) check_file(g_queue[g_done]);
    L("\nsummary: %d static import(s) missing, %d delay-load import(s) missing, %d file(s) checked\n",
      g_static_missing, g_delay_missing, g_nq);
    L("(static = the DLL cannot load at all; delay = fails later, only when that function is first used)\n");
    if (g_log) fclose(g_log);
    return g_static_missing ? 2 : 0;
}
