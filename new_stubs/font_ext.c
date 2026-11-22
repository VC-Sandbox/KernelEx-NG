/*
 * font_ext.c - KernelEx-NG: AddFontMemResourceEx / RemoveFontMemResourceEx for Windows 98.
 *
 * Windows 98 has no AddFontMemResourceEx (Windows 2000+). KernelEx 4.5 answers it with a fake success
 * (handle 0x10000, one font) without registering anything. Mypal (Gecko's GDI font backend) then believes
 * a web font is installed under the unique name it gave it, CreateFont falls back to another face, and the
 * text is drawn with the web font's glyph numbers in that other face: "whats my ip" came out as "ZKDWV P \L"
 * (2026-11-02, DuckDuckGo). kexnt now really registers the font: the data goes to a file in the TEMP folder
 * and AddFontResourceA adds it (TrueType outlines only - Windows 98 cannot read CFF/PostScript outlines;
 * then the call fails honestly and the browser uses one of its fallback fonts). RemoveFontMemResourceEx and
 * process exit remove the font and delete the file. kexnt imports only KERNEL32/ADVAPI32: GDI32 is reached
 * with kex_sysproc.
 */
#include "kexnt_common.h"

void kex_trace(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);

typedef int (WINAPI *T_ADDFR)(LPCSTR);
typedef BOOL (WINAPI *T_REMFR)(LPCSTR);

#define FONT_MAGIC 0x544E464BUL   /* 'KFNT' */
#define FONT_MAX 256
typedef struct { DWORD magic; char path[MAX_PATH]; } KFONT;
static KFONT *g_fonts[FONT_MAX];
static LONG g_font_seq, g_font_lock;

static void lock(void) { kex_spin_acquire((volatile LONG *)&g_font_lock); }
static void unlock(void) { InterlockedExchange(&g_font_lock, 0); }

static void hex8(char *o, DWORD v) { int i; for (i = 0; i < 8; i++) o[i] = "0123456789ABCDEF"[(v >> (28 - 4 * i)) & 15]; o[8] = 0; }

HANDLE KEXAPI kex_AddFontMemResourceEx(PVOID data, DWORD size, PVOID reserved, DWORD *count)
{
    T_ADDFR add = (T_ADDFR)(void *)kex_sysproc("GDI32.DLL", "AddFontResourceA");
    T_REMFR rem = (T_REMFR)(void *)kex_sysproc("GDI32.DLL", "RemoveFontResourceA");
    KFONT *f; HANDLE h; DWORD w = 0, tag; int n, i, slot = -1; char num[9];
    if (!data || !size || !count || reserved || !add) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    *count = 0;
    if (IsBadReadPtr(data, size) || size < 12) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    tag = *(DWORD *)data;
    if (tag == 0x4F54544FUL /* 'OTTO' = CFF outlines */) {
        kex_trace("font: CFF font not supported by Windows 98", size, 0, 0, 0);
        SetLastError(ERROR_NOT_SUPPORTED); return NULL;
    }
    if (!(f = (KFONT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*f)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    n = (int)GetTempPathA(MAX_PATH - 32, f->path);
    if (n <= 0 || n >= MAX_PATH - 32) { lstrcpyA(f->path, "C:\\"); n = 3; }
    if (f->path[n - 1] != '\\') { f->path[n++] = '\\'; f->path[n] = 0; }
    hex8(num, (GetCurrentProcessId() << 12) ^ (DWORD)InterlockedIncrement(&g_font_seq) ^ GetTickCount());
    lstrcatA(f->path, "KXF"); lstrcatA(f->path, num + 3); lstrcatA(f->path, ".TTF");
    h = CreateFileA(f->path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { HeapFree(GetProcessHeap(), 0, f); return NULL; }
    if (!WriteFile(h, data, size, &w, NULL) || w != size) { CloseHandle(h); DeleteFileA(f->path); HeapFree(GetProcessHeap(), 0, f); return NULL; }
    CloseHandle(h);
    n = add(f->path);
    kex_trace("font: AddFontResource n size", (DWORD)n, size, tag, 0);
    if (n <= 0) { DeleteFileA(f->path); HeapFree(GetProcessHeap(), 0, f); SetLastError(ERROR_INVALID_DATA); return NULL; }
    lock();
    for (i = 0; i < FONT_MAX; i++) if (!g_fonts[i]) { g_fonts[i] = f; slot = i; break; }
    unlock();
    if (slot < 0) { if (rem) rem(f->path); DeleteFileA(f->path); HeapFree(GetProcessHeap(), 0, f); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    f->magic = FONT_MAGIC;
    *count = (DWORD)n;
    return (HANDLE)f;
}

static void drop(KFONT *f)
{
    T_REMFR rem = (T_REMFR)(void *)kex_sysproc("GDI32.DLL", "RemoveFontResourceA");
    if (rem) rem(f->path);
    DeleteFileA(f->path);
    f->magic = 0;
    HeapFree(GetProcessHeap(), 0, f);
}

BOOL KEXAPI kex_RemoveFontMemResourceEx(HANDLE h)
{
    int i; KFONT *f = NULL;
    if (!h) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    lock();
    for (i = 0; i < FONT_MAX; i++) if (g_fonts[i] == (KFONT *)h) { f = g_fonts[i]; g_fonts[i] = NULL; break; }
    unlock();
    if (!f || f->magic != FONT_MAGIC) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    drop(f);
    return TRUE;
}

/* kexnt DLL_PROCESS_DETACH: fonts the program did not remove itself */
void kex_font_detach(void)
{
    int i;
    for (i = 0; i < FONT_MAX; i++) if (g_fonts[i]) { KFONT *f = g_fonts[i]; g_fonts[i] = NULL; if (f->magic == FONT_MAGIC) drop(f); }
}
