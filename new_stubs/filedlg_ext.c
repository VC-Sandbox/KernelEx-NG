/*
 * filedlg_ext.c - KernelEx-NG: the Vista+ file dialogs (IFileOpenDialog / IFileSaveDialog) on Windows 98.
 *
 * Chromium (and most programs built since ~2010) open "Save as" / "Open" through CoCreateInstance(CLSID_File
 * SaveDialog / CLSID_FileOpenDialog) only - Windows 98 has neither class, so "Save as" in Chrome did nothing (and
 * left the window disabled). kexnt answers those two CLSIDs itself with a small COM object that keeps the
 * settings the program makes (file types, folder, name, title, options) and shows the classic dialog in Show():
 * GetSaveFileNameW / GetOpenFileNameW (KernelEx's Unicode versions) or, for FOS_PICKFOLDERS, SHBrowseForFolder.
 * Results come back as IShellItem / IShellItemArray objects that know their file-system path. Also
 * SHCreateItemFromParsingName (used to pass the start folder) returns such an item.
 * Everything else asked of CoCreateInstance goes to the previous implementation unchanged.
 */
#include "kexnt_common.h"

void kex_crashnote(const char *what, DWORD a, DWORD b, DWORD c, DWORD d);   /* crashlog_ext.c */
FARPROC kex_prev_impl(const char *dll, const char *name);                   /* gdiguard_ext.c */
void kex_crashlog_text(const char *s);                                      /* crashlog_ext.c */

#define E_NOINTERFACE_ ((HRESULT)0x80004002L)
#define E_NOTIMPL_     ((HRESULT)0x80004001L)
#define E_FAIL_        ((HRESULT)0x80004005L)
#define E_INVALIDARG_  ((HRESULT)0x80070057L)
#define E_OUTOFMEMORY_ ((HRESULT)0x8007000EL)
#define E_CANCELLED_   ((HRESULT)0x800704C7L)   /* HRESULT_FROM_WIN32(ERROR_CANCELLED) */
#define E_UNEXPECTED_  ((HRESULT)0x8000FFFFL)

static const GUID CLSID_FileOpenDialog_ = {0xDC1C5A9C,0xE88A,0x4DDE,{0xA5,0xA1,0x60,0xF8,0x2A,0x20,0xAE,0xF7}};
static const GUID CLSID_FileSaveDialog_ = {0xC0B4E2F3,0xBA21,0x4773,{0x8D,0xBA,0x33,0x5E,0xC9,0x46,0xEB,0x8B}};
static const GUID IID_IUnknown_       = {0x00000000,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID IID_IModalWindow_   = {0xB4DB1657,0x70D7,0x485E,{0x8E,0x3E,0x6F,0xCB,0x5A,0x5C,0x18,0x02}};
static const GUID IID_IFileDialog_    = {0x42F85136,0xDB7E,0x439C,{0x85,0xF1,0xE4,0x07,0x5D,0x13,0x5F,0xC8}};
static const GUID IID_IFileOpenDialog_= {0xD57C7288,0xD4AD,0x4768,{0xBE,0x02,0x9D,0x96,0x95,0x32,0xD9,0x60}};
static const GUID IID_IFileSaveDialog_= {0x84BCCD23,0x5FDE,0x4CDB,{0xAE,0xA4,0xAF,0x64,0xB8,0x3D,0x78,0xAB}};
static const GUID IID_IShellItem_     = {0x43826D1E,0xE718,0x42EE,{0xBC,0x55,0xA1,0xE2,0x61,0xC3,0x7B,0xFE}};
static const GUID IID_IShellItemArray_= {0xB63EA76D,0x1F85,0x456F,{0xA1,0x9C,0x48,0x15,0x9E,0xFA,0x85,0x8B}};

static int same(const GUID *a, const GUID *b) { return a && b && !memcmp(a, b, sizeof(GUID)); }
static void *co_alloc_(SIZE_T n) { typedef void *(WINAPI *T)(SIZE_T); T f = (T)(void *)kex_sysproc("OLE32.DLL", "CoTaskMemAlloc"); return f ? f(n) : NULL; }
static void co_free_(void *p) { typedef void (WINAPI *T)(void *); T f = (T)(void *)kex_sysproc("OLE32.DLL", "CoTaskMemFree"); if (f && p) f(p); }
static WCHAR *wdup(const WCHAR *s)
{
    WCHAR *d; int n; if (!s) return NULL;
    n = lstrlenW(s); if (!(d = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR)))) return NULL;
    memcpy(d, s, (n + 1) * sizeof(WCHAR)); return d;
}
static void wfree(WCHAR *s) { if (s) HeapFree(GetProcessHeap(), 0, s); }

/* ============================================ IShellItem ============================================== */
typedef struct SItem { void **vt; LONG ref; WCHAR *path; } SItem;
static void *g_item_vt[8];
static SItem *item_new(const WCHAR *path);
static HRESULT WINAPI si_qi(SItem *t, const GUID *iid, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (same(iid, &IID_IUnknown_) || same(iid, &IID_IShellItem_)) { *out = t; InterlockedIncrement(&t->ref); return S_OK; }
    *out = NULL; return E_NOINTERFACE_;
}
static ULONG WINAPI si_addref(SItem *t) { return (ULONG)InterlockedIncrement(&t->ref); }
static ULONG WINAPI si_release(SItem *t)
{
    LONG r = InterlockedDecrement(&t->ref);
    if (!r) { wfree(t->path); HeapFree(GetProcessHeap(), 0, t); }
    return (ULONG)r;
}
static HRESULT WINAPI si_bind(SItem *t, void *bc, const GUID *bhid, const GUID *riid, void **out) { if (out) *out = NULL; return E_NOTIMPL_; }
static HRESULT WINAPI si_parent(SItem *t, SItem **out)
{
    WCHAR *p; int i, last = -1;
    if (!out) return E_INVALIDARG_;
    *out = NULL;
    if (!(p = wdup(t->path))) return E_OUTOFMEMORY_;
    for (i = 0; p[i]; i++) if (p[i] == '\\') last = i;
    if (last < 0) { wfree(p); return E_FAIL_; }
    p[last == 2 ? 3 : last] = 0;                       /* "C:\" stays a root */
    *out = item_new(p); wfree(p);
    return *out ? S_OK : E_OUTOFMEMORY_;
}
static HRESULT WINAPI si_name(SItem *t, DWORD sigdn, WCHAR **out)
{
    const WCHAR *s = t->path; WCHAR *d; int i, n;
    if (!out) return E_INVALIDARG_;
    if (sigdn == 0 /* SIGDN_NORMALDISPLAY */ || sigdn == 0x80018001 /* PARENTRELATIVEPARSING */ || sigdn == 0x8001C001 /* PARENTRELATIVE */) {
        for (i = 0; t->path[i]; i++) if (t->path[i] == '\\' && t->path[i + 1]) s = t->path + i + 1;
    }
    n = lstrlenW(s);
    if (!(d = (WCHAR *)co_alloc_((n + 1) * sizeof(WCHAR)))) { *out = NULL; return E_OUTOFMEMORY_; }
    memcpy(d, s, (n + 1) * sizeof(WCHAR)); *out = d;
    return S_OK;
}
static HRESULT WINAPI si_attr(SItem *t, DWORD mask, DWORD *out)
{
    DWORD a = 0, fa; char p[MAX_PATH * 2];
    WideCharToMultiByte(CP_ACP, 0, t->path, -1, p, sizeof(p), NULL, NULL);
    fa = GetFileAttributesA(p);
    if (fa != 0xFFFFFFFF) { a |= 0x40000000 /* SFGAO_FILESYSTEM */; if (fa & FILE_ATTRIBUTE_DIRECTORY) a |= 0x20000000 /* SFGAO_FOLDER */ | 0x80000000; }
    if (out) *out = a & mask;
    return (a & mask) == mask ? S_OK : S_FALSE;
}
static HRESULT WINAPI si_compare(SItem *t, SItem *o, DWORD hint, int *order)
{
    WCHAR *op = NULL; HRESULT hr;
    if (!o || !order) return E_INVALIDARG_;
    hr = ((HRESULT (WINAPI *)(void *, DWORD, WCHAR **))o->vt[5])(o, 0x80058000, &op);
    if (FAILED(hr)) return hr;
    *order = lstrcmpiW(t->path, op); co_free_(op);
    return *order ? S_FALSE : S_OK;
}
static SItem *item_new(const WCHAR *path)
{
    SItem *s;
    if (!g_item_vt[0]) {
        g_item_vt[0] = (void *)si_qi; g_item_vt[1] = (void *)si_addref; g_item_vt[2] = (void *)si_release; g_item_vt[3] = (void *)si_bind;
        g_item_vt[4] = (void *)si_parent; g_item_vt[5] = (void *)si_name; g_item_vt[6] = (void *)si_attr; g_item_vt[7] = (void *)si_compare;
    }
    if (!path || !(s = (SItem *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SItem)))) return NULL;
    s->vt = g_item_vt; s->ref = 1;
    if (!(s->path = wdup(path))) { HeapFree(GetProcessHeap(), 0, s); return NULL; }
    return s;
}
/* path of any IShellItem (ours or someone else's) */
static WCHAR *item_path(void *it)
{
    WCHAR *p = NULL;
    if (!it) return NULL;
    if (*(void ***)it == g_item_vt) return wdup(((SItem *)it)->path);
    if (FAILED(((HRESULT (WINAPI *)(void *, DWORD, WCHAR **))(*(void ***)it)[5])(it, 0x80058000 /* SIGDN_FILESYSPATH */, &p)) || !p) return NULL;
    { WCHAR *d = wdup(p); co_free_(p); return d; }
}

HRESULT KEXAPI kex_SHCreateItemFromParsingName(PCWSTR path, void *bc, const GUID *riid, void **out)
{
    SItem *s; HRESULT hr;
    if (!out) return E_INVALIDARG_;
    *out = NULL;
    if (!path || !path[0]) return E_INVALIDARG_;
    if (!(s = item_new(path))) return E_OUTOFMEMORY_;
    hr = si_qi(s, riid, out); si_release(s);
    return hr;
}

/* ========================================= IShellItemArray ============================================ */
typedef struct SArr { void **vt; LONG ref; int n; SItem **it; } SArr;
static void *g_arr_vt[10];
static HRESULT WINAPI sa_qi(SArr *t, const GUID *iid, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (same(iid, &IID_IUnknown_) || same(iid, &IID_IShellItemArray_)) { *out = t; InterlockedIncrement(&t->ref); return S_OK; }
    *out = NULL; return E_NOINTERFACE_;
}
static ULONG WINAPI sa_addref(SArr *t) { return (ULONG)InterlockedIncrement(&t->ref); }
static ULONG WINAPI sa_release(SArr *t)
{
    LONG r = InterlockedDecrement(&t->ref); int i;
    if (!r) { for (i = 0; i < t->n; i++) si_release(t->it[i]); HeapFree(GetProcessHeap(), 0, t->it); HeapFree(GetProcessHeap(), 0, t); }
    return (ULONG)r;
}
static HRESULT WINAPI sa_notimpl3(SArr *t, void *a, const GUID *b, void **c) { if (c) *c = NULL; return E_NOTIMPL_; }
static HRESULT WINAPI sa_notimpl2(SArr *t, const GUID *a, void **b) { if (b) *b = NULL; return E_NOTIMPL_; }
static HRESULT WINAPI sa_attr(SArr *t, int how, DWORD mask, DWORD *out) { if (out) *out = 0; return E_NOTIMPL_; }
static HRESULT WINAPI sa_count(SArr *t, DWORD *n) { if (!n) return E_INVALIDARG_; *n = (DWORD)t->n; return S_OK; }
static HRESULT WINAPI sa_at(SArr *t, DWORD i, SItem **out)
{
    if (!out) return E_INVALIDARG_;
    if (i >= (DWORD)t->n) { *out = NULL; return E_INVALIDARG_; }
    *out = t->it[i]; si_addref(t->it[i]); return S_OK;
}
static HRESULT WINAPI sa_enum(SArr *t, void **out) { if (out) *out = NULL; return E_NOTIMPL_; }
static SArr *arr_new(int n)
{
    SArr *a;
    if (!g_arr_vt[0]) {
        g_arr_vt[0] = (void *)sa_qi; g_arr_vt[1] = (void *)sa_addref; g_arr_vt[2] = (void *)sa_release; g_arr_vt[3] = (void *)sa_notimpl3;
        g_arr_vt[4] = (void *)sa_notimpl2; g_arr_vt[5] = (void *)sa_notimpl2; g_arr_vt[6] = (void *)sa_attr; g_arr_vt[7] = (void *)sa_count;
        g_arr_vt[8] = (void *)sa_at; g_arr_vt[9] = (void *)sa_enum;
    }
    if (!(a = (SArr *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SArr)))) return NULL;
    if (!(a->it = (SItem **)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (n ? n : 1) * sizeof(SItem *)))) { HeapFree(GetProcessHeap(), 0, a); return NULL; }
    a->vt = g_arr_vt; a->ref = 1;
    return a;
}

/* =========================================== the dialog =============================================== */
typedef struct { LPCWSTR name, spec; } FILTERSPEC_;
typedef struct FDlg {
    void **vt; LONG ref; int save;
    DWORD opts; UINT type_index;
    WCHAR *filter; int filter_len;              /* "desc\0spec\0...\0\0" */
    WCHAR *folder, *deffolder, *name, *title, *defext, *okl;
    SArr *results;
} FDlg;
static void *g_open_vt[29], *g_save_vt[32];

static HRESULT WINAPI fd_qi(FDlg *t, const GUID *iid, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (same(iid, &IID_IUnknown_) || same(iid, &IID_IModalWindow_) || same(iid, &IID_IFileDialog_) ||
        (t->save && same(iid, &IID_IFileSaveDialog_)) || (!t->save && same(iid, &IID_IFileOpenDialog_))) {
        *out = t; InterlockedIncrement(&t->ref); return S_OK;
    }
    *out = NULL; return E_NOINTERFACE_;
}
static ULONG WINAPI fd_addref(FDlg *t) { return (ULONG)InterlockedIncrement(&t->ref); }
static ULONG WINAPI fd_release(FDlg *t)
{
    LONG r = InterlockedDecrement(&t->ref);
    if (!r) {
        if (t->filter) HeapFree(GetProcessHeap(), 0, t->filter);
        wfree(t->folder); wfree(t->deffolder); wfree(t->name); wfree(t->title); wfree(t->defext); wfree(t->okl);
        if (t->results) sa_release(t->results);
        HeapFree(GetProcessHeap(), 0, t);
    }
    return (ULONG)r;
}

typedef struct { DWORD lStructSize; HWND hwndOwner; HINSTANCE hInstance; LPCWSTR lpstrFilter; LPWSTR lpstrCustomFilter;
    DWORD nMaxCustFilter; DWORD nFilterIndex; LPWSTR lpstrFile; DWORD nMaxFile; LPWSTR lpstrFileTitle; DWORD nMaxFileTitle;
    LPCWSTR lpstrInitialDir; LPCWSTR lpstrTitle; DWORD Flags; WORD nFileOffset; WORD nFileExtension; LPCWSTR lpstrDefExt;
    LPARAM lCustData; void *lpfnHook; LPCWSTR lpTemplateName; } OFNW_;
typedef BOOL (WINAPI *T_GFN)(OFNW_ *);
typedef DWORD (WINAPI *T_CDEE)(void);
typedef struct { HWND hwndOwner; void *pidlRoot; LPSTR pszDisplayName; LPCSTR lpszTitle; UINT ulFlags; void *lpfn; LPARAM lParam; int iImage; } BIA_;
typedef void *(WINAPI *T_SHBFF)(BIA_ *);
typedef BOOL (WINAPI *T_SHGPFIL)(void *, LPSTR);

static void set_results(FDlg *t, SArr *a) { if (t->results) sa_release(t->results); t->results = a; }

static HRESULT pick_folder(FDlg *t, HWND owner)
{
    T_SHBFF bff = (T_SHBFF)(void *)kex_sysproc("SHELL32.DLL", "SHBrowseForFolderA");
    T_SHGPFIL gp = (T_SHGPFIL)(void *)kex_sysproc("SHELL32.DLL", "SHGetPathFromIDListA");
    BIA_ bi; char disp[MAX_PATH], path[MAX_PATH], title[256] = ""; void *pidl; WCHAR wp[MAX_PATH]; SArr *a;
    if (!bff || !gp) return E_FAIL_;
    if (t->title) WideCharToMultiByte(CP_ACP, 0, t->title, -1, title, sizeof(title), NULL, NULL);
    memset(&bi, 0, sizeof(bi));
    bi.hwndOwner = owner; bi.pszDisplayName = disp; bi.lpszTitle = title[0] ? title : NULL;
    bi.ulFlags = 0x0001 /* BIF_RETURNONLYFSDIRS */ | 0x0040 /* BIF_NEWDIALOGSTYLE (ignored where unknown) */;
    if (!(pidl = bff(&bi))) return E_CANCELLED_;
    path[0] = 0;
    if (!gp(pidl, path) || !path[0]) { co_free_(pidl); return E_FAIL_; }
    co_free_(pidl);
    MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH);
    if (!(a = arr_new(1)) || !(a->it[0] = item_new(wp))) { if (a) sa_release(a); return E_OUTOFMEMORY_; }
    a->n = 1; set_results(t, a);
    return S_OK;
}

/* build 74: Chrome's Save dialog came up with an EMPTY file name box although kexnt passed the name in lpstrFile
 * ("shown with name images.jpg" in KEXCRASH); kextest's dialog (no folder, no filter) showed it. Whatever Windows 98
 * does with Chrome's settings, a hook puts the suggested name into the box (edt1) once the dialog is ready, and
 * notes what the box held before. */
typedef struct { DWORD lStructSize; HWND hwndOwner; } OFNHDR_;
/* build 75: in Chrome the box was empty AGAIN after we set it at CDN_INITDONE (build 74 log: "held "", set to
 * images.jpg", user saw it empty) - Windows 98 refills/clears it later (folder listing, file type), in a dialog of a
 * helper process that is not in front. So: set it at CDN_INITDONE and again at CDN_FOLDERCHANGE / CDN_TYPECHANGE and
 * from a timer (0.3 s, 1 s, 2.5 s) - each time only while the box is EMPTY, so the user's typing is never
 * overwritten. And bring the dialog to the front (it waited behind Chrome until clicked): Windows 98 lets only the
 * foreground thread do that, so attach to that thread's input for the call. */
static void fd_fill_name(HWND dlg, const char *why)
{
    typedef LONG (WINAPI *T_GWL)(HWND, int); typedef HWND (WINAPI *T_GP)(HWND);
    typedef BOOL (WINAPI *T_SDT)(HWND, int, LPCSTR); typedef UINT (WINAPI *T_GDT)(HWND, int, LPSTR, int);
    T_GWL gwl = (T_GWL)(void *)kex_sysproc("USER32.DLL", "GetWindowLongA");
    T_GP gp = (T_GP)(void *)kex_sysproc("USER32.DLL", "GetParent");
    T_SDT sdt = (T_SDT)(void *)kex_sysproc("USER32.DLL", "SetDlgItemTextA");
    T_GDT gdt = (T_GDT)(void *)kex_sysproc("USER32.DLL", "GetDlgItemTextA");
    const WCHAR *name = gwl ? (const WCHAR *)(ULONG_PTR)gwl(dlg, 8) : NULL;
    HWND top = gp ? gp(dlg) : NULL;
    static LONG nnote;
    if (name && name[0] && top && sdt && gdt) {
        char was[MAX_PATH], a[MAX_PATH], l[2 * MAX_PATH + 100];
        was[0] = 0; gdt(top, 0x480 /* edt1 */, was, MAX_PATH);
        if (was[0]) return;                                  /* something there (ours or the user's): leave it */
        a[0] = 0; WideCharToMultiByte(CP_ACP, 0, name, -1, a, MAX_PATH, NULL, NULL); a[MAX_PATH - 1] = 0;
        sdt(top, 0x480, a);
        if (InterlockedIncrement(&nnote) <= 40) {
            lstrcpyA(l, "--- file dialog: name box was empty ("); lstrcatA(l, why); lstrcatA(l, "), set to \""); lstrcatA(l, a); lstrcatA(l, "\"");
            kex_crashlog_text(l);
        }
    }
}
static void fd_to_front(HWND dlg)
{
    typedef HWND (WINAPI *T_GP)(HWND); typedef HWND (WINAPI *T_GFW)(void); typedef DWORD (WINAPI *T_GWTP)(HWND, LPDWORD);
    typedef BOOL (WINAPI *T_ATI)(DWORD, DWORD, BOOL); typedef BOOL (WINAPI *T_SFW)(HWND); typedef BOOL (WINAPI *T_BWT)(HWND);
    T_GP gp = (T_GP)(void *)kex_sysproc("USER32.DLL", "GetParent");
    T_GFW gfw = (T_GFW)(void *)kex_sysproc("USER32.DLL", "GetForegroundWindow");
    T_GWTP gwtp = (T_GWTP)(void *)kex_sysproc("USER32.DLL", "GetWindowThreadProcessId");
    T_ATI ati = (T_ATI)(void *)kex_sysproc("USER32.DLL", "AttachThreadInput");
    T_SFW sfw = (T_SFW)(void *)kex_sysproc("USER32.DLL", "SetForegroundWindow");
    T_BWT bwt = (T_BWT)(void *)kex_sysproc("USER32.DLL", "BringWindowToTop");
    HWND top = gp ? gp(dlg) : NULL, fg = gfw ? gfw() : NULL;
    DWORD me = GetCurrentThreadId(), ft = (fg && gwtp) ? gwtp(fg, NULL) : 0;
    BOOL att = FALSE, ok = FALSE;
    if (!top || !sfw) return;
    if (ft && ft != me && ati) att = ati(me, ft, TRUE);
    ok = sfw(top); if (bwt) bwt(top);
    if (att) ati(me, ft, FALSE);
    kex_crashnote("file dialog: brought to the front (ok, attached to the foreground thread)", (DWORD)ok, (DWORD)att, 0, 0);
    if (!ok) { void kex_hang_ask_front(HWND w); kex_hang_ask_front(top); }   /* build 81: ask the parent process */
}
static UINT_PTR CALLBACK fd_hook(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    typedef LONG (WINAPI *T_SWL)(HWND, int, LONG); typedef UINT_PTR (WINAPI *T_ST)(HWND, UINT_PTR, UINT, void *);
    typedef BOOL (WINAPI *T_KT)(HWND, UINT_PTR);
    if (msg == 0x0110 /* WM_INITDIALOG */) {
        T_SWL swl = (T_SWL)(void *)kex_sysproc("USER32.DLL", "SetWindowLongA");
        OFNW_ *o = (OFNW_ *)lp;
        if (swl && o) swl(dlg, 8 /* DWL_USER */, (LONG)o->lCustData);
        return 0;
    }
    if (msg == 0x004E /* WM_NOTIFY */ && lp) {
        UINT code = ((NMHDR *)lp)->code;
        if (code == (UINT)-601 /* CDN_INITDONE */) {
            T_ST st = (T_ST)(void *)kex_sysproc("USER32.DLL", "SetTimer");
            fd_fill_name(dlg, "dialog ready");
            fd_to_front(dlg);
            if (st) { st(dlg, 0x4B01, 300, NULL); st(dlg, 0x4B02, 1000, NULL); st(dlg, 0x4B03, 2500, NULL); }
        } else if (code == (UINT)-603 /* CDN_FOLDERCHANGE */) fd_fill_name(dlg, "folder shown");
        else if (code == (UINT)-607 /* CDN_TYPECHANGE */) fd_fill_name(dlg, "file type set");
        return 0;
    }
    if (msg == 0x0113 /* WM_TIMER */ && wp >= 0x4B01 && wp <= 0x4B03) {
        T_KT kt = (T_KT)(void *)kex_sysproc("USER32.DLL", "KillTimer");
        if (kt) kt(dlg, wp);
        fd_fill_name(dlg, wp == 0x4B01 ? "after 0.3 s" : wp == 0x4B02 ? "after 1 s" : "after 2.5 s");
        if (wp == 0x4B01) fd_to_front(dlg);
        return 0;
    }
    return 0;
}

static HRESULT WINAPI fd_show(FDlg *t, HWND owner)
{
    OFNW_ o; WCHAR *buf; const DWORD BUFN = 8192;   /* build 68: KernelEx's W->A wrapper passes nMaxFile*2 bytes to Windows 98's
                                * COMDLG32, which keeps it in 16 bits: 32768 chars -> 65536 -> 0 = FNERR_BUFFERTOOSMALL
                                * on Save (and the suggested name was not shown) */ BOOL ok; T_GFN f; HRESULT hr = S_OK; WCHAR *init;
    static const WCHAR all[] = { 'A','l','l',' ','f','i','l','e','s',0,'*','.','*',0,0 };
    if (t->opts & 0x20 /* FOS_PICKFOLDERS */) {
        hr = pick_folder(t, owner);
        kex_crashnote("file dialog (folder picker): result", (DWORD)hr, (DWORD)(ULONG_PTR)owner, 0, 0);
        return hr;
    }
    f = (T_GFN)(void *)kex_prev_impl("COMDLG32.DLL", t->save ? "GetSaveFileNameW" : "GetOpenFileNameW");
    if (!f) return E_FAIL_;
    if (!(buf = (WCHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFN * sizeof(WCHAR)))) return E_OUTOFMEMORY_;
    if (t->name) lstrcpynW(buf, t->name, BUFN);
    init = t->folder ? t->folder : t->deffolder;
    {   /* build 69: the name box came up empty in Chrome - what were we given? */
        char l[3 * MAX_PATH], a[MAX_PATH];
        lstrcpyA(l, t->save ? "--- file dialog (save) shown with name \"" : "--- file dialog (open) shown with name \"");
        a[0] = 0; if (t->name) WideCharToMultiByte(CP_ACP, 0, t->name, -1, a, MAX_PATH, NULL, NULL); a[MAX_PATH - 1] = 0; lstrcatA(l, t->name ? a : "(none)");
        lstrcatA(l, "\" folder \"");
        a[0] = 0; if (init) WideCharToMultiByte(CP_ACP, 0, init, -1, a, MAX_PATH, NULL, NULL); a[MAX_PATH - 1] = 0; lstrcatA(l, init ? a : "(none)");
        lstrcatA(l, "\" default extension \"");
        a[0] = 0; if (t->defext) WideCharToMultiByte(CP_ACP, 0, t->defext, -1, a, 64, NULL, NULL); a[63] = 0; lstrcatA(l, a); lstrcatA(l, "\"");
        kex_crashlog_text(l);
    }
    memset(&o, 0, sizeof(o));
    o.lStructSize = 76;                          /* OPENFILENAME_SIZE_VERSION_400 - what Windows 98 knows */
    o.hwndOwner = owner;
    o.lpstrFilter = t->filter ? t->filter : all;
    o.nFilterIndex = t->type_index ? t->type_index : 1;
    o.lpstrFile = buf; o.nMaxFile = BUFN;
    o.lpstrInitialDir = init; o.lpstrTitle = t->title; o.lpstrDefExt = t->defext;
    if (t->name && t->name[0]) { o.lpfnHook = (void *)fd_hook; o.lCustData = (LPARAM)t->name; }
    o.Flags = (o.lpfnHook ? 0x20 /* OFN_ENABLEHOOK */ : 0) | 0x00080000 /* OFN_EXPLORER */ | 0x4 /* OFN_HIDEREADONLY */ | 0x8 /* OFN_NOCHANGEDIR */ |
              (t->opts & (0x2 | 0x200 | 0x800 | 0x1000 | 0x2000 | 0x8000 | 0x10000));
    ok = f(&o);
    if (!ok) {
        T_CDEE ce = (T_CDEE)(void *)kex_sysproc("COMDLG32.DLL", "CommDlgExtendedError");
        DWORD e = ce ? ce() : 0;
        kex_crashnote(t->save ? "file dialog (save): cancelled or failed - CommDlgExtendedError, owner" : "file dialog (open): cancelled or failed - CommDlgExtendedError, owner", e, (DWORD)(ULONG_PTR)owner, 0, 0);
        hr = e ? E_FAIL_ : E_CANCELLED_;
    } else {
        SArr *a; int n = 0, i, k;
        t->type_index = o.nFilterIndex;
        /* multi-select: "dir\0name1\0name2\0\0"; single: full path */
        if ((t->opts & 0x200) && buf[lstrlenW(buf) + 1]) {
            WCHAR *p = buf + lstrlenW(buf) + 1;
            for (; *p; p += lstrlenW(p) + 1) n++;
            if ((a = arr_new(n)) != NULL) {
                WCHAR full[MAX_PATH * 2];
                for (p = buf + lstrlenW(buf) + 1, i = 0; *p && i < n; p += lstrlenW(p) + 1, i++) {
                    lstrcpynW(full, buf, MAX_PATH); k = lstrlenW(full);
                    if (k && full[k - 1] != '\\') full[k++] = '\\';
                    lstrcpynW(full + k, p, MAX_PATH);
                    if ((a->it[a->n] = item_new(full)) != NULL) a->n++;
                }
                set_results(t, a);
            } else hr = E_OUTOFMEMORY_;
        } else if ((a = arr_new(1)) != NULL && (a->it[0] = item_new(buf)) != NULL) { a->n = 1; set_results(t, a); }
        else { if (a) sa_release(a); hr = E_OUTOFMEMORY_; }
        kex_crashnote(t->save ? "file dialog (save): file chosen (items, type index)" : "file dialog (open): file(s) chosen (items, type index)",
                      t->results ? (DWORD)t->results->n : 0, t->type_index, 0, 0);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return hr;
}
static HRESULT WINAPI fd_settypes(FDlg *t, UINT n, const FILTERSPEC_ *s)
{
    UINT i; int len = 1; WCHAR *p;
    if (!s && n) return E_INVALIDARG_;
    for (i = 0; i < n; i++) len += lstrlenW(s[i].name ? s[i].name : L"") + lstrlenW(s[i].spec ? s[i].spec : L"") + 2;
    if (t->filter) HeapFree(GetProcessHeap(), 0, t->filter);
    t->filter = NULL;
    if (!n) return S_OK;
    if (!(t->filter = p = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, len * sizeof(WCHAR)))) return E_OUTOFMEMORY_;
    for (i = 0; i < n; i++) {
        const WCHAR *a = s[i].name ? s[i].name : L"", *b = s[i].spec ? s[i].spec : L"";
        lstrcpyW(p, a); p += lstrlenW(a) + 1; lstrcpyW(p, b); p += lstrlenW(b) + 1;
    }
    *p = 0;
    return S_OK;
}
static HRESULT WINAPI fd_settypeindex(FDlg *t, UINT i) { t->type_index = i; return S_OK; }
static HRESULT WINAPI fd_gettypeindex(FDlg *t, UINT *i) { if (!i) return E_INVALIDARG_; *i = t->type_index ? t->type_index : 1; return S_OK; }
static HRESULT WINAPI fd_advise(FDlg *t, void *ev, DWORD *cookie) { if (cookie) *cookie = 1; return S_OK; }   /* events are not sent */
static HRESULT WINAPI fd_unadvise(FDlg *t, DWORD c) { return S_OK; }
static HRESULT WINAPI fd_setopts(FDlg *t, DWORD o) { t->opts = o; return S_OK; }
static HRESULT WINAPI fd_getopts(FDlg *t, DWORD *o) { if (!o) return E_INVALIDARG_; *o = t->opts; return S_OK; }
static HRESULT WINAPI fd_setdeffolder(FDlg *t, void *it) { wfree(t->deffolder); t->deffolder = item_path(it); return S_OK; }
static HRESULT WINAPI fd_setfolder(FDlg *t, void *it) { wfree(t->folder); t->folder = item_path(it); return S_OK; }
static HRESULT WINAPI fd_getfolder(FDlg *t, void **out)
{
    const WCHAR *f = t->folder ? t->folder : t->deffolder;
    if (!out) return E_INVALIDARG_;
    if (!f) { *out = NULL; return E_FAIL_; }
    return (*out = item_new(f)) ? S_OK : E_OUTOFMEMORY_;
}
static HRESULT WINAPI fd_getsel(FDlg *t, void **out) { if (out) *out = NULL; return E_FAIL_; }
static HRESULT WINAPI fd_setname(FDlg *t, LPCWSTR n) { wfree(t->name); t->name = wdup(n); return S_OK; }
static HRESULT WINAPI fd_getname(FDlg *t, WCHAR **out)
{
    int n; if (!out) return E_INVALIDARG_;
    *out = NULL; if (!t->name) return E_FAIL_;
    n = lstrlenW(t->name);
    if (!(*out = (WCHAR *)co_alloc_((n + 1) * sizeof(WCHAR)))) return E_OUTOFMEMORY_;
    memcpy(*out, t->name, (n + 1) * sizeof(WCHAR)); return S_OK;
}
static HRESULT WINAPI fd_settitle(FDlg *t, LPCWSTR s) { wfree(t->title); t->title = wdup(s); return S_OK; }
static HRESULT WINAPI fd_setok(FDlg *t, LPCWSTR s) { wfree(t->okl); t->okl = wdup(s); return S_OK; }
static HRESULT WINAPI fd_setnamelabel(FDlg *t, LPCWSTR s) { return S_OK; }
static HRESULT WINAPI fd_getresult(FDlg *t, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (!t->results || !t->results->n) { *out = NULL; return E_UNEXPECTED_; }
    *out = t->results->it[0]; si_addref(t->results->it[0]); return S_OK;
}
static HRESULT WINAPI fd_addplace(FDlg *t, void *it, int where) { return S_OK; }
static HRESULT WINAPI fd_setdefext(FDlg *t, LPCWSTR e) { wfree(t->defext); t->defext = wdup(e && e[0] == '.' ? e + 1 : e); return S_OK; }
static HRESULT WINAPI fd_close(FDlg *t, HRESULT hr) { return S_OK; }
static HRESULT WINAPI fd_setguid(FDlg *t, const GUID *g) { return S_OK; }
static HRESULT WINAPI fd_clearclient(FDlg *t) { return S_OK; }
static HRESULT WINAPI fd_setfilter(FDlg *t, void *f) { return S_OK; }
/* IFileOpenDialog */
static HRESULT WINAPI fo_getresults(FDlg *t, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (!t->results) { *out = NULL; return E_UNEXPECTED_; }
    *out = t->results; sa_addref(t->results); return S_OK;
}
static HRESULT WINAPI fo_getselected(FDlg *t, void **out) { if (out) *out = NULL; return E_FAIL_; }
/* IFileSaveDialog */
static HRESULT WINAPI fs_saveasitem(FDlg *t, void *it)
{
    WCHAR *p = item_path(it); int i, last = -1;
    if (!p) return S_OK;
    for (i = 0; p[i]; i++) if (p[i] == '\\') last = i;
    if (last >= 0) { wfree(t->name); t->name = wdup(p + last + 1); p[last == 2 ? 3 : last] = 0; wfree(t->folder); t->folder = wdup(p); }
    wfree(p); return S_OK;
}
static HRESULT WINAPI fs_setprops(FDlg *t, void *ps) { return S_OK; }
static HRESULT WINAPI fs_setcollected(FDlg *t, void *l, BOOL b) { return S_OK; }
static HRESULT WINAPI fs_getprops(FDlg *t, void **out) { if (out) *out = NULL; return E_FAIL_; }
static HRESULT WINAPI fs_applyprops(FDlg *t, void *it, void *ps, HWND h, void *sink) { return S_OK; }

static void vt_init(void)
{
    static void *common[27];
    int i;
    if (g_open_vt[0]) return;
    common[0] = (void *)fd_qi; common[1] = (void *)fd_addref; common[2] = (void *)fd_release; common[3] = (void *)fd_show;
    common[4] = (void *)fd_settypes; common[5] = (void *)fd_settypeindex; common[6] = (void *)fd_gettypeindex; common[7] = (void *)fd_advise;
    common[8] = (void *)fd_unadvise; common[9] = (void *)fd_setopts; common[10] = (void *)fd_getopts; common[11] = (void *)fd_setdeffolder;
    common[12] = (void *)fd_setfolder; common[13] = (void *)fd_getfolder; common[14] = (void *)fd_getsel; common[15] = (void *)fd_setname;
    common[16] = (void *)fd_getname; common[17] = (void *)fd_settitle; common[18] = (void *)fd_setok; common[19] = (void *)fd_setnamelabel;
    common[20] = (void *)fd_getresult; common[21] = (void *)fd_addplace; common[22] = (void *)fd_setdefext; common[23] = (void *)fd_close;
    common[24] = (void *)fd_setguid; common[25] = (void *)fd_clearclient; common[26] = (void *)fd_setfilter;
    for (i = 0; i < 27; i++) g_open_vt[i] = g_save_vt[i] = common[i];
    g_open_vt[27] = (void *)fo_getresults; g_open_vt[28] = (void *)fo_getselected;
    g_save_vt[27] = (void *)fs_saveasitem; g_save_vt[28] = (void *)fs_setprops; g_save_vt[29] = (void *)fs_setcollected;
    g_save_vt[30] = (void *)fs_getprops; g_save_vt[31] = (void *)fs_applyprops;
}

/* ============================================ IFileOperation ==========================================
 * build 69: Chromium finishes a download by MOVING the temporary file to its final name through IFileOperation
 * (components/download/internal/common/base_file_win.cc: MoveItem + PerformOperations + GetAnyOperationsAborted).
 * Windows 98 has no such class (CLSID_FileOperation, Vista+) -> "Something went wrong" in the download bubble.
 * A small queue of move / copy / rename / delete operations carried out with the plain file functions. */
static const GUID CLSID_FileOperation_ = {0x3AD05575,0x8857,0x4850,{0x92,0x77,0x11,0xB8,0x5B,0xDB,0x8E,0x09}};
static const GUID IID_IFileOperation_  = {0x947AAB5F,0x0A5C,0x4C13,{0xB4,0xD6,0x4B,0xF7,0x83,0x6F,0xC9,0xF8}};
#define FOP_MAX 16
typedef struct { int kind; WCHAR *src, *dst; } FOpItem;            /* kind 1 move/rename, 2 copy, 3 delete */
typedef struct FOp { void **vt; LONG ref; DWORD flags; int n; FOpItem it[FOP_MAX]; BOOL aborted; } FOp;
static void *g_fop_vt[23];
static HRESULT WINAPI fop_qi(FOp *t, const GUID *iid, void **out)
{
    if (!out) return E_INVALIDARG_;
    if (same(iid, &IID_IUnknown_) || same(iid, &IID_IFileOperation_)) { *out = t; InterlockedIncrement(&t->ref); return S_OK; }
    *out = NULL; return E_NOINTERFACE_;
}
static ULONG WINAPI fop_addref(FOp *t) { return (ULONG)InterlockedIncrement(&t->ref); }
static void fop_clear(FOp *t) { int i; for (i = 0; i < t->n; i++) { wfree(t->it[i].src); wfree(t->it[i].dst); } t->n = 0; }
static ULONG WINAPI fop_release(FOp *t)
{
    LONG r = InterlockedDecrement(&t->ref);
    if (!r) { fop_clear(t); HeapFree(GetProcessHeap(), 0, t); }
    return (ULONG)r;
}
static HRESULT WINAPI fop_advise(FOp *t, void *sink, DWORD *cookie) { if (cookie) *cookie = 1; return S_OK; }
static HRESULT WINAPI fop_ok1(FOp *t, void *a) { return S_OK; }
static HRESULT WINAPI fop_setflags(FOp *t, DWORD f) { t->flags = f; return S_OK; }
static HRESULT WINAPI fop_notimpl1(FOp *t, void *a) { return E_NOTIMPL_; }
static HRESULT WINAPI fop_notimpl2(FOp *t, void *a, void *b) { return E_NOTIMPL_; }
/* dir + "\" + name */
static WCHAR *wjoin(const WCHAR *dir, const WCHAR *name)
{
    int a = lstrlenW(dir), b = lstrlenW(name); WCHAR *d;
    if (!(d = (WCHAR *)HeapAlloc(GetProcessHeap(), 0, (a + b + 2) * sizeof(WCHAR)))) return NULL;
    memcpy(d, dir, a * sizeof(WCHAR));
    if (a && d[a - 1] != '\\') d[a++] = '\\';
    memcpy(d + a, name, (b + 1) * sizeof(WCHAR));
    return d;
}
static const WCHAR *wbase(const WCHAR *p) { const WCHAR *b = p; for (; *p; p++) if (*p == '\\' || *p == '/') b = p + 1; return b; }
static HRESULT fop_add(FOp *t, int kind, WCHAR *src, WCHAR *dst)
{
    if (!src || (kind != 3 && !dst) || t->n >= FOP_MAX) { wfree(src); wfree(dst); return src ? E_OUTOFMEMORY_ : E_INVALIDARG_; }
    t->it[t->n].kind = kind; t->it[t->n].src = src; t->it[t->n].dst = dst; t->n++;
    return S_OK;
}
static HRESULT WINAPI fop_rename(FOp *t, void *item, LPCWSTR newname, void *sink)
{
    WCHAR *src = item_path(item), *dir, *dst; int i, last = -1;
    if (!src || !newname) { wfree(src); return E_INVALIDARG_; }
    if (!(dir = wdup(src))) { wfree(src); return E_OUTOFMEMORY_; }
    for (i = 0; dir[i]; i++) if (dir[i] == '\\') last = i;
    dir[last < 0 ? 0 : last] = 0;
    dst = wjoin(dir, newname); wfree(dir);
    return fop_add(t, 1, src, dst);
}
static HRESULT WINAPI fop_moveorcopy(FOp *t, int kind, void *item, void *folder, LPCWSTR newname)
{
    WCHAR *src = item_path(item), *dir = item_path(folder), *dst;
    if (!src || !dir) { wfree(src); wfree(dir); return E_INVALIDARG_; }
    dst = wjoin(dir, (newname && newname[0]) ? newname : wbase(src)); wfree(dir);
    return fop_add(t, kind, src, dst);
}
static HRESULT WINAPI fop_move(FOp *t, void *item, void *folder, LPCWSTR newname, void *sink) { return fop_moveorcopy(t, 1, item, folder, newname); }
static HRESULT WINAPI fop_copy(FOp *t, void *item, void *folder, LPCWSTR newname, void *sink) { return fop_moveorcopy(t, 2, item, folder, newname); }
static HRESULT WINAPI fop_delete(FOp *t, void *item, void *sink) { return fop_add(t, 3, item_path(item), NULL); }
static HRESULT WINAPI fop_newitem(FOp *t, void *folder, DWORD attrs, LPCWSTR name, LPCWSTR templ, void *sink) { return E_NOTIMPL_; }
static HRESULT WINAPI fop_perform(FOp *t)
{
    int i; HRESULT hr = S_OK;
    if (!t->n) return E_UNEXPECTED_;
    for (i = 0; i < t->n; i++) {
        char a[MAX_PATH], b[MAX_PATH], l[2 * MAX_PATH + 100]; BOOL ok = FALSE; DWORD e = 0, at;
        a[0] = b[0] = 0;
        WideCharToMultiByte(CP_ACP, 0, t->it[i].src, -1, a, MAX_PATH, NULL, NULL); a[MAX_PATH - 1] = 0;
        if (t->it[i].dst) { WideCharToMultiByte(CP_ACP, 0, t->it[i].dst, -1, b, MAX_PATH, NULL, NULL); b[MAX_PATH - 1] = 0; }
        if (t->it[i].kind == 3) { ok = DeleteFileA(a); e = GetLastError(); }
        else {
            if (lstrcmpiA(a, b) == 0) ok = TRUE;
            else {
                /* the shell replaces an existing destination (the program asked without UI) */
                at = GetFileAttributesA(b);
                if (at != 0xFFFFFFFF && !(at & FILE_ATTRIBUTE_DIRECTORY)) {
                    if (at & FILE_ATTRIBUTE_READONLY) SetFileAttributesA(b, at & ~FILE_ATTRIBUTE_READONLY);
                    if (t->it[i].kind == 1) DeleteFileA(b);
                }
                ok = t->it[i].kind == 1 ? MoveFileA(a, b) : CopyFileA(a, b, FALSE);
                e = GetLastError();
                if (!ok && t->it[i].kind == 1) {            /* another drive, or a sharing problem: copy, then delete */
                    ok = CopyFileA(a, b, FALSE); e = GetLastError();
                    if (ok) { at = GetFileAttributesA(a); if (at != 0xFFFFFFFF && (at & FILE_ATTRIBUTE_READONLY)) SetFileAttributesA(a, at & ~FILE_ATTRIBUTE_READONLY); DeleteFileA(a); }
                }
            }
        }
        lstrcpyA(l, t->it[i].kind == 1 ? "--- IFileOperation move " : t->it[i].kind == 2 ? "--- IFileOperation copy " : "--- IFileOperation delete ");
        lstrcatA(l, ok ? "ok  " : "FAILED  "); lstrcatA(l, a); if (b[0]) { lstrcatA(l, " -> "); lstrcatA(l, b); }
        kex_crashlog_text(l);
        if (!ok) { kex_crashnote("IFileOperation: operation failed (kind 1 move 2 copy 3 delete, error)", (DWORD)t->it[i].kind, e, 0, 0); t->aborted = TRUE; hr = (HRESULT)(0x80070000 | (e & 0xFFFF)); break; }
    }
    fop_clear(t);
    return hr;
}
static HRESULT WINAPI fop_aborted(FOp *t, BOOL *out) { if (!out) return E_INVALIDARG_; *out = t->aborted; return S_OK; }
static HRESULT fop_new(const GUID *riid, void **out)
{
    FOp *t; HRESULT hr;
    if (!g_fop_vt[0]) {
        g_fop_vt[0] = (void *)fop_qi; g_fop_vt[1] = (void *)fop_addref; g_fop_vt[2] = (void *)fop_release;
        g_fop_vt[3] = (void *)fop_advise;      /* Advise */
        g_fop_vt[4] = (void *)fop_ok1;         /* Unadvise */
        g_fop_vt[5] = (void *)fop_setflags;    /* SetOperationFlags */
        g_fop_vt[6] = (void *)fop_ok1;         /* SetProgressMessage */
        g_fop_vt[7] = (void *)fop_ok1;         /* SetProgressDialog */
        g_fop_vt[8] = (void *)fop_ok1;         /* SetProperties */
        g_fop_vt[9] = (void *)fop_ok1;         /* SetOwnerWindow */
        g_fop_vt[10] = (void *)fop_ok1;        /* ApplyPropertiesToItem */
        g_fop_vt[11] = (void *)fop_ok1;        /* ApplyPropertiesToItems */
        g_fop_vt[12] = (void *)fop_rename;     /* RenameItem */
        g_fop_vt[13] = (void *)fop_notimpl2;   /* RenameItems */
        g_fop_vt[14] = (void *)fop_move;       /* MoveItem */
        g_fop_vt[15] = (void *)fop_notimpl2;   /* MoveItems */
        g_fop_vt[16] = (void *)fop_copy;       /* CopyItem */
        g_fop_vt[17] = (void *)fop_notimpl2;   /* CopyItems */
        g_fop_vt[18] = (void *)fop_delete;     /* DeleteItem */
        g_fop_vt[19] = (void *)fop_notimpl1;   /* DeleteItems */
        g_fop_vt[20] = (void *)fop_newitem;    /* NewItem */
        g_fop_vt[21] = (void *)fop_perform;    /* PerformOperations */
        g_fop_vt[22] = (void *)fop_aborted;    /* GetAnyOperationsAborted */
    }
    if (!(t = (FOp *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FOp)))) return E_OUTOFMEMORY_;
    t->vt = g_fop_vt; t->ref = 1;
    hr = fop_qi(t, riid, out); fop_release(t);
    return hr;
}

static HRESULT dialog_new(int save, const GUID *riid, void **out)
{
    FDlg *d; HRESULT hr;
    vt_init();
    if (!(d = (FDlg *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FDlg)))) return E_OUTOFMEMORY_;
    d->vt = save ? g_save_vt : g_open_vt; d->ref = 1; d->save = save;
    d->opts = save ? (0x2 | 0x800 | 0x8 | 0x40) : (0x800 | 0x1000 | 0x8 | 0x40);   /* Windows' defaults */
    hr = fd_qi(d, riid, out); fd_release(d);
    return hr;
}

typedef HRESULT (WINAPI *T_CCI)(const GUID *, void *, DWORD, const GUID *, void **);
extern const GUID kex_CLSID_ApplicationAssociationRegistration;   /* assoc_ext.c */
HRESULT kex_assocreg_new(const GUID *riid, void **out);
extern const GUID kex_CLSID_ShellLink;   /* assoc_ext.c */
HRESULT kex_shelllink_wrap(void *real, const GUID *riid, void **out);
HRESULT KEXAPI kex_CoCreateInstance(const GUID *clsid, void *outer, DWORD ctx, const GUID *riid, void **out)
{
    static T_CCI prev;
    int save = same(clsid, &CLSID_FileSaveDialog_);
    {   /* build 59: Save As in Chrome left no note at all - log every class asked for (first 60 calls) */
        static LONG nall; if (clsid && InterlockedIncrement(&nall) <= 60)
            kex_crashnote("CoCreateInstance (CLSID first 3 parts, context, thread)", clsid->Data1, ((DWORD)clsid->Data2 << 16) | clsid->Data3, ctx, GetCurrentThreadId());
    }
    if (save || same(clsid, &CLSID_FileOpenDialog_)) {
        HRESULT hr;
        if (!out) return E_INVALIDARG_;
        *out = NULL;
        if (outer) return (HRESULT)0x80040110L;   /* CLASS_E_NOAGGREGATION */
        hr = dialog_new(save, riid, out);
        { static LONG n; if (InterlockedIncrement(&n) <= 20) kex_crashnote(save ? "file dialog: Save dialog object made by kexnt (result)" : "file dialog: Open dialog object made by kexnt (result)", (DWORD)hr, 0, 0, 0); }
        return hr;
    }
    if (same(clsid, &kex_CLSID_ShellLink) && !outer && out) {           /* build 132: assoc_ext.c, IPropertyStore */
        static T_CCI prev2; void *real = NULL; HRESULT hr;
        if (!prev2) prev2 = (T_CCI)(void *)kex_prev_impl("OLE32.DLL", "CoCreateInstance");
        if (prev2 && (void *)prev2 != (void *)kex_CoCreateInstance &&
            SUCCEEDED(hr = prev2(clsid, NULL, ctx, &IID_IUnknown_, (void **)&real)) && real)
            return kex_shelllink_wrap(real, riid, out);
    }
    if (same(clsid, &kex_CLSID_ApplicationAssociationRegistration)) {   /* build 132: assoc_ext.c */
        if (!out) return E_INVALIDARG_;
        *out = NULL;
        if (outer) return (HRESULT)0x80040110L;
        return kex_assocreg_new(riid, out);
    }
    if (same(clsid, &CLSID_FileOperation_)) {
        HRESULT hr;
        if (!out) return E_INVALIDARG_;
        *out = NULL;
        if (outer) return (HRESULT)0x80040110L;
        hr = fop_new(riid, out);
        { static LONG n; if (InterlockedIncrement(&n) <= 10) kex_crashnote("IFileOperation object made by kexnt (result)", (DWORD)hr, 0, 0, 0); }
        return hr;
    }
    if (!prev) prev = (T_CCI)(void *)kex_prev_impl("OLE32.DLL", "CoCreateInstance");
    if (!prev || (void *)prev == (void *)kex_CoCreateInstance) return REGDB_E_CLASSNOTREG;
    {   HRESULT hr = prev(clsid, outer, ctx, riid, out);
        /* build 131: Windows 98's OLE32 refuses class contexts it does not know (REMOTE_SERVER without DCOM, the
         * Windows 2000+ flags): .NET 4's setup asks for MSXML's DOMDocument30 with 0x17 and stopped with 5100.
         * Retry with the in-process and local-server bits only. */
        if (FAILED(hr) && (ctx & ~0x7UL) && (ctx & 0x7)) {
            HRESULT h2 = prev(clsid, outer, ctx & 0x7, riid, out);
            static LONG n; if (InterlockedIncrement(&n) <= 20) kex_crashnote("CoCreateInstance: retried without the context bits Windows 98 does not know (first result, context, second result)", (DWORD)hr, ctx, (DWORD)h2, 0);
            hr = h2;
        } else if (FAILED(hr)) { static LONG nf; if (InterlockedIncrement(&nf) <= 20) kex_crashnote("CoCreateInstance FAILED (result, context, CLSID first part)", (DWORD)hr, ctx, clsid ? clsid->Data1 : 0, 0); }
        return hr;
    }
}
