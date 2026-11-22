/*
 * kexaudio.c - KEXAUDIO.DLL: the Windows Vista+ Core Audio API (MMDevice API + WASAPI shared mode) for Windows 98 SE,
 * implemented on top of waveOut / waveIn. KernelEx-NG (build 39; capture, loopback and volume interfaces build 128).
 *
 * Modern programs (Chromium's media/audio/win, many games and players) only know Core Audio: they CoCreateInstance
 * CLSID_MMDeviceEnumerator, take the default endpoint, Activate an IAudioClient, Initialize it in shared mode (event
 * driven), and move data through IAudioRenderClient / IAudioCaptureClient. Win98 has no MMDevAPI. This DLL is our own
 * implementation of that documented interface set (written from the public SDK headers and MSDN semantics),
 * registered as the in-process server of CLSID_MMDeviceEnumerator; there is no Microsoft code in it.
 *
 * Endpoints:
 *   render  "Speakers (<waveOut device>)"   - waveOut, when waveOutGetNumDevs() > 0
 *   capture "Microphone (<waveIn device>)"  - waveIn,  when waveInGetNumDevs() > 0 (build 128)
 * Interfaces: IMMDeviceEnumerator, IMMDeviceCollection, IMMDevice, IMMEndpoint, IPropertyStore, IAudioEndpointVolume,
 *   IAudioClient (shared mode; float32 or PCM16, 1-2 channels), IAudioRenderClient, IAudioCaptureClient, IAudioClock,
 *   ISimpleAudioVolume; ActivateAudioInterfaceAsync for process loopback (exported, MMDEVAPI.DLL #17 forwards here).
 *
 * Render: mix format = 32-bit float stereo at the device rate (48000/44100...); the client must use that rate (as on
 *   Windows without AUTOCONVERTPCM). One engine thread per client moves ring data into waveOut blocks.
 * Capture (build 128): waveIn at a rate/channel count the device takes, converted (linear resampling, channel up/down
 *   mix) to whatever rate and channel count the client asked for; packets of 10 ms; event every packet.
 * Loopback (build 128) = "what is playing": every render client in every process also writes what it plays into a
 *   system-wide shared "bus" (KXAUDIO_BUS: one 16-bit stereo ring per process, blocks tagged with their position on a
 *   common clock = timeGetTime x rate). A loopback client (render endpoint + AUDCLNT_STREAMFLAGS_LOOPBACK, or a
 *   process-loopback client from ActivateAudioInterfaceAsync with include/exclude-process-tree) reads the bus 60 ms
 *   behind real time and sums the processes it wants. Only sound that goes through KEXAUDIO is seen (modern programs);
 *   plain waveOut/DirectSound programs are not - Windows 98 has no system mixer tap.
 * No SSE: built with -mno-sse like the rest of KernelEx-NG (86Box CPUs).
 */
#define COBJMACROS
#define CINTERFACE
#include <windows.h>
#include <mmsystem.h>
#include <objbase.h>
#include <mmreg.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <endpointvolume.h>
#include <propsys.h>
#include <tlhelp32.h>

/* ------------------------------------------------------------------ GUIDs (from the SDK headers' declarations) */
static const GUID kCLSID_MMDeviceEnumerator = {0xBCDE0395,0xE52F,0x467C,{0x8E,0x3D,0xC4,0x57,0x92,0x91,0x69,0x2E}};
static const GUID kIID_IUnknown           = {0x00000000,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID kIID_IClassFactory      = {0x00000001,0x0000,0x0000,{0xC0,0x00,0x00,0x00,0x00,0x00,0x00,0x46}};
static const GUID kIID_IMMDeviceEnumerator= {0xA95664D2,0x9614,0x4F35,{0xA7,0x46,0xDE,0x8D,0xB6,0x36,0x17,0xE6}};
static const GUID kIID_IMMDeviceCollection= {0x0BD7A1BE,0x7A1A,0x44DB,{0x83,0x97,0xCC,0x53,0x92,0x38,0x7B,0x5E}};
static const GUID kIID_IMMDevice          = {0xD666063F,0x1587,0x4E43,{0x81,0xF1,0xB9,0x48,0xE8,0x07,0x36,0x3F}};
static const GUID kIID_IMMEndpoint        = {0x1BE09788,0x6894,0x4089,{0x85,0x86,0x9A,0x2A,0x6C,0x26,0x5A,0xC5}};
static const GUID kIID_IPropertyStore     = {0x886D8EEB,0x8CF2,0x4446,{0x8D,0x02,0xCD,0xBA,0x1D,0xBD,0xCF,0x99}};
static const GUID kIID_IAudioClient       = {0x1CB9AD4C,0xDBFA,0x4C32,{0xB1,0x78,0xC2,0xF5,0x68,0xA7,0x03,0xB2}};
static const GUID kIID_IAudioRenderClient = {0xF294ACFC,0x3146,0x4483,{0xA7,0xBF,0xAD,0xDC,0xA7,0xC2,0x60,0xE2}};
static const GUID kIID_IAudioCaptureClient= {0xC8ADBD64,0xE71E,0x48A0,{0xA4,0xDE,0x18,0x5C,0x39,0x5C,0xD3,0x17}};
static const GUID kIID_IAudioClock        = {0xCD63314F,0x3FBA,0x4A1B,{0x81,0x2C,0xEF,0x96,0x35,0x87,0x28,0xE7}};
static const GUID kIID_ISimpleAudioVolume = {0x87CE5498,0x68D6,0x44E5,{0x92,0x15,0x6D,0xA4,0x7E,0xF8,0x83,0xD8}};
static const GUID kIID_IAudioEndpointVolume={0x5CDF2C82,0x841E,0x4546,{0x97,0x22,0x0C,0xF7,0x40,0x78,0x22,0x9A}};
static const GUID kIID_IActivateOp        = {0x72A22D78,0xCDE4,0x431D,{0xB8,0xCC,0x84,0x3A,0x71,0x19,0x9B,0x6D}};
static const GUID kIID_IAgileObject       = {0x94EA2B94,0xE9CC,0x49E0,{0xC0,0xFF,0xEE,0x64,0xCA,0x8F,0x5B,0x90}};
static const GUID kKSDATAFORMAT_PCM       = {0x00000001,0x0000,0x0010,{0x80,0x00,0x00,0xAA,0x00,0x38,0x9B,0x71}};
static const GUID kKSDATAFORMAT_FLOAT     = {0x00000003,0x0000,0x0010,{0x80,0x00,0x00,0xAA,0x00,0x38,0x9B,0x71}};
static const GUID kPKEY_DeviceFmtid       = {0xA45C254E,0xDF1C,0x4EFD,{0x80,0x20,0x67,0xD1,0x46,0xA8,0x50,0xE0}};
#define PID_FRIENDLYNAME 14
#define PID_DEVICEDESC    2

#define K_E_NOTFOUND        ((HRESULT)0x80070490L)          /* HRESULT_FROM_WIN32(ERROR_NOT_FOUND) */
#define K_NOT_INITIALIZED   ((HRESULT)0x88890001L)
#define K_ALREADY_INIT      ((HRESULT)0x88890002L)
#define K_WRONG_TYPE        ((HRESULT)0x88890003L)
#define K_DEVICE_INVALID    ((HRESULT)0x88890004L)
#define K_NOT_STOPPED       ((HRESULT)0x88890005L)
#define K_BUFFER_TOO_LARGE  ((HRESULT)0x88890006L)
#define K_OUT_OF_ORDER      ((HRESULT)0x88890007L)
#define K_UNSUPPORTED_FMT   ((HRESULT)0x88890008L)
#define K_INVALID_SIZE      ((HRESULT)0x88890009L)
#define K_EXCLUSIVE_NA      ((HRESULT)0x8889000EL)
#define K_EVENT_NOT_SET     ((HRESULT)0x88890014L)
#define K_S_BUFFER_EMPTY    ((HRESULT)0x08890001L)

static HINSTANCE g_inst;
static const WCHAR g_dev_id[]  = L"{0.0.0.00000000}.{6b6e7865-6175-6469-6f00-776176656f75}";   /* "kexaudio waveou" */
static const WCHAR g_cdev_id[] = L"{0.0.1.00000000}.{6b6e7865-6175-6469-6f00-776176656969}";   /* "kexaudio waveii" */

static int wlen(const WCHAR *s) { int n = 0; while (s[n]) n++; return n; }   /* lstrlenW/lstrcmpiW are stubs on 98 */
static int wieq(const WCHAR *a, const WCHAR *b)
{
    for (;; a++, b++) {
        WCHAR x = *a, y = *b;
        if (x >= 'a' && x <= 'z') x -= 32;
        if (y >= 'a' && y <= 'z') y -= 32;
        if (x != y) return 0;
        if (!x) return 1;
    }
}
static int wcontains(const WCHAR *s, const WCHAR *sub)          /* case-insensitive */
{
    int n = wlen(sub), i, j;
    for (i = 0; s[i]; i++) {
        for (j = 0; j < n && s[i + j]; j++) {
            WCHAR x = s[i + j], y = sub[j];
            if (x >= 'a' && x <= 'z') x -= 32;
            if (y >= 'a' && y <= 'z') y -= 32;
            if (x != y) break;
        }
        if (j == n) return 1;
    }
    return 0;
}
static BOOL same_guid(REFGUID a, const GUID *b) { return !memcmp(a, b, sizeof(GUID)); }

/* ------------------------------------------------------------------ small log (C:\WINDOWS\TEMP\KEXAUDIO.LOG, 256 KB max) */
static void alog(const char *f, ...)
{
    char b[600], path[MAX_PATH]; int n; va_list a; HANDLE h; DWORD w; SYSTEMTIME t; static LONG lines;
    if (InterlockedIncrement(&lines) > 400) return;
    GetLocalTime(&t);
    n = wsprintfA(b, "%02u:%02u:%02u.%03u %08lx ", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds, GetCurrentProcessId());
    va_start(a, f); n += wvsprintfA(b + n, f, a); va_end(a);
    b[n++] = '\r'; b[n++] = '\n';
    if (!GetTempPathA(MAX_PATH - 20, path)) return;
    lstrcatA(path, "KEXAUDIO.LOG");
    h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    if (GetFileSize(h, NULL) < 256 * 1024) { SetFilePointer(h, 0, NULL, FILE_END); WriteFile(h, b, n, &w, NULL); }
    CloseHandle(h);
}

/* ------------------------------------------------------------------ mix formats */
static DWORD g_rate; static UINT g_wdev = WAVE_MAPPER; static DWORD g_open_flags;
static DWORD g_crate; static WORD g_cch;
/* build 39c: pick a rate the card takes WITHOUT conversion (WAVE_FORMAT_DIRECT on device 0) */
static BOOL query(UINT dev, DWORD rate, DWORD flags)
{
    WAVEFORMATEX f; f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = 2; f.wBitsPerSample = 16; f.cbSize = 0;
    f.nSamplesPerSec = rate; f.nBlockAlign = 4; f.nAvgBytesPerSec = rate * 4;
    return waveOutOpen(NULL, dev, &f, 0, 0, WAVE_FORMAT_QUERY | flags) == MMSYSERR_NOERROR;
}
static void mix_rate(void)
{
    static const DWORD rates[] = { 48000, 44100, 32000, 22050 };
    int i;
    if (g_rate) return;
    if (waveOutGetNumDevs() > 0)
        for (i = 0; i < 4; i++)
            if (query(0, rates[i], WAVE_FORMAT_DIRECT)) { g_rate = rates[i]; g_wdev = 0; g_open_flags = WAVE_FORMAT_DIRECT; return; }
    g_wdev = WAVE_MAPPER; g_open_flags = 0;
    g_rate = query(WAVE_MAPPER, 48000, 0) ? 48000 : 44100;
}
static BOOL in_query(DWORD rate, WORD ch)
{
    WAVEFORMATEX f; f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = ch; f.wBitsPerSample = 16; f.cbSize = 0;
    f.nSamplesPerSec = rate; f.nBlockAlign = (WORD)(ch * 2); f.nAvgBytesPerSec = rate * ch * 2;
    return waveInOpen(NULL, WAVE_MAPPER, &f, 0, 0, WAVE_FORMAT_QUERY) == MMSYSERR_NOERROR;
}
static void cap_rate(void)                       /* the capture endpoint's own format (what waveIn takes) */
{
    static const DWORD rates[] = { 48000, 44100, 32000, 22050, 16000, 11025, 8000 };
    int i, c;
    if (g_crate) return;
    for (c = 2; c >= 1 && !g_crate; c--)
        for (i = 0; i < 7; i++) if (in_query(rates[i], (WORD)c)) { g_crate = rates[i]; g_cch = (WORD)c; break; }
    if (!g_crate) { g_crate = 44100; g_cch = 2; }
}
static void fill_fmt(WAVEFORMATEXTENSIBLE *x, DWORD rate, WORD ch)
{
    memset(x, 0, sizeof(*x));
    x->Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE;
    x->Format.nChannels = ch;
    x->Format.nSamplesPerSec = rate;
    x->Format.wBitsPerSample = 32;
    x->Format.nBlockAlign = (WORD)(4 * ch);
    x->Format.nAvgBytesPerSec = rate * 4 * ch;
    x->Format.cbSize = sizeof(WAVEFORMATEXTENSIBLE) - sizeof(WAVEFORMATEX);
    x->Samples.wValidBitsPerSample = 32;
    x->dwChannelMask = ch == 1 ? SPEAKER_FRONT_CENTER : (SPEAKER_FRONT_LEFT | SPEAKER_FRONT_RIGHT);
    x->SubFormat = kKSDATAFORMAT_FLOAT;
}
static void fill_mix(WAVEFORMATEXTENSIBLE *x) { mix_rate(); fill_fmt(x, g_rate, 2); }
static void fill_cmix(WAVEFORMATEXTENSIBLE *x) { cap_rate(); fill_fmt(x, g_crate, 2); }   /* stereo: we up/down-mix */
/* 1 = float32, 2 = PCM16, 0 = not something we take. rate_any: capture side resamples, any sane rate */
static int fmt_kind2(const WAVEFORMATEX *f, BOOL rate_any)
{
    mix_rate();
    if (!f || f->nChannels < 1 || f->nChannels > 2) return 0;
    if (rate_any ? (f->nSamplesPerSec < 8000 || f->nSamplesPerSec > 192000) : f->nSamplesPerSec != g_rate) return 0;
    if (f->wFormatTag == WAVE_FORMAT_IEEE_FLOAT && f->wBitsPerSample == 32) return 1;
    if (f->wFormatTag == WAVE_FORMAT_PCM && f->wBitsPerSample == 16) return 2;
    if (f->wFormatTag == WAVE_FORMAT_EXTENSIBLE && f->cbSize >= 22) {
        const WAVEFORMATEXTENSIBLE *x = (const WAVEFORMATEXTENSIBLE *)f;
        if (same_guid(&x->SubFormat, &kKSDATAFORMAT_FLOAT) && f->wBitsPerSample == 32) return 1;
        if (same_guid(&x->SubFormat, &kKSDATAFORMAT_PCM) && f->wBitsPerSample == 16) return 2;
    }
    return 0;
}
static WCHAR *co_wstr(const WCHAR *s)
{
    int n = wlen(s) + 1; WCHAR *r = (WCHAR *)CoTaskMemAlloc(n * sizeof(WCHAR));
    if (r) memcpy(r, s, n * sizeof(WCHAR));
    return r;
}
static BOOL have_device(void) { return waveOutGetNumDevs() > 0; }
static BOOL have_capture(void) { return waveInGetNumDevs() > 0; }
static ULONGLONG qpc100(void)
{
    LARGE_INTEGER c, f;
    if (QueryPerformanceFrequency(&f) && f.QuadPart && QueryPerformanceCounter(&c))
        return (ULONGLONG)((double)c.QuadPart * 10000000.0 / (double)f.QuadPart);
    return (ULONGLONG)GetTickCount() * 10000;
}
static short sat16(LONG v) { return v > 32767 ? 32767 : v < -32768 ? -32768 : (short)v; }

/* ================================================================== the loopback bus (shared by all processes) */
#define BUS_SLOTS 4
#define BUS_BF    256                  /* frames per block */
#define BUS_NB    256                  /* blocks per ring: 65536 frames = 1.36 s at 48 kHz */
#define BUS_MAGIC 0x5355424BUL         /* "KBUS" */
typedef struct {
    DWORD pid, anc[4];                 /* the writing process and up to 4 of its ancestors (process tree) */
    DWORD tag[BUS_NB];                 /* absolute block number held by each block (else: silence) */
    short d[BUS_NB * BUS_BF * 2];
} BUSSLOT;
typedef struct {
    DWORD magic, rate; volatile LONG lock; volatile LONG mute; volatile LONG vol;   /* vol: 0..1000 (render endpoint) */
    volatile LONG cvol, cmute;                                                        /* capture endpoint */
    BUSSLOT s[BUS_SLOTS];
} BUS;
static BUS *g_bus; static int g_slot = -1;
static BUS *bus(void)
{
    if (!g_bus) {
        HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(BUS), "KXAUDIO_BUS");
        BUS *b;
        if (!m) return NULL;
        b = (BUS *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
        if (!b) { CloseHandle(m); return NULL; }        /* the mapping handle stays open for the life of the process */
        mix_rate();
        if (InterlockedCompareExchange((LONG *)&b->magic, BUS_MAGIC, 0) == 0) { b->rate = g_rate; b->vol = 1000; b->cvol = 1000; }
        g_bus = b;
    }
    return g_bus;
}
static void bus_lock(BUS *b) { int k = 0; while (InterlockedCompareExchange(&b->lock, 1, 0)) { if (++k > 50) Sleep(1); else Sleep(0); } }
static void bus_unlock(BUS *b) { InterlockedExchange(&b->lock, 0); }
static ULONGLONG bus_now(BUS *b) { return (ULONGLONG)timeGetTime() * b->rate / 1000; }
static BOOL pid_alive(DWORD pid)
{
    HANDLE h; DWORD code = 0;
    if (!pid) return FALSE;
    if (pid == GetCurrentProcessId()) return TRUE;
    if (!(h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid))) return FALSE;
    if (!GetExitCodeProcess(h, &code)) code = STILL_ACTIVE;
    CloseHandle(h);
    return code == STILL_ACTIVE;
}
static void ancestors(DWORD pid, DWORD *anc)
{
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); PROCESSENTRY32 e; int k; DWORD cur = pid;
    memset(anc, 0, 4 * sizeof(DWORD));
    if (s == INVALID_HANDLE_VALUE) return;
    for (k = 0; k < 4 && cur; k++) {
        DWORD parent = 0;
        e.dwSize = sizeof(e);
        if (Process32First(s, &e)) do { if (e.th32ProcessID == cur) { parent = e.th32ParentProcessID; break; } } while (Process32Next(s, &e));
        anc[k] = parent; cur = parent;
    }
    CloseHandle(s);
}
static BUSSLOT *my_slot(BUS *b)                  /* bus locked */
{
    DWORD me = GetCurrentProcessId(); int i, free_i = -1;
    if (g_slot >= 0 && b->s[g_slot].pid == me) return &b->s[g_slot];
    for (i = 0; i < BUS_SLOTS; i++) if (b->s[i].pid == me) { g_slot = i; return &b->s[i]; }
    for (i = 0; i < BUS_SLOTS && free_i < 0; i++) if (!b->s[i].pid) free_i = i;
    for (i = 0; i < BUS_SLOTS && free_i < 0; i++) if (!pid_alive(b->s[i].pid)) free_i = i;
    if (free_i < 0) return NULL;                  /* more than 4 processes playing: this one is not heard by loopback */
    memset(b->s[free_i].tag, 0xFF, sizeof(b->s[free_i].tag));
    b->s[free_i].pid = me; ancestors(me, b->s[free_i].anc);
    g_slot = free_i;
    return &b->s[free_i];
}
/* a render stream writes n frames (ch channels, 16-bit) that will be heard at bus position pos */
static void bus_write(ULONGLONG pos, const short *d, UINT32 n, UINT32 ch)
{
    BUS *b = bus(); BUSSLOT *s; UINT32 i;
    if (!b || b->rate != g_rate) return;
    bus_lock(b);
    if ((s = my_slot(b)) != NULL)
        for (i = 0; i < n; i++, pos++) {
            DWORD blk = (DWORD)(pos / BUS_BF), bi = blk % BUS_NB, off = (DWORD)(pos % BUS_BF);
            short *o;
            if (s->tag[bi] != blk) { memset(s->d + bi * BUS_BF * 2, 0, BUS_BF * 4); s->tag[bi] = blk; }
            o = s->d + (bi * BUS_BF + off) * 2;
            if (ch == 1) { o[0] = sat16((LONG)o[0] + d[i]); o[1] = sat16((LONG)o[1] + d[i]); }
            else { o[0] = sat16((LONG)o[0] + d[2 * i]); o[1] = sat16((LONG)o[1] + d[2 * i + 1]); }
        }
    bus_unlock(b);
}
/* mode 0: every process; 1: only target's tree; 2: all but target's tree */
static BOOL slot_wanted(const BUSSLOT *s, DWORD target, int mode)
{
    BOOL in = FALSE; int k;
    if (!s->pid) return FALSE;
    if (!mode) return TRUE;
    if (s->pid == target) in = TRUE;
    for (k = 0; k < 4 && !in; k++) if (s->anc[k] && s->anc[k] == target) in = TRUE;
    return mode == 1 ? in : !in;
}
static void bus_read(ULONGLONG pos, short *out, UINT32 n, DWORD target, int mode)   /* stereo out */
{
    BUS *b = bus(); UINT32 i; int k;
    LONG *acc = (LONG *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n * 2 * sizeof(LONG));
    if (!acc) { memset(out, 0, n * 4); return; }
    if (b) {
        bus_lock(b);
        for (k = 0; k < BUS_SLOTS; k++) {
            const BUSSLOT *s = &b->s[k];
            if (!slot_wanted(s, target, mode)) continue;
            for (i = 0; i < n; i++) {
                ULONGLONG p = pos + i; DWORD blk = (DWORD)(p / BUS_BF), bi = blk % BUS_NB;
                if (s->tag[bi] == blk) { const short *x = s->d + (bi * BUS_BF + (DWORD)(p % BUS_BF)) * 2; acc[2 * i] += x[0]; acc[2 * i + 1] += x[1]; }
            }
        }
        bus_unlock(b);
    }
    for (i = 0; i < 2 * n; i++) out[i] = sat16(acc[i]);
    HeapFree(GetProcessHeap(), 0, acc);
}

/* ================================================================== IAudioClient + render/capture/clock/volume */
#define NBLK 8          /* waveOut / waveIn headers */
#define NQ   4          /* render: at most this many in flight (4 x 20 ms) */
enum { F_RENDER, F_CAPTURE, F_LOOPBACK };
typedef struct CLIENT CLIENT;
typedef struct { IAudioRenderClientVtbl *vt; CLIENT *c; } RENDER;
typedef struct { IAudioCaptureClientVtbl *vt; CLIENT *c; } CAPT;
typedef struct { IAudioClockVtbl *vt; CLIENT *c; } CLOCK;
typedef struct { ISimpleAudioVolumeVtbl *vt; CLIENT *c; } SVOL;
struct CLIENT {
    IAudioClientVtbl *vt;
    RENDER render; CAPT capt; CLOCK clock; SVOL svol;
    volatile LONG ref;
    CRITICAL_SECTION cs;
    int flow;                                  /* F_RENDER / F_CAPTURE / F_LOOPBACK */
    DWORD lb_target; int lb_mode;              /* loopback: process filter (0 all, 1 include tree, 2 exclude tree) */
    BOOL inited, started, evflag;
    int kind; UINT32 ch, rate, block;          /* client format */
    UINT32 buf, period;                        /* frames */
    float vol; BOOL mute;                      /* ISimpleAudioVolume */
    /* render */
    short *ring; UINT32 head, count;           /* ring of 16-bit frames (ch samples each) */
    BYTE *stage; UINT32 pending;               /* GetBuffer area, frames handed out */
    HANDLE cev, wev, quit, thread;
    HWAVEOUT wo;
    WAVEHDR hdr[NBLK]; short *blk[NBLK]; BOOL busy[NBLK]; UINT32 blk_n[NBLK]; ULONGLONG blk_start[NBLK]; DWORD blk_seq[NBLK];
    DWORD seq; ULONGLONG submitted, played;     /* device frames submitted since reset, client frames played */
    ULONGLONG wpos; BOOL wvalid;               /* render: bus position of the next frame given to waveOut */
    /* capture / loopback */
    HWAVEIN wi; UINT32 in_rate, in_ch, in_frames;  /* waveIn format, frames per waveIn block */
    float *cring; UINT32 chead, ccount;        /* captured frames in the client's rate/channels */
    BOOL disc;                                 /* data lost since the last packet (overflow) */
    double rs_pos; float rs_last[2]; BOOL rs_have;   /* resampler state: input position of the next output frame */
    ULONGLONG cpos;                            /* frames captured (device position) */
    ULONGLONG rpos; BOOL rvalid;               /* loopback: bus position read next */
    DWORD st_blocks, st_in, st_pk, st_t0, st_logs;   /* diagnostics: waveIn blocks done, frames in, packets out */
    DWORD last_blk, fill_t, st_fill;           /* capture: tick of the last waveIn block, of the last silence fill */
};
static IAudioClientVtbl g_client_vt; static IAudioRenderClientVtbl g_render_vt; static IAudioClockVtbl g_clock_vt;
static IAudioCaptureClientVtbl g_capt_vt; static ISimpleAudioVolumeVtbl g_svol_vt;

/* ---- render engine */
static void reap(CLIENT *c)                    /* lock held: finished blocks */
{
    int i;
    for (i = 0; i < NBLK; i++)
        if (c->busy[i] && (c->hdr[i].dwFlags & WHDR_DONE)) {
            waveOutUnprepareHeader(c->wo, &c->hdr[i], sizeof(WAVEHDR));
            c->played += c->blk_n[i];
            c->busy[i] = FALSE;
        }
}
static void feed(CLIENT *c)                    /* lock held */
{
    int i, inflight = 0; BUS *b = bus();
    for (i = 0; i < NBLK; i++) if (c->busy[i]) inflight++;
    while (c->started && inflight < NQ && c->count) {
        UINT32 n = c->count < c->period ? c->count : c->period, first;
        if (n < c->period && inflight >= 2) break;            /* wait for a full period while two are queued */
        for (i = 0; i < NBLK && c->busy[i]; i++) ;
        if (i >= NBLK) break;
        first = c->buf - c->head; if (first > n) first = n;  /* copy out of the ring (maybe in two parts) */
        memcpy(c->blk[i], c->ring + c->head * c->ch, first * c->ch * sizeof(short));
        if (n > first) memcpy(c->blk[i] + first * c->ch, c->ring, (n - first) * c->ch * sizeof(short));
        c->head = (c->head + n) % c->buf; c->count -= n;
        if (b) {                                              /* build 128: what is played also goes to the loopback bus */
            ULONGLONG now = bus_now(b), target = now + (c->submitted - c->played);
            if (!c->wvalid || c->wpos + c->rate / 5 < target || c->wpos > target + c->rate / 5) { c->wpos = target; c->wvalid = TRUE; }
            bus_write(c->wpos, c->blk[i], n, c->ch);
            c->wpos += n;
            if (b->mute) memset(c->blk[i], 0, n * c->ch * sizeof(short));   /* render endpoint muted (loopback-with-mute) */
            else if (b->vol < 1000) { UINT32 k; for (k = 0; k < n * c->ch; k++) c->blk[i][k] = (short)((LONG)c->blk[i][k] * b->vol / 1000); }
        }
        memset(&c->hdr[i], 0, sizeof(WAVEHDR));
        c->hdr[i].lpData = (LPSTR)c->blk[i];
        c->hdr[i].dwBufferLength = n * c->ch * sizeof(short);
        if (waveOutPrepareHeader(c->wo, &c->hdr[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) break;
        c->blk_n[i] = n; c->blk_start[i] = c->submitted; c->blk_seq[i] = ++c->seq;
        c->busy[i] = TRUE;
        if (waveOutWrite(c->wo, &c->hdr[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
            waveOutUnprepareHeader(c->wo, &c->hdr[i], sizeof(WAVEHDR)); c->busy[i] = FALSE; break;
        }
        c->submitted += n;
        inflight++;
    }
}

/* ---- capture side: converter (any input rate/channels, 16-bit) -> client rate/channels as float in cring */
static void cput(CLIENT *c, float l, float r)
{
    UINT32 t;
    if (c->ccount == c->buf) { c->chead = (c->chead + 1) % c->buf; c->ccount--; c->disc = TRUE; }   /* overflow: drop the oldest */
    t = (c->chead + c->ccount) % c->buf;
    if (c->ch == 1) c->cring[t] = (l + r) * 0.5f;
    else { c->cring[2 * t] = l; c->cring[2 * t + 1] = r; }
    c->ccount++;
}
static void convert_in(CLIENT *c, const short *in, UINT32 n, UINT32 in_ch, UINT32 in_rate)
{
    double step = (double)in_rate / (double)c->rate; UINT32 i;
    for (i = 0; i < n; i++) {
        float l = in[i * in_ch] / 32768.0f, r = in_ch > 1 ? in[i * in_ch + 1] / 32768.0f : l;
        if (!c->rs_have) { c->rs_last[0] = l; c->rs_last[1] = r; c->rs_have = TRUE; c->rs_pos = 0.0; }
        if (in_rate == c->rate) { cput(c, l, r); continue; }
        /* output frames whose input position lies in (i-1, i]: interpolate between the previous frame and this one */
        while (c->rs_pos <= 1.0) {
            float f = (float)c->rs_pos;
            cput(c, c->rs_last[0] + (l - c->rs_last[0]) * f, c->rs_last[1] + (r - c->rs_last[1]) * f);
            c->rs_pos += step;
        }
        c->rs_pos -= 1.0;
        c->rs_last[0] = l; c->rs_last[1] = r;
    }
}
static void in_requeue(CLIENT *c, int i)
{
    memset(&c->hdr[i], 0, sizeof(WAVEHDR));
    c->hdr[i].lpData = (LPSTR)c->blk[i];
    c->hdr[i].dwBufferLength = c->in_frames * c->in_ch * sizeof(short);
    if (waveInPrepareHeader(c->wi, &c->hdr[i], sizeof(WAVEHDR)) == MMSYSERR_NOERROR) {
        if (waveInAddBuffer(c->wi, &c->hdr[i], sizeof(WAVEHDR)) == MMSYSERR_NOERROR) c->busy[i] = TRUE;
        else waveInUnprepareHeader(c->wi, &c->hdr[i], sizeof(WAVEHDR));
    }
}
static void capture_reap(CLIENT *c)            /* lock held */
{
    int i, k;
    for (k = 0; k < NBLK; k++) {               /* in submission order: oldest sequence first */
        int best = -1;
        for (i = 0; i < NBLK; i++)
            if (c->busy[i] && (c->hdr[i].dwFlags & WHDR_DONE) && (best < 0 || c->blk_seq[i] < c->blk_seq[best])) best = i;
        if (best < 0) break;
        i = best;
        waveInUnprepareHeader(c->wi, &c->hdr[i], sizeof(WAVEHDR));
        c->busy[i] = FALSE;
        c->st_blocks++;
        c->last_blk = c->fill_t = GetTickCount();
        if (c->started && c->hdr[i].dwBytesRecorded) {
            UINT32 n = c->hdr[i].dwBytesRecorded / (c->in_ch * 2);
            c->st_in += n;
            if (c->mute) memset(c->blk[i], 0, n * c->in_ch * 2);
            convert_in(c, c->blk[i], n, c->in_ch, c->in_rate);
        }
        if (c->started) { c->blk_seq[i] = ++c->seq; in_requeue(c, i); }
    }
}
static void loopback_pull(CLIENT *c)           /* lock held */
{
    BUS *b = bus(); ULONGLONG now, want; UINT32 n; short *tmp;
    if (!b || !c->started) return;
    now = bus_now(b); want = now - (ULONGLONG)b->rate * 60 / 1000;      /* 60 ms behind real time: writers are ahead */
    if (!c->rvalid || c->rpos + b->rate / 2 < want || c->rpos > want) { c->rpos = want - b->rate / 50; c->rvalid = TRUE; }
    while (c->rpos < want) {
        n = (UINT32)(want - c->rpos); if (n > 2048) n = 2048;
        if (!(tmp = (short *)HeapAlloc(GetProcessHeap(), 0, n * 4))) return;
        bus_read(c->rpos, tmp, n, c->lb_target, c->lb_mode);
        if (c->mute) memset(tmp, 0, n * 4);
        convert_in(c, tmp, n, 2, b->rate);
        HeapFree(GetProcessHeap(), 0, tmp);
        c->rpos += n;
    }
}

static DWORD WINAPI engine(LPVOID p)
{
    CLIENT *c = (CLIENT *)p;
    HANDLE w[2]; DWORD ms;
    w[0] = c->quit; w[1] = c->wev;
    ms = c->flow == F_LOOPBACK ? 10 : c->period * 1000 / c->rate; if (ms < 5) ms = 5;
    for (;;) {
        DWORD r = WaitForMultipleObjects(2, w, FALSE, ms);
        if (r == WAIT_OBJECT_0) break;
        EnterCriticalSection(&c->cs);
        if (c->flow == F_RENDER) {
            reap(c);
            feed(c);
            if (c->started && c->cev && c->buf - c->count >= c->period) SetEvent(c->cev);   /* room for a period */
        } else {
            if (c->flow == F_CAPTURE) {
                DWORD now = GetTickCount();
                capture_reap(c);
                /* a recording device that delivers nothing (driver stuck, no input path - QEMU's SB16 records no
                 * data at all): WASAPI keeps delivering packets as long as the stream runs, so silence is put in
                 * after 300 ms without a block - Chromium's WebRTC sends no audio at all if its capture stalls */
                if (c->started && now - c->last_blk > 300) {
                    DWORD n = (now - c->fill_t) * c->rate / 1000, k;
                    if (n > c->rate / 2) n = c->rate / 2;
                    for (k = 0; k < n; k++) cput(c, 0.0f, 0.0f);
                    c->fill_t += n * 1000 / c->rate; c->st_fill += n;
                }
            } else loopback_pull(c);
            if (c->started && c->st_logs < 3 && GetTickCount() - c->st_t0 > 5000) {
                c->st_logs++; c->st_t0 = GetTickCount();
                alog("flow %d after 5 s: %lu waveIn blocks done, %lu frames in, %lu silence frames put in, %lu packets taken, %lu frames waiting", c->flow, c->st_blocks, c->st_in, c->st_fill, c->st_pk, c->ccount);
            }
            if (c->started && c->cev && c->ccount >= c->period) SetEvent(c->cev);          /* a packet is ready */
        }
        LeaveCriticalSection(&c->cs);
    }
    return 0;
}

static CLIENT *CL(IAudioClient *t) { return (CLIENT *)t; }
static HRESULT STDMETHODCALLTYPE cl_qi(IAudioClient *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IAudioClient) || same_guid(iid, &kIID_IAgileObject)) { *pv = t; InterlockedIncrement(&CL(t)->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;                         /* no IAudioClient2/3: callers fall back */
}
static ULONG STDMETHODCALLTYPE cl_addref(IAudioClient *t) { return (ULONG)InterlockedIncrement(&CL(t)->ref); }
static ULONG STDMETHODCALLTYPE cl_release(IAudioClient *t)
{
    CLIENT *c = CL(t); LONG r = InterlockedDecrement(&c->ref); int i;
    if (r) return (ULONG)r;
    if (c->thread) {
        SetEvent(c->quit);
        /* build 126: the device and the client are only given up once the engine thread has really ended (VLC crash
         * in WINMM's prepare code with a closed device's data). If it does not end: a small leak instead of a crash. */
        if (WaitForSingleObject(c->thread, 15000) != WAIT_OBJECT_0) return 0;
        CloseHandle(c->thread);
    }
    if (c->wo) {
        waveOutReset(c->wo);
        for (i = 0; i < NBLK; i++) if (c->busy[i]) waveOutUnprepareHeader(c->wo, &c->hdr[i], sizeof(WAVEHDR));
        waveOutClose(c->wo);
    }
    if (c->wi) {
        waveInReset(c->wi);
        for (i = 0; i < NBLK; i++) if (c->busy[i]) waveInUnprepareHeader(c->wi, &c->hdr[i], sizeof(WAVEHDR));
        waveInClose(c->wi);
    }
    for (i = 0; i < NBLK; i++) if (c->blk[i]) HeapFree(GetProcessHeap(), 0, c->blk[i]);
    if (c->ring) HeapFree(GetProcessHeap(), 0, c->ring);
    if (c->cring) HeapFree(GetProcessHeap(), 0, c->cring);
    if (c->stage) HeapFree(GetProcessHeap(), 0, c->stage);
    if (c->wev) CloseHandle(c->wev);
    if (c->quit) CloseHandle(c->quit);
    DeleteCriticalSection(&c->cs);
    HeapFree(GetProcessHeap(), 0, c);
    return 0;
}
static HRESULT open_capture(CLIENT *c)         /* waveIn at the client's format if the card takes it, else its own */
{
    WAVEFORMATEX wf; int pass;
    cap_rate();
    for (pass = 0; pass < 3; pass++) {
        if (pass == 0) { c->in_rate = c->rate; c->in_ch = c->ch; }
        else if (pass == 1) { c->in_rate = g_crate; c->in_ch = g_cch; }
        else { c->in_rate = 22050; c->in_ch = 1; }
        wf.wFormatTag = WAVE_FORMAT_PCM; wf.nChannels = (WORD)c->in_ch; wf.nSamplesPerSec = c->in_rate; wf.wBitsPerSample = 16;
        wf.nBlockAlign = (WORD)(c->in_ch * 2); wf.nAvgBytesPerSec = c->in_rate * wf.nBlockAlign; wf.cbSize = 0;
        if (waveInOpen(&c->wi, WAVE_MAPPER, &wf, (DWORD_PTR)c->wev, 0, CALLBACK_EVENT) == MMSYSERR_NOERROR) break;
        c->wi = NULL;
    }
    if (!c->wi) return K_DEVICE_INVALID;
    c->in_frames = c->in_rate / 50;            /* 20 ms blocks */
    alog("capture: waveIn %lu Hz %lu ch for a client at %lu Hz %lu ch (%s)", c->in_rate, c->in_ch, c->rate, c->ch, c->kind == 1 ? "float" : "16-bit");
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_init(IAudioClient *t, AUDCLNT_SHAREMODE mode, DWORD flags, REFERENCE_TIME dur,
                                         REFERENCE_TIME per, const WAVEFORMATEX *f, LPCGUID session)
{
    CLIENT *c = CL(t); UINT32 frames; int i; HRESULT hr = S_OK; BOOL cap;
    if (!f) return E_POINTER;
    if (mode != AUDCLNT_SHAREMODE_SHARED) return K_EXCLUSIVE_NA;
    if ((flags & AUDCLNT_STREAMFLAGS_LOOPBACK) && c->flow == F_RENDER) c->flow = F_LOOPBACK;   /* "what you hear" */
    cap = c->flow != F_RENDER;
    if (!fmt_kind2(f, cap)) { alog("Initialize: format refused (flow %d, tag %04x, %lu Hz, %u ch, %u bits)", c->flow, f->wFormatTag, f->nSamplesPerSec, f->nChannels, f->wBitsPerSample); return K_UNSUPPORTED_FMT; }
    EnterCriticalSection(&c->cs);
    if (c->inited) { LeaveCriticalSection(&c->cs); return K_ALREADY_INIT; }
    c->kind = fmt_kind2(f, cap); c->ch = f->nChannels; c->rate = f->nSamplesPerSec; c->block = f->nBlockAlign;
    c->evflag = (flags & AUDCLNT_STREAMFLAGS_EVENTCALLBACK) != 0;
    c->period = cap ? c->rate / 100 : c->rate / 50;            /* capture 10 ms packets, render 20 ms */
    frames = (UINT32)((dur * (LONGLONG)c->rate + 5000000) / 10000000);
    c->buf = frames > 4 * c->period ? frames : 4 * c->period;
    if (cap && c->buf < c->rate / 5) c->buf = c->rate / 5;    /* capture: keep at least 200 ms */
    c->stage = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, c->buf * c->block);
    c->wev = CreateEventA(NULL, FALSE, FALSE, NULL);
    c->quit = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!c->stage || !c->wev || !c->quit) { hr = E_OUTOFMEMORY; goto out; }
    if (!cap) {
        WAVEFORMATEX wf;
        c->ring = (short *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, c->buf * c->ch * sizeof(short));
        for (i = 0; i < NBLK; i++) c->blk[i] = (short *)HeapAlloc(GetProcessHeap(), 0, c->period * c->ch * sizeof(short));
        for (i = 0; i < NBLK && c->blk[i]; i++) ;
        if (!c->ring || i < NBLK) { hr = E_OUTOFMEMORY; goto out; }
        wf.wFormatTag = WAVE_FORMAT_PCM; wf.nChannels = (WORD)c->ch; wf.nSamplesPerSec = c->rate; wf.wBitsPerSample = 16;
        wf.nBlockAlign = (WORD)(c->ch * 2); wf.nAvgBytesPerSec = c->rate * wf.nBlockAlign; wf.cbSize = 0;
        mix_rate();
        if (waveOutOpen(&c->wo, g_wdev, &wf, (DWORD_PTR)c->wev, 0, CALLBACK_EVENT | g_open_flags) != MMSYSERR_NOERROR &&
            waveOutOpen(&c->wo, WAVE_MAPPER, &wf, (DWORD_PTR)c->wev, 0, CALLBACK_EVENT) != MMSYSERR_NOERROR) {
            c->wo = NULL; hr = K_DEVICE_INVALID; goto out;
        }
        waveOutPause(c->wo);                                   /* nothing plays before Start */
    } else {
        c->cring = (float *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, c->buf * c->ch * sizeof(float));
        if (!c->cring) { hr = E_OUTOFMEMORY; goto out; }
        if (c->flow == F_CAPTURE) {
            if (FAILED(hr = open_capture(c))) goto out;
            for (i = 0; i < NBLK; i++) c->blk[i] = (short *)HeapAlloc(GetProcessHeap(), 0, c->in_frames * c->in_ch * sizeof(short));
            for (i = 0; i < NBLK && c->blk[i]; i++) ;
            if (i < NBLK) { hr = E_OUTOFMEMORY; goto out; }
        } else alog("loopback client: %lu Hz %lu ch, processes: %s %08lx, event %d", c->rate, c->ch,
                    c->lb_mode == 0 ? "all" : c->lb_mode == 1 ? "only the tree of" : "all but the tree of", c->lb_target, c->evflag);
    }
    c->thread = CreateThread(NULL, 0, engine, c, 0, NULL);
    if (!c->thread) { hr = E_OUTOFMEMORY; goto out; }
    SetThreadPriority(c->thread, THREAD_PRIORITY_HIGHEST);   /* above Chromium's normal threads, not above everything (build 39b) */
    c->inited = TRUE;
out:
    LeaveCriticalSection(&c->cs);
    if (FAILED(hr)) alog("Initialize (flow %d) failed %08lx", c->flow, hr);
    (void)per; (void)session;
    return hr;
}
static HRESULT STDMETHODCALLTYPE cl_bufsize(IAudioClient *t, UINT32 *n)
{
    if (!n) return E_POINTER;
    if (!CL(t)->inited) return K_NOT_INITIALIZED;
    *n = CL(t)->buf; return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_latency(IAudioClient *t, REFERENCE_TIME *l)
{
    if (!l) return E_POINTER;
    if (!CL(t)->inited) return K_NOT_INITIALIZED;
    *l = CL(t)->flow == F_RENDER ? (REFERENCE_TIME)NQ * 200000 : 400000; return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_padding(IAudioClient *t, UINT32 *n)
{
    CLIENT *c = CL(t);
    if (!n) return E_POINTER;
    if (!c->inited) return K_NOT_INITIALIZED;
    EnterCriticalSection(&c->cs); *n = c->flow == F_RENDER ? c->count : c->ccount; LeaveCriticalSection(&c->cs);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_supported(IAudioClient *t, AUDCLNT_SHAREMODE mode, const WAVEFORMATEX *f, WAVEFORMATEX **closest)
{
    CLIENT *c = CL(t);
    if (closest) *closest = NULL;
    if (!f) return E_POINTER;
    if (mode != AUDCLNT_SHAREMODE_SHARED) return K_UNSUPPORTED_FMT;
    if (fmt_kind2(f, c->flow != F_RENDER)) return S_OK;
    if (closest) {
        WAVEFORMATEXTENSIBLE *x = (WAVEFORMATEXTENSIBLE *)CoTaskMemAlloc(sizeof(*x));
        if (!x) return E_OUTOFMEMORY;
        if (c->flow == F_CAPTURE) fill_cmix(x); else fill_mix(x);
        *closest = &x->Format; return S_FALSE;
    }
    return K_UNSUPPORTED_FMT;
}
static HRESULT STDMETHODCALLTYPE cl_mixformat(IAudioClient *t, WAVEFORMATEX **f)
{
    WAVEFORMATEXTENSIBLE *x;
    if (!f) return E_POINTER;
    x = (WAVEFORMATEXTENSIBLE *)CoTaskMemAlloc(sizeof(*x));
    if (!x) return E_OUTOFMEMORY;
    if (CL(t)->flow == F_CAPTURE) fill_cmix(x); else fill_mix(x);
    *f = &x->Format; return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_period(IAudioClient *t, REFERENCE_TIME *def, REFERENCE_TIME *min)
{
    if (!def && !min) return E_POINTER;
    if (CL(t)->flow == F_RENDER) { if (def) *def = 200000; if (min) *min = 100000; }   /* 20 ms */
    else { if (def) *def = 100000; if (min) *min = 100000; }                          /* capture: 10 ms */
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_start(IAudioClient *t)
{
    CLIENT *c = CL(t); HRESULT hr = S_OK; int i;
    EnterCriticalSection(&c->cs);
    if (!c->inited) hr = K_NOT_INITIALIZED;
    else if (c->started) hr = K_NOT_STOPPED;
    else if (c->evflag && !c->cev) hr = K_EVENT_NOT_SET;
    else if (c->flow == F_RENDER) { c->started = TRUE; feed(c); waveOutRestart(c->wo); SetEvent(c->wev); }
    else {
        c->started = TRUE; c->st_t0 = c->last_blk = c->fill_t = GetTickCount();
        if (c->flow == F_CAPTURE) {
            for (i = 0; i < NBLK; i++) if (!c->busy[i]) { c->blk_seq[i] = ++c->seq; in_requeue(c, i); }
            if (waveInStart(c->wi) != MMSYSERR_NOERROR) { c->started = FALSE; hr = K_DEVICE_INVALID; }
        } else c->rvalid = FALSE;
        SetEvent(c->wev);
    }
    LeaveCriticalSection(&c->cs);
    if (c->flow != F_RENDER) alog("Start (flow %d) = %08lx", c->flow, hr);
    return hr;
}
static HRESULT STDMETHODCALLTYPE cl_stop(IAudioClient *t)
{
    CLIENT *c = CL(t); HRESULT hr = S_OK;
    EnterCriticalSection(&c->cs);
    if (!c->inited) hr = K_NOT_INITIALIZED;
    else if (!c->started) hr = S_FALSE;
    else {
        c->started = FALSE;
        if (c->flow == F_RENDER) waveOutPause(c->wo);
        else if (c->flow == F_CAPTURE) waveInStop(c->wi);
    }
    LeaveCriticalSection(&c->cs);
    return hr;
}
static HRESULT STDMETHODCALLTYPE cl_reset(IAudioClient *t)
{
    CLIENT *c = CL(t); HRESULT hr = S_OK;
    EnterCriticalSection(&c->cs);
    if (!c->inited) hr = K_NOT_INITIALIZED;
    else if (c->started) hr = K_NOT_STOPPED;
    else if (c->pending) hr = K_OUT_OF_ORDER;            /* AUDCLNT_E_BUFFER_OPERATION_PENDING in the SDK */
    else if (c->flow == F_RENDER) {
        waveOutReset(c->wo);                                  /* returns every block (WHDR_DONE), position -> 0 */
        reap(c);
        waveOutPause(c->wo);
        c->head = c->count = 0; c->submitted = c->played = 0; c->wvalid = FALSE;
    } else {
        if (c->flow == F_CAPTURE) { waveInReset(c->wi); capture_reap(c); }
        c->chead = c->ccount = 0; c->cpos = 0; c->rs_have = FALSE; c->rvalid = FALSE;
    }
    LeaveCriticalSection(&c->cs);
    return hr;
}
static HRESULT STDMETHODCALLTYPE cl_setevent(IAudioClient *t, HANDLE e)
{
    CLIENT *c = CL(t);
    if (!e || e == INVALID_HANDLE_VALUE) return E_INVALIDARG;
    if (!c->inited) return K_NOT_INITIALIZED;
    if (!c->evflag) return (HRESULT)0x88890013L;               /* AUDCLNT_E_EVENTHANDLE_NOT_EXPECTED */
    c->cev = e; return S_OK;
}
static HRESULT STDMETHODCALLTYPE cl_service(IAudioClient *t, REFIID iid, void **pv)
{
    CLIENT *c = CL(t);
    if (!pv) return E_POINTER;
    *pv = NULL;
    if (!c->inited) return K_NOT_INITIALIZED;
    if (same_guid(iid, &kIID_IAudioRenderClient)) { if (c->flow != F_RENDER) return K_WRONG_TYPE; *pv = &c->render; InterlockedIncrement(&c->ref); return S_OK; }
    if (same_guid(iid, &kIID_IAudioCaptureClient)) { if (c->flow == F_RENDER) return K_WRONG_TYPE; *pv = &c->capt; InterlockedIncrement(&c->ref); return S_OK; }
    if (same_guid(iid, &kIID_IAudioClock)) { *pv = &c->clock; InterlockedIncrement(&c->ref); return S_OK; }
    if (same_guid(iid, &kIID_ISimpleAudioVolume)) { *pv = &c->svol; InterlockedIncrement(&c->ref); return S_OK; }
    return E_NOINTERFACE;
}

/* IAudioRenderClient */
static HRESULT STDMETHODCALLTYPE rc_qi(IAudioRenderClient *t, REFIID iid, void **pv)
{
    RENDER *r = (RENDER *)t;
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IAudioRenderClient)) { *pv = t; InterlockedIncrement(&r->c->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE rc_addref(IAudioRenderClient *t) { return cl_addref((IAudioClient *)((RENDER *)t)->c); }
static ULONG STDMETHODCALLTYPE rc_release(IAudioRenderClient *t) { return cl_release((IAudioClient *)((RENDER *)t)->c); }
static HRESULT STDMETHODCALLTYPE rc_getbuffer(IAudioRenderClient *t, UINT32 n, BYTE **data)
{
    CLIENT *c = ((RENDER *)t)->c; HRESULT hr = S_OK;
    if (!data) return E_POINTER;
    *data = NULL;
    EnterCriticalSection(&c->cs);
    if (c->pending) hr = K_OUT_OF_ORDER;
    else if (n > c->buf - c->count) hr = K_BUFFER_TOO_LARGE;
    else if (n) { *data = c->stage; c->pending = n; }
    LeaveCriticalSection(&c->cs);
    return hr;
}
static short to16(float v)
{
    float s = v * 32768.0f;
    if (s >= 32767.0f) return 32767;
    if (s <= -32768.0f) return -32768;
    return (short)s;
}
static HRESULT STDMETHODCALLTYPE rc_release_buffer(IAudioRenderClient *t, UINT32 n, DWORD flags)
{
    CLIENT *c = ((RENDER *)t)->c; HRESULT hr = S_OK; UINT32 i, j, tail; short *d;
    float g = c->mute ? 0.0f : c->vol;
    EnterCriticalSection(&c->cs);
    if (n > c->pending || (!c->pending && n)) hr = K_INVALID_SIZE;
    else if (n) {
        tail = (c->head + c->count) % c->buf;
        for (i = 0; i < n; i++) {
            d = c->ring + tail * c->ch;
            if ((flags & AUDCLNT_BUFFERFLAGS_SILENT) || g == 0.0f) for (j = 0; j < c->ch; j++) d[j] = 0;
            else if (c->kind == 1) { const float *s = (const float *)(c->stage + i * c->block); for (j = 0; j < c->ch; j++) d[j] = to16(s[j] * g); }
            else { const short *s = (const short *)(c->stage + i * c->block); for (j = 0; j < c->ch; j++) d[j] = g >= 1.0f ? s[j] : (short)(s[j] * g); }
            if (++tail == c->buf) tail = 0;
        }
        c->count += n;
    }
    c->pending = 0;
    LeaveCriticalSection(&c->cs);
    return hr;
}

/* IAudioCaptureClient (build 128) */
static HRESULT STDMETHODCALLTYPE cc_qi(IAudioCaptureClient *t, REFIID iid, void **pv)
{
    CAPT *k = (CAPT *)t;
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IAudioCaptureClient)) { *pv = t; InterlockedIncrement(&k->c->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE cc_addref(IAudioCaptureClient *t) { return cl_addref((IAudioClient *)((CAPT *)t)->c); }
static ULONG STDMETHODCALLTYPE cc_release(IAudioCaptureClient *t) { return cl_release((IAudioClient *)((CAPT *)t)->c); }
static HRESULT STDMETHODCALLTYPE cc_getbuffer(IAudioCaptureClient *t, BYTE **data, UINT32 *frames, DWORD *flags, UINT64 *devpos, UINT64 *qpcpos)
{
    CLIENT *c = ((CAPT *)t)->c; HRESULT hr = S_OK; UINT32 i, j, n;
    if (!data || !frames || !flags) return E_POINTER;
    *data = NULL; *frames = 0; *flags = 0;
    EnterCriticalSection(&c->cs);
    if (c->flow == F_LOOPBACK && !c->evflag) loopback_pull(c);   /* endpoint loopback is polled */
    if (c->pending) hr = K_OUT_OF_ORDER;
    else if (c->ccount < c->period) hr = K_S_BUFFER_EMPTY;
    else {
        n = c->period;
        for (i = 0; i < n; i++) {
            const float *s = c->cring + ((c->chead + i) % c->buf) * c->ch;
            if (c->kind == 1) { float *o = (float *)(c->stage + i * c->block); for (j = 0; j < c->ch; j++) o[j] = s[j] * c->vol; }
            else { short *o = (short *)(c->stage + i * c->block); for (j = 0; j < c->ch; j++) o[j] = to16(s[j] * c->vol); }
        }
        *data = c->stage; *frames = n; c->pending = n; c->st_pk++;
        if (c->disc) { *flags |= AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY; c->disc = FALSE; }
        if (devpos) *devpos = c->cpos;
        if (qpcpos) *qpcpos = qpc100() - (ULONGLONG)c->ccount * 10000000 / c->rate;   /* when its first frame was recorded */
    }
    LeaveCriticalSection(&c->cs);
    return hr;
}
static HRESULT STDMETHODCALLTYPE cc_releasebuffer(IAudioCaptureClient *t, UINT32 n)
{
    CLIENT *c = ((CAPT *)t)->c; HRESULT hr = S_OK;
    EnterCriticalSection(&c->cs);
    if (n && n != c->pending) hr = K_INVALID_SIZE;
    else if (n) { c->chead = (c->chead + n) % c->buf; c->ccount -= n; c->cpos += n; }
    c->pending = 0;
    LeaveCriticalSection(&c->cs);
    return hr;
}
static HRESULT STDMETHODCALLTYPE cc_nextsize(IAudioCaptureClient *t, UINT32 *n)
{
    CLIENT *c = ((CAPT *)t)->c;
    if (!n) return E_POINTER;
    EnterCriticalSection(&c->cs);
    if (c->flow == F_LOOPBACK && !c->evflag) loopback_pull(c);
    *n = c->ccount >= c->period ? c->period : 0;
    LeaveCriticalSection(&c->cs);
    return S_OK;
}

/* IAudioClock */
static HRESULT STDMETHODCALLTYPE ck_qi(IAudioClock *t, REFIID iid, void **pv)
{
    CLOCK *k = (CLOCK *)t;
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IAudioClock)) { *pv = t; InterlockedIncrement(&k->c->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE ck_addref(IAudioClock *t) { return cl_addref((IAudioClient *)((CLOCK *)t)->c); }
static ULONG STDMETHODCALLTYPE ck_release(IAudioClock *t) { return cl_release((IAudioClient *)((CLOCK *)t)->c); }
static HRESULT STDMETHODCALLTYPE ck_freq(IAudioClock *t, UINT64 *f)
{
    if (!f) return E_POINTER;
    *f = ((CLOCK *)t)->c->rate; return S_OK;
}
static HRESULT STDMETHODCALLTYPE ck_pos(IAudioClock *t, UINT64 *pos, UINT64 *qpc)
{
    CLIENT *c = ((CLOCK *)t)->c; int i, old = -1; ULONGLONG p;
    if (!pos) return E_POINTER;
    EnterCriticalSection(&c->cs);
    if (c->flow != F_RENDER) p = c->cpos + c->ccount;
    else {
        p = c->played;
        for (i = 0; i < NBLK; i++)                              /* the oldest block still in the device */
            if (c->busy[i] && !(c->hdr[i].dwFlags & WHDR_DONE) && (old < 0 || c->blk_seq[i] < c->blk_seq[old])) old = i;
        if (old >= 0) {
            MMTIME mt; ULONGLONG dev = 0;
            mt.wType = TIME_SAMPLES;
            if (waveOutGetPosition(c->wo, &mt, sizeof(mt)) == MMSYSERR_NOERROR) {
                if (mt.wType == TIME_SAMPLES) dev = mt.u.sample;
                else if (mt.wType == TIME_BYTES) dev = mt.u.cb / (c->ch * 2);
                else if (mt.wType == TIME_MS) dev = (ULONGLONG)mt.u.ms * c->rate / 1000;
            }
            if (dev > c->blk_start[old]) {
                ULONGLONG in = dev - c->blk_start[old];
                p += in < c->blk_n[old] ? in : c->blk_n[old];
            }
        }
    }
    LeaveCriticalSection(&c->cs);
    *pos = p;
    if (qpc) *qpc = qpc100();
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ck_chars(IAudioClock *t, DWORD *ch) { if (!ch) return E_POINTER; *ch = 0; return S_OK; }

/* ISimpleAudioVolume (per stream) */
static HRESULT STDMETHODCALLTYPE sv_qi(ISimpleAudioVolume *t, REFIID iid, void **pv)
{
    SVOL *k = (SVOL *)t;
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_ISimpleAudioVolume)) { *pv = t; InterlockedIncrement(&k->c->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE sv_addref(ISimpleAudioVolume *t) { return cl_addref((IAudioClient *)((SVOL *)t)->c); }
static ULONG STDMETHODCALLTYPE sv_release(ISimpleAudioVolume *t) { return cl_release((IAudioClient *)((SVOL *)t)->c); }
static HRESULT STDMETHODCALLTYPE sv_setvol(ISimpleAudioVolume *t, float v, LPCGUID ctx)
{
    (void)ctx; if (!(v >= 0.0f && v <= 1.0f)) return E_INVALIDARG; ((SVOL *)t)->c->vol = v; return S_OK;
}
static HRESULT STDMETHODCALLTYPE sv_getvol(ISimpleAudioVolume *t, float *v) { if (!v) return E_POINTER; *v = ((SVOL *)t)->c->vol; return S_OK; }
static HRESULT STDMETHODCALLTYPE sv_setmute(ISimpleAudioVolume *t, BOOL m, LPCGUID ctx) { (void)ctx; ((SVOL *)t)->c->mute = m != 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE sv_getmute(ISimpleAudioVolume *t, BOOL *m) { if (!m) return E_POINTER; *m = ((SVOL *)t)->c->mute; return S_OK; }

static IAudioClientVtbl g_client_vt = {
    cl_qi, cl_addref, cl_release, cl_init, cl_bufsize, cl_latency, cl_padding, cl_supported, cl_mixformat, cl_period,
    cl_start, cl_stop, cl_reset, cl_setevent, cl_service };
static IAudioRenderClientVtbl g_render_vt = { rc_qi, rc_addref, rc_release, rc_getbuffer, rc_release_buffer };
static IAudioCaptureClientVtbl g_capt_vt = { cc_qi, cc_addref, cc_release, cc_getbuffer, cc_releasebuffer, cc_nextsize };
static IAudioClockVtbl g_clock_vt = { ck_qi, ck_addref, ck_release, ck_freq, ck_pos, ck_chars };
static ISimpleAudioVolumeVtbl g_svol_vt = { sv_qi, sv_addref, sv_release, sv_setvol, sv_getvol, sv_setmute, sv_getmute };

static HRESULT new_client(void **pv, int flow)
{
    CLIENT *c = (CLIENT *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CLIENT));
    if (!c) return E_OUTOFMEMORY;
    c->vt = &g_client_vt; c->render.vt = &g_render_vt; c->render.c = c; c->clock.vt = &g_clock_vt; c->clock.c = c;
    c->capt.vt = &g_capt_vt; c->capt.c = c; c->svol.vt = &g_svol_vt; c->svol.c = c;
    c->ref = 1; c->flow = flow; c->vol = 1.0f;
    InitializeCriticalSection(&c->cs);
    *pv = c;
    return S_OK;
}

/* ================================================================== IAudioEndpointVolume (per endpoint, static) */
typedef struct { IAudioEndpointVolumeVtbl *vt; BOOL capture; } EPVOL;
static volatile LONG *ev_vol(EPVOL *e)  { BUS *b = bus(); static LONG dv = 1000; return b ? (e->capture ? &b->cvol : &b->vol) : &dv; }
static volatile LONG *ev_mute(EPVOL *e) { BUS *b = bus(); static LONG dm; return b ? (e->capture ? &b->cmute : &b->mute) : &dm; }
static HRESULT STDMETHODCALLTYPE evq(IAudioEndpointVolume *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IAudioEndpointVolume)) { *pv = t; return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE ev_ref(IAudioEndpointVolume *t) { return 2; }
static ULONG STDMETHODCALLTYPE ev_unref(IAudioEndpointVolume *t) { return 1; }
static HRESULT STDMETHODCALLTYPE ev_reg(IAudioEndpointVolume *t, IAudioEndpointVolumeCallback *c) { return c ? S_OK : E_POINTER; }
static HRESULT STDMETHODCALLTYPE ev_chcount(IAudioEndpointVolume *t, UINT *n) { if (!n) return E_POINTER; *n = 2; return S_OK; }
/* level in dB: 0 .. -64 dB mapped linearly on the scalar (simple, monotonic) */
static float db_of(LONG v) { return v >= 1000 ? 0.0f : -64.0f + 64.0f * v / 1000.0f; }
static LONG of_db(float db) { if (db >= 0.0f) return 1000; if (db <= -64.0f) return 0; return (LONG)((db + 64.0f) * 1000.0f / 64.0f); }
static HRESULT STDMETHODCALLTYPE ev_setdb(IAudioEndpointVolume *t, float db, LPCGUID g) { InterlockedExchange(ev_vol((EPVOL *)t), of_db(db)); return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_setsc(IAudioEndpointVolume *t, float v, LPCGUID g) { if (!(v >= 0.0f && v <= 1.0f)) return E_INVALIDARG; InterlockedExchange(ev_vol((EPVOL *)t), (LONG)(v * 1000.0f)); return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_getdb(IAudioEndpointVolume *t, float *db) { if (!db) return E_POINTER; *db = db_of(*ev_vol((EPVOL *)t)); return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_getsc(IAudioEndpointVolume *t, float *v) { if (!v) return E_POINTER; *v = *ev_vol((EPVOL *)t) / 1000.0f; return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_setchdb(IAudioEndpointVolume *t, UINT ch, float db, LPCGUID g) { return ch < 2 ? ev_setdb(t, db, g) : E_INVALIDARG; }
static HRESULT STDMETHODCALLTYPE ev_setchsc(IAudioEndpointVolume *t, UINT ch, float v, LPCGUID g) { return ch < 2 ? ev_setsc(t, v, g) : E_INVALIDARG; }
static HRESULT STDMETHODCALLTYPE ev_getchdb(IAudioEndpointVolume *t, UINT ch, float *db) { return ch < 2 ? ev_getdb(t, db) : E_INVALIDARG; }
static HRESULT STDMETHODCALLTYPE ev_getchsc(IAudioEndpointVolume *t, UINT ch, float *v) { return ch < 2 ? ev_getsc(t, v) : E_INVALIDARG; }
static HRESULT STDMETHODCALLTYPE ev_setmute(IAudioEndpointVolume *t, BOOL m, LPCGUID g) { InterlockedExchange(ev_mute((EPVOL *)t), m != 0); return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_getmute(IAudioEndpointVolume *t, BOOL *m) { if (!m) return E_POINTER; *m = *ev_mute((EPVOL *)t) != 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_step(IAudioEndpointVolume *t, UINT *s, UINT *n)
{
    LONG v = *ev_vol((EPVOL *)t);
    if (!s || !n) return E_POINTER;
    *n = 101; *s = (UINT)(v / 10); return S_OK;
}
static HRESULT STDMETHODCALLTYPE ev_up(IAudioEndpointVolume *t, LPCGUID g) { volatile LONG *p = ev_vol((EPVOL *)t); LONG v = *p + 10; InterlockedExchange(p, v > 1000 ? 1000 : v); return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_down(IAudioEndpointVolume *t, LPCGUID g) { volatile LONG *p = ev_vol((EPVOL *)t); LONG v = *p - 10; InterlockedExchange(p, v < 0 ? 0 : v); return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_hw(IAudioEndpointVolume *t, DWORD *m) { if (!m) return E_POINTER; *m = 0; return S_OK; }
static HRESULT STDMETHODCALLTYPE ev_range(IAudioEndpointVolume *t, float *mn, float *mx, float *inc)
{
    if (!mn || !mx || !inc) return E_POINTER;
    *mn = -64.0f; *mx = 0.0f; *inc = 0.64f; return S_OK;
}
static IAudioEndpointVolumeVtbl g_epv_vt = { evq, ev_ref, ev_unref, ev_reg, ev_reg, ev_chcount, ev_setdb, ev_setsc, ev_getdb,
    ev_getsc, ev_setchdb, ev_setchsc, ev_getchdb, ev_getchsc, ev_setmute, ev_getmute, ev_step, ev_up, ev_down, ev_hw, ev_range };
static EPVOL g_epv_r = { &g_epv_vt, FALSE }, g_epv_c = { &g_epv_vt, TRUE };

/* ================================================================== IPropertyStore (static, read only; one per endpoint) */
typedef struct { IPropertyStoreVtbl *vt; BOOL capture; } PSTORE;
static HRESULT STDMETHODCALLTYPE ps_qi(IPropertyStore *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IPropertyStore)) { *pv = t; return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE st_addref(void *t) { return 2; }
static ULONG STDMETHODCALLTYPE st_release(void *t) { return 1; }
static HRESULT STDMETHODCALLTYPE ps_count(IPropertyStore *t, DWORD *n) { if (!n) return E_POINTER; *n = 2; return S_OK; }
static HRESULT STDMETHODCALLTYPE ps_at(IPropertyStore *t, DWORD i, PROPERTYKEY *k)
{
    if (!k || i > 1) return E_INVALIDARG;
    k->fmtid = kPKEY_DeviceFmtid; k->pid = i ? PID_DEVICEDESC : PID_FRIENDLYNAME; return S_OK;
}
static void dev_name(WCHAR *out, int cch, BOOL friendly, BOOL capture)
{
    char a[160], p[64];
    if (capture) {
        WAVEINCAPSA caps;
        if (waveInGetDevCapsA(WAVE_MAPPER, &caps, sizeof(caps)) != MMSYSERR_NOERROR &&
            waveInGetDevCapsA(0, &caps, sizeof(caps)) != MMSYSERR_NOERROR) lstrcpyA(caps.szPname, "Wave input");
        lstrcpynA(p, caps.szPname, sizeof(p));
        if (friendly) wsprintfA(a, "Microphone (%s)", p); else lstrcpyA(a, "Microphone");
    } else {
        WAVEOUTCAPSA caps;
        if (waveOutGetDevCapsA(WAVE_MAPPER, &caps, sizeof(caps)) != MMSYSERR_NOERROR &&
            waveOutGetDevCapsA(0, &caps, sizeof(caps)) != MMSYSERR_NOERROR) lstrcpyA(caps.szPname, "Wave output");
        lstrcpynA(p, caps.szPname, sizeof(p));
        if (friendly) wsprintfA(a, "Speakers (%s)", p); else lstrcpyA(a, "Speakers");
    }
    if (!MultiByteToWideChar(CP_ACP, 0, a, -1, out, cch)) out[0] = 0;
}
static HRESULT STDMETHODCALLTYPE ps_get(IPropertyStore *t, REFPROPERTYKEY k, PROPVARIANT *v)
{
    if (!v) return E_POINTER;
    memset(v, 0, sizeof(*v));                                   /* VT_EMPTY: "no such property", S_OK as on Windows */
    if (k && same_guid(&k->fmtid, &kPKEY_DeviceFmtid) && (k->pid == PID_FRIENDLYNAME || k->pid == PID_DEVICEDESC)) {
        WCHAR n[200];
        dev_name(n, 200, k->pid == PID_FRIENDLYNAME, ((PSTORE *)t)->capture);
        if ((v->pwszVal = co_wstr(n)) != NULL) v->vt = VT_LPWSTR;
    }
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE ps_set(IPropertyStore *t, REFPROPERTYKEY k, REFPROPVARIANT v) { return STG_E_ACCESSDENIED; }
static HRESULT STDMETHODCALLTYPE ps_commit(IPropertyStore *t) { return S_OK; }
static IPropertyStoreVtbl g_ps_vt = { ps_qi, (void *)st_addref, (void *)st_release, ps_count, ps_at, ps_get, ps_set, ps_commit };
static PSTORE g_ps = { &g_ps_vt, FALSE }, g_cps = { &g_ps_vt, TRUE };

/* ================================================================== IMMDevice + IMMEndpoint (static: render and capture) */
typedef struct { IMMEndpointVtbl *vt; BOOL capture; } EP;
typedef struct { IMMDeviceVtbl *vt; BOOL capture; EP *ep; } DEV;
static EP g_ep, g_cep; static DEV g_dev, g_cdev;
static HRESULT STDMETHODCALLTYPE dv_qi(IMMDevice *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IMMDevice)) { *pv = t; return S_OK; }
    if (same_guid(iid, &kIID_IMMEndpoint)) { *pv = ((DEV *)t)->ep; return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static HRESULT STDMETHODCALLTYPE dv_activate(IMMDevice *t, REFIID iid, DWORD ctx, PROPVARIANT *params, void **pv)
{
    BOOL cap = ((DEV *)t)->capture;
    if (!pv) return E_POINTER;
    *pv = NULL;
    if (same_guid(iid, &kIID_IAudioClient)) return new_client(pv, cap ? F_CAPTURE : F_RENDER);
    if (same_guid(iid, &kIID_IAudioEndpointVolume)) { *pv = cap ? &g_epv_c : &g_epv_r; return S_OK; }
    return E_NOINTERFACE;                                       /* IAudioClient2/3, IDeviceTopology, sessions ... */
}
static HRESULT STDMETHODCALLTYPE dv_props(IMMDevice *t, DWORD access, IPropertyStore **ps)
{
    if (!ps) return E_POINTER;
    *ps = (IPropertyStore *)(((DEV *)t)->capture ? &g_cps : &g_ps); return S_OK;
}
static HRESULT STDMETHODCALLTYPE dv_id(IMMDevice *t, LPWSTR *id)
{
    if (!id) return E_POINTER;
    return (*id = co_wstr(((DEV *)t)->capture ? g_cdev_id : g_dev_id)) != NULL ? S_OK : E_OUTOFMEMORY;
}
static HRESULT STDMETHODCALLTYPE dv_state(IMMDevice *t, DWORD *s)
{
    if (!s) return E_POINTER;
    *s = (((DEV *)t)->capture ? have_capture() : have_device()) ? DEVICE_STATE_ACTIVE : DEVICE_STATE_NOTPRESENT; return S_OK;
}
static IMMDeviceVtbl g_dev_vt = { dv_qi, (void *)st_addref, (void *)st_release, dv_activate, dv_props, dv_id, dv_state };
static HRESULT STDMETHODCALLTYPE ep_qi(IMMEndpoint *t, REFIID iid, void **pv) { return dv_qi((IMMDevice *)(((EP *)t)->capture ? &g_cdev : &g_dev), iid, pv); }
static HRESULT STDMETHODCALLTYPE ep_flow(IMMEndpoint *t, EDataFlow *f) { if (!f) return E_POINTER; *f = ((EP *)t)->capture ? eCapture : eRender; return S_OK; }
static IMMEndpointVtbl g_ep_vt = { ep_qi, (void *)st_addref, (void *)st_release, ep_flow };
static EP g_ep = { &g_ep_vt, FALSE }, g_cep = { &g_ep_vt, TRUE };
static DEV g_dev = { &g_dev_vt, FALSE, &g_ep }, g_cdev = { &g_dev_vt, TRUE, &g_cep };

/* ================================================================== IMMDeviceCollection (0-2 devices) */
typedef struct { IMMDeviceCollectionVtbl *vt; volatile LONG ref; UINT n; DEV *d[2]; } COLL;
static HRESULT STDMETHODCALLTYPE co_qi(IMMDeviceCollection *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IMMDeviceCollection)) { *pv = t; InterlockedIncrement(&((COLL *)t)->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE co_addref(IMMDeviceCollection *t) { return (ULONG)InterlockedIncrement(&((COLL *)t)->ref); }
static ULONG STDMETHODCALLTYPE co_release(IMMDeviceCollection *t)
{
    LONG r = InterlockedDecrement(&((COLL *)t)->ref);
    if (!r) HeapFree(GetProcessHeap(), 0, t);
    return (ULONG)r;
}
static HRESULT STDMETHODCALLTYPE co_count(IMMDeviceCollection *t, UINT *n) { if (!n) return E_POINTER; *n = ((COLL *)t)->n; return S_OK; }
static HRESULT STDMETHODCALLTYPE co_item(IMMDeviceCollection *t, UINT i, IMMDevice **d)
{
    if (!d) return E_POINTER;
    *d = NULL;
    if (i >= ((COLL *)t)->n) return E_INVALIDARG;
    *d = (IMMDevice *)((COLL *)t)->d[i]; return S_OK;
}
static IMMDeviceCollectionVtbl g_coll_vt = { co_qi, co_addref, co_release, co_count, co_item };

/* ================================================================== IMMDeviceEnumerator (static) */
static HRESULT STDMETHODCALLTYPE en_qi(IMMDeviceEnumerator *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IMMDeviceEnumerator)) { *pv = t; return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static HRESULT STDMETHODCALLTYPE en_enum(IMMDeviceEnumerator *t, EDataFlow flow, DWORD mask, IMMDeviceCollection **out)
{
    COLL *c;
    if (!out) return E_POINTER;
    *out = NULL;
    if ((unsigned)flow > (unsigned)eAll || !mask || (mask & ~0xFUL)) return E_INVALIDARG;
    if (!(c = (COLL *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(COLL)))) return E_OUTOFMEMORY;
    c->vt = &g_coll_vt; c->ref = 1;
    if (mask & DEVICE_STATE_ACTIVE) {
        if ((flow == eRender || flow == eAll) && have_device()) c->d[c->n++] = &g_dev;
        if ((flow == eCapture || flow == eAll) && have_capture()) c->d[c->n++] = &g_cdev;
    }
    *out = (IMMDeviceCollection *)c;
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE en_default(IMMDeviceEnumerator *t, EDataFlow flow, ERole role, IMMDevice **d)
{
    if (!d) return E_POINTER;
    *d = NULL;
    if ((unsigned)flow >= (unsigned)eAll || (unsigned)role >= (unsigned)ERole_enum_count) return E_INVALIDARG;
    if (flow == eCapture) { if (!have_capture()) return K_E_NOTFOUND; *d = (IMMDevice *)&g_cdev; return S_OK; }
    if (!have_device()) return K_E_NOTFOUND;
    *d = (IMMDevice *)&g_dev; return S_OK;
}
static HRESULT STDMETHODCALLTYPE en_get(IMMDeviceEnumerator *t, LPCWSTR id, IMMDevice **d)
{
    if (!d || !id) return E_POINTER;
    *d = NULL;
    if (wieq(id, g_dev_id) && have_device()) { *d = (IMMDevice *)&g_dev; return S_OK; }
    if (wieq(id, g_cdev_id) && have_capture()) { *d = (IMMDevice *)&g_cdev; return S_OK; }
    return K_E_NOTFOUND;
}
static HRESULT STDMETHODCALLTYPE en_reg(IMMDeviceEnumerator *t, IMMNotificationClient *c) { return c ? S_OK : E_POINTER; }
static HRESULT STDMETHODCALLTYPE en_unreg(IMMDeviceEnumerator *t, IMMNotificationClient *c) { return c ? S_OK : E_POINTER; }
static IMMDeviceEnumeratorVtbl g_en_vt = { en_qi, (void *)st_addref, (void *)st_release, en_enum, en_default, en_get, en_reg, en_unreg };
static struct { IMMDeviceEnumeratorVtbl *vt; } g_en = { &g_en_vt };

/* ================================================================== ActivateAudioInterfaceAsync (build 128)
 * Windows 10 2004+: process loopback (path VAD\Process_Loopback, AUDIOCLIENT_ACTIVATION_PARAMS in a VT_BLOB) or an
 * endpoint by its interface path. Completed at once (the handler is called before we return), as the documentation
 * allows ("may be called on any thread"). Exported; MMDEVAPI.DLL ordinal 17 (the stub KEXSETUP installs) forwards here. */
typedef struct {
    IActivateAudioInterfaceAsyncOperationVtbl *vt; volatile LONG ref; HRESULT hr; IUnknown *unk;
} AOP;
static HRESULT STDMETHODCALLTYPE op_qi(IActivateAudioInterfaceAsyncOperation *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IActivateOp) || same_guid(iid, &kIID_IAgileObject)) { *pv = t; InterlockedIncrement(&((AOP *)t)->ref); return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE op_addref(IActivateAudioInterfaceAsyncOperation *t) { return (ULONG)InterlockedIncrement(&((AOP *)t)->ref); }
static ULONG STDMETHODCALLTYPE op_release(IActivateAudioInterfaceAsyncOperation *t)
{
    AOP *o = (AOP *)t; LONG r = InterlockedDecrement(&o->ref);
    if (!r) { if (o->unk) IUnknown_Release(o->unk); HeapFree(GetProcessHeap(), 0, o); }
    return (ULONG)r;
}
static HRESULT STDMETHODCALLTYPE op_result(IActivateAudioInterfaceAsyncOperation *t, HRESULT *hr, IUnknown **unk)
{
    AOP *o = (AOP *)t;
    if (!hr || !unk) return E_POINTER;
    *hr = o->hr; *unk = o->unk; if (o->unk) IUnknown_AddRef(o->unk);
    return S_OK;
}
static IActivateAudioInterfaceAsyncOperationVtbl g_op_vt = { op_qi, op_addref, op_release, op_result };

HRESULT WINAPI KexActivateAudioInterfaceAsync(LPCWSTR path, REFIID iid, PROPVARIANT *params,
                                              IActivateAudioInterfaceCompletionHandler *h, IActivateAudioInterfaceAsyncOperation **op)
{
    AOP *o; void *obj = NULL; HRESULT hr = E_NOINTERFACE;
    if (!path || !iid || !h || !op) return E_POINTER;
    *op = NULL;
    if (!(o = (AOP *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(AOP)))) return E_OUTOFMEMORY;
    o->vt = &g_op_vt; o->ref = 1;
    if (wcontains(path, L"Process_Loopback")) {
        /* AUDIOCLIENT_ACTIVATION_PARAMS: ActivationType (1 = process loopback), TargetProcessId, ProcessLoopbackMode
         * (0 include target process tree, 1 exclude it) */
        DWORD type = 0, pid = 0, mode = 0;
        if (params && params->vt == VT_BLOB && params->blob.cbSize >= 12 && params->blob.pBlobData) {
            const DWORD *p = (const DWORD *)params->blob.pBlobData; type = p[0]; pid = p[1]; mode = p[2];
        }
        if (!same_guid(iid, &kIID_IAudioClient)) hr = E_NOINTERFACE;
        else if (type != 1) hr = E_INVALIDARG;
        else if (SUCCEEDED(hr = new_client(&obj, F_LOOPBACK))) {
            CLIENT *c = (CLIENT *)obj; c->lb_target = pid; c->lb_mode = mode == 0 ? 1 : 2;
            if (pid == 4 && mode == 1) c->lb_mode = 0;          /* "all devices" form: exclude the System process = everything */
        }
        alog("ActivateAudioInterfaceAsync(process loopback, type %lu, process %08lx, mode %lu) = %08lx", type, pid, mode, hr);
    } else {
        BOOL cap = wcontains(path, L"{0.0.1.") || wcontains(path, L"{2EEF81BE-33FA-4800-9670-1CD474972C3F}");  /* capture id / DEVINTERFACE_AUDIO_CAPTURE */
        if (same_guid(iid, &kIID_IAudioClient)) hr = new_client(&obj, cap ? F_CAPTURE : F_RENDER);
        alog("ActivateAudioInterfaceAsync(endpoint, %s) = %08lx", cap ? "capture" : "render", hr);
    }
    o->hr = hr; o->unk = (IUnknown *)obj;
    *op = (IActivateAudioInterfaceAsyncOperation *)o; op_addref(*op);
    IActivateAudioInterfaceCompletionHandler_ActivateCompleted(h, *op);
    op_release((IActivateAudioInterfaceAsyncOperation *)o);
    return S_OK;
}

/* ================================================================== class factory + DLL entry points */
static volatile LONG g_locks;
static HRESULT STDMETHODCALLTYPE cf_qi(IClassFactory *t, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    if (same_guid(iid, &kIID_IUnknown) || same_guid(iid, &kIID_IClassFactory)) { *pv = t; return S_OK; }
    *pv = NULL; return E_NOINTERFACE;
}
static HRESULT STDMETHODCALLTYPE cf_create(IClassFactory *t, IUnknown *outer, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    *pv = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    return en_qi((IMMDeviceEnumerator *)&g_en, iid, pv);
}
static HRESULT STDMETHODCALLTYPE cf_lock(IClassFactory *t, BOOL lock)
{
    if (lock) InterlockedIncrement(&g_locks); else InterlockedDecrement(&g_locks);
    return S_OK;
}
static IClassFactoryVtbl g_cf_vt = { cf_qi, (void *)st_addref, (void *)st_release, cf_create, cf_lock };
static struct { IClassFactoryVtbl *vt; } g_cf = { &g_cf_vt };

HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, void **pv)
{
    if (!pv) return E_POINTER;
    *pv = NULL;
    if (!same_guid(clsid, &kCLSID_MMDeviceEnumerator)) return CLASS_E_CLASSNOTAVAILABLE;
    return cf_qi((IClassFactory *)&g_cf, iid, pv);
}
HRESULT WINAPI DllCanUnloadNow(void) { return S_FALSE; }   /* audio threads may be running */

#define SELFREG_E_CLASS_K ((HRESULT)0x80040201L)
#define CLSID_KEY "CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291692E}"
HRESULT WINAPI DllRegisterServer(void)
{
    char path[MAX_PATH]; HKEY k; LONG e;
    if (!GetModuleFileNameA(g_inst, path, sizeof(path))) return E_FAIL;
    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, CLSID_KEY, 0, NULL, 0, KEY_WRITE, NULL, &k, NULL)) return SELFREG_E_CLASS_K;
    RegSetValueExA(k, NULL, 0, REG_SZ, (const BYTE *)"MMDeviceEnumerator class (KernelEx-NG)", 39);
    RegCloseKey(k);
    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, CLSID_KEY "\\InprocServer32", 0, NULL, 0, KEY_WRITE, NULL, &k, NULL)) return SELFREG_E_CLASS_K;
    e = RegSetValueExA(k, NULL, 0, REG_SZ, (const BYTE *)path, lstrlenA(path) + 1);
    if (!e) e = RegSetValueExA(k, "ThreadingModel", 0, REG_SZ, (const BYTE *)"Both", 5);
    RegCloseKey(k);
    return e ? SELFREG_E_CLASS_K : S_OK;
}
HRESULT WINAPI DllUnregisterServer(void)
{
    RegDeleteKeyA(HKEY_CLASSES_ROOT, CLSID_KEY "\\InprocServer32");
    RegDeleteKeyA(HKEY_CLASSES_ROOT, CLSID_KEY);
    return S_OK;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID r)
{
    if (why == DLL_PROCESS_ATTACH) { g_inst = h; DisableThreadLibraryCalls(h); }
    return TRUE;
}
