/* wout.c - WOUT.EXE <out> <case>: waveOutPrepareHeader/Write with the WAVEHDR and data in different places
 * case 1: private memory (VirtualAlloc), case 2: header private, data in a shared section view (above 2 GB),
 * case 3: header and data in a shared section view (above 2 GB). Windows 4.0 program (kexnt stays out). */
#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    FILE *o = fopen(argv[1], "a"); int c = atoi(argv[2]); HWAVEOUT wo; WAVEFORMATEX f = {0}; MMRESULT r;
    BYTE *priv = (BYTE *)VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);
    HANDLE m = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 65536, NULL);
    BYTE *sh = (BYTE *)MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 65536);
    WAVEHDR *h; BYTE *data;
    f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = 2; f.nSamplesPerSec = 44100; f.wBitsPerSample = 16;
    f.nBlockAlign = 4; f.nAvgBytesPerSec = 44100 * 4;
    r = waveOutOpen(&wo, WAVE_MAPPER, &f, 0, 0, CALLBACK_NULL);
    fprintf(o, "case %d: priv %p shared %p open %u\n", c, priv, sh, r); fflush(o);
    if (r) return 1;
    h = (WAVEHDR *)(c == 3 ? sh : priv); data = (c == 1 ? priv : sh) + 4096;
    ZeroMemory(h, sizeof(*h)); h->lpData = (LPSTR)data; h->dwBufferLength = 8192;
    r = waveOutPrepareHeader(wo, h, sizeof(*h)); fprintf(o, "  prepare %u (header %p data %p)\n", r, h, data); fflush(o);
    if (!r) { r = waveOutWrite(wo, h, sizeof(*h)); fprintf(o, "  write %u\n", r); fflush(o); Sleep(300);
              waveOutReset(wo); r = waveOutUnprepareHeader(wo, h, sizeof(*h)); fprintf(o, "  unprepare %u\n", r); }
    waveOutClose(wo); fclose(o); return 0;
}
