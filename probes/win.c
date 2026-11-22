#include <windows.h>
#include <mmsystem.h>
#include <stdio.h>
int main(void)
{
    FILE *o = fopen("C:\\WIN.TXT", "w"); WAVEFORMATEX f; HWAVEIN wi; HANDLE ev = CreateEventA(NULL, FALSE, FALSE, NULL);
    static short buf[4][9600]; WAVEHDR h[4]; int i, done = 0; MMRESULT r; DWORD t0; WAVEINCAPSA caps; UINT rates[] = {48000, 44100, 22050, 11025}; int k;
    fprintf(o, "waveInGetNumDevs %u\n", waveInGetNumDevs());
    if (!waveInGetDevCapsA(0, &caps, sizeof(caps))) fprintf(o, "dev0 %s formats %08lx ch %u\n", caps.szPname, caps.dwFormats, caps.wChannels);
    for (k = 0; k < 4; k++) {
        f.wFormatTag = WAVE_FORMAT_PCM; f.nChannels = 2; f.nSamplesPerSec = rates[k]; f.wBitsPerSample = 16; f.nBlockAlign = 4; f.nAvgBytesPerSec = rates[k] * 4; f.cbSize = 0;
        r = waveInOpen(&wi, WAVE_MAPPER, &f, (DWORD_PTR)ev, 0, CALLBACK_EVENT);
        fprintf(o, "open %u: %u\n", rates[k], r); if (r) continue;
        for (i = 0; i < 4; i++) { memset(&h[i], 0, sizeof(h[i])); h[i].lpData = (LPSTR)buf[i]; h[i].dwBufferLength = rates[k] / 50 * 4; waveInPrepareHeader(wi, &h[i], sizeof(h[i])); waveInAddBuffer(wi, &h[i], sizeof(h[i])); }
        r = waveInStart(wi); t0 = GetTickCount(); done = 0;
        while (GetTickCount() - t0 < 2000) { WaitForSingleObject(ev, 100); for (i = 0; i < 4; i++) if (h[i].dwFlags & WHDR_DONE) { done++; waveInUnprepareHeader(wi, &h[i], sizeof(h[i])); h[i].dwFlags = 0; waveInPrepareHeader(wi, &h[i], sizeof(h[i])); waveInAddBuffer(wi, &h[i], sizeof(h[i])); } }
        { MMTIME mt; mt.wType = TIME_BYTES; waveInGetPosition(wi, &mt, sizeof(mt)); fprintf(o, "  start %u, blocks done in 2 s: %d, position %lu bytes\n", r, done, mt.u.cb); }
        waveInReset(wi); for (i = 0; i < 4; i++) waveInUnprepareHeader(wi, &h[i], sizeof(h[i])); waveInClose(wi);
    }
    fclose(o); return 0;
}
