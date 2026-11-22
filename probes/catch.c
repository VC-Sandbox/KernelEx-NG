/* catch.c - CATCH.EXE <dir pattern> <file pattern> <out dir> <seconds>: copy files matching <file pattern> inside
 * directories matching <dir pattern> as soon as they appear (Inno Setup's is-XXXXX.tmp setup program) */
#include <windows.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
    char base[MAX_PATH], *s, dp[MAX_PATH], fp[MAX_PATH], src[MAX_PATH], dst[MAX_PATH]; DWORD end; int got = 0;
    WIN32_FIND_DATAA d, f; HANDLE hd, hf;
    if (argc < 5) return 1;
    lstrcpyA(base, argv[1]); if ((s = strrchr(base, '\\'))) s[1] = 0;
    end = GetTickCount() + atoi(argv[4]) * 1000;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    while (GetTickCount() < end && !got) {
        hd = FindFirstFileA(argv[1], &d);
        if (hd != INVALID_HANDLE_VALUE) do {
            sprintf(dp, "%s%s\\%s", base, d.cFileName, argv[2]);
            hf = FindFirstFileA(dp, &f);
            if (hf != INVALID_HANDLE_VALUE) {
                do { if (f.nFileSizeLow) { sprintf(src, "%s%s\\%s", base, d.cFileName, f.cFileName); sprintf(dst, "%s\\%s", argv[3], f.cFileName);
                       Sleep(30); if (CopyFileA(src, dst, FALSE)) got = 1; } } while (FindNextFileA(hf, &f));
                FindClose(hf);
            }
        } while (FindNextFileA(hd, &d));
        if (hd != INVALID_HANDLE_VALUE) FindClose(hd);
        Sleep(1);
    }
    return got ? 0 : 2;
}
