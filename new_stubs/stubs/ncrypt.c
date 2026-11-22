/* ncrypt.dll for Windows 98 SE: on Windows ncrypt.dll also exports BCryptGenRandom (Firefox 115's osclientcerts.dll
 * imports it from there). Same generator as the bcrypt.dll stub (kexnt's KexGenRandom). */
#include <windows.h>
__declspec(dllimport) BOOL WINAPI KexGenRandom(PVOID buf, SIZE_T len);
LONG WINAPI BCryptGenRandom(void *h, PUCHAR buf, ULONG len, ULONG flags)
{
    if (!buf && len) return (LONG)0xC000000DL;
    if (len) KexGenRandom(buf, len);
    return 0;                       /* any handle: there is only one generator here */
}
