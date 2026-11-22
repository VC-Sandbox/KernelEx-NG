/* bcryptprimitives.dll for Windows 98 SE: ProcessPrng from kexnt's ChaCha20 generator
 * (seeded from CryptoAPI + timers; see sysdll_ext.c). Never fails, like the real one. */
#include <windows.h>
__declspec(dllimport) BOOL WINAPI KexGenRandom(PVOID buf, SIZE_T len);
BOOL WINAPI ProcessPrng(PBYTE buf, SIZE_T len) { if (len) KexGenRandom(buf, len); return TRUE; }
