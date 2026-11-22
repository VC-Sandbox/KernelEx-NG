/*
 * kexcfg.c - what the RUNNING KernelEx core actually loaded.
 *
 * For every configuration listed in core.ini [ApiConfigurations] it asks KERNELEX.DLL to assign that
 * configuration to a dummy file and reads it back (kexSetModuleSettings / kexGetModuleSettings). The core
 * only keeps names it has loaded, so a configuration that failed at boot comes back empty.
 * Also prints the KernelEx version and whether vectored exception handling can start (KexVehState).
 * Log: KEXCFG.LOG next to this program.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

static FILE *g_log;
#define LOG(...) do { printf(__VA_ARGS__); if (g_log) { fprintf(g_log, __VA_ARGS__); fflush(g_log); } } while (0)

typedef void (__cdecl *GETMS)(const char *, char *, DWORD *);
typedef void (__cdecl *SETMS)(const char *, const char *, DWORD);
typedef void (__cdecl *RESETMS)(const char *);
typedef unsigned long (__cdecl *GETVER)(void);
typedef LONG (WINAPI *VEHSTATE)(void);
typedef PVOID (WINAPI *ADDVEH)(ULONG, PVECTORED_EXCEPTION_HANDLER);
typedef ULONG (WINAPI *REMVEH)(PVOID);

static LONG CALLBACK dummy_veh(PEXCEPTION_POINTERS ep) { return EXCEPTION_CONTINUE_SEARCH; }

int main(void)
{
    char dir[MAX_PATH], ini[MAX_PATH], probe[MAX_PATH], self[MAX_PATH], *bs;
    HKEY k;
    DWORD type, size = sizeof(dir);
    HMODULE kx;
    GETMS getms; SETMS setms; RESETMS resetms; GETVER getver;
    int i, bad = 0;

    GetModuleFileNameA(NULL, self, MAX_PATH);
    strcpy(probe, self);
    if ((bs = strrchr(probe, '\\'))) strcpy(bs + 1, "KEXCFG.PRB"); else strcpy(probe, "C:\\KEXCFG.PRB");
    {
        char logp[MAX_PATH]; strcpy(logp, self);
        if ((bs = strrchr(logp, '\\'))) strcpy(bs + 1, "kexcfg.log");
        g_log = fopen(logp, "a");
    }
    LOG("kexcfg\n");
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\KernelEx", 0, KEY_READ, &k) != ERROR_SUCCESS ||
        RegQueryValueExA(k, "InstallDir", NULL, &type, (BYTE *)dir, &size) != ERROR_SUCCESS) {
        LOG("  KernelEx is not installed\n"); return 1;
    }
    RegCloseKey(k);
    if (dir[strlen(dir) - 1] != '\\') strcat(dir, "\\");
    sprintf(ini, "%score.ini", dir);
    strcat(dir, "KERNELEX.DLL");
    kx = GetModuleHandleA("KERNELEX.DLL");
    if (!kx) kx = LoadLibraryA(dir);
    if (!kx) { LOG("  cannot load %s (%lu)\n", dir, GetLastError()); return 1; }
    getms = (GETMS)GetProcAddress(kx, "kexGetModuleSettings");
    setms = (SETMS)GetProcAddress(kx, "kexSetModuleSettings");
    resetms = (RESETMS)GetProcAddress(kx, "kexResetModuleSettings");
    getver = (GETVER)GetProcAddress(kx, "kexGetKEXVersion");
    {
        static const char *names[] = { "kexAllocObject", "kexPsAllocIndex", "kexPsGetValue", "kexPsSetValue",
                                        "kexGetModuleSettings", "kexSetModuleSettings", "kexGetKEXVersion" };
        LOG("  KERNELEX.DLL at %08lx, version %08lx\n", (DWORD)(ULONG_PTR)kx, getver ? getver() : 0UL);
        LOG("  exports:");
        for (i = 0; i < 7; i++) LOG(" %s=%s", names[i], GetProcAddress(kx, names[i]) ? "yes" : "NO");
        LOG("\n");
    }
    if (!getms || !setms || !resetms) { LOG("  module settings API missing\n"); return 1; }

    LOG("  configurations in %s (loaded = the running core knows it):\n", ini);
    for (i = 0; i < 4096; i++) {
        char key[8], name[256], desc[256], got[256];
        DWORD flags = 0;
        sprintf(key, "%d", i);
        if (!GetPrivateProfileStringA("ApiConfigurations", key, "", name, sizeof(name), ini)) break;
        GetPrivateProfileStringA(name, "desc", name, desc, sizeof(desc), ini);
        setms(probe, name, 128 /* KRF_VALID_FLAG */);
        got[0] = 0;
        getms(probe, got, &flags);
        LOG("   %2d %-11s %-28s %s\n", i, name, desc, strcmp(got, name) ? "NOT LOADED" : "loaded");
        if (strcmp(got, name)) bad++;
    }
    resetms(probe);
    LOG("  %d configuration(s) not loaded by the core\n", bad);

    {   /* VEH: kexnt.dll next to this program (as kextest does) */
        char p[MAX_PATH]; HMODULE kn; VEHSTATE st; ADDVEH add; REMVEH rem;
        strcpy(p, self); if ((bs = strrchr(p, '\\'))) strcpy(bs + 1, "kexnt.dll");
        kn = LoadLibraryA(p);
        st = kn ? (VEHSTATE)GetProcAddress(kn, "KexVehState") : NULL;
        add = kn ? (ADDVEH)GetProcAddress(kn, "AddVectoredExceptionHandler") : NULL;
        rem = kn ? (REMVEH)GetProcAddress(kn, "RemoveVectoredExceptionHandler") : NULL;
        if (st && add && rem) {
            PVOID h = add(0, dummy_veh);
            LOG("  vectored exceptions: KexVehState = %ld\n", st());
            {
                typedef VOID (WINAPI *VEHDIAG)(PDWORD);
                VEHDIAG dg = (VEHDIAG)GetProcAddress(kn, "KexVehDiag");
                DWORD d[8] = { 0 }, kxp = 0;
                if (getver && getver() == 0x04050078UL && !IsBadReadPtr((void *)0xBFA0A1C4, 4))
                    kxp = *(DWORD *)0xBFA0A1C4;           /* KernelEx 4.5.2's pppdbCur (from its kexPsGetValue) */
                if (dg) dg(d);
                LOG("    diag: ppdbCur %08lx  PDB %08lx  index %lu  [PDB+C4] %08lx  slot %08lx  KernelEx pppdbCur %08lx -> %08lx\n",
                    d[0], d[1], d[2], d[3], d[4], kxp, (kxp && !IsBadReadPtr((void *)kxp, 4)) ? *(DWORD *)kxp : 0UL);
            }
            LOG("    (1 ok; -1 no KERNELEX.DLL; -2 no kexPs* exports; -3/-4 KERNEL32 dispatcher/continue not found;\n"
                "     -5 no space in KERNEL32 .text; -6 storage index; -7 patch race; -8 foreign hook;\n"
                "     -9 slot re-check; -10 slot not found; -11 KERNEL32 page not writable; -12 kexPs round trip;\n"
                "     -13 several candidates; -14 KERNEL32 current-process global not found)\n");
            if (h) rem(h);
        } else LOG("  kexnt.dll next to kexcfg.exe not found\n");
    }
    LOG("\n");
    if (g_log) fclose(g_log);
    printf("Press Enter to close...");
    getchar();
    return 0;
}
