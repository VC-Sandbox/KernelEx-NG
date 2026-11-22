/* qdd.c - QDD.EXE out: what Windows 98's own QueryDosDeviceA answers (Windows 95 program: KernelEx/kexnt not used) */
#include <windows.h>
#include <stdio.h>
int main(int argc, char **argv)
{
    static const char *n[] = { "A:", "C:", "D:", "E:", "F:", "NUL", "COM1", "LPT1", "c:", NULL };
    char buf[2048]; int i; DWORD r; FILE *o = fopen(argv[1], "w");
    for (i = 0; ; i++) {
        const char *nm = n[i]; SetLastError(0xdead);
        r = QueryDosDeviceA(nm, buf, sizeof(buf));
        fprintf(o, "%s: ret %lu err %lu", nm ? nm : "(NULL)", r, GetLastError());
        if (r) { DWORD k; fprintf(o, " ["); for (k = 0; k < r && k < 300; k++) fputc(buf[k] ? buf[k] : '|', o); fprintf(o, "]"); }
        fprintf(o, "  type %u\n", nm ? GetDriveTypeA(nm) : 0);
        if (!nm) break;
    }
    fclose(o); return 0;
}
