#include <windows.h>
#include <stdio.h>
__declspec(dllexport) int KexNG_ModernProcess = 1;
int main(void){ HMODULE k=LoadLibraryA("C:\\WINDOWS\\KERNELEX\\KEXNT.DLL"); LONG (WINAPI*f)(void)=(void*)GetProcAddress(k,"KexLoaderFix");
 LONG (WINAPI*s)(PDWORD)=(void*)GetProcAddress(k,"KexFwdStats"); DWORD v[5]={0}; LONG r=f?f():-999, q=s?s(v):-999;
 FILE*o=fopen("C:\\LFX.TXT","w"); fprintf(o,"KexLoaderFix %ld  FwdStats %ld markers %lu thunks %lu resolved %lu unresolved %lu loads %lu\n", r,q,v[0],v[1],v[2],v[3],v[4]); fclose(o); return 0;}
