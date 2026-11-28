/* svcacl.c - probe: the calls a service-ACL custom action (WiX ExecSecureObjects on the .NET 3.0 SP2 font cache
 * service) makes, and what each returns on Windows 98 + KernelEx.  SVCACL.EXE [service] [account] > out.txt */
#include <windows.h>
#include <aclapi.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    WCHAR svc[128] = L"FontCache3.0.0.0", acc[128] = L"INTERACTIVE", dom[128]; BYTE sid[128];
    DWORD cs = sizeof(sid), cd = 128, r; SID_NAME_USE use; SC_HANDLE m, s; PACL dacl = NULL, nd = NULL;
    PSECURITY_DESCRIPTOR sd = NULL; EXPLICIT_ACCESSW ea;
    if (argc > 1) MultiByteToWideChar(CP_ACP, 0, argv[1], -1, svc, 128);
    if (argc > 2) MultiByteToWideChar(CP_ACP, 0, argv[2], -1, acc, 128);
    SetLastError(0); m = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    printf("OpenSCManagerW -> %p  gle %lu\n", (void *)m, GetLastError());
    SetLastError(0); s = m ? OpenServiceW(m, svc, READ_CONTROL | WRITE_DAC) : NULL;
    printf("OpenServiceW -> %p  gle %lu\n", (void *)s, GetLastError());
    if (s) {
        r = GetSecurityInfo(s, SE_SERVICE, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
        printf("GetSecurityInfo(SE_SERVICE) -> %lu  dacl %p\n", r, (void *)dacl);
    }
    r = GetNamedSecurityInfoW(svc, SE_SERVICE, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &sd);
    printf("GetNamedSecurityInfoW(SE_SERVICE) -> %lu  dacl %p\n", r, (void *)dacl);
    SetLastError(0); r = LookupAccountNameW(NULL, acc, sid, &cs, dom, &cd, &use);
    printf("LookupAccountNameW(%ls) -> %lu  gle %lu  use %d\n", acc, r, GetLastError(), (int)use);
    ZeroMemory(&ea, sizeof(ea)); BuildExplicitAccessWithNameW(&ea, acc, 16, GRANT_ACCESS, 0);
    r = SetEntriesInAclW(1, &ea, dacl, &nd);
    printf("SetEntriesInAclW(name) -> %lu  acl %p\n", r, (void *)nd);
    if (s) { r = SetSecurityInfo(s, SE_SERVICE, DACL_SECURITY_INFORMATION, NULL, NULL, nd, NULL); printf("SetSecurityInfo -> %lu\n", r); }
    r = SetNamedSecurityInfoW(svc, SE_SERVICE, DACL_SECURITY_INFORMATION, NULL, NULL, nd, NULL);
    printf("SetNamedSecurityInfoW(SE_SERVICE) -> %lu\n", r);
    return 0;
}
