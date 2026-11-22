/* KernelEx-NG: the few KernelEx core constants sheet.dll needs, for MinGW builds (kexcoresdk.h pulls in
 * kstructs.h with MSVC inline assembly). Values from common/kexcoresdk.h. */
#ifndef KEXCORE_MIN_H
#define KEXCORE_MIN_H
#define KCC_DEBUG                1
#define KCC_APIHOOK              2
#define KRF_KEX_DISABLE          1
#define KRF_OVERRIDE_PROC_MOD    2
#define KRF_HOOK_APIS            8
#define KRF_NO_INHERIT          16
#define KRF_VALID_FLAG         128
#endif
