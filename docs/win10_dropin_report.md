# Windows 10 DLLs as drop-ins on Windows 98 SE + KernelEx + KernelEx-NG

"missing" = static imports nothing provides yet (the DLL will not load). "delay" = delay-load imports (fail only when called). "Nt calls" = direct NT system-call wrappers it imports.

| DLL | imports | missing | delay missing | Nt calls | verdict |
|---|---|---|---|---|---|
| ucrtbase | 131 | 0 | 0 | 0 | loads now |
| bcryptprimitives | 59 | 20 | 0 | 6 | needs work |
| ncrypt | 94 | 22 | 8 | 1 | needs work |
| version | 74 | 26 | 0 | 0 | needs work |
| psapi | 33 | 28 | 0 | 0 | needs work |
| bcrypt | 83 | 29 | 0 | 7 | needs work |
| dbghelp | 256 | 30 | 0 | 2 | needs work |
| powrprof | 128 | 30 | 18 | 2 | needs work |
| iphlpapi | 153 | 48 | 40 | 11 | needs work |
| winmm | 312 | 48 | 172 | 8 | needs work |
| dwrite | 248 | 54 | 41 | 5 | needs work |
| userenv | 238 | 56 | 31 | 1 | needs work |
| dwmapi | 184 | 60 | 3 | 11 | needs work |
| propsys | 447 | 60 | 154 | 0 | needs work |
| crypt32 | 477 | 69 | 122 | 3 | needs work |
| d3d11 | 356 | 69 | 141 | 5 | needs work |
| oleaut32 | 318 | 72 | 40 | 0 | needs work |
| shcore | 339 | 75 | 78 | 3 | needs work |
| uxtheme | 438 | 91 | 16 | 5 | needs work |
| winhttp | 464 | 91 | 107 | 4 | needs work |
| dxgi | 386 | 100 | 117 | 23 | needs work |
| ws2_32 | 254 | 100 | 7 | 10 | needs work |
| shlwapi | 665 | 128 | 112 | 3 | needs work |
| ole32 | 779 | 154 | 140 | 11 | needs work |
| sechost | 364 | 160 | 20 | 21 | needs work |
| combase | 691 | 215 | 138 | 19 | needs work |
| advapi32 | 762 | 294 | 102 | 45 | needs work |
| shell32 | 2549 | 347 | 1110 | 25 | needs work |
| ntdll | 0 | 0 | 0 | 0 | kernel boundary - reimplement, do not load |
| win32u | 3 | 3 | 0 | 1 | kernel boundary - reimplement, do not load |
| gdi32 | 740 | 168 | 546 | 126 | kernel boundary - reimplement, do not load |
| gdi32full | 714 | 437 | 28 | 363 | kernel boundary - reimplement, do not load |
| kernelbase | 893 | 574 | 181 | 192 | kernel boundary - reimplement, do not load |
| kernel32 | 1254 | 721 | 6 | 93 | kernel boundary - reimplement, do not load |
| user32 | 1028 | 734 | 23 | 589 | kernel boundary - reimplement, do not load |

## bcryptprimitives

- **ntdll** (12): EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, NtQueryInformationProcess, RtlGetCurrentProcessorNumberEx, RtlUnhandledExceptionFilter, _alloca_probe, _vsnwprintf, wcscpy_s
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (3): DisableThreadLibraryCalls, GetModuleFileNameW, GetModuleHandleExW
- **no api-set shell api-ms-win-core-xstate-l2-1-0** (1): GetEnabledXStateFeatures

## ncrypt

- **ntdll** (6): EtwTraceMessage, LdrDisableThreadCalloutsForDll, RtlFreeAnsiString, RtlUnhandledExceptionFilter, _alloca_probe, _vsnwprintf
- **ntasn1** (6): #2 (delay), #3 (delay), #37 (delay), #4 (delay), #5 (delay), #6 (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (4): FreeLibrary, GetModuleFileNameW, GetProcAddress, LoadLibraryExW
- **not in our api-ms-win-eventing-classicprovider-l1-1-0** (4): GetTraceEnableFlags, GetTraceEnableLevel, GetTraceLoggerHandle, UnregisterTraceGuids
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (3): EventRegister, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-heap-l2-1-0** (2): LocalAlloc, LocalFree
- **cryptsp** (2): CryptGetKeyParam (delay), CryptGetProvParam (delay)
- **no api-set shell api-ms-win-eventing-obsolete-l1-1-0** (1): RegisterTraceGuidsA
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-rtlsupport-l1-2-0** (1): RtlCompareMemory

## version

- **kernel32** (5): LZClose, LZCloseFile, LZCopy, LZCreateFileW, LZInit
- **no api-set shell api-ms-win-core-versionansi-l1-1-0** (4): GetFileVersionInfoExA, GetFileVersionInfoSizeExA, VerFindFileA, VerQueryValueA
- **kernelbase** (3): lstrcmpiA, lstrcmpiW, lstrlenW
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **no api-set shell api-ms-win-core-version-l1-1-1** (2): GetFileVersionInfoSizeW, GetFileVersionInfoW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (2): FreeLibrary, GetProcAddress
- **no api-set shell api-ms-win-core-heap-l2-1-0** (2): LocalAlloc, LocalFree
- **no api-set shell api-ms-win-core-versionansi-l1-1-1** (2): GetFileVersionInfoA, GetFileVersionInfoSizeA
- **msvcrt** (1): _except_handler4_common
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryW
- **no api-set shell api-ms-win-core-version-private-l1-1-0** (1): GetFileVersionInfoByHandle
- **ntdll** (1): NlsMbCodePageTag

## psapi

- **no api-set shell api-ms-win-core-psapi-l1-1-0** (20): K32EmptyWorkingSet, K32EnumDeviceDrivers, K32EnumPageFilesW, K32EnumProcessModules, K32EnumProcessModulesEx, K32EnumProcesses, K32GetDeviceDriverBaseNameW, K32GetDeviceDriverFileNameW, K32GetMappedFileNameW, K32GetModuleBaseNameW, K32GetModuleFileNameExW, K32GetModuleInformation, K32GetPerformanceInfo, K32GetProcessImageFileNameW, K32GetProcessMemoryInfo, K32GetWsChanges, K32GetWsChangesEx, K32InitializeProcessForWsWatch, K32QueryWorkingSet, K32QueryWorkingSetEx
- **no api-set shell api-ms-win-core-psapi-ansi-l1-1-0** (5): K32EnumPageFilesA, K32GetDeviceDriverBaseNameA, K32GetDeviceDriverFileNameA, K32GetMappedFileNameA, K32GetProcessImageFileNameA
- **no api-set shell api-ms-win-core-psapi-obsolete-l1-1-0** (2): K32GetModuleBaseNameA, K32GetModuleFileNameExA
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (1): DisableThreadLibraryCalls

## bcrypt

- **ntdll** (18): EtwEventRegister, EtwEventUnregister, EtwEventWrite, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, LdrDisableThreadCalloutsForDll, NtQueryInformationProcess, RtlAcquireResourceExclusive, RtlAcquireResourceShared, RtlDeleteResource, RtlInitializeResource, RtlReleaseResource, RtlUnhandledExceptionFilter, _alloca_probe
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (5): FreeLibrary, GetModuleFileNameW, GetModuleHandleExW, GetProcAddress, LoadLibraryExW
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (1): QueryFullProcessImageNameW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI

## dbghelp

- **ntdll** (7): NtQueryInformationProcess, NtQueryObject, RtlCreateQueryDebugBuffer, RtlDestroyQueryDebugBuffer, RtlQueryProcessDebugInformation, RtlRunOnceExecuteOnce, RtlUTF8ToUnicodeN
- **no api-set shell api-ms-win-core-localregistry-l1-1-0** (5): RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW
- **no api-set shell api-ms-win-core-threadpool-l1-1-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventActivityIdControl, EventRegister, EventUnregister, EventWriteTransfer
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateMutexExW, CreateSemaphoreExW, OpenProcess
- **no api-set shell api-ms-win-core-misc-l1-1-0** (3): FormatMessageW, LocalAlloc, Sleep
- **no api-set shell api-ms-win-core-localization-l1-1-0** (2): LCMapStringEx, LCMapStringW
- **not in our api-ms-win-core-sysinfo-l1-1-0** (1): SystemTimeToFileTime
- **no api-set shell api-ms-win-downlevel-kernel32-l2-1-0** (1): LocalFree

## powrprof

- **ntdll** (10): LdrAddRefDll, RtlAllocateWnfSerializationGroup, RtlGetActiveConsoleId, RtlPublishWnfStateData, RtlQueryWnfStateData, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfNotificationWaitForCompletion, RtlUnsubscribeWnfNotificationWithCompletionCallback, RtlUnsubscribeWnfStateChangeNotification, RtlWnfDllUnloadCallback
- **umpdc** (7): PdcAcquireRwLockExclusive (delay), PdcPortClose (delay), PdcPortOpen (delay), PdcPortSendMessage (delay), PdcReleaseRwLockExclusive (delay), PdcRwLockInitialize (delay), PdcSleep (delay)
- **wmiclnt** (5): WmiCloseBlock (delay), WmiDevInstToInstanceNameW (delay), WmiOpenBlock (delay), WmiQuerySingleInstanceW (delay), WmiSetSingleInstanceW (delay)
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-devices-query-l1-1-0** (3): DevCloseObjectQuery (delay), DevCreateObjectQuery (delay), DevCreateObjectQueryFromId (delay)
- **no api-set shell api-ms-win-service-private-l1-1-0** (3): I_ScPnPGetServiceName (delay), I_ScSendPnPMessage (delay), I_ScValidatePnPService (delay)
- **not in our api-ms-win-core-registry-l1-1-0** (2): RegDeleteKeyExW, RegGetValueW
- **no api-set shell api-ms-win-core-heap-l2-1-0** (2): LocalAlloc, LocalFree
- **rpcrt4** (2): I_RpcExceptionFilter, NdrClientCall4
- **not in our api-ms-win-core-wow64-l1-1-0** (2): Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (1): DisableThreadLibraryCalls
- **no api-set shell api-ms-win-core-localization-private-l1-1-0** (1): LoadStringByReference
- **no api-set shell api-ms-win-core-realtime-l1-1-1** (1): QueryInterruptTime
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI

## iphlpapi

- **no api-set shell api-ms-win-core-crt-l1-1-0** (14): _except_handler4_common, _vsnprintf_s, _vsnwprintf_s, _wcsicmp, _wcsnicmp, _wtoi, iswdigit, memcmp, memcpy, memset, qsort_s, wcschr, wcscpy_s, wcsncmp
- **ntdll** (14): NtQueryInformationProcess, NtQueryWnfStateData, RtlAppendUnicodeStringToString, RtlGUIDFromString, RtlGetPersistedStateLocation, RtlIdnToAscii, RtlIpv4AddressToStringA, RtlIpv4StringToAddressExW, RtlIpv6StringToAddressExW, RtlStringFromGUID, RtlSubscribeWnfStateChangeNotification, RtlTimeToSecondsSince1970, RtlUnsubscribeWnfNotificationWaitForCompletion, ZwCreateFile
- **dhcpcsvc** (10): DhcpAcquireParameters (delay), DhcpEnableDhcp (delay), DhcpEnumInterfaces (delay), DhcpFreeEnumeratedInterfaces (delay), DhcpFreeLeaseInfo (delay), DhcpFreeLeaseInfoArray (delay), DhcpIsEnabled (delay), DhcpQueryLeaseInfo (delay), DhcpQueryLeaseInfoArray (delay), DhcpReleaseParameters (delay)
- **dnsapi** (10): DnsApiFree (delay), DnsFreeAdaptersInfo (delay), DnsGetAdaptersInfo (delay), DnsGetInterfaceSettings (delay), DnsGetSettings (delay), DnsQueryConfig (delay), DnsSetInterfaceSettings (delay), DnsSetSettings (delay), DnsValidateName_UTF8 (delay), DnsValidateName_W (delay)
- **nsi** (10): NsiAllocateAndGetTable (delay), NsiCancelChangeNotification (delay), NsiEnumerateObjectsAllParameters (delay), NsiFreeTable (delay), NsiGetAllParameters (delay), NsiGetParameter (delay), NsiRequestChangeNotification (delay), NsiSetAllParameters (delay), NsiSetAllPersistentParametersWithMask (delay), NsiSetParameter (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (6): DisableThreadLibraryCalls, FreeLibrary, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (5): CallbackMayRunLong, CloseThreadpoolWork, CreateThreadpoolWork, SubmitThreadpoolWork, WaitForThreadpoolWorkCallbacks
- **not in our api-ms-win-eventing-classicprovider-l1-1-0** (5): GetTraceEnableFlags, GetTraceEnableLevel, GetTraceLoggerHandle, RegisterTraceGuidsW, UnregisterTraceGuids
- **winnsi** (5): NsiConnectToServer (delay), NsiDisconnectFromServer (delay), NsiRpcDeregisterChangeNotification (delay), NsiRpcGetParameter (delay), NsiRpcRegisterChangeNotification (delay)
- **no api-set shell api-ms-win-core-crt-l2-1-0** (3): _initterm, _initterm_e, time
- **ws2_32** (3): #14 (delay), #15 (delay), #8 (delay)
- **dhcpcsvc6** (2): Dhcpv6FreeLeaseInfoArray (delay), Dhcpv6QueryLeaseInfoArray (delay)
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI

## winmm

- **no api-set shell api-ms-win-mm-mme-l1-1-0** (102): auxGetDevCapsA (delay), auxGetDevCapsW (delay), auxGetNumDevs (delay), auxGetVolume (delay), auxOutMessage (delay), auxSetVolume (delay), midiConnect (delay), midiDisconnect (delay), midiInAddBuffer (delay), midiInClose (delay), midiInGetDevCapsA (delay), midiInGetDevCapsW (delay), midiInGetErrorTextA (delay), midiInGetErrorTextW (delay), midiInGetID (delay), midiInGetNumDevs (delay), midiInMessage (delay), midiInOpen (delay), midiInPrepareHeader (delay), midiInReset (delay), midiInStart (delay), midiInStop (delay), midiInUnprepareHeader (delay), midiOutCacheDrumPatches (delay), midiOutCachePatches (delay), midiOutClose (delay), midiOutGetDevCapsA (delay), midiOutGetDevCapsW (delay), midiOutGetErrorTextA (delay), midiOutGetErrorTextW (delay), midiOutGetID (delay), midiOutGetNumDevs (delay), midiOutGetVolume (delay), midiOutLongMsg (delay), midiOutMessage (delay), midiOutOpen (delay), midiOutPrepareHeader (delay), midiOutReset (delay), midiOutSetVolume (delay), midiOutShortMsg (delay), midiOutUnprepareHeader (delay), midiStreamClose (delay), midiStreamOpen (delay), midiStreamOut (delay), midiStreamPause (delay), midiStreamPosition (delay), midiStreamProperty (delay), midiStreamRestart (delay), midiStreamStop (delay), mixerClose (delay), mixerGetControlDetailsA (delay), mixerGetControlDetailsW (delay), mixerGetDevCapsA (delay), mixerGetDevCapsW (delay), mixerGetID (delay), mixerGetLineControlsA (delay), mixerGetLineControlsW (delay), mixerGetLineInfoA (delay), mixerGetLineInfoW (delay), mixerGetNumDevs (delay), mixerMessage (delay), mixerOpen (delay), mixerSetControlDetails (delay), waveInAddBuffer (delay), waveInClose (delay), waveInGetDevCapsA (delay), waveInGetDevCapsW (delay), waveInGetErrorTextA (delay), waveInGetErrorTextW (delay), waveInGetID (delay), waveInGetNumDevs (delay), waveInGetPosition (delay), waveInMessage (delay), waveInOpen (delay), waveInPrepareHeader (delay), waveInReset (delay), waveInStart (delay), waveInStop (delay), waveInUnprepareHeader (delay), waveOutBreakLoop (delay), waveOutClose (delay), waveOutGetDevCapsA (delay), waveOutGetDevCapsW (delay), waveOutGetErrorTextA (delay), waveOutGetErrorTextW (delay), waveOutGetID (delay), waveOutGetNumDevs (delay), waveOutGetPitch (delay), waveOutGetPlaybackRate (delay), waveOutGetPosition (delay), waveOutGetVolume (delay), waveOutMessage (delay), waveOutOpen (delay), waveOutPause (delay), waveOutPrepareHeader (delay), waveOutReset (delay), waveOutRestart (delay), waveOutSetPitch (delay), waveOutSetPlaybackRate (delay), waveOutSetVolume (delay), waveOutUnprepareHeader (delay), waveOutWrite (delay)
- **no api-set shell api-ms-win-mm-misc-l1-1-0** (22): mmDrvInstall (delay), mmioAdvance (delay), mmioAscend (delay), mmioClose (delay), mmioCreateChunk (delay), mmioDescend (delay), mmioFlush (delay), mmioGetInfo (delay), mmioInstallIOProcA (delay), mmioInstallIOProcW (delay), mmioOpenA (delay), mmioOpenW (delay), mmioRead (delay), mmioRenameA (delay), mmioRenameW (delay), mmioSeek (delay), mmioSendMessage (delay), mmioSetBuffer (delay), mmioSetInfo (delay), mmioStringToFOURCCA (delay), mmioStringToFOURCCW (delay), mmioWrite (delay)
- **ntdll** (17): EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, NtCancelTimer, NtCreateTimer, NtQueryTimerResolution, NtSetTimer, NtWaitForMultipleObjects, RtlGetActiveConsoleId, _allmul, _aulldiv, _vsnwprintf, iswdigit, strspn
- **winmmbase** (15): CloseDriver (delay), DefDriverProc (delay), DrvGetModuleHandle (delay), GetDriverModuleHandle (delay), OpenDriver (delay), SendDriverMessage (delay), mmGetCurrentTask (delay), mmTaskBlock (delay), mmTaskCreate (delay), mmTaskSignal (delay), mmTaskYield (delay), winmmbaseFreeMMEHandles (delay), winmmbaseGetWOWHandle (delay), winmmbaseHandle32FromHandle16 (delay), winmmbaseSetWOWHandle (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (14): DisableThreadLibraryCalls, FreeLibrary, FreeResource, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW, LoadResource, LoadStringA, LoadStringW, LockResource, SizeofResource
- **no api-set shell ext-ms-win-ntuser-message-l1-1-0** (9): DispatchMessageA (delay), GetMessageA (delay), PeekMessageA (delay), PeekMessageW (delay), PostMessageA (delay), PostMessageW (delay), PostThreadMessageA (delay), RegisterWindowMessageW (delay), SendMessageA (delay)
- **no api-set shell api-ms-win-mm-time-l1-1-0** (5): timeBeginPeriod, timeEndPeriod, timeGetDevCaps, timeGetSystemTime, timeGetTime
- **no api-set shell ext-ms-win-ntuser-window-l1-1-0** (5): CreateWindowExA (delay), DefWindowProcA (delay), DestroyWindow (delay), IsWindow (delay), SoundSentry (delay)
- **oleaut32** (5): #161 (delay), #162 (delay), #2 (delay), #6 (delay), #7 (delay)
- **no api-set shell ext-ms-win-ntuser-windowclass-l1-1-0** (3): GetClassInfoA (delay), RegisterClassA (delay), UnregisterClassA (delay)
- **no api-set shell api-ms-win-core-heap-l2-1-0** (2): LocalAlloc, LocalFree
- **no api-set shell api-ms-win-core-path-l1-1-0** (2): PathCchIsRoot, PathCchStripToRoot
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (2): EventRegister, EventUnregister
- **no api-set shell ext-ms-win-ntuser-window-l1-1-2** (2): KillTimer (delay), SetTimer (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-sysparams-l1-1-0** (2): GetSystemMetrics (delay), SystemParametersInfoW (delay)
- **msvcrt** (1): __CxxFrameHandler3
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): FindResourceW
- **no api-set shell api-ms-win-core-kernel32-private-l1-1-2** (1): CheckForReadOnlyResource
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell ext-ms-win-gdi-dc-l1-2-0** (1): GetObjectW (delay)
- **no api-set shell ext-ms-win-gdi-draw-l1-1-1** (1): GetBkMode (delay)
- **no api-set shell ext-ms-win-ntuser-dialogbox-l1-1-0** (1): MessageBoxW (delay)
- **no api-set shell ext-ms-win-ntuser-gui-l1-1-0** (1): LoadIconA (delay)
- **no api-set shell ext-ms-win-ntuser-keyboard-l1-1-0** (1): GetKeyState (delay)
- **no api-set shell ext-ms-win-ntuser-server-l1-1-0** (1): NotifyWinEvent (delay)
- **no api-set shell ext-ms-win-oleacc-l1-1-1** (1): LresultFromObject (delay)

## dwrite

- **msvcrt** (24): ??0exception@@QAE@ABQBDH@Z, ??_V@YAXPAX@Z, __CxxFrameHandler3, _except_handler4_common, _ftol2, _itow_s, _libm_sse2_exp_precise, _libm_sse2_log10_precise, _libm_sse2_log_precise, _libm_sse2_pow_precise, _libm_sse2_sqrt_precise, _snprintf_s, _ultow_s, _vsnprintf_s, memcpy_s, memmove_s, sprintf_s, sscanf_s, strcat_s, strcpy_s, strncpy_s, strnlen, vsprintf_s, wcsnlen
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (10): DisableThreadLibraryCalls, FindResourceExW, FreeLibraryAndExitThread, GetModuleFileNameA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadResource, LockResource, SizeofResource
- **no api-set shell ext-ms-win-gdi-draw-l1-1-0** (7): CreateDIBSection (delay), GetWorldTransform (delay), LineTo (delay), MoveToEx (delay), PolyBezierTo (delay), SetGraphicsMode (delay), SetWorldTransform (delay)
- **ntdll** (6): AlpcGetMessageAttribute, AlpcInitializeMessageAttribute, NtAlpcConnectPort, NtAlpcSendWaitReceivePort, NtQueryInformationThread, RtlCaptureStackBackTrace
- **no api-set shell ext-ms-win-rtcore-ntuser-sysparams-l1-1-0** (6): DisplayConfigGetDeviceInfo (delay), EnumDisplayDevicesW (delay), GetDisplayConfigBufferSizes (delay), GetMonitorInfoW (delay), QueryDisplayConfig (delay), SystemParametersInfoW (delay)
- **textshaping** (5): ShapingCreateFontCacheData (delay), ShapingGetGlyphPositions (delay), ShapingGetGlyphs (delay), ShapingLoadScriptEngine (delay), ShapingSetInvariantAssertFunction (delay)
- **no api-set shell ext-ms-win-gdi-path-l1-1-0** (5): BeginPath (delay), CloseFigure (delay), EndPath (delay), FillPath (delay), PathToRegion (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell ext-ms-win-gdi-dc-l1-2-0** (4): GetCurrentObject (delay), GetStockObject (delay), SelectObject (delay), SetDCBrushColor (delay)
- **no api-set shell ext-ms-win-gdi-font-l1-1-0** (4): GetFontData (delay), GetFontFileData (delay), GetFontFileInfo (delay), GetFontRealizationInfo (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-rgn-l1-1-0** (4): FillRgn (delay), GetRegionData (delay), GetRgnBox (delay), SetPolyFillMode (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **no api-set shell ext-ms-win-gdi-dc-create-l1-1-0** (2): CreateCompatibleDC (delay), DeleteDC (delay)
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-core-localization-l1-2-2** (1): LCIDToLocaleName
- **no api-set shell api-ms-win-core-windowserrorreporting-l1-1-0** (1): WerRegisterMemoryBlock
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **not in our api-ms-win-service-management-l2-1-0** (1): NotifyServiceStatusChangeW (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-devcaps-l1-1-0** (1): GetDeviceCaps (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-object-l1-1-0** (1): DeleteObject (delay)
- **bcp47mrm** (1): GetDistanceOfClosestLanguageInList (delay)

## userenv

- **no api-set shell api-ms-win-security-grouppolicy-l1-1-0** (22): AreThereVisibleLogoffScriptsInternal, AreThereVisibleShutdownScriptsInternal, EnterCriticalPolicySectionInternal, ForceSyncFgPolicyInternal, FreeGPOListInternalA, FreeGPOListInternalW, GenerateGPNotificationInternal, GetAppliedGPOListInternalA, GetAppliedGPOListInternalW, GetGPOListInternalA, GetGPOListInternalW, GetNextFgPolicyRefreshInfoInternal, GetPreviousFgPolicyRefreshInfoInternal, HasPolicyForegroundProcessingCompletedInternal, LeaveCriticalPolicySectionInternal, RefreshPolicyExInternal, RefreshPolicyInternal, RegisterGPNotificationInternal, RsopLoggingEnabledInternal, UnregisterGPNotificationInternal, WaitForMachinePolicyForegroundProcessingInternal, WaitForUserPolicyForegroundProcessingInternal
- **no api-set shell ext-ms-win-profile-userenv-l1-1-0** (20): CreateAppContainerProfileWorker (delay), CreateDirectoryJunctionsForSystemWorker (delay), CreateDirectoryJunctionsForUserProfileWorker (delay), CreateGroupExWorker (delay), CreateLinkFileExWorker (delay), DeleteAppContainerProfileWorker (delay), DeleteGroupWorker (delay), DeleteLinkFileWorker (delay), DeriveAppContainerSidFromAppContainerNameWorker (delay), DeriveRestrictedAppContainerSidFromAppContainerSidAndRestrictedNameWorker (delay), GetAppContainerFolderPathWorker (delay), GetAppContainerRegistryLocationWorker (delay), LookupAppContainerDisplayNameWorker (delay), ProcessGroupPolicyCompletedExWorker (delay), ProcessGroupPolicyCompletedWorker (delay), RsopAccessCheckByTypeWorker (delay), RsopFileAccessCheckWorker (delay), RsopResetPolicySettingStatusWorker (delay), RsopSetPolicySettingStatusWorker (delay), UpdateAppContainerProfileWorker (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (8): DisableThreadLibraryCalls, FindResourceExW, GetModuleFileNameA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadResource, LockResource
- **ntdll** (7): EtwEventActivityIdControl, EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWriteTransfer, RtlAdjustPrivilege, RtlStringFromGUID
- **profapi** (5): #101 (delay), #102 (delay), #103 (delay), #104 (delay), #105 (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **rpcrt4** (2): I_RpcExceptionFilter, NdrClientCall4
- **no api-set shell api-ms-win-core-heap-l2-1-0** (2): LocalAlloc, LocalFree
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (2): EventActivityIdControl, EventWriteTransfer
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (1): QueryFullProcessImageNameW
- **not in our api-ms-win-core-file-l2-1-0** (1): GetFileInformationByHandleEx
- **no api-set shell api-ms-win-core-path-l1-1-0** (1): PathCchAddBackslashEx
- **no api-set shell api-ms-win-core-kernel32-private-l1-1-1** (1): PrivCopyFileExW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **sspicli** (1): GetUserNameExW (delay)
- **dnsapi** (1): DnsNameCompare_W (delay)
- **netutils** (1): NetApiBufferFree (delay)
- **logoncli** (1): DsEnumerateDomainTrustsW (delay)
- **no api-set shell ext-ms-win-profile-userenv-l1-1-1** (1): IsAppContainerProfilePresentWorker (delay)
- **cldapi** (1): CfGetPlaceholderStateFromAttributeTag (delay)

## dwmapi

- **ntdll** (17): DbgPrintEx, EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWriteTransfer, NtAlpcConnectPort, NtAlpcCreatePortSection, NtAlpcCreateSectionView, NtAlpcDeletePortSection, NtAlpcDeleteSectionView, NtAlpcSendWaitReceivePort, RtlAllocateAndInitializeSid, RtlCaptureStackBackTrace, RtlNumberGenericTableElements, SbSelectProcedure, WinSqmAddToStream, WinSqmIsOptedIn
- **user32** (11): #2557, #2574, #2635, DwmGetDxSharedSurface, GetPointerInfo, GetWindowCompositionAttribute, IsThreadDesktopComposited, IsTopLevelWindow, SetWindowCompositionAttribute, SetWindowCompositionTransition, UpdateDefaultDesktopThumbnail
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (6): DisableThreadLibraryCalls, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress
- **msvcrt** (4): _except_handler4_common, _ftol2, memcpy_s, memmove_s
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **win32u** (3): NtDCompositionRegisterThumbnailVisual, NtDCompositionRegisterVirtualDesktopVisual, NtDCompositionSetChildRootVisual
- **gdi32** (3): #1005, ScaleRgn, ScaleValues
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **no api-set shell ext-ms-win-rtcore-ntuser-dpi-l1-2-0** (2): GetDpiForSystem (delay), GetThreadDpiAwarenessContext (delay)
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryW
- **no api-set shell api-ms-win-core-errorhandling-l1-1-3** (1): TerminateProcessOnMemoryExhaustion
- **no api-set shell api-ms-win-core-errorhandling-l1-1-2** (1): RaiseFailFastException
- **no api-set shell api-ms-win-core-heap-l2-1-0** (1): LocalFree
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (1): RoOriginateError
- **no api-set shell api-ms-win-gdi-dpiinfo-l1-1-0** (1): GetCurrentDpiInfo
- **no api-set shell api-ms-win-core-quirks-l1-1-0** (1): QuirkIsEnabled
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (1): EventWriteTransfer
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **dcomp** (1): #1031 (delay)

## propsys

- **oleaut32** (59): #10 (delay), #108 (delay), #109 (delay), #110 (delay), #112 (delay), #116 (delay), #12 (delay), #122 (delay), #125 (delay), #13 (delay), #133 (delay), #143 (delay), #148 (delay), #15 (delay), #156 (delay), #158 (delay), #16 (delay), #17 (delay), #173 (delay), #175 (delay), #176 (delay), #18 (delay), #184 (delay), #185 (delay), #19 (delay), #2 (delay), #20 (delay), #229 (delay), #23 (delay), #230 (delay), #231 (delay), #24 (delay), #248 (delay), #25 (delay), #26 (delay), #261 (delay), #274 (delay), #283 (delay), #284 (delay), #285 (delay), #286 (delay), #291 (delay), #292 (delay), #293 (delay), #294 (delay), #336 (delay), #368 (delay), #369 (delay), #4 (delay), #411 (delay), #42 (delay), #432 (delay), #51 (delay), #6 (delay), #61 (delay), #7 (delay), #77 (delay), #8 (delay), #9 (delay)
- **no api-set shell api-ms-win-core-com-midlproxystub-l1-1-0** (34): CStdStubBuffer2_Connect (delay), CStdStubBuffer2_CountRefs (delay), CStdStubBuffer2_Disconnect (delay), CStdStubBuffer2_QueryInterface (delay), NdrProxyForwardingFunction3 (delay), NdrProxyForwardingFunction4 (delay), NdrProxyForwardingFunction5 (delay), NdrProxyForwardingFunction6 (delay), NdrProxyForwardingFunction7 (delay), NdrProxyForwardingFunction8 (delay), ObjectStublessClient10 (delay), ObjectStublessClient11 (delay), ObjectStublessClient12 (delay), ObjectStublessClient13 (delay), ObjectStublessClient14 (delay), ObjectStublessClient15 (delay), ObjectStublessClient16 (delay), ObjectStublessClient17 (delay), ObjectStublessClient18 (delay), ObjectStublessClient19 (delay), ObjectStublessClient20 (delay), ObjectStublessClient22 (delay), ObjectStublessClient23 (delay), ObjectStublessClient24 (delay), ObjectStublessClient25 (delay), ObjectStublessClient26 (delay), ObjectStublessClient27 (delay), ObjectStublessClient3 (delay), ObjectStublessClient4 (delay), ObjectStublessClient5 (delay), ObjectStublessClient6 (delay), ObjectStublessClient7 (delay), ObjectStublessClient8 (delay), ObjectStublessClient9 (delay)
- **icu** (14): u_charType (delay), u_errorName (delay), ucal_getDefaultTimeZone (delay), udat_close (delay), udat_format (delay), udat_open (delay), udatpg_close (delay), udatpg_getBestPattern (delay), udatpg_open (delay), ureldatefmt_close (delay), ureldatefmt_format (delay), ureldatefmt_open (delay), utmscale_fromInt64 (delay), utmscale_toInt64 (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (13): DisableThreadLibraryCalls, FindResourceExW, FindStringOrdinal, FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadResource, LoadStringW, LockResource
- **shcore** (13): #108 (delay), #109 (delay), #127 (delay), #130 (delay), #141 (delay), #143 (delay), #144 (delay), #145 (delay), #150 (delay), #151 (delay), #192 (delay), #193 (delay), #200 (delay)
- **not in our api-ms-win-core-shlwapi-obsolete-l1-1-0** (6): QISearch, StrCmpCW, StrCmpICW, StrCmpLogicalW, StrCmpNICW, StrToInt64ExW
- **ntdll** (6): EtwEventActivityIdControl, EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWriteTransfer, RtlDllShutdownInProgress
- **not in our api-ms-win-shcore-stream-l1-1-0** (6): IStream_Read (delay), IStream_Reset (delay), IStream_Size (delay), IStream_Write (delay), IStream_WriteStr (delay), SHCreateMemStream (delay)
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (5): EventProviderEnabled, EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (5): WindowsCompareStringOrdinal (delay), WindowsCreateString (delay), WindowsCreateStringReference (delay), WindowsDeleteString (delay), WindowsGetStringRawBuffer (delay)
- **no api-set shell api-ms-win-core-heap-l2-1-0** (4): GlobalAlloc, GlobalFree, LocalAlloc, LocalFree
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-shcore-registry-l1-1-0** (4): SHDeleteKeyW (delay), SHQueryValueExW (delay), SHRegGetValueW (delay), SHSetValueW (delay)
- **no api-set shell ext-ms-win-els-elscore-l1-1-0** (3): MappingFreePropertyBag (delay), MappingGetServices (delay), MappingRecognizeText (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-shlwapi-legacy-l1-1-0** (2): IsCharSpaceW, SHExpandEnvironmentStringsW
- **not in our api-ms-win-security-base-l1-1-0** (2): CreatePrivateObjectSecurityEx, SetSecurityDescriptorControl
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (2): K32EnumProcessModules, K32GetModuleBaseNameW
- **rpcrt4** (2): NdrClientCall4, NdrGetUserMarshalInfo
- **not in our api-ms-win-core-wow64-l1-1-0** (2): Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection
- **no api-set shell api-ms-win-core-com-private-l1-1-0** (2): CoRegisterInitializeSpy (delay), CoRevokeInitializeSpy (delay)
- **no api-set shell api-ms-win-shcore-obsolete-l1-1-0** (2): SHStrDupA (delay), SHStrDupW (delay)
- **no api-set shell api-ms-win-shcore-unicodeansi-l1-1-0** (2): SHAnsiToUnicode (delay), SHUnicodeToAnsi (delay)
- **not in our api-ms-win-core-localization-l1-2-0** (1): FindNLSString
- **no api-set shell api-ms-win-core-datetime-l1-1-2** (1): GetDurationFormatEx
- **no api-set shell api-ms-win-core-path-l1-1-0** (1): PathCchAppend
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-stateseparation-helpers-l1-1-0** (1): GetPersistedRegistryLocationW
- **not in our api-ms-win-core-timezone-l1-1-0** (1): GetTimeZoneInformationForYear
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (1): RoOriginateError
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (1): GetSystemWow64DirectoryW
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **not in our api-ms-win-core-com-l1-1-0** (1): CoGetApartmentType (delay)
- **no api-set shell api-ms-win-shcore-comhelpers-l1-1-0** (1): IUnknown_Set (delay)
- **no api-set shell api-ms-win-shcore-taskpool-l1-1-0** (1): SHTaskPoolQueueTask (delay)
- **no api-set shell api-ms-win-core-winrt-l1-1-0** (1): RoGetActivationFactory (delay)
- **no api-set shell api-ms-win-shcore-sysinfo-l1-1-0** (1): IsOS (delay)
- **xmllite** (1): CreateXmlReader (delay)
- **profapi** (1): #104 (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-0** (1): StgOpenStorageOnILockBytes (delay)
- **no api-set shell api-ms-win-shell-namespace-l1-1-0** (1): SHCreateItemWithParent (delay)
- **bcp47langs** (1): Bcp47GetNlsForm (delay)

## crypt32

- **msasn1** (78): ASN1BERDecBitString (delay), ASN1BERDecBitString2 (delay), ASN1BERDecBool (delay), ASN1BERDecChar16String (delay), ASN1BERDecChar32String (delay), ASN1BERDecCharString (delay), ASN1BERDecEndOfContents (delay), ASN1BERDecEoid (delay), ASN1BERDecExplicitTag (delay), ASN1BERDecGeneralizedTime (delay), ASN1BERDecMultibyteString (delay), ASN1BERDecNotEndOfContents (delay), ASN1BERDecNull (delay), ASN1BERDecObjectIdentifier2 (delay), ASN1BERDecOctetString (delay), ASN1BERDecOctetString2 (delay), ASN1BERDecOpenType (delay), ASN1BERDecOpenType2 (delay), ASN1BERDecPeekTag (delay), ASN1BERDecS32Val (delay), ASN1BERDecSXVal (delay), ASN1BERDecU16Val (delay), ASN1BERDecU32Val (delay), ASN1BERDecUTCTime (delay), ASN1BERDecUTF8String (delay), ASN1BERDecZeroCharString (delay), ASN1BERDotVal2Eoid (delay), ASN1BEREncBool (delay), ASN1BEREncEndOfContents (delay), ASN1BEREncEoid (delay), ASN1BEREncExplicitTag (delay), ASN1BEREncNull (delay), ASN1BEREncObjectIdentifier2 (delay), ASN1BEREncOpenType (delay), ASN1BEREncRemoveZeroBits (delay), ASN1BEREncS32 (delay), ASN1BEREncSX (delay), ASN1BEREncU32 (delay), ASN1BEREoid2DotVal (delay), ASN1BEREoid_free (delay), ASN1DEREncBeginBlk (delay), ASN1DEREncBitString (delay), ASN1DEREncChar16String (delay), ASN1DEREncChar32String (delay), ASN1DEREncCharString (delay), ASN1DEREncEndBlk (delay), ASN1DEREncFlushBlkElement (delay), ASN1DEREncGeneralizedTime (delay), ASN1DEREncMultibyteString (delay), ASN1DEREncNewBlkElement (delay), ASN1DEREncOctetString (delay), ASN1DEREncUTCTime (delay), ASN1DEREncUTF8String (delay), ASN1DecRealloc (delay), ASN1DecSetError (delay), ASN1EncSetError (delay), ASN1Free (delay), ASN1_CloseDecoder (delay), ASN1_CloseEncoder (delay), ASN1_CloseModule (delay), ASN1_CreateDecoder (delay), ASN1_CreateEncoder (delay), ASN1_CreateModule (delay), ASN1_Decode (delay), ASN1_Encode (delay), ASN1_FreeDecoded (delay), ASN1_FreeEncoded (delay), ASN1_SetEncoderOption (delay), ASN1bitstring_free (delay), ASN1char16string_free (delay), ASN1char32string_free (delay), ASN1charstring_free (delay), ASN1intx_free (delay), ASN1objectidentifier2_cmp (delay), ASN1octetstring_free (delay), ASN1open_free (delay), ASN1utf8string_free (delay), ASN1ztcharstring_free (delay)
- **ntdll** (29): A_SHAFinal, A_SHAInit, A_SHAUpdate, EtwEventRegister, EtwEventUnregister, EtwEventWriteFull, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, EvtIntReportEventAndSourceAsync, MD5Final, MD5Init, MD5Update, NtQueryObject, RtlCreateUnicodeStringFromAsciiz, RtlIpv4StringToAddressExW, RtlIpv6StringToAddressExW, RtlIsStateSeparationEnabled, RtlPublishWnfStateData, RtlQueryWnfStateData, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfNotificationWaitForCompletion, ShipAssert, WinSqmIncrementDWORD, _vsnwprintf, memmove_s
- **cryptsp** (28): CryptAcquireContextA (delay), CryptAcquireContextW (delay), CryptContextAddRef (delay), CryptCreateHash (delay), CryptDecrypt (delay), CryptDeriveKey (delay), CryptDestroyHash (delay), CryptDestroyKey (delay), CryptEncrypt (delay), CryptEnumProvidersW (delay), CryptExportKey (delay), CryptGenKey (delay), CryptGetDefaultProviderW (delay), CryptGetHashParam (delay), CryptGetKeyParam (delay), CryptGetProvParam (delay), CryptGetUserKey (delay), CryptHashData (delay), CryptImportKey (delay), CryptReleaseContext (delay), CryptSetHashParam (delay), CryptSetKeyParam (delay), CryptSetProvParam (delay), CryptSetProviderW (delay), CryptSignHashA (delay), CryptSignHashW (delay), CryptVerifySignatureA (delay), CryptVerifySignatureW (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (13): FreeLibrary, FreeLibraryAndExitThread, FreeResource, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadResource, LoadStringW, LockResource, SizeofResource
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (6): CloseThreadpoolTimer, CreateThreadpoolTimer, FreeLibraryWhenCallbackReturns, SetThreadpoolTimer, TrySubmitThreadpoolCallback, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **not in our api-ms-win-core-registry-l1-1-0** (3): RegDeleteKeyExW, RegGetValueW, RegLoadMUIStringW
- **no api-set shell api-ms-win-core-heap-l2-1-0** (3): LocalAlloc, LocalFree, LocalReAlloc
- **cabinet** (3): #20 (delay), #22 (delay), #23 (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **not in our api-ms-win-core-localization-l1-2-0** (2): IdnToAscii, IdnToUnicode
- **no api-set shell api-ms-win-security-grouppolicy-l1-1-0** (2): RegisterGPNotificationInternal, UnregisterGPNotificationInternal
- **no api-set shell api-ms-win-power-setting-l1-1-0** (2): PowerSettingRegisterNotification (delay), PowerSettingUnregisterNotification (delay)
- **profapi** (2): #104 (delay), #107 (delay)
- **dpapi** (2): CryptProtectDataNoUI (delay), CryptUnprotectDataNoUI (delay)
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (1): QueryFullProcessImageNameW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryA
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **not in our api-ms-win-security-base-l1-1-0** (1): AddAccessAllowedAceEx (delay)
- **rpcrt4** (1): NdrClientCall4 (delay)
- **no api-set shell api-ms-win-security-base-l1-2-0** (1): CheckTokenCapability (delay)
- **sspicli** (1): GetUserNameExW (delay)
- **no api-set shell api-ms-win-security-base-l1-2-1** (1): CveEventWrite (delay)
- **no api-set shell api-ms-win-core-registry-private-l1-1-0** (1): RegConnectRegistryExW (delay)
- **no api-set shell api-ms-win-service-private-l1-1-0** (1): WaitServiceState (delay)

## d3d11

- **no api-set shell ext-ms-win-dx-d3dkmt-dxcore-l1-1-0** (100): #10 (delay), #100 (delay), #101 (delay), #102 (delay), #103 (delay), #104 (delay), #105 (delay), #106 (delay), #107 (delay), #108 (delay), #109 (delay), #11 (delay), #110 (delay), #111 (delay), #112 (delay), #113 (delay), #114 (delay), #115 (delay), #116 (delay), #117 (delay), #118 (delay), #119 (delay), #120 (delay), #121 (delay), #124 (delay), #126 (delay), #127 (delay), #128 (delay), #129 (delay), #130 (delay), #131 (delay), #132 (delay), #133 (delay), #134 (delay), #135 (delay), #136 (delay), #137 (delay), #138 (delay), #139 (delay), #140 (delay), #141 (delay), #142 (delay), #147 (delay), #148 (delay), #15 (delay), #160 (delay), #161 (delay), #162 (delay), #163 (delay), #164 (delay), #169 (delay), #17 (delay), #170 (delay), #171 (delay), #19 (delay), #190 (delay), #193 (delay), #2 (delay), #20 (delay), #204 (delay), #205 (delay), #206 (delay), #207 (delay), #208 (delay), #209 (delay), #21 (delay), #210 (delay), #212 (delay), #213 (delay), #214 (delay), #22 (delay), #23 (delay), #24 (delay), #25 (delay), #27 (delay), #31 (delay), #34 (delay), #36 (delay), #4 (delay), #5 (delay), #50 (delay), #57 (delay), #6 (delay), #65 (delay), #68 (delay), #69 (delay), #7 (delay), #70 (delay), #71 (delay), #72 (delay), #73 (delay), #74 (delay), #75 (delay), #76 (delay), #77 (delay), #79 (delay), #8 (delay), #80 (delay), #81 (delay), #88 (delay)
- **msvcrt** (22): ??0bad_cast@@QAE@PBD@Z, ??0exception@@QAE@ABQBDH@Z, _W_Getdays, _W_Getmonths, _W_Gettnames, _Wcsftime, __CxxFrameHandler3, ___lc_codepage_func, ___lc_collate_cp_func, ___lc_handle_func, ___mb_cur_max_func, __crtCompareStringW, __crtLCMapStringW, __pctype_func, _except_handler4_common, _ftol2, _ftol2_sse, _vsnprintf_s, memcpy_s, memmove_s, sprintf_s, swprintf_s
- **ntdll** (15): EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWrite, EtwEventWriteTransfer, NtFlushProcessWriteBuffers, NtQueryObject, RtlCaptureStackBackTrace, RtlDllShutdownInProgress, RtlFindLeastSignificantBit, RtlNumberOfSetBitsUlongPtr, RtlQueryWnfStateData, RtlSetLastWin32Error, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfStateChangeNotification
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (11): DisableThreadLibraryCalls, FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleA, GetModuleHandleExA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW
- **d3dscache** (6): ShaderCache_AddValue (delay), ShaderCache_Create (delay), ShaderCache_Destroy (delay), ShaderCache_FindValue (delay), ShaderCache_FreeValue (delay), ShaderCache_GetDesc (delay)
- **no api-set shell ext-ms-mf-pal-l2-1-0** (5): XboxGetAsyncCompute3DPipeplineCaps (delay), XboxGetAsyncComputeD3DCreationFlag (delay), XboxGetAsyncComputeDDICreationFlag (delay), XboxGetAsyncComputeShaderCaps (delay), XboxIsAsyncComputeOnlyDevice (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell ext-ms-win-gdi-draw-l1-1-0** (4): BitBlt (delay), GdiFlush (delay), SetGraphicsMode (delay), SetWorldTransform (delay)
- **win32u** (3): NtBindCompositionSurface, NtNotifyPresentToCompositionSurface, NtUnBindCompositionSurface
- **no api-set shell ext-ms-win-dx-d3dkmt-gdi-l1-1-0** (3): D3DKMTCreateDCFromMemory (delay), D3DKMTDestroyDCFromMemory (delay), GdiEntry13 (delay)
- **no api-set shell ext-ms-win-gdi-dc-create-l1-1-0** (3): CreateCompatibleDC (delay), CreateDCW (delay), DeleteDC (delay)
- **no api-set shell ext-ms-win-gdi-render-l1-1-0** (3): BeginGdiRendering (delay), CreateBitmapFromDxSurface2 (delay), EndGdiRendering (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **no api-set shell ext-ms-win-rtcore-ntuser-dc-access-l1-1-0** (2): GetDC (delay), ReleaseDC (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-rgn-l1-1-0** (2): IntersectClipRect (delay), SetMetaRgn (delay)
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (1): K32GetModuleInformation
- **no api-set shell api-ms-win-core-heap-l2-1-0** (1): LocalFree
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-core-quirks-l1-1-0** (1): QuirkIsEnabled
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryA
- **no api-set shell api-ms-win-core-synch-l1-2-1** (1): WaitForMultipleObjects
- **kernelbase** (1): BaseFormatObjectAttributes
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (1): EventWrite
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-security-lsalookup-ansi-l2-1-0** (1): LookupPrivilegeValueA (delay)
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (1): WindowsCreateString (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (1): RoOriginateError (delay)
- **no api-set shell ext-ms-win-dxcore-l1-1-0** (1): DXCoreCreateAdapterFactory (delay)
- **no api-set shell ext-ms-win-dxcore-internal-l1-1-0** (1): #218 (delay)
- **no api-set shell ext-ms-win-gdi-dc-l1-2-0** (1): SelectObject (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-object-l1-1-0** (1): DeleteObject (delay)
- **no api-set shell ext-ms-onecore-dcomp-l1-1-0** (1): DCompositionCreateSurfaceHandle (delay)
- **no api-set shell api-ms-win-appmodel-unlock-l1-1-0** (1): IsDeveloperModeEnabled (delay)
- **no api-set shell api-ms-win-rtcore-ntuser-window-l1-1-0** (1): GetDesktopWindow (delay)
- **no api-set shell api-ms-win-ntuser-sysparams-l1-1-0** (1): EnumDisplayDevicesW (delay)
- **no api-set shell ext-ms-win-ntuser-uicontext-ext-l1-1-0** (1): #2521 (delay)
- **d3d11on12** (1): OpenAdapter_D3D11On12 (delay)

## oleaut32

- **combase** (42): #10, #11, #12, #13, #14, #15, #16, #167, #17, #18, #180, #181, #19, #2, #20, #21, #22, #23, #24, #25, #26, #27, #28, #3, #32, #33, #34, #35, #36, #37, #38, #39, #4, #40, #41, #42, #43, #5, #6, #7, #8, #9
- **no api-set shell ext-ms-win-ole32-oleautomation-l1-1-0** (34): CLIPFORMAT_UserFreeExt (delay), CLIPFORMAT_UserMarshalExt (delay), CLIPFORMAT_UserSizeExt (delay), CLIPFORMAT_UserUnmarshalExt (delay), GetActiveObjectExt (delay), HPALETTE_UserFreeExt (delay), HPALETTE_UserMarshalExt (delay), HPALETTE_UserSizeExt (delay), HPALETTE_UserUnmarshalExt (delay), HWND_UserFreeExt (delay), HWND_UserMarshalExt (delay), HWND_UserSizeExt (delay), HWND_UserUnmarshalExt (delay), MonikerLoadTypeLib (delay), OleCreateFontIndirectExt (delay), OleCreatePictureIndirectExt (delay), OleCreatePropertyFrameIndirectExt (delay), OleIconToCursorExt (delay), OleLoadPictureExt (delay), OleLoadPictureFileExt (delay), OleLoadPicturePathExt (delay), OleSavePictureFileExt (delay), OleTranslateColorExt (delay), ReadStorageProperties (delay), RegisterActiveObjectExt (delay), RevokeActiveObjectExt (delay), STGMEDIUM_UserFreeExt (delay), STGMEDIUM_UserMarshalExt (delay), STGMEDIUM_UserSizeExt (delay), STGMEDIUM_UserUnmarshalExt (delay), SetOleautModule (delay), StdTypesGetClassObject (delay), StdTypesRegisterServer (delay), WriteStorageProperties (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (7): FreeLibrary, GetModuleFileNameA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell ext-ms-win-sxs-oleautomation-l1-1-0** (4): SxsOleAut32MapConfiguredClsidToReferenceClsid (delay), SxsOleAut32MapIIDToProxyStubCLSID (delay), SxsOleAut32MapIIDToTLBPath (delay), SxsOleAut32RedirectTypeLibrary (delay)
- **ntdll** (3): LdrGetDllPath, RtlReleasePath, RtlRunOnceBeginInitialize
- **kernelbase** (3): CompareStringA, GetNumberFormatW, lstrcmpiA
- **not in our api-ms-win-core-registry-l1-1-0** (2): RegDeleteKeyExW, RegGetValueW
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-wow64-l1-1-0** (2): Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (2): WindowsDeleteString (delay), WindowsGetStringRawBuffer (delay)
- **msvcp_win** (1): ?_Xlength_error@std@@YAXPBD@Z
- **rpcrt4** (1): NdrGetUserMarshalInfo
- **no api-set shell api-ms-win-core-localization-l2-1-0** (1): GetCurrencyFormatW
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (1): IsWow64Process2
- **no api-set shell api-ms-win-core-localization-private-l1-1-0** (1): NlsGetCacheUpdateCount
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence

## shcore

- **no api-set shell api-ms-win-rtcore-ntuser-window-l1-1-0** (26): CallWindowProcW (delay), CreateWindowExW (delay), DefWindowProcW (delay), DispatchMessageW (delay), FindWindowW (delay), GetAncestor (delay), GetClassInfoW (delay), GetDesktopWindow (delay), GetForegroundWindow (delay), GetMessageW (delay), GetParent (delay), GetPropW (delay), GetWindow (delay), GetWindowLongW (delay), GetWindowThreadProcessId (delay), IsWindow (delay), PeekMessageW (delay), PostMessageW (delay), PostQuitMessage (delay), PostThreadMessageW (delay), RegisterClassW (delay), RegisterWindowMessageW (delay), RemovePropW (delay), SetPropW (delay), SetWindowLongW (delay), TranslateMessage (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (13): DisableThreadLibraryCalls, FindResourceExW, FreeLibrary, FreeLibraryAndExitThread, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadResource, LockResource, SizeofResource
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (12): CallbackMayRunLong, CloseThreadpoolTimer, CloseThreadpoolWait, CreateThreadpoolTimer, CreateThreadpoolWait, DisassociateCurrentThreadFromCallback, FreeLibraryWhenCallbackReturns, SetThreadpoolTimer, SetThreadpoolWait, TrySubmitThreadpoolCallback, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWaitCallbacks
- **ntdll** (8): NtQueryInformationProcess, RtlAreLongPathsEnabled, RtlQueryWnfStateData, RtlSleepConditionVariableSRW, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfNotificationWaitForCompletion, _vsnprintf_s, memmove_s
- **msvcrt** (5): __CxxFrameHandler3, _except_handler4_common, _ftol2, _ftol2_sse, memcpy_s
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (5): EventProviderEnabled, EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (5): WindowsCreateString (delay), WindowsCreateStringReference (delay), WindowsGetStringRawBuffer (delay), WindowsIsStringEmpty (delay), WindowsStringHasEmbeddedNull (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (5): GetRestrictedErrorInfo (delay), RoOriginateError (delay), RoOriginateErrorW (delay), RoTransformError (delay), SetRestrictedErrorInfo (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-window-ext-l1-1-0** (5): CallNextHookEx (delay), GetWindowInfo (delay), MapWindowPoints (delay), SetWindowsHookExW (delay), UnhookWindowsHookEx (delay)
- **not in our api-ms-win-core-com-l1-1-0** (4): CoCancelCall (delay), CoDisableCallCancellation (delay), CoEnableCallCancellation (delay), CoGetApartmentType (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateEventExW, CreateMutexExW, CreateSemaphoreExW
- **no api-set shell api-ms-win-core-heap-l2-1-0** (3): LocalAlloc, LocalFree, LocalReAlloc
- **not in our api-ms-win-core-shlwapi-obsolete-l1-1-0** (3): QISearch, StrCmpICW, StrCmpNICW
- **not in our api-ms-win-core-registry-l1-1-0** (3): RegDeleteKeyExA, RegDeleteKeyExW, RegGetValueW
- **no api-set shell api-ms-win-core-atoms-l1-1-0** (3): GlobalAddAtomExW, GlobalDeleteAtom, GlobalGetAtomNameW
- **no api-set shell api-ms-win-core-winrt-l1-1-0** (3): RoGetActivationFactory (delay), RoInitialize (delay), RoUninitialize (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-dpi-l1-1-0** (3): GetDpiForMonitorInternal (delay), GetProcessDpiAwarenessInternal (delay), SetProcessDpiAwarenessInternal (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-dpi-l1-2-0** (3): AreDpiAwarenessContextsEqual (delay), GetAwarenessFromDpiAwarenessContext (delay), GetWindowDpiAwarenessContext (delay)
- **not in our api-ms-win-core-file-l1-1-0** (2): GetVolumeInformationByHandleW, SetFileInformationByHandle
- **not in our api-ms-win-core-shlwapi-legacy-l1-1-0** (2): PathUnExpandEnvStringsA, PathUnExpandEnvStringsW
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **no api-set shell api-ms-win-ntuser-sysparams-l1-1-0** (2): GetSystemMetrics (delay), SystemParametersInfoW (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-0** (2): OleInitialize (delay), OleUninitialize (delay)
- **no api-set shell ext-ms-win-ntuser-keyboard-l1-1-0** (2): ActivateKeyboardLayout (delay), GetKeyboardLayout (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-cursor-l1-1-0** (2): LoadCursorW (delay), SetCursor (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-sysparams-l1-1-0** (2): MonitorFromPoint (delay), MonitorFromWindow (delay)
- **not in our api-ms-win-core-sysinfo-l1-2-0** (1): GetOsSafeBootMode
- **no api-set shell api-ms-win-core-string-l2-1-1** (1): SHLoadIndirectString
- **no api-set shell api-ms-win-core-largeinteger-l1-1-0** (1): MulDiv
- **no api-set shell api-ms-win-core-quirks-l1-1-0** (1): QuirkIsEnabled
- **not in our api-ms-win-core-file-l2-1-0** (1): GetFileInformationByHandleEx
- **not in our api-ms-win-core-file-l1-2-0** (1): CreateFile2
- **no api-set shell api-ms-win-core-errorhandling-l1-1-2** (1): RaiseFailFastException
- **no api-set shell api-ms-win-core-path-l1-1-0** (1): PathCchAddBackslashEx
- **combase** (1): #134
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **oleaut32** (1): #2 (delay)
- **no api-set shell api-ms-win-core-com-l1-1-1** (1): RoGetAgileReference (delay)
- **no api-set shell api-ms-win-core-winrt-robuffer-l1-1-0** (1): RoGetBufferMarshaler (delay)
- **rpcrt4** (1): I_RpcBindingInqLocalClientPID (delay)
- **wkscli** (1): NetGetJoinInformation (delay)
- **netutils** (1): NetApiBufferFree (delay)
- **no api-set shell api-ms-win-gdi-dpiinfo-l1-1-0** (1): GetCurrentDpiInfo (delay)
- **no api-set shell api-ms-win-rtcore-ntuser-synch-l1-1-0** (1): MsgWaitForMultipleObjectsEx (delay)
- **no api-set shell api-ms-win-shell-changenotify-l1-1-0** (1): SHChangeNotify (delay)
- **no api-set shell ext-ms-win-devmgmt-policy-l1-1-0** (1): PolicyManager_GetPolicyInt (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-dpi-l1-2-1** (1): #2636 (delay)
- **no api-set shell ext-ms-win-shell-directory-l1-1-0** (1): SHSysErrorMessageBox (delay)
- **no api-set shell ext-ms-win-appmodel-viewscalefactor-l1-1-0** (1): GetDefaultScaleFactor (delay)
- **no api-set shell ext-ms-win-imm-l1-1-0** (1): ImmDisableIME (delay)

## uxtheme

- **user32** (26): #2525, #2527, #2703, #2705, #2706, #2707, #2708, #2711, CalcMenuBar, DisplayConfigGetDeviceInfo, GetDpiForMonitorInternal, GetDpiForSystem, GetSystemMetricsForDpi, GetWindowCompositionAttribute, GetWindowRgnBox, IsProcessDPIAware, IsServerSideWindow, IsThreadDesktopComposited, IsTopLevelWindow, IsWindowInDestroy, IsWindowRedirectedForPrint, PaintMenuBar, RegisterUserApiHook, SetProcessDPIAware, SetWindowCompositionAttribute, SystemParametersInfoForDpi
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (14): DisableThreadLibraryCalls, FindResourceExW, FreeLibrary, FreeLibraryAndExitThread, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW, LoadResource, LoadStringW, LockResource, SizeofResource
- **ntdll** (12): EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWriteTransfer, NtConnectPort, NtOpenSection, NtRequestWaitReplyPort, RtlGetThreadLangIdByIndex, SbSelectProcedure, bsearch_s, wcstok_s, wcstoul
- **gdi32** (10): ClearBitmapAttributes, CreateDPIScaledDIBSection, CreateSessionMappedDIBSection, GdiDrawStream, GdiGradientFill, GdiTransparentBlt, GditPopCallerInfo, GditPushCallerInfo, GetDCDpiScaleValue, SetBitmapAttributes
- **msvcrt** (9): __CxxFrameHandler3, _except_handler4_common, _ftol2, _ftol2_sse, _wsplitpath_s, _wtof, memcpy_s, memmove_s, rand_s
- **cryptsp** (8): CryptAcquireContextW (delay), CryptCreateHash (delay), CryptDestroyHash (delay), CryptDestroyKey (delay), CryptHashData (delay), CryptImportKey (delay), CryptReleaseContext (delay), CryptVerifySignatureW (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-core-sidebyside-l1-1-0** (4): ActivateActCtx, CreateActCtxW, DeactivateActCtx, ReleaseActCtx
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (4): WindowsCreateString (delay), WindowsGetStringRawBuffer (delay), WindowsIsStringEmpty (delay), WindowsStringHasEmbeddedNull (delay)
- **no api-set shell api-ms-win-core-atoms-l1-1-0** (3): AddAtomW, DeleteAtom, GetAtomNameW
- **dwmapi** (3): #127 (delay), #131 (delay), #168 (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (2): RoOriginateError, RoOriginateErrorW
- **no api-set shell api-ms-win-core-heap-l2-1-0** (2): LocalAlloc, LocalFree
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryW
- **not in our api-ms-win-core-registry-l1-1-0** (1): RegGetValueW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **windowscodecs** (1): WICCreateImagingFactory_Proxy (delay)

## winhttp

- **webio** (32): #1 (delay), #10 (delay), #11 (delay), #14 (delay), #17 (delay), #18 (delay), #19 (delay), #20 (delay), #21 (delay), #22 (delay), #23 (delay), #24 (delay), #25 (delay), #26 (delay), #28 (delay), #29 (delay), #31 (delay), #32 (delay), #33 (delay), #35 (delay), #36 (delay), #37 (delay), #38 (delay), #39 (delay), #4 (delay), #42 (delay), #43 (delay), #44 (delay), #45 (delay), #5 (delay), #8 (delay), #9 (delay)
- **ntdll** (24): EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessageVa, EtwUnregisterTraceGuids, NtQueryLicenseValue, NtSetInformationObject, RtlCanonicalizeDomainName, RtlConvertSidToUnicodeString, RtlDllShutdownInProgress, RtlGUIDFromString, RtlGetDeviceFamilyInfoEnum, RtlGetPersistedStateLocation, RtlIpv4AddressToStringExW, RtlIpv4AddressToStringW, RtlIpv4StringToAddressExW, RtlIpv6AddressToStringExW, RtlIpv6StringToAddressExW, RtlMoveMemory, RtlPublishWnfStateData, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfNotificationWaitForCompletion, RtlValidSid
- **rpcrt4** (18): I_RpcExceptionFilter (delay), NdrAsyncClientCall2 (delay), NdrAsyncServerCall (delay), NdrClientCall4 (delay), NdrMesTypeDecode2 (delay), NdrMesTypeEncode2 (delay), RpcAsyncAbortCall (delay), RpcAsyncCancelCall (delay), RpcAsyncCompleteCall (delay), RpcAsyncInitializeHandle (delay), RpcBindingBind (delay), RpcBindingCreateW (delay), RpcBindingUnbind (delay), RpcExceptionFilter (delay), RpcServerInqBindingsEx (delay), RpcServerRegisterIf3 (delay), RpcServerTestCancel (delay), RpcServerUnregisterIfEx (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (17): CallbackMayRunLong, CloseThreadpoolCleanupGroup, CloseThreadpoolCleanupGroupMembers, CloseThreadpoolTimer, CloseThreadpoolWait, CloseThreadpoolWork, CreateThreadpoolCleanupGroup, CreateThreadpoolTimer, CreateThreadpoolWait, CreateThreadpoolWork, FreeLibraryWhenCallbackReturns, SetThreadpoolTimer, SetThreadpoolWait, SubmitThreadpoolWork, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWaitCallbacks, WaitForThreadpoolWorkCallbacks
- **dnsapi** (15): DnsConnectionDeletePolicyEntries (delay), DnsConnectionDeleteProxyInfo (delay), DnsConnectionFreeNameList (delay), DnsConnectionFreeProxyInfo (delay), DnsConnectionFreeProxyInfoEx (delay), DnsConnectionFreeProxyList (delay), DnsConnectionGetNameList (delay), DnsConnectionGetProxyInfo (delay), DnsConnectionGetProxyInfoForHostUrl (delay), DnsConnectionGetProxyList (delay), DnsConnectionSetPolicyEntries (delay), DnsConnectionSetProxyInfo (delay), DnsConnectionUpdateIfIndexTable (delay), DnsFreeProxyName (delay), DnsGetProxyInformation (delay)
- **websocket** (10): WebSocketAbortHandle (delay), WebSocketBeginClientHandshake (delay), WebSocketCompleteAction (delay), WebSocketCreateClientHandle (delay), WebSocketDeleteHandle (delay), WebSocketEndClientHandshake (delay), WebSocketGetAction (delay), WebSocketGetGlobalProperty (delay), WebSocketReceive (delay), WebSocketSend (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (9): FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW
- **sspicli** (9): EnumerateSecurityPackagesA (delay), FreeContextBuffer (delay), SspiCopyAuthIdentity (delay), SspiEncodeAuthIdentityAsStrings (delay), SspiEncryptAuthIdentity (delay), SspiFreeAuthIdentity (delay), SspiIsAuthIdentityEncrypted (delay), SspiLocalFree (delay), SspiZeroAuthIdentity (delay)
- **kernelbase** (8): AppContainerRegisterSid, AppContainerUnregisterSid, GetIsEdpEnabled, GetIsWdagEnabled, SubscribeEdpEnabledStateChange, SubscribeWdagEnabledStateChange, UnsubscribeEdpEnabledStateChange, UnsubscribeWdagEnabledStateChange
- **ws2_32** (8): #111 (delay), #115 (delay), #116 (delay), #14 (delay), #15 (delay), #21 (delay), #23 (delay), #3 (delay)
- **no api-set shell api-ms-win-security-credentials-l1-1-0** (6): CredDeleteW, CredEnumerateW, CredFree, CredReadDomainCredentialsW, CredReadW, CredWriteW
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (6): EventActivityIdControl, EventRegister, EventSetInformation, EventUnregister, EventWrite, EventWriteTransfer
- **no api-set shell api-ms-win-core-heap-l2-1-0** (4): GlobalAlloc, GlobalFree, LocalAlloc, LocalFree
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateEventExA, CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-registry-l1-1-0** (3): RegDeleteKeyExW, RegGetValueA, RegGetValueW
- **not in our api-ms-win-core-shlwapi-obsolete-l1-1-0** (2): StrCmpNCA, StrCmpNICA
- **no api-set shell api-ms-win-power-setting-l1-1-0** (2): PowerSettingRegisterNotification (delay), PowerSettingUnregisterNotification (delay)
- **nsi** (2): NsiAllocateAndGetTable (delay), NsiFreeTable (delay)
- **no api-set shell api-ms-win-networking-interfacecontexts-l1-1-0** (2): FreeInterfaceContextTable (delay), GetInterfaceContextTableForHostName (delay)
- **oleaut32** (2): #2 (delay), #6 (delay)
- **not in our api-ms-win-core-localization-l1-2-0** (1): IdnToAscii
- **not in our api-ms-win-core-processthreads-l1-1-0** (1): CreateProcessAsUserW
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (1): Wow64SetThreadDefaultGuestMachine
- **not in our api-ms-win-security-base-l1-1-0** (1): AddMandatoryAce
- **no api-set shell api-ms-win-core-registry-l1-1-1** (1): RegDeleteKeyValueW
- **no api-set shell api-ms-win-core-errorhandling-l1-1-2** (1): RaiseFailFastException
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **not in our api-ms-win-service-core-l1-1-0** (1): RegisterServiceCtrlHandlerExW (delay)
- **no api-set shell api-ms-win-service-core-l1-1-4** (1): GetServiceDirectory (delay)
- **not in our api-ms-win-service-management-l2-1-0** (1): NotifyServiceStatusChangeW (delay)
- **no api-set shell api-ms-win-power-base-l1-1-0** (1): GetPwrCapabilities (delay)
- **cryptbase** (1): SystemFunction036 (delay)
- **no api-set shell ext-ms-win-firewallapi-webproxy-l1-1-0** (1): FWIndicateProxyForUrl (delay)
- **dhcpcsvc** (1): DhcpRequestParams (delay)

## dxgi

- **ntdll** (42): EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWrite, EtwEventWriteNoRegistration, EtwEventWriteTransfer, LdrResSearchResource, NtQueryInformationProcess, NtQueryWnfStateData, RtlAppendUnicodeStringToString, RtlAppendUnicodeToString, RtlCaptureStackBackTrace, RtlCopyUnicodeString, RtlDosPathNameToNtPathName_U_WithStatus, RtlFormatCurrentUserKeyPath, RtlGUIDFromString, RtlGetDeviceFamilyInfoEnum, RtlGetNativeSystemInformation, RtlImageDirectoryEntryToData, RtlInitString, RtlInitUnicodeStringEx, RtlIsCriticalSectionLockedByThread, RtlIsMultiSessionSku, RtlNtPathNameToDosPathName, RtlPublishWnfStateData, RtlQueryWnfStateData, RtlRunOnceExecuteOnce, RtlSubscribeWnfStateChangeNotification, RtlUnicodeStringToInteger, RtlUnsubscribeWnfStateChangeNotification, RtlpEnsureBufferSize, RtlxAnsiStringToUnicodeSize, VerSetConditionMask, ZwCreateFile, ZwEnumerateKey, ZwEnumerateValueKey, ZwMapViewOfSection, ZwQueryDirectoryFile, ZwQueryInformationProcess, ZwQueryKey, ZwSetInformationProcess, ZwUnmapViewOfSection
- **no api-set shell ext-ms-win-ntuser-window-l1-1-0** (20): AdjustWindowRectEx (delay), CallNextHookEx (delay), CreateWindowExA (delay), DefWindowProcA (delay), DestroyWindow (delay), GetClientRect (delay), GetDesktopWindow (delay), GetForegroundWindow (delay), GetPropW (delay), GetWindow (delay), GetWindowInfo (delay), GetWindowRect (delay), GetWindowThreadProcessId (delay), IsWindow (delay), RemovePropW (delay), SetForegroundWindow (delay), SetPropW (delay), SetWindowPos (delay), SetWindowsHookExW (delay), UnhookWindowsHookEx (delay)
- **msvcrt** (13): ??0exception@@QAE@ABQBDH@Z, __CxxFrameHandler3, _except_handler4_common, _ftol2, _ftol2_sse, _vsnprintf_s, memcpy_s, memmove_s, swprintf_s, swscanf_s, wcscat_s, wcscpy_s, wcstombs_s
- **no api-set shell ext-ms-win-rtcore-ntuser-sysparams-l1-1-0** (11): ChangeDisplaySettingsExW (delay), DisplayConfigGetDeviceInfo (delay), EnumDisplayDevicesW (delay), EnumDisplayMonitors (delay), EnumDisplaySettingsW (delay), GetDisplayConfigBufferSizes (delay), GetMonitorInfoW (delay), MonitorFromRect (delay), MonitorFromWindow (delay), QueryDisplayConfig (delay), SystemParametersInfoA (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (10): DisableThreadLibraryCalls, FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleA, GetModuleHandleExA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (8): CloseThreadpoolTimer, CloseThreadpoolWait, CreateThreadpoolTimer, CreateThreadpoolWait, SetThreadpoolTimer, SetThreadpoolWait, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWaitCallbacks
- **no api-set shell ext-ms-win-ntuser-rectangle-ext-l1-1-0** (7): EqualRect (delay), IntersectRect (delay), IsRectEmpty (delay), OffsetRect (delay), SetRect (delay), SubtractRect (delay), UnionRect (delay)
- **no api-set shell api-ms-win-dx-d3dkmt-l1-1-0** (6): #1004 (delay), D3DKMTCacheHybridQueryValue (delay), D3DKMTEscape (delay), D3DKMTGetCachedHybridQueryValue (delay), D3DKMTQueryAdapterInfo (delay), GdiEntry13 (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-rgn-l1-1-0** (5): CombineRgn (delay), CreateRectRgnIndirect (delay), EqualRgn (delay), GetRegionData (delay), SetRectRgn (delay)
- **no api-set shell ext-ms-win-ntuser-window-l1-1-1** (5): GetAncestor (delay), GetLayeredWindowAttributes (delay), GetWindowDisplayAffinity (delay), IsWindowVisible (delay), SetWindowDisplayAffinity (delay)
- **no api-set shell ext-ms-win-ntuser-windowclass-l1-1-0** (5): GetClassNameA (delay), GetWindowLongA (delay), RegisterClassA (delay), SetWindowLongA (delay), UnregisterClassA (delay)
- **no api-set shell ext-ms-win-ntuser-misc-l1-2-0** (5): AttachThreadInput (delay), CloseClipboard (delay), EmptyClipboard (delay), OpenClipboard (delay), SetClipboardData (delay)
- **no api-set shell api-ms-win-appmodel-runtime-l1-1-0** (5): GetApplicationUserModelId (delay), GetCurrentApplicationUserModelId (delay), GetCurrentPackageFamilyName (delay), GetCurrentPackageFullName (delay), GetPackageFamilyName (delay)
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell ext-ms-win-gdi-draw-l1-1-0** (4): BitBlt (delay), CreateCompatibleBitmap (delay), CreateDIBSection (delay), StretchBlt (delay)
- **no api-set shell ext-ms-win-ntuser-message-l1-1-0** (4): DispatchMessageA (delay), PeekMessageA (delay), PostMessageA (delay), TranslateMessage (delay)
- **no api-set shell api-ms-win-dx-d3dkmt-l1-1-1** (4): D3DKMTAdjustFullscreenGamma (delay), D3DKMTOpenAdapterFromLuid (delay), D3DKMTQueryVidPnExclusiveOwnership (delay), D3DKMTSetVidPnSourceHwProtection (delay)
- **win32u** (3): NtBindCompositionSurface, NtQueryCompositionSurfaceStatistics, NtUnBindCompositionSurface
- **no api-set shell ext-ms-win-gdi-dc-create-l1-1-0** (3): CreateCompatibleDC (delay), CreateDCW (delay), DeleteDC (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (2): LoadLibraryA, LoadLibraryW
- **not in our api-ms-win-core-registry-l1-1-0** (2): RegGetValueA, RegGetValueW
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (2): K32GetModuleFileNameExW, K32GetModuleInformation
- **kernelbase** (2): BaseFormatObjectAttributes, CheckIsMSIXPackage
- **no api-set shell ext-ms-win-dwmapidxgi-ext-l1-1-0** (2): DwmpDxGetWindowSharedSurface (delay), DwmpDxgiIsThreadDesktopComposited (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-dc-access-l1-1-0** (2): GetDC (delay), ReleaseDC (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-cursor-l1-1-0** (2): LoadCursorA (delay), LoadCursorW (delay)
- **no api-set shell ext-ms-win-ntuser-keyboard-l1-1-0** (2): RegisterHotKey (delay), UnregisterHotKey (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-dpi-l1-1-0** (2): GetProcessDpiAwarenessInternal (delay), SetProcessDpiAwarenessInternal (delay)
- **no api-set shell api-ms-win-dx-d3dkmt-l1-1-3** (2): D3DKMTGetMultiPlaneOverlayCaps (delay), D3DKMTGetPostCompositionCaps (delay)
- **no api-set shell api-ms-win-dx-d3dkmt-l1-1-4** (2): D3DKMTDispMgrSourceOperation (delay), D3DKMTSetProcessDeviceRemovalSupport (delay)
- **not in our api-ms-win-security-base-l1-1-0** (1): AddMandatoryAce
- **no api-set shell api-ms-win-core-heap-l2-1-0** (1): LocalFree
- **no api-set shell api-ms-win-core-synch-l1-2-1** (1): WaitForMultipleObjects
- **no api-set shell api-ms-win-core-errorhandling-l1-1-2** (1): RaiseFailFastException
- **no api-set shell api-ms-win-core-quirks-l1-1-0** (1): QuirkIsEnabled
- **no api-set shell api-ms-win-core-atoms-l1-1-0** (1): GlobalAddAtomA
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell ext-ms-onecore-dcomp-l1-1-0** (1): DCompositionCreateSurfaceHandle (delay)
- **no api-set shell ext-ms-win-ntuser-uicontext-ext-l1-1-0** (1): #2521 (delay)
- **no api-set shell ext-ms-win-gdi-dc-l1-2-0** (1): SelectObject (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-devcaps-l1-1-0** (1): GetDeviceCaps (delay)
- **no api-set shell ext-ms-win-gdi-draw-l1-1-1** (1): SetStretchBltMode (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-object-l1-1-0** (1): DeleteObject (delay)
- **no api-set shell ext-ms-win-ntuser-gui-l1-1-0** (1): LoadIconA (delay)
- **no api-set shell ext-ms-win-ntuser-private-l1-1-1** (1): GetWindowCompositionAttribute (delay)
- **no api-set shell api-ms-win-rtcore-ntuser-synch-l1-1-0** (1): MsgWaitForMultipleObjects (delay)
- **no api-set shell api-ms-win-rtcore-ntuser-private-l1-1-7** (1): IsOneCoreTransformMode (delay)
- **no api-set shell api-ms-win-core-winrt-l1-1-0** (1): RoGetActivationFactory (delay)
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (1): WindowsCreateStringReference (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (1): SetRestrictedErrorInfo (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-1** (1): RoGetMatchingRestrictedErrorInfo (delay)
- **no api-set shell api-ms-win-gdi-dpiinfo-l1-1-0** (1): GetCurrentDpiInfo (delay)
- **no api-set shell ext-ms-mf-pal-l2-1-0** (1): XboxGetMultiplaneOverlayPriority (delay)
- **dcomp** (1): DCompositionCreateDevice3 (delay)
- **no api-set shell ext-ms-win-dwmapidxgi-ext-l1-1-1** (1): DwmpUpdateProxyWindowForCapture (delay)
- **no api-set shell ext-ms-win-shell32-shellfolders-l1-1-0** (1): SHGetKnownFolderPath (delay)

## ws2_32

- **ntdll** (33): EtwEventEnabled, EtwEventRegister, EtwEventUnregister, EtwEventWrite, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwTraceMessageVa, EtwUnregisterTraceGuids, NtCreateNamedPipeFile, NtDelayExecution, NtLoadDriver, NtQueryDirectoryFile, RtlAdjustPrivilege, RtlCompareMemory, RtlGetNtProductType, RtlImpersonateSelf, RtlInitUnicodeStringEx, RtlIpv4AddressToStringExA, RtlIpv4AddressToStringExW, RtlIpv4StringToAddressA, RtlIpv4StringToAddressW, RtlIpv6AddressToStringExA, RtlIpv6AddressToStringExW, RtlIpv6StringToAddressA, RtlIpv6StringToAddressExW, RtlIpv6StringToAddressW, RtlUnhandledExceptionFilter, RtlUnicodeStringToInteger, WinSqmIsOptedIn, _vsnwprintf
- **no api-set shell api-ms-win-core-crt-l1-1-0** (24): __isascii, _except_handler4_common, _stricmp, _vsnprintf_s, _vsnwprintf_s, _wcsicmp, _wcsnicmp, atoi, isspace, memcmp, memcpy, memcpy_s, memmove_s, memset, sprintf_s, strchr, strcpy_s, strrchr, strtoul, towupper, wcschr, wcscpy_s, wcsncmp, wcsstr
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (13): FreeLibrary, FreeLibraryAndExitThread, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleA, GetModuleHandleExA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW, LoadStringA, LoadStringW
- **no api-set shell api-ms-win-core-crt-l2-1-0** (7): __dllonexit3, _initterm, _initterm_e, _onexit, _purecall, exit, hgets
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (5): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, TrySubmitThreadpoolCallback, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-heap-l2-1-0** (4): GlobalAlloc, GlobalFree, LocalAlloc, LocalFree
- **rpcrt4** (4): NdrAsyncServerCall, RpcAsyncCompleteCall, RpcServerInqCallAttributesW, RpcServerUnregisterIfEx
- **no api-set shell ext-ms-win-rtcore-ntuser-window-ext-l1-1-0** (4): DispatchMessageW (delay), PeekMessageW (delay), PostMessageW (delay), TranslateMessage (delay)
- **nsi** (3): NsiGetAllParameters (delay), NsiGetParameter (delay), NsiSetAllParameters (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (2): CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-registry-l1-1-0** (2): RegDeleteKeyExA, RegDeleteTreeA
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence

## shlwapi

- **no api-set shell api-ms-win-shcore-registry-l1-1-0** (28): SHCopyKeyA (delay), SHCopyKeyW (delay), SHDeleteEmptyKeyA (delay), SHDeleteEmptyKeyW (delay), SHDeleteKeyA (delay), SHDeleteKeyW (delay), SHDeleteValueA (delay), SHDeleteValueW (delay), SHEnumKeyExA (delay), SHEnumKeyExW (delay), SHEnumValueA (delay), SHEnumValueW (delay), SHGetValueA (delay), SHGetValueW (delay), SHQueryInfoKeyA (delay), SHQueryInfoKeyW (delay), SHQueryValueExA (delay), SHQueryValueExW (delay), SHRegDuplicateHKey (delay), SHRegGetIntW (delay), SHRegGetPathA (delay), SHRegGetPathW (delay), SHRegGetValueA (delay), SHRegGetValueW (delay), SHRegSetPathA (delay), SHRegSetPathW (delay), SHSetValueA (delay), SHSetValueW (delay)
- **no api-set shell api-ms-win-core-registryuserspecific-l1-1-0** (25): SHRegCloseUSKey, SHRegCreateUSKeyA, SHRegCreateUSKeyW, SHRegDeleteEmptyUSKeyA, SHRegDeleteEmptyUSKeyW, SHRegDeleteUSValueA, SHRegDeleteUSValueW, SHRegEnumUSKeyA, SHRegEnumUSKeyW, SHRegEnumUSValueA, SHRegEnumUSValueW, SHRegGetBoolUSValueA, SHRegGetBoolUSValueW, SHRegGetUSValueA, SHRegGetUSValueW, SHRegOpenUSKeyA, SHRegOpenUSKeyW, SHRegQueryInfoUSKeyA, SHRegQueryInfoUSKeyW, SHRegQueryUSValueA, SHRegQueryUSValueW, SHRegSetUSValueA, SHRegSetUSValueW, SHRegWriteUSValueA, SHRegWriteUSValueW
- **shcore** (23): #120 (delay), #121 (delay), #123 (delay), #126 (delay), #127 (delay), #130 (delay), #142 (delay), #143 (delay), #144 (delay), #145 (delay), #150 (delay), #151 (delay), #181 (delay), #182 (delay), #183 (delay), #184 (delay), #185 (delay), #186 (delay), #187 (delay), #188 (delay), #190 (delay), #191 (delay), #234 (delay)
- **not in our api-ms-win-core-shlwapi-obsolete-l1-1-0** (19): QISearch, StrCatChainW, StrChrNIW, StrChrNW, StrCmpCA, StrCmpCW, StrCmpICA, StrCmpICW, StrCmpLogicalW, StrCmpNCA, StrCmpNCW, StrCmpNICA, StrCmpNICW, StrCpyNXA, StrCpyNXW, StrStrNIW, StrStrNW, StrToInt64ExA, StrToInt64ExW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (15): DisableThreadLibraryCalls, FindResourceExW, FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW, LoadResource, LoadStringA, LoadStringW, LockResource, SizeofResource
- **ntdll** (14): EtwEventEnabled, EtwEventRegister, EtwEventUnregister, EtwEventWrite, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwUnregisterTraceGuids, NtQueryInformationToken, _allmul, _vsnwprintf, memcpy_s, memmove_s
- **not in our api-ms-win-core-shlwapi-legacy-l1-1-0** (14): IsCharBlankW, IsCharCntrlW, IsCharDigitW, IsCharPunctW, IsCharSpaceA, IsCharSpaceW, IsCharXDigitW, PathMatchSpecExA, PathMatchSpecExW, PathUnExpandEnvStringsA, PathUnExpandEnvStringsW, SHExpandEnvironmentStringsA, SHExpandEnvironmentStringsW, SHTruncateString
- **not in our api-ms-win-shcore-stream-l1-1-0** (9): IStream_Copy (delay), IStream_Read (delay), IStream_ReadStr (delay), IStream_Reset (delay), IStream_Size (delay), IStream_Write (delay), IStream_WriteStr (delay), SHCreateMemStream (delay), SHCreateStreamOnFileEx (delay)
- **oleaut32** (8): #12 (delay), #150 (delay), #2 (delay), #4 (delay), #6 (delay), #7 (delay), #8 (delay), #9 (delay)
- **not in our api-ms-win-core-url-l1-1-0** (7): GetAcceptLanguagesA, GetAcceptLanguagesW, IsInternetESCEnabled, ParseURLA, ParseURLW, PathCreateFromUrlAlloc, UrlFixupW
- **no api-set shell api-ms-win-shcore-thread-l1-1-0** (6): SHCreateThread (delay), SHCreateThreadRef (delay), SHCreateThreadWithHandle (delay), SHGetThreadRef (delay), SHReleaseThreadRef (delay), SHSetThreadRef (delay)
- **no api-set shell ext-ms-win-ntuser-windowclass-l1-1-0** (6): GetClassInfoA (delay), GetWindowLongW (delay), RegisterClassA (delay), SetWindowLongW (delay), UnregisterClassA (delay), UnregisterClassW (delay)
- **no api-set shell api-ms-win-core-heap-l2-1-0** (5): GlobalAlloc, GlobalFree, LocalAlloc, LocalFree, LocalReAlloc
- **shell32** (5): #102 (delay), #152 (delay), #155 (delay), #18 (delay), #704 (delay)
- **no api-set shell api-ms-win-shcore-comhelpers-l1-1-0** (5): IUnknown_AtomicRelease (delay), IUnknown_GetSite (delay), IUnknown_QueryService (delay), IUnknown_Set (delay), IUnknown_SetSite (delay)
- **msvcrt** (4): __CxxFrameHandler3, _except_handler4_common, _get_errno, _set_errno
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (4): CloseThreadpoolTimer, CreateThreadpoolTimer, SetThreadpoolTimer, WaitForThreadpoolTimerCallbacks
- **no api-set shell api-ms-win-core-sidebyside-l1-1-0** (4): ActivateActCtx, CreateActCtxW, DeactivateActCtx, ReleaseActCtx
- **propsys** (4): #420 (delay), #421 (delay), #422 (delay), #429 (delay)
- **no api-set shell api-ms-win-shcore-unicodeansi-l1-1-0** (4): SHAnsiToAnsi (delay), SHAnsiToUnicode (delay), SHUnicodeToAnsi (delay), SHUnicodeToUnicode (delay)
- **no api-set shell api-ms-win-shcore-path-l1-1-0** (4): #170 (delay), #171 (delay), #172 (delay), #173 (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateEventExW, CreateMutexExW, CreateSemaphoreExW
- **no api-set shell api-ms-win-core-versionansi-l1-1-0** (3): GetFileVersionInfoExA, GetFileVersionInfoSizeExA, VerQueryValueA
- **not in our api-ms-win-core-registry-l1-1-0** (2): RegDeleteKeyExW, RegGetValueW
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **kernelbase** (2): ChrCmpIA, ChrCmpIW
- **no api-set shell api-ms-win-shcore-obsolete-l1-1-0** (2): SHStrDupA (delay), SHStrDupW (delay)
- **no api-set shell api-ms-win-core-string-l2-1-1** (1): SHLoadIndirectString
- **no api-set shell api-ms-win-core-path-l1-1-0** (1): PathCchRemoveFileSpec
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (1): LoadLibraryW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell api-ms-win-shcore-registry-l1-1-1** (1): SHRegGetValueFromHKCUHKLM (delay)
- **no api-set shell api-ms-win-shcore-sysinfo-l1-1-0** (1): IsOS (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (1): RoOriginateError (delay)
- **no api-set shell ext-ms-win-advapi32-safer-l1-1-0** (1): SaferiIsExecutableFileType (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-devcaps-l1-1-0** (1): GetDeviceCaps (delay)
- **msiltcfg** (1): #3 (delay)
- **apphelp** (1): ApphelpCheckShellObject (delay)
- **mrmcorer** (1): ResourceManagerQueueGetString (delay)

## ole32

- **no api-set shell api-ms-win-core-com-private-l1-1-0** (37): CleanupOleStateInAllTls (delay), CleanupTlsOleState (delay), ClearCleanupFlag (delay), CoGetInstanceFromFile (delay), CoInitializeWOW (delay), CoRegisterMessageFilter (delay), CoRegisterSurrogateEx (delay), CoUnloadingWOW (delay), GetFuncDescs (delay), InternalCCGetClassInformationForDde (delay), InternalCCGetClassInformationFromKey (delay), InternalCCSetDdeServerWindow (delay), InternalCallFrameExceptionFilter (delay), InternalCoRegisterDisconnectCallback (delay), InternalCoUnregisterDisconnectCallback (delay), InternalCreateCAggId (delay), InternalCreateIdentityHandler (delay), InternalDoATClassCreate (delay), InternalIrotEnumRunning2 (delay), InternalIrotGetTimeOfLastChange2 (delay), InternalIrotIsRunning2 (delay), InternalIrotNoteChangeTime (delay), InternalIrotRegister (delay), InternalIrotRevoke (delay), InternalIsApartmentInitialized (delay), InternalIsProcessInitialized (delay), InternalNotifyDDStartOrStop (delay), InternalOleModalLoopBlockFn (delay), InternalSTAInvoke (delay), InternalSetAptCallCtrlOnTlsIfRequired (delay), InternalSetOleThunkWowPtr (delay), InternalTlsAllocData (delay), NdrExtStubInitialize (delay), NdrOleDllGetClassObject (delay), NdrpFindInterface (delay), ReleaseFuncDescs (delay), SetCleanupFlag (delay)
- **combase** (24): #101, #102, #103, #104, #185, #186, #187, #188, #189, #190, #191, #192, #193, #194, #195, #196, #197, #198, #199, #200, #201, #202, #203, #204
- **rpcrt4** (22): I_RpcExceptionFilter, NdrAsyncClientCall, NdrCorrelationInitialize, NdrGetSimpleTypeBufferAlignment, NdrGetSimpleTypeBufferSize, NdrGetSimpleTypeMemorySize, NdrGetTypeFlags, NdrOutInit, NdrTypeMarshall, NdrTypeSize, NdrTypeUnmarshall, NdrUnmarshallBasetypeInline, NdrpGetProcFormatString, NdrpGetTypeFormatString, NdrpGetTypeGenCookie, NdrpMemoryIncrement, NdrpReleaseTypeFormatString, NdrpReleaseTypeGenCookie, NdrpVarVtOfTypeDesc, RpcAsyncCancelCall, RpcAsyncCompleteCall, RpcAsyncInitializeHandle
- **ntdll** (21): EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWriteTransfer, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, NtQuerySecurityAttributesToken, NtQueryWnfStateData, RtlGetNtSystemRoot, RtlIsCriticalSectionLockedByThread, RtlLoadString, RtlQueryPackageClaims, WinSqmSetDWORD, ZwCreateKey, ZwDeleteKey, ZwDeleteValueKey, ZwEnumerateKey
- **no api-set shell api-ms-win-core-com-l2-1-1** (21): CreateILockBytesOnHGlobal (delay), FmtIdToPropStgName (delay), GetConvertStg (delay), GetHGlobalFromILockBytes (delay), PropStgNameToFmtId (delay), ReadClassStg (delay), ReadClassStm (delay), StgCreateDocfile (delay), StgCreateDocfileOnILockBytes (delay), StgCreatePropSetStg (delay), StgCreatePropStg (delay), StgCreateStorageEx (delay), StgIsStorageFile (delay), StgIsStorageILockBytes (delay), StgOpenPropStg (delay), StgOpenStorage (delay), StgOpenStorageEx (delay), StgOpenStorageOnILockBytes (delay), StgSetTimes (delay), WriteClassStg (delay), WriteClassStm (delay)
- **oleaut32** (19): #10 (delay), #12 (delay), #149 (delay), #150 (delay), #16 (delay), #162 (delay), #183 (delay), #2 (delay), #201 (delay), #202 (delay), #295 (delay), #296 (delay), #297 (delay), #36 (delay), #37 (delay), #41 (delay), #6 (delay), #8 (delay), #9 (delay)
- **no api-set shell ext-ms-win-edputil-policy-l1-1-0** (17): EdpClearClipboardMetaData (delay), EdpFreeContext (delay), EdpGetAppLockerUniqueAppIdentifier (delay), EdpGetClipboardAccessDeniedData (delay), EdpGetContextForProcess (delay), EdpGetContextForWindow (delay), EdpGetDataInfoFromDataObject (delay), EdpGetEnterpriseIdForClipboard (delay), EdpGetIsManaged (delay), EdpGetSourceAppIdForClipboard (delay), EdpGetSourceIsEnlightenedForClipboard (delay), EdpIsContextExemptOrEnlightenedAllowed (delay), EdpIsUIPolicyEvaluationEnabledForThread (delay), EdpRequestAccessForContext (delay), EdpSetEnterpriseIdForClipboard (delay), EdpSetSourceAppIdForClipboard (delay), EdpSetSourceIsEnlightenedForClipboard (delay)
- **no api-set shell api-ms-win-core-marshal-l1-1-0** (12): CLIPFORMAT_UserFree, CLIPFORMAT_UserMarshal, CLIPFORMAT_UserSize, CLIPFORMAT_UserUnmarshal, HPALETTE_UserFree, HPALETTE_UserMarshal, HPALETTE_UserSize, HPALETTE_UserUnmarshal, HWND_UserFree, HWND_UserMarshal, HWND_UserSize, HWND_UserUnmarshal
- **kernelbase** (11): AreFileApisANSI, GetPackageFullName, GlobalAlloc, GlobalFree, LocalAlloc, LocalLock, LocalUnlock, Sleep, lstrcmpW, lstrcmpiW, lstrlenW
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (11): FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW, LoadResource, LoadStringW, LockResource
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (11): CloseThreadpoolTimer, CloseThreadpoolWait, CloseThreadpoolWork, CreateThreadpoolTimer, CreateThreadpoolWait, CreateThreadpoolWork, SetThreadpoolTimer, SetThreadpoolWait, SubmitThreadpoolWork, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWorkCallbacks
- **coml2** (10): #1 (delay), #11 (delay), #12 (delay), #2 (delay), #3 (delay), #4 (delay), #5 (delay), #6 (delay), #7 (delay), #8 (delay)
- **no api-set shell api-ms-win-core-atoms-l1-1-0** (7): GlobalAddAtomA, GlobalAddAtomW, GlobalDeleteAtom, GlobalFindAtomA, GlobalFindAtomW, GlobalGetAtomNameA, GlobalGetAtomNameW
- **user32** (7): #2521, #2550, #2715, #2716, GetThreadDpiAwarenessContext, GetWindowDpiAwarenessContext, SetThreadDpiAwarenessContext
- **not in our api-ms-win-core-com-l1-1-0** (7): CoCancelCall (delay), CoDecrementMTAUsage (delay), CoDisableCallCancellation (delay), CoEnableCallCancellation (delay), CoGetApartmentType (delay), CoGetCancelObject (delay), CoIncrementMTAUsage (delay)
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (6): EventActivityIdControl, EventProviderEnabled, EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-core-com-midlproxystub-l1-1-0** (5): ObjectStublessClient3 (delay), ObjectStublessClient4 (delay), ObjectStublessClient5 (delay), ObjectStublessClient6 (delay), ObjectStublessClient7 (delay)
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (5): WindowsCreateString (delay), WindowsCreateStringReference (delay), WindowsDeleteString (delay), WindowsDuplicateString (delay), WindowsGetStringRawBuffer (delay)
- **no api-set shell api-ms-win-core-com-private-l1-1-1** (5): InternalCAggIdRelease (delay), InternalCAggIdSetHandler (delay), InternalCStdIdentityGetIProxyManager (delay), InternalCStdIdentityGetInternalUnk (delay), InternalCStdIdentityUpdateFlags (delay)
- **not in our api-ms-win-core-registry-l1-1-0** (4): RegDeleteKeyExA, RegDeleteKeyExW, RegGetValueW, RegLoadMUIStringW
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateEventExW, CreateMutexExW, CreateSemaphoreExW
- **kernel32** (3): RegOpenUserClassesRoot, Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (3): RoOriginateError (delay), RoOriginateErrorW (delay), RoTransformError (delay)
- **no api-set shell api-ms-win-core-com-private-l1-3-0** (3): InternalCMLSendReceive2 (delay), InternalCanMakeOutCall2 (delay), InternalIrotGetObject3 (delay)
- **no api-set shell api-ms-win-core-com-private-l1-2-0** (3): InternalGetWindowPropInterface2 (delay), InternalRegisterWindowPropInterface2 (delay), InternalRevokeWindowPropInterface (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (2): FindResourceW, LoadLibraryA
- **no api-set shell api-ms-win-core-winrt-l1-1-0** (2): RoActivateInstance (delay), RoGetActivationFactory (delay)
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (1): GetSystemWow64DirectoryW
- **no api-set shell api-ms-win-core-heap-l2-1-0** (1): LocalFree
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (1): QueryFullProcessImageNameW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **not in our api-ms-win-core-kernel32-private-l1-1-0** (1): CheckElevationEnabled
- **no api-set shell api-ms-win-core-sidebyside-l1-1-0** (1): FindActCtxSectionGuid
- **no api-set shell api-ms-win-core-synch-l1-2-1** (1): CreateSemaphoreW
- **no api-set shell api-ms-win-core-psm-key-l1-1-0** (1): PsmGetKeyFromToken
- **no api-set shell api-ms-win-core-quirks-l1-1-0** (1): QuirkIsEnabled
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell ext-ms-win-sxs-oleautomation-l1-1-0** (1): SxsOleAut32MapReferenceClsidToConfiguredClsid (delay)
- **no api-set shell ext-ms-win32-subsystem-query-l1-1-0** (1): QueryWin32SubsystemHost (delay)
- **no api-set shell ext-ms-win-feclient-encryptedfile-l1-1-0** (1): EdpSetCredServiceInfo (delay)

## sechost

- **ntdll** (80): DbgPrintEx, EtwDeliverDataBlock, EtwEnumerateProcessRegGuids, EtwProcessPrivateLoggerRequest, EtwSendNotification, EtwpGetCpuSpeed, LdrQueryModuleServiceTags, LdrResSearchResource, NtCancelIoFile, NtOpenProcessTokenEx, NtOpenThreadToken, NtQueryInformationThread, NtQueryInformationToken, NtQueryIntervalProfile, NtQueueApcThread, NtSetIntervalProfile, NtSetSystemInformation, NtTraceControl, NtWaitForMultipleObjects, RtlAbsoluteToSelfRelativeSD, RtlAddAccessAllowedAceEx, RtlAddAccessAllowedObjectAce, RtlAddAccessDeniedAceEx, RtlAddAccessDeniedObjectAce, RtlAddAuditAccessAceEx, RtlAddAuditAccessObjectAce, RtlAddMandatoryAce, RtlAllocateAndInitializeSid, RtlCapabilityCheck, RtlCapabilityCheckForSingleSessionSku, RtlCheckTokenCapability, RtlCheckTokenMembership, RtlCheckTokenMembershipEx, RtlConvertSidToUnicodeString, RtlCopySecurityDescriptor, RtlCopyUnicodeString, RtlCreateServiceSid, RtlDecompressBufferEx, RtlDeriveCapabilitySidsFromName, RtlDllShutdownInProgress, RtlEqualPrefixSid, RtlEqualSid, RtlFirstFreeAce, RtlFreeAnsiString, RtlGUIDFromString, RtlGetAce, RtlGetCompressionWorkSpaceSize, RtlGetControlSecurityDescriptor, RtlGetCurrentServiceSessionId, RtlGetDaclSecurityDescriptor, RtlGetGroupSecurityDescriptor, RtlGetNativeSystemInformation, RtlGetNtProductType, RtlGetOwnerSecurityDescriptor, RtlGetPersistedStateLocation, RtlGetSaclSecurityDescriptor, RtlInitUnicodeStringEx, RtlInterlockedClearBitRun, RtlMakeSelfRelativeSD, RtlNtStatusToDosErrorNoTeb, RtlQueryPerformanceFrequency, RtlQueryRegistryValueWithFallback, RtlQueryTimeZoneInformation, RtlQueryWnfStateData, RtlRunOnceExecuteOnce, RtlSetLastWin32Error, RtlSetSaclSecurityDescriptor, RtlSetThreadSubProcessTag, RtlSubAuthorityCountSid, RtlSubscribeWnfStateChangeNotification, RtlUnhandledExceptionFilter, RtlUnicodeToMultiByteSize, RtlUnsubscribeWnfNotificationWaitForCompletion, RtlUnsubscribeWnfStateChangeNotification, RtlValidAcl, RtlValidRelativeSecurityDescriptor, RtlValidSid, RtlxAnsiStringToUnicodeSize, RtlxUnicodeStringToAnsiSize, _vsnwprintf
- **no api-set shell api-ms-win-core-crt-l1-1-0** (37): _errno, _except_handler4_common, _ftol2, _i64tow_s, _stricmp, _ui64tow_s, _ultow, _ultow_s, _vsnwprintf_s, _wcsicmp, _wcsnicmp, _wcstoi64, _wcstoui64, iswctype, memcmp, memcpy, memcpy_s, memmove, memmove_s, memset, qsort_s, strchr, strnlen, strrchr, strstr, swprintf_s, towlower, wcscat_s, wcschr, wcscpy_s, wcsncmp, wcsncpy_s, wcsnlen, wcsrchr, wcsstr, wcstok_s, wcstoul
- **rpcrt4** (11): I_RpcExceptionFilter, NdrAsyncClientCall2, NdrClientCall4, RpcAsyncCancelCall, RpcAsyncCompleteCall, RpcAsyncInitializeHandle, RpcBindingBind, RpcBindingCreateW, RpcServerInqCallAttributesA, RpcServerRegisterIf3, RpcSsGetContextBinding
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (8): DisableThreadLibraryCalls, FreeLibrary, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExW
- **no api-set shell api-ms-win-core-crt-l2-1-0** (5): __dllonexit3, _initterm, _initterm_e, _onexit, _purecall
- **cryptbase** (5): SystemFunction004 (delay), SystemFunction005 (delay), SystemFunction028 (delay), SystemFunction040 (delay), SystemFunction041 (delay)
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (5): WindowsCreateString (delay), WindowsCreateStringReference (delay), WindowsDeleteString (delay), WindowsDuplicateString (delay), WindowsGetStringRawBuffer (delay)
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateEventExW, CreateMutexExW, CreateSemaphoreExW
- **no api-set shell api-ms-win-core-heap-l2-1-0** (3): LocalAlloc, LocalFree, LocalReAlloc
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (3): CloseThreadpoolWork, CreateThreadpoolWork, SubmitThreadpoolWork
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (2): RoOriginateError (delay), RoTransformError (delay)
- **no api-set shell api-ms-win-core-winrt-l1-1-0** (2): RoActivateInstance (delay), RoGetActivationFactory (delay)
- **no api-set shell ext-ms-win-eventing-rundown-l1-1-0** (2): EtwLogHeapRundown (delay), EtwLogSysConfigRundown (delay)
- **not in our api-ms-win-core-processthreads-l1-1-0** (1): CreateProcessAsUserW
- **not in our api-ms-win-security-base-l1-1-0** (1): EqualDomainSid
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (1): IsWow64Process2
- **no api-set shell api-ms-win-core-rtlsupport-l1-2-0** (1): RtlCompareMemory
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **not in our api-ms-win-core-com-l1-1-0** (1): CoGetApartmentType (delay)
- **no api-set shell api-ms-win-security-base-private-l1-1-1** (1): CreateAppContainerToken (delay)
- **no api-set shell api-ms-win-appmodel-identity-l1-2-0** (1): AppContainerDeriveSidFromMoniker (delay)
- **no api-set shell ext-ms-win-security-chambers-l1-1-0** (1): GetCapabilitySidsEx (delay)

## combase

- **ntdll** (69): EtwEventActivityIdControl, EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWrite, EtwEventWriteTransfer, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, EvtIntReportEventAndSourceAsync, LdrStandardizeSystemPath, NtApphelpCacheControl, NtCreateKey, NtDeleteKey, NtLoadKeyEx, NtQueryInformationProcess, NtQueryInformationThread, NtQueryInformationToken, NtQueryKey, NtQueryObject, NtQuerySecurityAttributesToken, NtQueryTimerResolution, NtQueryVolumeInformationFile, NtQueryWnfStateData, NtSetInformationObject, NtUnloadKey2, RtlAdjustPrivilege, RtlAppendUnicodeToString, RtlApplicationVerifierStop, RtlCaptureStackBackTrace, RtlCheckForOrphanedCriticalSections, RtlCheckTokenCapability, RtlCompareMemory, RtlDelete, RtlDeleteNoSplay, RtlDllShutdownInProgress, RtlDosPathNameToRelativeNtPathName_U_WithStatus, RtlGetAppContainerNamedObjectPath, RtlGetAppContainerSidType, RtlGetDeviceFamilyInfoEnum, RtlGetThreadWorkOnBehalfTicket, RtlImageDirectoryEntryToData, RtlInitUnicodeStringEx, RtlInitializeSidEx, RtlIsCriticalSectionLockedByThread, RtlIsMultiSessionSku, RtlIsStateSeparationEnabled, RtlLoadString, RtlNtStatusToDosErrorNoTeb, RtlPcToFileHeader, RtlQueryPackageClaims, RtlQueryPackageIdentity, RtlRealPredecessor, RtlRealSuccessor, RtlReportException, RtlSetThreadSubProcessTag, RtlSetThreadWorkOnBehalfTicket, RtlSidDominates, RtlSleepConditionVariableCS, RtlSplay, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfNotificationWaitForCompletion, RtlValidRelativeSecurityDescriptor, RtlWow64GetEquivalentMachineCHPE, RtlWow64IsWowGuestMachineSupported, WinSqmSetDWORD
- **rpcrt4** (57): #1000, I_RpcAsyncAbortCall, I_RpcAsyncSetHandle, I_RpcBCacheAllocate, I_RpcBCacheFree, I_RpcBindingInqCurrentModifiedId, I_RpcBindingInqLocalClientPID, I_RpcBindingSetPrivateOption, I_RpcExceptionFilter, I_RpcFreeSystemHandle, I_RpcFreeSystemHandleCollection, I_RpcGetBufferWithObject, I_RpcGetSystemHandle, I_RpcMgmtEnableDedicatedThreadPool, I_RpcMgmtQueryDedicatedThreadPool, I_RpcOpenClientProcess, I_RpcServerGetAssociationID, I_RpcServerSubscribeForDisconnectNotification2, I_RpcServerUnsubscribeForDisconnectNotification, I_RpcSetDCOMAppId, I_RpcSetSystemHandle, I_RpcSystemHandleTypeSpecificWork, NdrAsyncServerCall, NdrClientCall4, NdrCorrelationFree, NdrCorrelationInitialize, NdrDcomAsyncClientCall2, NdrGetTypeFlags, NdrGetUserMarshalInfo, NdrMesTypeAlignSize2, NdrMesTypeDecode2, NdrMesTypeEncode2, NdrMesTypeFree2, RpcAsyncCancelCall, RpcAsyncCompleteCall, RpcAsyncGetCallStatus, RpcAsyncInitializeHandle, RpcBindingBind, RpcBindingCreateW, RpcBindingUnbind, RpcCancelThreadEx, RpcCertGeneratePrincipalNameW, RpcErrorAddRecord, RpcErrorEndEnumeration, RpcErrorGetNextRecord, RpcErrorStartEnumeration, RpcExceptionFilter, RpcImpersonateClient2, RpcServerInqBindingHandle, RpcServerInqCallAttributesW, RpcServerRegisterIf3, RpcServerSubscribeForNotification, RpcServerTestCancel, RpcServerUnsubscribeForNotification, SimpleTypeAlignment, SimpleTypeBufferSize, SimpleTypeMemorySize
- **no api-set shell ext-ms-win-rtcore-ntuser-window-ext-l1-1-0** (23): AllowSetForegroundWindow (delay), CreateWindowExW (delay), DefWindowProcW (delay), DestroyWindow (delay), DispatchMessageW (delay), GetMessageW (delay), GetQueueStatus (delay), GetWindowThreadProcessId (delay), InSendMessageEx (delay), IsChild (delay), IsGUIThread (delay), IsWindow (delay), KillTimer (delay), PeekMessageW (delay), PostMessageW (delay), PostQuitMessage (delay), PostThreadMessageW (delay), RegisterClassW (delay), SendMessageW (delay), SetCoalescableTimer (delay), SetWindowLongW (delay), TranslateMessage (delay), UnregisterClassW (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-0** (14): CheckInitDde (delay), CleanROTForApartment (delay), ClipboardProcessUninitialize (delay), CoGetInterceptorForOle32 (delay), DdeBindToObject (delay), DeletePatternAndExtensionTables (delay), DestroyRunningObjectTable (delay), DragDropSetFDT (delay), FindExt (delay), GetObjectFromRotByPath (delay), Ole32DllGetClassObject (delay), OleGetAutoConvert (delay), OleReleaseEnumVerbCache (delay), OleUninitialize (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (13): CloseThreadpoolTimer, CloseThreadpoolWait, CloseThreadpoolWork, CreateThreadpoolTimer, CreateThreadpoolWait, CreateThreadpoolWork, SetEventWhenCallbackReturns, SetThreadpoolTimer, SetThreadpoolWait, SubmitThreadpoolWork, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWaitCallbacks, WaitForThreadpoolWorkCallbacks
- **kernelbase** (12): FindPackagesByPackageFamily, GetApplicationUserModelId, GetCurrentApplicationUserModelId, GetCurrentPackageFamilyName, GetCurrentPackageInfo3, GetStagedPackagePathByFullName2, GetSystemMetadataPathForPackage, IsDeveloperModeEnabled, OpenPackageInfoByFullNameForMachine, OpenPackageInfoByFullNameForUser, ParseApplicationUserModelId, VerifyPackageFullName
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (11): FreeLibrary, FreeLibraryAndExitThread, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleA, GetModuleHandleExA, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW
- **no api-set shell ext-ms-onecore-appmodel-staterepository-cache-l1-1-0** (11): SRCacheContext_Close (delay), SRCacheContext_EnumerateData (delay), SRCacheContext_GetField_String (delay), SRCacheContext_GetField_UInt32 (delay), SRCacheContext_GetField_UInt64 (delay), SRCacheContext_Open (delay), SRCacheContext_OpenSubContext (delay), SRCacheManager_Close (delay), SRCacheManager_Open (delay), SRCache_AllocStringBuffer (delay), SRCache_Free (delay)
- **oleaut32** (9): #10 (delay), #161 (delay), #2 (delay), #200 (delay), #201 (delay), #4 (delay), #500 (delay), #6 (delay), #9 (delay)
- **not in our api-ms-win-core-registry-l1-1-0** (8): RegDeleteKeyExA, RegDeleteKeyExW, RegDeleteTreeW, RegGetValueA, RegGetValueW, RegLoadAppKeyW, RegLoadMUIStringW, RegSaveKeyExW
- **no api-set shell api-ms-win-core-sidebyside-l1-1-0** (8): ActivateActCtx, AddRefActCtx, CreateActCtxW, DeactivateActCtx, FindActCtxSectionGuid, FindActCtxSectionStringW, GetCurrentActCtx, ReleaseActCtx
- **no api-set shell ext-ms-win-kernel32-package-l1-1-0** (8): ClosePackageInfo (delay), GetPackageFullName (delay), GetPackageInfo (delay), OpenPackageInfoByFullName (delay), PackageFamilyNameFromFullName (delay), PackageFamilyNameFromId (delay), PackageFullNameFromId (delay), PackageIdFromFullName (delay)
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (7): EventActivityIdControl, EventProviderEnabled, EventRegister, EventSetInformation, EventUnregister, EventWriteEx, EventWriteTransfer
- **no api-set shell ext-ms-win-gdi-metafile-l1-1-0** (6): DeleteEnhMetaFile (delay), DeleteMetaFile (delay), GetEnhMetaFileBits (delay), GetMetaFileBitsEx (delay), SetEnhMetaFileBits (delay), SetMetaFileBitsEx (delay)
- **no api-set shell ext-ms-win-core-winrt-remote-l1-1-0** (5): GetEndPointMapperCrossVmPipeNamespace (delay), GetRemoteVmAliasName (delay), IsPackagedAppExemptFromSuspend (delay), RemoteWinRTActivation (delay), WinRTPerMachineSingleInstancing (delay)
- **wer** (5): WerReportAddFile (delay), WerReportCloseHandle (delay), WerReportCreate (delay), WerReportSetParameter (delay), WerReportSubmit (delay)
- **no api-set shell api-ms-win-core-heap-l2-1-0** (4): GlobalAlloc, GlobalFree, LocalAlloc, LocalFree
- **not in our api-ms-win-security-base-l1-1-0** (4): AccessCheckByType, GetSecurityDescriptorRMControl, ImpersonateAnonymousToken, SetSecurityDescriptorRMControl
- **no api-set shell api-ms-win-core-processsnapshot-l1-1-0** (4): PssCaptureSnapshot, PssDuplicateSnapshot, PssFreeSnapshot, PssQuerySnapshot
- **no api-set shell ext-ms-win-gdi-dc-l1-2-0** (4): CreatePalette (delay), GetObjectType (delay), GetObjectW (delay), GetPaletteEntries (delay)
- **no api-set shell ext-ms-win-com-suspendresiliency-l1-1-0** (4): GetSuspendResiliencyState (delay), IsPackageSuspended (delay), RegisterForSuspendResiliencyNotificationWithState (delay), UsingDoNotDisturb (delay)
- **rmclient** (4): HamAddHostDependency (delay), HamConnectForExtendedExecution (delay), HamDisconnectForExtendedExecution (delay), HamPopulateActivityProperties (delay)
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateMutexExW, CreateSemaphoreExW, SetWaitableTimerEx
- **cfgmgr32** (3): CM_Locate_DevNodeW (delay), CM_MapCrToWin32Err (delay), CM_Open_DevNode_Key (delay)
- **no api-set shell ext-ms-win-ntuser-misc-l1-1-0** (3): GetClipboardFormatNameW (delay), MessageBeep (delay), RegisterClipboardFormatW (delay)
- **no api-set shell ext-ms-win-ntuser-windowstation-l1-1-0** (3): GetProcessWindowStation (delay), GetThreadDesktop (delay), GetUserObjectInformationW (delay)
- **no api-set shell ext-ms-win-appmodel-state-ext-l1-2-0** (3): CloseState (delay), GetStateRootFolderBase (delay), OpenStateExplicit (delay)
- **not in our api-ms-win-core-file-l1-1-0** (2): GetFinalPathNameByHandleW, SetFileInformationByHandle
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (2): GetSystemWow64Directory2W, Wow64SetThreadDefaultGuestMachine
- **no api-set shell api-ms-win-core-windowserrorreporting-l1-1-0** (2): WerRegisterMemoryBlock, WerUnregisterMemoryBlock
- **no api-set shell api-ms-win-core-quirks-l1-1-0** (2): QuirkIsEnabled, QuirkIsEnabledForProcess
- **no api-set shell api-ms-win-security-lsalookup-l1-1-0** (2): LookupAccountNameLocalW (delay), LookupAccountSidLocalW (delay)
- **no api-set shell ext-ms-win-ntuser-private-l1-1-0** (2): IsThreadMessageQueueAttached (delay), SetThreadInputBlocked (delay)
- **no api-set shell ext-ms-win-gdi-draw-l1-1-0** (2): CreateBitmap (delay), GetBitmapBits (delay)
- **no api-set shell ext-ms-win-com-clbcatq-l1-1-0** (2): GetCatalogObject (delay), GetCatalogObject2 (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-3** (2): ReleaseStgMedium (delay), SetWOWThunkGlobalPtr (delay)
- **no api-set shell ext-ms-win-advapi32-msi-l1-1-0** (2): CommandLineFromMsiDescriptor (delay), InstallApplication (delay)
- **no api-set shell ext-ms-win-kernel32-package-l1-1-2** (2): FormatApplicationUserModelId (delay), GetStagedPackageOrigin (delay)
- **no api-set shell ext-ms-win-kernel32-package-current-l1-1-0** (2): GetCurrentPackageId (delay), GetCurrentPackageInfo (delay)
- **no api-set shell ext-ms-win-advapi32-psm-app-l1-1-0** (2): PsmRegisterAppStateChangeNotification (delay), PsmUnregisterAppStateChangeNotification (delay)
- **no api-set shell ext-ms-win-com-apartmentrestriction-l1-1-0** (2): IsProcessRestrictedToSingleApartment (delay), OnInitializationOfSingleThreadedApartment (delay)
- **no api-set shell ext-ms-win-ro-typeresolution-l1-1-0** (2): RoGetMetaDataFile (delay), RoParseTypeName (delay)
- **no api-set shell api-ms-win-core-errorhandling-l1-1-2** (1): RaiseFailFastException
- **no api-set shell api-ms-win-core-synch-l1-2-1** (1): WaitForMultipleObjects
- **no api-set shell api-ms-win-security-base-l1-2-0** (1): GetAppContainerAce
- **no api-set shell api-ms-win-core-path-l1-1-0** (1): PathCchRemoveFileSpec
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **not in our api-ms-win-core-file-l2-1-0** (1): GetFileInformationByHandleEx
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **ws2_32** (1): #3 (delay)
- **no api-set shell api-ms-win-core-winrt-propertysetprivate-l1-1-1** (1): RoCreatePropertySetSerializer (delay)
- **no api-set shell ext-ms-win-rtcore-ntuser-synch-ext-l1-1-0** (1): MsgWaitForMultipleObjectsEx (delay)
- **no api-set shell ext-ms-win-rtcore-gdi-object-l1-1-0** (1): DeleteObject (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-1** (1): IsRoInitializeASTAAllowedInDesktop (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-5** (1): GetClassFile (delay)
- **no api-set shell ext-ms-win-com-coml2-l1-1-1** (1): Coml2DllGetClassObject (delay)
- **no api-set shell ext-ms-win-com-psmregister-l1-1-0** (1): PsmQueryBackgroundActivationType (delay)
- **no api-set shell ext-ms-win-session-usermgr-l1-1-0** (1): UMgrQueryUserToken (delay)
- **not in our api-ms-win-shcore-stream-l1-1-0** (1): SHCreateMemStream (delay)
- **no api-set shell api-ms-win-core-debug-minidump-l1-1-0** (1): MiniDumpWriteDump (delay)

## advapi32

- **ntdll** (121): EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWrite, EtwEventWriteTransfer, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, NtAlpcQueryInformation, NtCompareTokens, NtCreateKey, NtCreateMutant, NtCreatePrivateNamespace, NtDeleteKey, NtDuplicateToken, NtEnumerateKey, NtOpenKeyEx, NtOpenPrivateNamespace, NtOpenThreadToken, NtQueryInformationProcess, NtQueryInformationThread, NtQueryInformationToken, NtQueryKey, NtQueryMutant, NtQueryObject, NtQuerySecurityObject, NtQueryVolumeInformationFile, NtRenameKey, NtReplaceKey, NtSaveKey, NtSaveMergedKeys, NtSetInformationToken, NtSetSystemInformation, NtSetValueKey, NtTraceControl, NtWaitForMultipleObjects, RtlAbsoluteToSelfRelativeSD, RtlAddAccessAllowedAceEx, RtlAddAccessAllowedObjectAce, RtlAddAccessDeniedAceEx, RtlAddAccessDeniedObjectAce, RtlAddAuditAccessAceEx, RtlAddAuditAccessObjectAce, RtlAddSIDToBoundaryDescriptor, RtlAdjustPrivilege, RtlAllocateAndInitializeSid, RtlAllocateHandle, RtlAnsiCharToUnicodeChar, RtlAppendUnicodeStringToString, RtlAppendUnicodeToString, RtlConvertSidToUnicodeString, RtlCopyString, RtlCopyUnicodeString, RtlCreateBoundaryDescriptor, RtlCreateQueryDebugBuffer, RtlCreateUnicodeString, RtlCreateUnicodeStringFromAsciiz, RtlDeleteBoundaryDescriptor, RtlDeleteElementGenericTableAvl, RtlDestroyHandleTable, RtlDestroyQueryDebugBuffer, RtlDetermineDosPathNameType_U, RtlDllShutdownInProgress, RtlDosPathNameToRelativeNtPathName_U, RtlDuplicateUnicodeString, RtlEnumerateGenericTableAvl, RtlEqualSid, RtlFirstFreeAce, RtlFormatCurrentUserKeyPath, RtlFreeAnsiString, RtlFreeHandle, RtlGUIDFromString, RtlGetAce, RtlGetControlSecurityDescriptor, RtlGetCurrentTransaction, RtlGetDaclSecurityDescriptor, RtlGetFullPathName_U, RtlGetGroupSecurityDescriptor, RtlGetLastNtStatus, RtlGetNtProductType, RtlGetOwnerSecurityDescriptor, RtlGetSaclSecurityDescriptor, RtlGetThreadPreferredUILanguages, RtlImpersonateSelf, RtlInitUnicodeStringEx, RtlInitializeGenericTableAvl, RtlInitializeHandleTable, RtlInsertElementGenericTableAvl, RtlIntegerToUnicodeString, RtlIsGenericTableEmpty, RtlIsTextUnicode, RtlIsValidIndexHandle, RtlLookupElementGenericTableAvl, RtlMakeSelfRelativeSD, RtlNtStatusToDosErrorNoTeb, RtlNumberGenericTableElements, RtlOemStringToUnicodeString, RtlOpenCurrentUser, RtlQueryPackageIdentity, RtlQueryPerformanceCounter, RtlQueryProcessDebugInformation, RtlQueryRegistryValuesEx, RtlReleaseRelativeName, RtlRunOnceBeginInitialize, RtlRunOnceExecuteOnce, RtlSetLastWin32Error, RtlSetSaclSecurityDescriptor, RtlStringFromGUID, RtlSubAuthorityCountSid, RtlTimeToSecondsSince1970, RtlUnicodeStringToInteger, RtlUnicodeToMultiByteSize, RtlValidAcl, RtlValidRelativeSecurityDescriptor, RtlValidSid, RtlWaitOnAddress, RtlxAnsiStringToUnicodeSize, RtlxUnicodeStringToAnsiSize
- **cryptsp** (39): CryptAcquireContextA (delay), CryptAcquireContextW (delay), CryptContextAddRef (delay), CryptCreateHash (delay), CryptDecrypt (delay), CryptDeriveKey (delay), CryptDestroyHash (delay), CryptDestroyKey (delay), CryptDuplicateHash (delay), CryptDuplicateKey (delay), CryptEncrypt (delay), CryptEnumProviderTypesA (delay), CryptEnumProviderTypesW (delay), CryptEnumProvidersA (delay), CryptEnumProvidersW (delay), CryptExportKey (delay), CryptGenKey (delay), CryptGenRandom (delay), CryptGetDefaultProviderA (delay), CryptGetDefaultProviderW (delay), CryptGetHashParam (delay), CryptGetKeyParam (delay), CryptGetProvParam (delay), CryptGetUserKey (delay), CryptHashData (delay), CryptHashSessionKey (delay), CryptImportKey (delay), CryptReleaseContext (delay), CryptSetHashParam (delay), CryptSetKeyParam (delay), CryptSetProvParam (delay), CryptSetProviderA (delay), CryptSetProviderExA (delay), CryptSetProviderExW (delay), CryptSetProviderW (delay), CryptSignHashA (delay), CryptSignHashW (delay), CryptVerifySignatureA (delay), CryptVerifySignatureW (delay)
- **no api-set shell api-ms-win-security-credentials-l1-1-0** (29): CredDeleteA (delay), CredDeleteW (delay), CredEnumerateA (delay), CredEnumerateW (delay), CredFindBestCredentialA (delay), CredFindBestCredentialW (delay), CredFree (delay), CredGetSessionTypes (delay), CredGetTargetInfoA (delay), CredGetTargetInfoW (delay), CredIsMarshaledCredentialW (delay), CredIsProtectedA (delay), CredIsProtectedW (delay), CredMarshalCredentialA (delay), CredMarshalCredentialW (delay), CredProtectA (delay), CredProtectW (delay), CredReadA (delay), CredReadDomainCredentialsA (delay), CredReadDomainCredentialsW (delay), CredReadW (delay), CredUnmarshalCredentialA (delay), CredUnmarshalCredentialW (delay), CredUnprotectA (delay), CredUnprotectW (delay), CredWriteA (delay), CredWriteDomainCredentialsA (delay), CredWriteDomainCredentialsW (delay), CredWriteW (delay)
- **kernelbase** (25): CLOSE_LOCAL_HANDLE_INTERNAL, CreateProcessAsUserA, CreateProcessAsUserW, DisablePredefinedHandleTableInternal, GetStagedPackagePathByFullName, GetSystemDefaultUILanguage, GetUserDefaultUILanguage, LocalAlloc, LocalReAlloc, MapPredefinedHandleInternal, PackageIdFromFullName, RegCreateKeyExInternalA, RegCreateKeyExInternalW, RegDeleteKeyExInternalA, RegDeleteKeyExInternalW, RegKrnGetClassesEnumTableAddressInternal, RegKrnGetHKEY_ClassesRootAddress, RegKrnGetTermsrvRegistryExtensionFlags, RegOpenKeyExInternalA, RegOpenKeyExInternalW, RemapPredefinedHandleInternal, Sleep, lstrcmpW, lstrcmpiW, lstrlenW
- **not in our api-ms-win-security-base-l1-1-0** (24): AccessCheckByType, AccessCheckByTypeAndAuditAlarmW, AccessCheckByTypeResultList, AccessCheckByTypeResultListAndAuditAlarmByHandleW, AccessCheckByTypeResultListAndAuditAlarmW, AddAccessAllowedAceEx, AddAccessAllowedObjectAce, AddAccessDeniedAceEx, AddAccessDeniedObjectAce, AddAuditAccessAceEx, AddAuditAccessObjectAce, ConvertToAutoInheritPrivateObjectSecurity, CreatePrivateObjectSecurityEx, CreatePrivateObjectSecurityWithMultipleInheritance, EqualDomainSid, GetSecurityDescriptorRMControl, GetWindowsAccountDomainSid, ImpersonateAnonymousToken, IsTokenRestricted, QuerySecurityAccessMask, SetPrivateObjectSecurityEx, SetSecurityAccessMask, SetSecurityDescriptorControl, SetSecurityDescriptorRMControl
- **msvcrt** (17): __CxxFrameHandler3, _except_handler4_common, _ftol2, _i64tow_s, _resetstkoflw, _ui64tow_s, _ultow_s, _wcstoi64, _wcstoui64, memcpy_s, swprintf_s, swscanf_s, wcscat_s, wcscpy_s, wcsncpy_s, wcsnlen, wcstok_s
- **not in our api-ms-win-core-registry-l1-1-0** (14): RegCopyTreeW, RegDeleteKeyExA, RegDeleteKeyExW, RegDeleteTreeA, RegDeleteTreeW, RegDisablePredefinedCacheEx, RegGetValueA, RegGetValueW, RegLoadAppKeyA, RegLoadAppKeyW, RegLoadMUIStringA, RegLoadMUIStringW, RegSaveKeyExA, RegSaveKeyExW
- **kernel32** (13): CancelThreadpoolIo, CloseThreadpoolIo, CreateThreadpoolIo, FreeLibraryWhenCallbackReturns, GetFileMUIPath, GetThreadUILanguage, ResolveDelayLoadedAPI, SetFileInformationByHandle, StartThreadpoolIo, TermsrvDeleteKey, TermsrvOpenUserClasses, Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection
- **no api-set shell api-ms-win-security-credentials-l2-1-0** (13): CredBackupCredentials (delay), CredEncryptAndMarshalBinaryBlob (delay), CredProfileLoaded (delay), CredProfileLoadedEx (delay), CredProfileUnloaded (delay), CredReadByTokenHandle (delay), CredRestoreCredentials (delay), CredpConvertCredential (delay), CredpConvertOneCredentialSize (delay), CredpConvertTargetInfo (delay), CredpDecodeCredential (delay), CredpEncodeCredential (delay), CredpEncodeSecret (delay)
- **no api-set shell api-ms-win-security-audit-l1-1-1** (11): AuditEnumerateCategories, AuditEnumeratePerUserPolicy, AuditEnumerateSubCategories, AuditLookupCategoryNameW, AuditLookupSubCategoryNameW, AuditQueryGlobalSaclW, AuditQueryPerUserPolicy, AuditQuerySecurity, AuditSetGlobalSaclW, AuditSetPerUserPolicy, AuditSetSecurity
- **no api-set shell api-ms-win-eventing-controller-l1-1-0** (10): ControlTraceW, EnableTraceEx2, EnumerateTraceGuidsEx, EventAccessControl, EventAccessQuery, EventAccessRemove, QueryAllTracesW, StartTraceW, StopTraceW, TraceSetInformation
- **no api-set shell api-ms-win-core-pcw-l1-1-0** (9): PcwAddQueryItem, PcwCollectData, PcwCreateNotifier, PcwCreateQuery, PcwEnumerateInstances, PcwRemoveQueryItem, PcwSendNotification, PcwSendStatelessNotification, PcwSetQueryItemUserData
- **wintrust** (7): CryptCATAdminAcquireContext (delay), CryptCATAdminCalcHashFromFileHandle (delay), CryptCATAdminEnumCatalogFromHash (delay), CryptCATAdminReleaseCatalogContext (delay), CryptCATAdminReleaseContext (delay), CryptCATCatalogInfoFromContext (delay), WTHelperIsChainedToMicrosoftFromStateData (delay)
- **rpcrt4** (6): I_RpcExceptionFilter, I_RpcSNCHOption, NdrClientCall4, RpcBindingBind, RpcBindingCreateW, RpcExceptionFilter
- **no api-set shell api-ms-win-service-private-l1-1-0** (5): I_ScRpcBindA, I_ScRpcBindW, I_ScSetServiceBitsA, I_ScSetServiceBitsW, WaitServiceState
- **cryptbase** (5): SystemFunction002 (delay), SystemFunction004 (delay), SystemFunction005 (delay), SystemFunction028 (delay), SystemFunction040 (delay)
- **not in our api-ms-win-service-winsvc-l1-1-0** (4): ControlServiceExA, NotifyServiceStatusChangeA, QueryServiceConfig2A, RegisterServiceCtrlHandlerExA
- **no api-set shell api-ms-win-core-registry-l1-1-1** (4): RegDeleteKeyValueA, RegDeleteKeyValueW, RegSetKeyValueA, RegSetKeyValueW
- **no api-set shell api-ms-win-security-audit-l1-1-0** (4): AuditComputeEffectivePolicyBySid, AuditFree, AuditQuerySystemPolicy, AuditSetSystemPolicy
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (4): EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **no api-set shell api-ms-win-security-lsalookup-l1-1-0** (4): LookupAccountNameLocalA (delay), LookupAccountNameLocalW (delay), LookupAccountSidLocalA (delay), LookupAccountSidLocalW (delay)
- **no api-set shell api-ms-win-eventing-consumer-l1-1-0** (3): CloseTrace, OpenTraceW, ProcessTrace
- **no api-set shell api-ms-win-service-private-l1-1-2** (3): I_ScReparseServiceDatabase, QueryLocalUserServiceName, QueryUserServiceName
- **sspicli** (3): GetUserNameExA (delay), GetUserNameExW (delay), LogonUserExExW (delay)
- **no api-set shell api-ms-win-service-core-l1-1-2** (2): GetServiceDisplayNameW, GetServiceKeyNameW
- **not in our api-ms-win-service-management-l2-1-0** (2): NotifyServiceStatusChangeW, QueryServiceConfig2W
- **no api-set shell api-ms-win-core-registry-l1-1-2** (2): RegQueryMultipleValuesA, RegQueryMultipleValuesW
- **not in our api-ms-win-core-timezone-l1-1-0** (2): EnumDynamicTimeZoneInformation, GetDynamicTimeZoneInformationEffectiveYears
- **no api-set shell api-ms-win-devices-config-l1-1-1** (2): CM_Get_DevNode_Registry_PropertyW (delay), CM_Locate_DevNodeW (delay)
- **no api-set shell api-ms-win-eventing-consumer-l1-1-1** (1): QueryTraceProcessingHandle
- **not in our api-ms-win-service-core-l1-1-0** (1): RegisterServiceCtrlHandlerExW
- **not in our api-ms-win-service-core-l1-1-1** (1): QueryServiceDynamicInformation
- **not in our api-ms-win-service-management-l1-1-0** (1): ControlServiceExW
- **no api-set shell api-ms-win-service-private-l1-1-4** (1): CreateServiceEx
- **no api-set shell api-ms-win-service-private-l1-1-3** (1): QueryUserServiceNameForContext
- **not in our api-ms-win-core-namedpipe-l1-1-0** (1): ImpersonateNamedPipeClient
- **no api-set shell api-ms-win-security-base-private-l1-1-0** (1): MakeAbsoluteSD2
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence

## shell32

- **dui70** (427): ??0AccessibleButton@DirectUI@@QAE@XZ (delay), ??0Button@DirectUI@@QAE@XZ (delay), ??0ClassInfoBase@DirectUI@@QAE@XZ (delay), ??0CritSecLock@DirectUI@@QAE@PAU_RTL_CRITICAL_SECTION@@@Z (delay), ??0DCSurface@DirectUI@@QAE@PAUHDC__@@@Z (delay), ??0Element@DirectUI@@QAE@XZ (delay), ??0ElementWithHWND@DirectUI@@QAE@XZ (delay), ??0HWNDElement@DirectUI@@QAE@XZ (delay), ??0HWNDHost@DirectUI@@QAE@XZ (delay), ??0Layout@DirectUI@@QAE@XZ (delay), ??0NativeHWNDHost@DirectUI@@QAE@XZ (delay), ??1AccessibleButton@DirectUI@@UAE@XZ (delay), ??1Button@DirectUI@@UAE@XZ (delay), ??1ClassInfoBase@DirectUI@@UAE@XZ (delay), ??1CritSecLock@DirectUI@@QAE@XZ (delay), ??1DCSurface@DirectUI@@UAE@XZ (delay), ??1Element@DirectUI@@UAE@XZ (delay), ??1ElementWithHWND@DirectUI@@UAE@XZ (delay), ??1HWNDElement@DirectUI@@UAE@XZ (delay), ??1HWNDHost@DirectUI@@UAE@XZ (delay), ??1Layout@DirectUI@@UAE@XZ (delay), ??1NativeHWNDHost@DirectUI@@UAE@XZ (delay), ?AccDescProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?AccNameProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?ActivateTooltip@Element@DirectUI@@MAEXPAV12@K@Z (delay), ?ActivateTooltip@HWNDElement@DirectUI@@UAEXPAVElement@2@K@Z (delay), ?Add@Element@DirectUI@@QAEJPAV12@@Z (delay), ?Add@Element@DirectUI@@UAEJPAPAV12@I@Z (delay), ?AddBehavior@Element@DirectUI@@UAEJPAUIDuiBehavior@@@Z (delay), ?AddChild@ClassInfoBase@DirectUI@@UAEXXZ (delay), ?AddListener@Element@DirectUI@@QAEJPAUIElementListener@2@@Z (delay), ?AddRef@ClassInfoBase@DirectUI@@UAEXXZ (delay), ?AddRef@Element@DirectUI@@QAGKXZ (delay), ?AddRef@Value@DirectUI@@QAEXXZ (delay), ?AnimationChange@Element@DirectUI@@SG?AVUID@@XZ (delay), ?AssertPIZeroRef@ClassInfoBase@DirectUI@@UBEXXZ (delay), ?Attach@Layout@DirectUI@@UAEXPAVElement@2@@Z (delay), ?BackgroundProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?BroadcastEvent@Element@DirectUI@@QAEXPAUEvent@2@@Z (delay), ?CanSetFocus@HWNDElement@DirectUI@@UAE_NXZ (delay), ?ClassExist@ClassInfoBase@DirectUI@@SG_NPAPAUIClassInfo@2@PBQBUPropertyInfo@2@IPAU32@PAUHINSTANCE__@@PBG_N@Z (delay), ?ClassProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?ClearCacheDirty@Layout@DirectUI@@IAEXXZ (delay), ?Click@Button@DirectUI@@SG?AVUID@@XZ (delay), ?Click@TouchButton@DirectUI@@SG?AVUID@@XZ (delay), ?ContentAlignProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?ContentProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?Context@Button@DirectUI@@SG?AVUID@@XZ (delay), ?Create@BorderLayout@DirectUI@@SGJHPAHPAPAVValue@2@@Z (delay), ?Create@BorderLayout@DirectUI@@SGJPAPAVLayout@2@@Z (delay), ?Create@DUIXmlParser@DirectUI@@SGJPAPAV12@P6GPAVValue@2@PBGPAX@Z2P6GX11H2@Z2@Z (delay), ?Create@Element@DirectUI@@SGJIPAV12@PAKPAPAV12@@Z (delay), ?Create@FillLayout@DirectUI@@SGJPAPAVLayout@2@@Z (delay), ?Create@FlowLayout@DirectUI@@SGJ_NIIIPAPAVLayout@2@@Z (delay), ?Create@HWNDHostAccessible@DirectUI@@SGJPAVElement@2@PAUIAccessible@@PAPAVDuiAccessible@2@@Z (delay), ?Create@HWNDHostClientAccessible@DirectUI@@SGJPAVElement@2@PAUIAccessible@@PAPAVDuiAccessible@2@@Z (delay), ?Create@RichText@DirectUI@@SGJPAVElement@2@PAKPAPAV32@@Z (delay), ?Create@ShellBorderLayout@DirectUI@@SGJPAPAVLayout@2@@Z (delay), ?Create@VerticalFlowLayout@DirectUI@@SGJ_NIIIPAPAVLayout@2@@Z (delay), ?Create@XElement@DirectUI@@SGJPAVElement@2@PAKPAPAV32@@Z (delay), ?CreateBool@Value@DirectUI@@SGPAV12@_N@Z (delay), ?CreateDTBFill@Value@DirectUI@@SGPAV12@PBGHH@Z (delay), ?CreateElement@DUIXmlParser@DirectUI@@QAEJPBGPAVElement@2@1PAKPAPAV32@@Z (delay), ?CreateGraphic@Value@DirectUI@@SGPAV12@PAUHBITMAP__@@EI_N11@Z (delay), ?CreateGraphic@Value@DirectUI@@SGPAV12@PAUHICON__@@_N11@Z (delay), ?CreateHostWindow@NativeHWNDHost@DirectUI@@UAEPAUHWND__@@KPBG0KHHHHPAU3@PAUHMENU__@@PAUHINSTANCE__@@PAX@Z (delay), ?CreateInstance@CSafeElementProxy@@SGJPAVElement@DirectUI@@PAPAV1@@Z (delay), ?CreateInt@Value@DirectUI@@SGPAV12@HW4DynamicScaleValue@@@Z (delay), ?CreateRect@Value@DirectUI@@SGPAV12@HHHHW4DynamicScaleValue@@@Z (delay), ?CreateString@Value@DirectUI@@SGPAV12@PBGPAUHINSTANCE__@@@Z (delay), ?CreateStyleParser@HWNDElement@DirectUI@@UAEJPAPAVDUIXmlParser@2@@Z (delay), ?DefaultAction@Button@DirectUI@@UAEJXZ (delay), ?DefaultAction@Element@DirectUI@@UAEJXZ (delay), ?DesiredSizeProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?Destroy@DUIXmlParser@DirectUI@@QAEXXZ (delay), ?Destroy@Element@DirectUI@@QAEJ_N@Z (delay), ?Destroy@Layout@DirectUI@@QAEXXZ (delay), ?DestroyAll@Element@DirectUI@@QAEJ_N@Z (delay), ?Detach@CSafeElementProxy@@QAEXXZ (delay), ?Detach@HWNDHost@DirectUI@@QAEXXZ (delay), ?Detach@Layout@DirectUI@@UAEXPAVElement@2@@Z (delay), ?DirectionProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?EndDefer@Element@DirectUI@@QAEXK@Z (delay), ?EnsureVisible@Element@DirectUI@@QAE_NXZ (delay), ?EnsureVisible@Element@DirectUI@@UAE_NHHHH@Z (delay), ?EnumPropertyInfo@ClassInfoBase@DirectUI@@UAEPBUPropertyInfo@2@I@Z (delay), ?EraseBkgnd@HWNDHost@DirectUI@@MAE_NPAUHDC__@@PAJ@Z (delay), ?ExtentProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?FindDescendent@Element@DirectUI@@QAEPAV12@G@Z (delay), ?FindShortcut@HWNDElement@DirectUI@@SG_NGPAVElement@2@PAPAV32@PAH2H@Z (delay), ?FireEvent@Element@DirectUI@@QAEXPAUEvent@2@_N1@Z (delay), ?FontFaceProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?FontQualityProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?FontSizeProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?FontStyleProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?FontWeightProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?ForegroundProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?GetAccName@Element@DirectUI@@QAEPBGPAPAVValue@2@@Z (delay), ?GetAccRole@Element@DirectUI@@QAEHXZ (delay), ?GetAccState@Element@DirectUI@@QAEHXZ (delay), ?GetAccessible@Element@DirectUI@@QAE_NXZ (delay), ?GetAccessibleImpl@Element@DirectUI@@UAEJPAPAUIAccessible@@@Z (delay), ?GetAccessibleImpl@HWNDElement@DirectUI@@UAEJPAPAUIAccessible@@@Z (delay), ?GetAccessibleImpl@HWNDHost@DirectUI@@UAEJPAPAUIAccessible@@@Z (delay), ?GetActive@Element@DirectUI@@QAEHXZ (delay), ?GetAdjacent@Element@DirectUI@@UAEPAV12@PAV12@HPBUNavReference@2@K@Z (delay), ?GetAdjacent@Layout@DirectUI@@UAEPAVElement@2@PAV32@0HPBUNavReference@2@K@Z (delay), ?GetAtom@Value@DirectUI@@QAEGXZ (delay), ?GetAtomZero@Value@DirectUI@@SGPAV12@XZ (delay), ?GetBackgroundStdColor@Element@DirectUI@@QAEHXZ (delay), ?GetBool@Value@DirectUI@@QAE_NXZ (delay), ?GetBoolFalse@Value@DirectUI@@SGPAV12@XZ (delay), ?GetBoolTrue@Value@DirectUI@@SGPAV12@XZ (delay), ?GetBorderThickness@Element@DirectUI@@QAEPBUtagRECT@@PAPAVValue@2@@Z (delay), ?GetByClassIndex@ClassInfoBase@DirectUI@@UAEPBUPropertyInfo@2@I@Z (delay), ?GetChildFromLayoutIndex@Layout@DirectUI@@QAEPAVElement@2@PAV32@HPAV?$DynamicArray@PAVElement@DirectUI@@$0A@@2@@Z (delay), ?GetChildren@ClassInfoBase@DirectUI@@UBEHXZ (delay), ?GetChildren@Element@DirectUI@@QAEPAV?$DynamicArray@PAVElement@DirectUI@@$0A@@2@PAPAVValue@2@@Z (delay), ?GetClassInfoPtr@AccessibleButton@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@Button@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@CCBaseCheckRadioButton@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@CCPushButton@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@CCSysLink@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@Element@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@ElementWithHWND@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@ExpandoButtonGlyph@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@HWNDElement@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@HWNDHost@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@ScrollViewer@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@Selector@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoPtr@XElement@DirectUI@@SGPAUIClassInfo@2@XZ (delay), ?GetClassInfoW@Button@DirectUI@@UAEPAUIClassInfo@2@XZ (delay), ?GetClassInfoW@HWNDElement@DirectUI@@UAEPAUIClassInfo@2@XZ (delay), ?GetColorize@Element@DirectUI@@QAEHXZ (delay), ?GetContentAlign@Element@DirectUI@@QAEHXZ (delay), ?GetContentSize@Element@DirectUI@@UAE?AUtagSIZE@@HHPAVSurface@2@@Z (delay), ?GetContentString@Element@DirectUI@@QAEPBGPAPAVValue@2@@Z (delay), ?GetContentStringAsDisplayed@Element@DirectUI@@UAEPBGPAPAVValue@2@@Z (delay), ?GetDPI@Element@DirectUI@@QAEHXZ (delay), ?GetDeferObject@Element@DirectUI@@QAEPAVDeferCycle@2@XZ (delay), ?GetDesiredSize@Element@DirectUI@@QAEPBUtagSIZE@@XZ (delay), ?GetDisplayNode@Element@DirectUI@@QAEPAUHGADGET__@@XZ (delay), ?GetElementProviderImpl@Element@DirectUI@@UAEJPAVInvokeHelper@2@PAPAVElementProvider@2@@Z (delay), ?GetElementScaleFactor@Element@DirectUI@@QAEMXZ (delay), ?GetEnabled@Element@DirectUI@@QAE_NXZ (delay), ?GetExtent@Element@DirectUI@@QAEPBUtagSIZE@@PAPAVValue@2@@Z (delay), ?GetFactoryLock@Element@DirectUI@@SGPAU_RTL_CRITICAL_SECTION@@XZ (delay), ?GetFill@Value@DirectUI@@QAEPBUFill@2@XZ (delay), ?GetFontFace@Element@DirectUI@@QAEPBGPAPAVValue@2@@Z (delay), ?GetFontQuality@Element@DirectUI@@QAEHXZ (delay), ?GetFontSize@Element@DirectUI@@QAEHXZ (delay), ?GetFontStyle@Element@DirectUI@@QAEHXZ (delay), ?GetFontWeight@Element@DirectUI@@QAEHXZ (delay), ?GetForegroundStdColor@Element@DirectUI@@QAEHXZ (delay), ?GetGlobalIndex@ClassInfoBase@DirectUI@@UBEIXZ (delay), ?GetHDC@DCSurface@DirectUI@@QAEPAUHDC__@@XZ (delay), ?GetHWND@HWNDElement@DirectUI@@UAEPAUHWND__@@XZ (delay), ?GetHWND@HWNDHost@DirectUI@@UAEPAUHWND__@@XZ (delay), ?GetHWND@NativeHWNDHost@DirectUI@@QAEPAUHWND__@@XZ (delay), ?GetHeight@Element@DirectUI@@QAEHXZ (delay), ?GetID@Element@DirectUI@@QAEGXZ (delay), ?GetImmediateChild@Element@DirectUI@@QAEPAV12@PAV12@@Z (delay), ?GetImmersiveFocusRectOffsets@Element@DirectUI@@UAEXPAUtagRECT@@@Z (delay), ?GetIndex@Element@DirectUI@@QAEHXZ (delay), ?GetInnerHWND@XElement@DirectUI@@QAEPAUHWND__@@XZ (delay), ?GetInt@Value@DirectUI@@QAEHXZ (delay), ?GetIntZero@Value@DirectUI@@SGPAV12@XZ (delay), ?GetKeyFocused@Element@DirectUI@@UAE_NXZ (delay), ?GetKeyFocused@HWNDHost@DirectUI@@UAE_NXZ (delay), ?GetKeyFocusedElement@HWNDElement@DirectUI@@SGPAVElement@2@XZ (delay), ?GetKeyWithin@Element@DirectUI@@QAE_NXZ (delay), ?GetKeyWithinChild@Element@DirectUI@@QAEPAV12@XZ (delay), ?GetLayout@Element@DirectUI@@QAEPAVLayout@2@PAPAVValue@2@@Z (delay), ?GetLayoutChildCount@Layout@DirectUI@@QAEIPAVElement@2@@Z (delay), ?GetLayoutIndexFromChild@Layout@DirectUI@@QAEHPAVElement@2@0@Z (delay), ?GetLayoutPos@Element@DirectUI@@QAEHXZ (delay), ?GetLocation@Element@DirectUI@@QAEPBUtagPOINT@@PAPAVValue@2@@Z (delay), ?GetMargin@Element@DirectUI@@QAEPBUtagRECT@@PAPAVValue@2@@Z (delay), ?GetMinSize@Element@DirectUI@@QAEPBUtagSIZE@@PAPAVValue@2@@Z (delay), ?GetModule@ClassInfoBase@DirectUI@@UBEPAUHINSTANCE__@@XZ (delay), ?GetMouseFocused@Element@DirectUI@@QAE_NXZ (delay), ?GetName@ClassInfoBase@DirectUI@@UBEPBGXZ (delay), ?GetOverhang@Element@DirectUI@@QAE_NXZ (delay), ?GetPICount@ClassInfoBase@DirectUI@@UBEIXZ (delay), ?GetPadding@Element@DirectUI@@QAEPBUtagRECT@@PAPAVValue@2@@Z (delay), ?GetParent@Element@DirectUI@@QAEPAV12@XZ (delay), ?GetPressed@Button@DirectUI@@QAE_NXZ (delay), ?GetRect@Value@DirectUI@@QAEPBUtagRECT@@XZ (delay), ?GetRoot@Element@DirectUI@@QAEPAV12@XZ (delay), ?GetRootRelativeBounds@Element@DirectUI@@QAEJPAUtagRECT@@@Z (delay), ?GetSelected@Element@DirectUI@@QAE_NXZ (delay), ?GetSelection@Selector@DirectUI@@QAEPAVElement@2@XZ (delay), ?GetSheet@DUIXmlParser@DirectUI@@QAEJPBGPAPAVValue@2@@Z (delay), ?GetShortcut@Element@DirectUI@@QAEHXZ (delay), ?GetSize@Value@DirectUI@@QAEPBUtagSIZE@@XZ (delay), ?GetString@Value@DirectUI@@QAEPBGXZ (delay), ?GetStringNull@Value@DirectUI@@SGPAV12@XZ (delay), ?GetTopLevel@Element@DirectUI@@QAEPAV12@XZ (delay), ?GetType@Value@DirectUI@@QBEHXZ (delay), ?GetUIAElementProvider@Element@DirectUI@@UAEJABU_GUID@@PAPAX@Z (delay), ?GetUiaFocusDelegate@Element@DirectUI@@UAEPAV12@XZ (delay), ?GetUnset@Value@DirectUI@@SGPAV12@XZ (delay), ?GetValue@Element@DirectUI@@QAEPAVValue@2@P6GPBUPropertyInfo@2@XZHPAUUpdateCache@2@@Z (delay), ?GetValue@Element@DirectUI@@QAEPAVValue@2@PBUPropertyInfo@2@HPAUUpdateCache@2@@Z (delay), ?GetVisible@Element@DirectUI@@QAE_NXZ (delay), ?GetWidth@Element@DirectUI@@QAEHXZ (delay), ?GetWindowClassNameAndStyle@HWNDElement@DirectUI@@UAEXPAPBGPAI@Z (delay), ?GetYOffset@BaseScrollViewer@DirectUI@@QAEHXZ (delay), ?HandleUiaDestroyListener@Element@DirectUI@@UAEXXZ (delay), ?HandleUiaEventListener@Element@DirectUI@@UAEXPAUEvent@2@@Z (delay), ?HandleUiaPropertyChangingListener@Element@DirectUI@@UAEXPBUPropertyInfo@2@@Z (delay), ?HandleUiaPropertyListener@Element@DirectUI@@UAEXPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?HasBorder@Element@DirectUI@@QAE_NXZ (delay), ?HasChildren@Element@DirectUI@@QAE_NXZ (delay), ?HasContent@Element@DirectUI@@QAE_NXZ (delay), ?HasPadding@Element@DirectUI@@QAE_NXZ (delay), ?HeightProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?Host@NativeHWNDHost@DirectUI@@QAEXPAVElement@2@@Z (delay), ?ImmersiveColorSchemeChange@HWNDElement@DirectUI@@SG?AVUID@@XZ (delay), ?Init@NavReference@DirectUI@@QAEXPAVElement@2@PAUtagRECT@@@Z (delay), ?Init@NavScoring@DirectUI@@QAEXPAVElement@2@HPBUNavReference@2@@Z (delay), ?Initialize@AccessibleButton@DirectUI@@QAEJPAVElement@2@PAK@Z (delay), ?Initialize@Button@DirectUI@@QAEJIPAVElement@2@PAK@Z (delay), ?Initialize@ClassInfoBase@DirectUI@@QAEJPAUHINSTANCE__@@PBG_NPBQBUPropertyInfo@2@I@Z (delay), ?Initialize@Element@DirectUI@@QAEJIPAV12@PAK@Z (delay), ?Initialize@HWNDElement@DirectUI@@QAEJPAUHWND__@@_NIPAVElement@2@PAK@Z (delay), ?Initialize@HWNDHost@DirectUI@@QAEJIIPAVElement@2@PAK@Z (delay), ?Initialize@Layout@DirectUI@@QAEXXZ (delay), ?Initialize@NativeHWNDHost@DirectUI@@QAEJPBG0PAUHWND__@@PAUHICON__@@HHHHHHPAUHINSTANCE__@@I@Z (delay), ?Insert@Element@DirectUI@@QAEJPAV12@I@Z (delay), ?Insert@Element@DirectUI@@UAEJPAPAV12@II@Z (delay), ?IsCacheDirty@Layout@DirectUI@@IAE_NXZ (delay), ?IsContentProtected@Element@DirectUI@@UAE_NXZ (delay), ?IsDescendent@Element@DirectUI@@QAE_NPAV12@@Z (delay), ?IsDestroyed@Element@DirectUI@@QAE_NXZ (delay), ?IsEqual@Value@DirectUI@@QAE_NPAV12@@Z (delay), ?IsGlobal@ClassInfoBase@DirectUI@@UBE_NXZ (delay), ?IsMSAAEnabled@HWNDElement@DirectUI@@UAE_NXZ (delay), ?IsRTL@Element@DirectUI@@QAE_NXZ (delay), ?IsRTLReading@Element@DirectUI@@UAE_NXZ (delay), ?IsSubclassOf@ClassInfoBase@DirectUI@@UBE_NPAUIClassInfo@2@@Z (delay), ?IsValidProperty@ClassInfoBase@DirectUI@@UBE_NPBUPropertyInfo@2@@Z (delay), ?KeyFocusedProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?KeyWithinProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?KeyboardNavigate@Element@DirectUI@@SG?AVUID@@XZ (delay), ?LayoutPosProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?LayoutProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?LoadFromResource@Movie@DirectUI@@QAEJPAUHINSTANCE__@@H@Z (delay), ?MarkSelfLayout@Element@DirectUI@@IAEXXZ (delay), ?MessageCallback@Element@DirectUI@@UAEIPAUtagGMSG@@@Z (delay), ?MessageCallback@HWNDHost@DirectUI@@UAEIPAUtagGMSG@@@Z (delay), ?MouseFocusedProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?MouseWithinProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?OnAdd@Layout@DirectUI@@UAEXPAVElement@2@PAPAV32@I@Z (delay), ?OnAdjustWindowSize@HWNDHost@DirectUI@@UAEHHHI@Z (delay), ?OnCompositionChanged@HWNDElement@DirectUI@@UAEXXZ (delay), ?OnCtrlThemeChanged@HWNDHost@DirectUI@@UAE_NIIJPAJ@Z (delay), ?OnDestroy@Element@DirectUI@@UAEXXZ (delay), ?OnDestroy@HWNDElement@DirectUI@@UAEXXZ (delay), ?OnDestroy@HWNDHost@DirectUI@@UAEXXZ (delay), ?OnEvent@Element@DirectUI@@UAEXPAUEvent@2@@Z (delay), ?OnEvent@HWNDElement@DirectUI@@UAEXPAUEvent@2@@Z (delay), ?OnEvent@HWNDHost@DirectUI@@UAEXPAUEvent@2@@Z (delay), ?OnGetDlgCode@HWNDElement@DirectUI@@UAEXPAUtagMSG@@PAJ@Z (delay), ?OnGroupChanged@Element@DirectUI@@UAEXH_N@Z (delay), ?OnGroupChanged@HWNDElement@DirectUI@@UAEXH_N@Z (delay), ?OnHosted@Element@DirectUI@@MAEXPAV12@@Z (delay), ?OnHosted@HWNDHost@DirectUI@@MAEXPAVElement@2@@Z (delay), ?OnImmersiveColorSchemeChanged@HWNDElement@DirectUI@@UAEXXZ (delay), ?OnInput@Button@DirectUI@@UAEXPAUInputEvent@2@@Z (delay), ?OnInput@Element@DirectUI@@UAEXPAUInputEvent@2@@Z (delay), ?OnInput@HWNDElement@DirectUI@@UAEXPAUInputEvent@2@@Z (delay), ?OnInput@HWNDHost@DirectUI@@UAEXPAUInputEvent@2@@Z (delay), ?OnKeyFocusMoved@Element@DirectUI@@UAEXPAV12@0@Z (delay), ?OnLayoutPosChanged@Layout@DirectUI@@UAEXPAVElement@2@0HH@Z (delay), ?OnLostDialogFocus@Button@DirectUI@@UAE_NPAUIDialogElement@2@@Z (delay), ?OnMessage@HWNDHost@DirectUI@@UAE_NIIJPAJ@Z (delay), ?OnMouseFocusMoved@Element@DirectUI@@UAEXPAV12@0@Z (delay), ?OnNoChildWithShortcutFound@HWNDElement@DirectUI@@UAEXPAUKeyboardEvent@2@@Z (delay), ?OnNotify@HWNDHost@DirectUI@@UAE_NIIJPAJ@Z (delay), ?OnPropertyChanged@AccessibleButton@DirectUI@@UAEXPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanged@Button@DirectUI@@UAEXPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanged@Element@DirectUI@@UAEXPAUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanged@Element@DirectUI@@UAEXPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanged@HWNDElement@DirectUI@@UAEXPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanged@HWNDHost@DirectUI@@UAEXPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanging@Element@DirectUI@@UAE_NPAUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnPropertyChanging@Element@DirectUI@@UAE_NPBUPropertyInfo@2@HPAVValue@2@1@Z (delay), ?OnReceivedDialogFocus@Button@DirectUI@@UAE_NPAUIDialogElement@2@@Z (delay), ?OnRemove@Layout@DirectUI@@UAEXPAVElement@2@PAPAV32@I@Z (delay), ?OnSinkThemeChanged@HWNDHost@DirectUI@@UAE_NIIJPAJ@Z (delay), ?OnSysChar@HWNDHost@DirectUI@@UAE_NG@Z (delay), ?OnThemeChanged@HWNDElement@DirectUI@@UAEXPAUThemeChangedEvent@2@@Z (delay), ?OnUnHosted@Element@DirectUI@@MAEXPAV12@@Z (delay), ?OnUnHosted@HWNDHost@DirectUI@@MAEXPAVElement@2@@Z (delay), ?OnWindowStyleChanged@HWNDHost@DirectUI@@UAEXIPBUtagSTYLESTRUCT@@@Z (delay), ?OnWmSettingChanged@HWNDElement@DirectUI@@UAEXIJ@Z (delay), ?OnWmThemeChanged@HWNDElement@DirectUI@@UAEXIJ@Z (delay), ?PaddingProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?Paint@Element@DirectUI@@UAEXPAUHDC__@@PBUtagRECT@@1PAU4@2@Z (delay), ?Paint@HWNDHost@DirectUI@@UAEXPAUHDC__@@PBUtagRECT@@1PAU4@2@Z (delay), ?Pause@Movie@DirectUI@@QAEXXZ (delay), ?Play@Movie@DirectUI@@QAEXXZ (delay), ?PressedProp@Button@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?QueryInterface@Element@DirectUI@@UAGJABU_GUID@@PAPAX@Z (delay), ?Register@AccessibleButton@DirectUI@@SGJXZ (delay), ?Register@Button@DirectUI@@SGJXZ (delay), ?Register@ClassInfoBase@DirectUI@@QAEJXZ (delay), ?Register@Element@DirectUI@@SGJXZ (delay), ?Register@ElementWithHWND@DirectUI@@SGJXZ (delay), ?Register@HWNDElement@DirectUI@@SGJXZ (delay), ?Register@HWNDHost@DirectUI@@SGJXZ (delay), ?Register@Movie@DirectUI@@SGJXZ (delay), ?Release@ClassInfoBase@DirectUI@@UAEHXZ (delay), ?Release@Element@DirectUI@@QAGKXZ (delay), ?Release@Value@DirectUI@@QAEXXZ (delay), ?Remove@Element@DirectUI@@QAEJPAV12@@Z (delay), ?Remove@Element@DirectUI@@UAEJPAPAV12@I@Z (delay), ?RemoveAll@Element@DirectUI@@QAEJXZ (delay), ?RemoveBehavior@Element@DirectUI@@UAEJPAUIDuiBehavior@@@Z (delay), ?RemoveChild@ClassInfoBase@DirectUI@@UAEXXZ (delay), ?RemoveListener@Element@DirectUI@@QAEXPAUIElementListener@2@@Z (delay), ?RemoveLocalValue@Element@DirectUI@@QAEJP6GPBUPropertyInfo@2@XZ@Z (delay), ?RemoveLocalValue@Element@DirectUI@@QAEJPBUPropertyInfo@2@@Z (delay), ?RemoveTooltip@Element@DirectUI@@MAEXPAV12@@Z (delay), ?RemoveTooltip@HWNDElement@DirectUI@@UAEXPAVElement@2@@Z (delay), ?Resume@Movie@DirectUI@@QAEXXZ (delay), ?ScaleFactorProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?Scroll@BaseScrollBar@DirectUI@@SG?AVUID@@XZ (delay), ?SelectedProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?SelectionChange@Selector@DirectUI@@SG?AVUID@@XZ (delay), ?SetAbsorbsShortcut@Element@DirectUI@@QAEJ_N@Z (delay), ?SetAccDesc@Element@DirectUI@@QAEJPBG@Z (delay), ?SetAccName@Element@DirectUI@@QAEJPBG@Z (delay), ?SetAccRole@Element@DirectUI@@QAEJH@Z (delay), ?SetAccState@Element@DirectUI@@QAEJH@Z (delay), ?SetAccValue@Element@DirectUI@@QAEJPBG@Z (delay), ?SetAccessible@Element@DirectUI@@QAEJ_N@Z (delay), ?SetActive@Element@DirectUI@@QAEJH@Z (delay), ?SetAlpha@Element@DirectUI@@QAEJH@Z (delay), ?SetAnimation@Element@DirectUI@@QAEJH@Z (delay), ?SetBackgroundColor@Element@DirectUI@@QAEJK@Z (delay), ?SetBackgroundStdColor@Element@DirectUI@@QAEJH@Z (delay), ?SetClass@Element@DirectUI@@QAEJPBG@Z (delay), ?SetConstrainLayout@RichText@DirectUI@@QAEJH@Z (delay), ?SetContentAlign@Element@DirectUI@@QAEJH@Z (delay), ?SetContentString@Element@DirectUI@@QAEJPBG@Z (delay), ?SetDirection@Element@DirectUI@@QAEJH@Z (delay), ?SetEnabled@Element@DirectUI@@QAEJ_N@Z (delay), ?SetForegroundColor@Element@DirectUI@@QAEJK@Z (delay), ?SetHeight@Element@DirectUI@@QAEJH@Z (delay), ?SetID@Element@DirectUI@@QAEJPBG@Z (delay), ?SetKeyFocus@Element@DirectUI@@UAEXXZ (delay), ?SetKeyFocus@HWNDHost@DirectUI@@UAEXXZ (delay), ?SetLayout@Element@DirectUI@@QAEJPAVLayout@2@@Z (delay), ?SetLayoutPos@Element@DirectUI@@QAEJH@Z (delay), ?SetMargin@Element@DirectUI@@QAEJHHHH@Z (delay), ?SetMinSize@Element@DirectUI@@QAEJHH@Z (delay), ?SetNotifyHandler@CCBase@DirectUI@@QAEXP6GHIIJPAJPAX@Z1@Z (delay), ?SetOptimizeMove@HWNDHost@DirectUI@@QAEJ_N@Z (delay), ?SetPadding@Element@DirectUI@@QAEJHHHH@Z (delay), ?SetParentSizeControl@HWNDElement@DirectUI@@QAEX_N@Z (delay), ?SetPreprocessedXML@DUIXmlParser@DirectUI@@QAEJPBGPAUHINSTANCE__@@1@Z (delay), ?SetPressed@Button@DirectUI@@QAEJ_N@Z (delay), ?SetProvider@XElement@DirectUI@@QAEJPAUIUnknown@@@Z (delay), ?SetRootWindowForTheming@DUIXmlParser@DirectUI@@QAEXPAUHWND__@@@Z (delay), ?SetScreenCenter@HWNDElement@DirectUI@@QAEX_N@Z (delay), ?SetSelected@Element@DirectUI@@QAEJ_N@Z (delay), ?SetShortcut@Element@DirectUI@@QAEJH@Z (delay), ?SetTooltip@Element@DirectUI@@QAEJ_N@Z (delay), ?SetValue@Element@DirectUI@@QAEJP6GPBUPropertyInfo@2@XZHPAVValue@2@@Z (delay), ?SetValue@Element@DirectUI@@QAEJPBUPropertyInfo@2@HPAVValue@2@@Z (delay), ?SetVisible@Element@DirectUI@@QAEJ_N@Z (delay), ?SetWidth@Element@DirectUI@@QAEJH@Z (delay), ?SetWindowDirection@HWNDHost@DirectUI@@UAEXPAUHWND__@@@Z (delay), ?SetWrapKeyboardNavigate@HWNDElement@DirectUI@@QAEJ_N@Z (delay), ?SetXML@DUIXmlParser@DirectUI@@QAEJPBGPAUHINSTANCE__@@1@Z (delay), ?SetXMLFromResource@DUIXmlParser@DirectUI@@QAEJIPAUHINSTANCE__@@0@Z (delay), ?SetXMLFromResource@DUIXmlParser@DirectUI@@QAEJPBGPAUHINSTANCE__@@1@Z (delay), ?SetXMLFromResourceWithTheme@DUIXmlParser@DirectUI@@QAEJIPAUHINSTANCE__@@00@Z (delay), ?SetYBarVisibility@BaseScrollViewer@DirectUI@@QAEJH@Z (delay), ?SetYOffset@BaseScrollViewer@DirectUI@@QAEJH@Z (delay), ?ShiftChild@Element@DirectUI@@QAEJII@Z (delay), ?ShowAccel@HWNDElement@DirectUI@@QAE_NXZ (delay), ?ShowFocus@HWNDElement@DirectUI@@QAE_NXZ (delay), ?ShowUIState@HWNDElement@DirectUI@@QAEX_N0@Z (delay), ?ShowWindow@NativeHWNDHost@DirectUI@@QAEXH@Z (delay), ?SizeInLayoutProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?StartDefer@Element@DirectUI@@QAEXPAK@Z (delay), ?ThemeChange@HWNDElement@DirectUI@@SG?AVUID@@XZ (delay), ?TrackScore@NavScoring@DirectUI@@QAEHPAVElement@2@0@Z (delay), ?UpdateLayoutRect@Layout@DirectUI@@SGXPAVElement@2@HH0HHHH@Z (delay), ?UpdateSheets@DUIXmlParser@DirectUI@@QAEJPAVElement@2@@Z (delay), ?UpdateTooltip@Element@DirectUI@@MAEXPAV12@@Z (delay), ?UpdateTooltip@HWNDElement@DirectUI@@UAEXPAVElement@2@@Z (delay), ?VisibleProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?WidthProp@Element@DirectUI@@SGPBUPropertyInfo@2@XZ (delay), ?WindowDpiChanged@HWNDElement@DirectUI@@SG?AVUID@@XZ (delay), ?WndProc@HWNDElement@DirectUI@@UAEJPAUHWND__@@IIJ@Z (delay), ?_OnUIStateChanged@HWNDElement@DirectUI@@MAEXGG@Z (delay), ?_PostEvent@Element@DirectUI@@AAEXPAUEvent@2@H@Z (delay), ?_SelfLayoutDoLayout@Element@DirectUI@@MAEXHH@Z (delay), ?_SelfLayoutUpdateDesiredSize@Element@DirectUI@@MAE?AUtagSIZE@@HHPAVSurface@2@@Z (delay), ?_SetGroupChanges@Element@DirectUI@@SG_NPAV12@HPAVDeferCycle@2@@Z (delay), ?_SetValue@Element@DirectUI@@IAEJPBUPropertyInfo@2@HPAVValue@2@_N@Z (delay), ?_UpdateDesiredSize@Element@DirectUI@@QAE?AUtagSIZE@@HHPAVSurface@2@@Z (delay), ?_UpdateLayoutPosition@Element@DirectUI@@QAEXHH@Z (delay), ?_UpdateLayoutSize@Element@DirectUI@@QAEXHH@Z (delay), ARGBColorFromEnumI (delay), ColorFromEnumI (delay), CreateDUIWrapper (delay), DUIDrawShadowText (delay), DisableAnimations (delay), EnableAnimations (delay), FlushThemeHandles (delay), GetFontCache (delay), GetScaleFactor (delay), InitProcessPriv (delay), InitThread (delay), IsUIAutomationProviderEnabled (delay), StartMessagePump (delay), StrToID (delay), UiaHideOnGetObject (delay), UiaOnDestroySink (delay), UiaOnGetObject (delay), UnInitProcessPriv (delay), UnInitThread (delay)
- **no api-set shell api-ms-win-storage-exports-internal-l1-1-0** (86): CCachedShellItem_CreateInstance (delay), CCollectionFactory_CreateInstance (delay), CDesktopFolder_CreateInstanceWithBindContext (delay), CFSFolder_AdjustForSlowColumn (delay), CFSFolder_CreateFolder (delay), CFSFolder_IsCommonItem (delay), CFileOperationRecorder_CreateInstance (delay), CMruLongList_CreateInstance (delay), CPrivateProfileCache_Save (delay), CRegFolder_CreateAndInit (delay), CShellItemArrayAsCollection_CreateInstance (delay), CShellItemArrayAsVirtualizedObjectArray_CreateInstance (delay), CShellItemArrayWithCommonParent_CreateInstance (delay), CShellItemArray_CreateInstance (delay), CShellItem_CreateInstance (delay), CTaskAddDoc_Create (delay), CViewSettings_CreateInstance (delay), CheckSmartScreenWithAltFile (delay), CopyDefaultLibrariesFromGroupPolicy (delay), CreateItemArrayFromItemStore (delay), CreateItemArrayFromObjectArray (delay), CreateLocalizationDesktopIni (delay), CreateSortColumnArray (delay), CustomStatePropertyDescription_CreateWithItemPropertyStore (delay), DataAccessCaches_InvalidateForLibrary (delay), DetermineFolderDestinationParentAppID (delay), EnumShellItemsFromEnumFullIdList (delay), GetCommandProviderForFolderType (delay), GetFileUndoText (delay), GetFindDataForPath (delay), GetInfoForFileInUse (delay), GetRegDataDrivenCommand (delay), GetRegDataDrivenCommandWithAssociation (delay), GetSelectionStateFromItemArray (delay), GetThreadFlags (delay), Global_WindowsStorage_MaxIcons (delay), Global_WindowsStorage_Untyped_FileClassSRWLock (delay), Global_WindowsStorage_Untyped_MountPoint (delay), Global_WindowsStorage_Untyped_pFileClassCacheTable (delay), Global_WindowsStorage_Untyped_pFileHanderMap (delay), Global_WindowsStorage_Untyped_rgshil (delay), Global_WindowsStorage_afNotRedirected (delay), Global_WindowsStorage_ccIcon (delay), Global_WindowsStorage_csIconCache (delay), Global_WindowsStorage_csSCN (delay), Global_WindowsStorage_dwThreadBindCtx (delay), Global_WindowsStorage_dwThreadInitializing (delay), Global_WindowsStorage_esServerMode (delay), Global_WindowsStorage_fEndInitialized (delay), Global_WindowsStorage_fIconCacheHasBeenSuccessfullyCreated (delay), Global_WindowsStorage_fIconCacheIsValid (delay), Global_WindowsStorage_fNeedsInitBroadcast (delay), Global_WindowsStorage_hwndSCN (delay), Global_WindowsStorage_iLastSysIcon (delay), Global_WindowsStorage_iLastSystemColorDepth (delay), Global_WindowsStorage_iUseLinkPrefix (delay), Global_WindowsStorage_lProcessClassCount (delay), Global_WindowsStorage_lrFlags (delay), Global_WindowsStorage_tlsChangeClientProxy (delay), Global_WindowsStorage_tlsIconCache (delay), Global_WindowsStorage_ulNextID (delay), HideExtension (delay), IsLibraryCreatedByPolicy (delay), IsLibraryPolicyEnabled (delay), IsNameListedUnderKey (delay), RegistryVerbs_GetHandlerMultiSelectModel (delay), SHCreateItemWithParentAndChildId (delay), SHFileOperationWithAdditionalFlags (delay), SHGetFolderPathAndSubDirA (delay), SHGetFolderPathEx (delay), SHGetKnownFolderIDList (delay), SHGetKnownFolderIDList_Internal (delay), SHGetKnownFolderItem (delay), SHGetSpecialFolderLocation (delay), SHKnownFolderFromCSIDL (delay), SHPrepareKnownFoldersCommon (delay), SHPrepareKnownFoldersUser (delay), SHResolveLibrary (delay), SHSetFolderPathA (delay), SHSetFolderPathW (delay), SendNotificationsForLibraryItem (delay), SetThreadFlags (delay), StateRepoVerbsCache_GetContextMenuVerbs (delay), StateRepoVerbsCache_RebuildCacheAsync (delay), _CleanRecentDocs (delay), _PredictReasonableImpact (delay)
- **shlwapi** (74): #172 (delay), #173 (delay), #177 (delay), #178 (delay), #179 (delay), #186 (delay), #187 (delay), #192 (delay), #193 (delay), #195 (delay), #200 (delay), #201 (delay), #204 (delay), #208 (delay), #210 (delay), #211 (delay), #220 (delay), #221 (delay), #225 (delay), #23 (delay), #233 (delay), #235 (delay), #236 (delay), #239 (delay), #240 (delay), #266 (delay), #267 (delay), #268 (delay), #269 (delay), #271 (delay), #279 (delay), #282 (delay), #283 (delay), #284 (delay), #288 (delay), #292 (delay), #294 (delay), #317 (delay), #331 (delay), #354 (delay), #355 (delay), #363 (delay), #381 (delay), #384 (delay), #388 (delay), #407 (delay), #409 (delay), #433 (delay), #445 (delay), #471 (delay), #479 (delay), #484 (delay), #509 (delay), #512 (delay), #513 (delay), #515 (delay), #516 (delay), #517 (delay), #519 (delay), #537 (delay), #538 (delay), #540 (delay), #544 (delay), #545 (delay), #546 (delay), #571 (delay), #575 (delay), #580 (delay), #581 (delay), #583 (delay), #616 (delay), #626 (delay), #635 (delay), #639 (delay)
- **msvcp_win** (73): ??0?$basic_ios@GU?$char_traits@G@std@@@std@@IAE@XZ, ??0?$basic_ostream@GU?$char_traits@G@std@@@std@@QAE@PAV?$basic_streambuf@GU?$char_traits@G@std@@@1@_N@Z, ??0?$basic_streambuf@GU?$char_traits@G@std@@@std@@IAE@XZ, ??0task_continuation_context@Concurrency@@AAE@XZ, ??1?$basic_ios@GU?$char_traits@G@std@@@std@@UAE@XZ, ??1?$basic_ostream@GU?$char_traits@G@std@@@std@@UAE@XZ, ??1?$basic_streambuf@GU?$char_traits@G@std@@@std@@UAE@XZ, ?GetCurrentThreadId@platform@details@Concurrency@@YAJXZ, ?_CallInContext@_ContextCallback@details@Concurrency@@QBEXV?$function@$$A6AXXZ@std@@_N@Z, ?_Capture@_ContextCallback@details@Concurrency@@AAEXXZ, ?_Execute_once@std@@YAHAAUonce_flag@1@P6GHPAX1PAPAX@Z1@Z, ?_Lock@?$basic_streambuf@GU?$char_traits@G@std@@@std@@UAEXXZ, ?_LogCancelTask@_TaskEventLogger@details@Concurrency@@QAEXXZ, ?_LogScheduleTask@_TaskEventLogger@details@Concurrency@@QAEX_N@Z, ?_LogTaskCompleted@_TaskEventLogger@details@Concurrency@@QAEXXZ, ?_LogTaskExecutionCompleted@_TaskEventLogger@details@Concurrency@@QAEXXZ, ?_LogWorkItemCompleted@_TaskEventLogger@details@Concurrency@@QAEXXZ, ?_LogWorkItemStarted@_TaskEventLogger@details@Concurrency@@QAEXXZ, ?_Osfx@?$basic_ostream@GU?$char_traits@G@std@@@std@@QAEXXZ, ?_Pninc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IAEPAGXZ, ?_Release_chore@details@Concurrency@@YAXPAU_Threadpool_chore@12@@Z, ?_ReportUnobservedException@details@Concurrency@@YAXXZ, ?_Reset@_ContextCallback@details@Concurrency@@AAEXXZ, ?_Schedule_chore@details@Concurrency@@YAHPAU_Threadpool_chore@12@@Z, ?_Throw_C_error@std@@YAXH@Z, ?_Unlock@?$basic_streambuf@GU?$char_traits@G@std@@@std@@UAEXXZ, ?_XGetLastError@std@@YAXXZ, ?_Xbad_function_call@std@@YAXXZ, ?_Xlength_error@std@@YAXPBD@Z, ?__ExceptionPtrCopy@@YAXPAXPBX@Z, ?__ExceptionPtrCreate@@YAXPAX@Z, ?__ExceptionPtrCurrentException@@YAXPAX@Z, ?__ExceptionPtrDestroy@@YAXPAX@Z, ?__ExceptionPtrRethrow@@YAXPBX@Z, ?__ExceptionPtrToBool@@YA_NPBX@Z, ?eback@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IBEPAGXZ, ?egptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IBEPAGXZ, ?epptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IBEPAGXZ, ?fill@?$basic_ios@GU?$char_traits@G@std@@@std@@QBEGXZ, ?flags@ios_base@std@@QBEHXZ, ?flush@?$basic_ostream@GU?$char_traits@G@std@@@std@@QAEAAV12@XZ, ?gbump@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IAEXH@Z, ?good@ios_base@std@@QBE_NXZ, ?gptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IBEPAGXZ, ?imbue@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAEXABVlocale@2@@Z, ?pbase@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IBEPAGXZ, ?pptr@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IBEPAGXZ, ?rdbuf@?$basic_ios@GU?$char_traits@G@std@@@std@@QBEPAV?$basic_streambuf@GU?$char_traits@G@std@@@2@XZ, ?setbuf@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAEPAV12@PAG_J@Z, ?setg@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IAEXPAG00@Z, ?setp@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IAEXPAG00@Z, ?setp@?$basic_streambuf@GU?$char_traits@G@std@@@std@@IAEXPAG0@Z, ?setstate@?$basic_ios@GU?$char_traits@G@std@@@std@@QAEXH_N@Z, ?showmanyc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAE_JXZ, ?sputc@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QAEGG@Z, ?sputn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@QAE_JPBG_J@Z, ?sync@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAEHXZ, ?tellp@?$basic_ostream@GU?$char_traits@G@std@@@std@@QAE?AV?$fpos@U_Mbstatet@@@2@XZ, ?tie@?$basic_ios@GU?$char_traits@G@std@@@std@@QBEPAV?$basic_ostream@GU?$char_traits@G@std@@@2@XZ, ?uflow@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAEGXZ, ?uncaught_exception@std@@YA_NXZ, ?width@ios_base@std@@QAE_J_J@Z, ?width@ios_base@std@@QBE_JXZ, ?xsgetn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAE_JPAG_J@Z, ?xsputn@?$basic_streambuf@GU?$char_traits@G@std@@@std@@MAE_JPBG_J@Z, _Cnd_broadcast, _Cnd_destroy_in_situ, _Cnd_init_in_situ, _Cnd_wait, _Mtx_destroy_in_situ, _Mtx_init_in_situ, _Mtx_lock, _Mtx_unlock
- **ntdll** (71): EtwEventActivityIdControl, EtwEventEnabled, EtwEventRegister, EtwEventSetInformation, EtwEventUnregister, EtwEventWrite, EtwEventWriteTransfer, EtwGetTraceEnableFlags, EtwGetTraceEnableLevel, EtwGetTraceLoggerHandle, EtwLogTraceEvent, EtwRegisterTraceGuidsW, EtwTraceMessage, EtwUnregisterTraceGuids, NtCompareSigningLevels, NtGetCachedSigningLevel, NtOpenThreadToken, NtQueryAttributesFile, NtQueryInformationProcess, NtQueryInformationThread, NtQueryInformationToken, NtQueryKey, NtQueryObject, NtQuerySecurityObject, NtQueryVolumeInformationFile, NtQueryWnfStateData, NtSetCachedSigningLevel, NtSetInformationToken, NtSetSecurityObject, RtlAcquireResourceExclusive, RtlAreLongPathsEnabled, RtlCheckRegistryKey, RtlCreateEnvironment, RtlCreateServiceSid, RtlCreateUnicodeString, RtlDeleteResource, RtlDestroyEnvironment, RtlDllShutdownInProgress, RtlDosPathNameToNtPathName_U_WithStatus, RtlDosPathNameToRelativeNtPathName_U, RtlDosPathNameToRelativeNtPathName_U_WithStatus, RtlFlushHeaps, RtlGetDeviceFamilyInfoEnum, RtlGetLastNtStatus, RtlGetNtProductType, RtlGetNtSystemRoot, RtlInitUnicodeStringEx, RtlInitializeResource, RtlIsNonEmptyDirectoryReparsePointAllowed, RtlIsPartialPlaceholder, RtlMapGenericMask, RtlNtStatusToDosErrorNoTeb, RtlPrefixString, RtlPublishWnfStateData, RtlQueryEnvironmentVariable_U, RtlQueryRegistryValuesEx, RtlQueryResourcePolicy, RtlQueryWnfStateData, RtlRandomEx, RtlReleaseRelativeName, RtlReleaseResource, RtlSetCurrentEnvironment, RtlSetEnvironmentVariable, RtlSubscribeWnfStateChangeNotification, RtlUnsubscribeWnfNotificationWaitForCompletion, ShipAssert, WinSqmAddToStream, WinSqmAddToStreamEx, WinSqmIncrementDWORD, WinSqmSetDWORD, ZwQueryWnfStateData
- **gdiplus** (65): GdipAddPathArcI (delay), GdipAlloc (delay), GdipBitmapSetResolution (delay), GdipCloneBrush (delay), GdipCloneImage (delay), GdipCreateBitmapFromScan0 (delay), GdipCreateFromHDC (delay), GdipCreateLineBrushFromRectI (delay), GdipCreateMatrix (delay), GdipCreatePath (delay), GdipCreatePen1 (delay), GdipCreateSolidFill (delay), GdipDeleteBrush (delay), GdipDeleteGraphics (delay), GdipDeleteMatrix (delay), GdipDeletePath (delay), GdipDeletePen (delay), GdipDisposeImage (delay), GdipDrawImagePointRectI (delay), GdipDrawImageRectRectI (delay), GdipDrawRectangleI (delay), GdipFillEllipseI (delay), GdipFillPieI (delay), GdipFillRectangleI (delay), GdipFree (delay), GdipGetEncoderParameterList (delay), GdipGetEncoderParameterListSize (delay), GdipGetImageBounds (delay), GdipGetImageEncoders (delay), GdipGetImageEncodersSize (delay), GdipGetImageFlags (delay), GdipGetImageGraphicsContext (delay), GdipGetImageHeight (delay), GdipGetImageHorizontalResolution (delay), GdipGetImagePixelFormat (delay), GdipGetImageRawFormat (delay), GdipGetImageThumbnail (delay), GdipGetImageVerticalResolution (delay), GdipGetImageWidth (delay), GdipGetPathLastPoint (delay), GdipGetPropertyCount (delay), GdipGetPropertyIdList (delay), GdipGetPropertyItem (delay), GdipGetPropertyItemSize (delay), GdipImageGetFrameCount (delay), GdipImageRotateFlip (delay), GdipImageSelectActiveFrame (delay), GdipLoadImageFromStreamICM (delay), GdipRemovePropertyItem (delay), GdipSaveAddImage (delay), GdipSaveImageToStream (delay), GdipScaleMatrix (delay), GdipSetClipRectI (delay), GdipSetCompositingMode (delay), GdipSetInterpolationMode (delay), GdipSetLineWrapMode (delay), GdipSetPageUnit (delay), GdipSetPropertyItem (delay), GdipSetSmoothingMode (delay), GdipSetSolidFillColor (delay), GdipSetWorldTransform (delay), GdipShearMatrix (delay), GdipTranslateMatrix (delay), GdiplusShutdown (delay), GdiplusStartup (delay)
- **user32** (40): #2521, #2705, #2707, AdjustWindowRectExForDpi, AreDpiAwarenessContextsEqual, ChangeWindowMessageFilterEx, CloseGestureInfoHandle, CreateWindowInBand, CreateWindowIndirect, DisplayConfigGetDeviceInfo, GetCurrentInputMessageSource, GetDisplayConfigBufferSizes, GetDpiForSystem, GetDpiForWindow, GetGestureInfo, GetPointerDevices, GetShellChangeNotifyWindow, GetSystemMetricsForDpi, GetTaskmanWindow, GetWindowBand, GetWindowDpiAwarenessContext, IsProcessDPIAware, IsSETEnabled, IsWinEventHookInstalled, PrivateExtractIconsW, QueryDisplayConfig, RegisterPowerSettingNotification, SetCoalescableTimer, SetDialogDpiChangeBehavior, SetGestureConfig, SetProcessDPIAware, SetShellChangeNotifyWindow, SetShellWindowEx, SetTaskmanWindow, SetThreadDpiAwarenessContext, SetWindowCompositionAttribute, ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy, SystemParametersInfoForDpi, UnregisterPowerSettingNotification
- **shcore** (40): #102 (delay), #103 (delay), #107 (delay), #108 (delay), #109 (delay), #110 (delay), #120 (delay), #121 (delay), #123 (delay), #125 (delay), #126 (delay), #130 (delay), #131 (delay), #132 (delay), #140 (delay), #141 (delay), #142 (delay), #143 (delay), #144 (delay), #145 (delay), #150 (delay), #160 (delay), #162 (delay), #174 (delay), #175 (delay), #182 (delay), #183 (delay), #184 (delay), #186 (delay), #187 (delay), #188 (delay), #189 (delay), #190 (delay), #191 (delay), #192 (delay), #193 (delay), #200 (delay), #234 (delay), #284 (delay), #290 (delay)
- **no api-set shell api-ms-win-storage-exports-external-l1-1-0** (34): STORAGE_AddItemToRecentDocs (delay), STORAGE_AddNewFolderToFrequentPlaces (delay), STORAGE_CEnumFiles_CreateInstance (delay), STORAGE_CStorageItem_GetValidatedStorageItem (delay), STORAGE_CStorageItem_GetValidatedStorageItemObject (delay), STORAGE_ClearDestinationsForAllApps (delay), STORAGE_CreateSortColumnArrayFromListDesc (delay), STORAGE_CreateStorageItemFromPath_FullTrustCaller (delay), STORAGE_CreateStorageItemFromPath_FullTrustCaller_ForPackage (delay), STORAGE_CreateStorageItemFromPath_PartialTrustCaller (delay), STORAGE_CreateStorageItemFromShellItem_FullTrustCaller (delay), STORAGE_CreateStorageItemFromShellItem_FullTrustCaller_ForPackage (delay), STORAGE_CreateStorageItemFromShellItem_FullTrustCaller_ForPackage_WithProcessHandle (delay), STORAGE_CreateStorageItemFromShellItem_FullTrustCaller_UseImplicitFlagsAndPackage (delay), STORAGE_GetShellItemFromStorageItem (delay), STORAGE_GetSystemPersistedStorageItemList (delay), STORAGE_MakeDestinationItem (delay), STORAGE_SHAddToRecentDocs (delay), STORAGE_SHAddToRecentDocsEx (delay), STORAGE_SHConfirmOperation (delay), STORAGE_SHCreateDirectory (delay), STORAGE_SHCreateDirectoryExA (delay), STORAGE_SHCreateShellItemArray (delay), STORAGE_SHCreateShellItemArrayFromDataObject (delay), STORAGE_SHCreateShellItemArrayFromIDLists (delay), STORAGE_SHCreateShellItemArrayFromShellItem (delay), STORAGE_SHFileOperation (delay), STORAGE_SHFileOperationA (delay), STORAGE_SHFreeNameMappings (delay), STORAGE_SHGetDesktopFolderWorker (delay), STORAGE_SHGetPathFromMsUri (delay), STORAGE_SHPathPrepareForWriteA (delay), STORAGE_SHPathPrepareForWriteW (delay), STORAGE_SHValidateMSUri (delay)
- **oleaut32** (24): #10 (delay), #12 (delay), #125 (delay), #149 (delay), #15 (delay), #150 (delay), #16 (delay), #161 (delay), #162 (delay), #163 (delay), #17 (delay), #184 (delay), #185 (delay), #2 (delay), #201 (delay), #23 (delay), #24 (delay), #25 (delay), #4 (delay), #417 (delay), #6 (delay), #7 (delay), #8 (delay), #9 (delay)
- **no api-set shell api-ms-win-shlwapi-ie-l1-1-0** (22): #165 (delay), #167 (delay), #197 (delay), #24 (delay), #348 (delay), #365 (delay), #4 (delay), #448 (delay), #478 (delay), #481 (delay), #511 (delay), #6 (delay), AssocGetPerceivedType (delay), AssocQueryKeyW (delay), ConnectToConnectionPoint (delay), IUnknown_Exec (delay), IUnknown_QueryStatus (delay), PathFileExistsAndAttributesW (delay), PathFindOnPathW (delay), PathIsDirectoryA (delay), PathIsDirectoryEmptyW (delay), PathIsDirectoryW (delay)
- **kernelbase** (19): ClosePackageInfo, CloseState, ExtensionProgIdExists, GetCurrentPackageInfo, GetEffectivePackageStatusForUser, GetExtensionProgIds, GetPackageFullName, GetPackageInfo, GetPackagesByPackageFamily, GetStagedPackagePathByFullName2, GetStateFolder, GetSystemAppDataKey, IsMrtResourceRedirectionEnabled, NotifyRedirectedStringChange, OpenPackageInfoByFullName, OpenState, OpenStateExplicit, PackageNameAndPublisherIdFromFamilyName, ParseApplicationUserModelId
- **propsys** (19): #402 (delay), #404 (delay), #405 (delay), #406 (delay), #407 (delay), #408 (delay), #411 (delay), #412 (delay), #416 (delay), #423 (delay), #430 (delay), #432 (delay), #435 (delay), #436 (delay), #440 (delay), #441 (delay), #442 (delay), #443 (delay), #445 (delay)
- **no api-set shell api-ms-win-core-libraryloader-l1-2-0** (18): DisableThreadLibraryCalls, EnumResourceNamesExW, FindResourceExW, FindStringOrdinal, FreeLibrary, FreeResource, GetModuleFileNameA, GetModuleFileNameW, GetModuleHandleExW, GetModuleHandleW, GetProcAddress, LoadLibraryExA, LoadLibraryExW, LoadResource, LoadStringA, LoadStringW, LockResource, SizeofResource
- **no api-set shell api-ms-win-core-path-l1-1-0** (18): PathAllocCanonicalize, PathAllocCombine, PathCchAddBackslash, PathCchAddBackslashEx, PathCchAddExtension, PathCchAppend, PathCchAppendEx, PathCchCanonicalize, PathCchCombine, PathCchCombineEx, PathCchRemoveBackslash, PathCchRemoveExtension, PathCchRemoveFileSpec, PathCchRenameExtension, PathCchSkipRoot, PathCchStripPrefix, PathCchStripToRoot, PathIsUNCEx
- **no api-set shell api-ms-win-core-winrt-string-l1-1-0** (13): WindowsCompareStringOrdinal (delay), WindowsCreateString (delay), WindowsCreateStringReference (delay), WindowsDeleteString (delay), WindowsDeleteStringBuffer (delay), WindowsDuplicateString (delay), WindowsGetStringLen (delay), WindowsGetStringRawBuffer (delay), WindowsIsStringEmpty (delay), WindowsPreallocateStringBuffer (delay), WindowsPromoteStringBuffer (delay), WindowsStringHasEmbeddedNull (delay), WindowsSubstringWithSpecifiedLength (delay)
- **edputil** (12): EdpCheckAccess (delay), EdpCheckAccessForContext (delay), EdpFreeContext (delay), EdpGetContextForProcess (delay), EdpGetEnterpriseIdForClipboard (delay), EdpGetEnterpriseIdForDataObject (delay), EdpGetIsManaged (delay), EdpGetPrimaryIdentities (delay), EdpIsContextExemptOrEnlightenedAllowed (delay), EdpRequestAccess (delay), EdpUtilFreeEnterpriseContext (delay), EdpUtilGetEnterpriseContextByName (delay)
- **no api-set shell api-ms-win-core-threadpool-l1-2-0** (11): CloseThreadpoolTimer, CloseThreadpoolWait, CloseThreadpoolWork, CreateThreadpoolTimer, CreateThreadpoolWait, CreateThreadpoolWork, SetThreadpoolTimer, SetThreadpoolWait, SubmitThreadpoolWork, WaitForThreadpoolTimerCallbacks, WaitForThreadpoolWaitCallbacks
- **uxtheme** (11): #104 (delay), #106 (delay), #119 (delay), #120 (delay), #121 (delay), #122 (delay), #132 (delay), #133 (delay), #135 (delay), #139 (delay), #47 (delay)
- **no api-set shell api-ms-win-shcore-registry-l1-1-0** (10): SHDeleteKeyA (delay), SHDeleteKeyW (delay), SHDeleteValueW (delay), SHEnumKeyExW (delay), SHEnumValueW (delay), SHGetValueW (delay), SHQueryValueExW (delay), SHRegGetValueW (delay), SHRegSetPathW (delay), SHSetValueW (delay)
- **duser** (10): AttachWndProcW (delay), CreateAction (delay), DUserPostEvent (delay), DeleteHandle (delay), ForwardGadgetMessage (delay), GetGadgetAnimation (delay), GetGadgetRect (delay), InitGadgets (delay), InvalidateGadget (delay), SetGadgetStyle (delay)
- **devobj** (9): DevObjCreateDeviceInfoList (delay), DevObjDestroyDeviceInfoList (delay), DevObjEnumDeviceInfo (delay), DevObjEnumDeviceInterfaces (delay), DevObjGetClassDevs (delay), DevObjGetDeviceInterfaceDetail (delay), DevObjGetDeviceProperty (delay), DevObjOpenDeviceInfo (delay), DevObjOpenDeviceInterface (delay)
- **not in our api-ms-win-shcore-stream-l1-1-0** (9): IStream_Copy (delay), IStream_Read (delay), IStream_ReadStr (delay), IStream_Reset (delay), IStream_Size (delay), IStream_Write (delay), IStream_WriteStr (delay), SHCreateMemStream (delay), SHCreateStreamOnFileEx (delay)
- **not in our api-ms-win-core-shlwapi-obsolete-l1-1-0** (8): QISearch, StrCmpCW, StrCmpICA, StrCmpICW, StrCmpLogicalW, StrCmpNCW, StrCmpNICW, StrCpyNXW
- **no api-set shell api-ms-win-devices-query-l1-1-0** (8): DevCloseObjectQuery (delay), DevCreateObjectQueryFromId (delay), DevFindProperty (delay), DevFreeObjectProperties (delay), DevFreeObjects (delay), DevGetObjectProperties (delay), DevGetObjects (delay), DevSetObjectProperties (delay)
- **no api-set shell api-ms-win-shell-shellfolders-l1-1-0** (8): SHGetFolderLocation (delay), SHGetFolderPathA (delay), SHGetFolderPathAndSubDirW (delay), SHGetFolderPathW (delay), SHGetKnownFolderPath (delay), SHGetSpecialFolderPathA (delay), SHGetSpecialFolderPathW (delay), SHSetKnownFolderPath (delay)
- **no api-set shell ext-ms-win-gui-dui70-l1-1-0** (8): DUI70_ElementDestroy (delay), DUI70_ElementSetAccRole (delay), DUI70_ElementSetAccessible (delay), DUI70_ElementSetContentAlign (delay), DUI70_ElementSetContentString (delay), DUI70_ElementSetID (delay), DUI70_RichTextCreate (delay), DUI70_RichTextSetConstrainLayout (delay)
- **no api-set shell api-ms-win-core-registryuserspecific-l1-1-0** (7): SHRegCloseUSKey, SHRegEnumUSKeyW, SHRegGetBoolUSValueW, SHRegGetUSValueW, SHRegOpenUSKeyA, SHRegOpenUSKeyW, SHRegQueryUSValueW
- **ws2_32** (7): #111 (delay), #115 (delay), #116 (delay), #20 (delay), #21 (delay), #23 (delay), #3 (delay)
- **no api-set shell api-ms-win-shcore-thread-l1-1-0** (7): GetProcessReference (delay), SHCreateThread (delay), SHCreateThreadRef (delay), SHCreateThreadWithHandle (delay), SHGetThreadRef (delay), SHSetThreadRef (delay), SetProcessReference (delay)
- **no api-set shell ext-ms-win-shell-fileplaceholder-l1-1-0** (7): FECommon_CSyncRootManager_CreateInstance (delay), FECommon_CreatePlaceholderFile (delay), FECommon_FilePlaceholder_BindToPrimaryStream (delay), FECommon_GetPlaceholderStatesFromFileAttributesAndReparsePointTag (delay), FECommon_GetStorageProviderDisplayName (delay), FECommon_GetStorageProviderInfoFromItem (delay), FECommon_PerformCloudFilePinAction (delay)
- **not in our api-ms-win-core-shlwapi-legacy-l1-1-0** (6): IsCharSpaceW, PathIsValidCharW, PathMatchSpecExW, PathUnExpandEnvStringsW, SHExpandEnvironmentStringsA, SHExpandEnvironmentStringsW
- **cryptsp** (6): CryptAcquireContextW (delay), CryptCreateHash (delay), CryptDestroyHash (delay), CryptGetHashParam (delay), CryptHashData (delay), CryptReleaseContext (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-3** (6): CreateOleAdviseHolder (delay), DoDragDrop (delay), OleRegEnumVerbs (delay), OleRegGetMiscStatus (delay), OleRegGetUserType (delay), ReleaseStgMedium (delay)
- **chartv** (6): CvCloseDataSource (delay), CvCreateDataSource (delay), CvGetData (delay), CvInitialize (delay), CvSetData (delay), CvUninitialize (delay)
- **no api-set shell api-ms-win-core-heap-l2-1-0** (5): GlobalAlloc, GlobalFree, LocalAlloc, LocalFree, LocalReAlloc
- **no api-set shell api-ms-win-eventing-provider-l1-1-0** (5): EventProviderEnabled, EventRegister, EventSetInformation, EventUnregister, EventWriteTransfer
- **not in our api-ms-win-eventing-classicprovider-l1-1-0** (5): GetTraceEnableFlags, GetTraceEnableLevel, GetTraceLoggerHandle, RegisterTraceGuidsW, UnregisterTraceGuids
- **no api-set shell api-ms-win-core-atoms-l1-1-0** (5): FindAtomW, GetAtomNameW, GlobalAddAtomW, GlobalDeleteAtom, GlobalGetAtomNameW
- **no api-set shell api-ms-win-core-sidebyside-l1-1-0** (5): ActivateActCtx, CreateActCtxW, DeactivateActCtx, QueryActCtxW, ReleaseActCtx
- **not in our api-ms-win-core-com-l1-1-0** (5): CoCancelCall (delay), CoDisableCallCancellation (delay), CoEnableCallCancellation (delay), CoGetApartmentType (delay), CoIncrementMTAUsage (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-0** (5): GetRestrictedErrorInfo (delay), RoOriginateError (delay), RoOriginateErrorW (delay), RoTransformError (delay), SetRestrictedErrorInfo (delay)
- **no api-set shell api-ms-win-devices-config-l1-1-1** (5): CM_Get_Device_IDW (delay), CM_Get_Device_Interface_ListW (delay), CM_Get_Device_Interface_List_SizeW (delay), CM_Get_Device_Interface_PropertyW (delay), CM_Locate_DevNodeW (delay)
- **winbrand** (5): BrandingFormatString (delay), BrandingLoadImage (delay), BrandingLoadString (delay), EulaFreeBuffer (delay), GetEULAInCurrentUILanguage (delay)
- **virtdisk** (5): AttachVirtualDisk (delay), DetachVirtualDisk (delay), GetStorageDependencyInformation (delay), GetVirtualDiskPhysicalPath (delay), OpenVirtualDisk (delay)
- **linkinfo** (5): CreateLinkInfoW (delay), DestroyLinkInfo (delay), GetLinkInfoData (delay), IsValidLinkInfo (delay), ResolveLinkInfoW (delay)
- **no api-set shell ext-ms-win-storage-sense-l1-1-0** (5): CloseFindStorageSearch (delay), FindNextStorageTypeEx (delay), OpenStorageTypeSearch (delay), SelectStorageVolumeEx (delay), TriggerStorageCleanup (delay)
- **no api-set shell api-ms-win-core-winrt-error-l1-1-1** (4): IsErrorPropagationEnabled (delay), RoGetMatchingRestrictedErrorInfo (delay), RoOriginateLanguageException (delay), RoReportFailedDelegate (delay)
- **not in our api-ms-win-security-lsapolicy-l1-1-0** (4): LsaFreeMemory (delay), LsaLookupNames2 (delay), LsaLookupSids (delay), LsaQueryInformationPolicy (delay)
- **no api-set shell api-ms-win-shcore-comhelpers-l1-1-0** (4): IUnknown_GetSite (delay), IUnknown_QueryService (delay), IUnknown_Set (delay), IUnknown_SetSite (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-5** (4): CreateClassMoniker (delay), OleGetClipboard (delay), OleLoadFromStream (delay), OleSetClipboard (delay)
- **dwmapi** (4): #106 (delay), #127 (delay), #131 (delay), #139 (delay)
- **oleacc** (4): AccessibleObjectFromWindow (delay), CreateStdAccessibleObject (delay), LresultFromObject (delay), ObjectFromLresult (delay)
- **cfgmgr32** (4): CM_Get_DevNode_Registry_Property_ExW (delay), CM_Get_Device_Interface_List_ExW (delay), CM_Get_Device_Interface_List_Size_ExW (delay), CM_Get_Parent_Ex (delay)
- **no api-set shell ext-ms-win-storage-sense-l1-2-0** (4): GetStoragePolicySettings (delay), ResetStoragePolicySettings (delay), SetStoragePolicySettings (delay), TriggerStoragePolicies (delay)
- **not in our api-ms-win-core-registry-l1-1-0** (3): RegDeleteKeyExW, RegDeleteTreeW, RegGetValueW
- **not in our api-ms-win-core-synch-l1-1-0** (3): CreateEventExW, CreateMutexExW, CreateSemaphoreExW
- **not in our api-ms-win-core-localization-l1-2-0** (3): FindNLSString, FindNLSStringEx, GetThreadUILanguage
- **not in our api-ms-win-core-url-l1-1-0** (3): ParseURLW, PathCreateFromUrlAlloc, UrlFixupW
- **not in our api-ms-win-core-kernel32-private-l1-1-0** (3): CheckElevation, CheckElevationEnabled, Wow64EnableWow64FsRedirection
- **no api-set shell api-ms-win-core-job-l2-1-0** (3): AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject
- **no api-set shell api-ms-win-shcore-obsolete-l1-1-0** (3): CommandLineToArgvW (delay), SHStrDupA (delay), SHStrDupW (delay)
- **no api-set shell api-ms-win-shcore-sysinfo-l1-1-0** (3): GetCurrentProcessExplicitAppUserModelID (delay), IsOS (delay), SetCurrentProcessExplicitAppUserModelID (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-1** (3): CoAllowSetForegroundWindow (delay), CoInitialize (delay), OleSaveToStream (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-0** (3): GetRunningObjectTable (delay), OleInitialize (delay), OleUninitialize (delay)
- **urlmon** (3): #503 (delay), #504 (delay), CreateUri (delay)
- **ntshrui** (3): GetLocalPathFromNetResourceW (delay), GetNetResourceFromLocalPathW (delay), IsPathSharedW (delay)
- **efsadu** (3): EfsDetail (delay), EfsUIUtilPromptForPinDialog (delay), EfsUIUtilSelectCard (delay)
- **wtsapi32** (3): WTSLogoffSession (delay), WTSRegisterSessionNotification (delay), WTSUnRegisterSessionNotification (delay)
- **elscore** (3): MappingFreePropertyBag (delay), MappingGetServices (delay), MappingRecognizeText (delay)
- **credui** (3): CredUIParseUserNameW (delay), CredUIPromptForWindowsCredentialsW (delay), CredUnPackAuthenticationBufferW (delay)
- **xmllite** (3): CreateXmlReader (delay), CreateXmlReaderInputWithEncodingName (delay), CreateXmlWriter (delay)
- **cldapi** (3): CfGetPlaceholderStateFromFindData (delay), CfGetSyncRootInfoByHandle (delay), CfGetSyncRootInfoByPath (delay)
- **hvsifiletrust** (3): IsFileSupportedByWDAG (delay), IsFileTrustedEx (delay), IsWDAGEnabledForEdge (delay)
- **not in our api-ms-win-core-file-l1-1-0** (2): GetFinalPathNameByHandleW, SetFileInformationByHandle
- **no api-set shell api-ms-win-core-libraryloader-l1-2-1** (2): FindResourceW, LoadLibraryW
- **not in our api-ms-win-core-file-l2-1-0** (2): CopyFile2, GetFileInformationByHandleEx
- **not in our api-ms-win-security-base-l1-1-0** (2): AddAccessAllowedAceEx, AddAccessDeniedAceEx
- **no api-set shell api-ms-win-core-psapi-l1-1-0** (2): K32GetProcessImageFileNameW, QueryFullProcessImageNameW
- **no api-set shell api-ms-win-core-registry-l1-1-1** (2): RegDeleteKeyValueW, RegSetKeyValueW
- **not in our api-ms-win-core-wow64-l1-1-0** (2): Wow64DisableWow64FsRedirection, Wow64RevertWow64FsRedirection
- **no api-set shell api-ms-win-core-wow64-l1-1-1** (2): GetSystemWow64DirectoryW, IsWow64Process2
- **not in our api-ms-win-core-version-l1-1-0** (2): GetFileVersionInfoExW, GetFileVersionInfoSizeExW
- **no api-set shell api-ms-win-core-winrt-l1-1-0** (2): RoActivateInstance (delay), RoGetActivationFactory (delay)
- **mpr** (2): WNetGetConnection3W (delay), WNetGetProviderTypeW (delay)
- **sspicli** (2): GetUserNameExW (delay), LogonUserExExW (delay)
- **samcli** (2): NetUserGetInfo (delay), NetUserModalsGet (delay)
- **no api-set shell api-ms-win-power-base-l1-1-0** (2): GetPwrCapabilities (delay), PowerDeterminePlatformRoleEx (delay)
- **no api-set shell api-ms-win-security-lsalookup-l1-1-0** (2): LookupAccountNameLocalW (delay), LookupAccountSidLocalW (delay)
- **no api-set shell api-ms-win-core-com-private-l1-1-0** (2): CoRegisterInitializeSpy (delay), CoRevokeInitializeSpy (delay)
- **no api-set shell api-ms-win-shcore-unicodeansi-l1-1-0** (2): SHAnsiToUnicode (delay), SHUnicodeToAnsi (delay)
- **no api-set shell api-ms-win-shcore-path-l1-1-0** (2): #170 (delay), #172 (delay)
- **no api-set shell api-ms-win-shcore-taskpool-l1-1-0** (2): SHTaskPoolGetUniqueContext (delay), SHTaskPoolQueueTask (delay)
- **no api-set shell api-ms-win-shcore-scaling-l1-1-1** (2): #244 (delay), GetDpiForMonitor (delay)
- **no api-set shell api-ms-win-shcore-stream-winrt-l1-1-0** (2): CreateRandomAccessStreamOverStream (delay), CreateStreamOverRandomAccessStream (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-2** (2): RegisterDragDrop (delay), RevokeDragDrop (delay)
- **no api-set shell ext-ms-win-ole32-bindctx-l1-1-0** (2): CoGetObject (delay), CreateBindCtx (delay)
- **msiltcfg** (2): #3 (delay), #6 (delay)
- **davhlpr** (2): DavFlushFile (delay), DavGetHTTPFromUNCPath (delay)
- **shdocvw** (2): #141 (delay), #160 (delay)
- **apphelp** (2): ApphelpCheckExe (delay), ApphelpCheckShellObject (delay)
- **combase** (2): #157 (delay), #90 (delay)
- **twinapi.appcore** (2): #2 (delay), #3 (delay)
- **mrmcorer** (2): ResourceManagerQueueGetString (delay), ResourceManagerQueueIsResourceReference (delay)
- **no api-set shell ext-ms-win-feclient-encryptedfile-l1-1-0** (2): EfsClientFreeKeyInfo (delay), EfsClientGetKeyInfo (delay)
- **no api-set shell ext-ms-win-devmgmt-policy-l1-1-1** (2): PolicyManager_FreeGetPolicyData (delay), PolicyManager_GetPolicy (delay)
- **bcp47langs** (2): Bcp47FromHkl (delay), Bcp47GetNlsForm (delay)
- **not in our api-ms-win-core-processthreads-l1-1-0** (1): CreateProcessAsUserW
- **not in our api-ms-win-core-timezone-l1-1-0** (1): GetTimeZoneInformationForYear
- **no api-set shell api-ms-win-core-string-l2-1-1** (1): SHLoadIndirectString
- **no api-set shell api-ms-win-core-file-l2-1-2** (1): CopyFileW
- **no api-set shell api-ms-win-core-localization-l1-2-2** (1): LCIDToLocaleName
- **no api-set shell api-ms-win-core-synch-l1-2-1** (1): WaitForMultipleObjects
- **no api-set shell api-ms-win-core-localization-l2-1-0** (1): GetNumberFormatEx
- **not in our api-ms-win-core-io-l1-1-1** (1): CancelSynchronousIo
- **no api-set shell api-ms-win-core-sysinfo-l1-2-3** (1): GetIntegratedDisplaySize
- **no api-set shell api-ms-win-core-kernel32-legacy-l1-1-2** (1): GetBinaryTypeW
- **no api-set shell api-ms-win-core-apiquery-l1-1-0** (1): ApiSetQueryApiSetPresence
- **no api-set shell api-ms-win-shell-shellcom-l1-1-0** (1): SHCoCreateInstance
- **gdi32** (1): GdiTransparentBlt
- **no api-set shell api-ms-win-stateseparation-helpers-l1-1-0** (1): GetPersistedRegistryLocationW
- **no api-set shell api-ms-win-core-delayload-l1-1-1** (1): ResolveDelayLoadedAPI
- **no api-set shell api-ms-win-core-com-l1-1-1** (1): RoGetAgileReference (delay)
- **rpcrt4** (1): UuidCreateSequential (delay)
- **netutils** (1): NetApiBufferFree (delay)
- **srvcli** (1): NetServerGetInfo (delay)
- **wkscli** (1): NetGetJoinInformation (delay)
- **no api-set shell api-ms-win-core-com-l1-1-2** (1): CoFileTimeNow (delay)
- **no api-set shell api-ms-win-shcore-registry-l1-1-1** (1): SHRegGetValueFromHKCUHKLM (delay)
- **no api-set shell ext-ms-onecore-appdefaults-l1-1-0** (1): GetUserChoiceForUrl (delay)
- **no api-set shell ext-ms-onecore-appmodel-staterepository-internal-l1-1-3** (1): SRDictionaryToPropertySet (delay)
- **no api-set shell api-ms-win-shell-associations-l1-1-1** (1): AssocShouldProcessUseAppToAppLaunching (delay)
- **no api-set shell ext-ms-win-domainjoin-netjoin-l1-1-0** (1): NetpDomainJoinLicensingCheck (delay)
- **no api-set shell ext-ms-win-com-ole32-l1-1-4** (1): CreateFileMoniker (delay)
- **no api-set shell ext-ms-win32-subsystem-query-l1-1-0** (1): QueryWin32SubsystemHost (delay)
- **devmgr** (1): #20 (delay)
- **secur32** (1): TranslateNameW (delay)
- **dsreg** (1): DsrIsDeviceJoined (delay)
- **cscapi** (1): OfflineFilesQueryStatus (delay)
- **efsutil** (1): EfsUtilGetCurrentKey (delay)
- **advpack** (1): RunSetupCommandW (delay)
- **windowscodecs** (1): WICConvertBitmapSource (delay)
- **winsta** (1): WinStationIsSessionRemoteable (delay)
- **wintrust** (1): WTGetSignatureInfo (delay)
- **efswrt** (1): ProtectFileToIdentity (delay)
- **no api-set shell ext-ms-win-devmgmt-policy-l1-1-0** (1): PolicyManager_GetPolicyInt (delay)
- **no api-set shell api-ms-win-security-capability-l1-1-0** (1): CapabilityCheck (delay)
- **no api-set shell api-ms-win-power-setting-l1-1-0** (1): PowerGetActiveScheme (delay)
- **profapi** (1): #104 (delay)
- **wldp** (1): WldpQueryWindowsLockdownMode (delay)
