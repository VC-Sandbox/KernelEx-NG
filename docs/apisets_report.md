# API-set forwarder coverage

96 api sets, 1036 forwarders: kexnt 96, win98 native 853, KernelEx runtime 87, manual 0; **514 unresolved** (left out).

| api set | resolved | unresolved | unresolved functions |
|---|---|---|---|
| api-ms-win-base-util-l1-1-0 | 1 | 0 |  |
| api-ms-win-core-com-l1-1-0 | 60 | 20 | CoAllowUnmarshalerCLSID CoCancelCall CoCreateInstanceFromApp CoDecodeProxy CoDecrementMTAUsage CoDisableCallCancellation CoDisconnectContext CoEnableCallCancellation CoFreeUnusedLibrariesEx CoGetApartmentType CoGetCancelObject CoGetContextToken CoGetDefaultContext CoGetObjectContext CoGetStdMarshalEx CoIncrementMTAUsage CoInvalidateRemoteMachineBindings CoSetCancelObject CoTestCancel CoWaitForMultipleObjects |
| api-ms-win-core-comm-l1-1-0 | 18 | 0 |  |
| api-ms-win-core-console-l1-1-0 | 14 | 0 |  |
| api-ms-win-core-datetime-l1-1-0 | 4 | 0 |  |
| api-ms-win-core-datetime-l1-1-1 | 2 | 0 |  |
| api-ms-win-core-debug-l1-1-0 | 4 | 0 |  |
| api-ms-win-core-debug-l1-1-1 | 4 | 1 | DebugActiveProcessStop |
| api-ms-win-core-delayload-l1-1-0 | 1 | 0 |  |
| api-ms-win-core-errorhandling-l1-1-0 | 7 | 0 |  |
| api-ms-win-core-errorhandling-l1-1-1 | 5 | 0 |  |
| api-ms-win-core-fibers-l1-1-0 | 4 | 0 |  |
| api-ms-win-core-fibers-l1-1-1 | 1 | 0 |  |
| api-ms-win-core-file-l1-1-0 | 69 | 6 | DeleteVolumeMountPointW GetFinalPathNameByHandleA GetFinalPathNameByHandleW GetVolumeInformationByHandleW SetFileInformationByHandle SetFileValidData |
| api-ms-win-core-file-l1-2-0 | 3 | 1 | CreateFile2 |
| api-ms-win-core-file-l1-2-1 | 2 | 1 | SetFileIoOverlappedRange |
| api-ms-win-core-file-l2-1-0 | 7 | 4 | CopyFile2 CreateSymbolicLinkW GetFileInformationByHandleEx ReOpenFile |
| api-ms-win-core-file-l2-1-1 | 0 | 1 | OpenFileById |
| api-ms-win-core-handle-l1-1-0 | 5 | 0 |  |
| api-ms-win-core-heap-l1-1-0 | 15 | 1 | HeapSummary |
| api-ms-win-core-heap-obsolete-l1-1-0 | 15 | 0 |  |
| api-ms-win-core-interlocked-l1-1-0 | 10 | 2 | InterlockedCompareExchange64 InterlockedPushListSList |
| api-ms-win-core-io-l1-1-0 | 6 | 1 | GetQueuedCompletionStatusEx |
| api-ms-win-core-io-l1-1-1 | 1 | 2 | CancelSynchronousIo GetOverlappedResultEx |
| api-ms-win-core-kernel32-legacy-l1-1-0 | 46 | 8 | AddLocalAlternateComputerNameW BindIoCompletionCallback CreateFileTransactedW DnsHostnameToComputerNameW GetDurationFormatEx GetSystemWow64DirectoryA GetSystemWow64DirectoryW RaiseFailFastException |
| api-ms-win-core-kernel32-legacy-l1-1-1 | 7 | 8 | FindFirstVolumeMountPointW FindNextVolumeMountPointW FindVolumeMountPointClose GetFileAttributesTransactedW GetNumaAvailableMemoryNodeEx GetNumaNodeProcessorMask GetNumaProcessorNodeEx SetVolumeMountPointW |
| api-ms-win-core-kernel32-private-l1-1-0 | 6 | 11 | BaseSetLastNTError CheckElevation CheckElevationEnabled CompareCalendarDates DosPathToSessionPathW EnumerateLocalComputerNamesW GetCalendarMonthsInYear RegisterWaitForInputIdle RemoveLocalAlternateComputerNameW SetLocalPrimaryComputerNameW Wow64EnableWow64FsRedirection |
| api-ms-win-core-kernel32-private-l1-1-1 | 0 | 1 | PrivCopyFileExW |
| api-ms-win-core-libraryloader-l1-1-0 | 19 | 4 | AddDllDirectory FindStringOrdinal LoadStringA RemoveDllDirectory |
| api-ms-win-core-libraryloader-l1-1-1 | 0 | 6 | EnumResourceLanguagesExA EnumResourceLanguagesExW EnumResourceNamesExA EnumResourceNamesExW EnumResourceTypesExA EnumResourceTypesExW |
| api-ms-win-core-localization-l1-2-0 | 42 | 17 | EnumSystemGeoID FindNLSString FindNLSStringEx GetCalendarInfoEx GetFileMUIInfo GetFileMUIPath GetGeoInfoW GetNLSVersion GetNLSVersionEx GetThreadUILanguage GetUILanguageInfo GetUserGeoID IdnToAscii IdnToUnicode IsNLSDefinedString IsValidNLSVersion SetUserGeoID |
| api-ms-win-core-localization-l1-2-1 | 1 | 0 |  |
| api-ms-win-core-localization-obsolete-l1-2-0 | 8 | 2 | EnumLanguageGroupLocalesW EnumSystemLanguageGroupsW |
| api-ms-win-core-memory-l1-1-0 | 16 | 0 |  |
| api-ms-win-core-memory-l1-1-1 | 6 | 10 | CreateFileMappingFromApp CreateFileMappingNumaW CreateMemoryResourceNotification GetProcessWorkingSetSizeEx GetSystemFileCacheSize MapViewOfFileFromApp QueryMemoryResourceNotification SetProcessWorkingSetSizeEx SetSystemFileCacheSize UnmapViewOfFileEx |
| api-ms-win-core-memory-l1-1-2 | 1 | 10 | AllocateUserPhysicalPages AllocateUserPhysicalPagesNuma FreeUserPhysicalPages GetMemoryErrorHandlingCapabilities MapUserPhysicalPages OfferVirtualMemory ReclaimVirtualMemory RegisterBadMemoryNotification UnregisterBadMemoryNotification VirtualAllocExNuma |
| api-ms-win-core-namedpipe-l1-1-0 | 8 | 2 | GetNamedPipeClientComputerNameW ImpersonateNamedPipeClient |
| api-ms-win-core-privateprofile-l1-1-0 | 14 | 0 |  |
| api-ms-win-core-privateprofile-l1-1-1 | 2 | 0 |  |
| api-ms-win-core-processenvironment-l1-1-0 | 19 | 2 | SetEnvironmentStringsW SetStdHandleEx |
| api-ms-win-core-processenvironment-l1-2-0 | 1 | 2 | NeedCurrentDirectoryForExePathA NeedCurrentDirectoryForExePathW |
| api-ms-win-core-processthreads-l1-1-0 | 46 | 3 | CreateProcessAsUserW QueryProcessAffinityUpdateMode SetProcessAffinityUpdateMode |
| api-ms-win-core-processthreads-l1-1-1 | 12 | 2 | GetThreadIdealProcessorEx SetThreadIdealProcessorEx |
| api-ms-win-core-processthreads-l1-1-2 | 4 | 5 | GetSystemTimes GetThreadIOPendingFlag IsProcessCritical QueryProtectedPolicy SetProtectedPolicy |
| api-ms-win-core-processtopology-obsolete-l1-1-0 | 5 | 0 |  |
| api-ms-win-core-profile-l1-1-0 | 2 | 0 |  |
| api-ms-win-core-realtime-l1-1-0 | 3 | 2 | QueryIdleProcessorCycleTime QueryIdleProcessorCycleTimeEx |
| api-ms-win-core-registry-l1-1-0 | 29 | 14 | RegCopyTreeW RegDeleteKeyExA RegDeleteKeyExW RegDeleteTreeA RegDeleteTreeW RegDisablePredefinedCacheEx RegGetValueA RegGetValueW RegLoadAppKeyA RegLoadAppKeyW RegLoadMUIStringA RegLoadMUIStringW RegSaveKeyExA RegSaveKeyExW |
| api-ms-win-core-registry-l2-1-0 | 22 | 11 | RegCopyTreeA RegCreateKeyTransactedA RegCreateKeyTransactedW RegDeleteKeyTransactedA RegDeleteKeyTransactedW RegDeleteKeyValueA RegDeleteKeyValueW RegOpenKeyTransactedA RegOpenKeyTransactedW RegSetKeyValueA RegSetKeyValueW |
| api-ms-win-core-rtlsupport-l1-1-0 | 3 | 0 |  |
| api-ms-win-core-shlwapi-legacy-l1-1-0 | 72 | 16 | IsCharBlankW IsCharCntrlW IsCharDigitW IsCharPunctW IsCharSpaceA IsCharSpaceW IsCharXDigitW PathIsValidCharA PathIsValidCharW PathMatchSpecExA PathMatchSpecExW PathUnExpandEnvStringsA PathUnExpandEnvStringsW SHExpandEnvironmentStringsA SHExpandEnvironmentStringsW SHTruncateString |
| api-ms-win-core-shlwapi-obsolete-l1-1-0 | 41 | 20 | QISearch SHLoadIndirectString StrCatChainW StrChrNIW StrChrNW StrCmpCA StrCmpCW StrCmpICA StrCmpICW StrCmpLogicalW StrCmpNCA StrCmpNCW StrCmpNICA StrCmpNICW StrCpyNXA StrCpyNXW StrStrNIW StrStrNW StrToInt64ExA StrToInt64ExW |
| api-ms-win-core-shutdown-l1-1-0 | 2 | 0 |  |
| api-ms-win-core-string-l1-1-0 | 8 | 0 |  |
| api-ms-win-core-string-l2-1-0 | 10 | 0 |  |
| api-ms-win-core-string-obsolete-l1-1-0 | 10 | 0 |  |
| api-ms-win-core-stringansi-l1-1-0 | 12 | 0 |  |
| api-ms-win-core-stringloader-l1-1-1 | 2 | 0 |  |
| api-ms-win-core-synch-l1-1-0 | 35 | 6 | CreateEventExA CreateEventExW CreateMutexExA CreateMutexExW CreateSemaphoreExW SetWaitableTimerEx |
| api-ms-win-core-synch-l1-2-0 | 14 | 3 | DeleteSynchronizationBarrier EnterSynchronizationBarrier InitializeSynchronizationBarrier |
| api-ms-win-core-sysinfo-l1-1-0 | 22 | 0 |  |
| api-ms-win-core-sysinfo-l1-2-0 | 5 | 4 | EnumSystemFirmwareTables GetOsSafeBootMode GetSystemFirmwareTable SetComputerNameExW |
| api-ms-win-core-sysinfo-l1-2-1 | 1 | 4 | DnsHostnameToComputerNameExW GetPhysicallyInstalledSystemMemory InstallELAMCertificateInfo SetComputerNameEx2W |
| api-ms-win-core-threadpool-l1-2-0 | 0 | 37 | CallbackMayRunLong CancelThreadpoolIo CloseThreadpool CloseThreadpoolCleanupGroup CloseThreadpoolCleanupGroupMembers CloseThreadpoolIo CloseThreadpoolTimer CloseThreadpoolWait CloseThreadpoolWork CreateThreadpool CreateThreadpoolCleanupGroup CreateThreadpoolIo CreateThreadpoolTimer CreateThreadpoolWait CreateThreadpoolWork DisassociateCurrentThreadFromCallback FreeLibraryWhenCallbackReturns IsThreadpoolTimerSet LeaveCriticalSectionWhenCallbackReturns QueryThreadpoolStackInformation ReleaseMutexWhenCallbackReturns ReleaseSemaphoreWhenCallbackReturns SetEventWhenCallbackReturns SetThreadpoolStackInformation SetThreadpoolThreadMaximum SetThreadpoolThreadMinimum SetThreadpoolTimer SetThreadpoolTimerEx SetThreadpoolWait SetThreadpoolWaitEx StartThreadpoolIo SubmitThreadpoolWork TrySubmitThreadpoolCallback WaitForThreadpoolIoCallbacks WaitForThreadpoolTimerCallbacks WaitForThreadpoolWaitCallbacks WaitForThreadpoolWorkCallbacks |
| api-ms-win-core-threadpool-legacy-l1-1-0 | 7 | 0 |  |
| api-ms-win-core-threadpool-private-l1-1-0 | 1 | 0 |  |
| api-ms-win-core-timezone-l1-1-0 | 7 | 6 | EnumDynamicTimeZoneInformation GetDynamicTimeZoneInformationEffectiveYears GetTimeZoneInformationForYear SetDynamicTimeZoneInformation SystemTimeToTzSpecificLocalTimeEx TzSpecificLocalTimeToSystemTimeEx |
| api-ms-win-core-url-l1-1-0 | 31 | 7 | GetAcceptLanguagesA GetAcceptLanguagesW IsInternetESCEnabled ParseURLA ParseURLW PathCreateFromUrlAlloc UrlFixupW |
| api-ms-win-core-util-l1-1-0 | 5 | 0 |  |
| api-ms-win-core-version-l1-1-0 | 2 | 2 | GetFileVersionInfoExW GetFileVersionInfoSizeExW |
| api-ms-win-core-wow64-l1-1-0 | 1 | 2 | Wow64DisableWow64FsRedirection Wow64RevertWow64FsRedirection |
| api-ms-win-core-xstate-l1-1-0 | 0 | 8 | RtlCopyExtendedContext RtlGetEnabledExtendedFeatures RtlGetExtendedContextLength RtlGetExtendedFeaturesMask RtlInitializeExtendedContext RtlLocateExtendedFeature RtlLocateLegacyContext RtlSetExtendedFeaturesMask |
| api-ms-win-core-xstate-l2-1-0 | 0 | 6 | CopyContext GetEnabledXStateFeatures GetXStateFeaturesMask InitializeContext LocateXStateFeature SetXStateFeaturesMask |
| api-ms-win-devices-config-l1-1-0 | 0 | 38 | CM_Delete_Class_Key CM_Delete_DevNode_Key CM_Delete_Device_Interface_KeyW CM_Disable_DevNode CM_Enable_DevNode CM_Get_Child CM_Get_Class_PropertyW CM_Get_Class_Property_Keys CM_Get_Class_Registry_PropertyW CM_Get_Depth CM_Get_DevNode_PropertyW CM_Get_DevNode_Property_Keys CM_Get_DevNode_Registry_PropertyW CM_Get_DevNode_Status CM_Get_Device_IDW CM_Get_Device_ID_ListW CM_Get_Device_ID_List_SizeW CM_Get_Device_ID_Size CM_Get_Device_Interface_ListW CM_Get_Device_Interface_List_SizeW CM_Get_Device_Interface_PropertyW CM_Get_Device_Interface_Property_KeysW CM_Get_Parent CM_Get_Sibling CM_Locate_DevNodeW CM_Open_Class_KeyW CM_Open_DevNode_Key CM_Open_Device_Interface_KeyW CM_Query_And_Remove_SubTreeW CM_Register_Notification CM_Set_Class_PropertyW CM_Set_Class_Registry_PropertyW CM_Set_DevNode_PropertyW CM_Set_DevNode_Registry_PropertyW CM_Set_Device_Interface_PropertyW CM_Setup_DevNode CM_Uninstall_DevNode CM_Unregister_Notification |
| api-ms-win-devices-config-l1-1-1 | 0 | 39 | CM_Delete_Class_Key CM_Delete_DevNode_Key CM_Delete_Device_Interface_KeyW CM_Disable_DevNode CM_Enable_DevNode CM_Get_Child CM_Get_Class_PropertyW CM_Get_Class_Property_Keys CM_Get_Class_Registry_PropertyW CM_Get_Depth CM_Get_DevNode_PropertyW CM_Get_DevNode_Property_Keys CM_Get_DevNode_Registry_PropertyW CM_Get_DevNode_Status CM_Get_Device_IDW CM_Get_Device_ID_ListW CM_Get_Device_ID_List_SizeW CM_Get_Device_ID_Size CM_Get_Device_Interface_ListW CM_Get_Device_Interface_List_SizeW CM_Get_Device_Interface_PropertyW CM_Get_Device_Interface_Property_KeysW CM_Get_Parent CM_Get_Sibling CM_Locate_DevNodeW CM_MapCrToWin32Err CM_Open_Class_KeyW CM_Open_DevNode_Key CM_Open_Device_Interface_KeyW CM_Query_And_Remove_SubTreeW CM_Register_Notification CM_Set_Class_PropertyW CM_Set_Class_Registry_PropertyW CM_Set_DevNode_PropertyW CM_Set_DevNode_Registry_PropertyW CM_Set_Device_Interface_PropertyW CM_Setup_DevNode CM_Uninstall_DevNode CM_Unregister_Notification |
| api-ms-win-eventing-classicprovider-l1-1-0 | 1 | 7 | GetTraceEnableFlags GetTraceEnableLevel GetTraceLoggerHandle RegisterTraceGuidsW TraceEvent TraceMessageVa UnregisterTraceGuids |
| api-ms-win-eventing-consumer-l1-1-0 | 0 | 3 | CloseTrace OpenTraceW ProcessTrace |
| api-ms-win-eventing-controller-l1-1-0 | 0 | 11 | ControlTraceW EnableTraceEx2 EnumerateTraceGuidsEx EventAccessControl EventAccessQuery EventAccessRemove QueryAllTracesW StartTraceW StopTraceW TraceQueryInformation TraceSetInformation |
| api-ms-win-eventing-legacy-l1-1-0 | 0 | 14 | ControlTraceA EnableTrace EnableTraceEx EnumerateTraceGuids FlushTraceA FlushTraceW OpenTraceA QueryAllTracesA QueryTraceA QueryTraceW StartTraceA StopTraceA UpdateTraceA UpdateTraceW |
| api-ms-win-eventing-provider-l1-1-0 | 0 | 10 | EventActivityIdControl EventEnabled EventProviderEnabled EventRegister EventSetInformation EventUnregister EventWrite EventWriteEx EventWriteString EventWriteTransfer |
| api-ms-win-eventlog-legacy-l1-1-0 | 5 | 1 | GetEventLogInformation |
| api-ms-win-security-base-l1-1-0 | 70 | 27 | AccessCheckByType AccessCheckByTypeAndAuditAlarmW AccessCheckByTypeResultList AccessCheckByTypeResultListAndAuditAlarmByHandleW AccessCheckByTypeResultListAndAuditAlarmW AddAccessAllowedAceEx AddAccessAllowedObjectAce AddAccessDeniedAceEx AddAccessDeniedObjectAce AddAuditAccessAceEx AddAuditAccessObjectAce AddMandatoryAce ConvertToAutoInheritPrivateObjectSecurity CreatePrivateObjectSecurityEx CreatePrivateObjectSecurityWithMultipleInheritance EqualDomainSid GetSecurityDescriptorRMControl GetWindowsAccountDomainSid ImpersonateAnonymousToken IsTokenRestricted IsValidRelativeSecurityDescriptor MakeAbsoluteSD2 QuerySecurityAccessMask SetPrivateObjectSecurityEx SetSecurityAccessMask SetSecurityDescriptorControl SetSecurityDescriptorRMControl |
| api-ms-win-security-cryptoapi-l1-1-0 | 39 | 0 |  |
| api-ms-win-security-lsalookup-l2-1-0 | 5 | 1 | LsaEnumerateTrustedDomains |
| api-ms-win-security-lsalookup-l2-1-1 | 0 | 1 | LsaManageSidNameMapping |
| api-ms-win-security-lsapolicy-l1-1-0 | 4 | 18 | LsaAddAccountRights LsaCreateSecret LsaEnumerateAccountRights LsaEnumerateAccountsWithUserRight LsaFreeMemory LsaICLookupNames LsaICLookupNamesWithCreds LsaICLookupSids LsaICLookupSidsWithCreds LsaLookupNames2 LsaLookupSids LsaLookupSids2 LsaOpenSecret LsaQueryInformationPolicy LsaQuerySecret LsaRemoveAccountRights LsaSetInformationPolicy LsaSetSecret |
| api-ms-win-security-provider-l1-1-0 | 6 | 0 |  |
| api-ms-win-security-sddl-l1-1-0 | 4 | 0 |  |
| api-ms-win-service-core-l1-1-0 | 2 | 1 | RegisterServiceCtrlHandlerExW |
| api-ms-win-service-core-l1-1-1 | 2 | 1 | QueryServiceDynamicInformation |
| api-ms-win-service-management-l1-1-0 | 6 | 1 | ControlServiceExW |
| api-ms-win-service-management-l2-1-0 | 6 | 2 | NotifyServiceStatusChangeW QueryServiceConfig2W |
| api-ms-win-service-private-l1-1-0 | 0 | 17 | I_QueryTagInformation I_ScBroadcastServiceControlMessage I_ScIsSecurityProcess I_ScPnPGetServiceName I_ScQueryServiceConfig I_ScRegisterDeviceNotification I_ScRpcBindA I_ScRpcBindW I_ScSendPnPMessage I_ScSendTSMessage I_ScSetServiceBitsA I_ScSetServiceBitsW I_ScUnregisterDeviceNotification I_ScValidatePnPService SubscribeServiceChangeNotifications UnsubscribeServiceChangeNotifications WaitServiceState |
| api-ms-win-service-private-l1-1-1 | 0 | 18 | I_QueryTagInformation I_ScBroadcastServiceControlMessage I_ScIsSecurityProcess I_ScPnPGetServiceName I_ScQueryServiceConfig I_ScRegisterDeviceNotification I_ScRegisterPreshutdownRestart I_ScRpcBindA I_ScRpcBindW I_ScSendPnPMessage I_ScSendTSMessage I_ScSetServiceBitsA I_ScSetServiceBitsW I_ScUnregisterDeviceNotification I_ScValidatePnPService SubscribeServiceChangeNotifications UnsubscribeServiceChangeNotifications WaitServiceState |
| api-ms-win-service-winsvc-l1-1-0 | 12 | 14 | ControlServiceExA I_QueryTagInformation I_ScBroadcastServiceControlMessage I_ScIsSecurityProcess I_ScPnPGetServiceName I_ScQueryServiceConfig I_ScRpcBindA I_ScRpcBindW I_ScSendPnPMessage I_ScSendTSMessage I_ScValidatePnPService NotifyServiceStatusChangeA QueryServiceConfig2A RegisterServiceCtrlHandlerExA |
| api-ms-win-shcore-stream-l1-1-0 | 6 | 9 | IStream_Copy IStream_Read IStream_ReadStr IStream_Reset IStream_Size IStream_Write IStream_WriteStr SHCreateMemStream SHCreateStreamOnFileEx |
