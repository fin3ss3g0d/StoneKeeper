.data

.code

InvokeImage PROC 
	mov r10, rcx
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	jmp r10
	ret
InvokeImage ENDP
SyscallPrepare PROC
    xor r11, r11
    xor r10, r10
    mov r11, rcx
    mov r10, rdx
    ret
SyscallPrepare ENDP
SysNtAccessCheck PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheck ENDP
SysNtWorkerFactoryWorkerReady PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWorkerFactoryWorkerReady ENDP
SysNtAcceptConnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAcceptConnectPort ENDP
SysNtMapUserPhysicalPagesScatter PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMapUserPhysicalPagesScatter ENDP
SysNtWaitForSingleObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForSingleObject ENDP
SysNtCallbackReturn PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCallbackReturn ENDP
SysNtReadFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReadFile ENDP
SysNtDeviceIoControlFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeviceIoControlFile ENDP
SysNtWriteFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWriteFile ENDP
SysNtRemoveIoCompletion PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRemoveIoCompletion ENDP
SysNtReleaseSemaphore PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReleaseSemaphore ENDP
SysNtReplyWaitReceivePort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReplyWaitReceivePort ENDP
SysNtReplyPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReplyPort ENDP
SysNtSetInformationThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationThread ENDP
SysNtSetEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetEvent ENDP
SysNtClose PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtClose ENDP
SysNtQueryObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryObject ENDP
SysNtQueryInformationFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationFile ENDP
SysNtOpenKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenKey ENDP
SysNtEnumerateValueKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnumerateValueKey ENDP
SysNtFindAtom PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFindAtom ENDP
SysNtQueryDefaultLocale PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDefaultLocale ENDP
SysNtQueryKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryKey ENDP
SysNtQueryValueKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryValueKey ENDP
SysNtAllocateVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAllocateVirtualMemory ENDP
SysNtQueryInformationProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationProcess ENDP
SysNtWaitForMultipleObjects32 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForMultipleObjects32 ENDP
SysNtWriteFileGather PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWriteFileGather ENDP
SysNtCreateKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateKey ENDP
SysNtFreeVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFreeVirtualMemory ENDP
SysNtImpersonateClientOfPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtImpersonateClientOfPort ENDP
SysNtReleaseMutant PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReleaseMutant ENDP
SysNtQueryInformationToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationToken ENDP
SysNtRequestWaitReplyPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRequestWaitReplyPort ENDP
SysNtQueryVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryVirtualMemory ENDP
SysNtOpenThreadToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenThreadToken ENDP
SysNtQueryInformationThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationThread ENDP
SysNtOpenProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenProcess ENDP
SysNtSetInformationFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationFile ENDP
SysNtMapViewOfSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMapViewOfSection ENDP
SysNtAccessCheckAndAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheckAndAuditAlarm ENDP
SysNtUnmapViewOfSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnmapViewOfSection ENDP
SysNtReplyWaitReceivePortEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReplyWaitReceivePortEx ENDP
SysNtTerminateProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTerminateProcess ENDP
SysNtSetEventBoostPriority PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetEventBoostPriority ENDP
SysNtReadFileScatter PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReadFileScatter ENDP
SysNtOpenThreadTokenEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenThreadTokenEx ENDP
SysNtOpenProcessTokenEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenProcessTokenEx ENDP
SysNtQueryPerformanceCounter PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryPerformanceCounter ENDP
SysNtEnumerateKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnumerateKey ENDP
SysNtOpenFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenFile ENDP
SysNtDelayExecution PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDelayExecution ENDP
SysNtQueryDirectoryFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDirectoryFile ENDP
SysNtQuerySystemInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySystemInformation ENDP
SysNtOpenSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenSection ENDP
SysNtQueryTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryTimer ENDP
SysNtFsControlFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFsControlFile ENDP
SysNtWriteVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWriteVirtualMemory ENDP
SysNtCloseObjectAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCloseObjectAuditAlarm ENDP
SysNtDuplicateObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDuplicateObject ENDP
SysNtQueryAttributesFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryAttributesFile ENDP
SysNtClearEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtClearEvent ENDP
SysNtReadVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReadVirtualMemory ENDP
SysNtOpenEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenEvent ENDP
SysNtAdjustPrivilegesToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAdjustPrivilegesToken ENDP
SysNtDuplicateToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDuplicateToken ENDP
SysNtContinue PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtContinue ENDP
SysNtQueryDefaultUILanguage PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDefaultUILanguage ENDP
SysNtQueueApcThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueueApcThread ENDP
SysNtYieldExecution PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtYieldExecution ENDP
SysNtAddAtom PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAddAtom ENDP
SysNtCreateEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateEvent ENDP
SysNtQueryVolumeInformationFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryVolumeInformationFile ENDP
SysNtCreateSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateSection ENDP
SysNtFlushBuffersFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushBuffersFile ENDP
SysNtApphelpCacheControl PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtApphelpCacheControl ENDP
SysNtCreateProcessEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateProcessEx ENDP
SysNtCreateThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateThread ENDP
SysNtIsProcessInJob PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtIsProcessInJob ENDP
SysNtProtectVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtProtectVirtualMemory ENDP
SysNtQuerySection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySection ENDP
SysNtResumeThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtResumeThread ENDP
SysNtTerminateThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTerminateThread ENDP
SysNtReadRequestData PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReadRequestData ENDP
SysNtCreateFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateFile ENDP
SysNtQueryEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryEvent ENDP
SysNtWriteRequestData PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWriteRequestData ENDP
SysNtOpenDirectoryObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenDirectoryObject ENDP
SysNtAccessCheckByTypeAndAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheckByTypeAndAuditAlarm ENDP
SysNtWaitForMultipleObjects PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForMultipleObjects ENDP
SysNtSetInformationObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationObject ENDP
SysNtCancelIoFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCancelIoFile ENDP
SysNtTraceEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTraceEvent ENDP
SysNtPowerInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPowerInformation ENDP
SysNtSetValueKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetValueKey ENDP
SysNtCancelTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCancelTimer ENDP
SysNtSetTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetTimer ENDP
SysNtAccessCheckByType PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheckByType ENDP
SysNtAccessCheckByTypeResultList PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheckByTypeResultList ENDP
SysNtAccessCheckByTypeResultListAndAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheckByTypeResultListAndAuditAlarm ENDP
SysNtAccessCheckByTypeResultListAndAuditAlarmByHandle PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAccessCheckByTypeResultListAndAuditAlarmByHandle ENDP
SysNtAcquireProcessActivityReference PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAcquireProcessActivityReference ENDP
SysNtAddAtomEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAddAtomEx ENDP
SysNtAddBootEntry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAddBootEntry ENDP
SysNtAddDriverEntry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAddDriverEntry ENDP
SysNtAdjustGroupsToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAdjustGroupsToken ENDP
SysNtAdjustTokenClaimsAndDeviceGroups PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAdjustTokenClaimsAndDeviceGroups ENDP
SysNtAlertResumeThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlertResumeThread ENDP
SysNtAlertThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlertThread ENDP
SysNtAlertThreadByThreadId PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlertThreadByThreadId ENDP
SysNtAllocateLocallyUniqueId PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAllocateLocallyUniqueId ENDP
SysNtAllocateReserveObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAllocateReserveObject ENDP
SysNtAllocateUserPhysicalPages PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAllocateUserPhysicalPages ENDP
SysNtAllocateUuids PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAllocateUuids ENDP
SysNtAllocateVirtualMemoryEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAllocateVirtualMemoryEx ENDP
SysNtAlpcAcceptConnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcAcceptConnectPort ENDP
SysNtAlpcCancelMessage PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcCancelMessage ENDP
SysNtAlpcConnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcConnectPort ENDP
SysNtAlpcConnectPortEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcConnectPortEx ENDP
SysNtAlpcCreatePort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcCreatePort ENDP
SysNtAlpcCreatePortSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcCreatePortSection ENDP
SysNtAlpcCreateResourceReserve PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcCreateResourceReserve ENDP
SysNtAlpcCreateSectionView PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcCreateSectionView ENDP
SysNtAlpcCreateSecurityContext PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcCreateSecurityContext ENDP
SysNtAlpcDeletePortSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcDeletePortSection ENDP
SysNtAlpcDeleteResourceReserve PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcDeleteResourceReserve ENDP
SysNtAlpcDeleteSectionView PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcDeleteSectionView ENDP
SysNtAlpcDeleteSecurityContext PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcDeleteSecurityContext ENDP
SysNtAlpcDisconnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcDisconnectPort ENDP
SysNtAlpcImpersonateClientContainerOfPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcImpersonateClientContainerOfPort ENDP
SysNtAlpcImpersonateClientOfPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcImpersonateClientOfPort ENDP
SysNtAlpcOpenSenderProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcOpenSenderProcess ENDP
SysNtAlpcOpenSenderThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcOpenSenderThread ENDP
SysNtAlpcQueryInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcQueryInformation ENDP
SysNtAlpcQueryInformationMessage PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcQueryInformationMessage ENDP
SysNtAlpcRevokeSecurityContext PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcRevokeSecurityContext ENDP
SysNtAlpcSendWaitReceivePort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcSendWaitReceivePort ENDP
SysNtAlpcSetInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAlpcSetInformation ENDP
SysNtAreMappedFilesTheSame PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAreMappedFilesTheSame ENDP
SysNtAssignProcessToJobObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAssignProcessToJobObject ENDP
SysNtAssociateWaitCompletionPacket PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtAssociateWaitCompletionPacket ENDP
SysNtCallEnclave PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCallEnclave ENDP
SysNtCancelIoFileEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCancelIoFileEx ENDP
SysNtCancelSynchronousIoFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCancelSynchronousIoFile ENDP
SysNtCancelTimer2 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCancelTimer2 ENDP
SysNtCancelWaitCompletionPacket PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCancelWaitCompletionPacket ENDP
SysNtCommitComplete PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCommitComplete ENDP
SysNtCommitEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCommitEnlistment ENDP
SysNtCommitRegistryTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCommitRegistryTransaction ENDP
SysNtCommitTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCommitTransaction ENDP
SysNtCompactKeys PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCompactKeys ENDP
SysNtCompareObjects PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCompareObjects ENDP
SysNtCompareSigningLevels PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCompareSigningLevels ENDP
SysNtCompareTokens PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCompareTokens ENDP
SysNtCompleteConnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCompleteConnectPort ENDP
SysNtCompressKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCompressKey ENDP
SysNtConnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtConnectPort ENDP
SysNtConvertBetweenAuxiliaryCounterAndPerformanceCounter PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtConvertBetweenAuxiliaryCounterAndPerformanceCounter ENDP
SysNtCreateDebugObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateDebugObject ENDP
SysNtCreateDirectoryObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateDirectoryObject ENDP
SysNtCreateDirectoryObjectEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateDirectoryObjectEx ENDP
SysNtCreateEnclave PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateEnclave ENDP
SysNtCreateEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateEnlistment ENDP
SysNtCreateEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateEventPair ENDP
SysNtCreateIRTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateIRTimer ENDP
SysNtCreateIoCompletion PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateIoCompletion ENDP
SysNtCreateJobObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateJobObject ENDP
SysNtCreateJobSet PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateJobSet ENDP
SysNtCreateKeyTransacted PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateKeyTransacted ENDP
SysNtCreateKeyedEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateKeyedEvent ENDP
SysNtCreateLowBoxToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateLowBoxToken ENDP
SysNtCreateMailslotFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateMailslotFile ENDP
SysNtCreateMutant PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateMutant ENDP
SysNtCreateNamedPipeFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateNamedPipeFile ENDP
SysNtCreatePagingFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreatePagingFile ENDP
SysNtCreatePartition PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreatePartition ENDP
SysNtCreatePort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreatePort ENDP
SysNtCreatePrivateNamespace PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreatePrivateNamespace ENDP
SysNtCreateProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateProcess ENDP
SysNtCreateProfile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateProfile ENDP
SysNtCreateProfileEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateProfileEx ENDP
SysNtCreateRegistryTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateRegistryTransaction ENDP
SysNtCreateResourceManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateResourceManager ENDP
SysNtCreateSemaphore PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateSemaphore ENDP
SysNtCreateSymbolicLinkObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateSymbolicLinkObject ENDP
SysNtCreateThreadEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateThreadEx ENDP
SysNtCreateTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateTimer ENDP
SysNtCreateTimer2 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateTimer2 ENDP
SysNtCreateToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateToken ENDP
SysNtCreateTokenEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateTokenEx ENDP
SysNtCreateTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateTransaction ENDP
SysNtCreateTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateTransactionManager ENDP
SysNtCreateUserProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateUserProcess ENDP
SysNtCreateWaitCompletionPacket PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateWaitCompletionPacket ENDP
SysNtCreateWaitablePort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateWaitablePort ENDP
SysNtCreateWnfStateName PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateWnfStateName ENDP
SysNtCreateWorkerFactory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateWorkerFactory ENDP
SysNtDebugActiveProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDebugActiveProcess ENDP
SysNtDebugContinue PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDebugContinue ENDP
SysNtDeleteAtom PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteAtom ENDP
SysNtDeleteBootEntry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteBootEntry ENDP
SysNtDeleteDriverEntry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteDriverEntry ENDP
SysNtDeleteFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteFile ENDP
SysNtDeleteKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteKey ENDP
SysNtDeleteObjectAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteObjectAuditAlarm ENDP
SysNtDeletePrivateNamespace PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeletePrivateNamespace ENDP
SysNtDeleteValueKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteValueKey ENDP
SysNtDeleteWnfStateData PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteWnfStateData ENDP
SysNtDeleteWnfStateName PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDeleteWnfStateName ENDP
SysNtDisableLastKnownGood PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDisableLastKnownGood ENDP
SysNtDisplayString PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDisplayString ENDP
SysNtDrawText PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtDrawText ENDP
SysNtEnableLastKnownGood PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnableLastKnownGood ENDP
SysNtEnumerateBootEntries PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnumerateBootEntries ENDP
SysNtEnumerateDriverEntries PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnumerateDriverEntries ENDP
SysNtEnumerateSystemEnvironmentValuesEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnumerateSystemEnvironmentValuesEx ENDP
SysNtEnumerateTransactionObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtEnumerateTransactionObject ENDP
SysNtExtendSection PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtExtendSection ENDP
SysNtFilterBootOption PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFilterBootOption ENDP
SysNtFilterToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFilterToken ENDP
SysNtFilterTokenEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFilterTokenEx ENDP
SysNtFlushBuffersFileEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushBuffersFileEx ENDP
SysNtFlushInstallUILanguage PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushInstallUILanguage ENDP
SysNtFlushInstructionCache PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushInstructionCache ENDP
SysNtFlushKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushKey ENDP
SysNtFlushProcessWriteBuffers PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushProcessWriteBuffers ENDP
SysNtFlushVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushVirtualMemory ENDP
SysNtFlushWriteBuffer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFlushWriteBuffer ENDP
SysNtFreeUserPhysicalPages PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFreeUserPhysicalPages ENDP
SysNtFreezeRegistry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFreezeRegistry ENDP
SysNtFreezeTransactions PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtFreezeTransactions ENDP
SysNtGetCachedSigningLevel PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetCachedSigningLevel ENDP
SysNtGetCompleteWnfStateSubscription PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetCompleteWnfStateSubscription ENDP
SysNtGetContextThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetContextThread ENDP
SysNtGetCurrentProcessorNumber PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetCurrentProcessorNumber ENDP
SysNtGetCurrentProcessorNumberEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetCurrentProcessorNumberEx ENDP
SysNtGetDevicePowerState PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetDevicePowerState ENDP
SysNtGetMUIRegistryInfo PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetMUIRegistryInfo ENDP
SysNtGetNextProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetNextProcess ENDP
SysNtGetNextThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetNextThread ENDP
SysNtGetNlsSectionPtr PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetNlsSectionPtr ENDP
SysNtGetNotificationResourceManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetNotificationResourceManager ENDP
SysNtGetWriteWatch PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtGetWriteWatch ENDP
SysNtImpersonateAnonymousToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtImpersonateAnonymousToken ENDP
SysNtImpersonateThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtImpersonateThread ENDP
SysNtInitializeEnclave PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtInitializeEnclave ENDP
SysNtInitializeNlsFiles PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtInitializeNlsFiles ENDP
SysNtInitializeRegistry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtInitializeRegistry ENDP
SysNtInitiatePowerAction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtInitiatePowerAction ENDP
SysNtIsSystemResumeAutomatic PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtIsSystemResumeAutomatic ENDP
SysNtIsUILanguageComitted PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtIsUILanguageComitted ENDP
SysNtListenPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtListenPort ENDP
SysNtLoadDriver PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLoadDriver ENDP
SysNtLoadEnclaveData PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLoadEnclaveData ENDP
SysNtLoadKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLoadKey ENDP
SysNtLoadKey2 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLoadKey2 ENDP
SysNtLoadKeyEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLoadKeyEx ENDP
SysNtLockFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLockFile ENDP
SysNtLockProductActivationKeys PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLockProductActivationKeys ENDP
SysNtLockRegistryKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLockRegistryKey ENDP
SysNtLockVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtLockVirtualMemory ENDP
SysNtMakePermanentObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMakePermanentObject ENDP
SysNtMakeTemporaryObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMakeTemporaryObject ENDP
SysNtManagePartition PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtManagePartition ENDP
SysNtMapCMFModule PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMapCMFModule ENDP
SysNtMapUserPhysicalPages PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMapUserPhysicalPages ENDP
SysNtMapViewOfSectionEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtMapViewOfSectionEx ENDP
SysNtModifyBootEntry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtModifyBootEntry ENDP
SysNtModifyDriverEntry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtModifyDriverEntry ENDP
SysNtNotifyChangeDirectoryFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtNotifyChangeDirectoryFile ENDP
SysNtNotifyChangeDirectoryFileEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtNotifyChangeDirectoryFileEx ENDP
SysNtNotifyChangeKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtNotifyChangeKey ENDP
SysNtNotifyChangeMultipleKeys PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtNotifyChangeMultipleKeys ENDP
SysNtNotifyChangeSession PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtNotifyChangeSession ENDP
SysNtOpenEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenEnlistment ENDP
SysNtOpenEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenEventPair ENDP
SysNtOpenIoCompletion PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenIoCompletion ENDP
SysNtOpenJobObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenJobObject ENDP
SysNtOpenKeyEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenKeyEx ENDP
SysNtOpenKeyTransacted PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenKeyTransacted ENDP
SysNtOpenKeyTransactedEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenKeyTransactedEx ENDP
SysNtOpenKeyedEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenKeyedEvent ENDP
SysNtOpenMutant PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenMutant ENDP
SysNtOpenObjectAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenObjectAuditAlarm ENDP
SysNtOpenPartition PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenPartition ENDP
SysNtOpenPrivateNamespace PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenPrivateNamespace ENDP
SysNtOpenProcessToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenProcessToken ENDP
SysNtOpenRegistryTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenRegistryTransaction ENDP
SysNtOpenResourceManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenResourceManager ENDP
SysNtOpenSemaphore PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenSemaphore ENDP
SysNtOpenSession PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenSession ENDP
SysNtOpenSymbolicLinkObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenSymbolicLinkObject ENDP
SysNtOpenThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenThread ENDP
SysNtOpenTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenTimer ENDP
SysNtOpenTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenTransaction ENDP
SysNtOpenTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtOpenTransactionManager ENDP
SysNtPlugPlayControl PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPlugPlayControl ENDP
SysNtPrePrepareComplete PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrePrepareComplete ENDP
SysNtPrePrepareEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrePrepareEnlistment ENDP
SysNtPrepareComplete PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrepareComplete ENDP
SysNtPrepareEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrepareEnlistment ENDP
SysNtPrivilegeCheck PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrivilegeCheck ENDP
SysNtPrivilegeObjectAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrivilegeObjectAuditAlarm ENDP
SysNtPrivilegedServiceAuditAlarm PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPrivilegedServiceAuditAlarm ENDP
SysNtPropagationComplete PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPropagationComplete ENDP
SysNtPropagationFailed PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPropagationFailed ENDP
SysNtPulseEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtPulseEvent ENDP
SysNtQueryAuxiliaryCounterFrequency PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryAuxiliaryCounterFrequency ENDP
SysNtQueryBootEntryOrder PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryBootEntryOrder ENDP
SysNtQueryBootOptions PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryBootOptions ENDP
SysNtQueryDebugFilterState PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDebugFilterState ENDP
SysNtQueryDirectoryFileEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDirectoryFileEx ENDP
SysNtQueryDirectoryObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDirectoryObject ENDP
SysNtQueryDriverEntryOrder PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryDriverEntryOrder ENDP
SysNtQueryEaFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryEaFile ENDP
SysNtQueryFullAttributesFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryFullAttributesFile ENDP
SysNtQueryInformationAtom PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationAtom ENDP
SysNtQueryInformationByName PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationByName ENDP
SysNtQueryInformationEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationEnlistment ENDP
SysNtQueryInformationJobObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationJobObject ENDP
SysNtQueryInformationPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationPort ENDP
SysNtQueryInformationResourceManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationResourceManager ENDP
SysNtQueryInformationTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationTransaction ENDP
SysNtQueryInformationTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationTransactionManager ENDP
SysNtQueryInformationWorkerFactory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInformationWorkerFactory ENDP
SysNtQueryInstallUILanguage PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryInstallUILanguage ENDP
SysNtQueryIntervalProfile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryIntervalProfile ENDP
SysNtQueryIoCompletion PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryIoCompletion ENDP
SysNtQueryLicenseValue PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryLicenseValue ENDP
SysNtQueryMultipleValueKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryMultipleValueKey ENDP
SysNtQueryMutant PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryMutant ENDP
SysNtQueryOpenSubKeys PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryOpenSubKeys ENDP
SysNtQueryOpenSubKeysEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryOpenSubKeysEx ENDP
SysNtQueryPortInformationProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryPortInformationProcess ENDP
SysNtQueryQuotaInformationFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryQuotaInformationFile ENDP
SysNtQuerySecurityAttributesToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySecurityAttributesToken ENDP
SysNtQuerySecurityObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySecurityObject ENDP
SysNtQuerySecurityPolicy PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySecurityPolicy ENDP
SysNtQuerySemaphore PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySemaphore ENDP
SysNtQuerySymbolicLinkObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySymbolicLinkObject ENDP
SysNtQuerySystemEnvironmentValue PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySystemEnvironmentValue ENDP
SysNtQuerySystemEnvironmentValueEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySystemEnvironmentValueEx ENDP
SysNtQuerySystemInformationEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQuerySystemInformationEx ENDP
SysNtQueryTimerResolution PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryTimerResolution ENDP
SysNtQueryWnfStateData PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryWnfStateData ENDP
SysNtQueryWnfStateNameInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueryWnfStateNameInformation ENDP
SysNtQueueApcThreadEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtQueueApcThreadEx ENDP
SysNtRaiseException PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRaiseException ENDP
SysNtRaiseHardError PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRaiseHardError ENDP
SysNtReadOnlyEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReadOnlyEnlistment ENDP
SysNtRecoverEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRecoverEnlistment ENDP
SysNtRecoverResourceManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRecoverResourceManager ENDP
SysNtRecoverTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRecoverTransactionManager ENDP
SysNtRegisterProtocolAddressInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRegisterProtocolAddressInformation ENDP
SysNtRegisterThreadTerminatePort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRegisterThreadTerminatePort ENDP
SysNtReleaseKeyedEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReleaseKeyedEvent ENDP
SysNtReleaseWorkerFactoryWorker PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReleaseWorkerFactoryWorker ENDP
SysNtRemoveIoCompletionEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRemoveIoCompletionEx ENDP
SysNtRemoveProcessDebug PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRemoveProcessDebug ENDP
SysNtRenameKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRenameKey ENDP
SysNtRenameTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRenameTransactionManager ENDP
SysNtReplaceKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReplaceKey ENDP
SysNtReplacePartitionUnit PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReplacePartitionUnit ENDP
SysNtReplyWaitReplyPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtReplyWaitReplyPort ENDP
SysNtRequestPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRequestPort ENDP
SysNtResetEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtResetEvent ENDP
SysNtResetWriteWatch PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtResetWriteWatch ENDP
SysNtRestoreKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRestoreKey ENDP
SysNtResumeProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtResumeProcess ENDP
SysNtRevertContainerImpersonation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRevertContainerImpersonation ENDP
SysNtRollbackComplete PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRollbackComplete ENDP
SysNtRollbackEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRollbackEnlistment ENDP
SysNtRollbackRegistryTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRollbackRegistryTransaction ENDP
SysNtRollbackTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRollbackTransaction ENDP
SysNtRollforwardTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtRollforwardTransactionManager ENDP
SysNtSaveKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSaveKey ENDP
SysNtSaveKeyEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSaveKeyEx ENDP
SysNtSaveMergedKeys PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSaveMergedKeys ENDP
SysNtSecureConnectPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSecureConnectPort ENDP
SysNtSerializeBoot PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSerializeBoot ENDP
SysNtSetBootEntryOrder PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetBootEntryOrder ENDP
SysNtSetBootOptions PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetBootOptions ENDP
SysNtSetCachedSigningLevel PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetCachedSigningLevel ENDP
SysNtSetCachedSigningLevel2 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetCachedSigningLevel2 ENDP
SysNtSetContextThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetContextThread ENDP
SysNtSetDebugFilterState PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetDebugFilterState ENDP
SysNtSetDefaultHardErrorPort PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetDefaultHardErrorPort ENDP
SysNtSetDefaultLocale PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetDefaultLocale ENDP
SysNtSetDefaultUILanguage PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetDefaultUILanguage ENDP
SysNtSetDriverEntryOrder PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetDriverEntryOrder ENDP
SysNtSetEaFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetEaFile ENDP
SysNtSetHighEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetHighEventPair ENDP
SysNtSetHighWaitLowEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetHighWaitLowEventPair ENDP
SysNtSetIRTimer PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetIRTimer ENDP
SysNtSetInformationDebugObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationDebugObject ENDP
SysNtSetInformationEnlistment PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationEnlistment ENDP
SysNtSetInformationJobObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationJobObject ENDP
SysNtSetInformationKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationKey ENDP
SysNtSetInformationResourceManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationResourceManager ENDP
SysNtSetInformationSymbolicLink PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationSymbolicLink ENDP
SysNtSetInformationToken PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationToken ENDP
SysNtSetInformationTransaction PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationTransaction ENDP
SysNtSetInformationTransactionManager PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationTransactionManager ENDP
SysNtSetInformationVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationVirtualMemory ENDP
SysNtSetInformationWorkerFactory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationWorkerFactory ENDP
SysNtSetIntervalProfile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetIntervalProfile ENDP
SysNtSetIoCompletion PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetIoCompletion ENDP
SysNtSetIoCompletionEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetIoCompletionEx ENDP
SysNtSetLdtEntries PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetLdtEntries ENDP
SysNtSetLowEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetLowEventPair ENDP
SysNtSetLowWaitHighEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetLowWaitHighEventPair ENDP
SysNtSetQuotaInformationFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetQuotaInformationFile ENDP
SysNtSetSecurityObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetSecurityObject ENDP
SysNtSetSystemEnvironmentValue PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetSystemEnvironmentValue ENDP
SysNtSetSystemEnvironmentValueEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetSystemEnvironmentValueEx ENDP
SysNtSetSystemInformation PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetSystemInformation ENDP
SysNtSetSystemPowerState PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetSystemPowerState ENDP
SysNtSetSystemTime PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetSystemTime ENDP
SysNtSetThreadExecutionState PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetThreadExecutionState ENDP
SysNtSetTimer2 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetTimer2 ENDP
SysNtSetTimerEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetTimerEx ENDP
SysNtSetTimerResolution PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetTimerResolution ENDP
SysNtSetUuidSeed PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetUuidSeed ENDP
SysNtSetVolumeInformationFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetVolumeInformationFile ENDP
SysNtSetWnfProcessNotificationEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetWnfProcessNotificationEvent ENDP
SysNtShutdownSystem PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtShutdownSystem ENDP
SysNtShutdownWorkerFactory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtShutdownWorkerFactory ENDP
SysNtSignalAndWaitForSingleObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSignalAndWaitForSingleObject ENDP
SysNtSinglePhaseReject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSinglePhaseReject ENDP
SysNtStartProfile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtStartProfile ENDP
SysNtStopProfile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtStopProfile ENDP
SysNtSubscribeWnfStateChange PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSubscribeWnfStateChange ENDP
SysNtSuspendProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSuspendProcess ENDP
SysNtSuspendThread PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSuspendThread ENDP
SysNtSystemDebugControl PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSystemDebugControl ENDP
SysNtTerminateEnclave PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTerminateEnclave ENDP
SysNtTerminateJobObject PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTerminateJobObject ENDP
SysNtTestAlert PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTestAlert ENDP
SysNtThawRegistry PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtThawRegistry ENDP
SysNtThawTransactions PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtThawTransactions ENDP
SysNtTraceControl PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTraceControl ENDP
SysNtTranslateFilePath PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtTranslateFilePath ENDP
SysNtUmsThreadYield PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUmsThreadYield ENDP
SysNtUnloadDriver PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnloadDriver ENDP
SysNtUnloadKey PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnloadKey ENDP
SysNtUnloadKey2 PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnloadKey2 ENDP
SysNtUnloadKeyEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnloadKeyEx ENDP
SysNtUnlockFile PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnlockFile ENDP
SysNtUnlockVirtualMemory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnlockVirtualMemory ENDP
SysNtUnmapViewOfSectionEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnmapViewOfSectionEx ENDP
SysNtUnsubscribeWnfStateChange PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUnsubscribeWnfStateChange ENDP
SysNtUpdateWnfStateData PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtUpdateWnfStateData ENDP
SysNtVdmControl PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtVdmControl ENDP
SysNtWaitForAlertByThreadId PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForAlertByThreadId ENDP
SysNtWaitForDebugEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForDebugEvent ENDP
SysNtWaitForKeyedEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForKeyedEvent ENDP
SysNtWaitForWorkViaWorkerFactory PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitForWorkViaWorkerFactory ENDP
SysNtWaitHighEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitHighEventPair ENDP
SysNtWaitLowEventPair PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtWaitLowEventPair ENDP
SysNtCreateSectionEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateSectionEx ENDP
SysNtCreateCrossVmEvent PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtCreateCrossVmEvent ENDP
SysNtSetInformationProcess PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtSetInformationProcess ENDP
SysNtManageHotPatch PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtManageHotPatch ENDP
SysNtContinueEx PROC
    push r10
    xor rax, rax
    mov r10, rcx
    mov eax, r11d
    ret
SysNtContinueEx ENDP

END
