#include "Syscalls.hpp"
#include "Instance.hpp"

// Define storage for static members
PPEB SystemCalls::Peb = nullptr;
VX_TABLE SystemCalls::SysTable = {};

unsigned long SystemCalls::djb2_unicode(const wchar_t* str) {
    unsigned long hash = 5381;
    DWORD val;
    while (*str != 0) {
        val = (DWORD)*str++;
        hash = ((hash << 5) + hash) + val;
    }
    return hash;
}

unsigned long SystemCalls::djb2(unsigned char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

unsigned long SystemCalls::xor_hash(unsigned long hash) {
    return hash ^ XORKEY;
}

WCHAR* SystemCalls::toLower(WCHAR* str) {
    WCHAR* start = str;
    while (*str) {
        if (*str <= L'Z' && *str >= 'A') {
            *str += 32;
        }
        str += 1;
    }
    return start;
}

BOOL SystemCalls::ResolveSyscall(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD dwCryptedHash, PSYSCALL pSyscall) {
    pSyscall->dwCryptedHash = dwCryptedHash;
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
    BYTE cleanStart[] = { 0x4c, 0x8b, 0xd1, 0xb8 };
    BYTE syscallMatch[] = { 0x0f, 0x05, 0xc3 };
    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PBYTE pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]]; // Change type to PBYTE
        if (djb2(reinterpret_cast<unsigned char*>(pczFunctionName)) == xor_hash(dwCryptedHash)) {
            if (Instance::memcmp(pFunctionAddress, cleanStart, 4) == 0 && Instance::memcmp(pFunctionAddress + 18, syscallMatch, 3) == 0) {
                BYTE high = *((PBYTE)pFunctionAddress + 5);
                BYTE low = *((PBYTE)pFunctionAddress + 4);
                pSyscall->wSyscallNr = (high << 8) | low;
                pSyscall->pRecycled = pFunctionAddress + 18;
#ifdef DEBUG
                printf("[*] Found clean stub start for %s! Byte: %x Num: %lu\n", pczFunctionName, *((PBYTE)pFunctionAddress + 18), pSyscall->wSyscallNr);
#endif
                return TRUE;
            }
            else {
#ifdef DEBUG
                printf("[*] %s hooked!\n", pczFunctionName);
#endif
                for (WORD idx = 1; idx <= 500; idx++) {
                    if (Instance::memcmp(pFunctionAddress + idx * DOWN, cleanStart, 4) == 0 && Instance::memcmp(pFunctionAddress + idx * DOWN + 18, syscallMatch, 3) == 0) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                        pSyscall->wSyscallNr = (high << 8) | low - idx;
                        pSyscall->pRecycled = pFunctionAddress + idx * DOWN + 18;
#ifdef DEBUG
                        printf("    -> Found num for %s using DOWN after %d jumps! Num: %lu\n", pczFunctionName, idx, pSyscall->wSyscallNr);
#endif
                        return TRUE;
                    }
                    if (Instance::memcmp(pFunctionAddress + idx * UP, cleanStart, 4) == 0 && Instance::memcmp(pFunctionAddress + idx * UP + 18, syscallMatch, 3) == 0) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * UP);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * UP);
                        pSyscall->wSyscallNr = (high << 8) | low + idx;
                        pSyscall->pRecycled = pFunctionAddress + idx * UP + 18;
#ifdef DEBUG
                        printf("    -> Found num for %s using UP after %d jumps! Num: %lu\n", pczFunctionName, idx, pSyscall->wSyscallNr);
#endif
                        return TRUE;
                    }
                }
                return FALSE;
            }
        }
    }
    return TRUE;
}

void SystemCalls::ResolveSyscallTable() {
    VX_TABLE Table = { 0 };
    PUNICODE_STRING pDllName = NULL, pFullDllName = NULL;
    PVOID pNtdllBase = NULL;
    PPEB_LDR_DATA LdrData = NULL;
    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
    LdrData = Peb->Ldr;

    pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)LdrData->InLoadOrderModuleList.Flink;

    do {
        pDllName = &pModuleEntry->BaseDllName;
        pFullDllName = &pModuleEntry->FullDllName;
        if (pDllName->Buffer == NULL) {
            continue;
        }
        if (djb2_unicode(toLower(pDllName->Buffer)) == xor_hash(NTDLLDLL_HASH)) {
#ifdef DEBUG
            printf("[+] Got module for table resolution!\n");
#endif
            pNtdllBase = (PVOID)pModuleEntry->DllBase;
            break;
        }
        pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;
    } while (pModuleEntry != pModuleStart);

    PIMAGE_DOS_HEADER pInMemImageDosHeader = (PIMAGE_DOS_HEADER)pNtdllBase;

    if (pInMemImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        Table.isResolved = FALSE;
    }

    PIMAGE_NT_HEADERS pInMemImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBase + pInMemImageDosHeader->e_lfanew);
    if (pInMemImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Table.isResolved = FALSE;
    }

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pNtdllBase + pInMemImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECK_HASH, &Table.SysNtAccessCheck);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWORKERFACTORYWORKERREADY_HASH, &Table.SysNtWorkerFactoryWorkerReady);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCEPTCONNECTPORT_HASH, &Table.SysNtAcceptConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAPUSERPHYSICALPAGESSCATTER_HASH, &Table.SysNtMapUserPhysicalPagesScatter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORSINGLEOBJECT_HASH, &Table.SysNtWaitForSingleObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCALLBACKRETURN_HASH, &Table.SysNtCallbackReturn);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREADFILE_HASH, &Table.SysNtReadFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDEVICEIOCONTROLFILE_HASH, &Table.SysNtDeviceIoControlFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWRITEFILE_HASH, &Table.SysNtWriteFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREMOVEIOCOMPLETION_HASH, &Table.SysNtRemoveIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRELEASESEMAPHORE_HASH, &Table.SysNtReleaseSemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREPLYWAITRECEIVEPORT_HASH, &Table.SysNtReplyWaitReceivePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREPLYPORT_HASH, &Table.SysNtReplyPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONTHREAD_HASH, &Table.SysNtSetInformationThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETEVENT_HASH, &Table.SysNtSetEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCLOSE_HASH, &Table.SysNtClose);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYOBJECT_HASH, &Table.SysNtQueryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONFILE_HASH, &Table.SysNtQueryInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENKEY_HASH, &Table.SysNtOpenKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENUMERATEVALUEKEY_HASH, &Table.SysNtEnumerateValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFINDATOM_HASH, &Table.SysNtFindAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDEFAULTLOCALE_HASH, &Table.SysNtQueryDefaultLocale);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYKEY_HASH, &Table.SysNtQueryKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYVALUEKEY_HASH, &Table.SysNtQueryValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALLOCATEVIRTUALMEMORY_HASH, &Table.SysNtAllocateVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONPROCESS_HASH, &Table.SysNtQueryInformationProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORMULTIPLEOBJECTS32_HASH, &Table.SysNtWaitForMultipleObjects32);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWRITEFILEGATHER_HASH, &Table.SysNtWriteFileGather);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEKEY_HASH, &Table.SysNtCreateKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFREEVIRTUALMEMORY_HASH, &Table.SysNtFreeVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTIMPERSONATECLIENTOFPORT_HASH, &Table.SysNtImpersonateClientOfPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRELEASEMUTANT_HASH, &Table.SysNtReleaseMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONTOKEN_HASH, &Table.SysNtQueryInformationToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREQUESTWAITREPLYPORT_HASH, &Table.SysNtRequestWaitReplyPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYVIRTUALMEMORY_HASH, &Table.SysNtQueryVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENTHREADTOKEN_HASH, &Table.SysNtOpenThreadToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONTHREAD_HASH, &Table.SysNtQueryInformationThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENPROCESS_HASH, &Table.SysNtOpenProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONFILE_HASH, &Table.SysNtSetInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAPVIEWOFSECTION_HASH, &Table.SysNtMapViewOfSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECKANDAUDITALARM_HASH, &Table.SysNtAccessCheckAndAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNMAPVIEWOFSECTION_HASH, &Table.SysNtUnmapViewOfSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREPLYWAITRECEIVEPORTEX_HASH, &Table.SysNtReplyWaitReceivePortEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTERMINATEPROCESS_HASH, &Table.SysNtTerminateProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETEVENTBOOSTPRIORITY_HASH, &Table.SysNtSetEventBoostPriority);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREADFILESCATTER_HASH, &Table.SysNtReadFileScatter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENTHREADTOKENEX_HASH, &Table.SysNtOpenThreadTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENPROCESSTOKENEX_HASH, &Table.SysNtOpenProcessTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYPERFORMANCECOUNTER_HASH, &Table.SysNtQueryPerformanceCounter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENUMERATEKEY_HASH, &Table.SysNtEnumerateKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENFILE_HASH, &Table.SysNtOpenFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELAYEXECUTION_HASH, &Table.SysNtDelayExecution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDIRECTORYFILE_HASH, &Table.SysNtQueryDirectoryFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSYSTEMINFORMATION_HASH, &Table.SysNtQuerySystemInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENSECTION_HASH, &Table.SysNtOpenSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYTIMER_HASH, &Table.SysNtQueryTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFSCONTROLFILE_HASH, &Table.SysNtFsControlFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWRITEVIRTUALMEMORY_HASH, &Table.SysNtWriteVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCLOSEOBJECTAUDITALARM_HASH, &Table.SysNtCloseObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDUPLICATEOBJECT_HASH, &Table.SysNtDuplicateObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYATTRIBUTESFILE_HASH, &Table.SysNtQueryAttributesFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCLEAREVENT_HASH, &Table.SysNtClearEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREADVIRTUALMEMORY_HASH, &Table.SysNtReadVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENEVENT_HASH, &Table.SysNtOpenEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADJUSTPRIVILEGESTOKEN_HASH, &Table.SysNtAdjustPrivilegesToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDUPLICATETOKEN_HASH, &Table.SysNtDuplicateToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCONTINUE_HASH, &Table.SysNtContinue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDEFAULTUILANGUAGE_HASH, &Table.SysNtQueryDefaultUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUEUEAPCTHREAD_HASH, &Table.SysNtQueueApcThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTYIELDEXECUTION_HASH, &Table.SysNtYieldExecution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADDATOM_HASH, &Table.SysNtAddAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEEVENT_HASH, &Table.SysNtCreateEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYVOLUMEINFORMATIONFILE_HASH, &Table.SysNtQueryVolumeInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATESECTION_HASH, &Table.SysNtCreateSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHBUFFERSFILE_HASH, &Table.SysNtFlushBuffersFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTAPPHELPCACHECONTROL_HASH, &Table.SysNtApphelpCacheControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPROCESSEX_HASH, &Table.SysNtCreateProcessEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETHREAD_HASH, &Table.SysNtCreateThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTISPROCESSINJOB_HASH, &Table.SysNtIsProcessInJob);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPROTECTVIRTUALMEMORY_HASH, &Table.SysNtProtectVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSECTION_HASH, &Table.SysNtQuerySection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRESUMETHREAD_HASH, &Table.SysNtResumeThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTERMINATETHREAD_HASH, &Table.SysNtTerminateThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREADREQUESTDATA_HASH, &Table.SysNtReadRequestData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEFILE_HASH, &Table.SysNtCreateFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYEVENT_HASH, &Table.SysNtQueryEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWRITEREQUESTDATA_HASH, &Table.SysNtWriteRequestData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENDIRECTORYOBJECT_HASH, &Table.SysNtOpenDirectoryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECKBYTYPEANDAUDITALARM_HASH, &Table.SysNtAccessCheckByTypeAndAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORMULTIPLEOBJECTS_HASH, &Table.SysNtWaitForMultipleObjects);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONOBJECT_HASH, &Table.SysNtSetInformationObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCANCELIOFILE_HASH, &Table.SysNtCancelIoFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTRACEEVENT_HASH, &Table.SysNtTraceEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPOWERINFORMATION_HASH, &Table.SysNtPowerInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETVALUEKEY_HASH, &Table.SysNtSetValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCANCELTIMER_HASH, &Table.SysNtCancelTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETTIMER_HASH, &Table.SysNtSetTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECKBYTYPE_HASH, &Table.SysNtAccessCheckByType);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECKBYTYPERESULTLIST_HASH, &Table.SysNtAccessCheckByTypeResultList);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM_HASH, &Table.SysNtAccessCheckByTypeResultListAndAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE_HASH, &Table.SysNtAccessCheckByTypeResultListAndAuditAlarmByHandle);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTACQUIREPROCESSACTIVITYREFERENCE_HASH, &Table.SysNtAcquireProcessActivityReference);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADDATOMEX_HASH, &Table.SysNtAddAtomEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADDBOOTENTRY_HASH, &Table.SysNtAddBootEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADDDRIVERENTRY_HASH, &Table.SysNtAddDriverEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADJUSTGROUPSTOKEN_HASH, &Table.SysNtAdjustGroupsToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTADJUSTTOKENCLAIMSANDDEVICEGROUPS_HASH, &Table.SysNtAdjustTokenClaimsAndDeviceGroups);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALERTRESUMETHREAD_HASH, &Table.SysNtAlertResumeThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALERTTHREAD_HASH, &Table.SysNtAlertThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALERTTHREADBYTHREADID_HASH, &Table.SysNtAlertThreadByThreadId);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALLOCATELOCALLYUNIQUEID_HASH, &Table.SysNtAllocateLocallyUniqueId);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALLOCATERESERVEOBJECT_HASH, &Table.SysNtAllocateReserveObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALLOCATEUSERPHYSICALPAGES_HASH, &Table.SysNtAllocateUserPhysicalPages);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALLOCATEUUIDS_HASH, &Table.SysNtAllocateUuids);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALLOCATEVIRTUALMEMORYEX_HASH, &Table.SysNtAllocateVirtualMemoryEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCACCEPTCONNECTPORT_HASH, &Table.SysNtAlpcAcceptConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCANCELMESSAGE_HASH, &Table.SysNtAlpcCancelMessage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCONNECTPORT_HASH, &Table.SysNtAlpcConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCONNECTPORTEX_HASH, &Table.SysNtAlpcConnectPortEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCREATEPORT_HASH, &Table.SysNtAlpcCreatePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCREATEPORTSECTION_HASH, &Table.SysNtAlpcCreatePortSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCREATERESOURCERESERVE_HASH, &Table.SysNtAlpcCreateResourceReserve);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCREATESECTIONVIEW_HASH, &Table.SysNtAlpcCreateSectionView);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCCREATESECURITYCONTEXT_HASH, &Table.SysNtAlpcCreateSecurityContext);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCDELETEPORTSECTION_HASH, &Table.SysNtAlpcDeletePortSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCDELETERESOURCERESERVE_HASH, &Table.SysNtAlpcDeleteResourceReserve);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCDELETESECTIONVIEW_HASH, &Table.SysNtAlpcDeleteSectionView);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCDELETESECURITYCONTEXT_HASH, &Table.SysNtAlpcDeleteSecurityContext);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCDISCONNECTPORT_HASH, &Table.SysNtAlpcDisconnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCIMPERSONATECLIENTCONTAINEROFPORT_HASH, &Table.SysNtAlpcImpersonateClientContainerOfPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCIMPERSONATECLIENTOFPORT_HASH, &Table.SysNtAlpcImpersonateClientOfPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCOPENSENDERPROCESS_HASH, &Table.SysNtAlpcOpenSenderProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCOPENSENDERTHREAD_HASH, &Table.SysNtAlpcOpenSenderThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCQUERYINFORMATION_HASH, &Table.SysNtAlpcQueryInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCQUERYINFORMATIONMESSAGE_HASH, &Table.SysNtAlpcQueryInformationMessage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCREVOKESECURITYCONTEXT_HASH, &Table.SysNtAlpcRevokeSecurityContext);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCSENDWAITRECEIVEPORT_HASH, &Table.SysNtAlpcSendWaitReceivePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTALPCSETINFORMATION_HASH, &Table.SysNtAlpcSetInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTAREMAPPEDFILESTHESAME_HASH, &Table.SysNtAreMappedFilesTheSame);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTASSIGNPROCESSTOJOBOBJECT_HASH, &Table.SysNtAssignProcessToJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTASSOCIATEWAITCOMPLETIONPACKET_HASH, &Table.SysNtAssociateWaitCompletionPacket);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCALLENCLAVE_HASH, &Table.SysNtCallEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCANCELIOFILEEX_HASH, &Table.SysNtCancelIoFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCANCELSYNCHRONOUSIOFILE_HASH, &Table.SysNtCancelSynchronousIoFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCANCELTIMER2_HASH, &Table.SysNtCancelTimer2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCANCELWAITCOMPLETIONPACKET_HASH, &Table.SysNtCancelWaitCompletionPacket);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMMITCOMPLETE_HASH, &Table.SysNtCommitComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMMITENLISTMENT_HASH, &Table.SysNtCommitEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMMITREGISTRYTRANSACTION_HASH, &Table.SysNtCommitRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMMITTRANSACTION_HASH, &Table.SysNtCommitTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMPACTKEYS_HASH, &Table.SysNtCompactKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMPAREOBJECTS_HASH, &Table.SysNtCompareObjects);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMPARESIGNINGLEVELS_HASH, &Table.SysNtCompareSigningLevels);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMPARETOKENS_HASH, &Table.SysNtCompareTokens);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMPLETECONNECTPORT_HASH, &Table.SysNtCompleteConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCOMPRESSKEY_HASH, &Table.SysNtCompressKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCONNECTPORT_HASH, &Table.SysNtConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCONVERTBETWEENAUXILIARYCOUNTERANDPERFORMANCECOUNTER_HASH, &Table.SysNtConvertBetweenAuxiliaryCounterAndPerformanceCounter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEDEBUGOBJECT_HASH, &Table.SysNtCreateDebugObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEDIRECTORYOBJECT_HASH, &Table.SysNtCreateDirectoryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEDIRECTORYOBJECTEX_HASH, &Table.SysNtCreateDirectoryObjectEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEENCLAVE_HASH, &Table.SysNtCreateEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEENLISTMENT_HASH, &Table.SysNtCreateEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEEVENTPAIR_HASH, &Table.SysNtCreateEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEIRTIMER_HASH, &Table.SysNtCreateIRTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEIOCOMPLETION_HASH, &Table.SysNtCreateIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEJOBOBJECT_HASH, &Table.SysNtCreateJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEJOBSET_HASH, &Table.SysNtCreateJobSet);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEKEYTRANSACTED_HASH, &Table.SysNtCreateKeyTransacted);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEKEYEDEVENT_HASH, &Table.SysNtCreateKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATELOWBOXTOKEN_HASH, &Table.SysNtCreateLowBoxToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEMAILSLOTFILE_HASH, &Table.SysNtCreateMailslotFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEMUTANT_HASH, &Table.SysNtCreateMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATENAMEDPIPEFILE_HASH, &Table.SysNtCreateNamedPipeFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPAGINGFILE_HASH, &Table.SysNtCreatePagingFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPARTITION_HASH, &Table.SysNtCreatePartition);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPORT_HASH, &Table.SysNtCreatePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPRIVATENAMESPACE_HASH, &Table.SysNtCreatePrivateNamespace);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPROCESS_HASH, &Table.SysNtCreateProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPROFILE_HASH, &Table.SysNtCreateProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEPROFILEEX_HASH, &Table.SysNtCreateProfileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEREGISTRYTRANSACTION_HASH, &Table.SysNtCreateRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATERESOURCEMANAGER_HASH, &Table.SysNtCreateResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATESEMAPHORE_HASH, &Table.SysNtCreateSemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATESYMBOLICLINKOBJECT_HASH, &Table.SysNtCreateSymbolicLinkObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETHREADEX_HASH, &Table.SysNtCreateThreadEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETIMER_HASH, &Table.SysNtCreateTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETIMER2_HASH, &Table.SysNtCreateTimer2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETOKEN_HASH, &Table.SysNtCreateToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETOKENEX_HASH, &Table.SysNtCreateTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETRANSACTION_HASH, &Table.SysNtCreateTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATETRANSACTIONMANAGER_HASH, &Table.SysNtCreateTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEUSERPROCESS_HASH, &Table.SysNtCreateUserProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEWAITCOMPLETIONPACKET_HASH, &Table.SysNtCreateWaitCompletionPacket);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEWAITABLEPORT_HASH, &Table.SysNtCreateWaitablePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEWNFSTATENAME_HASH, &Table.SysNtCreateWnfStateName);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATEWORKERFACTORY_HASH, &Table.SysNtCreateWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDEBUGACTIVEPROCESS_HASH, &Table.SysNtDebugActiveProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDEBUGCONTINUE_HASH, &Table.SysNtDebugContinue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEATOM_HASH, &Table.SysNtDeleteAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEBOOTENTRY_HASH, &Table.SysNtDeleteBootEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEDRIVERENTRY_HASH, &Table.SysNtDeleteDriverEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEFILE_HASH, &Table.SysNtDeleteFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEKEY_HASH, &Table.SysNtDeleteKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEOBJECTAUDITALARM_HASH, &Table.SysNtDeleteObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEPRIVATENAMESPACE_HASH, &Table.SysNtDeletePrivateNamespace);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEVALUEKEY_HASH, &Table.SysNtDeleteValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEWNFSTATEDATA_HASH, &Table.SysNtDeleteWnfStateData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDELETEWNFSTATENAME_HASH, &Table.SysNtDeleteWnfStateName);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDISABLELASTKNOWNGOOD_HASH, &Table.SysNtDisableLastKnownGood);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDISPLAYSTRING_HASH, &Table.SysNtDisplayString);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTDRAWTEXT_HASH, &Table.SysNtDrawText);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENABLELASTKNOWNGOOD_HASH, &Table.SysNtEnableLastKnownGood);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENUMERATEBOOTENTRIES_HASH, &Table.SysNtEnumerateBootEntries);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENUMERATEDRIVERENTRIES_HASH, &Table.SysNtEnumerateDriverEntries);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENUMERATESYSTEMENVIRONMENTVALUESEX_HASH, &Table.SysNtEnumerateSystemEnvironmentValuesEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTENUMERATETRANSACTIONOBJECT_HASH, &Table.SysNtEnumerateTransactionObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTEXTENDSECTION_HASH, &Table.SysNtExtendSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFILTERBOOTOPTION_HASH, &Table.SysNtFilterBootOption);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFILTERTOKEN_HASH, &Table.SysNtFilterToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFILTERTOKENEX_HASH, &Table.SysNtFilterTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHBUFFERSFILEEX_HASH, &Table.SysNtFlushBuffersFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHINSTALLUILANGUAGE_HASH, &Table.SysNtFlushInstallUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHINSTRUCTIONCACHE_HASH, &Table.SysNtFlushInstructionCache);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHKEY_HASH, &Table.SysNtFlushKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHPROCESSWRITEBUFFERS_HASH, &Table.SysNtFlushProcessWriteBuffers);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHVIRTUALMEMORY_HASH, &Table.SysNtFlushVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFLUSHWRITEBUFFER_HASH, &Table.SysNtFlushWriteBuffer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFREEUSERPHYSICALPAGES_HASH, &Table.SysNtFreeUserPhysicalPages);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFREEZEREGISTRY_HASH, &Table.SysNtFreezeRegistry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTFREEZETRANSACTIONS_HASH, &Table.SysNtFreezeTransactions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETCACHEDSIGNINGLEVEL_HASH, &Table.SysNtGetCachedSigningLevel);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETCOMPLETEWNFSTATESUBSCRIPTION_HASH, &Table.SysNtGetCompleteWnfStateSubscription);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETCONTEXTTHREAD_HASH, &Table.SysNtGetContextThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETCURRENTPROCESSORNUMBER_HASH, &Table.SysNtGetCurrentProcessorNumber);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETCURRENTPROCESSORNUMBEREX_HASH, &Table.SysNtGetCurrentProcessorNumberEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETDEVICEPOWERSTATE_HASH, &Table.SysNtGetDevicePowerState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETMUIREGISTRYINFO_HASH, &Table.SysNtGetMUIRegistryInfo);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETNEXTPROCESS_HASH, &Table.SysNtGetNextProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETNEXTTHREAD_HASH, &Table.SysNtGetNextThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETNLSSECTIONPTR_HASH, &Table.SysNtGetNlsSectionPtr);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETNOTIFICATIONRESOURCEMANAGER_HASH, &Table.SysNtGetNotificationResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTGETWRITEWATCH_HASH, &Table.SysNtGetWriteWatch);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTIMPERSONATEANONYMOUSTOKEN_HASH, &Table.SysNtImpersonateAnonymousToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTIMPERSONATETHREAD_HASH, &Table.SysNtImpersonateThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTINITIALIZEENCLAVE_HASH, &Table.SysNtInitializeEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTINITIALIZENLSFILES_HASH, &Table.SysNtInitializeNlsFiles);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTINITIALIZEREGISTRY_HASH, &Table.SysNtInitializeRegistry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTINITIATEPOWERACTION_HASH, &Table.SysNtInitiatePowerAction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTISSYSTEMRESUMEAUTOMATIC_HASH, &Table.SysNtIsSystemResumeAutomatic);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTISUILANGUAGECOMITTED_HASH, &Table.SysNtIsUILanguageComitted);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLISTENPORT_HASH, &Table.SysNtListenPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOADDRIVER_HASH, &Table.SysNtLoadDriver);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOADENCLAVEDATA_HASH, &Table.SysNtLoadEnclaveData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOADKEY_HASH, &Table.SysNtLoadKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOADKEY2_HASH, &Table.SysNtLoadKey2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOADKEYEX_HASH, &Table.SysNtLoadKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOCKFILE_HASH, &Table.SysNtLockFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOCKPRODUCTACTIVATIONKEYS_HASH, &Table.SysNtLockProductActivationKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOCKREGISTRYKEY_HASH, &Table.SysNtLockRegistryKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTLOCKVIRTUALMEMORY_HASH, &Table.SysNtLockVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAKEPERMANENTOBJECT_HASH, &Table.SysNtMakePermanentObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAKETEMPORARYOBJECT_HASH, &Table.SysNtMakeTemporaryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMANAGEPARTITION_HASH, &Table.SysNtManagePartition);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAPCMFMODULE_HASH, &Table.SysNtMapCMFModule);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAPUSERPHYSICALPAGES_HASH, &Table.SysNtMapUserPhysicalPages);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMAPVIEWOFSECTIONEX_HASH, &Table.SysNtMapViewOfSectionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMODIFYBOOTENTRY_HASH, &Table.SysNtModifyBootEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMODIFYDRIVERENTRY_HASH, &Table.SysNtModifyDriverEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTNOTIFYCHANGEDIRECTORYFILE_HASH, &Table.SysNtNotifyChangeDirectoryFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTNOTIFYCHANGEDIRECTORYFILEEX_HASH, &Table.SysNtNotifyChangeDirectoryFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTNOTIFYCHANGEKEY_HASH, &Table.SysNtNotifyChangeKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTNOTIFYCHANGEMULTIPLEKEYS_HASH, &Table.SysNtNotifyChangeMultipleKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTNOTIFYCHANGESESSION_HASH, &Table.SysNtNotifyChangeSession);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENENLISTMENT_HASH, &Table.SysNtOpenEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENEVENTPAIR_HASH, &Table.SysNtOpenEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENIOCOMPLETION_HASH, &Table.SysNtOpenIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENJOBOBJECT_HASH, &Table.SysNtOpenJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENKEYEX_HASH, &Table.SysNtOpenKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENKEYTRANSACTED_HASH, &Table.SysNtOpenKeyTransacted);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENKEYTRANSACTEDEX_HASH, &Table.SysNtOpenKeyTransactedEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENKEYEDEVENT_HASH, &Table.SysNtOpenKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENMUTANT_HASH, &Table.SysNtOpenMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENOBJECTAUDITALARM_HASH, &Table.SysNtOpenObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENPARTITION_HASH, &Table.SysNtOpenPartition);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENPRIVATENAMESPACE_HASH, &Table.SysNtOpenPrivateNamespace);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENPROCESSTOKEN_HASH, &Table.SysNtOpenProcessToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENREGISTRYTRANSACTION_HASH, &Table.SysNtOpenRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENRESOURCEMANAGER_HASH, &Table.SysNtOpenResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENSEMAPHORE_HASH, &Table.SysNtOpenSemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENSESSION_HASH, &Table.SysNtOpenSession);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENSYMBOLICLINKOBJECT_HASH, &Table.SysNtOpenSymbolicLinkObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENTHREAD_HASH, &Table.SysNtOpenThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENTIMER_HASH, &Table.SysNtOpenTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENTRANSACTION_HASH, &Table.SysNtOpenTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTOPENTRANSACTIONMANAGER_HASH, &Table.SysNtOpenTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPLUGPLAYCONTROL_HASH, &Table.SysNtPlugPlayControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPREPREPARECOMPLETE_HASH, &Table.SysNtPrePrepareComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPREPREPAREENLISTMENT_HASH, &Table.SysNtPrePrepareEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPREPARECOMPLETE_HASH, &Table.SysNtPrepareComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPREPAREENLISTMENT_HASH, &Table.SysNtPrepareEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPRIVILEGECHECK_HASH, &Table.SysNtPrivilegeCheck);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPRIVILEGEOBJECTAUDITALARM_HASH, &Table.SysNtPrivilegeObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPRIVILEGEDSERVICEAUDITALARM_HASH, &Table.SysNtPrivilegedServiceAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPROPAGATIONCOMPLETE_HASH, &Table.SysNtPropagationComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPROPAGATIONFAILED_HASH, &Table.SysNtPropagationFailed);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTPULSEEVENT_HASH, &Table.SysNtPulseEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYAUXILIARYCOUNTERFREQUENCY_HASH, &Table.SysNtQueryAuxiliaryCounterFrequency);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYBOOTENTRYORDER_HASH, &Table.SysNtQueryBootEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYBOOTOPTIONS_HASH, &Table.SysNtQueryBootOptions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDEBUGFILTERSTATE_HASH, &Table.SysNtQueryDebugFilterState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDIRECTORYFILEEX_HASH, &Table.SysNtQueryDirectoryFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDIRECTORYOBJECT_HASH, &Table.SysNtQueryDirectoryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYDRIVERENTRYORDER_HASH, &Table.SysNtQueryDriverEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYEAFILE_HASH, &Table.SysNtQueryEaFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYFULLATTRIBUTESFILE_HASH, &Table.SysNtQueryFullAttributesFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONATOM_HASH, &Table.SysNtQueryInformationAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONBYNAME_HASH, &Table.SysNtQueryInformationByName);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONENLISTMENT_HASH, &Table.SysNtQueryInformationEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONJOBOBJECT_HASH, &Table.SysNtQueryInformationJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONPORT_HASH, &Table.SysNtQueryInformationPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONRESOURCEMANAGER_HASH, &Table.SysNtQueryInformationResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONTRANSACTION_HASH, &Table.SysNtQueryInformationTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONTRANSACTIONMANAGER_HASH, &Table.SysNtQueryInformationTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINFORMATIONWORKERFACTORY_HASH, &Table.SysNtQueryInformationWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINSTALLUILANGUAGE_HASH, &Table.SysNtQueryInstallUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYINTERVALPROFILE_HASH, &Table.SysNtQueryIntervalProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYIOCOMPLETION_HASH, &Table.SysNtQueryIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYLICENSEVALUE_HASH, &Table.SysNtQueryLicenseValue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYMULTIPLEVALUEKEY_HASH, &Table.SysNtQueryMultipleValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYMUTANT_HASH, &Table.SysNtQueryMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYOPENSUBKEYS_HASH, &Table.SysNtQueryOpenSubKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYOPENSUBKEYSEX_HASH, &Table.SysNtQueryOpenSubKeysEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYPORTINFORMATIONPROCESS_HASH, &Table.SysNtQueryPortInformationProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYQUOTAINFORMATIONFILE_HASH, &Table.SysNtQueryQuotaInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSECURITYATTRIBUTESTOKEN_HASH, &Table.SysNtQuerySecurityAttributesToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSECURITYOBJECT_HASH, &Table.SysNtQuerySecurityObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSECURITYPOLICY_HASH, &Table.SysNtQuerySecurityPolicy);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSEMAPHORE_HASH, &Table.SysNtQuerySemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSYMBOLICLINKOBJECT_HASH, &Table.SysNtQuerySymbolicLinkObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSYSTEMENVIRONMENTVALUE_HASH, &Table.SysNtQuerySystemEnvironmentValue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSYSTEMENVIRONMENTVALUEEX_HASH, &Table.SysNtQuerySystemEnvironmentValueEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYSYSTEMINFORMATIONEX_HASH, &Table.SysNtQuerySystemInformationEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYTIMERRESOLUTION_HASH, &Table.SysNtQueryTimerResolution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYWNFSTATEDATA_HASH, &Table.SysNtQueryWnfStateData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUERYWNFSTATENAMEINFORMATION_HASH, &Table.SysNtQueryWnfStateNameInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTQUEUEAPCTHREADEX_HASH, &Table.SysNtQueueApcThreadEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRAISEEXCEPTION_HASH, &Table.SysNtRaiseException);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRAISEHARDERROR_HASH, &Table.SysNtRaiseHardError);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREADONLYENLISTMENT_HASH, &Table.SysNtReadOnlyEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRECOVERENLISTMENT_HASH, &Table.SysNtRecoverEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRECOVERRESOURCEMANAGER_HASH, &Table.SysNtRecoverResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRECOVERTRANSACTIONMANAGER_HASH, &Table.SysNtRecoverTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREGISTERPROTOCOLADDRESSINFORMATION_HASH, &Table.SysNtRegisterProtocolAddressInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREGISTERTHREADTERMINATEPORT_HASH, &Table.SysNtRegisterThreadTerminatePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRELEASEKEYEDEVENT_HASH, &Table.SysNtReleaseKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRELEASEWORKERFACTORYWORKER_HASH, &Table.SysNtReleaseWorkerFactoryWorker);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREMOVEIOCOMPLETIONEX_HASH, &Table.SysNtRemoveIoCompletionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREMOVEPROCESSDEBUG_HASH, &Table.SysNtRemoveProcessDebug);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRENAMEKEY_HASH, &Table.SysNtRenameKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRENAMETRANSACTIONMANAGER_HASH, &Table.SysNtRenameTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREPLACEKEY_HASH, &Table.SysNtReplaceKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREPLACEPARTITIONUNIT_HASH, &Table.SysNtReplacePartitionUnit);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREPLYWAITREPLYPORT_HASH, &Table.SysNtReplyWaitReplyPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREQUESTPORT_HASH, &Table.SysNtRequestPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRESETEVENT_HASH, &Table.SysNtResetEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRESETWRITEWATCH_HASH, &Table.SysNtResetWriteWatch);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRESTOREKEY_HASH, &Table.SysNtRestoreKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTRESUMEPROCESS_HASH, &Table.SysNtResumeProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTREVERTCONTAINERIMPERSONATION_HASH, &Table.SysNtRevertContainerImpersonation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTROLLBACKCOMPLETE_HASH, &Table.SysNtRollbackComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTROLLBACKENLISTMENT_HASH, &Table.SysNtRollbackEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTROLLBACKREGISTRYTRANSACTION_HASH, &Table.SysNtRollbackRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTROLLBACKTRANSACTION_HASH, &Table.SysNtRollbackTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTROLLFORWARDTRANSACTIONMANAGER_HASH, &Table.SysNtRollforwardTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSAVEKEY_HASH, &Table.SysNtSaveKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSAVEKEYEX_HASH, &Table.SysNtSaveKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSAVEMERGEDKEYS_HASH, &Table.SysNtSaveMergedKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSECURECONNECTPORT_HASH, &Table.SysNtSecureConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSERIALIZEBOOT_HASH, &Table.SysNtSerializeBoot);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETBOOTENTRYORDER_HASH, &Table.SysNtSetBootEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETBOOTOPTIONS_HASH, &Table.SysNtSetBootOptions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETCACHEDSIGNINGLEVEL_HASH, &Table.SysNtSetCachedSigningLevel);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETCACHEDSIGNINGLEVEL2_HASH, &Table.SysNtSetCachedSigningLevel2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETCONTEXTTHREAD_HASH, &Table.SysNtSetContextThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETDEBUGFILTERSTATE_HASH, &Table.SysNtSetDebugFilterState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETDEFAULTHARDERRORPORT_HASH, &Table.SysNtSetDefaultHardErrorPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETDEFAULTLOCALE_HASH, &Table.SysNtSetDefaultLocale);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETDEFAULTUILANGUAGE_HASH, &Table.SysNtSetDefaultUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETDRIVERENTRYORDER_HASH, &Table.SysNtSetDriverEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETEAFILE_HASH, &Table.SysNtSetEaFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETHIGHEVENTPAIR_HASH, &Table.SysNtSetHighEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETHIGHWAITLOWEVENTPAIR_HASH, &Table.SysNtSetHighWaitLowEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETIRTIMER_HASH, &Table.SysNtSetIRTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONDEBUGOBJECT_HASH, &Table.SysNtSetInformationDebugObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONENLISTMENT_HASH, &Table.SysNtSetInformationEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONJOBOBJECT_HASH, &Table.SysNtSetInformationJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONKEY_HASH, &Table.SysNtSetInformationKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONRESOURCEMANAGER_HASH, &Table.SysNtSetInformationResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONSYMBOLICLINK_HASH, &Table.SysNtSetInformationSymbolicLink);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONTOKEN_HASH, &Table.SysNtSetInformationToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONTRANSACTION_HASH, &Table.SysNtSetInformationTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONTRANSACTIONMANAGER_HASH, &Table.SysNtSetInformationTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONVIRTUALMEMORY_HASH, &Table.SysNtSetInformationVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONWORKERFACTORY_HASH, &Table.SysNtSetInformationWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINTERVALPROFILE_HASH, &Table.SysNtSetIntervalProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETIOCOMPLETION_HASH, &Table.SysNtSetIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETIOCOMPLETIONEX_HASH, &Table.SysNtSetIoCompletionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETLDTENTRIES_HASH, &Table.SysNtSetLdtEntries);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETLOWEVENTPAIR_HASH, &Table.SysNtSetLowEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETLOWWAITHIGHEVENTPAIR_HASH, &Table.SysNtSetLowWaitHighEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETQUOTAINFORMATIONFILE_HASH, &Table.SysNtSetQuotaInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETSECURITYOBJECT_HASH, &Table.SysNtSetSecurityObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETSYSTEMENVIRONMENTVALUE_HASH, &Table.SysNtSetSystemEnvironmentValue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETSYSTEMENVIRONMENTVALUEEX_HASH, &Table.SysNtSetSystemEnvironmentValueEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETSYSTEMINFORMATION_HASH, &Table.SysNtSetSystemInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETSYSTEMPOWERSTATE_HASH, &Table.SysNtSetSystemPowerState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETSYSTEMTIME_HASH, &Table.SysNtSetSystemTime);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETTHREADEXECUTIONSTATE_HASH, &Table.SysNtSetThreadExecutionState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETTIMER2_HASH, &Table.SysNtSetTimer2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETTIMEREX_HASH, &Table.SysNtSetTimerEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETTIMERRESOLUTION_HASH, &Table.SysNtSetTimerResolution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETUUIDSEED_HASH, &Table.SysNtSetUuidSeed);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETVOLUMEINFORMATIONFILE_HASH, &Table.SysNtSetVolumeInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETWNFPROCESSNOTIFICATIONEVENT_HASH, &Table.SysNtSetWnfProcessNotificationEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSHUTDOWNSYSTEM_HASH, &Table.SysNtShutdownSystem);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSHUTDOWNWORKERFACTORY_HASH, &Table.SysNtShutdownWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSIGNALANDWAITFORSINGLEOBJECT_HASH, &Table.SysNtSignalAndWaitForSingleObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSINGLEPHASEREJECT_HASH, &Table.SysNtSinglePhaseReject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSTARTPROFILE_HASH, &Table.SysNtStartProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSTOPPROFILE_HASH, &Table.SysNtStopProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSUBSCRIBEWNFSTATECHANGE_HASH, &Table.SysNtSubscribeWnfStateChange);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSUSPENDPROCESS_HASH, &Table.SysNtSuspendProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSUSPENDTHREAD_HASH, &Table.SysNtSuspendThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSYSTEMDEBUGCONTROL_HASH, &Table.SysNtSystemDebugControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTERMINATEENCLAVE_HASH, &Table.SysNtTerminateEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTERMINATEJOBOBJECT_HASH, &Table.SysNtTerminateJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTESTALERT_HASH, &Table.SysNtTestAlert);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTHAWREGISTRY_HASH, &Table.SysNtThawRegistry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTHAWTRANSACTIONS_HASH, &Table.SysNtThawTransactions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTRACECONTROL_HASH, &Table.SysNtTraceControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTTRANSLATEFILEPATH_HASH, &Table.SysNtTranslateFilePath);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUMSTHREADYIELD_HASH, &Table.SysNtUmsThreadYield);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNLOADDRIVER_HASH, &Table.SysNtUnloadDriver);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNLOADKEY_HASH, &Table.SysNtUnloadKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNLOADKEY2_HASH, &Table.SysNtUnloadKey2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNLOADKEYEX_HASH, &Table.SysNtUnloadKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNLOCKFILE_HASH, &Table.SysNtUnlockFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNLOCKVIRTUALMEMORY_HASH, &Table.SysNtUnlockVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNMAPVIEWOFSECTIONEX_HASH, &Table.SysNtUnmapViewOfSectionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUNSUBSCRIBEWNFSTATECHANGE_HASH, &Table.SysNtUnsubscribeWnfStateChange);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTUPDATEWNFSTATEDATA_HASH, &Table.SysNtUpdateWnfStateData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTVDMCONTROL_HASH, &Table.SysNtVdmControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORALERTBYTHREADID_HASH, &Table.SysNtWaitForAlertByThreadId);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORDEBUGEVENT_HASH, &Table.SysNtWaitForDebugEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORKEYEDEVENT_HASH, &Table.SysNtWaitForKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITFORWORKVIAWORKERFACTORY_HASH, &Table.SysNtWaitForWorkViaWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITHIGHEVENTPAIR_HASH, &Table.SysNtWaitHighEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTWAITLOWEVENTPAIR_HASH, &Table.SysNtWaitLowEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATESECTIONEX_HASH, &Table.SysNtCreateSectionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCREATECROSSVMEVENT_HASH, &Table.SysNtCreateCrossVmEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTSETINFORMATIONPROCESS_HASH, &Table.SysNtSetInformationProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTMANAGEHOTPATCH_HASH, &Table.SysNtManageHotPatch);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, NTCONTINUEEX_HASH, &Table.SysNtContinueEx);

    SysTable = Table;
    return;
}
