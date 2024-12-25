#include "Syscalls.hpp"
#include <stdio.h>

unsigned long djb2_unicode(const wchar_t* str) {
    unsigned long hash = 5381;
    DWORD val;
    while (*str != 0) {
        val = (DWORD)*str++;
        hash = ((hash << 5) + hash) + val;
    }
    return hash;
}

unsigned long djb2(unsigned char* str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

unsigned long xor_hash(unsigned long hash) {
    return hash ^ XORKEY;
}

WCHAR* toLower(WCHAR* str) {
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
            if (memcmp(pFunctionAddress, cleanStart, 4) == 0 && memcmp(pFunctionAddress + 18, syscallMatch, 3) == 0) {
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
                    if (memcmp(pFunctionAddress + idx * DOWN, cleanStart, 4) == 0 && memcmp(pFunctionAddress + idx * DOWN + 18, syscallMatch, 3) == 0) {
                        BYTE high = *((PBYTE)pFunctionAddress + 5 + idx * DOWN);
                        BYTE low = *((PBYTE)pFunctionAddress + 4 + idx * DOWN);
                        pSyscall->wSyscallNr = (high << 8) | low - idx;
                        pSyscall->pRecycled = pFunctionAddress + idx * DOWN + 18;
#ifdef DEBUG
                        printf("    -> Found num for %s using DOWN after %d jumps! Num: %lu\n", pczFunctionName, idx, pSyscall->wSyscallNr);
#endif
                        return TRUE;
                    }
                    if (memcmp(pFunctionAddress + idx * UP, cleanStart, 4) == 0 && memcmp(pFunctionAddress + idx * UP + 18, syscallMatch, 3) == 0) {
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
    PPEB_LDR_DATA pLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
    pLdrData = ThisPeb->pLdr;

    pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;

    do {
        pDllName = &pModuleEntry->BaseDllName;
        pFullDllName = &pModuleEntry->FullDllName;
        if (pDllName->Buffer == NULL) {
            continue;
        }
        if (djb2_unicode(toLower(pDllName->Buffer)) == xor_hash(0x31e4a6da)) {
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

    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xda605e0, &Table.SysNtAccessCheck);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd58c643f, &Table.SysNtWorkerFactoryWorkerReady);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfd4e0e51, &Table.SysNtAcceptConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb782a190, &Table.SysNtMapUserPhysicalPagesScatter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5f5ad50b, &Table.SysNtWaitForSingleObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe3e8a063, &Table.SysNtCallbackReturn);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3da089d4, &Table.SysNtReadFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb73b58e7, &Table.SysNtDeviceIoControlFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc5a43585, &Table.SysNtWriteFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x63aea750, &Table.SysNtRemoveIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc30d2f1b, &Table.SysNtReleaseSemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe1ddeda7, &Table.SysNtReplyWaitReceivePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x895c158f, &Table.SysNtReplyPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x47163d06, &Table.SysNtSetInformationThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5623aea2, &Table.SysNtSetEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x98b9000a, &Table.SysNtClose);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x32b605c3, &Table.SysNtQueryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5412eb54, &Table.SysNtQueryInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x58802d35, &Table.SysNtOpenKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb2da5be4, &Table.SysNtEnumerateValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7e8c07ee, &Table.SysNtFindAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x98375a05, &Table.SysNtQueryDefaultLocale);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf5011b1, &Table.SysNtQueryKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa7f699b4, &Table.SysNtQueryValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x74a4d07b, &Table.SysNtAllocateVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc303ef55, &Table.SysNtQueryInformationProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb7048d09, &Table.SysNtWaitForMultipleObjects32);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x83a7c6ba, &Table.SysNtWriteFileGather);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4e8859b3, &Table.SysNtCreateKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x542db4de, &Table.SysNtFreeVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4c2dea90, &Table.SysNtImpersonateClientOfPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3a616a56, &Table.SysNtReleaseMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3fd2b173, &Table.SysNtQueryInformationToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb2c10281, &Table.SysNtRequestWaitReplyPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf0aa9d6a, &Table.SysNtQueryVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xef72aa45, &Table.SysNtOpenThreadToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xda2807ac, &Table.SysNtQueryInformationThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4334d36f, &Table.SysNtOpenProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7dbfa74e, &Table.SysNtSetInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x30280a5d, &Table.SysNtMapViewOfSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5664b879, &Table.SysNtAccessCheckAndAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4a67079a, &Table.SysNtUnmapViewOfSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4a93f8da, &Table.SysNtReplyWaitReceivePortEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x434b818, &Table.SysNtTerminateProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x12d397c9, &Table.SysNtSetEventBoostPriority);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe964752e, &Table.SysNtReadFileScatter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x37aef478, &Table.SysNtOpenThreadTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa289e4c1, &Table.SysNtOpenProcessTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8ca7b9b8, &Table.SysNtQueryPerformanceCounter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x79699de1, &Table.SysNtEnumerateKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd1ab432e, &Table.SysNtOpenFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x197e1b7d, &Table.SysNtDelayExecution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xba322c45, &Table.SysNtQueryDirectoryFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfd78609f, &Table.SysNtQuerySystemInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4f8b079, &Table.SysNtOpenSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc1e1b749, &Table.SysNtQueryTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xebaacc56, &Table.SysNtFsControlFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x86c4b4a5, &Table.SysNtWriteVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xacb0876f, &Table.SysNtCloseObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x30bffd2e, &Table.SysNtDuplicateObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9b27ba73, &Table.SysNtQueryAttributesFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x40df35c7, &Table.SysNtClearEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd17771d4, &Table.SysNtReadVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x52c2c4c, &Table.SysNtOpenEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7a16eafa, &Table.SysNtAdjustPrivilegesToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2337fff4, &Table.SysNtDuplicateToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6b3d721b, &Table.SysNtContinue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xcfa509d3, &Table.SysNtQueryDefaultUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc756310f, &Table.SysNtQueueApcThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x20b72fc5, &Table.SysNtYieldExecution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xeae8fd36, &Table.SysNtAddAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd96f674a, &Table.SysNtCreateEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe28c9d0c, &Table.SysNtQueryVolumeInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc31933e7, &Table.SysNtCreateSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x90196de1, &Table.SysNtFlushBuffersFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8eccbd31, &Table.SysNtApphelpCacheControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbade3680, &Table.SysNtCreateProcessEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x24591424, &Table.SysNtCreateThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x44460da3, &Table.SysNtIsProcessInJob);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1b1e71ff, &Table.SysNtProtectVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9f211ae5, &Table.SysNtQuerySection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3f4c2e07, &Table.SysNtResumeThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbf0b8eff, &Table.SysNtTerminateThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd60230f1, &Table.SysNtReadRequestData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x692ffec, &Table.SysNtCreateFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc2f927c8, &Table.SysNtQueryEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1f966382, &Table.SysNtWriteRequestData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x76de332, &Table.SysNtOpenDirectoryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc53b14bc, &Table.SysNtAccessCheckByTypeAndAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2e72760e, &Table.SysNtWaitForMultipleObjects);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5b317e67, &Table.SysNtSetInformationObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x806f1b52, &Table.SysNtCancelIoFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd1796cf, &Table.SysNtTraceEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb061082d, &Table.SysNtPowerInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe61a406e, &Table.SysNtSetValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x160c6399, &Table.SysNtCancelTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x552a3e23, &Table.SysNtSetTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc253d8c3, &Table.SysNtAccessCheckByType);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x56e78, &Table.SysNtAccessCheckByTypeResultList);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4792c7f1, &Table.SysNtAccessCheckByTypeResultListAndAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5af280ba, &Table.SysNtAccessCheckByTypeResultListAndAuditAlarmByHandle);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xebf054fb, &Table.SysNtAcquireProcessActivityReference);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe2a468a9, &Table.SysNtAddAtomEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb373781, &Table.SysNtAddBootEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe162dc19, &Table.SysNtAddDriverEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8248dbc4, &Table.SysNtAdjustGroupsToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfbeb0358, &Table.SysNtAdjustTokenClaimsAndDeviceGroups);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5b19973f, &Table.SysNtAlertResumeThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x21b92ae0, &Table.SysNtAlertThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc46ea660, &Table.SysNtAlertThreadByThreadId);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdae1b517, &Table.SysNtAllocateLocallyUniqueId);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8fa31f68, &Table.SysNtAllocateReserveObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x685e2eef, &Table.SysNtAllocateUserPhysicalPages);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x74e5e561, &Table.SysNtAllocateUuids);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x88a6dc9e, &Table.SysNtAllocateVirtualMemoryEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x57cca0f1, &Table.SysNtAlpcAcceptConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbe2f6745, &Table.SysNtAlpcCancelMessage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7274d881, &Table.SysNtAlpcConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd25289a4, &Table.SysNtAlpcConnectPortEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x48c39657, &Table.SysNtAlpcCreatePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x868f4582, &Table.SysNtAlpcCreatePortSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x261b2be8, &Table.SysNtAlpcCreateResourceReserve);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xcc9280dc, &Table.SysNtAlpcCreateSectionView);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xab6a58f, &Table.SysNtAlpcCreateSecurityContext);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfee32023, &Table.SysNtAlpcDeletePortSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa5ba3f89, &Table.SysNtAlpcDeleteResourceReserve);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x24f6637d, &Table.SysNtAlpcDeleteSectionView);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x89d5b9a0, &Table.SysNtAlpcDeleteSecurityContext);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4882aa81, &Table.SysNtAlpcDisconnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x70b1149d, &Table.SysNtAlpcImpersonateClientContainerOfPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9fbbcb30, &Table.SysNtAlpcImpersonateClientOfPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3781ece, &Table.SysNtAlpcOpenSenderProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3d6dc65, &Table.SysNtAlpcOpenSenderThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb1bf0af4, &Table.SysNtAlpcQueryInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xeb813aff, &Table.SysNtAlpcQueryInformationMessage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x663ac47, &Table.SysNtAlpcRevokeSecurityContext);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb79fb6b9, &Table.SysNtAlpcSendWaitReceivePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6ca931ee, &Table.SysNtAlpcSetInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe2bf08a7, &Table.SysNtAreMappedFilesTheSame);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf71cc77, &Table.SysNtAssignProcessToJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xcf4909bd, &Table.SysNtAssociateWaitCompletionPacket);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc231b4b6, &Table.SysNtCallEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xda4cac35, &Table.SysNtCancelIoFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8de89327, &Table.SysNtCancelSynchronousIoFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbf9e9597, &Table.SysNtCancelTimer2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7a40483, &Table.SysNtCancelWaitCompletionPacket);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb863bfbe, &Table.SysNtCommitComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6227fae4, &Table.SysNtCommitEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x569e1bb8, &Table.SysNtCommitRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf18f9321, &Table.SysNtCommitTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x92c2c8bd, &Table.SysNtCompactKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xca4dcecf, &Table.SysNtCompareObjects);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8fa0321f, &Table.SysNtCompareSigningLevels);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x528f4b55, &Table.SysNtCompareTokens);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x141d9318, &Table.SysNtCompleteConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb076882b, &Table.SysNtCompressKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x42ed6e61, &Table.SysNtConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5a65c7f8, &Table.SysNtConvertBetweenAuxiliaryCounterAndPerformanceCounter);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5826e60e, &Table.SysNtCreateDebugObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2620dcb0, &Table.SysNtCreateDirectoryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc97ec593, &Table.SysNtCreateDirectoryObjectEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbc4fa48e, &Table.SysNtCreateEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1404b69, &Table.SysNtCreateEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6142e0de, &Table.SysNtCreateEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb2374660, &Table.SysNtCreateIRTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3f7b989a, &Table.SysNtCreateIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1965d3a, &Table.SysNtCreateJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x33a71975, &Table.SysNtCreateJobSet);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5468d1ba, &Table.SysNtCreateKeyTransacted);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa44da3f8, &Table.SysNtCreateKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf2c31c00, &Table.SysNtCreateLowBoxToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2d8b1a57, &Table.SysNtCreateMailslotFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3b312183, &Table.SysNtCreateMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xcc05f319, &Table.SysNtCreateNamedPipeFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb99140a6, &Table.SysNtCreatePagingFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1b5e27c2, &Table.SysNtCreatePartition);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x69c9037, &Table.SysNtCreatePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x40282274, &Table.SysNtCreatePrivateNamespace);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1b552eed, &Table.SysNtCreateProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1b54e03b, &Table.SysNtCreateProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa21bfc5e, &Table.SysNtCreateProfileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x86df104d, &Table.SysNtCreateRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x52c7d009, &Table.SysNtCreateResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x791fcba8, &Table.SysNtCreateSemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xadd2ec75, &Table.SysNtCreateSymbolicLinkObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd83b3207, &Table.SysNtCreateThreadEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd857f0cb, &Table.SysNtCreateTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x244a7099, &Table.SysNtCreateTimer2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd853368b, &Table.SysNtCreateToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x26339d2e, &Table.SysNtCreateTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa3dbd336, &Table.SysNtCreateTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5feba88b, &Table.SysNtCreateTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4cb9566e, &Table.SysNtCreateUserProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3f7aa675, &Table.SysNtCreateWaitCompletionPacket);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x36879fbe, &Table.SysNtCreateWaitablePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3afcef7f, &Table.SysNtCreateWnfStateName);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x26d378da, &Table.SysNtCreateWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x934c139e, &Table.SysNtDebugActiveProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x895e7244, &Table.SysNtDebugContinue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xca26e45c, &Table.SysNtDeleteAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2f15b357, &Table.SysNtDeleteBootEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xba32ce6f, &Table.SysNtDeleteDriverEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xca23952d, &Table.SysNtDeleteFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe42724d4, &Table.SysNtDeleteKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe6a6a782, &Table.SysNtDeleteObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x13a9b235, &Table.SysNtDeletePrivateNamespace);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x854b137, &Table.SysNtDeleteValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x966afa97, &Table.SysNtDeleteWnfStateData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x965477b0, &Table.SysNtDeleteWnfStateName);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x525793d2, &Table.SysNtDisableLastKnownGood);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xcd2832e3, &Table.SysNtDisplayString);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3e2568ed, &Table.SysNtDrawText);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8a5e54f, &Table.SysNtEnableLastKnownGood);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x398888c, &Table.SysNtEnumerateBootEntries);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x39932c44, &Table.SysNtEnumerateDriverEntries);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xaac72e03, &Table.SysNtEnumerateSystemEnvironmentValuesEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfbf83d9d, &Table.SysNtEnumerateTransactionObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdd3bdfb3, &Table.SysNtExtendSection);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x184d8a4d, &Table.SysNtFilterBootOption);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x98399cd9, &Table.SysNtFilterToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9bc55ffc, &Table.SysNtFilterTokenEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1bfe8684, &Table.SysNtFlushBuffersFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x448a4315, &Table.SysNtFlushInstallUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x932f29e8, &Table.SysNtFlushInstructionCache);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x75151905, &Table.SysNtFlushKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x620d1657, &Table.SysNtFlushProcessWriteBuffers);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe5600e3e, &Table.SysNtFlushVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x53c1a159, &Table.SysNtFlushWriteBuffer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc5ec3bc2, &Table.SysNtFreeUserPhysicalPages);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc2816696, &Table.SysNtFreezeRegistry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9a5124f6, &Table.SysNtFreezeTransactions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf71f40f1, &Table.SysNtGetCachedSigningLevel);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x85689986, &Table.SysNtGetCompleteWnfStateSubscription);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8d390973, &Table.SysNtGetContextThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe8e21e64, &Table.SysNtGetCurrentProcessorNumber);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x567aa447, &Table.SysNtGetCurrentProcessorNumberEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x21595432, &Table.SysNtGetDevicePowerState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa3006c20, &Table.SysNtGetMUIRegistryInfo);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x71846612, &Table.SysNtGetNextProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9cb713c9, &Table.SysNtGetNextThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4af952a8, &Table.SysNtGetNlsSectionPtr);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf5baefe6, &Table.SysNtGetNotificationResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfff74dfe, &Table.SysNtGetWriteWatch);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf4a8aacf, &Table.SysNtImpersonateAnonymousToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x817a4b1, &Table.SysNtImpersonateThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7d85b5e0, &Table.SysNtInitializeEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf3db0ce, &Table.SysNtInitializeNlsFiles);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8b8c4ce5, &Table.SysNtInitializeRegistry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x67e41b7e, &Table.SysNtInitiatePowerAction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x485fec37, &Table.SysNtIsSystemResumeAutomatic);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3877cfe9, &Table.SysNtIsUILanguageComitted);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb24b56ec, &Table.SysNtListenPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb0490de4, &Table.SysNtLoadDriver);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd6aa3788, &Table.SysNtLoadEnclaveData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x71129267, &Table.SysNtLoadKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb5e2b8b5, &Table.SysNtLoadKey2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x92bc0d9a, &Table.SysNtLoadKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb8cceac7, &Table.SysNtLockFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc6e84368, &Table.SysNtLockProductActivationKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdc4c1b45, &Table.SysNtLockRegistryKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa3be13a7, &Table.SysNtLockVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x31fd9691, &Table.SysNtMakePermanentObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x622b01a8, &Table.SysNtMakeTemporaryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6da6df3d, &Table.SysNtManagePartition);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7843ecb6, &Table.SysNtMapCMFModule);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x67de1806, &Table.SysNtMapUserPhysicalPages);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x747c3670, &Table.SysNtMapViewOfSectionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8b8941c2, &Table.SysNtModifyBootEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x886f9a1a, &Table.SysNtModifyDriverEntry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xed16f42c, &Table.SysNtNotifyChangeDirectoryFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1d0f300f, &Table.SysNtNotifyChangeDirectoryFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfc6e41d8, &Table.SysNtNotifyChangeKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5c229539, &Table.SysNtNotifyChangeMultipleKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2b0a715d, &Table.SysNtNotifyChangeSession);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9931a12b, &Table.SysNtOpenEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3bb51ed0, &Table.SysNtOpenEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd62e5fdc, &Table.SysNtOpenIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdb9a7b3c, &Table.SysNtOpenJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x549dce8, &Table.SysNtOpenKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xeaf3b8bc, &Table.SysNtOpenKeyTransacted);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6eaad09f, &Table.SysNtOpenKeyTransactedEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3c3d19ba, &Table.SysNtOpenKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xff154e45, &Table.SysNtOpenMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1c8e6603, &Table.SysNtOpenObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xad425dc4, &Table.SysNtOpenPartition);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9f172b6, &Table.SysNtOpenPrivateNamespace);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x68e7676e, &Table.SysNtOpenProcessToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb99421cf, &Table.SysNtOpenRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3204f08b, &Table.SysNtOpenResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3303e1aa, &Table.SysNtOpenSemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbc78dca, &Table.SysNtOpenSession);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1e2d2437, &Table.SysNtOpenSymbolicLinkObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe8bd22e6, &Table.SysNtOpenThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x414bdcd, &Table.SysNtOpenTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9504248, &Table.SysNtOpenTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8827e04d, &Table.SysNtOpenTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8abc641, &Table.SysNtPlugPlayControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x50a4bda1, &Table.SysNtPrePrepareComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x62fb017, &Table.SysNtPrePrepareEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x749ef058, &Table.SysNtPrepareComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x84b8610e, &Table.SysNtPrepareEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd46fa35b, &Table.SysNtPrivilegeCheck);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5f6d9fe, &Table.SysNtPrivilegeObjectAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x38cc7290, &Table.SysNtPrivilegedServiceAuditAlarm);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x874756d3, &Table.SysNtPropagationComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x87de407, &Table.SysNtPropagationFailed);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x72d49505, &Table.SysNtPulseEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x58cea370, &Table.SysNtQueryAuxiliaryCounterFrequency);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc5f3b7c8, &Table.SysNtQueryBootEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5e43884a, &Table.SysNtQueryBootOptions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x73f6b2dc, &Table.SysNtQueryDebugFilterState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xec65fe78, &Table.SysNtQueryDirectoryFileEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe689be, &Table.SysNtQueryDirectoryObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x60f06a80, &Table.SysNtQueryDriverEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1930af94, &Table.SysNtQueryEaFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6b124a0, &Table.SysNtQueryFullAttributesFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x54147a83, &Table.SysNtQueryInformationAtom);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb3751f88, &Table.SysNtQueryInformationByName);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1ab4fad1, &Table.SysNtQueryInformationEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x92adda2, &Table.SysNtQueryInformationJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x541c9dbf, &Table.SysNtQueryInformationPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xea8a9af1, &Table.SysNtQueryInformationResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9abc91be, &Table.SysNtQueryInformationTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfd314673, &Table.SysNtQueryInformationTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa20ae342, &Table.SysNtQueryInformationWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x69f35841, &Table.SysNtQueryInstallUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xeaed6944, &Table.SysNtQueryIntervalProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe40f76d8, &Table.SysNtQueryIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3329892a, &Table.SysNtQueryLicenseValue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x27f9ff78, &Table.SysNtQueryMultipleValueKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd031041, &Table.SysNtQueryMutant);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2c3e7102, &Table.SysNtQueryOpenSubKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x35dddfe5, &Table.SysNtQueryOpenSubKeysEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x10fddcf0, &Table.SysNtQueryPortInformationProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb37876da, &Table.SysNtQueryQuotaInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdadd63ea, &Table.SysNtQuerySecurityAttributesToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1cd13ebb, &Table.SysNtQuerySecurityObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x10adb2, &Table.SysNtQuerySecurityPolicy);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xac981916, &Table.SysNtQuerySemaphore);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xad661033, &Table.SysNtQuerySymbolicLinkObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdedc31e3, &Table.SysNtQuerySystemEnvironmentValue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe6082206, &Table.SysNtQuerySystemEnvironmentValueEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xaccc1432, &Table.SysNtQuerySystemInformationEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb621b7c5, &Table.SysNtQueryTimerResolution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe7854894, &Table.SysNtQueryWnfStateData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe149cb87, &Table.SysNtQueryWnfStateNameInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x62058aa2, &Table.SysNtQueueApcThreadEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe2b5a51d, &Table.SysNtRaiseException);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x81602cb3, &Table.SysNtRaiseHardError);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x316b679f, &Table.SysNtReadOnlyEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7bd16197, &Table.SysNtRecoverEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x26e385f7, &Table.SysNtRecoverResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5eede4c9, &Table.SysNtRecoverTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa95cda1d, &Table.SysNtRegisterProtocolAddressInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa47f8dc5, &Table.SysNtRegisterThreadTerminatePort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xcc8f96cb, &Table.SysNtReleaseKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xef42b4c3, &Table.SysNtReleaseWorkerFactoryWorker);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xeeef60b3, &Table.SysNtRemoveIoCompletionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x351ea08c, &Table.SysNtRemoveProcessDebug);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf6c8825f, &Table.SysNtRenameKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa7faed17, &Table.SysNtRenameTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa216ae3b, &Table.SysNtReplaceKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7809712a, &Table.SysNtReplacePartitionUnit);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbcfd0c8e, &Table.SysNtReplyWaitReplyPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe1433322, &Table.SysNtRequestPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x967b6a5b, &Table.SysNtResetEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdac9983b, &Table.SysNtResetWriteWatch);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xec47d923, &Table.SysNtRestoreKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8c2124a0, &Table.SysNtResumeProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5f54633d, &Table.SysNtRevertContainerImpersonation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x76e0ec7d, &Table.SysNtRollbackComplete);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xca84e3e3, &Table.SysNtRollbackEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x70999387, &Table.SysNtRollbackRegistryTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4c8b7400, &Table.SysNtRollbackTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x8ff06a01, &Table.SysNtRollforwardTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4ee69388, &Table.SysNtSaveKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb03a6eb, &Table.SysNtSaveKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x253c9e91, &Table.SysNtSaveMergedKeys);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdd8392aa, &Table.SysNtSecureConnectPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xddd487f4, &Table.SysNtSerializeBoot);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x47222562, &Table.SysNtSetBootEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbb17afa4, &Table.SysNtSetBootOptions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa3f302e5, &Table.SysNtSetCachedSigningLevel);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xda715f73, &Table.SysNtSetCachedSigningLevel2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x23bcf3e7, &Table.SysNtSetContextThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x674cf3f6, &Table.SysNtSetDebugFilterState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7f2069f1, &Table.SysNtSetDefaultHardErrorPort);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x520e14ff, &Table.SysNtSetDefaultLocale);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x74a3274d, &Table.SysNtSetDefaultUILanguage);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x94b6abba, &Table.SysNtSetDriverEntryOrder);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf52844ce, &Table.SysNtSetEaFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x76b4516, &Table.SysNtSetHighEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x647a371f, &Table.SysNtSetHighWaitLowEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa8c45758, &Table.SysNtSetIRTimer);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9de72c20, &Table.SysNtSetInformationDebugObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7b3cd4b, &Table.SysNtSetInformationEnlistment);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf8d09b5c, &Table.SysNtSetInformationJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6c4f8555, &Table.SysNtSetInformationKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7e6bdf2b, &Table.SysNtSetInformationResourceManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7088e9be, &Table.SysNtSetInformationSymbolicLink);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x53a8f22d, &Table.SysNtSetInformationToken);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe79c1ae8, &Table.SysNtSetInformationTransaction);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc6926ced, &Table.SysNtSetInformationTransactionManager);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf499b60e, &Table.SysNtSetInformationVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x716bb67c, &Table.SysNtSetInformationWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x320a25be, &Table.SysNtSetIntervalProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb45fbaf2, &Table.SysNtSetIoCompletion);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x370d2b55, &Table.SysNtSetIoCompletionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x26deafe6, &Table.SysNtSetLdtEntries);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe6046144, &Table.SysNtSetLowEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9e8c9fff, &Table.SysNtSetLowWaitHighEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x612e0cf4, &Table.SysNtSetQuotaInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x9e01add5, &Table.SysNtSetSecurityObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2a3db91d, &Table.SysNtSetSystemEnvironmentValue);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb56af530, &Table.SysNtSetSystemEnvironmentValueEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6a669e09, &Table.SysNtSetSystemInformation);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2a4aeef1, &Table.SysNtSetSystemPowerState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x13bdd3f0, &Table.SysNtSetSystemTime);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1a5ffd17, &Table.SysNtSetThreadExecutionState);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x1af5dcf1, &Table.SysNtSetTimer2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x512bd846, &Table.SysNtSetTimerEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xdf4e723f, &Table.SysNtSetTimerResolution);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x170ca1fc, &Table.SysNtSetUuidSeed);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xef8b91e6, &Table.SysNtSetVolumeInformationFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x97f203b1, &Table.SysNtSetWnfProcessNotificationEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6992b9df, &Table.SysNtShutdownSystem);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6cb23d22, &Table.SysNtShutdownWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x68ea06fa, &Table.SysNtSignalAndWaitForSingleObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xea01840, &Table.SysNtSinglePhaseReject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xe0556791, &Table.SysNtStartProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc835b1e9, &Table.SysNtStopProfile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd6b42b8c, &Table.SysNtSubscribeWnfStateChange);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x473eaedf, &Table.SysNtSuspendProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x43c9ae56, &Table.SysNtSuspendThread);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xf3cc3123, &Table.SysNtSystemDebugControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xad2d3639, &Table.SysNtTerminateEnclave);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x5c647795, &Table.SysNtTerminateJobObject);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6a22a4e8, &Table.SysNtTestAlert);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x13112fa3, &Table.SysNtThawRegistry);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x74415303, &Table.SysNtThawTransactions);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6d806820, &Table.SysNtTraceControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa80f1615, &Table.SysNtTranslateFilePath);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6d1b4fbc, &Table.SysNtUmsThreadYield);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x87b0e1, &Table.SysNtUnloadDriver);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x4a87e04, &Table.SysNtUnloadKey);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x18ba00f2, &Table.SysNtUnloadKey2);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x6e189c67, &Table.SysNtUnloadKeyEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x3847104, &Table.SysNtUnlockFile);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbfee7704, &Table.SysNtUnlockVirtualMemory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xfe90ee7d, &Table.SysNtUnmapViewOfSectionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x959199a9, &Table.SysNtUnsubscribeWnfStateChange);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa65ceee7, &Table.SysNtUpdateWnfStateData);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x46596d18, &Table.SysNtVdmControl);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc4af448c, &Table.SysNtWaitForAlertByThreadId);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x2c54489b, &Table.SysNtWaitForDebugEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xadc33ee0, &Table.SysNtWaitForKeyedEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xd7005baf, &Table.SysNtWaitForWorkViaWorkerFactory);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xab45559d, &Table.SysNtWaitHighEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xbfafe6eb, &Table.SysNtWaitLowEventPair);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x870e8d1a, &Table.SysNtCreateSectionEx);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xc192319d, &Table.SysNtCreateCrossVmEvent);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xa84d5b8f, &Table.SysNtSetInformationProcess);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0x7604fddc, &Table.SysNtManageHotPatch);
    Table.isResolved = ResolveSyscall(pNtdllBase, pImageExportDirectory, 0xb71076be, &Table.SysNtContinueEx);
    SysTable = Table;
    return;
}

int main(int argv, char** argc)
{
    SystemCalls Syscalls = SystemCalls();
    PTEB ThisTeb = (PTEB)__readgsqword(0x30);
    PPEB ThisPeb = ThisTeb->ProcessEnvironmentBlock;
    Syscalls.ThisPeb = ThisPeb;
    Syscalls.ResolveSyscallTable();
    if (Syscalls.SysTable.isResolved)
    {
		printf("Syscall table resolved\n");
        // Convert 5 seconds to 100-nanosecond intervals
        LARGE_INTEGER delayInterval;
        delayInterval.QuadPart = -5LL * 10000000LL;
        SyscallPrepare(Syscalls.SysTable.SysNtDelayExecution.wSyscallNr, Syscalls.SysTable.SysNtDelayExecution.pRecycled);
        NTSTATUS status = SysNtDelayExecution(FALSE, &delayInterval);
        if (NT_SUCCESS(status))
		{ 
            printf("DelayExecution success\n");
        }
        else
        {
            printf("DelayExecution failed\n");
        }
	}
    else
    {
		printf("Syscall table not resolved\n");
	}
}