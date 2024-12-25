#pragma once
#include <Windows.h>

// Spoof types
#define SPOOF_TYPE_ZERO_TRACE 1
#define SPOOF_TYPE_TIB_COPY 2

// PVOID rcxGadget, PVOID rdxGadget, PVOID shadowFixerGadget, PVOID r8Gadget, PLARGE_INTEGER liTimeout, PVOID pNtWaitForSingleObject, PVOID pNtDelayExecution, HANDLE hTimer1, HANDLE hTimer2, HANDLE hTimer3, HANDLE hTimer4
extern "C" void PentaNtWaitAndDelayZeroTrace(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
// PVOID rcxGadget, PVOID rdxGadget, PVOID shadowFixerGadget, PVOID r8Gadget, PLARGE_INTEGER liTimeout, PVOID pNtWaitForSingleObject, PVOID pNtDelayExecution, HANDLE hTimer1, HANDLE hTimer2, HANDLE hTimer3, HANDLE hTimer4, HANDLE hTimer5, HANDLE hTimer6, HANDLE hTimer7
extern "C" void SeptaNtWaitAndDelay(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);

typedef VOID(NTAPI* PTIMER_APC_ROUTINE)(
    _In_ PVOID TimerContext,
    _In_ ULONG TimerLowValue,
    _In_ LONG TimerHighValue);

class SleepObfuscation {
public:
    static SleepObfuscation& Get() {
        static SleepObfuscation sleepObfuscation; // Guaranteed to be destroyed and instantiated on first use.
        return sleepObfuscation;
    }

    // Public methods
    static void SnapSiestaZeroTrace();
    static void SnapSiestaTibCopy();

    // Delete copy/move constructors and assignment operators
    SleepObfuscation(SleepObfuscation const&) = delete;
    void operator=(SleepObfuscation const&) = delete;
    SleepObfuscation(SleepObfuscation&&) = delete;
    void operator=(SleepObfuscation&&) = delete;

private:
    SleepObfuscation() {};

    // Private methods
    static void DoStackHeapEncryptDecrypt(bool encrypt);
    static void GenerateRandomKey(CHAR array[], size_t length);
    static PVOID FindGadget(PBYTE sequence);

    // Private members
};