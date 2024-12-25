#pragma once
#include <Windows.h>
#include <atomic>
#include <vector>
#include <future>
#include <memory>

class SecureString;

struct SecureTask {
    int ID;
    int AgentID;
    std::unique_ptr<SecureString> Command;
    std::vector<std::unique_ptr<SecureString>> Arguments;  // Changed to vector of unique_ptr<SecureString>
    int Timeout;
    bool Active;
    bool Success;
    bool InQueue;
    std::unique_ptr<SecureString> CreateTime;
    std::unique_ptr<SecureString> EndTime;
    std::unique_ptr<SecureString> Result;

    // Custom copy constructor
    SecureTask(const SecureTask& other);

    // Custom copy assignment operator
    SecureTask& operator=(const SecureTask& other);

    // Default constructor
    SecureTask();

    // Destructor
    ~SecureTask();
};

struct ThreadDetails {
    HANDLE Handle;
    bool Success;
};

struct FutureWithTask {
    std::future<std::unique_ptr<SecureString>> future;
    SecureTask task;
    ThreadDetails* details;
};

class ApcWorkerThread {
private:
    // Private methods
    static DWORD WINAPI ThreadFunction(LPVOID param);

    // Private members
    static std::vector<HANDLE> ApcHandles;

public:
    // Constructor
    explicit ApcWorkerThread();
    
    // Public methods
    static bool WaitForCompletion(DWORD milliseconds);
    static void TerminateThreads();

    // Public members
    HANDLE Handle;
    DWORD Id;
    ThreadDetails Details;
    static std::vector<ThreadDetails> Threads;    
    std::atomic<bool> Running;
    std::atomic<bool> Completed; // Tracks completion of APC work

    // Destructor
    ~ApcWorkerThread() {};
};
