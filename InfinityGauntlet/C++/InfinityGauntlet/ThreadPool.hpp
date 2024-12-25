#pragma once
#include <vector>
#include <memory>
#include <tuple>
#include <Windows.h>

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
    bool TimedOut;
    std::unique_ptr<SecureString> CreateTime;
    std::unique_ptr<SecureString> EndTime;
    std::unique_ptr<SecureString> Result;
    HANDLE CompletionEvent;

    // Custom copy constructor
    SecureTask(const SecureTask& other);

    // Custom copy assignment operator
    SecureTask& operator=(const SecureTask& other);

    // Default constructor
    SecureTask();

    // Destructor
    ~SecureTask();
};

// Templated structure that can hold a SecureTask pointer and as many arguments as necessary
template<typename... Args>
struct WorkItemContext {
    SecureTask* Task;
    std::tuple<Args...> Arguments;

    // Constructor to initialize the SecureTask pointer and the arguments tuple
    WorkItemContext(SecureTask* task, Args... args) : Task(task), Arguments(std::make_tuple(args...)) {}
};

/*
    // Context with no additional arguments
    WorkItemContext<> context0(task);

    // Context with one argument
    WorkItemContext<int> context1(task, 42);

    // Context with three arguments of different types
    WorkItemContext<int, double, char> context3(task, 42, 3.14, 'a');
*/

struct WorkDetails {
    PTP_WORK Work;
    PTP_POOL Pool;
};

class ThreadPool {
public:
    static ThreadPool& Get() {
        static ThreadPool threadPool; // Guaranteed to be destroyed and instantiated on first use.
        return threadPool;
    }

    // Public methods
    static void SubmitWorkItem(PTP_WORK_CALLBACK WorkItemCallback, PVOID WorkContext, SecureTask* Task, int BatchSize);
    static void WaitForCompletion(DWORD milliseconds, std::vector<SecureTask>* tasks);

    // Public members    

    // Delete copy/move constructors and assignment operators
    ThreadPool(ThreadPool const&) = delete;
    void operator=(ThreadPool const&) = delete;
    ThreadPool(ThreadPool&&) = delete;
    void operator=(ThreadPool&&) = delete;

private:
    ThreadPool() {};

    // Private methods
    static void ResetVectors();

    // Private members
    static std::vector<HANDLE> CompletionHandles;
    static std::vector<WorkDetails> WorkDetailsList;
};
