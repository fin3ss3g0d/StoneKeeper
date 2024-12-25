#include "Header.hpp"

struct MyParams {
	CHAR* dll;
	PVOID pLoadLibraryA;
};

PVOID fpLoadLibraryA;

extern "C" void CALLBACK ExtractAndJump(PTP_CALLBACK_INSTANCE Instance, PVOID Parameter, PTP_TIMER Timer);

void ProxyDllLoad() {
	// Load the thread pool functions	
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	pTpAllocPool TpAllocPool = (pTpAllocPool)GetProcAddress(hNtDll, "TpAllocPool");
	pTpSetPoolMaxThreads TpSetPoolMaxThreads = (pTpSetPoolMaxThreads)GetProcAddress(hNtDll, "TpSetPoolMaxThreads");
	pTpSetPoolMinThreads TpSetPoolMinThreads = (pTpSetPoolMinThreads)GetProcAddress(hNtDll, "TpSetPoolMinThreads");
	pTpReleasePool TpReleasePool = (pTpReleasePool)GetProcAddress(hNtDll, "TpReleasePool");
	pTpAllocTimer TpAllocTimer = (pTpAllocTimer)GetProcAddress(hNtDll, "TpAllocTimer");
	pTpSetTimer TpSetTimer = (pTpSetTimer)GetProcAddress(hNtDll, "TpSetTimer");
	pTpReleaseTimer TpReleaseTimer = (pTpReleaseTimer)GetProcAddress(hNtDll, "TpReleaseTimer");

	NTSTATUS status = 0;
	PTP_POOL pool = NULL;
	PTP_TIMER timer = NULL;
	TP_CALLBACK_ENVIRON pcbe;

	// Get the address of LoadLibraryA
	fpLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

	// Prepare the DLL string pointer
	CHAR* dll = (CHAR*)"wininet.dll";

	// Prepare the structure
	MyParams params;
	params.dll = dll;
	params.pLoadLibraryA = fpLoadLibraryA;

	// Set the maximum number of threads for the pool
	LONG maxThreads = 2;

	// Set the minimum number of threads for the pool
	LONG minThreads = 1;

	// Allocate a new thread pool
	status = TpAllocPool(&pool, NULL);
	if (!NT_SUCCESS(status)) {
		printf("TpAllocPool failed with status 0x%X\n", status);
		return;
	}

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

	// Set the minimum number of threads for the pool
	status = TpSetPoolMinThreads(pool, minThreads);
	if (!NT_SUCCESS(status)) {
		printf("TpSetPoolMinThreads failed with status 0x%X\n", status);
		return;
	}

	// Set the maximum number of threads for the pool
	status = TpSetPoolMaxThreads(pool, maxThreads);
	if (!NT_SUCCESS(status)) {
		printf("TpSetPoolMaxThreads failed with status 0x%X\n", status);
		return;
	}

	// Allocate a timer
	status = TpAllocTimer(&timer, (PTP_TIMER_CALLBACK)ExtractAndJump, &params, &pcbe);	
	if (!NT_SUCCESS(status)) {
		printf("TpAllocTimer failed with status 0x%X\n", status);
		return;
	}

	// Set the timer to fire after 5 seconds
	LARGE_INTEGER dueTime;
	dueTime.QuadPart = (ULONGLONG)-(5 * 10 * 1000 * 1000);
	status = TpSetTimer(timer, &dueTime, 0, 0);
	if (!NT_SUCCESS(status)) {
		printf("TpSetTimer failed with status 0x%X\n", status);
		return;
	}

	/*
	* Sleep for 10 seconds, test the timer expiration
	* After five seconds, the timer callback will be executed
	* You would normally wait on something like an event and set it
	* in the work item callback to signal that the work is done
	*/
	Sleep(60000*3); // Wait for 10 seconds

	// Release the timer when it is done
	status = TpReleaseTimer(timer);
	if (!NT_SUCCESS(status)) {
		printf("TpReleaseTimer failed with status 0x%X\n", status);
		return;
	}

	// Cleanup
	status = TpReleasePool(pool);
	if (!NT_SUCCESS(status)) {
		printf("TpReleasePool failed with status 0x%X\n", status);
		return;
	}
}

int main(int argc, char* argv[]) {
	ProxyDllLoad();
}