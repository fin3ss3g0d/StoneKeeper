#include "Header.h"

volatile LONG shouldCancel = 0;

// Timer callback prototype might vary
void CALLBACK TimerCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Parameter, PTP_TIMER Timer) {
	printf("Timer callback is executing.\n");

	InterlockedExchange(&shouldCancel, 1); // Signal cancellation
}

void CALLBACK WorkItemCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
	printf("Work callback is executing.\n");

	while (InterlockedCompareExchange(&shouldCancel, 0, 0) == 0) {
		// Perform work here in small, interruptible chunks
		Sleep(1000);

		// Check for cancellation signal
		if (InterlockedCompareExchange(&shouldCancel, 0, 0) != 0) {
			// Perform cleanup and exit
			printf("Work callback is cancelled. Timeout reached.\n");
			break;
		}
	}
}

VOID CALLBACK WaitCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WAIT Wait, TP_WAIT_RESULT WaitResult) {
	printf("Wait callback is executing.\n");
}

VOID CALLBACK IoCompletionCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PVOID Overlapped, ULONG IoResult, ULONG_PTR NumberOfBytesTransferred, PTP_IO Io) {
	printf("I/O completion callback is executing.\n");
}

void TestThreadpoolCallbackNative() {
	// Load the thread pool functions
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	pTpAllocPool TpAllocPool = (pTpAllocPool)GetProcAddress(hNtDll, "TpAllocPool");
	pTpSetPoolMaxThreads TpSetPoolMaxThreads = (pTpSetPoolMaxThreads)GetProcAddress(hNtDll, "TpSetPoolMaxThreads");
	pTpSetPoolMinThreads TpSetPoolMinThreads = (pTpSetPoolMinThreads)GetProcAddress(hNtDll, "TpSetPoolMinThreads");
	pTpReleasePool TpReleasePool = (pTpReleasePool)GetProcAddress(hNtDll, "TpReleasePool");
	pTpWaitForWork TpWaitForWork = (pTpWaitForWork)GetProcAddress(hNtDll, "TpWaitForWork");
	pTpPostWork TpPostWork = (pTpPostWork)GetProcAddress(hNtDll, "TpPostWork");
	pTpReleaseWork TpReleaseWork = (pTpReleaseWork)GetProcAddress(hNtDll, "TpReleaseWork");
	pTpAllocWork TpAllocWork = (pTpAllocWork)GetProcAddress(hNtDll, "TpAllocWork");
	pTpAllocTimer TpAllocTimer = (pTpAllocTimer)GetProcAddress(hNtDll, "TpAllocTimer");
	pTpSetTimer TpSetTimer = (pTpSetTimer)GetProcAddress(hNtDll, "TpSetTimer");
	pTpReleaseTimer TpReleaseTimer = (pTpReleaseTimer)GetProcAddress(hNtDll, "TpReleaseTimer");
	pTpAllocWait TpAllocWait = (pTpAllocWait)GetProcAddress(hNtDll, "TpAllocWait");
	pTpSetWait TpSetWait = (pTpSetWait)GetProcAddress(hNtDll, "TpSetWait");
	pTpReleaseWait TpReleaseWait = (pTpReleaseWait)GetProcAddress(hNtDll, "TpReleaseWait");
	pTpAllocIoCompletion TpAllocIoCompletion = (pTpAllocIoCompletion)GetProcAddress(hNtDll, "TpAllocIoCompletion");
	pTpReleaseIoCompletion TpReleaseIoCompletion = (pTpReleaseIoCompletion)GetProcAddress(hNtDll, "TpReleaseIoCompletion");

	NTSTATUS status = 0;
	PTP_POOL pool = NULL;
	PTP_WORK work = NULL;
	PTP_TIMER timer = NULL;
	PTP_WAIT wait = NULL;
	PTP_IO ioCompletion = NULL;
	TP_CALLBACK_ENVIRON pcbe;
	HANDLE waitEvent = NULL;

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

	// Correctly allocate a work item with the callback and the callback environment
	status = TpAllocWork(&work, (PTP_WORK_CALLBACK)WorkItemCallback, NULL, &pcbe);
	if (!NT_SUCCESS(status)) {
		printf("TpAllocWork failed with status 0x%X\n", status);
		return;
	}

	// Post the work item to the thread pool
	status = TpPostWork(work);
	if (!NT_SUCCESS(status)) {
		printf("TpPostWork failed with status 0x%X\n", status);
		return;
	}

	// Allocate a timer
	status = TpAllocTimer(&timer, (PTP_TIMER_CALLBACK)TimerCallback, NULL, &pcbe);
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
	Sleep(10000); // Wait for 10 seconds

	// Create an event to wait on
	waitEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (NULL == waitEvent) {
		printf("CreateEvent failed with LastError: %u\n", GetLastError());
		return;
	}

	// Allocate a wait object
	status = TpAllocWait(&wait, (PTP_WAIT_CALLBACK)WaitCallback, NULL, &pcbe);
	if (!NT_SUCCESS(status)) {
		printf("TpAllocWait failed with status 0x%X\n", status);
		return;
	}

	// Set the wait object to wait on the event
	// This example sets the wait object to wait indefinitely until the event is signaled
	TpSetWait(wait, waitEvent, NULL);

	// Simulate signaling the event after a delay (for demonstration)
	SetEvent(waitEvent);

	// Wait for an additional time to ensure callbacks can complete
	Sleep(5000); // Wait for another 5 seconds

	HANDLE hPipe = CreateNamedPipe(
		L"\\\\.\\pipe\\MyTestPipe",
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // Use overlapped (asynchronous) mode
		PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
		1,  // Number of instances
		1024,  // Out buffer size
		1024,  // In buffer size
		0,     // Default time-out value
		NULL); // Default security attributes

	if (hPipe == INVALID_HANDLE_VALUE) {
		printf("CreateNamedPipe failed with error: %d\n", GetLastError());
		return 1;
	}

	// Prepare the OVERLAPPED structure for asynchronous ConnectNamedPipe
	OVERLAPPED olConnect = { 0 };
	if (ConnectNamedPipe(hPipe, &olConnect) || GetLastError() == ERROR_PIPE_CONNECTED) {
		printf("Client connected or connection in progress...\n");
	}
	else if (GetLastError() != ERROR_IO_PENDING) {
		printf("ConnectNamedPipe failed with error: %d\n", GetLastError());
		CloseHandle(hPipe);
		return 1;
	}

	// Proceed with the I/O completion setup
	status = TpAllocIoCompletion(&ioCompletion, hPipe, (PTP_WIN32_IO_CALLBACK)IoCompletionCallback, NULL, &pcbe);
	if (!NT_SUCCESS(status)) {
		printf("TpAllocIoCompletion failed. Status 0x%x\n", status);
		CloseHandle(hPipe);
		return 1;
	}

	// Client simulation (for educational purposes, typically in another thread or process)
	HANDLE hClientPipe = CreateFile(
		L"\\\\.\\pipe\\MyTestPipe",
		GENERIC_READ | GENERIC_WRITE,
		0,    // no sharing
		NULL, // default security attributes
		OPEN_EXISTING, // opens existing pipe
		0,    // default attributes
		NULL); // no template file

	if (hClientPipe == INVALID_HANDLE_VALUE) {
		printf("Failed to connect to pipe as client. Error: %d\n", GetLastError());
		// Perform necessary cleanup...
		return 1;
	}

	printf("Connected to pipe as client. Client pipe handle: %p\n", hClientPipe);

	OVERLAPPED olWrite = { 0 };
	unsigned char* message = "Hello from client!";
	DWORD bytesWritten;
	BOOL writeResult = WriteFile(
		hClientPipe,         // Handle to the pipe
		message,             // Buffer to write from
		(DWORD)strlen(message) + 1, // Number of bytes to write, include the NULL terminator
		&bytesWritten,       // Number of bytes written
		&olWrite);               // Overlapped I/O

	if (!writeResult) {
		printf("Failed to write to pipe. Error: %d\n", GetLastError());
	}

	printf("Write to pipe succeeded. Bytes written: %d\n", bytesWritten);

	unsigned char buffer[1024];
	DWORD bytesRead;
	OVERLAPPED ol = { 0 };

	BOOL readResult = ReadFile(
		hPipe,
		buffer,
		sizeof(buffer),
		&bytesRead,
		&ol);

	if (!readResult && GetLastError() != ERROR_IO_PENDING) {
		printf("ReadFile failed with error: %d\n", GetLastError());
		CloseHandle(hPipe);
		return 1;
	}

	printf("ReadFile succeeded. Bytes read: %d\n", bytesRead);

	// Here you can simulate client behavior or proceed with other tasks
	//Sleep(10000); // Wait for 10 seconds

	// Cleanup
	CloseHandle(hPipe);
	TpReleaseIoCompletion(ioCompletion, &pcbe);

	/*
	* Unused, it's best practice to use cooperative cancellation using timers.
	* This will wait for all work items to finish, if something doesn't finish
	* for whatever reason, it will wait indefinitely.
	*/
	/*
	status = TpWaitForWork(work, FALSE);
	if (!NT_SUCCESS(status)) {
		printf("TpWaitForWork failed with status 0x%X\n", status);
		return;
	}
	*/

	// Release the wait object when it is done
	status = TpReleaseWait(wait);
	if (!NT_SUCCESS(status)) {
		printf("TpReleaseWait failed with status 0x%X\n", status);
	}

	CloseHandle(waitEvent);

	// Release the timer when it is done
	status = TpReleaseTimer(timer);
	if (!NT_SUCCESS(status)) {
		printf("TpReleaseTimer failed with status 0x%X\n", status);
		return;
	}

	// Release the work item when it is done
	status = TpReleaseWork(work);
	if (!NT_SUCCESS(status)) {
		printf("TpReleaseWork failed with status 0x%X\n", status);
		return;
	}

	// Cleanup
	status = TpReleasePool(pool);
	if (!NT_SUCCESS(status)) {
		printf("TpReleasePool failed with status 0x%X\n", status);
		return;
	}
}

void TestAlpc() {
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	pNtAlpcCreatePort NtAlpcCreatePort = (pNtAlpcCreatePort)GetProcAddress(hNtDll, "NtAlpcCreatePort");
	pNtAlpcConnectPort NtAlpcConnectPort = (pNtAlpcConnectPort)GetProcAddress(hNtDll, "NtAlpcConnectPort");
	pNtAlpcSendWaitReceivePort NtAlpcSendWaitReceivePort = (pNtAlpcSendWaitReceivePort)GetProcAddress(hNtDll, "NtAlpcSendWaitReceivePort");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtDll, "RtlInitUnicodeString");

	NTSTATUS status = 0;
	OBJECT_ATTRIBUTES objAttr = { 0 };
	UNICODE_STRING portName;

	// Initialize the UNICODE_STRING with the desired port name
	RtlInitUnicodeString(&portName, L"\\RPC Control\\MyNamedPort");

	// Initialize the OBJECT_ATTRIBUTES structure
	InitializeObjectAttributes(&objAttr, &portName, OBJ_CASE_INSENSITIVE, NULL, NULL);

	HANDLE serverPortHandle = NULL;
	status = NtAlpcCreatePort(&serverPortHandle, &objAttr, NULL);
	if (!NT_SUCCESS(status)) {
		printf("NtAlpcCreatePort failed with status 0x%X\n", status);
		return;
	}

	HANDLE clientPortHandle = NULL;
	printf("Connecting to port %ls\n", portName.Buffer);
	status = NtAlpcConnectPort(&clientPortHandle, &portName, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		printf("NtAlpcConnectPort failed with status 0x%X\n", status);
		return;
	}

	printf("Server handle: %p Client handle: %p\n", serverPortHandle, clientPortHandle);

	SIZE_T MessageSize = sizeof(L"Hello World!");

	PORT_MESSAGE portMsg = { 0 };
	portMsg.u1.s1.DataLength = MessageSize;
	portMsg.u1.s1.TotalLength = MessageSize + sizeof(PORT_MESSAGE);

	LPVOID lpMem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MessageSize + sizeof(PORT_MESSAGE));
	if (lpMem != NULL)
	{
		memcpy(lpMem, &portMsg, sizeof(PORT_MESSAGE));
		memcpy((BYTE*)lpMem + sizeof(PORT_MESSAGE), L"Hello World!", MessageSize);
	}

	status = NtAlpcSendWaitReceivePort(clientPortHandle, 0, (PPORT_MESSAGE)lpMem, NULL, NULL, NULL, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		printf("NtAlpcSendWaitReceivePort failed with status 0x%X\n", status);
		return;
	}

	/*
	* I apologize for the confusion. The status code 0xC0000707 is indeed STATUS_LPC_REQUESTS_NOT_ALLOWED, which indicates that the ALPC port does not accept new request messages.
	* This error can occur if the port has not been correctly set up to receive the type of messages you are attempting to send. Here are a few specific reasons why you might be receiving this error and some steps you can take to address it:
	* ALPC Port Configuration: The ALPC port may need to be specifically configured to allow message requests. This can involve setting flags in the ALPC_PORT_ATTRIBUTES structure when the port is created. If this structure is not properly initialized and passed to the NtAlpcCreatePort function, the port might not accept certain types of messages.
	* Message Type: The Type field in the PORT_MESSAGE structure is important and should be set to the correct message type that the ALPC port is expecting. For example, ALPC may distinguish between connection requests, data messages, and other types of communication. Make sure you're setting the Type field to an appropriate value for the communication you're attempting.
	* Server-Side Handling: On the server side, there needs to be a mechanism in place to accept and process incoming messages. This usually involves a message loop that calls NtAlpcSendWaitReceivePort or a similar function to handle incoming message requests. If the server is not properly set up to handle requests, you may encounter STATUS_LPC_REQUESTS_NOT_ALLOWED.
	*/
}
