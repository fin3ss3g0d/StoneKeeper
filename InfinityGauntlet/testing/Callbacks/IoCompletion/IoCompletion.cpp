#include <windows.h>
#include <stdio.h>

extern "C" void CALLBACK IoCompletionCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PVOID Overlapped, ULONG IoResult, ULONG_PTR NumberOfBytesTransferred, PTP_IO Io);
void StartRead(HANDLE pipe, PTP_IO tpIo, OVERLAPPED* overlapped, char* buffer);
void CALLBACK ClientWorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

PVOID pLoadLibraryA;
HANDLE g_WriteCompleteEvent; // Global event to signal completion of write operation

typedef struct LOAD_CONTEXT {
    char* DllName;
    PVOID pLoadLibraryA;
};

int main()
{
    HANDLE pipe;
    PTP_IO tpIo = NULL;
    OVERLAPPED overlapped = { 0 };
    char buffer[128] = { 0 };

    // Get the address of LoadLibraryA
    pLoadLibraryA = GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");

    // Prepare the LOAD_CONTEXT structure
    LOAD_CONTEXT loadContext;
    loadContext.DllName = (char*)"wininet.dll";
    loadContext.pLoadLibraryA = pLoadLibraryA;

    // Create a global event to signal when the write operation is complete
    g_WriteCompleteEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_WriteCompleteEvent == NULL) {
        printf("Failed to create write complete event\n");
        return 1;
    }

    // Create a named pipe with FILE_FLAG_OVERLAPPED flag
    pipe = CreateNamedPipe(
        TEXT("\\\\.\\pipe\\MyPipe"),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,  // Number of instances
        4096,  // Out buffer size
        4096,  // In buffer size
        0,  // Timeout in milliseconds
        NULL); // Default security attributes

    if (pipe == INVALID_HANDLE_VALUE) {
        printf("Failed to create named pipe\n");
        CloseHandle(g_WriteCompleteEvent);
        return 1;
    }

    // Create an event for the OVERLAPPED structure
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (overlapped.hEvent == NULL) {
        printf("Failed to create event\n");
        CloseHandle(pipe);
        CloseHandle(g_WriteCompleteEvent);
        return 1;
    }

    // Associate the pipe with the thread pool
    tpIo = CreateThreadpoolIo(pipe, IoCompletionCallback, &loadContext, NULL);
    if (tpIo == NULL) {
        printf("Failed to associate pipe with thread pool\n");
        CloseHandle(overlapped.hEvent);
        CloseHandle(pipe);
        CloseHandle(g_WriteCompleteEvent);
        return 1;
    }

    // Create threadpool work item for the client code
    PTP_WORK clientWork = CreateThreadpoolWork(ClientWorkCallback, NULL, NULL);
    if (clientWork == NULL) {
        printf("Failed to create threadpool work item\n");
        CloseThreadpoolIo(tpIo);
        CloseHandle(overlapped.hEvent);
        CloseHandle(pipe);
        CloseHandle(g_WriteCompleteEvent);
        return 1;
    }

    // Submit the client work item to the thread pool
    SubmitThreadpoolWork(clientWork);

    // Wait for the client work item to signal that the write operation is complete
    WaitForSingleObject(g_WriteCompleteEvent, INFINITE);

    // Start an asynchronous read operation
    StartRead(pipe, tpIo, &overlapped, buffer);
    printf("Pipe buffer: %s\n", buffer);

    // Wait for the read operation to complete
    WaitForSingleObject(overlapped.hEvent, INFINITE);

    // Wait for client work to complete
    WaitForThreadpoolWorkCallbacks(clientWork, FALSE);
    CloseThreadpoolWork(clientWork);

    // Cleanup
    CloseThreadpoolIo(tpIo);
    CloseHandle(overlapped.hEvent);
    CloseHandle(pipe);
    CloseHandle(g_WriteCompleteEvent);

    printf("wininet.dll should be loaded! Input any key to exit...\n");
    getchar();

    return 0;
}

void StartRead(HANDLE pipe, PTP_IO tpIo, OVERLAPPED* overlapped, char* buffer)
{
    DWORD bytesRead = 0;
    StartThreadpoolIo(tpIo);
    if (!ReadFile(pipe, buffer, 128, &bytesRead, overlapped) && GetLastError() != ERROR_IO_PENDING) {
        printf("ReadFile failed, error %lu\n", GetLastError());
        CancelThreadpoolIo(tpIo);
    }
}

void CALLBACK ClientWorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work)
{
    // Open the named pipe
    HANDLE pipe = CreateFile(
        TEXT("\\\\.\\pipe\\MyPipe"),
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        printf("Client failed to connect to pipe\n");
        return;
    }

    const char message[] = "Hello from the pipe!";
    DWORD bytesWritten;
    if (!WriteFile(pipe, message, sizeof(message), &bytesWritten, NULL)) {
        printf("Client WriteFile failed, error: %lu\n", GetLastError());
    }
    else {
        printf("Client wrote to pipe\n");
    }

    // Signal that the write operation is complete
    SetEvent(g_WriteCompleteEvent);

    CloseHandle(pipe);
}
