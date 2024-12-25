#include "Utils.h"

BOOL bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return FALSE;

    return TRUE;
}

DWORD_PTR findPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask)
{
    for (DWORD i = 0; i < dwLen; i++)
        if (bCompare((PBYTE)(dwAddress + i), bMask, szMask))
            return (DWORD_PTR)(dwAddress + i);

    return 0;
}

DWORD_PTR findInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask)
{
    PIMAGE_DOS_HEADER ImageBase = (PIMAGE_DOS_HEADER)GetModuleHandleA(moduleName);
    PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)ImageBase + ImageBase->e_lfanew);
    DWORD_PTR section_offset = (DWORD_PTR)ImageBase + ImageBase->e_lfanew + sizeof(IMAGE_NT_HEADERS);
    PIMAGE_SECTION_HEADER text_section = (PIMAGE_SECTION_HEADER)(section_offset);
    DWORD_PTR dwAddress = findPattern((DWORD_PTR)ImageBase + text_section->VirtualAddress, text_section->SizeOfRawData, bMask, szMask);
    return dwAddress;
}

PVOID findGadget(PBYTE hdrParserFuncB, PCHAR hdrParserFunctMask)
{
    HANDLE hProcess;
    BOOL result;
    HMODULE* moduleList;
    DWORD bytesNeeded;
    DWORD nModules = 0;
    LPSTR moduleName = NULL;
    DWORD_PTR ptr = 0;
    // PBYTE hdrParserFuncB = (PBYTE)"\x48\x89\x22\xc3";

    hProcess = GetCurrentProcess();

    moduleList = malloc(SIZE_MODULE_LIST * sizeof(HMODULE));
    result = EnumProcessModules(hProcess, moduleList, SIZE_MODULE_LIST * sizeof(HMODULE), &bytesNeeded);
    if (bytesNeeded > SIZE_MODULE_LIST * sizeof(HMODULE))
    {
        moduleList = realloc(moduleList, bytesNeeded);
        result = EnumProcessModules(hProcess, moduleList, bytesNeeded, &bytesNeeded);
    }

    if (!result)
        goto end;
    for (int iModule = 1; iModule < (bytesNeeded / sizeof(HMODULE)); iModule++)
    {
        moduleName = malloc(MAX_MODULE_NAME * sizeof(CHAR));
        if (GetModuleFileNameExA(hProcess, moduleList[iModule], moduleName, MAX_MODULE_NAME * sizeof(CHAR)) == 0)
            goto end;
        ptr = findInModule(moduleName, hdrParserFuncB, hdrParserFunctMask);
        if (ptr)
        {
            break;
        }
    }
end:
    if (moduleList)
        free(moduleList);

    if (moduleName)
        free(moduleName);
    if (hProcess)
        CloseHandle(hProcess);
    return (PVOID)ptr;
}

int PrintWaitStatus(NTSTATUS status, const char* message) {
	switch (status) {
	case STATUS_SUCCESS:
		printf("STATUS_SUCCESS - %s\n", message);
		break;
	case STATUS_ALERTED:
		printf("STATUS_ALERTED - %s\n", message);
		break;
	case STATUS_USER_APC:
		printf("STATUS_USER_APC - %s\n", message);
		break;
	default:
		printf("Unknown status: 0x%x\n", status);
		break;
	}
	return 0;
}

HANDLE CreateTimerNative(PWSTR wTimerName) {
	PFN_RTLINITUNICODESTRING RtlInitUnicodeString = (PFN_RTLINITUNICODESTRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");
	PFN_NTCREATETIMER NtCreateTimer = (PFN_NTCREATETIMER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateTimer");

	HANDLE hTimer = NULL;
	UNICODE_STRING timerName;
	OBJECT_ATTRIBUTES objectAttributes;
	RtlInitUnicodeString(&timerName, wTimerName);

	HANDLE hRootDirectory = NULL;
	BaseGetNamedObjectDirectoryFunc pBaseGetNamedObjectDirectoryFunc = (BaseGetNamedObjectDirectoryFunc)GetProcAddress(GetModuleHandleA("kernelbase.dll"), "BaseGetNamedObjectDirectory");
	NTSTATUS status = pBaseGetNamedObjectDirectoryFunc(&hRootDirectory);
	if (status != STATUS_SUCCESS) {
		printf("Failed to get root directory! Status: 0x%x\n", status);
		return;
	}

	InitializeObjectAttributes(&objectAttributes, &timerName, OBJ_OPENIF, hRootDirectory, NULL);

	//printf("Timer name: %ls\nRootDirectory: %p\n", objectAttributes.ObjectName->Buffer, objectAttributes.RootDirectory);
	status = NtCreateTimer(&hTimer, TIMER_ALL_ACCESS, &objectAttributes, NotificationTimer);
	if (status != STATUS_SUCCESS) {
		printf("Failed to create timer! Status: 0x%x\n", status);
		return;
	}
	return hTimer;
}

void SetTimerNative(HANDLE hTimer, LARGE_INTEGER TimerDueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext) {
	PFN_NTSETTIMEREX NtSetTimerEx = (PFN_NTSETTIMEREX)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimerEx");

	TIMER_SET_COALESCABLE_TIMER_INFO timerInfo;
	PCOUNTED_REASON_CONTEXT wakeContext = NULL;
	ZeroMemory(&timerInfo, sizeof(TIMER_SET_COALESCABLE_TIMER_INFO));
	timerInfo.DueTime = TimerDueTime;
	timerInfo.TimerApcRoutine = TimerApcRoutine;
	timerInfo.TimerContext = TimerContext;
	timerInfo.WakeContext = wakeContext;
	timerInfo.Period = 0;
	timerInfo.TolerableDelay = 0;
	timerInfo.PreviousState = NULL;

	NTSTATUS status = NtSetTimerEx(hTimer, TimerSetCoalescableTimer, &timerInfo, sizeof(TIMER_SET_COALESCABLE_TIMER_INFO));
	if (status != STATUS_SUCCESS) {
		printf("Failed to set timer! Status: 0x%x\n", status);
		return;
	}
}

VOID NTAPI MyTimerApcRoutine(
	_In_ PVOID TimerContext,
	_In_ ULONG TimerLowValue,
	_In_ LONG TimerHighValue
) {
	// Just print "Hello World", ignore the parameters
	printf("Hello World\n");
}

void PrintHelloWorld() {
	printf("Hello World\n");
}

NT_TIB * GetTib() {
	NT_TIB *tib = NULL;
	tib = (NT_TIB*)__readgsqword(0x30);
	return tib;
}