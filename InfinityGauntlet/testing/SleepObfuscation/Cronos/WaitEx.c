#include "Cronos.h"
#include "Utils.h"

int TestPentaWaitExAndDelay(int sleepTime) {
	PFN_NTDELAYEXECUTION NtDelayExecution = (PFN_NTDELAYEXECUTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hDummyThreadTimer;
	HANDLE hDummyThreadTimer2;
	HANDLE hDummyThreadTimer3;
	HANDLE hDummyThreadTimer4;
	HANDLE hDummyThreadTimer5;

	HANDLE hArray[5];

	LARGE_INTEGER dummyDueTime;
	LARGE_INTEGER dummyDueTime2;
	LARGE_INTEGER dummyDueTime3;
	LARGE_INTEGER dummyDueTime4;
	LARGE_INTEGER dummyDueTime5;

	CONTEXT ctxTest = { 0 };
	CONTEXT ctxTest2 = { 0 };
	CONTEXT ctxTest3 = { 0 };
	CONTEXT ctxTest4 = { 0 };
	CONTEXT ctxTest5 = { 0 };

	PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	//hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	hDummyThreadTimer = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer");
	//printf("Created timer one!\n");
	//hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	hDummyThreadTimer2 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer2");
	//printf("Created timer two!\n");
	//hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	hDummyThreadTimer3 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer3");
	//printf("Created timer three!\n");
	//hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	hDummyThreadTimer4 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer4");
	//printf("Created timer four!\n");
	//hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	hDummyThreadTimer5 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer5");
	//printf("Created timer five!\n");

	if (hDummyThreadTimer == NULL || hDummyThreadTimer2 == NULL || hDummyThreadTimer3 == NULL || hDummyThreadTimer4 == NULL || hDummyThreadTimer5 == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}
	hArray[0] = hDummyThreadTimer;
	hArray[1] = hDummyThreadTimer2;
	hArray[2] = hDummyThreadTimer3;
	hArray[3] = hDummyThreadTimer4;
	hArray[4] = hDummyThreadTimer5;

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE;

	InitializeTimerMs(&dummyDueTime, 0);

	//SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);
	SetWaitableTimer(hDummyThreadTimer, &dummyDueTime, 0, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest, FALSE);

	// Wait indefinitely in an alertable state
	WaitForSingleObjectEx(hDummyThreadTimer, INFINITE, TRUE);
	printf("ctxTest.Rsp: %p\n", ctxTest.Rsp);

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, sleepTime - 1);
	InitializeTimerMs(&dummyDueTime5, sleepTime);

	/*SetTimerNative(hDummyThreadTimer2, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxTest);
	SetTimerNative(hDummyThreadTimer3, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxTest2);
	SetTimerNative(hDummyThreadTimer4, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxTest3);
	SetTimerNative(hDummyThreadTimer5, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxTest4);
	SetTimerNative(hDummyThreadTimer6, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxTest5);*/
	if (!SetWaitableTimer(hDummyThreadTimer2, &dummyDueTime2, 0, RtlCaptureContext, &ctxTest2, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer3, &dummyDueTime3, 0, RtlCaptureContext, &ctxTest3, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer4, &dummyDueTime4, 0, RtlCaptureContext, &ctxTest4, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer5, &dummyDueTime5, 0, RtlCaptureContext, &ctxTest5, FALSE))
	{
		printf("[ - ] Failed to SetWaitableTimer: %d", GetLastError());
	}

	// Gadget: pop rcx; ret;
	// This gadget pops the top value of the stack into the rcx register and then returns
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

	// Gadget: pop r8; ret;
	// This gadget pops the top value of the stack into the r8 register and then returns.
	// 'pop r8' is represented by the opcodes 0x41 0x58, and 'ret' is represented by 0xC3.
	r8Gadget = findGadget((PBYTE)"\x41\x58\xC3", "xxx");

	if (rcxGadget == 0 || rdxGadget == 0 || r8Gadget == 0 || shadowFixerGadget == 0) {
		printf("[!] Error finding gadget\n");
		return 1;
	}	

	/*WaitForSingleObjectEx(hDummyThreadTimer2, INFINITE, TRUE);
	WaitForSingleObjectEx(hDummyThreadTimer3, INFINITE, TRUE);
	WaitForSingleObjectEx(hDummyThreadTimer4, INFINITE, TRUE);
	WaitForSingleObjectEx(hDummyThreadTimer5, INFINITE, TRUE);
	NtDelayExecution(TRUE, &liTimeout);
	NtDelayExecution(TRUE, &liTimeout);
	NtDelayExecution(TRUE, &liTimeout);
	NtDelayExecution(TRUE, &liTimeout);*/

	char debugMessage[256];
	sprintf_s(debugMessage, sizeof(debugMessage), "WaitForSingleObjectEx: %p\nNtDelayExecution: %p\nliTimeout: %p\nhDummyThreadTimer2: %p\nhDummyThreadTimer3: %p\nhDummyThreadTimer4: %p\nhDummyThreadTimer5: %p\n", (PVOID)WaitForSingleObjectEx, pNtDelayExecution, &liTimeout, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
	OutputDebugStringA(debugMessage);

	PentaWaitExAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, (PVOID)WaitForSingleObjectEx, pNtDelayExecution, &liTimeout, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);

	printf("ctxTest2.Rsp: %p\n", ctxTest2.Rsp);
	printf("ctxTest3.Rsp: %p\n", ctxTest3.Rsp);
	printf("ctxTest4.Rsp: %p\n", ctxTest4.Rsp);
	printf("ctxTest5.Rsp: %p\n", ctxTest5.Rsp);
}

// This was used to debug the CONTEXT structures with the NtContinue ROP
int TestPentaWaitExAndDelay2(int sleepTime) {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hDummyThreadTimer;
	HANDLE hDummyThreadTimer2;
	HANDLE hDummyThreadTimer3;
	HANDLE hDummyThreadTimer4;
	HANDLE hDummyThreadTimer5;

	HANDLE hArray[5];

	LARGE_INTEGER dummyDueTime;
	LARGE_INTEGER dummyDueTime2;
	LARGE_INTEGER dummyDueTime3;
	LARGE_INTEGER dummyDueTime4;
	LARGE_INTEGER dummyDueTime5;

	CONTEXT ctxDummyThread = { 0 };

	CONTEXT helloWorld = { 0 };
	CONTEXT helloWorld2 = { 0 };
	CONTEXT helloWorld3 = { 0 };
	CONTEXT helloWorld4 = { 0 };

	PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	//hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	hDummyThreadTimer = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer");
	//printf("Created timer one!\n");
	//hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	hDummyThreadTimer2 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer2");
	//printf("Created timer two!\n");
	//hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	hDummyThreadTimer3 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer3");
	//printf("Created timer three!\n");
	//hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	hDummyThreadTimer4 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer4");
	//printf("Created timer four!\n");
	//hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	hDummyThreadTimer5 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer5");
	//printf("Created timer five!\n");

	if (hDummyThreadTimer == NULL || hDummyThreadTimer2 == NULL || hDummyThreadTimer3 == NULL || hDummyThreadTimer4 == NULL || hDummyThreadTimer5 == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}
	hArray[0] = hDummyThreadTimer;
	hArray[1] = hDummyThreadTimer2;
	hArray[2] = hDummyThreadTimer3;
	hArray[3] = hDummyThreadTimer4;
	hArray[4] = hDummyThreadTimer5;

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	InitializeTimerMs(&dummyDueTime, 0);

	//SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);
	SetWaitableTimer(hDummyThreadTimer, &dummyDueTime, 0, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread, FALSE);

	// Wait indefinitely in an alertable state
	WaitForSingleObjectEx(hDummyThreadTimer, INFINITE, TRUE);
	//printf("ctxDummyThread.Rsp: %p\n", &ctxDummyThread.Rsp);

	// Creating the contexts.
	memcpy(&helloWorld, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&helloWorld2, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&helloWorld3, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&helloWorld4, &ctxDummyThread, sizeof(CONTEXT));

	/*
	* These were the results of TestPentaWaitExAndDelay CONTEXT captures from the assembly function after each interval:
	* ctxTest.Rsp: 000000A500CFDD10
	* ctxTest2.Rsp: 000000A500CFDB20 (496)
	* ctxTest3.Rsp: 000000A500CFDC00 (-224)
	* ctxTest4.Rsp: 000000A500CFDC70 (-112)
	* ctxTest5.Rsp: 000000A500CFDD70 (-256)
	*/
	helloWorld.Rsp -= (DWORD64)(8+496);
	helloWorld.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 224 from 496
	helloWorld2.Rsp -= (DWORD64)(8+272);
	helloWorld2.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 112 from 272
	helloWorld3.Rsp -= (DWORD64)(8+160);
	helloWorld3.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 256 from 160
	helloWorld4.Rsp -= (DWORD64)(8);
	helloWorld4.Rsp -= (DWORD64)(-96);
	helloWorld4.Rip = (DWORD_PTR)PrintHelloWorld;

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, sleepTime - 1);
	InitializeTimerMs(&dummyDueTime5, sleepTime);

	/*SetTimerNative(hDummyThreadTimer2, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld);
	SetTimerNative(hDummyThreadTimer3, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld2);
	SetTimerNative(hDummyThreadTimer4, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld3);
	SetTimerNative(hDummyThreadTimer5, dummyDueTime, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld4);*/
	if (!SetWaitableTimer(hDummyThreadTimer2, &dummyDueTime2, 0, NtContinue, &helloWorld, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer3, &dummyDueTime3, 0, NtContinue, &helloWorld2, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer4, &dummyDueTime4, 0, NtContinue, &helloWorld3, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer5, &dummyDueTime5, 0, NtContinue, &helloWorld4, FALSE))
	{
		printf("[ - ] Failed to SetWaitableTimer: %d", GetLastError());
	}

	// Gadget: pop rcx; ret;
	// This gadget pops the top value of the stack into the rcx register and then returns
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

	// Gadget: pop r8; ret;
	// This gadget pops the top value of the stack into the r8 register and then returns.
	// 'pop r8' is represented by the opcodes 0x41 0x58, and 'ret' is represented by 0xC3.
	r8Gadget = findGadget((PBYTE)"\x41\x58\xC3", "xxx");

	if (rcxGadget == 0 || rdxGadget == 0 || r8Gadget == 0 || shadowFixerGadget == 0) {
		printf("[!] Error finding gadget\n");
		return 1;
	}

	char debugMessage[256];
	sprintf_s(debugMessage, sizeof(debugMessage), "WaitForSingleObjectEx: %p\nNtDelayExecution: %p\nliTimeout: %p\nhDummyThreadTimer2: %p\nhDummyThreadTimer3: %p\nhDummyThreadTimer4: %p\nhDummyThreadTimer5: %p\n", (PVOID)WaitForSingleObjectEx, pNtDelayExecution, &liTimeout, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
	OutputDebugStringA(debugMessage);

	PentaWaitExAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, (PVOID)WaitForSingleObjectEx, pNtDelayExecution, &liTimeout, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
}

int TestQuadSleep() {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID shadowFixerGadget;

	HANDLE hDummyThreadTimer;
	HANDLE hDummyThreadTimer2;
	HANDLE hDummyThreadTimer3;
	HANDLE hDummyThreadTimer4;
	HANDLE hDummyThreadTimer5;
	
	HANDLE hArray[5];

	LARGE_INTEGER dummyDueTime;
	LARGE_INTEGER dummyDueTime2;
	LARGE_INTEGER dummyDueTime3;
	LARGE_INTEGER dummyDueTime4;
	LARGE_INTEGER dummyDueTime5;

	CONTEXT ctxDummyThread = { 0 };

	CONTEXT ctxTest = { 0 };
	CONTEXT ctxTest2 = { 0 };
	CONTEXT ctxTest3 = { 0 };
	CONTEXT ctxTest4 = { 0 };		

	//hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	hDummyThreadTimer = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer");
	//printf("Created timer one!\n");
	//hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	hDummyThreadTimer2 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer2");
	//printf("Created timer two!\n");
	//hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	hDummyThreadTimer3 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer3");
	//printf("Created timer three!\n");
	//hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	hDummyThreadTimer4 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer4");
	//printf("Created timer four!\n");
	//hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	hDummyThreadTimer5 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer5");
	//printf("Created timer five!\n");

	if (hDummyThreadTimer == NULL || hDummyThreadTimer2 == NULL || hDummyThreadTimer3 == NULL || hDummyThreadTimer4 == NULL || hDummyThreadTimer5 == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}
	hArray[0] = hDummyThreadTimer;
	hArray[1] = hDummyThreadTimer2;
	hArray[2] = hDummyThreadTimer3;
	hArray[3] = hDummyThreadTimer4;
	hArray[4] = hDummyThreadTimer5;

	InitializeTimerMs(&dummyDueTime, 0);

	SetWaitableTimer(hDummyThreadTimer, &dummyDueTime, 0, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread, FALSE);

	// Wait indefinitely in an alertable state
	SleepEx(INFINITE, TRUE);

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, 2);
	InitializeTimerMs(&dummyDueTime5, 3);
	
	if (!SetWaitableTimer(hDummyThreadTimer2, &dummyDueTime2, 0, RtlCaptureContext, &ctxTest, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer3, &dummyDueTime3, 0, RtlCaptureContext, &ctxTest2, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer4, &dummyDueTime4, 0, RtlCaptureContext, &ctxTest3, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer5, &dummyDueTime5, 0, RtlCaptureContext, &ctxTest4, FALSE))
	{
		printf("[ - ] Failed to SetWaitableTimer: %d", GetLastError());
	}

	// Gadget: pop rcx; ret;
	// This gadget pops the top value of the stack into the rcx register and then returns
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
		return 1;
	}

	QuadSleep(rcxGadget, rdxGadget, shadowFixerGadget, (PVOID)SleepEx);

	printf("ctxDummyThread.Rsp: %p\n", ctxDummyThread.Rsp);
	printf("ctxTest.Rsp: %p\n", ctxTest.Rsp);
	printf("ctxTest2.Rsp: %p\n", ctxTest2.Rsp);
	printf("ctxTest3.Rsp: %p\n", ctxTest3.Rsp);
	printf("ctxTest4.Rsp: %p\n", ctxTest4.Rsp);
}
