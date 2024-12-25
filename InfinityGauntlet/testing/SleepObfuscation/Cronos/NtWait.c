#include "Cronos.h"
#include "Utils.h"

// This was used to debug the assembly code of PentaNtWait
int TestPentaNtWaitAndDelay(int sleepTime) {
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

	PFN_NTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PFN_NTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PFN_NTDELAYEXECUTION NtDelayExecution = (PFN_NTDELAYEXECUTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	hDummyThreadTimer = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer");
	printf("Created timer one!\n");
	hDummyThreadTimer2 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer2");
	printf("Created timer two!\n");
	hDummyThreadTimer3 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer3");
	printf("Created timer three!\n");
	hDummyThreadTimer4 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer4");
	printf("Created timer four!\n");
	hDummyThreadTimer5 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer5");
	printf("Created timer five!\n");

	/*hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	printf("Created timer one!\n");
	hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	printf("Created timer two!\n");
	hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	printf("Created timer three!\n");
	hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	printf("Created timer four!\n");
	hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	printf("Created timer five!\n");*/

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

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	SetWaitableTimer(hDummyThreadTimer, &dummyDueTime, 0, RtlCaptureContext, &ctxTest, FALSE);
	//SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest);

	NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	printf("ctxTest.Rsp: %p\n", ctxTest.Rsp);

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, sleepTime - 1);
	InitializeTimerMs(&dummyDueTime5, sleepTime);

	if (!SetWaitableTimer(hDummyThreadTimer2, &dummyDueTime2, 0, RtlCaptureContext, &ctxTest2, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer3, &dummyDueTime3, 0, RtlCaptureContext, &ctxTest3, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer4, &dummyDueTime4, 0, RtlCaptureContext, &ctxTest4, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer5, &dummyDueTime5, 0, RtlCaptureContext, &ctxTest5, FALSE))
	{
		printf("[ - ] Failed to SetWaitableTimer: %d", GetLastError());
	}
	/*SetTimerNative(hDummyThreadTimer2, dummyDueTime2, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest2);
	SetTimerNative(hDummyThreadTimer3, dummyDueTime3, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest3);
	SetTimerNative(hDummyThreadTimer4, dummyDueTime4, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest4);
	SetTimerNative(hDummyThreadTimer5, dummyDueTime5, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest5);*/

	/*NTSTATUS status = NtWaitForSingleObject(hArray[1], TRUE, &liTimeout);
	PrintWaitStatus(status, "1");
	status = NtWaitForSingleObject(hArray[2], TRUE, &liTimeout);
	PrintWaitStatus(status, "2");
	status = NtWaitForSingleObject(hArray[3], TRUE, &liTimeout);
	PrintWaitStatus(status, "3");
	status = NtWaitForSingleObject(hArray[4], TRUE, &liTimeout);
	PrintWaitStatus(status, "4");
	NtDelayExecution(TRUE, &liTimeout);
	printf("ctxTest.Rsp: %p\n", &ctxTest.Rsp);
	printf("ctxTest2.Rsp: %p\n", &ctxTest2.Rsp);
	printf("ctxTest3.Rsp: %p\n", &ctxTest3.Rsp);
	printf("ctxTest4.Rsp: %p\n", &ctxTest4.Rsp);
	printf("ctxTest5.Rsp: %p\n", &ctxTest5.Rsp);
	getchar();*/

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

	PVOID pNtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	char debugMessage[256];
	sprintf_s(debugMessage, sizeof(debugMessage), "liTimeout: %p\nNtWaitForSingleObject: %p\nNtDelayExecution: %p\nhDummyThreadTimer2: %p\nhDummyThreadTimer3: %p\nhDummyThreadTimer4: %p\nhDummyThreadTimer5: %p\n", &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
	OutputDebugStringA(debugMessage);

	PentaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
	
	printf("ctxTest2.Rsp: %p\n", ctxTest2.Rsp);
	printf("ctxTest3.Rsp: %p\n", ctxTest3.Rsp);
	printf("ctxTest4.Rsp: %p\n", ctxTest4.Rsp);
	printf("ctxTest5.Rsp: %p\n", ctxTest5.Rsp);
}

// This was used to debug the assembly code of SeptaNtWait
int TestSeptaNtWaitAndDelay(int sleepTime) {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hDummyThreadTimer;
	HANDLE hDummyThreadTimer2;
	HANDLE hDummyThreadTimer3;
	HANDLE hDummyThreadTimer4;
	HANDLE hDummyThreadTimer5;
	HANDLE hDummyThreadTimer6;
	HANDLE hDummyThreadTimer7;
	HANDLE hDummyThreadTimer8;
	HANDLE hArray[8];
	LARGE_INTEGER dummyDueTime;
	LARGE_INTEGER dummyDueTime2;
	LARGE_INTEGER dummyDueTime3;
	LARGE_INTEGER dummyDueTime4;
	LARGE_INTEGER dummyDueTime5;
	LARGE_INTEGER dummyDueTime6;
	LARGE_INTEGER dummyDueTime7;
	LARGE_INTEGER dummyDueTime8;

	CONTEXT ctxTest = { 0 };
	CONTEXT ctxTest2 = { 0 };
	CONTEXT ctxTest3 = { 0 };
	CONTEXT ctxTest4 = { 0 };
	CONTEXT ctxTest5 = { 0 };
	CONTEXT ctxTest6 = { 0 };
	CONTEXT ctxTest7 = { 0 };
	CONTEXT ctxTest8 = { 0 };

	PFN_NTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PFN_NTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PFN_NTDELAYEXECUTION NtDelayExecution = (PFN_NTDELAYEXECUTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	printf("Created timer one!\n");
	hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	printf("Created timer two!\n");
	hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	printf("Created timer three!\n");
	hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	printf("Created timer four!\n");
	hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	printf("Created timer five!\n");
	hDummyThreadTimer6 = CreateTimerNative(L"DummyTimer6");
	printf("Created timer six!\n");
	hDummyThreadTimer7 = CreateTimerNative(L"DummyTimer7");
	printf("Created timer seven!\n");
	hDummyThreadTimer8 = CreateTimerNative(L"DummyTimer8");
	printf("Created timer eight!\n");

	if (hDummyThreadTimer == NULL || hDummyThreadTimer2 == NULL || hDummyThreadTimer3 == NULL || hDummyThreadTimer4 == NULL || hDummyThreadTimer5 == NULL || hDummyThreadTimer6 == NULL || hDummyThreadTimer7 == NULL || hDummyThreadTimer8 == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}
	hArray[0] = hDummyThreadTimer;
	hArray[1] = hDummyThreadTimer2;
	hArray[2] = hDummyThreadTimer3;
	hArray[3] = hDummyThreadTimer4;
	hArray[4] = hDummyThreadTimer5;
	hArray[5] = hDummyThreadTimer6;
	hArray[6] = hDummyThreadTimer7;
	hArray[7] = hDummyThreadTimer8;

	InitializeTimerMs(&dummyDueTime, 0);

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest);

	NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	printf("ctxTest.Rsp: %p\n", ctxTest.Rsp);

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, 2);
	InitializeTimerMs(&dummyDueTime5, 3);
	InitializeTimerMs(&dummyDueTime6, 4);
	InitializeTimerMs(&dummyDueTime7, 5);
	InitializeTimerMs(&dummyDueTime8, 6);

	SetTimerNative(hDummyThreadTimer2, dummyDueTime2, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest2);
	SetTimerNative(hDummyThreadTimer3, dummyDueTime3, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest3);
	SetTimerNative(hDummyThreadTimer4, dummyDueTime4, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest4);
	SetTimerNative(hDummyThreadTimer5, dummyDueTime5, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest5);
	SetTimerNative(hDummyThreadTimer6, dummyDueTime6, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest6);
	SetTimerNative(hDummyThreadTimer7, dummyDueTime7, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest7);
	SetTimerNative(hDummyThreadTimer8, dummyDueTime8, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxTest8);

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

	PVOID pNtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	char debugMessage[500];
	sprintf_s(debugMessage, sizeof(debugMessage), "liTimeout: %p\nNtWaitForSingleObject: %p\nNtDelayExecution: %p\nhDummyThreadTimer2: %p\nhDummyThreadTimer3: %p\nhDummyThreadTimer4: %p\nhDummyThreadTimer5: %p\nhDummyThreadTimer6: %p\nhDummyThreadTimer7: %p\nhDummyThreadTimer8: %p\n", &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5, hDummyThreadTimer6, hDummyThreadTimer7, hDummyThreadTimer8);
	OutputDebugStringA(debugMessage);

	SeptaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5, hDummyThreadTimer6, hDummyThreadTimer7, hDummyThreadTimer8);

	printf("ctxTest2.Rsp: %p\n", ctxTest2.Rsp);
	printf("ctxTest3.Rsp: %p\n", ctxTest3.Rsp);
	printf("ctxTest4.Rsp: %p\n", ctxTest4.Rsp);
	printf("ctxTest5.Rsp: %p\n", ctxTest5.Rsp);
	printf("ctxTest6.Rsp: %p\n", ctxTest6.Rsp);
	printf("ctxTest7.Rsp: %p\n", ctxTest7.Rsp);
	printf("ctxTest8.Rsp: %p\n", ctxTest8.Rsp);
}

// This was used to debug the CONTEXT structures with the NtContinue ROP
int TestPentaNtWaitAndDelay2(int sleepTime) {
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
	PVOID pNtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	PFN_NTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PFN_NTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");

	hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	//hDummyThreadTimer = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer");
	printf("Created timer one!\n");
	hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	//hDummyThreadTimer2 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer2");
	printf("Created timer two!\n");
	hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	//hDummyThreadTimer3 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer3");
	printf("Created timer three!\n");
	hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	//hDummyThreadTimer4 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer4");
	printf("Created timer four!\n");
	hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	//hDummyThreadTimer5 = CreateWaitableTimerW(NULL, TRUE, L"DummyTimer5");
	printf("Created timer five!\n");

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

	SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	// Wait indefinitely in an alertable state
	NTSTATUS status = NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	PrintWaitStatus(status, "ctxDummyThread");
	printf("ctxDummyThread.Rsp: %p\n", &ctxDummyThread.Rsp);

	// Creating the contexts.
	memcpy(&helloWorld, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&helloWorld2, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&helloWorld3, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&helloWorld4, &ctxDummyThread, sizeof(CONTEXT));

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, sleepTime - 1);
	InitializeTimerMs(&dummyDueTime5, sleepTime);

	/*
	* These were the results of TestPentaNtWaitAndDelay CONTEXT captures from the assembly function after each interval:
	* ctxTest.Rsp: 0000008BB572DC70
	* ctxTest2.Rsp: 0000008BB572DA70 (512)
	* ctxTest3.Rsp: 0000008BB572DB50 (-224)
	* ctxTest4.Rsp: 0000008BB572DBC0 (-112)
	* ctxTest5.Rsp: 0000008BB572DC20 (-96)
	*/
	helloWorld.Rsp -= (DWORD64)(8+512);
	helloWorld.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 224 from 512
	helloWorld2.Rsp -= (DWORD64)(8+288);
	helloWorld2.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 112 from 288
	helloWorld3.Rsp -= (DWORD64)(8+176);
	helloWorld3.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 96 from 176
	helloWorld4.Rsp -= (DWORD64)(8+80);
	helloWorld4.Rip = (DWORD_PTR)PrintHelloWorld;

	SetTimerNative(hDummyThreadTimer2, dummyDueTime2, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld);
	SetTimerNative(hDummyThreadTimer3, dummyDueTime3, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld2);
	SetTimerNative(hDummyThreadTimer4, dummyDueTime4, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld3);
	SetTimerNative(hDummyThreadTimer5, dummyDueTime5, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld4);
	/*if (!SetWaitableTimer(hDummyThreadTimer2, &dummyDueTime2, 0, NtContinue, &helloWorld, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer3, &dummyDueTime3, 0, NtContinue, &helloWorld2, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer4, &dummyDueTime4, 0, NtContinue, &helloWorld3, FALSE) ||
		!SetWaitableTimer(hDummyThreadTimer5, &dummyDueTime5, 0, NtContinue, &helloWorld4, FALSE))
	{
		printf("[ - ] Failed to SetWaitableTimer: %d", GetLastError());
	}*/

	/*NTSTATUS status = NtWaitForSingleObject(hArray[0], TRUE, &liTimeout);
	PrintWaitStatus(status, "1");
	status = NtWaitForSingleObject(hArray[1], TRUE, &liTimeout);
	PrintWaitStatus(status, "2");
	status = NtWaitForSingleObject(hArray[2], TRUE, &liTimeout);
	PrintWaitStatus(status, "3");
	status = NtWaitForSingleObject(hArray[3], TRUE, &liTimeout);
	PrintWaitStatus(status, "4");
	getchar();*/

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
	sprintf_s(debugMessage, sizeof(debugMessage), "liTimeout: %p\nNtWaitForSingleObject: %p\nNtDelayExecution: %p\nhDummyThreadTimer2: %p\nhDummyThreadTimer3: %p\nhDummyThreadTimer4: %p\nhDummyThreadTimer5: %p\n", &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
	OutputDebugStringA(debugMessage);

	PentaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5);
}

// This was used to debug the CONTEXT structures with the NtContinue ROP
int TestSeptaNtWaitAndDelay2(int sleepTime) {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hDummyThreadTimer;
	HANDLE hDummyThreadTimer2;
	HANDLE hDummyThreadTimer3;
	HANDLE hDummyThreadTimer4;
	HANDLE hDummyThreadTimer5;
	HANDLE hDummyThreadTimer6;
	HANDLE hDummyThreadTimer7;
	HANDLE hDummyThreadTimer8;
	HANDLE hArray[8];
	LARGE_INTEGER dummyDueTime;
	LARGE_INTEGER dummyDueTime2;
	LARGE_INTEGER dummyDueTime3;
	LARGE_INTEGER dummyDueTime4;
	LARGE_INTEGER dummyDueTime5;
	LARGE_INTEGER dummyDueTime6;
	LARGE_INTEGER dummyDueTime7;
	LARGE_INTEGER dummyDueTime8;

	CONTEXT helloWorld = { 0 };
	CONTEXT helloWorld2 = { 0 };
	CONTEXT helloWorld3 = { 0 };
	CONTEXT helloWorld4 = { 0 };
	CONTEXT helloWorld5 = { 0 };
	CONTEXT helloWorld6 = { 0 };
	CONTEXT helloWorld7 = { 0 };
	CONTEXT helloWorld8 = { 0 };

	PFN_NTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PFN_NTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PFN_NTDELAYEXECUTION NtDelayExecution = (PFN_NTDELAYEXECUTION)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
	PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");

	hDummyThreadTimer = CreateTimerNative(L"DummyTimer");
	printf("Created timer one!\n");
	hDummyThreadTimer2 = CreateTimerNative(L"DummyTimer2");
	printf("Created timer two!\n");
	hDummyThreadTimer3 = CreateTimerNative(L"DummyTimer3");
	printf("Created timer three!\n");
	hDummyThreadTimer4 = CreateTimerNative(L"DummyTimer4");
	printf("Created timer four!\n");
	hDummyThreadTimer5 = CreateTimerNative(L"DummyTimer5");
	printf("Created timer five!\n");
	hDummyThreadTimer6 = CreateTimerNative(L"DummyTimer6");
	printf("Created timer six!\n");
	hDummyThreadTimer7 = CreateTimerNative(L"DummyTimer7");
	printf("Created timer seven!\n");
	hDummyThreadTimer8 = CreateTimerNative(L"DummyTimer8");
	printf("Created timer eight!\n");

	if (hDummyThreadTimer == NULL || hDummyThreadTimer2 == NULL || hDummyThreadTimer3 == NULL || hDummyThreadTimer4 == NULL || hDummyThreadTimer5 == NULL || hDummyThreadTimer6 == NULL || hDummyThreadTimer7 == NULL || hDummyThreadTimer8 == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}
	hArray[0] = hDummyThreadTimer;
	hArray[1] = hDummyThreadTimer2;
	hArray[2] = hDummyThreadTimer3;
	hArray[3] = hDummyThreadTimer4;
	hArray[4] = hDummyThreadTimer5;
	hArray[5] = hDummyThreadTimer6;
	hArray[6] = hDummyThreadTimer7;
	hArray[7] = hDummyThreadTimer8;

	InitializeTimerMs(&dummyDueTime, 0);

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &helloWorld);

	NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	printf("helloWorld.Rsp: %p\n", helloWorld.Rsp);

	// Creating the contexts
	memcpy(&helloWorld2, &helloWorld, sizeof(CONTEXT));
	memcpy(&helloWorld3, &helloWorld, sizeof(CONTEXT));
	memcpy(&helloWorld4, &helloWorld, sizeof(CONTEXT));
	memcpy(&helloWorld5, &helloWorld, sizeof(CONTEXT));
	memcpy(&helloWorld6, &helloWorld, sizeof(CONTEXT));
	memcpy(&helloWorld7, &helloWorld, sizeof(CONTEXT));
	memcpy(&helloWorld8, &helloWorld, sizeof(CONTEXT));

	InitializeTimerMs(&dummyDueTime2, 0);
	InitializeTimerMs(&dummyDueTime3, 1);
	InitializeTimerMs(&dummyDueTime4, 2);
	InitializeTimerMs(&dummyDueTime5, 3);
	InitializeTimerMs(&dummyDueTime6, 4);
	InitializeTimerMs(&dummyDueTime7, 5);
	InitializeTimerMs(&dummyDueTime8, 6);

	/*
	* These were the results of TestSeptaNtWaitAndDelay CONTEXT captures from the assembly function after each interval:
	* ctxTest.Rsp: 000000BABEB5CCB0
	* ctxTest2.Rsp: 000000BABEB5C960 (848)
	* ctxTest3.Rsp: 000000BABEB5CA40 (-224)
	* ctxTest4.Rsp: 000000BABEB5CAB0 (-112)
	* ctxTest5.Rsp: 000000BABEB5CB20 (-112)
	* ctxTest6.Rsp: 000000BABEB5CB90 (-112)
	* ctxTest7.Rsp: 000000BABEB5CC00 (-112)
	* ctxTest8.Rsp: 000000BABEB5CC60 (-96)
	*/
	helloWorld2.Rsp -= (DWORD64)(8+848);
	helloWorld2.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 224 from 848
	helloWorld3.Rsp -= (DWORD64)(8+624);
	helloWorld3.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 112 from 624
	helloWorld4.Rsp -= (DWORD64)(8+512);
	helloWorld4.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 112 from 512
	helloWorld5.Rsp -= (DWORD64)(8+400);
	helloWorld5.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 112 from 400
	helloWorld6.Rsp -= (DWORD64)(8+288);
	helloWorld6.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 112 from 288
	helloWorld7.Rsp -= (DWORD64)(8+176);
	helloWorld7.Rip = (DWORD_PTR)PrintHelloWorld;

	// Subtract 96 from 176
	helloWorld8.Rsp -= (DWORD64)(8+80);
	helloWorld8.Rip = (DWORD_PTR)PrintHelloWorld;

	SetTimerNative(hDummyThreadTimer2, dummyDueTime2, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld2);
	SetTimerNative(hDummyThreadTimer3, dummyDueTime3, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld3);
	SetTimerNative(hDummyThreadTimer4, dummyDueTime4, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld4);
	SetTimerNative(hDummyThreadTimer5, dummyDueTime5, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld5);
	SetTimerNative(hDummyThreadTimer6, dummyDueTime6, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld6);
	SetTimerNative(hDummyThreadTimer7, dummyDueTime7, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld7);
	SetTimerNative(hDummyThreadTimer8, dummyDueTime8, (PTIMER_APC_ROUTINE)NtContinue, &helloWorld8);

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

	PVOID pNtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");

	char debugMessage[500];
	sprintf_s(debugMessage, sizeof(debugMessage), "liTimeout: %p\nNtWaitForSingleObject: %p\nNtDelayExecution: %p\nhDummyThreadTimer2: %p\nhDummyThreadTimer3: %p\nhDummyThreadTimer4: %p\nhDummyThreadTimer5: %p\nhDummyThreadTimer6: %p\nhDummyThreadTimer7: %p\nhDummyThreadTimer8: %p\n", &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5, hDummyThreadTimer6, hDummyThreadTimer7, hDummyThreadTimer8);
	OutputDebugStringA(debugMessage);

	SeptaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hDummyThreadTimer2, hDummyThreadTimer3, hDummyThreadTimer4, hDummyThreadTimer5, hDummyThreadTimer6, hDummyThreadTimer7, hDummyThreadTimer8);
}

// This function implements the self encryption after the correct offsets were obtained
int TestPentaNtWaitAndDelay3(int sleepTime) {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

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

	CONTEXT ctxDummyThread = { 0 };
	CONTEXT ctxProtectionRW = { 0 };
	CONTEXT ctxProtectionRWX = { 0 };
	CONTEXT ctxEncryption = { 0 };
	CONTEXT ctxDecryption = { 0 };

	PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
	PVOID pNtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
	PVOID pNtProtectVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");

	PFN_NTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PFN_NTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");

	PVOID ImageBase = NULL;
	DWORD ImageSize = 0;
	DWORD oldProtect = 0;
	CRYPT_BUFFER Image = { 0 };
	DATA_KEY Key = { 0 };
	CHAR keyBuffer[16] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 };

	// Load systemfunction032.
	HMODULE hAdvapi32 = LoadLibraryA("Advapi32.dll");

	if (hAdvapi32 == 0)
		return 1;

	PVOID SystemFunction032 = (tSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032");

	// Getting the image base.
	ImageBase = GetModuleHandleA(NULL);
	ImageSize = ((PIMAGE_NT_HEADERS)((DWORD_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	// Initializing the image and key for SystemFunction032.
	Key.Buffer = keyBuffer;
	Key.Length = Key.MaximumLength = 16;

	Image.Buffer = ImageBase;
	Image.Length = Image.MaximumLength = ImageSize;

	hDummyThreadTimer = CreateTimerNative(L"Timer1");
	printf("Created timer one!\n");
	hProtectionRWTimer = CreateTimerNative(L"Timer2");
	printf("Created timer two!\n");
	hEncryptionTimer = CreateTimerNative(L"Timer3");
	printf("Created timer three!\n");
	hDecryptionTimer = CreateTimerNative(L"Timer4");
	printf("Created timer four!\n");
	hProtectionRWXTimer = CreateTimerNative(L"Timer5");
	printf("Created timer five!\n");

	if (hDummyThreadTimer == NULL || hProtectionRWTimer == NULL || hEncryptionTimer == NULL || hDecryptionTimer == NULL || hProtectionRWXTimer == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}

	InitializeTimerMs(&dummyDueTime, 0);

	SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	// Wait indefinitely in an alertable state
	NTSTATUS status = NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	PrintWaitStatus(status, "ctxDummyThread");

	// Creating the contexts.
	memcpy(&ctxProtectionRW, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxEncryption, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxDecryption, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxProtectionRWX, &ctxDummyThread, sizeof(CONTEXT));

	InitializeTimerMs(&protectionRWDueTime, 0);
	InitializeTimerMs(&encryptionDueTime, 1);
	InitializeTimerMs(&decryptionDueTime, sleepTime - 1);
	InitializeTimerMs(&protectionRWXDueTime, sleepTime);

	/*
	* These were the results of TestPentaNtWaitAndDelay CONTEXT captures from the assembly function after each interval:
	* ctxTest.Rsp: 0000008BB572DC70
	* ctxTest2.Rsp: 0000008BB572DA70 (512)
	* ctxTest3.Rsp: 0000008BB572DB50 (-224)
	* ctxTest4.Rsp: 0000008BB572DBC0 (-112)
	* ctxTest5.Rsp: 0000008BB572DC20 (-96)
	*/
	ctxProtectionRW.Rsp -= (DWORD64)(8 + 512);
	ctxProtectionRW.Rip = (DWORD_PTR)VirtualProtect;
	ctxProtectionRW.Rcx = (DWORD_PTR)ImageBase;
	ctxProtectionRW.Rdx = ImageSize;
	ctxProtectionRW.R8 = PAGE_READWRITE;
	ctxProtectionRW.R9 = (DWORD_PTR)&oldProtect;

	// Subtract 224 from 512
	ctxEncryption.Rsp -= (DWORD64)(8 + 288);
	ctxEncryption.Rip = (DWORD_PTR)SystemFunction032;
	ctxEncryption.Rcx = (DWORD_PTR)&Image;
	ctxEncryption.Rdx = (DWORD_PTR)&Key;

	// Subtract 112 from 288
	ctxDecryption.Rsp -= (DWORD64)(8 + 176);
	ctxDecryption.Rip = (DWORD_PTR)SystemFunction032;
	ctxDecryption.Rcx = (DWORD_PTR)&Image;
	ctxDecryption.Rdx = (DWORD_PTR)&Key;
	
	// Subtract 96 from 176
	ctxProtectionRWX.Rsp -= (DWORD64)(8 + 80);
	ctxProtectionRWX.Rip = (DWORD_PTR)VirtualProtect;
	ctxProtectionRWX.Rcx = (DWORD_PTR)ImageBase;
	ctxProtectionRWX.Rdx = ImageSize;
	ctxProtectionRWX.R8 = PAGE_EXECUTE_READWRITE;
	ctxProtectionRWX.R9 = (DWORD_PTR)&oldProtect;

	SetTimerNative(hProtectionRWTimer, protectionRWDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxProtectionRW);
	SetTimerNative(hEncryptionTimer, encryptionDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxEncryption);
	SetTimerNative(hDecryptionTimer, decryptionDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxDecryption);
	SetTimerNative(hProtectionRWXTimer, protectionRWXDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxProtectionRWX);

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

	//PentaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer);
	PentaNtWaitAndDelayZeroTrace(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hProtectionRWTimer, hEncryptionTimer, hDecryptionTimer, hProtectionRWXTimer);
}

// This function implements the self encryption with stack spoofing after the correct offsets were obtained
int TestSeptaNtWaitAndDelay3(int sleepTime) {
	PVOID rcxGadget;
	PVOID rdxGadget;
	PVOID r8Gadget;
	PVOID shadowFixerGadget;

	HANDLE hProtectionRWTimer;
	HANDLE hProtectionRWXTimer;
	HANDLE hEncryptionTimer;
	HANDLE hRtlCopyMappedContextTimer;
	HANDLE hRtlCopyMappedContextTimer2;
	HANDLE hRtlCopyMappedContextTimer3;
	HANDLE hDecryptionTimer;
	HANDLE hDummyThreadTimer;

	LARGE_INTEGER protectionRWDueTime;
	LARGE_INTEGER protectionRWXDueTime;
	LARGE_INTEGER encryptionDueTime;
	LARGE_INTEGER rtlCopyMappedDueTime;
	LARGE_INTEGER rtlCopyMappedDueTime2;
	LARGE_INTEGER rtlCopyMappedDueTime3;
	LARGE_INTEGER decryptionDueTime;
	LARGE_INTEGER dummyDueTime;

	CONTEXT ctxDummyThread = { 0 };
	CONTEXT ctxProtectionRW = { 0 };
	CONTEXT ctxProtectionRWX = { 0 };
	CONTEXT ctxRtlCopyMappedMemory = { 0 };
	CONTEXT ctxRtlCopyMappedMemory2 = { 0 };
	CONTEXT ctxRtlCopyMappedMemory3 = { 0 };
	CONTEXT ctxEncryption = { 0 };
	CONTEXT ctxDecryption = { 0 };	

	PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
	PVOID pNtWaitForSingleObject = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");
	PVOID pNtDelayExecution = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDelayExecution");
	PVOID pNtProtectVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
	PVOID pRtlCopyMappedMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlCopyMappedMemory");

	PFN_NTWAITFORSINGLEOBJECT NtWaitForSingleObject = (PFN_NTWAITFORSINGLEOBJECT)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWaitForSingleObject");

	PVOID ImageBase = NULL;
	DWORD ImageSize = 0;
	DWORD oldProtect = 0;
	CRYPT_BUFFER Image = { 0 };
	DATA_KEY Key = { 0 };
	CHAR keyBuffer[16] = { 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18 };

	// Load systemfunction032.
	HMODULE hAdvapi32 = LoadLibraryA("Advapi32.dll");

	if (hAdvapi32 == 0)
		return 1;

	PVOID SystemFunction032 = (tSystemFunction032)GetProcAddress(hAdvapi32, "SystemFunction032");

	// Getting the image base.
	ImageBase = GetModuleHandleA(NULL);
	ImageSize = ((PIMAGE_NT_HEADERS)((DWORD_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

	// Initializing the image and key for SystemFunction032.
	Key.Buffer = keyBuffer;
	Key.Length = Key.MaximumLength = 16;

	Image.Buffer = ImageBase;
	Image.Length = Image.MaximumLength = ImageSize;

	hDummyThreadTimer = CreateTimerNative(L"Timer1");
	printf("Created timer one!\n");
	hProtectionRWTimer = CreateTimerNative(L"Timer2");
	printf("Created timer two!\n");
	hEncryptionTimer = CreateTimerNative(L"Timer3");
	printf("Created timer three!\n");
	hRtlCopyMappedContextTimer = CreateTimerNative(L"Timer4");
	printf("Created timer four!\n");
	hRtlCopyMappedContextTimer2 = CreateTimerNative(L"Timer5");
	printf("Created timer five!\n");
	hRtlCopyMappedContextTimer3 = CreateTimerNative(L"Timer6");
	printf("Created timer six!\n");
	hDecryptionTimer = CreateTimerNative(L"Timer7");
	printf("Created timer seven!\n");
	hProtectionRWXTimer = CreateTimerNative(L"Timer8");
	printf("Created timer eight!\n");

	if (hDummyThreadTimer == NULL || hProtectionRWTimer == NULL || hEncryptionTimer == NULL || hRtlCopyMappedContextTimer == NULL || hRtlCopyMappedContextTimer2 == NULL || hRtlCopyMappedContextTimer3 == NULL || hDecryptionTimer == NULL || hProtectionRWXTimer == NULL) {
		printf("[ - ] Failed to create waitable timers: %d\n", GetLastError());
		return 1;
	}

	InitializeTimerMs(&dummyDueTime, 0);

	SetTimerNative(hDummyThreadTimer, dummyDueTime, (PTIMER_APC_ROUTINE)RtlCaptureContext, &ctxDummyThread);

	LARGE_INTEGER liTimeout;
	liTimeout.QuadPart = -10000LL * INFINITE; // A negative value indicates a relative time	

	// Wait indefinitely in an alertable state
	NTSTATUS status = NtWaitForSingleObject(hDummyThreadTimer, TRUE, &liTimeout);
	PrintWaitStatus(status, "ctxDummyThread");

	// Get the current NT_TIB
	NT_TIB* tib = GetTib();

	// Allocate memory for the copy
	NT_TIB* bkpTib = (NT_TIB*)malloc(sizeof(NT_TIB));
	NT_TIB* bkpTib2 = (NT_TIB*)malloc(sizeof(NT_TIB));
	if (bkpTib == NULL || bkpTib2 == NULL) {
		printf("[!] Error allocating memory for the NT_TIB structure\n");
		return 1;
	}
	
	// Copy the NT_TIB structure
	memcpy(bkpTib, tib, sizeof(NT_TIB));

	/* Used to test stack spoofing - specific compiler flags are needed for this to work:
	* Disable GS (/GS-)
	* Disable Code Optimisation (/Od)
	* Disable Whole Program Optimisation (Remove /GL)
	* Disable size and speed preference (Remove /Os, /Ot)
	* Enable intrinsic if not enabled (/Oi)
	getchar();
	Sleep(10000);
	memcpy(tib, bkpTib, sizeof(NT_TIB));
	getchar();*/

	// Creating the contexts.
	memcpy(&ctxProtectionRW, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxEncryption, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxRtlCopyMappedMemory, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxRtlCopyMappedMemory2, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxRtlCopyMappedMemory3, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxDecryption, &ctxDummyThread, sizeof(CONTEXT));
	memcpy(&ctxProtectionRWX, &ctxDummyThread, sizeof(CONTEXT));

	InitializeTimerMs(&protectionRWDueTime, 0);
	InitializeTimerMs(&encryptionDueTime, 1);
	InitializeTimerMs(&rtlCopyMappedDueTime, 1.25);
	InitializeTimerMs(&rtlCopyMappedDueTime2, 1.5);
	InitializeTimerMs(&rtlCopyMappedDueTime3, sleepTime - 1.5);
	InitializeTimerMs(&decryptionDueTime, sleepTime - 1);
	InitializeTimerMs(&protectionRWXDueTime, sleepTime);

	/*
	* These were the results of TestSeptaNtWaitAndDelay CONTEXT captures from the assembly function after each interval:
	* ctxTest.Rsp: 000000BABEB5CCB0
	* ctxTest2.Rsp: 000000BABEB5C960 (848)
	* ctxTest3.Rsp: 000000BABEB5CA40 (-224)
	* ctxTest4.Rsp: 000000BABEB5CAB0 (-112)
	* ctxTest5.Rsp: 000000BABEB5CB20 (-112)
	* ctxTest6.Rsp: 000000BABEB5CB90 (-112)
	* ctxTest7.Rsp: 000000BABEB5CC00 (-112)
	* ctxTest8.Rsp: 000000BABEB5CC60 (-96)
	*/
	ctxProtectionRW.Rsp -= (DWORD64)(8 + 848);
	ctxProtectionRW.Rip = (DWORD_PTR)VirtualProtect;
	ctxProtectionRW.Rcx = (DWORD_PTR)ImageBase;
	ctxProtectionRW.Rdx = ImageSize;
	ctxProtectionRW.R8 = PAGE_READWRITE;
	ctxProtectionRW.R9 = (DWORD_PTR)&oldProtect;

	// Subtract 224 from 848
	ctxEncryption.Rsp -= (DWORD64)(8 + 624);
	ctxEncryption.Rip = (DWORD_PTR)SystemFunction032;
	ctxEncryption.Rcx = (DWORD_PTR)&Image;
	ctxEncryption.Rdx = (DWORD_PTR)&Key;

	// Subtract 112 from 624
	ctxRtlCopyMappedMemory.Rsp -= (DWORD64)(8 + 512);
	ctxRtlCopyMappedMemory.Rip = (DWORD_PTR)pRtlCopyMappedMemory;
	ctxRtlCopyMappedMemory.Rcx = (DWORD_PTR)bkpTib2;
	ctxRtlCopyMappedMemory.Rdx = (DWORD_PTR)tib;
	ctxRtlCopyMappedMemory.R8 = (DWORD64)sizeof(NT_TIB);

	// Subtract 112 from 512
	ctxRtlCopyMappedMemory2.Rsp -= (DWORD64)(8 + 400);
	ctxRtlCopyMappedMemory2.Rip = (DWORD_PTR)pRtlCopyMappedMemory;
	ctxRtlCopyMappedMemory2.Rcx = (DWORD_PTR)tib;
	ctxRtlCopyMappedMemory2.Rdx = (DWORD_PTR)bkpTib;
	ctxRtlCopyMappedMemory2.R8 = (DWORD64)sizeof(NT_TIB);

	// Subtract 112 from 400
	ctxRtlCopyMappedMemory3.Rsp -= (DWORD64)(8 + 288);
	ctxRtlCopyMappedMemory3.Rip = (DWORD_PTR)pRtlCopyMappedMemory;
	ctxRtlCopyMappedMemory3.Rcx = (DWORD_PTR)tib;
	ctxRtlCopyMappedMemory3.Rdx = (DWORD_PTR)bkpTib2;
	ctxRtlCopyMappedMemory3.R8 = (DWORD64)sizeof(NT_TIB);

	// Subtract 112 from 288
	ctxDecryption.Rsp -= (DWORD64)(8 + 176);
	ctxDecryption.Rip = (DWORD_PTR)SystemFunction032;
	ctxDecryption.Rcx = (DWORD_PTR)&Image;
	ctxDecryption.Rdx = (DWORD_PTR)&Key;

	// Subtract 96 from 176
	ctxProtectionRWX.Rsp -= (DWORD64)(8 + 80);
	ctxProtectionRWX.Rip = (DWORD_PTR)VirtualProtect;
	ctxProtectionRWX.Rcx = (DWORD_PTR)ImageBase;
	ctxProtectionRWX.Rdx = ImageSize;
	ctxProtectionRWX.R8 = PAGE_EXECUTE_READWRITE;
	ctxProtectionRWX.R9 = (DWORD_PTR)&oldProtect;
	
	SetTimerNative(hProtectionRWTimer, protectionRWDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxProtectionRW);
	SetTimerNative(hEncryptionTimer, encryptionDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxEncryption);
	SetTimerNative(hRtlCopyMappedContextTimer, rtlCopyMappedDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxRtlCopyMappedMemory);
	SetTimerNative(hRtlCopyMappedContextTimer2, rtlCopyMappedDueTime2, (PTIMER_APC_ROUTINE)NtContinue, &ctxRtlCopyMappedMemory2);
	SetTimerNative(hRtlCopyMappedContextTimer3, rtlCopyMappedDueTime3, (PTIMER_APC_ROUTINE)NtContinue, &ctxRtlCopyMappedMemory3);
	SetTimerNative(hDecryptionTimer, decryptionDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxDecryption);
	SetTimerNative(hProtectionRWXTimer, protectionRWXDueTime, (PTIMER_APC_ROUTINE)NtContinue, &ctxProtectionRWX);

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

	SeptaNtWaitAndDelay(rcxGadget, rdxGadget, shadowFixerGadget, r8Gadget, &liTimeout, pNtWaitForSingleObject, pNtDelayExecution, hProtectionRWTimer, hEncryptionTimer, hRtlCopyMappedContextTimer, hRtlCopyMappedContextTimer2, hRtlCopyMappedContextTimer3, hDecryptionTimer, hProtectionRWXTimer);
}