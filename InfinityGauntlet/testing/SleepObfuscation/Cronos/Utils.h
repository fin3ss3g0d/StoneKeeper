#ifndef UTILS_H
#define UTILS_H

#include "Cronos.h"
#include <psapi.h>

#define SIZE_MODULE_LIST 2
#define MAX_MODULE_NAME 100

BOOL        bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);
DWORD_PTR   findPattern(DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR   findInModule(LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
PVOID       findGadget(PBYTE hdrParserFuncB, PCHAR hdrParserFunctMask);
HANDLE CreateTimerNative(PWSTR wTimerName);
void SetTimerNative(HANDLE hTimer, LARGE_INTEGER TimerDueTime, PTIMER_APC_ROUTINE TimerApcRoutine, PVOID TimerContext);
VOID NTAPI MyTimerApcRoutine(PVOID TimerContext, ULONG TimerLowValue, LONG TimerHighValue);
int PrintWaitStatus(NTSTATUS status, const char* message);
void PrintHelloWorld();
NT_TIB* GetTib();

#endif
