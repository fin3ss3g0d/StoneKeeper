#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdint.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef ULONG LOGICAL;
typedef ULONG* PLOGICAL;

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

typedef NTSTATUS(NTAPI* pTpWaitForWork)(
	_Inout_ PTP_WORK Work,
	_In_ LOGICAL CancelPendingCallbacks);

typedef NTSTATUS(NTAPI* pTpPostWork)(
	_Inout_ PTP_WORK Work);

typedef NTSTATUS(NTAPI* pTpReleaseWork)(
	_Inout_ PTP_WORK Work);

typedef NTSTATUS(NTAPI* pTpAllocWork)(
	_Out_ PTP_WORK* WorkReturn,
	_In_ PTP_WORK_CALLBACK WorkCallback,
	_Inout_opt_ PVOID WorkContext,
	_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

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

typedef NTSTATUS(NTAPI* pTpAllocWait)(
	_Out_ PTP_WAIT* Wait,
	_In_ PTP_WAIT_CALLBACK Callback,
	_Inout_opt_ PVOID Context,
	_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

typedef NTSTATUS(NTAPI* pTpSetWait)(
	_Inout_ PTP_WAIT Wait,
	_In_opt_ HANDLE Handle,
	_In_opt_ PLARGE_INTEGER Timeout);

typedef NTSTATUS(NTAPI* pTpReleaseWait)(
	_Inout_ PTP_WAIT Wait);

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

// Function definitions
void CALLBACK TimerCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Parameter, PTP_TIMER Timer);
void CALLBACK WorkItemCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
VOID CALLBACK WaitCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WAIT Wait, TP_WAIT_RESULT WaitResult);
void TestThreadpoolCallbackNative();
EXTERN_C void CALLBACK ProxyFunctionTimerCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Parameter, PTP_TIMER Timer);