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

typedef NTSTATUS(NTAPI* pTpAllocIoCompletion)(
	_Out_ PTP_IO* IoCompletion,
	_In_ HANDLE FileHandle,
	_In_ PTP_WIN32_IO_CALLBACK IoCompletionCallback,
	_Inout_opt_ PVOID Context,
	_In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron);

typedef NTSTATUS(NTAPI* pTpReleaseIoCompletion)(
	_Inout_ PTP_IO IoCompletion);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#define OBJ_CASE_INSENSITIVE    0x00000040L

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, * PALPC_PORT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtAlpcCreatePort)(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL);

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef short CSHORT;
typedef struct _QUAD
{
	union
	{
		INT64 UseThisFieldToCopy;
		float DoNotUseThisField;
	};
} QUAD, * PQUAD;

typedef struct PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		CLIENT_ID ClientId;
		QUAD DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		SIZE_T ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE, * PPORT_MESSAGE;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

typedef NTSTATUS(NTAPI* pNtAlpcConnectPort)(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

typedef NTSTATUS(NTAPI* pNtAlpcSendWaitReceivePort)(
	HANDLE PortHandle,
	ULONG Flags,
	PPORT_MESSAGE SendMessage,
	PALPC_MESSAGE_ATTRIBUTES SendAttributes,
	PPORT_MESSAGE ReceiveMessage,
	PULONG BufferLength,
	PALPC_MESSAGE_ATTRIBUTES ReceiveAttributes,
	PLARGE_INTEGER Timeout);

typedef VOID (NTAPI* pRtlInitUnicodeString)(
	OUT PUNICODE_STRING DestinationString,
	IN __drv_aliasesMem PCWSTR SourceString OPTIONAL
);

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
void TestAlpc();