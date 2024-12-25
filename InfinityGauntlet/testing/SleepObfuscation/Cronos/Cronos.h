#ifndef CRONUS_H
#define CRONUS_H

#include <stdio.h>
#include <windows.h>

// Macros
#define TIMER_SLEEP 2000
#define InitializeTimerMs(ft, sec)                                                  \
    {                                                                                            \
        (ft)->HighPart = (DWORD)(((ULONGLONG) - ((sec) * 1000 * 10 * 1000)) >> 32);                               \
        (ft)->LowPart  = (DWORD)(((ULONGLONG) - ((sec) * 1000 * 10 * 1000)) & 0xffffffff);                          \
    }

#define STATUS_SUCCESS 0x00000000
#define STATUS_ALERTED 0x00000101
#define STATUS_USER_APC 0x000000C0
#define OBJ_INHERIT             0x00000002L
#define OBJ_PERMANENT           0x00000010L
#define OBJ_EXCLUSIVE           0x00000020L
#define OBJ_CASE_INSENSITIVE    0x00000040L
#define OBJ_OPENIF              0x00000080L
#define OBJ_OPENLINK            0x00000100L
#define OBJ_VALID_ATTRIBUTES    0x000001F2L

// Struct definitions.    
typedef struct _CRYPT_BUFFER {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} CRYPT_BUFFER, * PCRYPT_BUFFER, DATA_KEY, * PDATA_KEY, CLEAR_DATA, * PCLEAR_DATA, CYPHER_DATA, * PCYPHER_DATA;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
    (p)->RootDirectory = r;                           \
    (p)->Attributes = a;                              \
    (p)->ObjectName = n;                              \
    (p)->SecurityDescriptor = s;                      \
    (p)->SecurityQualityOfService = NULL;             \
}

typedef enum _TIMER_TYPE
{
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE, * PTIMER_TYPE;

typedef enum _TIMER_SET_INFORMATION_CLASS {
    TimerSetCoalescableTimer,
    MaxTimerInfoClass  // MaxTimerInfoClass should always be the last enum
} TIMER_SET_INFORMATION_CLASS;

typedef VOID(NTAPI* PTIMER_APC_ROUTINE)(
	_In_ PVOID TimerContext,
	_In_ ULONG TimerLowValue,
	_In_ LONG TimerHighValue
);

typedef struct _COUNTED_REASON_CONTEXT {
    ULONG Version;
    ULONG Flags;
    union {
        struct {
            UNICODE_STRING ResourceFileName;
            USHORT ResourceReasonId;
            ULONG StringCount;
            _Field_size_(StringCount) PUNICODE_STRING ReasonStrings;
        } DUMMYSTRUCTNAME;

        UNICODE_STRING SimpleString;
    } DUMMYUNIONNAME;
} COUNTED_REASON_CONTEXT, * PCOUNTED_REASON_CONTEXT;

typedef struct _TIMER_SET_COALESCABLE_TIMER_INFO {
    _In_ LARGE_INTEGER DueTime;
    _In_opt_ PTIMER_APC_ROUTINE TimerApcRoutine;
    _In_opt_ PVOID TimerContext;
    _In_opt_ struct _COUNTED_REASON_CONTEXT* WakeContext;
    _In_opt_ ULONG Period;
    _In_ ULONG TolerableDelay;
    _Out_opt_ PBOOLEAN PreviousState;
} TIMER_SET_COALESCABLE_TIMER_INFO, * PTIMER_SET_COALESCABLE_TIMER_INFO;

// Functions.
typedef NTSTATUS(WINAPI* tSystemFunction032)(PCRYPT_BUFFER pData, PDATA_KEY pKey);

typedef NTSTATUS(NTAPI* PFN_NTDELAYEXECUTION)(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
    );

typedef VOID(*PFN_RTLINITUNICODESTRING)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef NTSTATUS(NTAPI* PFN_NTWAITFORSINGLEOBJECT)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* PFN_NTCREATETIMER)(
    PHANDLE TimerHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    TIMER_TYPE TimerType
    );

typedef NTSTATUS(NTAPI* PFN_NTCREATETIMER2)(
    PHANDLE TimerHandle,
    PVOID Reserved1,
    POBJECT_ATTRIBUTES ObjectAttributes,
    ULONG Attributes,
    ACCESS_MASK DesiredAccess
    );

typedef NTSTATUS(NTAPI* PFN_NTSETTIMEREX)(
    HANDLE TimerHandle,
    TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    PVOID TimerSetInformation,
    ULONG TimerSetInformationLength
    );

typedef NTSTATUS(NTAPI* PFN_NTWAITFORSINGLEOBJECT)(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(WINAPI* BaseGetNamedObjectDirectoryFunc)(HANDLE* phDir);

// PVOID rcxGadget, PVOID rdxGadget, PVOID shadowFixerGadget, PVOID r8Gadget, PVOID pWaitForSingleObjectEx, PVOID pNtDelayExecution, PLARGE_INTEGER liTimeout, HANDLE hTimer1, HANDLE hTimer2, HANDLE hTimer3, HANDLE hTimer4
extern void PentaWaitExAndDelay(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
// PVOID rcxGadget, PVOID rdxGadget, PVOID shadowFixerGadget, PVOID r8Gadget, PLARGE_INTEGER liTimeout, PVOID pNtWaitForSingleObject, PVOID pNtDelayExecution, HANDLE hTimer1, HANDLE hTimer2, HANDLE hTimer3, HANDLE hTimer4
extern void PentaNtWaitAndDelay(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
// Same as above with ZeroTrace stack spoofing
extern void PentaNtWaitAndDelayZeroTrace(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
// PVOID rcxGadget, PVOID rdxGadget, PVOID shadowFixerGadget, PVOID r8Gadget, PLARGE_INTEGER liTimeout, PVOID pNtWaitForSingleObject, PVOID pNtDelayExecution, HANDLE hTimer1, HANDLE hTimer2, HANDLE hTimer3, HANDLE hTimer4, HANDLE hTimer5, HANDLE hTimer6, HANDLE hTimer7
extern void SeptaNtWaitAndDelay(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
extern void QuadSleep(PVOID, PVOID, PVOID, PVOID);
void CronosSleep(int ticks);
int TestPentaNtWaitAndDelay(int sleepTime);
int TestPentaNtWaitAndDelay2(int sleepTime);
int TestPentaNtWaitAndDelay3(int sleepTime);
int TestSeptaNtWaitAndDelay(int sleepTime);
int TestSeptaNtWaitAndDelay2(int sleepTime);
int TestSeptaNtWaitAndDelay3(int sleepTime);
int TestPentaWaitExAndDelay(int sleepTime);
int TestPentaWaitExAndDelay2(int sleepTime);
int TestQuadSleep();

#endif