#pragma once
#include <Windows.h>
#include <stdio.h>
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define FAIL 0
#define SUCCESS 1
#define XORKEY 0x13371337
#define UP -32
#define DOWN 32
#define OBJ_CASE_INSENSITIVE 0x00000040
#define OBJ_INHERIT 0x00000002L
#define DUPLICATE_SAME_ATTRIBUTES 0x00000004
#define NtCurrentProcess() (HANDLE)-1
#define NtCurrentThread() (HANDLE)-2

typedef BYTE SE_SIGNING_LEVEL, * PSE_SIGNING_LEVEL;

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
    PVOID pValue;
    ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
    ULONG64        Version;
    UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, * PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _WNF_TYPE_ID
{
    GUID TypeId;
} WNF_TYPE_ID, * PWNF_TYPE_ID;

typedef enum _KCONTINUE_TYPE
{
    KCONTINUE_UNWIND,
    KCONTINUE_RESUME,
    KCONTINUE_LONGJUMP,
    KCONTINUE_SET,
    KCONTINUE_LAST
} KCONTINUE_TYPE;

typedef struct _IO_STATUS_BLOCK
{
    union
    {
        NTSTATUS Status;
        VOID* Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName,
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE, * PPS_CREATE_STATE;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
    HardwareProfileChangeEvent,
    TargetDeviceChangeEvent,
    DeviceClassChangeEvent,
    CustomDeviceEvent,
    DeviceInstallEvent,
    DeviceArrivalEvent,
    PowerEvent,
    VetoEvent,
    BlockedDriverEvent,
    InvalidIDEvent,
    MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, * PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
    PNP_VetoTypeUnknown, // unspecified
    PNP_VetoLegacyDevice, // instance path
    PNP_VetoPendingClose, // instance path
    PNP_VetoWindowsApp, // module
    PNP_VetoWindowsService, // service
    PNP_VetoOutstandingOpen, // instance path
    PNP_VetoDevice, // instance path
    PNP_VetoDriver, // driver service name
    PNP_VetoIllegalDeviceRequest, // instance path
    PNP_VetoInsufficientPower, // unspecified
    PNP_VetoNonDisableable, // instance path
    PNP_VetoLegacyDriver, // service
    PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, * PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
    UNICODE_STRING Name;
    USHORT         ValueType;
    USHORT         Reserved;
    ULONG          Flags;
    ULONG          ValueCount;
    union
    {
        PLONG64                                      pInt64;
        PULONG64                                     pUint64;
        PUNICODE_STRING                              pString;
        PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
        PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
    } Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, * PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef VOID(KNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE {
    ULONGLONG Attribute;				/// PROC_THREAD_ATTRIBUTE_XXX | PROC_THREAD_ATTRIBUTE_XXX modifiers, see ProcThreadAttributeValue macro and Windows Internals 6 (372)
    SIZE_T Size;						/// Size of Value or *ValuePtr
    union {
        ULONG_PTR Value;				/// Reserve 8 bytes for data (such as a Handle or a data pointer)
        PVOID ValuePtr;					/// data pointer
    };
    PSIZE_T ReturnLength;				/// Either 0 or specifies size of data returned to caller via "ValuePtr"
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _WNF_STATE_NAME
{
    ULONG Data[2];
} WNF_STATE_NAME, * PWNF_STATE_NAME;

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

typedef struct _KEY_VALUE_ENTRY
{
    PUNICODE_STRING ValueName;
    ULONG           DataLength;
    ULONG           DataOffset;
    ULONG           Type;
} KEY_VALUE_ENTRY, * PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
    KeyWriteTimeInformation,
    KeyWow64FlagsInformation,
    KeyControlFlagsInformation,
    KeySetVirtualizationInformation,
    KeySetDebugInformation,
    KeySetHandleTagsInformation,
    MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, * PKEY_SET_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemHandleInformation = 16,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessWow64Information = 26,
    ProcessImageFileName = 27,
    ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
    ULONG    Version;
    ULONG    Reserved;
    LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, * PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
    ULONG Version;
    ULONG Length;
    ULONG Type;
    CHAR  FilePath[1];
} FILE_PATH, * PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
    ULONG         NextEntryOffset;
    ULONG         SidLength;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER QuotaUsed;
    LARGE_INTEGER QuotaThreshold;
    LARGE_INTEGER QuotaLimit;
    SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, * PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG SidLength;
    SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, * PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         FileAttributes;
    ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, * PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
    FilterBootOptionOperationOpenSystemStore,
    FilterBootOptionOperationSetElement,
    FilterBootOptionOperationDeleteElement,
    FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, * PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
    NotificationEvent = 0,
    SynchronizationEvent = 1,
} EVENT_TYPE, * PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
    ULONG  NextEntryOffset;
    UCHAR  Flags;
    UCHAR  EaNameLength;
    USHORT EaValueLength;
    CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, * PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
    ULONG NextEntryOffset;
    BYTE  EaNameLength;
    CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, * PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
    ULONG Version;
    ULONG Length;
    ULONG Timeout;
    ULONG CurrentBootEntryId;
    ULONG NextBootEntryId;
    WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, * PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, * PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
    WnfDataScopeSystem = 0,
    WnfDataScopeSession = 1,
    WnfDataScopeUser = 2,
    WnfDataScopeProcess = 3,
    WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, * PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
    WnfWellKnownStateName = 0,
    WnfPermanentStateName = 1,
    WnfPersistentStateName = 2,
    WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, * PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, * PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
    IoSessionEventIgnore,
    IoSessionEventCreated,
    IoSessionEventTerminated,
    IoSessionEventConnected,
    IoSessionEventDisconnected,
    IoSessionEventLogon,
    IoSessionEventLogoff,
    IoSessionEventMax
} IO_SESSION_EVENT, * PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
    PortBasicInformation,
#if DEVL
    PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, * PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
    PlugPlayControlEnumerateDevice,
    PlugPlayControlRegisterNewDevice,
    PlugPlayControlDeregisterDevice,
    PlugPlayControlInitializeDevice,
    PlugPlayControlStartDevice,
    PlugPlayControlUnlockDevice,
    PlugPlayControlQueryAndRemoveDevice,
    PlugPlayControlUserResponse,
    PlugPlayControlGenerateLegacyDevice,
    PlugPlayControlGetInterfaceDeviceList,
    PlugPlayControlProperty,
    PlugPlayControlDeviceClassAssociation,
    PlugPlayControlGetRelatedDevice,
    PlugPlayControlGetInterfaceDeviceAlias,
    PlugPlayControlDeviceStatus,
    PlugPlayControlGetDeviceDepth,
    PlugPlayControlQueryDeviceRelations,
    PlugPlayControlTargetDeviceRelation,
    PlugPlayControlQueryConflictList,
    PlugPlayControlRetrieveDock,
    PlugPlayControlResetDevice,
    PlugPlayControlHaltDevice,
    PlugPlayControlGetBlockedDriverList,
    MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, * PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
    IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, * PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
    DebugObjectFlags = 1,
    MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, * PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
    SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, * PSEMAPHORE_INFORMATION_CLASS;

typedef enum _VDMSERVICECLASS
{
    VdmStartExecution,
    VdmQueueInterrupt,
    VdmDelayInterrupt,
    VdmInitialize,
    VdmFeatures,
    VdmSetInt21Handler,
    VdmQueryDir,
    VdmPrinterDirectIoOpen,
    VdmPrinterDirectIoClose,
    VdmPrinterInitialize,
    VdmSetLdtEntries,
    VdmSetProcessLdtInfo,
    VdmAdlibEmulation,
    VdmPMCliControl,
    VdmQueryVdmProcess
} VDMSERVICECLASS, * PVDMSERVICECLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
    MemoryReserveUserApc,
    MemoryReserveIoCompletion,
    MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, * PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
    AlpcBasicInformation,
    AlpcPortInformation,
    AlpcAssociateCompletionPortInformation,
    AlpcConnectedSIDInformation,
    AlpcServerInformation,
    AlpcMessageZoneInformation,
    AlpcRegisterCompletionListInformation,
    AlpcUnregisterCompletionListInformation,
    AlpcAdjustCompletionListConcurrencyCountInformation,
    AlpcRegisterCallbackInformation,
    AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, * PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
    PVOID PortContext;
    PVOID MessageContext;
    ULONG SequenceNumber;
    ULONG MessageID;
    ULONG CallbackID;
} ALPC_CONTEXT_ATTR, * PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
    ULONG  Flags;
    HANDLE SectionHandle;
    PVOID  ViewBase;
    SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, * PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
    ULONG                        Flags;
    PSECURITY_QUALITY_OF_SERVICE SecurityQos;
    HANDLE                       ContextHandle;
    ULONG                        Reserved1;
    ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, * PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
    ProfileTime = 0,
    ProfileAlignmentFixup = 1,
    ProfileTotalIssues = 2,
    ProfilePipelineDry = 3,
    ProfileLoadInstructions = 4,
    ProfilePipelineFrozen = 5,
    ProfileBranchInstructions = 6,
    ProfileTotalNonissues = 7,
    ProfileDcacheMisses = 8,
    ProfileIcacheMisses = 9,
    ProfileCacheMisses = 10,
    ProfileBranchMispredictions = 11,
    ProfileStoreInstructions = 12,
    ProfileFpInstructions = 13,
    ProfileIntegerInstructions = 14,
    Profile2Issue = 15,
    Profile3Issue = 16,
    Profile4Issue = 17,
    ProfileSpecialInstructions = 18,
    ProfileTotalCycles = 19,
    ProfileIcacheIssues = 20,
    ProfileDcacheAccesses = 21,
    ProfileMemoryBarrierCycles = 22,
    ProfileLoadLinkedIssues = 23,
    ProfileMaximum = 24,
} KPROFILE_SOURCE, * PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
    AlpcMessageSidInformation,
    AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, * PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout,
    WorkerFactoryRetryTimeout,
    WorkerFactoryIdleTimeout,
    WorkerFactoryBindingCount,
    WorkerFactoryThreadMinimum,
    WorkerFactoryThreadMaximum,
    WorkerFactoryPaused,
    WorkerFactoryBasicInformation,
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation,
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
    SystemMemoryPartitionInformation,
    SystemMemoryPartitionMoveMemory,
    SystemMemoryPartitionAddPagefile,
    SystemMemoryPartitionCombineMemory,
    SystemMemoryPartitionInitialAddMemory,
    SystemMemoryPartitionGetMemoryEvents,
    SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, * PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
    MutantBasicInformation,
    MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, * PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
    AtomBasicInformation,
    AtomTableInformation
} ATOM_INFORMATION_CLASS, * PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
    IN PVOID TimerContext,
    IN ULONG TimerLowValue,
    IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation = 0,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
    GUID EventGuid;
    PLUGPLAY_EVENT_CATEGORY EventCategory;
    PULONG Result;
    ULONG Flags;
    ULONG TotalSize;
    PVOID DeviceObject;

    union
    {
        struct
        {
            GUID ClassGuid;
            WCHAR SymbolicLinkName[1];
        } DeviceClass;
        struct
        {
            WCHAR DeviceIds[1];
        } TargetDevice;
        struct
        {
            WCHAR DeviceId[1];
        } InstallDevice;
        struct
        {
            PVOID NotificationStructure;
            WCHAR DeviceIds[1];
        } CustomNotification;
        struct
        {
            PVOID Notification;
        } ProfileNotification;
        struct
        {
            ULONG NotificationCode;
            ULONG NotificationData;
        } PowerNotification;
        struct
        {
            PNP_VETO_TYPE VetoType;
            WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
        } VetoNotification;
        struct
        {
            GUID BlockedDriverGuid;
        } BlockedDriverNotification;
        struct
        {
            WCHAR ParentId[1];
        } InvalidIDNotification;
    } u;
} PLUGPLAY_EVENT_BLOCK, * PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
    IN PVOID            ApcContext,
    IN PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
    DirectoryNotifyInformation = 1,
    DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, * PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
    EventBasicInformation
} EVENT_INFORMATION_CLASS, * PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
    unsigned long AllocatedAttributes;
    unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, * PALPC_MESSAGE_ATTRIBUTES;

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

typedef enum _IO_SESSION_STATE
{
    IoSessionStateCreated = 1,
    IoSessionStateInitialized = 2,
    IoSessionStateConnected = 3,
    IoSessionStateDisconnected = 4,
    IoSessionStateDisconnectedLoggedOn = 5,
    IoSessionStateLoggedOn = 6,
    IoSessionStateLoggedOff = 7,
    IoSessionStateTerminated = 8,
    IoSessionStateMax = 9,
} IO_SESSION_STATE, * PIO_SESSION_STATE;

typedef const WNF_STATE_NAME* PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID* PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
    unsigned __int64 SubscriptionId;
    WNF_STATE_NAME   StateName;
    unsigned long    ChangeStamp;
    unsigned long    StateDataSize;
    unsigned long    EventMask;
    WNF_TYPE_ID      TypeId;
    unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, * PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
    SysDbgQueryModuleInformation = 0,
    SysDbgQueryTraceInformation = 1,
    SysDbgSetTracePoint = 2,
    SysDbgSetSpecialCall = 3,
    SysDbgClearSpecialCalls = 4,
    SysDbgQuerySpecialCalls = 5,
    SysDbgBreakPoint = 6,
    SysDbgQueryVersion = 7,
    SysDbgReadVirtual = 8,
    SysDbgWriteVirtual = 9,
    SysDbgReadPhysical = 10,
    SysDbgWritePhysical = 11,
    SysDbgReadControlSpace = 12,
    SysDbgWriteControlSpace = 13,
    SysDbgReadIoSpace = 14,
    SysDbgWriteIoSpace = 15,
    SysDbgReadMsr = 16,
    SysDbgWriteMsr = 17,
    SysDbgReadBusData = 18,
    SysDbgWriteBusData = 19,
    SysDbgCheckLowMemory = 20,
    SysDbgEnableKernelDebugger = 21,
    SysDbgDisableKernelDebugger = 22,
    SysDbgGetAutoKdEnable = 23,
    SysDbgSetAutoKdEnable = 24,
    SysDbgGetPrintBufferSize = 25,
    SysDbgSetPrintBufferSize = 26,
    SysDbgGetKdUmExceptionEnable = 27,
    SysDbgSetKdUmExceptionEnable = 28,
    SysDbgGetTriageDump = 29,
    SysDbgGetKdBlockEnable = 30,
    SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, * PDEBUG_CONTROL_CODE;

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

typedef struct FILE_BASIC_INFORMATION
{
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, * PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
    ULONG Length;
    ULONG ViewSize;
    ULONG ViewBase;
} PORT_SECTION_READ, * PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
    ULONG  Length;
    HANDLE SectionHandle;
    ULONG  SectionOffset;
    ULONG  ViewSize;
    PVOID  ViewBase;
    PVOID  TargetViewBase;
} PORT_SECTION_WRITE, * PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE, * PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
    ULONG Version;
    ULONG Length;
    ULONG Id;
    ULONG Attributes;
    ULONG FriendlyNameOffset;
    ULONG BootFilePathOffset;
    ULONG OsOptionsLength;
    UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, * PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
    ULONG Version;
    ULONG Length;
    ULONG Id;
    ULONG Attributes;
    ULONG FriendlyNameOffset;
    ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, * PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, * PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
    TimerSetCoalescableTimer,
    MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, * PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
    FileFsVolumeInformation = 1,
    FileFsLabelInformation = 2,
    FileFsSizeInformation = 3,
    FileFsDeviceInformation = 4,
    FileFsAttributeInformation = 5,
    FileFsControlInformation = 6,
    FileFsFullSizeInformation = 7,
    FileFsObjectIdInformation = 8,
    FileFsDriverPathInformation = 9,
    FileFsVolumeFlagsInformation = 10,
    FileFsSectorSizeInformation = 11,
    FileFsDataCopyInformation = 12,
    FileFsMetadataSizeInformation = 13,
    FileFsFullSizeInformationEx = 14,
    FileFsMaximumInformation = 15,
} FSINFOCLASS, * PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
    WaitAll = 0,
    WaitAny = 1
} WAIT_TYPE, * PWAIT_TYPE;

typedef struct _USER_STACK
{
    PVOID FixedStackBase;
    PVOID FixedStackLimit;
    PVOID ExpandableStackBase;
    PVOID ExpandableStackLimit;
    PVOID ExpandableStackBottom;
} USER_STACK, * PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
    SectionBasicInformation,
    SectionImageInformation,
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
    ApphelpCacheServiceLookup = 0,
    ApphelpCacheServiceRemove = 1,
    ApphelpCacheServiceUpdate = 2,
    ApphelpCacheServiceFlush = 3,
    ApphelpCacheServiceDump = 4,
    ApphelpDBGReadRegistry = 0x100,
    ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, * PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
    USHORT Version;
    USHORT Reserved;
    ULONG  AttributeCount;
    union
    {
        PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
    } Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, * PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
    PVOID           KeyContext;
    PVOID           ApcContext;
    IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, * PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    MaxThreadInfoClass
} THREADINFOCLASS, * PTHREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
    ObjectBasicInformation,
    ObjectNameInformation,
    ObjectTypeInformation,
    ObjectAllTypesInformation,
    ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, * POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation = 2,
    FileBothDirectoryInformation = 3,
    FileBasicInformation = 4,
    FileStandardInformation = 5,
    FileInternalInformation = 6,
    FileEaInformation = 7,
    FileAccessInformation = 8,
    FileNameInformation = 9,
    FileRenameInformation = 10,
    FileLinkInformation = 11,
    FileNamesInformation = 12,
    FileDispositionInformation = 13,
    FilePositionInformation = 14,
    FileFullEaInformation = 15,
    FileModeInformation = 16,
    FileAlignmentInformation = 17,
    FileAllInformation = 18,
    FileAllocationInformation = 19,
    FileEndOfFileInformation = 20,
    FileAlternateNameInformation = 21,
    FileStreamInformation = 22,
    FilePipeInformation = 23,
    FilePipeLocalInformation = 24,
    FilePipeRemoteInformation = 25,
    FileMailslotQueryInformation = 26,
    FileMailslotSetInformation = 27,
    FileCompressionInformation = 28,
    FileObjectIdInformation = 29,
    FileCompletionInformation = 30,
    FileMoveClusterInformation = 31,
    FileQuotaInformation = 32,
    FileReparsePointInformation = 33,
    FileNetworkOpenInformation = 34,
    FileAttributeTagInformation = 35,
    FileTrackingInformation = 36,
    FileIdBothDirectoryInformation = 37,
    FileIdFullDirectoryInformation = 38,
    FileValidDataLengthInformation = 39,
    FileShortNameInformation = 40,
    FileIoCompletionNotificationInformation = 41,
    FileIoStatusBlockRangeInformation = 42,
    FileIoPriorityHintInformation = 43,
    FileSfioReserveInformation = 44,
    FileSfioVolumeInformation = 45,
    FileHardLinkInformation = 46,
    FileProcessIdsUsingFileInformation = 47,
    FileNormalizedNameInformation = 48,
    FileNetworkPhysicalNameInformation = 49,
    FileIdGlobalTxDirectoryInformation = 50,
    FileIsRemoteDeviceInformation = 51,
    FileUnusedInformation = 52,
    FileNumaNodeInformation = 53,
    FileStandardLinkInformation = 54,
    FileRemoteProtocolInformation = 55,
    FileRenameInformationBypassAccessCheck = 56,
    FileLinkInformationBypassAccessCheck = 57,
    FileVolumeNameInformation = 58,
    FileIdInformation = 59,
    FileIdExtdDirectoryInformation = 60,
    FileReplaceCompletionInformation = 61,
    FileHardLinkFullIdInformation = 62,
    FileIdExtdBothDirectoryInformation = 63,
    FileDispositionInformationEx = 64,
    FileRenameInformationEx = 65,
    FileRenameInformationExBypassAccessCheck = 66,
    FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, * PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
    TimerBasicInformation
} TIMER_INFORMATION_CLASS, * PTIMER_INFORMATION_CLASS;

typedef struct _KCONTINUE_ARGUMENT
{
    KCONTINUE_TYPE ContinueType;
    ULONG          ContinueFlags;
    ULONGLONG      Reserved[2];
} KCONTINUE_ARGUMENT, * PKCONTINUE_ARGUMENT;

/*
 * PEB/TEB structures
*/

typedef struct _LDR_MODULE {
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
    PVOID                   BaseAddress;
    PVOID                   EntryPoint;
    ULONG                   SizeOfImage;
    UNICODE_STRING          FullDllName;
    UNICODE_STRING          BaseDllName;
    ULONG                   Flags;
    SHORT                   LoadCount;
    SHORT                   TlsIndex;
    LIST_ENTRY              HashTableEntry;
    ULONG                   TimeDateStamp;
} LDR_MODULE, * PLDR_MODULE;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
    ULONG Flags;
    PCHAR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, * PTEB_ACTIVE_FRAME_CONTEXT;

typedef struct _TEB_ACTIVE_FRAME {
    ULONG Flags;
    struct _TEB_ACTIVE_FRAME* Previous;
    PTEB_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, * PTEB_ACTIVE_FRAME;

typedef struct _GDI_TEB_BATCH {
    ULONG Offset;
    ULONG HDC;
    ULONG Buffer[310];
} GDI_TEB_BATCH, * PGDI_TEB_BATCH;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    struct __RTL_ACTIVATION_CONTEXT_STACK_FRAME* Previous;
    PACTIVATION_CONTEXT ActivationContext;
    ULONG Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

/*
lkd> dt nt!_ACTIVATION_CONTEXT_STACK
    +0x000 ActiveFrame      : Ptr64 _RTL_ACTIVATION_CONTEXT_STACK_FRAME
    +0x008 FrameListCache   : _LIST_ENTRY
    +0x018 Flags            : Uint4B
    +0x01c NextCookieSequenceNumber : Uint4B
    +0x020 StackId          : Uint4B
*/

typedef struct _ACTIVATION_CONTEXT_STACK {
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY FrameListCache;
    ULONG Flags;
    ULONG NextCookieSequenceNumber;
    ULONG StackId;
} ACTIVATION_CONTEXT_STACK, * PACTIVATION_CONTEXT_STACK;

/*
lkd> dt nt!_PEB_LDR_DATA
    +0x000 Length           : Uint4B
    +0x004 Initialized      : UChar
    +0x008 SsHandle         : Ptr64 Void
    +0x010 InLoadOrderModuleList : _LIST_ENTRY
    +0x020 InMemoryOrderModuleList : _LIST_ENTRY
    +0x030 InInitializationOrderModuleList : _LIST_ENTRY
    +0x040 EntryInProgress  : Ptr64 Void
    +0x048 ShutdownInProgress : UChar
    +0x050 ShutdownThreadId : Ptr64 Void
*/

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    UCHAR ShutdownInProgress;
    PVOID ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

/*
lkd> dt nt!_LDR_DATA_TABLE_ENTRY
    +0x000 InLoadOrderLinks : _LIST_ENTRY
    +0x010 InMemoryOrderLinks : _LIST_ENTRY
    +0x020 InInitializationOrderLinks : _LIST_ENTRY
    +0x030 DllBase          : Ptr64 Void
    +0x038 EntryPoint       : Ptr64 Void
    +0x040 SizeOfImage      : Uint4B
    +0x048 FullDllName      : _UNICODE_STRING
    +0x058 BaseDllName      : _UNICODE_STRING
    +0x068 FlagGroup        : [4] UChar
    +0x068 Flags            : Uint4B
    +0x068 PackagedBinary   : Pos 0, 1 Bit
    +0x068 MarkedForRemoval : Pos 1, 1 Bit
    +0x068 ImageDll         : Pos 2, 1 Bit
    +0x068 LoadNotificationsSent : Pos 3, 1 Bit
    +0x068 TelemetryEntryProcessed : Pos 4, 1 Bit
    +0x068 ProcessStaticImport : Pos 5, 1 Bit
    +0x068 InLegacyLists    : Pos 6, 1 Bit
    +0x068 InIndexes        : Pos 7, 1 Bit
    +0x068 ShimDll          : Pos 8, 1 Bit
    +0x068 InExceptionTable : Pos 9, 1 Bit
    +0x068 ReservedFlags1   : Pos 10, 2 Bits
    +0x068 LoadInProgress   : Pos 12, 1 Bit
    +0x068 LoadConfigProcessed : Pos 13, 1 Bit
    +0x068 EntryProcessed   : Pos 14, 1 Bit
    +0x068 ProtectDelayLoad : Pos 15, 1 Bit
    +0x068 ReservedFlags3   : Pos 16, 2 Bits
    +0x068 DontCallForThreads : Pos 18, 1 Bit
    +0x068 ProcessAttachCalled : Pos 19, 1 Bit
    +0x068 ProcessAttachFailed : Pos 20, 1 Bit
    +0x068 CorDeferredValidate : Pos 21, 1 Bit
    +0x068 CorImage         : Pos 22, 1 Bit
    +0x068 DontRelocate     : Pos 23, 1 Bit
    +0x068 CorILOnly        : Pos 24, 1 Bit
    +0x068 ChpeImage        : Pos 25, 1 Bit
    +0x068 ReservedFlags5   : Pos 26, 2 Bits
    +0x068 Redirected       : Pos 28, 1 Bit
    +0x068 ReservedFlags6   : Pos 29, 2 Bits
    +0x068 CompatDatabaseProcessed : Pos 31, 1 Bit
    +0x06c ObsoleteLoadCount : Uint2B
    +0x06e TlsIndex         : Uint2B
    +0x070 HashLinks        : _LIST_ENTRY
    +0x080 TimeDateStamp    : Uint4B
    +0x088 EntryPointActivationContext : Ptr64 _ACTIVATION_CONTEXT
    +0x090 Lock             : Ptr64 Void
    +0x098 DdagNode         : Ptr64 _LDR_DDAG_NODE
    +0x0a0 NodeModuleLink   : _LIST_ENTRY
    +0x0b0 LoadContext      : Ptr64 _LDRP_LOAD_CONTEXT
    +0x0b8 ParentDllBase    : Ptr64 Void
    +0x0c0 SwitchBackContext : Ptr64 Void
    +0x0c8 BaseAddressIndexNode : _RTL_BALANCED_NODE
    +0x0e0 MappingInfoIndexNode : _RTL_BALANCED_NODE
    +0x0f8 OriginalBase     : Uint8B
    +0x100 LoadTime         : _LARGE_INTEGER
    +0x108 BaseNameHashValue : Uint4B
    +0x10c LoadReason       : _LDR_DLL_LOAD_REASON
    +0x110 ImplicitPathOptions : Uint4B
    +0x114 ReferenceCount   : Uint4B
    +0x118 DependentLoadFlags : Uint4B
    +0x11c SigningLevel     : UChar

*/
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    UCHAR FlagGroup[4];
    union {
        ULONG Flags;
        struct {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ChpeImage : 1;
            ULONG ReservedFlags5 : 2;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        };
    };
    SHORT ObsoleteLoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

/*
 * Structures/Definitions for SysNtCreateUserProcess
*/

typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct {
            union {
                ULONG InitFlags;
                struct {
                    UCHAR  WriteOutputOnExit : 1;
                    UCHAR  DetectManifest : 1;
                    UCHAR  IFEOSkipDebugger : 1;
                    UCHAR  IFEODoNotPropagateKeyState : 1;
                    UCHAR  SpareBits1 : 4;
                    UCHAR  SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;
        // PsCreateFailOnSectionCreate
        struct {
            HANDLE FileHandle;
        } FailSection;
        // PsCreateFailExeFormat
        struct {
            USHORT DllCharacteristics;
        } ExeFormat;
        // PsCreateFailExeName
        struct {
            HANDLE IFEOKey;
        } ExeName;
        // PsCreateSuccess
        struct {
            union {
                ULONG OutputFlags;
                struct {
                    UCHAR  ProtectedProcess : 1;
                    UCHAR  AddressSpaceOverride : 1;
                    UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR  ManifestDetected : 1;
                    UCHAR  ProtectedProcessLight : 1;
                    UCHAR  SpareBits1 : 3;
                    UCHAR  SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE    FileHandle;
            HANDLE    SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG     UserProcessParametersWow64;
            ULONG     CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG     PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG     ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, * PPS_CREATE_INFO;

typedef struct _RTLP_CURDIR_REF
{
    LONG RefCount;
    HANDLE Handle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;

typedef struct RTL_RELATIVE_NAME_U {
    UNICODE_STRING RelativeName;
    HANDLE ContainingDirectory;
    PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32
#define RTL_USER_PROCESS_PARAMETERS_NORMALIZED 0x01
#define	HANDLE_DETACHED_PROCESS ((HANDLE)-1)
#define	HANDLE_CREATE_NEW_CONSOLE ((HANDLE)-2)
#define HANDLE_CREATE_NO_WINDOW ((HANDLE)-3)
/*
lkd> dt nt!_RTL_USER_PROCESS_PARAMETERS
    +0x000 MaximumLength    : Uint4B
    +0x004 Length           : Uint4B
    +0x008 Flags            : Uint4B
    +0x00c DebugFlags       : Uint4B
    +0x010 ConsoleHandle    : Ptr64 Void
    +0x018 ConsoleFlags     : Uint4B
    +0x020 StandardInput    : Ptr64 Void
    +0x028 StandardOutput   : Ptr64 Void
    +0x030 StandardError    : Ptr64 Void
    +0x038 CurrentDirectory : _CURDIR
    +0x050 DllPath          : _UNICODE_STRING
    +0x060 ImagePathName    : _UNICODE_STRING
    +0x070 CommandLine      : _UNICODE_STRING
    +0x080 Environment      : Ptr64 Void
    +0x088 StartingX        : Uint4B
    +0x08c StartingY        : Uint4B
    +0x090 CountX           : Uint4B
    +0x094 CountY           : Uint4B
    +0x098 CountCharsX      : Uint4B
    +0x09c CountCharsY      : Uint4B
    +0x0a0 FillAttribute    : Uint4B
    +0x0a4 WindowFlags      : Uint4B
    +0x0a8 ShowWindowFlags  : Uint4B
    +0x0b0 WindowTitle      : _UNICODE_STRING
    +0x0c0 DesktopInfo      : _UNICODE_STRING
    +0x0d0 ShellInfo        : _UNICODE_STRING
    +0x0e0 RuntimeData      : _UNICODE_STRING
    +0x0f0 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
    +0x3f0 EnvironmentSize  : Uint8B
    +0x3f8 EnvironmentVersion : Uint8B
    +0x400 PackageDependencyData : Ptr64 Void
    +0x408 ProcessGroupId   : Uint4B
    +0x40c LoaderThreads    : Uint4B
    +0x410 RedirectionDllName : _UNICODE_STRING
    +0x420 HeapPartitionName : _UNICODE_STRING
    +0x430 DefaultThreadpoolCpuSetMasks : Ptr64 Uint8B
    +0x438 DefaultThreadpoolCpuSetMaskCount : Uint4B
    +0x43c DefaultThreadpoolThreadMaximum : Uint4B
*/
typedef struct _RTL_USER_PROCESS_PARAMETERS {
    ULONG MaximumLength;
    ULONG Length;
    ULONG Flags;
    ULONG DebugFlags;
    HANDLE ConsoleHandle;
    ULONG  ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;        // ProcessParameters
    UNICODE_STRING DllPath;         // ProcessParameters
    UNICODE_STRING ImagePathName;   // ProcessParameters
    UNICODE_STRING CommandLine;     // ProcessParameters
    PVOID Environment;              // NtAllocateVirtualMemory
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;     // ProcessParameters
    UNICODE_STRING DesktopInfo;     // ProcessParameters
    UNICODE_STRING ShellInfo;       // ProcessParameters
    UNICODE_STRING RuntimeData;     // ProcessParameters
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[RTL_MAX_DRIVE_LETTERS];
    ULONGLONG EnvironmentSize;
    ULONGLONG EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
    UNICODE_STRING RedirectionDllName;
    UNICODE_STRING HeapPartitionName;
    PULONGLONG DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _SECTION_IMAGE_INFORMATION {
    PVOID TransferAddress;
    ULONG ZeroBits;
    SIZE_T MaximumStackSize;
    SIZE_T CommittedStackSize;
    ULONG SubSystemType;
    union {
        struct {
            USHORT SubSystemMinorVersion;
            USHORT SubSystemMajorVersion;
        };
        ULONG SubSystemVersion;
    };
    ULONG GpValue;
    USHORT ImageCharacteristics;
    USHORT DllCharacteristics;
    USHORT Machine;
    BOOLEAN ImageContainsCode;
    BOOLEAN Spare1;
    ULONG LoaderFlags;
    ULONG ImageFileSize;
    ULONG Reserved[1];
} SECTION_IMAGE_INFORMATION, * PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, * PRTL_USER_PROCESS_INFORMATION;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T       TotalLength;
    PS_ATTRIBUTE Attributes[4];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess, // in HANDLE
    PsAttributeDebugObject, // in HANDLE
    PsAttributeToken, // in HANDLE
    PsAttributeClientId, // out PCLIENT_ID
    PsAttributeTebAddress, // out PTEB *
    PsAttributeImageName, // in PWSTR
    PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass, // in UCHAR
    PsAttributeErrorMode, // in ULONG
    PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList, // in HANDLE[]
    PsAttributeGroupAffinity, // in PGROUP_AFFINITY
    PsAttributePreferredNode, // in PUSHORT
    PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
    PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList, // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in
    PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe, // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in WORD // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

#define PROCESS_CREATE_FLAGS_BREAKAWAY 0x00000001
#define PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT 0x00000002
#define PROCESS_CREATE_FLAGS_INHERIT_HANDLES 0x00000004
#define PROCESS_CREATE_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00000008
#define PROCESS_CREATE_FLAGS_LARGE_PAGES 0x00000010
#define PROCESS_CREATE_FLAGS_LARGE_PAGE_SYSTEM_DLL 0x00000020
#define PROCESS_CREATE_FLAGS_PROTECTED_PROCESS 0x00000040
#define PROCESS_CREATE_FLAGS_CREATE_SESSION 0x00000080
#define PROCESS_CREATE_FLAGS_INHERIT_FROM_PARENT 0x00000100
#define PROCESS_CREATE_FLAGS_SUSPENDED 0x00000200
#define PROCESS_CREATE_FLAGS_EXTENDED_UNKNOWN 0x00000400

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080

#define PS_ATTRIBUTE_NUMBER_MASK    0x0000ffff
#define PS_ATTRIBUTE_THREAD         0x00010000 // Attribute may be used with thread creation
#define PS_ATTRIBUTE_INPUT          0x00020000 // Attribute is input only
#define PS_ATTRIBUTE_ADDITIVE       0x00040000 // Attribute may be "accumulated", e.g. bitmasks, counters, etc.

#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_PARENT_PROCESS \
    PsAttributeValue(PsAttributeParentProcess, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_DEBUG_OBJECT \
    PsAttributeValue(PsAttributeDebugObject, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_TOKEN \
    PsAttributeValue(PsAttributeToken, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_CLIENT_ID \
    PsAttributeValue(PsAttributeClientId, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_TEB_ADDRESS \
    PsAttributeValue(PsAttributeTebAddress, TRUE, FALSE, FALSE)
#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IMAGE_INFO \
    PsAttributeValue(PsAttributeImageInfo, FALSE, FALSE, FALSE)
#define PS_ATTRIBUTE_MEMORY_RESERVE \
    PsAttributeValue(PsAttributeMemoryReserve, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PRIORITY_CLASS \
    PsAttributeValue(PsAttributePriorityClass, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ERROR_MODE \
    PsAttributeValue(PsAttributeErrorMode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_STD_HANDLE_INFO \
    PsAttributeValue(PsAttributeStdHandleInfo, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_HANDLE_LIST \
    PsAttributeValue(PsAttributeHandleList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_GROUP_AFFINITY \
    PsAttributeValue(PsAttributeGroupAffinity, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_PREFERRED_NODE \
    PsAttributeValue(PsAttributePreferredNode, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_IDEAL_PROCESSOR \
    PsAttributeValue(PsAttributeIdealProcessor, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_UMS_THREAD \
    PsAttributeValue(PsAttributeUmsThread, TRUE, TRUE, FALSE)
#define PS_ATTRIBUTE_MITIGATION_OPTIONS \
    PsAttributeValue(PsAttributeMitigationOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_PROTECTION_LEVEL \
    PsAttributeValue(PsAttributeProtectionLevel, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_SECURE_PROCESS \
    PsAttributeValue(PsAttributeSecureProcess, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_JOB_LIST \
    PsAttributeValue(PsAttributeJobList, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHILD_PROCESS_POLICY \
    PsAttributeValue(PsAttributeChildProcessPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY \
    PsAttributeValue(PsAttributeAllApplicationPackagesPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_WIN32K_FILTER \
    PsAttributeValue(PsAttributeWin32kFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_SAFE_OPEN_PROMPT_ORIGIN_CLAIM \
    PsAttributeValue(PsAttributeSafeOpenPromptOriginClaim, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_BNO_ISOLATION \
    PsAttributeValue(PsAttributeBnoIsolation, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_DESKTOP_APP_POLICY \
    PsAttributeValue(PsAttributeDesktopAppPolicy, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_CHPE \
    PsAttributeValue(PsAttributeChpe, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_MITIGATION_AUDIT_OPTIONS \
    PsAttributeValue(PsAttributeMitigationAuditOptions, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_MACHINE_TYPE \
    PsAttributeValue(PsAttributeMachineType, FALSE, TRUE, TRUE)
#define PS_ATTRIBUTE_COMPONENT_FILTER \
    PsAttributeValue(PsAttributeComponentFilter, FALSE, TRUE, FALSE)
#define PS_ATTRIBUTE_ENABLE_OPTIONAL_XSTATE_FEATURES \
    PsAttributeValue(PsAttributeEnableOptionalXStateFeatures, TRUE, TRUE, FALSE)

typedef enum _PS_STD_HANDLE_STATE {
    PsNeverDuplicate,
    PsRequestDuplicate, // duplicate standard handles specified by PseudoHandleMask, and only if StdHandleSubsystemType matches the image subsystem
    PsAlwaysDuplicate, // always duplicate standard handles
    PsMaxStdHandleStates
} PS_STD_HANDLE_STATE;

// begin_rev
#define PS_STD_INPUT_HANDLE 0x1
#define PS_STD_OUTPUT_HANDLE 0x2
#define PS_STD_ERROR_HANDLE 0x4
// end_rev

typedef struct _PS_STD_HANDLE_INFO {
    union {
        ULONG Flags;
        struct {
            ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
            ULONG PseudoHandleMask : 3; // PS_STD_*
        };
    };
    ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, * PPS_STD_HANDLE_INFO;

/*
 * PEB structure
*/

/*lkd> dt nt!_PEB
    +0x000 InheritedAddressSpace : UChar
    +0x001 ReadImageFileExecOptions : UChar
    +0x002 BeingDebugged    : UChar
    +0x003 BitField         : UChar
    +0x003 ImageUsesLargePages : Pos 0, 1 Bit
    +0x003 IsProtectedProcess : Pos 1, 1 Bit
    +0x003 IsImageDynamicallyRelocated : Pos 2, 1 Bit
    +0x003 SkipPatchingUser32Forwarders : Pos 3, 1 Bit
    +0x003 IsPackagedProcess : Pos 4, 1 Bit
    +0x003 IsAppContainer   : Pos 5, 1 Bit
    +0x003 IsProtectedProcessLight : Pos 6, 1 Bit
    +0x003 IsLongPathAwareProcess : Pos 7, 1 Bit
    +0x004 Padding0         : [4] UChar
    +0x008 Mutant           : Ptr64 Void
    +0x010 ImageBaseAddress : Ptr64 Void
    +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
    +0x020 ProcessParameters : Ptr64 _RTL_USER_PROCESS_PARAMETERS
    +0x028 SubSystemData    : Ptr64 Void
    +0x030 ProcessHeap      : Ptr64 Void
    +0x038 FastPebLock      : Ptr64 _RTL_CRITICAL_SECTION
    +0x040 AtlThunkSListPtr : Ptr64 _SLIST_HEADER
    +0x048 IFEOKey          : Ptr64 Void
    +0x050 CrossProcessFlags : Uint4B
    +0x050 ProcessInJob     : Pos 0, 1 Bit
    +0x050 ProcessInitializing : Pos 1, 1 Bit
    +0x050 ProcessUsingVEH  : Pos 2, 1 Bit
    +0x050 ProcessUsingVCH  : Pos 3, 1 Bit
    +0x050 ProcessUsingFTH  : Pos 4, 1 Bit
    +0x050 ProcessPreviouslyThrottled : Pos 5, 1 Bit
    +0x050 ProcessCurrentlyThrottled : Pos 6, 1 Bit
    +0x050 ProcessImagesHotPatched : Pos 7, 1 Bit
    +0x050 ReservedBits0    : Pos 8, 24 Bits
    +0x054 Padding1         : [4] UChar
    +0x058 KernelCallbackTable : Ptr64 Void
    +0x058 UserSharedInfoPtr : Ptr64 Void
    +0x060 SystemReserved   : Uint4B
    +0x064 AtlThunkSListPtr32 : Uint4B
    +0x068 ApiSetMap        : Ptr64 Void
    +0x070 TlsExpansionCounter : Uint4B
    +0x074 Padding2         : [4] UChar
    +0x078 TlsBitmap        : Ptr64 Void
    +0x080 TlsBitmapBits    : [2] Uint4B
    +0x088 ReadOnlySharedMemoryBase : Ptr64 Void
    +0x090 SharedData       : Ptr64 Void
    +0x098 ReadOnlyStaticServerData : Ptr64 Ptr64 Void
    +0x0a0 AnsiCodePageData : Ptr64 Void
    +0x0a8 OemCodePageData  : Ptr64 Void
    +0x0b0 UnicodeCaseTableData : Ptr64 Void
    +0x0b8 NumberOfProcessors : Uint4B
    +0x0bc NtGlobalFlag     : Uint4B
    +0x0c0 CriticalSectionTimeout : _LARGE_INTEGER
    +0x0c8 HeapSegmentReserve : Uint8B
    +0x0d0 HeapSegmentCommit : Uint8B
    +0x0d8 HeapDeCommitTotalFreeThreshold : Uint8B
    +0x0e0 HeapDeCommitFreeBlockThreshold : Uint8B
    +0x0e8 NumberOfHeaps    : Uint4B
    +0x0ec MaximumNumberOfHeaps : Uint4B
    +0x0f0 ProcessHeaps     : Ptr64 Ptr64 Void
    +0x0f8 GdiSharedHandleTable : Ptr64 Void
    +0x100 ProcessStarterHelper : Ptr64 Void
    +0x108 GdiDCAttributeList : Uint4B
    +0x10c Padding3         : [4] UChar
    +0x110 LoaderLock       : Ptr64 _RTL_CRITICAL_SECTION
    +0x118 OSMajorVersion   : Uint4B
    +0x11c OSMinorVersion   : Uint4B
    +0x120 OSBuildNumber    : Uint2B
    +0x122 OSCSDVersion     : Uint2B
    +0x124 OSPlatformId     : Uint4B
    +0x128 ImageSubsystem   : Uint4B
    +0x12c ImageSubsystemMajorVersion : Uint4B
    +0x130 ImageSubsystemMinorVersion : Uint4B
    +0x134 Padding4         : [4] UChar
    +0x138 ActiveProcessAffinityMask : Uint8B
    +0x140 GdiHandleBuffer  : [60] Uint4B
    +0x230 PostProcessInitRoutine : Ptr64     void
    +0x238 TlsExpansionBitmap : Ptr64 Void
    +0x240 TlsExpansionBitmapBits : [32] Uint4B
    +0x2c0 SessionId        : Uint4B
    +0x2c4 Padding5         : [4] UChar
    +0x2c8 AppCompatFlags   : _ULARGE_INTEGER
    +0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER
    +0x2d8 pShimData        : Ptr64 Void
    +0x2e0 AppCompatInfo    : Ptr64 Void
    +0x2e8 CSDVersion       : _UNICODE_STRING
    +0x2f8 ActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
    +0x300 ProcessAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
    +0x308 SystemDefaultActivationContextData : Ptr64 _ACTIVATION_CONTEXT_DATA
    +0x310 SystemAssemblyStorageMap : Ptr64 _ASSEMBLY_STORAGE_MAP
    +0x318 MinimumStackCommit : Uint8B
    +0x320 SparePointers    : [4] Ptr64 Void
    +0x340 SpareUlongs      : [5] Uint4B
    +0x358 WerRegistrationData : Ptr64 Void
    +0x360 WerShipAssertPtr : Ptr64 Void
    +0x368 pUnused          : Ptr64 Void
    +0x370 pImageHeaderHash : Ptr64 Void
    +0x378 TracingFlags     : Uint4B
    +0x378 HeapTracingEnabled : Pos 0, 1 Bit
    +0x378 CritSecTracingEnabled : Pos 1, 1 Bit
    +0x378 LibLoaderTracingEnabled : Pos 2, 1 Bit
    +0x378 SpareTracingBits : Pos 3, 29 Bits
    +0x37c Padding6         : [4] UChar
    +0x380 CsrServerReadOnlySharedMemoryBase : Uint8B
    +0x388 TppWorkerpListLock : Uint8B
    +0x390 TppWorkerpList   : _LIST_ENTRY
    +0x3a0 WaitOnAddressHashTable : [128] Ptr64 Void
    +0x7a0 TelemetryCoverageHeader : Ptr64 Void
    +0x7a8 CloudFileFlags   : Uint4B
    +0x7ac CloudFileDiagFlags : Uint4B
    +0x7b0 PlaceholderCompatibilityMode : Char
    +0x7b1 PlaceholderCompatibilityModeReserved : [7] Char
    +0x7b8 LeapSecondData   : Ptr64 _LEAP_SECOND_DATA
    +0x7c0 LeapSecondFlags  : Uint4B
    +0x7c0 SixtySecondEnabled : Pos 0, 1 Bit
    +0x7c0 Reserved         : Pos 1, 31 Bits
    +0x7c4 NtGlobalFlag2    : Uint4B
*/

typedef ULONG GDI_HANDLE_BUFFER[60];

typedef VOID(*PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _LEAP_SECOND_DATA {
    UCHAR Enabled;
    ULONG Count;
    LARGE_INTEGER Data;
} LEAP_SECOND_DATA, * PLEAP_SECOND_DATA;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    union {
        UCHAR BitField;
        struct {
            UCHAR ImageUsesLargePages : 1;
            UCHAR IsProtectedProcess : 1;
            UCHAR IsImageDynamicallyRelocated : 1;
            UCHAR SkipPatchingUser32Forwarders : 1;
            UCHAR IsPackagedProcess : 1;
            UCHAR IsAppContainer : 1;
            UCHAR IsProtectedProcessLight : 1;
            UCHAR IsLongPathAwareProcess : 1;
        };
    };
    UCHAR Padding0[4];
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    _RTL_CRITICAL_SECTION* FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union {
        ULONG CrossProcessFlags;
        struct {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1;
            ULONG ReservedBits0 : 24;
        };
    };
    UCHAR Padding1[4];
    PVOID KernelCallbackTable;
    PVOID UserSharedInfoPtr;
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    UCHAR Padding2[4];
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData;
    PPVOID ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PPVOID ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    UCHAR Padding3[4];
    _RTL_CRITICAL_SECTION* LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    UCHAR Padding4[4];
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    UCHAR Padding5[4];
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;

    /*const _ACTIVATION_CONTEXT_DATA * ActivationContextData;
    _ASSEMBLY_STORAGE_MAP * ProcessAssemblyStorageMap;
    const _ACTIVATION_CONTEXT_DATA * SystemDefaultActivationContextData;
    _ASSEMBLY_STORAGE_MAP * SystemAssemblyStorageMap;*/

    SIZE_T MinimumStackCommit;
    PVOID SparePointers[4];
    ULONG SpareUlongs[5];
    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused;
    PVOID pImageHeaderHash;
    union {
        ULONG TracingFlags;
        struct {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    UCHAR Padding6[4];
    ULONG_PTR CsrServerReadOnlySharedMemoryBase;
    ULONG_PTR TppWorkerpListLock;
    LIST_ENTRY TppWorkerList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader;
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags;
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    LEAP_SECOND_DATA* LeapSecondData;
    union {
        ULONG LeapSecondFlags;
        struct {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
} PEB, * PPEB;

/*
 * TEB structure
*/
/*
typedef struct _PROCESSOR_NUMBER {
    USHORT Group;
    UCHAR Number;
    UCHAR Reserved;
} PROCESSOR_NUMBER, * PPROCESSOR_NUMBER;
*/
/*
lkd> dt nt!_TEB
    +0x000 NtTib            : _NT_TIB
    +0x038 EnvironmentPointer : Ptr64 Void
    +0x040 ClientId         : _CLIENT_ID
    +0x050 ActiveRpcHandle  : Ptr64 Void
    +0x058 ThreadLocalStoragePointer : Ptr64 Void
    +0x060 ProcessEnvironmentBlock : Ptr64 _PEB
    +0x068 LastErrorValue   : Uint4B
    +0x06c CountOfOwnedCriticalSections : Uint4B
    +0x070 CsrClientThread  : Ptr64 Void
    +0x078 Win32ThreadInfo  : Ptr64 Void
    +0x080 User32Reserved   : [26] Uint4B
    +0x0e8 UserReserved     : [5] Uint4B
    +0x100 WOW32Reserved    : Ptr64 Void
    +0x108 CurrentLocale    : Uint4B
    +0x10c FpSoftwareStatusRegister : Uint4B
    +0x110 ReservedForDebuggerInstrumentation : [16] Ptr64 Void
    +0x190 SystemReserved1  : [30] Ptr64 Void
    +0x280 PlaceholderCompatibilityMode : Char
    +0x281 PlaceholderHydrationAlwaysExplicit : UChar
    +0x282 PlaceholderReserved : [10] Char
    +0x28c ProxiedProcessId : Uint4B
    +0x290 _ActivationStack : _ACTIVATION_CONTEXT_STACK
    +0x2b8 WorkingOnBehalfTicket : [8] UChar
    +0x2c0 ExceptionCode    : Int4B
    +0x2c4 Padding0         : [4] UChar
    +0x2c8 ActivationContextStackPointer : Ptr64 _ACTIVATION_CONTEXT_STACK
    +0x2d0 InstrumentationCallbackSp : Uint8B
    +0x2d8 InstrumentationCallbackPreviousPc : Uint8B
    +0x2e0 InstrumentationCallbackPreviousSp : Uint8B
    +0x2e8 TxFsContext      : Uint4B
    +0x2ec InstrumentationCallbackDisabled : UChar
    +0x2ed UnalignedLoadStoreExceptions : UChar
    +0x2ee Padding1         : [2] UChar
    +0x2f0 GdiTebBatch      : _GDI_TEB_BATCH
    +0x7d8 RealClientId     : _CLIENT_ID
    +0x7e8 GdiCachedProcessHandle : Ptr64 Void
    +0x7f0 GdiClientPID     : Uint4B
    +0x7f4 GdiClientTID     : Uint4B
    +0x7f8 GdiThreadLocalInfo : Ptr64 Void
    +0x800 Win32ClientInfo  : [62] Uint8B
    +0x9f0 glDispatchTable  : [233] Ptr64 Void
    +0x1138 glReserved1      : [29] Uint8B
    +0x1220 glReserved2      : Ptr64 Void
    +0x1228 glSectionInfo    : Ptr64 Void
    +0x1230 glSection        : Ptr64 Void
    +0x1238 glTable          : Ptr64 Void
    +0x1240 glCurrentRC      : Ptr64 Void
    +0x1248 glContext        : Ptr64 Void
    +0x1250 LastStatusValue  : Uint4B
    +0x1254 Padding2         : [4] UChar
    +0x1258 StaticUnicodeString : _UNICODE_STRING
    +0x1268 StaticUnicodeBuffer : [261] Wchar
    +0x1472 Padding3         : [6] UChar
    +0x1478 DeallocationStack : Ptr64 Void
    +0x1480 TlsSlots         : [64] Ptr64 Void
    +0x1680 TlsLinks         : _LIST_ENTRY
    +0x1690 Vdm              : Ptr64 Void
    +0x1698 ReservedForNtRpc : Ptr64 Void
    +0x16a0 DbgSsReserved    : [2] Ptr64 Void
    +0x16b0 HardErrorMode    : Uint4B
    +0x16b4 Padding4         : [4] UChar
    +0x16b8 Instrumentation  : [11] Ptr64 Void
    +0x1710 ActivityId       : _GUID
    +0x1720 SubProcessTag    : Ptr64 Void
    +0x1728 PerflibData      : Ptr64 Void
    +0x1730 EtwTraceData     : Ptr64 Void
    +0x1738 WinSockData      : Ptr64 Void
    +0x1740 GdiBatchCount    : Uint4B
    +0x1744 CurrentIdealProcessor : _PROCESSOR_NUMBER
    +0x1744 IdealProcessorValue : Uint4B
    +0x1744 ReservedPad0     : UChar
    +0x1745 ReservedPad1     : UChar
    +0x1746 ReservedPad2     : UChar
    +0x1747 IdealProcessor   : UChar
    +0x1748 GuaranteedStackBytes : Uint4B
    +0x174c Padding5         : [4] UChar
    +0x1750 ReservedForPerf  : Ptr64 Void
    +0x1758 ReservedForOle   : Ptr64 Void
    +0x1760 WaitingOnLoaderLock : Uint4B
    +0x1764 Padding6         : [4] UChar
    +0x1768 SavedPriorityState : Ptr64 Void
    +0x1770 ReservedForCodeCoverage : Uint8B
    +0x1778 ThreadPoolData   : Ptr64 Void
    +0x1780 TlsExpansionSlots : Ptr64 Ptr64 Void
    +0x1788 DeallocationBStore : Ptr64 Void
    +0x1790 BStoreLimit      : Ptr64 Void
    +0x1798 MuiGeneration    : Uint4B
    +0x179c IsImpersonating  : Uint4B
    +0x17a0 NlsCache         : Ptr64 Void
    +0x17a8 pShimData        : Ptr64 Void
    +0x17b0 HeapData         : Uint4B
    +0x17b4 Padding7         : [4] UChar
    +0x17b8 CurrentTransactionHandle : Ptr64 Void
    +0x17c0 ActiveFrame      : Ptr64 _TEB_ACTIVE_FRAME
    +0x17c8 FlsData          : Ptr64 Void
    +0x17d0 PreferredLanguages : Ptr64 Void
    +0x17d8 UserPrefLanguages : Ptr64 Void
    +0x17e0 MergedPrefLanguages : Ptr64 Void
    +0x17e8 MuiImpersonation : Uint4B
    +0x17ec CrossTebFlags    : Uint2B
    +0x17ec SpareCrossTebBits : Pos 0, 16 Bits
    +0x17ee SameTebFlags     : Uint2B
    +0x17ee SafeThunkCall    : Pos 0, 1 Bit
    +0x17ee InDebugPrint     : Pos 1, 1 Bit
    +0x17ee HasFiberData     : Pos 2, 1 Bit
    +0x17ee SkipThreadAttach : Pos 3, 1 Bit
    +0x17ee WerInShipAssertCode : Pos 4, 1 Bit
    +0x17ee RanProcessInit   : Pos 5, 1 Bit
    +0x17ee ClonedThread     : Pos 6, 1 Bit
    +0x17ee SuppressDebugMsg : Pos 7, 1 Bit
    +0x17ee DisableUserStackWalk : Pos 8, 1 Bit
    +0x17ee RtlExceptionAttached : Pos 9, 1 Bit
    +0x17ee InitialThread    : Pos 10, 1 Bit
    +0x17ee SessionAware     : Pos 11, 1 Bit
    +0x17ee LoadOwner        : Pos 12, 1 Bit
    +0x17ee LoaderWorker     : Pos 13, 1 Bit
    +0x17ee SkipLoaderInit   : Pos 14, 1 Bit
    +0x17ee SpareSameTebBits : Pos 15, 1 Bit
    +0x17f0 TxnScopeEnterCallback : Ptr64 Void
    +0x17f8 TxnScopeExitCallback : Ptr64 Void
    +0x1800 TxnScopeContext  : Ptr64 Void
    +0x1808 LockCount        : Uint4B
    +0x180c WowTebOffset     : Int4B
    +0x1810 ResourceRetValue : Ptr64 Void
    +0x1818 ReservedForWdf   : Ptr64 Void
    +0x1820 ReservedForCrt   : Uint8B
    +0x1828 EffectiveContainerId : _GUID
*/

typedef struct _TEB {
    NT_TIB NtTib;
    PVOID EnvironmentPointer;
    CLIENT_ID ClientId;
    PVOID ActiveRpcHandle;
    PVOID ThreadLocalStoragePointer;
    PPEB ProcessEnvironmentBlock;
    ULONG LastErrorValue;
    ULONG CountOfOwnedCriticalSections;
    PVOID CsrClientThread;
    PVOID Win32ThreadInfo;
    ULONG User32Reserved[26];
    ULONG UserReserved[5];
    PVOID WOW32Reserved;
    ULONG CurrentLocale;
    ULONG FpSoftwareStatusRegister;
    PVOID ReservedForDebuggerInstrumentation[16];
    PVOID SystemReserved1[30];
    CHAR PlaceholderCompatibilityMode;
    UCHAR PlaceholderHydrationAlwaysExplicit;
    CHAR PlaceholderReserved[10];
    ULONG ProxiedProcessId;
    ACTIVATION_CONTEXT_STACK _ActivationStack;
    UCHAR WorkingOnBehalfTicket[8];
    ULONG ExceptionCode;
    UCHAR Padding0[4];
    PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
    SIZE_T InstrumentationCallbackSp;
    SIZE_T InstrumentationCallbackPreviousPc;
    SIZE_T InstrumentationCallbackPreviousSp;
    ULONG TxFsContext;
    UCHAR InstrumentationCallbackDisabled;
    UCHAR UnalignedLoadStoreExceptions;
    UCHAR Padding1[2];
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    PVOID GdiCachedProcessHandle;
    ULONG GdiClientPID;
    ULONG GdiClientTID;
    PVOID GdiThreadLocalInfo;
    SIZE_T Win32ClientInfo[62];
    PVOID glDispatchTable[233];
    SIZE_T glReserved1[29];
    PVOID glReserved2;
    PVOID glSectionInfo;
    PVOID glSection;
    PVOID glTable;
    PVOID glCurrentRC;
    PVOID glContext;
    ULONG LastStatusValue;
    UCHAR Padding2[4];
    UNICODE_STRING StaticUnicodeString;
    WCHAR StaticUnicodeBuffer[261];
    UCHAR Padding3[6];
    PVOID DeallocationStack;
    PVOID TlsSlots[64];
    LIST_ENTRY TlsLinks;
    PVOID Vdm;
    PVOID ReservedForNtRpc;
    PVOID DbgSsReserved[2];
    ULONG HardErrorMode;
    UCHAR Padding4[4];
    PVOID Instrumentation[11];
    GUID ActivityId;
    PVOID SubProcessTag;
    PVOID PerflibData;
    PVOID EtwTraceData;
    PVOID WinSockData;
    ULONG GdiBatchCount;
    PROCESSOR_NUMBER CurrentIdealProcessor;
    ULONG IdealProcessorValue;
    UCHAR ReservedPad0;
    UCHAR ReservedPad1;
    UCHAR ReservedPad2;
    UCHAR IdealProcessor;
    ULONG GuaranteedStackBytes;
    UCHAR Padding5[4];
    PVOID ReservedForPerf;
    PVOID ReservedForOle;
    ULONG WaitingOnLoaderLock;
    ULONG Padding6[4];
    PVOID SavedPriorityState;
    SIZE_T ReservedForCodeCoverage;
    PVOID ThreadPoolData;
    PPVOID TlsExpansionSlots;
    PVOID DeallocationBStore;
    PVOID BStoreLimit;
    ULONG MuiGeneration;
    ULONG IsImpersonating;
    PVOID NlsCache;
    PVOID pShimData;
    ULONG HeapData;
    UCHAR Padding7[4];
    PVOID CurrentTransactionHandle;
    TEB_ACTIVE_FRAME ActiveFrame;
    PVOID FlsData;
    PVOID PreferredLanguages;
    PVOID UserPrefLanguages;
    PVOID MergedPrefLanguages;
    ULONG MuiImpersonation;
    union {
        USHORT CrossTebFlags;
        struct {
            USHORT SpareCrossTebBits : 16;
        };
    };
    union {
        USHORT SameTebFlags;
        struct {
            USHORT SafeThunkCall : 1;
            USHORT InDebugPrint : 1;
            USHORT HasFiberData : 1;
            USHORT SkipThreadAttach : 1;
            USHORT WerInShipAssertCode : 1;
            USHORT RanProcessInit : 1;
            USHORT ClonedThread : 1;
            USHORT SuppressDebugMsg : 1;
            USHORT DisableUserStackWalk : 1;
            USHORT RtlExceptionAttached : 1;
            USHORT InitialThread : 1;
            USHORT SessionAware : 1;
            USHORT LoadOwner : 1;
            USHORT LoaderWorker : 1;
            USHORT SkipLoaderInit : 1;
            USHORT SpareSameTebBits : 1;
        };
    };
    PVOID TxnScopeEnterCallback;
    PVOID TxnScopeExitCallback;
    PVOID TxnScopeContext;
    ULONG LockCount;
    LONG WowTebOffset;
    PVOID ResourceRetValue;
    PVOID ReservedForWdf;
    SIZE_T ReservedForCrt;
    GUID EffectiveContainerId;
} TEB, * PTEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
typedef PROCESS_BASIC_INFORMATION* PPROCESS_BASIC_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

/*
 * Pipe Flags
*/
#define FILE_PIPE_BYTE_STREAM_TYPE              0x00000000
#define FILE_PIPE_MESSAGE_TYPE                  0x00000001
#define FILE_PIPE_BYTE_STREAM_MODE              0x00000000
#define FILE_PIPE_MESSAGE_MODE                  0x00000001
#define FILE_PIPE_QUEUE_OPERATION               0x00000000
#define FILE_PIPE_COMPLETE_OPERATION            0x00000001
#define FILE_PIPE_INBOUND                       0x00000000
#define FILE_PIPE_OUTBOUND                      0x00000001
#define FILE_PIPE_FULL_DUPLEX                   0x00000002
#define FILE_PIPE_CLIENT_END                    0x00000000
#define FILE_PIPE_SERVER_END                    0x00000001

/*
 * CSR
*/
#define CSR_MAKE_API_NUMBER( DllIndex, ApiIndex ) \
    (CSR_API_NUMBER)(((DllIndex) << 16) | (ApiIndex))

#define CSRSRV_SERVERDLL_INDEX          0
#define CSRSRV_FIRST_API_NUMBER         0

#define BASESRV_SERVERDLL_INDEX         1
#define BASESRV_FIRST_API_NUMBER        0

#define CONSRV_SERVERDLL_INDEX          2
#define CONSRV_FIRST_API_NUMBER         512

#define USERSRV_SERVERDLL_INDEX         3
#define USERSRV_FIRST_API_NUMBER        1024

typedef enum _BASESRV_API_NUMBER
{
    BasepCreateProcess = BASESRV_FIRST_API_NUMBER,
    BasepCreateThread,
    BasepGetTempFile,
    BasepExitProcess,
    BasepDebugProcess,
    BasepCheckVDM,
    BasepUpdateVDMEntry,
    BasepGetNextVDMCommand,
    BasepExitVDM,
    BasepIsFirstVDM,
    BasepGetVDMExitCode,
    BasepSetReenterCount,
    BasepSetProcessShutdownParam,
    BasepGetProcessShutdownParam,
    BasepNlsSetUserInfo,
    BasepNlsSetMultipleUserInfo,
    BasepNlsCreateSection,
    BasepSetVDMCurDirs,
    BasepGetVDMCurDirs,
    BasepBatNotification,
    BasepRegisterWowExec,
    BasepSoundSentryNotification,
    BasepRefreshIniFileMapping,
    BasepDefineDosDevice,
    BasepSetTermsrvAppInstallMode,
    BasepNlsUpdateCacheCount,
    BasepSetTermsrvClientTimeZone,
    BasepSxsCreateActivationContext,
    BasepDebugProcessStop,
    BasepRegisterThread,
    BasepNlsGetUserInfo,
} BASESRV_API_NUMBER, * PBASESRV_API_NUMBER;

typedef struct
{
    BYTE byte0;						// +00
    BYTE byte1;						// +01
    BYTE byte2;						// +02
    BYTE byte3;						// +02
    ULONG64 DUMMY;					// +08
    ULONG_PTR ManifestAddress;		// +10
    ULONG64 ManifestSize;			// +18
    HANDLE SectionHandle;			// +20
    ULONG64 Offset;					// +28
    ULONG_PTR Size;					// +30
} BASE_SXS_STREAM;					// 0x38

typedef struct
{
    ULONG Flags;					// +00      // direct set, value = 0x40
    ULONG ProcessParameterFlags;	// +04      // direct set, value = 0x4001
    HANDLE FileHandle;				// +08      // we can get this value
    UNICODE_STRING SxsWin32ExePath;	// +10      // UNICODE_STRING, we can build!
    UNICODE_STRING SxsNtExePath;	// +20      // UNICODE_STRING, we can build!
    BYTE    Field30[0x10];          // +30      // blank, ignore
    BASE_SXS_STREAM PolicyStream;	// +40      // !!!
    UNICODE_STRING AssemblyName;	// +78      // blank, ignore
    UNICODE_STRING FileName3;		// +88      // UNICODE_STRING, we can build!
    BYTE    Field98[0x10];			// +98      // blank, ignore
    UNICODE_STRING FileName4;		// +a8      // UNICODE_STRING, we can build!
    BYTE OtherFileds[0x110];		// +b8		// blank, ignore
} BASE_SXS_CREATEPROCESS_MSG;		// 0x1C8

typedef struct {
    HANDLE ProcessHandle;			// +00      // can get
    HANDLE ThreadHandle;			// +08      // can get
    CLIENT_ID ClientId;				// +10      // can get, PID, TID
    ULONG CreationFlags;			// +20      // direct set, must be zero
    ULONG VdmBinaryType;			// +24      // direct set, must be zero
    ULONG VdmTask;					// +28      // ignore
    //ULONG_PTR VdmTask;					// modified value
    HANDLE hVDM;					// +30      // ignore
    BASE_SXS_CREATEPROCESS_MSG Sxs;	// +38      // deep, need analyze, (for BASE_API_MSG, start with 0x78)
    ULONG64 PebAddressNative;       // +200     // can get
    ULONG_PTR PebAddressWow64;		// +208     // direct set, must be zero (Win64 limit)
    USHORT ProcessorArchitecture;	// +210     // direct set, must be 9 (AMD64 limit)
} BASE_CREATEPROCESS_MSG;

////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef CSHORT
#define CSHORT short
#endif

typedef struct _CSR_CAPTURE_HEADER {
    ULONG Length;
    PVOID RelatedCaptureBuffer;         // real: PCSR_CAPTURE_HEADER
    ULONG CountMessagePointers;
    PCHAR FreeSpace;
    ULONG_PTR MessagePointerOffsets[1]; // Offsets within CSR_API_MSG of pointers
} CSR_CAPTURE_HEADER, * PCSR_CAPTURE_HEADER;

typedef ULONG CSR_API_NUMBER;

////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _PORT_MESSAGE_HEADER
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
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union
    {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE_HEADER, * PPORT_MESSAGE_HEADER;

typedef struct _CSR_PORT_MESSAGE {
    PORT_MESSAGE_HEADER Header;                 // 0x00
    PCSR_CAPTURE_HEADER CaptureBuffer;			// 0x28 
    CSR_API_NUMBER ApiNumber;					// 0x30 
    ULONG ReturnValue;							// 0x34 
    ULONG64 Reserved;							// 0x38
} CSR_PORT_MESSAGE, * PCSR_PORT_MESSAGE;

typedef struct {
    CSR_PORT_MESSAGE PortHeader;
    BASE_CREATEPROCESS_MSG CreateProcessMSG;		// 0x40
} BASE_API_MSG, * PBASE_API_MSG;

typedef struct _CSR_CAPTURE_BUFFER
{
    ULONG Size;
    struct _CSR_CAPTURE_BUFFER* PreviousCaptureBuffer;
    ULONG PointerCount;
    PVOID BufferEnd;
    ULONG_PTR PointerOffsetsArray[ANYSIZE_ARRAY];
} CSR_CAPTURE_BUFFER, * PCSR_CAPTURE_BUFFER;


/*
* File
*/

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef NTSTATUS(*PUSER_THREAD_START_ROUTINE)(
    PVOID ThreadParameter);

/*
* Keys
*/

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

/*
 * pSnapshot replacement
*/

typedef struct _VM_COUNTERS {
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
} VM_COUNTERS, * PVM_COUNTERS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG PageDirectoryBase;
    VM_COUNTERS VirtualMemoryCounters;
    SIZE_T PrivatePageCount;
    IO_COUNTERS IoCounters;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


#define STATUS_UNSUCCESSFUL 0xc0000001
#define EVENT_QUERY_STATE 0x0001
#define ALPC_MSGFLG_SYNC_REQUEST 0x20000

extern "C" NTSTATUS SysNtAccessCheck(
    IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiaredAccess,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
    IN OUT PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PBOOLEAN AccessStatus);

extern "C" NTSTATUS SysNtWorkerFactoryWorkerReady(
    IN HANDLE WorkerFactoryHandle);

extern "C" NTSTATUS SysNtAcceptConnectPort(
    OUT PHANDLE ServerPortHandle,
    IN ULONG AlternativeReceivePortHandle OPTIONAL,
    IN PPORT_MESSAGE ConnectionReply,
    IN BOOLEAN AcceptConnection,
    IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
    OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL);

extern "C" NTSTATUS SysNtMapUserPhysicalPagesScatter(
    IN PVOID VirtualAddresses,
    IN PULONG NumberOfPages,
    IN PULONG UserPfnArray OPTIONAL);

extern "C" NTSTATUS SysNtWaitForSingleObject(
    IN HANDLE ObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER TimeOut OPTIONAL);

extern "C" NTSTATUS SysNtCallbackReturn(
    IN PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputLength,
    IN NTSTATUS Status);

extern "C" NTSTATUS SysNtReadFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    OUT PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL);

extern "C" NTSTATUS SysNtDeviceIoControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG IoControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength);

extern "C" NTSTATUS SysNtWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL);

extern "C" NTSTATUS SysNtRemoveIoCompletion(
    IN HANDLE IoCompletionHandle,
    OUT PULONG KeyContext,
    OUT PULONG ApcContext,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtReleaseSemaphore(
    IN HANDLE SemaphoreHandle,
    IN LONG ReleaseCount,
    OUT PLONG PreviousCount OPTIONAL);

extern "C" NTSTATUS SysNtReplyWaitReceivePort(
    IN HANDLE PortHandle,
    OUT PVOID PortContext OPTIONAL,
    IN PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage);

extern "C" NTSTATUS SysNtReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE ReplyMessage);

extern "C" NTSTATUS SysNtSetInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength);

extern "C" NTSTATUS SysNtSetEvent(
    IN HANDLE EventHandle,
    OUT PULONG PreviousState OPTIONAL);

extern "C" NTSTATUS SysNtClose(
    IN HANDLE Handle);

extern "C" NTSTATUS SysNtQueryObject(
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation OPTIONAL,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

extern "C" NTSTATUS SysNtOpenKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtEnumerateValueKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation OPTIONAL,
    IN ULONG Length,
    OUT PULONG ResultLength);

extern "C" NTSTATUS SysNtFindAtom(
    IN PWSTR AtomName OPTIONAL,
    IN ULONG Length,
    OUT PUSHORT Atom OPTIONAL);

extern "C" NTSTATUS SysNtQueryDefaultLocale(
    IN BOOLEAN UserProfile,
    OUT PLCID DefaultLocaleId);

extern "C" NTSTATUS SysNtQueryKey(
    IN HANDLE KeyHandle,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation OPTIONAL,
    IN ULONG Length,
    OUT PULONG ResultLength);

extern "C" NTSTATUS SysNtQueryValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    OUT PVOID KeyValueInformation OPTIONAL,
    IN ULONG Length,
    OUT PULONG ResultLength);

extern "C" NTSTATUS SysNtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect);

extern "C" NTSTATUS SysNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtWaitForMultipleObjects32(
    IN ULONG ObjectCount,
    IN PHANDLE Handles,
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtWriteFileGather(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset,
    IN PULONG Key OPTIONAL);

extern "C" NTSTATUS SysNtCreateKey(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class OPTIONAL,
    IN ULONG CreateOptions,
    OUT PULONG Disposition OPTIONAL);

extern "C" NTSTATUS SysNtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType);

extern "C" NTSTATUS SysNtImpersonateClientOfPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message);

extern "C" NTSTATUS SysNtReleaseMutant(
    IN HANDLE MutantHandle,
    OUT PULONG PreviousCount OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationToken(
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    OUT PVOID TokenInformation,
    IN ULONG TokenInformationLength,
    OUT PULONG ReturnLength);

extern "C" NTSTATUS SysNtRequestWaitReplyPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage,
    OUT PPORT_MESSAGE ReplyMessage);

extern "C" NTSTATUS SysNtQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtOpenThreadToken(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    OUT PHANDLE TokenHandle);

extern "C" NTSTATUS SysNtQueryInformationThread(
    IN HANDLE ThreadHandle,
    IN THREADINFOCLASS ThreadInformationClass,
    OUT PVOID ThreadInformation,
    IN ULONG ThreadInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtOpenProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

extern "C" NTSTATUS SysNtSetInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

extern "C" NTSTATUS SysNtMapViewOfSection(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
    IN OUT PSIZE_T ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Win32Protect);

extern "C" NTSTATUS SysNtAccessCheckAndAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN ACCESS_MASK DesiredAccess,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PBOOLEAN AccessStatus,
    OUT PBOOLEAN GenerateOnClose);

extern "C" NTSTATUS SysNtUnmapViewOfSection(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress);

extern "C" NTSTATUS SysNtReplyWaitReceivePortEx(
    IN HANDLE PortHandle,
    OUT PULONG PortContext OPTIONAL,
    IN PPORT_MESSAGE ReplyMessage OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtTerminateProcess(
    IN HANDLE ProcessHandle OPTIONAL,
    IN NTSTATUS ExitStatus);

extern "C" NTSTATUS SysNtSetEventBoostPriority(
    IN HANDLE EventHandle);

extern "C" NTSTATUS SysNtReadFileScatter(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_SEGMENT_ELEMENT SegmentArray,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL);

extern "C" NTSTATUS SysNtOpenThreadTokenEx(
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN BOOLEAN OpenAsSelf,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle);

extern "C" NTSTATUS SysNtOpenProcessTokenEx(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    OUT PHANDLE TokenHandle);

extern "C" NTSTATUS SysNtQueryPerformanceCounter(
    OUT PLARGE_INTEGER PerformanceCounter,
    OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL);

extern "C" NTSTATUS SysNtEnumerateKey(
    IN HANDLE KeyHandle,
    IN ULONG Index,
    IN KEY_INFORMATION_CLASS KeyInformationClass,
    OUT PVOID KeyInformation OPTIONAL,
    IN ULONG Length,
    OUT PULONG ResultLength);

extern "C" NTSTATUS SysNtOpenFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions);

extern "C" NTSTATUS SysNtDelayExecution(
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER DelayInterval);

extern "C" NTSTATUS SysNtQueryDirectoryFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan);

extern "C" NTSTATUS SysNtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtOpenSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtQueryTimer(
    IN HANDLE TimerHandle,
    IN TIMER_INFORMATION_CLASS TimerInformationClass,
    OUT PVOID TimerInformation,
    IN ULONG TimerInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtFsControlFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG FsControlCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength);

extern "C" NTSTATUS SysNtWriteVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T NumberOfBytesToWrite,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL);

extern "C" NTSTATUS SysNtCloseObjectAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN BOOLEAN GenerateOnClose);

extern "C" NTSTATUS SysNtDuplicateObject(
    IN HANDLE SourceProcessHandle,
    IN HANDLE SourceHandle,
    IN HANDLE TargetProcessHandle OPTIONAL,
    OUT PHANDLE TargetHandle OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Options);

extern "C" NTSTATUS SysNtQueryAttributesFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_BASIC_INFORMATION FileInformation);

extern "C" NTSTATUS SysNtClearEvent(
    IN HANDLE EventHandle);

extern "C" NTSTATUS SysNtReadVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    OUT PVOID Buffer,
    IN SIZE_T BufferSize,
    OUT PSIZE_T NumberOfBytesRead OPTIONAL);

extern "C" NTSTATUS SysNtOpenEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtAdjustPrivilegesToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN DisableAllPrivileges,
    IN PTOKEN_PRIVILEGES NewState OPTIONAL,
    IN ULONG BufferLength,
    OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtDuplicateToken(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle);

extern "C" NTSTATUS SysNtContinue(
    IN PCONTEXT ContextRecord,
    IN BOOLEAN TestAlert);

extern "C" NTSTATUS SysNtQueryDefaultUILanguage(
    OUT PLANGID DefaultUILanguageId);

extern "C" NTSTATUS SysNtQueueApcThread(
    IN HANDLE ThreadHandle,
    IN PKNORMAL_ROUTINE ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL);

extern "C" NTSTATUS SysNtYieldExecution();

extern "C" NTSTATUS SysNtAddAtom(
    IN PWSTR AtomName OPTIONAL,
    IN ULONG Length,
    OUT PUSHORT Atom OPTIONAL);

extern "C" NTSTATUS SysNtCreateEvent(
    OUT PHANDLE EventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN EVENT_TYPE EventType,
    IN BOOLEAN InitialState);

extern "C" NTSTATUS SysNtQueryVolumeInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FsInformation,
    IN ULONG Length,
    IN FSINFOCLASS FsInformationClass);

extern "C" NTSTATUS SysNtCreateSection(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL);

extern "C" NTSTATUS SysNtFlushBuffersFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock);

extern "C" NTSTATUS SysNtApphelpCacheControl(
    IN APPHELPCACHESERVICECLASS Service,
    IN PVOID ServiceData);

extern "C" NTSTATUS SysNtCreateProcessEx(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL,
    IN ULONG JobMemberLevel);

extern "C" NTSTATUS SysNtCreateThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    OUT PCLIENT_ID ClientId,
    IN PCONTEXT ThreadContext,
    IN PUSER_STACK InitialTeb,
    IN BOOLEAN CreateSuspended);

extern "C" NTSTATUS SysNtIsProcessInJob(
    IN HANDLE ProcessHandle,
    IN HANDLE JobHandle OPTIONAL);

extern "C" NTSTATUS SysNtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID * BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect);

extern "C" NTSTATUS SysNtQuerySection(
    IN HANDLE SectionHandle,
    IN SECTION_INFORMATION_CLASS SectionInformationClass,
    OUT PVOID SectionInformation,
    IN ULONG SectionInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtResumeThread(
    IN HANDLE ThreadHandle,
    IN OUT PULONG PreviousSuspendCount OPTIONAL);

extern "C" NTSTATUS SysNtTerminateThread(
    IN HANDLE ThreadHandle,
    IN NTSTATUS ExitStatus);

extern "C" NTSTATUS SysNtReadRequestData(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN ULONG DataEntryIndex,
    OUT PVOID Buffer,
    IN ULONG BufferSize,
    OUT PULONG NumberOfBytesRead OPTIONAL);

extern "C" NTSTATUS SysNtCreateFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength);

extern "C" NTSTATUS SysNtQueryEvent(
    IN HANDLE EventHandle,
    IN EVENT_INFORMATION_CLASS EventInformationClass,
    OUT PVOID EventInformation,
    IN ULONG EventInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtWriteRequestData(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Request,
    IN ULONG DataIndex,
    IN PVOID Buffer,
    IN ULONG Length,
    OUT PULONG ResultLength OPTIONAL);

extern "C" NTSTATUS SysNtOpenDirectoryObject(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtAccessCheckByTypeAndAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID PrincipalSelfSid OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PULONG AccessStatus,
    OUT PBOOLEAN GenerateOnClose);

extern "C" NTSTATUS SysNtWaitForMultipleObjects(
    IN ULONG Count,
    IN PHANDLE Handles,
    IN WAIT_TYPE WaitType,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtSetInformationObject(
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    IN PVOID ObjectInformation,
    IN ULONG ObjectInformationLength);

extern "C" NTSTATUS SysNtCancelIoFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock);

extern "C" NTSTATUS SysNtTraceEvent(
    IN HANDLE TraceHandle,
    IN ULONG Flags,
    IN ULONG FieldSize,
    IN PVOID Fields);

extern "C" NTSTATUS SysNtPowerInformation(
    IN POWER_INFORMATION_LEVEL InformationLevel,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength);

extern "C" NTSTATUS SysNtSetValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName,
    IN ULONG TitleIndex OPTIONAL,
    IN ULONG Type,
    IN PVOID SystemData,
    IN ULONG DataSize);

extern "C" NTSTATUS SysNtCancelTimer(
    IN HANDLE TimerHandle,
    OUT PBOOLEAN CurrentState OPTIONAL);

extern "C" NTSTATUS SysNtSetTimer(
    IN HANDLE TimerHandle,
    IN PLARGE_INTEGER DueTime,
    IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
    IN PVOID TimerContext OPTIONAL,
    IN BOOLEAN ResumeTimer,
    IN LONG Period OPTIONAL,
    OUT PBOOLEAN PreviousState OPTIONAL);

extern "C" NTSTATUS SysNtAccessCheckByType(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID PrincipalSelfSid OPTIONAL,
    IN HANDLE ClientToken,
    IN ULONG DesiredAccess,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PULONG AccessStatus);

extern "C" NTSTATUS SysNtAccessCheckByTypeResultList(
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID PrincipalSelfSid OPTIONAL,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_TYPE_LIST ObjectTypeList,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    OUT PPRIVILEGE_SET PrivilegeSet,
    IN OUT PULONG PrivilegeSetLength,
    OUT PACCESS_MASK GrantedAccess,
    OUT PULONG AccessStatus);

extern "C" NTSTATUS SysNtAccessCheckByTypeResultListAndAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID PrincipalSelfSid OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PULONG AccessStatus,
    OUT PULONG GenerateOnClose);

extern "C" NTSTATUS SysNtAccessCheckByTypeResultListAndAuditAlarmByHandle(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN HANDLE ClientToken,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor,
    IN PSID PrincipalSelfSid OPTIONAL,
    IN ACCESS_MASK DesiredAccess,
    IN AUDIT_EVENT_TYPE AuditType,
    IN ULONG Flags,
    IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
    IN ULONG ObjectTypeListLength,
    IN PGENERIC_MAPPING GenericMapping,
    IN BOOLEAN ObjectCreation,
    OUT PACCESS_MASK GrantedAccess,
    OUT PULONG AccessStatus,
    OUT PULONG GenerateOnClose);

extern "C" NTSTATUS SysNtAcquireProcessActivityReference();

extern "C" NTSTATUS SysNtAddAtomEx(
    IN PWSTR AtomName,
    IN ULONG Length,
    IN PRTL_ATOM Atom,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtAddBootEntry(
    IN PBOOT_ENTRY BootEntry,
    OUT PULONG Id OPTIONAL);

extern "C" NTSTATUS SysNtAddDriverEntry(
    IN PEFI_DRIVER_ENTRY DriverEntry,
    OUT PULONG Id OPTIONAL);

extern "C" NTSTATUS SysNtAdjustGroupsToken(
    IN HANDLE TokenHandle,
    IN BOOLEAN ResetToDefault,
    IN PTOKEN_GROUPS NewState OPTIONAL,
    IN ULONG BufferLength OPTIONAL,
    OUT PTOKEN_GROUPS PreviousState OPTIONAL,
    OUT PULONG ReturnLength);

extern "C" NTSTATUS SysNtAdjustTokenClaimsAndDeviceGroups(
    IN HANDLE TokenHandle,
    IN BOOLEAN UserResetToDefault,
    IN BOOLEAN DeviceResetToDefault,
    IN BOOLEAN DeviceGroupsResetToDefault,
    IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
    IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
    IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
    IN ULONG UserBufferLength,
    OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
    IN ULONG DeviceBufferLength,
    OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
    IN ULONG DeviceGroupsBufferLength,
    OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
    OUT PULONG UserReturnLength OPTIONAL,
    OUT PULONG DeviceReturnLength OPTIONAL,
    OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL);

extern "C" NTSTATUS SysNtAlertResumeThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL);

extern "C" NTSTATUS SysNtAlertThread(
    IN HANDLE ThreadHandle);

extern "C" NTSTATUS SysNtAlertThreadByThreadId(
    IN ULONG ThreadId);

extern "C" NTSTATUS SysNtAllocateLocallyUniqueId(
    OUT PLUID Luid);

extern "C" NTSTATUS SysNtAllocateReserveObject(
    OUT PHANDLE MemoryReserveHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN MEMORY_RESERVE_TYPE Type);

extern "C" NTSTATUS SysNtAllocateUserPhysicalPages(
    IN HANDLE ProcessHandle,
    IN OUT PULONG NumberOfPages,
    OUT PULONG UserPfnArray);

extern "C" NTSTATUS SysNtAllocateUuids(
    OUT PLARGE_INTEGER Time,
    OUT PULONG Range,
    OUT PULONG Sequence,
    OUT PUCHAR Seed);

extern "C" NTSTATUS SysNtAllocateVirtualMemoryEx(
    IN HANDLE ProcessHandle,
    IN OUT PPVOID lpAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T pSize,
    IN ULONG flAllocationType,
    IN OUT PVOID DataBuffer OPTIONAL,
    IN ULONG DataCount);

extern "C" NTSTATUS SysNtAlpcAcceptConnectPort(
    OUT PHANDLE PortHandle,
    IN HANDLE ConnectionPortHandle,
    IN ULONG Flags,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    IN PVOID PortContext OPTIONAL,
    IN PPORT_MESSAGE ConnectionRequest,
    IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
    IN BOOLEAN AcceptConnection);

extern "C" NTSTATUS SysNtAlpcCancelMessage(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PALPC_CONTEXT_ATTR MessageContext);

extern "C" NTSTATUS SysNtAlpcConnectPort(
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

extern "C" NTSTATUS SysNtAlpcConnectPortEx(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
    IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
    IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
    IN ULONG Flags,
    IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
    IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
    IN OUT PSIZE_T BufferLength OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtAlpcCreatePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL);

extern "C" NTSTATUS SysNtAlpcCreatePortSection(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN HANDLE SectionHandle OPTIONAL,
    IN SIZE_T SectionSize,
    OUT PHANDLE AlpcSectionHandle,
    OUT PSIZE_T ActualSectionSize);

extern "C" NTSTATUS SysNtAlpcCreateResourceReserve(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN SIZE_T MessageSize,
    OUT PHANDLE ResourceId);

extern "C" NTSTATUS SysNtAlpcCreateSectionView(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes);

extern "C" NTSTATUS SysNtAlpcCreateSecurityContext(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN OUT PALPC_SECURITY_ATTR SecurityAttribute);

extern "C" NTSTATUS SysNtAlpcDeletePortSection(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN HANDLE SectionHandle);

extern "C" NTSTATUS SysNtAlpcDeleteResourceReserve(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN HANDLE ResourceId);

extern "C" NTSTATUS SysNtAlpcDeleteSectionView(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PVOID ViewBase);

extern "C" NTSTATUS SysNtAlpcDeleteSecurityContext(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN HANDLE ContextHandle);

extern "C" NTSTATUS SysNtAlpcDisconnectPort(
    IN HANDLE PortHandle,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtAlpcImpersonateClientContainerOfPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtAlpcImpersonateClientOfPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE Message,
    IN PVOID Flags);

extern "C" NTSTATUS SysNtAlpcOpenSenderProcess(
    OUT PHANDLE ProcessHandle,
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE PortMessage,
    IN ULONG Flags,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtAlpcOpenSenderThread(
    OUT PHANDLE ThreadHandle,
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE PortMessage,
    IN ULONG Flags,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtAlpcQueryInformation(
    IN HANDLE PortHandle OPTIONAL,
    IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    IN OUT PVOID PortInformation,
    IN ULONG Length,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtAlpcQueryInformationMessage(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE PortMessage,
    IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
    OUT PVOID MessageInformation OPTIONAL,
    IN ULONG Length,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtAlpcRevokeSecurityContext(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN HANDLE ContextHandle);

extern "C" NTSTATUS SysNtAlpcSendWaitReceivePort(
    IN HANDLE PortHandle,
    IN ULONG Flags,
    IN PPORT_MESSAGE SendMessage OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
    OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
    IN OUT PSIZE_T BufferLength OPTIONAL,
    IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtAlpcSetInformation(
    IN HANDLE PortHandle,
    IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
    IN PVOID PortInformation OPTIONAL,
    IN ULONG Length);

extern "C" NTSTATUS SysNtAreMappedFilesTheSame(
    IN PVOID File1MappedAsAnImage,
    IN PVOID File2MappedAsFile);

extern "C" NTSTATUS SysNtAssignProcessToJobObject(
    IN HANDLE JobHandle,
    IN HANDLE ProcessHandle);

extern "C" NTSTATUS SysNtAssociateWaitCompletionPacket(
    IN HANDLE WaitCompletionPacketHandle,
    IN HANDLE IoCompletionHandle,
    IN HANDLE TargetObjectHandle,
    IN PVOID KeyContext OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    IN NTSTATUS IoStatus,
    IN ULONG_PTR IoStatusInformation,
    OUT PBOOLEAN AlreadySignaled OPTIONAL);

extern "C" NTSTATUS SysNtCallEnclave(
    IN PENCLAVE_ROUTINE Routine,
    IN PVOID Parameter,
    IN BOOLEAN WaitForThread,
    IN OUT PVOID ReturnValue OPTIONAL);

extern "C" NTSTATUS SysNtCancelIoFileEx(
    IN HANDLE FileHandle,
    IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock);

extern "C" NTSTATUS SysNtCancelSynchronousIoFile(
    IN HANDLE ThreadHandle,
    IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock);

extern "C" NTSTATUS SysNtCancelTimer2(
    IN HANDLE TimerHandle,
    IN PT2_CANCEL_PARAMETERS Parameters);

extern "C" NTSTATUS SysNtCancelWaitCompletionPacket(
    IN HANDLE WaitCompletionPacketHandle,
    IN BOOLEAN RemoveSignaledPacket);

extern "C" NTSTATUS SysNtCommitComplete(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtCommitEnlistment(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtCommitRegistryTransaction(
    IN HANDLE RegistryHandle,
    IN BOOL Wait);

extern "C" NTSTATUS SysNtCommitTransaction(
    IN HANDLE TransactionHandle,
    IN BOOLEAN Wait);

extern "C" NTSTATUS SysNtCompactKeys(
    IN ULONG Count,
    IN HANDLE KeyArray);

extern "C" NTSTATUS SysNtCompareObjects(
    IN HANDLE FirstObjectHandle,
    IN HANDLE SecondObjectHandle);

extern "C" NTSTATUS SysNtCompareSigningLevels(
    IN ULONG UnknownParameter1,
    IN ULONG UnknownParameter2);

extern "C" NTSTATUS SysNtCompareTokens(
    IN HANDLE FirstTokenHandle,
    IN HANDLE SecondTokenHandle,
    OUT PBOOLEAN Equal);

extern "C" NTSTATUS SysNtCompleteConnectPort(
    IN HANDLE PortHandle);

extern "C" NTSTATUS SysNtCompressKey(
    IN HANDLE Key);

extern "C" NTSTATUS SysNtConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
    IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
    OUT PULONG MaxMessageLength OPTIONAL,
    IN OUT PVOID ConnectionInformation OPTIONAL,
    IN OUT PULONG ConnectionInformationLength OPTIONAL);

extern "C" NTSTATUS SysNtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
    IN ULONG UnknownParameter1,
    IN ULONG UnknownParameter2,
    IN ULONG UnknownParameter3,
    IN ULONG UnknownParameter4);

extern "C" NTSTATUS SysNtCreateDebugObject(
    OUT PHANDLE DebugObjectHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtCreateDirectoryObject(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtCreateDirectoryObjectEx(
    OUT PHANDLE DirectoryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ShadowDirectoryHandle,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtCreateEnclave(
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN SIZE_T Size,
    IN SIZE_T InitialCommitment,
    IN ULONG EnclaveType,
    IN PVOID EnclaveInformation,
    IN ULONG EnclaveInformationLength,
    OUT PULONG EnclaveError OPTIONAL);

extern "C" NTSTATUS SysNtCreateEnlistment(
    OUT PHANDLE EnlistmentHandle,
    IN ACCESS_MASK DesiredAccess,
    IN HANDLE ResourceManagerHandle,
    IN HANDLE TransactionHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN NOTIFICATION_MASK NotificationMask,
    IN PVOID EnlistmentKey OPTIONAL);

extern "C" NTSTATUS SysNtCreateEventPair(
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

extern "C" NTSTATUS SysNtCreateIRTimer(
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess);

extern "C" NTSTATUS SysNtCreateIoCompletion(
    OUT PHANDLE IoCompletionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG Count OPTIONAL);

extern "C" NTSTATUS SysNtCreateJobObject(
    OUT PHANDLE JobHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

extern "C" NTSTATUS SysNtCreateJobSet(
    IN ULONG NumJob,
    IN PJOB_SET_ARRAY UserJobSet,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtCreateKeyTransacted(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG TitleIndex,
    IN PUNICODE_STRING Class OPTIONAL,
    IN ULONG CreateOptions,
    IN HANDLE TransactionHandle,
    OUT PULONG Disposition OPTIONAL);

extern "C" NTSTATUS SysNtCreateKeyedEvent(
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtCreateLowBoxToken(
    OUT PHANDLE TokenHandle,
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PSID PackageSid,
    IN ULONG CapabilityCount,
    IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
    IN ULONG HandleCount,
    IN HANDLE Handles OPTIONAL);

extern "C" NTSTATUS SysNtCreateMailslotFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CreateOptions,
    IN ULONG MailslotQuota,
    IN ULONG MaximumMessageSize,
    IN PLARGE_INTEGER ReadTimeout);

extern "C" NTSTATUS SysNtCreateMutant(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN BOOLEAN InitialOwner);

extern "C" NTSTATUS SysNtCreateNamedPipeFile(
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN BOOLEAN NamedPipeType,
    IN BOOLEAN ReadMode,
    IN BOOLEAN CompletionMode,
    IN ULONG MaximumInstances,
    IN ULONG InboundQuota,
    IN ULONG OutboundQuota,
    IN PLARGE_INTEGER DefaultTimeout OPTIONAL);

extern "C" NTSTATUS SysNtCreatePagingFile(
    IN PUNICODE_STRING PageFileName,
    IN PULARGE_INTEGER MinimumSize,
    IN PULARGE_INTEGER MaximumSize,
    IN ULONG Priority);

extern "C" NTSTATUS SysNtCreatePartition(
    OUT PHANDLE PartitionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG PreferredNode);

extern "C" NTSTATUS SysNtCreatePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN ULONG MaxPoolUsage OPTIONAL);

extern "C" NTSTATUS SysNtCreatePrivateNamespace(
    OUT PHANDLE NamespaceHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PVOID BoundaryDescriptor);

extern "C" NTSTATUS SysNtCreateProcess(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL);

extern "C" NTSTATUS SysNtCreateProfile(
    OUT PHANDLE ProfileHandle,
    IN HANDLE Process OPTIONAL,
    IN PVOID ProfileBase,
    IN ULONG ProfileSize,
    IN ULONG BucketSize,
    IN PULONG Buffer,
    IN ULONG BufferSize,
    IN KPROFILE_SOURCE ProfileSource,
    IN ULONG Affinity);

extern "C" NTSTATUS SysNtCreateProfileEx(
    OUT PHANDLE ProfileHandle,
    IN HANDLE Process OPTIONAL,
    IN PVOID ProfileBase,
    IN SIZE_T ProfileSize,
    IN ULONG BucketSize,
    IN PULONG Buffer,
    IN ULONG BufferSize,
    IN KPROFILE_SOURCE ProfileSource,
    IN USHORT GroupCount,
    IN PGROUP_AFFINITY GroupAffinity);

extern "C" NTSTATUS SysNtCreateRegistryTransaction(
    OUT PHANDLE Handle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN DWORD Flags);

extern "C" NTSTATUS SysNtCreateResourceManager(
    OUT PHANDLE ResourceManagerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN HANDLE TmHandle,
    IN LPGUID RmGuid,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN PUNICODE_STRING Description OPTIONAL);

extern "C" NTSTATUS SysNtCreateSemaphore(
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN LONG InitialCount,
    IN LONG MaximumCount);

extern "C" NTSTATUS SysNtCreateSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PUNICODE_STRING LinkTarget);

extern "C" NTSTATUS SysNtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument OPTIONAL,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

extern "C" NTSTATUS SysNtCreateTimer(
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN TIMER_TYPE TimerType);

extern "C" NTSTATUS SysNtCreateTimer2(
    OUT PHANDLE TimerHandle,
    IN PVOID Reserved1 OPTIONAL,
    IN PVOID Reserved2 OPTIONAL,
    IN ULONG Attributes,
    IN ACCESS_MASK DesiredAccess);

extern "C" NTSTATUS SysNtCreateToken(
    OUT PHANDLE TokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN TOKEN_TYPE TokenType,
    IN PLUID AuthenticationId,
    IN PLARGE_INTEGER ExpirationTime,
    IN PTOKEN_USER User,
    IN PTOKEN_GROUPS Groups,
    IN PTOKEN_PRIVILEGES Privileges,
    IN PTOKEN_OWNER Owner OPTIONAL,
    IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
    IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
    IN PTOKEN_SOURCE TokenSource);

extern "C" NTSTATUS SysNtCreateTokenEx(
    OUT PHANDLE TokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN TOKEN_TYPE TokenType,
    IN PLUID AuthenticationId,
    IN PLARGE_INTEGER ExpirationTime,
    IN PTOKEN_USER User,
    IN PTOKEN_GROUPS Groups,
    IN PTOKEN_PRIVILEGES Privileges,
    IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
    IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
    IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
    IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
    IN PTOKEN_OWNER Owner OPTIONAL,
    IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
    IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
    IN PTOKEN_SOURCE TokenSource);

extern "C" NTSTATUS SysNtCreateTransaction(
    OUT PHANDLE TransactionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN LPGUID Uow OPTIONAL,
    IN HANDLE TmHandle OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN ULONG IsolationLevel OPTIONAL,
    IN ULONG IsolationFlags OPTIONAL,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    IN PUNICODE_STRING Description OPTIONAL);

extern "C" NTSTATUS SysNtCreateTransactionManager(
    OUT PHANDLE TmHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PUNICODE_STRING LogFileName OPTIONAL,
    IN ULONG CreateOptions OPTIONAL,
    IN ULONG CommitStrength OPTIONAL);

extern "C" NTSTATUS SysNtCreateUserProcess(
    OUT PHANDLE ProcessHandle,
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK ProcessDesiredAccess,
    IN ACCESS_MASK ThreadDesiredAccess,
    IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
    IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
    IN ULONG ProcessFlags,
    IN ULONG ThreadFlags,
    IN PVOID ProcessParameters OPTIONAL,
    IN OUT PPS_CREATE_INFO CreateInfo,
    IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

extern "C" NTSTATUS SysNtCreateWaitCompletionPacket(
    OUT PHANDLE WaitCompletionPacketHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

extern "C" NTSTATUS SysNtCreateWaitablePort(
    OUT PHANDLE PortHandle,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN ULONG MaxConnectionInfoLength,
    IN ULONG MaxMessageLength,
    IN ULONG MaxPoolUsage OPTIONAL);

extern "C" NTSTATUS SysNtCreateWnfStateName(
    OUT PCWNF_STATE_NAME StateName,
    IN WNF_STATE_NAME_LIFETIME NameLifetime,
    IN WNF_DATA_SCOPE DataScope,
    IN BOOLEAN PersistData,
    IN PCWNF_TYPE_ID TypeId OPTIONAL,
    IN ULONG MaximumStateSize,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor);

extern "C" NTSTATUS SysNtCreateWorkerFactory(
    OUT PHANDLE WorkerFactoryHandleReturn,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE CompletionPortHandle,
    IN HANDLE WorkerProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID StartParameter OPTIONAL,
    IN ULONG MaxThreadCount OPTIONAL,
    IN SIZE_T StackReserve OPTIONAL,
    IN SIZE_T StackCommit OPTIONAL);

extern "C" NTSTATUS SysNtDebugActiveProcess(
    IN HANDLE ProcessHandle,
    IN HANDLE DebugObjectHandle);

extern "C" NTSTATUS SysNtDebugContinue(
    IN HANDLE DebugObjectHandle,
    IN PCLIENT_ID ClientId,
    IN NTSTATUS ContinueStatus);

extern "C" NTSTATUS SysNtDeleteAtom(
    IN USHORT Atom);

extern "C" NTSTATUS SysNtDeleteBootEntry(
    IN ULONG Id);

extern "C" NTSTATUS SysNtDeleteDriverEntry(
    IN ULONG Id);

extern "C" NTSTATUS SysNtDeleteFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtDeleteKey(
    IN HANDLE KeyHandle);

extern "C" NTSTATUS SysNtDeleteObjectAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN BOOLEAN GenerateOnClose);

extern "C" NTSTATUS SysNtDeletePrivateNamespace(
    IN HANDLE NamespaceHandle);

extern "C" NTSTATUS SysNtDeleteValueKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING ValueName);

extern "C" NTSTATUS SysNtDeleteWnfStateData(
    IN PCWNF_STATE_NAME StateName,
    IN PVOID ExplicitScope OPTIONAL);

extern "C" NTSTATUS SysNtDeleteWnfStateName(
    IN PCWNF_STATE_NAME StateName);

extern "C" NTSTATUS SysNtDisableLastKnownGood();

extern "C" NTSTATUS SysNtDisplayString(
    IN PUNICODE_STRING String);

extern "C" NTSTATUS SysNtDrawText(
    IN PUNICODE_STRING String);

extern "C" NTSTATUS SysNtEnableLastKnownGood();

extern "C" NTSTATUS SysNtEnumerateBootEntries(
    OUT PVOID Buffer OPTIONAL,
    IN OUT PULONG BufferLength);

extern "C" NTSTATUS SysNtEnumerateDriverEntries(
    OUT PVOID Buffer OPTIONAL,
    IN OUT PULONG BufferLength);

extern "C" NTSTATUS SysNtEnumerateSystemEnvironmentValuesEx(
    IN ULONG InformationClass,
    OUT PVOID Buffer,
    IN OUT PULONG BufferLength);

extern "C" NTSTATUS SysNtEnumerateTransactionObject(
    IN HANDLE RootObjectHandle OPTIONAL,
    IN KTMOBJECT_TYPE QueryType,
    IN OUT PKTMOBJECT_CURSOR ObjectCursor,
    IN ULONG ObjectCursorLength,
    OUT PULONG ReturnLength);

extern "C" NTSTATUS SysNtExtendSection(
    IN HANDLE SectionHandle,
    IN OUT PLARGE_INTEGER NewSectionSize);

extern "C" NTSTATUS SysNtFilterBootOption(
    IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
    IN ULONG ObjectType,
    IN ULONG ElementType,
    IN PVOID SystemData OPTIONAL,
    IN ULONG DataSize);

extern "C" NTSTATUS SysNtFilterToken(
    IN HANDLE ExistingTokenHandle,
    IN ULONG Flags,
    IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
    IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
    OUT PHANDLE NewTokenHandle);

extern "C" NTSTATUS SysNtFilterTokenEx(
    IN HANDLE TokenHandle,
    IN ULONG Flags,
    IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
    IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
    IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
    IN ULONG DisableUserClaimsCount,
    IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
    IN ULONG DisableDeviceClaimsCount,
    IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
    IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
    IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
    IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
    IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
    OUT PHANDLE NewTokenHandle);

extern "C" NTSTATUS SysNtFlushBuffersFileEx(
    IN HANDLE FileHandle,
    IN ULONG Flags,
    IN PVOID Parameters,
    IN ULONG ParametersSize,
    OUT PIO_STATUS_BLOCK IoStatusBlock);

extern "C" NTSTATUS SysNtFlushInstallUILanguage(
    IN LANGID InstallUILanguage,
    IN ULONG SetComittedFlag);

extern "C" NTSTATUS SysNtFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN ULONG Length);

extern "C" NTSTATUS SysNtFlushKey(
    IN HANDLE KeyHandle);

extern "C" NTSTATUS SysNtFlushProcessWriteBuffers();

extern "C" NTSTATUS SysNtFlushVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID BaseAddress,
    IN OUT PULONG RegionSize,
    OUT PIO_STATUS_BLOCK IoStatusBlock);

extern "C" NTSTATUS SysNtFlushWriteBuffer();

extern "C" NTSTATUS SysNtFreeUserPhysicalPages(
    IN HANDLE ProcessHandle,
    IN OUT PULONG NumberOfPages,
    IN PULONG UserPfnArray);

extern "C" NTSTATUS SysNtFreezeRegistry(
    IN ULONG TimeOutInSeconds);

extern "C" NTSTATUS SysNtFreezeTransactions(
    IN PLARGE_INTEGER FreezeTimeout,
    IN PLARGE_INTEGER ThawTimeout);

extern "C" NTSTATUS SysNtGetCachedSigningLevel(
    IN HANDLE File,
    OUT PULONG Flags,
    OUT PSE_SIGNING_LEVEL SigningLevel,
    OUT PUCHAR Thumbprint OPTIONAL,
    IN OUT PULONG ThumbprintSize OPTIONAL,
    OUT PULONG ThumbprintAlgorithm OPTIONAL);

extern "C" NTSTATUS SysNtGetCompleteWnfStateSubscription(
    IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
    IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
    IN ULONG OldDescriptorEventMask OPTIONAL,
    IN ULONG OldDescriptorStatus OPTIONAL,
    OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
    IN ULONG DescriptorSize);

extern "C" NTSTATUS SysNtGetContextThread(
    IN HANDLE ThreadHandle,
    IN OUT PCONTEXT ThreadContext);

extern "C" NTSTATUS SysNtGetCurrentProcessorNumber();

extern "C" NTSTATUS SysNtGetCurrentProcessorNumberEx(
    OUT PULONG ProcNumber OPTIONAL);

extern "C" NTSTATUS SysNtGetDevicePowerState(
    IN HANDLE Device,
    OUT PDEVICE_POWER_STATE State);

extern "C" NTSTATUS SysNtGetMUIRegistryInfo(
    IN ULONG Flags,
    IN OUT PULONG DataSize,
    OUT PVOID SystemData);

extern "C" NTSTATUS SysNtGetNextProcess(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewProcessHandle);

extern "C" NTSTATUS SysNtGetNextThread(
    IN HANDLE ProcessHandle,
    IN HANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN ULONG HandleAttributes,
    IN ULONG Flags,
    OUT PHANDLE NewThreadHandle);

extern "C" NTSTATUS SysNtGetNlsSectionPtr(
    IN ULONG SectionType,
    IN ULONG SectionData,
    IN PVOID ContextData,
    OUT PVOID SectionPointer,
    OUT PULONG SectionSize);

extern "C" NTSTATUS SysNtGetNotificationResourceManager(
    IN HANDLE ResourceManagerHandle,
    OUT PTRANSACTION_NOTIFICATION TransactionNotification,
    IN ULONG NotificationLength,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    OUT PULONG ReturnLength OPTIONAL,
    IN ULONG Asynchronous,
    IN ULONG AsynchronousContext OPTIONAL);

extern "C" NTSTATUS SysNtGetWriteWatch(
    IN HANDLE ProcessHandle,
    IN ULONG Flags,
    IN PVOID BaseAddress,
    IN ULONG RegionSize,
    OUT PULONG UserAddressArray,
    IN OUT PULONG EntriesInUserAddressArray,
    OUT PULONG Granularity);

extern "C" NTSTATUS SysNtImpersonateAnonymousToken(
    IN HANDLE ThreadHandle);

extern "C" NTSTATUS SysNtImpersonateThread(
    IN HANDLE ServerThreadHandle,
    IN HANDLE ClientThreadHandle,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos);

extern "C" NTSTATUS SysNtInitializeEnclave(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID EnclaveInformation,
    IN ULONG EnclaveInformationLength,
    OUT PULONG EnclaveError OPTIONAL);

extern "C" NTSTATUS SysNtInitializeNlsFiles(
    OUT PVOID BaseAddress,
    OUT PLCID DefaultLocaleId,
    OUT PLARGE_INTEGER DefaultCasingTableSize);

extern "C" NTSTATUS SysNtInitializeRegistry(
    IN USHORT BootCondition);

extern "C" NTSTATUS SysNtInitiatePowerAction(
    IN POWER_ACTION SystemAction,
    IN SYSTEM_POWER_STATE LightestSystemState,
    IN ULONG Flags,
    IN BOOLEAN Asynchronous);

extern "C" NTSTATUS SysNtIsSystemResumeAutomatic();

extern "C" NTSTATUS SysNtIsUILanguageComitted();

extern "C" NTSTATUS SysNtListenPort(
    IN HANDLE PortHandle,
    OUT PPORT_MESSAGE ConnectionRequest);

extern "C" NTSTATUS SysNtLoadDriver(
    IN PUNICODE_STRING DriverServiceName);

extern "C" NTSTATUS SysNtLoadEnclaveData(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PVOID Buffer,
    IN SIZE_T BufferSize,
    IN ULONG Protect,
    IN PVOID PageInformation,
    IN ULONG PageInformationLength,
    OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
    OUT PULONG EnclaveError OPTIONAL);

extern "C" NTSTATUS SysNtLoadHotPatch(
    IN PUNICODE_STRING HotPatchName,
    IN ULONG LoadFlag);

extern "C" NTSTATUS SysNtLoadKey(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile);

extern "C" NTSTATUS SysNtLoadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtLoadKeyEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN POBJECT_ATTRIBUTES SourceFile,
    IN ULONG Flags,
    IN HANDLE TrustClassKey OPTIONAL,
    IN HANDLE Event OPTIONAL,
    IN ACCESS_MASK DesiredAccess OPTIONAL,
    OUT PHANDLE RootHandle OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatus OPTIONAL);

extern "C" NTSTATUS SysNtLockFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PULARGE_INTEGER ByteOffset,
    IN PULARGE_INTEGER Length,
    IN ULONG Key,
    IN BOOLEAN FailImmediately,
    IN BOOLEAN ExclusiveLock);

extern "C" NTSTATUS SysNtLockProductActivationKeys(
    IN OUT PULONG pPrivateVer OPTIONAL,
    OUT PULONG pSafeMode OPTIONAL);

extern "C" NTSTATUS SysNtLockRegistryKey(
    IN HANDLE KeyHandle);

extern "C" NTSTATUS SysNtLockVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN PULONG RegionSize,
    IN ULONG MapType);

extern "C" NTSTATUS SysNtMakePermanentObject(
    IN HANDLE Handle);

extern "C" NTSTATUS SysNtMakeTemporaryObject(
    IN HANDLE Handle);

extern "C" NTSTATUS SysNtManagePartition(
    IN HANDLE TargetHandle,
    IN HANDLE SourceHandle,
    IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
    IN OUT PVOID PartitionInformation,
    IN ULONG PartitionInformationLength);

extern "C" NTSTATUS SysNtMapCMFModule(
    IN ULONG What,
    IN ULONG Index,
    OUT PULONG CacheIndexOut OPTIONAL,
    OUT PULONG CacheFlagsOut OPTIONAL,
    OUT PULONG ViewSizeOut OPTIONAL,
    OUT PVOID BaseAddress OPTIONAL);

extern "C" NTSTATUS SysNtMapUserPhysicalPages(
    IN PVOID VirtualAddress,
    IN PULONG NumberOfPages,
    IN PULONG UserPfnArray OPTIONAL);

extern "C" NTSTATUS SysNtMapViewOfSectionEx(
    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT PLARGE_INTEGER SectionOffset,
    IN OUT PPVOID BaseAddress,
    IN OUT PSIZE_T ViewSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN OUT PVOID DataBuffer OPTIONAL,
    IN ULONG DataCount);

extern "C" NTSTATUS SysNtModifyBootEntry(
    IN PBOOT_ENTRY BootEntry);

extern "C" NTSTATUS SysNtModifyDriverEntry(
    IN PEFI_DRIVER_ENTRY DriverEntry);

extern "C" NTSTATUS SysNtNotifyChangeDirectoryFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PFILE_NOTIFY_INFORMATION Buffer,
    IN ULONG Length,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree);

extern "C" NTSTATUS SysNtNotifyChangeDirectoryFileEx(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID Buffer,
    IN ULONG Length,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL);

extern "C" NTSTATUS SysNtNotifyChangeKey(
    IN HANDLE KeyHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    OUT PVOID Buffer OPTIONAL,
    IN ULONG BufferSize,
    IN BOOLEAN Asynchronous);

extern "C" NTSTATUS SysNtNotifyChangeMultipleKeys(
    IN HANDLE MasterKeyHandle,
    IN ULONG Count OPTIONAL,
    IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG CompletionFilter,
    IN BOOLEAN WatchTree,
    OUT PVOID Buffer OPTIONAL,
    IN ULONG BufferSize,
    IN BOOLEAN Asynchronous);

extern "C" NTSTATUS SysNtNotifyChangeSession(
    IN HANDLE SessionHandle,
    IN ULONG ChangeSequenceNumber,
    IN PLARGE_INTEGER ChangeTimeStamp,
    IN IO_SESSION_EVENT Event,
    IN IO_SESSION_STATE NewState,
    IN IO_SESSION_STATE PreviousState,
    IN PVOID Payload OPTIONAL,
    IN ULONG PayloadSize);

extern "C" NTSTATUS SysNtOpenEnlistment(
    OUT PHANDLE EnlistmentHandle,
    IN ACCESS_MASK DesiredAccess,
    IN HANDLE ResourceManagerHandle,
    IN LPGUID EnlistmentGuid,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

extern "C" NTSTATUS SysNtOpenEventPair(
    OUT PHANDLE EventPairHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenIoCompletion(
    OUT PHANDLE IoCompletionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenJobObject(
    OUT PHANDLE JobHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenKeyEx(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG OpenOptions);

extern "C" NTSTATUS SysNtOpenKeyTransacted(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE TransactionHandle);

extern "C" NTSTATUS SysNtOpenKeyTransactedEx(
    OUT PHANDLE KeyHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN ULONG OpenOptions,
    IN HANDLE TransactionHandle);

extern "C" NTSTATUS SysNtOpenKeyedEvent(
    OUT PHANDLE KeyedEventHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenMutant(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenObjectAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN PUNICODE_STRING ObjectTypeName,
    IN PUNICODE_STRING ObjectName,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN ACCESS_MASK GrantedAccess,
    IN PPRIVILEGE_SET Privileges OPTIONAL,
    IN BOOLEAN ObjectCreation,
    IN BOOLEAN AccessGranted,
    OUT PBOOLEAN GenerateOnClose);

extern "C" NTSTATUS SysNtOpenPartition(
    OUT PHANDLE PartitionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenPrivateNamespace(
    OUT PHANDLE NamespaceHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PVOID BoundaryDescriptor);

extern "C" NTSTATUS SysNtOpenProcessToken(
    IN HANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    OUT PHANDLE TokenHandle);

extern "C" NTSTATUS SysNtOpenRegistryTransaction(
    OUT PHANDLE RegistryHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenResourceManager(
    OUT PHANDLE ResourceManagerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN HANDLE TmHandle,
    IN LPGUID ResourceManagerGuid OPTIONAL,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

extern "C" NTSTATUS SysNtOpenSemaphore(
    OUT PHANDLE SemaphoreHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenSession(
    OUT PHANDLE SessionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenSymbolicLinkObject(
    OUT PHANDLE LinkHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenThread(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PCLIENT_ID ClientId OPTIONAL);

extern "C" NTSTATUS SysNtOpenTimer(
    OUT PHANDLE TimerHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes);

extern "C" NTSTATUS SysNtOpenTransaction(
    OUT PHANDLE TransactionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN LPGUID Uow,
    IN HANDLE TmHandle OPTIONAL);

extern "C" NTSTATUS SysNtOpenTransactionManager(
    OUT PHANDLE TmHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PUNICODE_STRING LogFileName OPTIONAL,
    IN LPGUID TmIdentity OPTIONAL,
    IN ULONG OpenOptions OPTIONAL);

extern "C" NTSTATUS SysNtPlugPlayControl(
    IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
    IN OUT PVOID PnPControlData,
    IN ULONG PnPControlDataLength);

extern "C" NTSTATUS SysNtPrePrepareComplete(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtPrePrepareEnlistment(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtPrepareComplete(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtPrepareEnlistment(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtPrivilegeCheck(
    IN HANDLE ClientToken,
    IN OUT PPRIVILEGE_SET RequiredPrivileges,
    OUT PBOOLEAN Result);

extern "C" NTSTATUS SysNtPrivilegeObjectAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PVOID HandleId OPTIONAL,
    IN HANDLE ClientToken,
    IN ACCESS_MASK DesiredAccess,
    IN PPRIVILEGE_SET Privileges,
    IN BOOLEAN AccessGranted);

extern "C" NTSTATUS SysNtPrivilegedServiceAuditAlarm(
    IN PUNICODE_STRING SubsystemName,
    IN PUNICODE_STRING ServiceName,
    IN HANDLE ClientToken,
    IN PPRIVILEGE_SET Privileges,
    IN BOOLEAN AccessGranted);

extern "C" NTSTATUS SysNtPropagationComplete(
    IN HANDLE ResourceManagerHandle,
    IN ULONG RequestCookie,
    IN ULONG BufferLength,
    IN PVOID Buffer);

extern "C" NTSTATUS SysNtPropagationFailed(
    IN HANDLE ResourceManagerHandle,
    IN ULONG RequestCookie,
    IN NTSTATUS PropStatus);

extern "C" NTSTATUS SysNtPulseEvent(
    IN HANDLE EventHandle,
    OUT PULONG PreviousState OPTIONAL);

extern "C" NTSTATUS SysNtQueryAuxiliaryCounterFrequency(
    OUT PULONGLONG lpAuxiliaryCounterFrequency);

extern "C" NTSTATUS SysNtQueryBootEntryOrder(
    OUT PULONG Ids OPTIONAL,
    IN OUT PULONG Count);

extern "C" NTSTATUS SysNtQueryBootOptions(
    OUT PBOOT_OPTIONS BootOptions OPTIONAL,
    IN OUT PULONG BootOptionsLength);

extern "C" NTSTATUS SysNtQueryDebugFilterState(
    IN ULONG ComponentId,
    IN ULONG Level);

extern "C" NTSTATUS SysNtQueryDirectoryFileEx(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN ULONG QueryFlags,
    IN PUNICODE_STRING FileName OPTIONAL);

extern "C" NTSTATUS SysNtQueryDirectoryObject(
    IN HANDLE DirectoryHandle,
    OUT PVOID Buffer OPTIONAL,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN BOOLEAN RestartScan,
    IN OUT PULONG Context,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryDriverEntryOrder(
    IN PULONG Ids OPTIONAL,
    IN OUT PULONG Count);

extern "C" NTSTATUS SysNtQueryEaFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PFILE_FULL_EA_INFORMATION Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
    IN ULONG EaListLength,
    IN PULONG EaIndex OPTIONAL,
    IN BOOLEAN RestartScan);

extern "C" NTSTATUS SysNtQueryFullAttributesFile(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation);

extern "C" NTSTATUS SysNtQueryInformationAtom(
    IN USHORT Atom,
    IN ATOM_INFORMATION_CLASS AtomInformationClass,
    OUT PVOID AtomInformation,
    IN ULONG AtomInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationByName(
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);

extern "C" NTSTATUS SysNtQueryInformationEnlistment(
    IN HANDLE EnlistmentHandle,
    IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    OUT PVOID EnlistmentInformation,
    IN ULONG EnlistmentInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationJobObject(
    IN HANDLE JobHandle,
    IN JOBOBJECTINFOCLASS JobObjectInformationClass,
    OUT PVOID JobObjectInformation,
    IN ULONG JobObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationPort(
    IN HANDLE PortHandle,
    IN PORT_INFORMATION_CLASS PortInformationClass,
    OUT PVOID PortInformation,
    IN ULONG Length,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationResourceManager(
    IN HANDLE ResourceManagerHandle,
    IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    OUT PVOID ResourceManagerInformation,
    IN ULONG ResourceManagerInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationTransaction(
    IN HANDLE TransactionHandle,
    IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    OUT PVOID TransactionInformation,
    IN ULONG TransactionInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationTransactionManager(
    IN HANDLE TransactionManagerHandle,
    IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
    OUT PVOID TransactionManagerInformation,
    IN ULONG TransactionManagerInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInformationWorkerFactory(
    IN HANDLE WorkerFactoryHandle,
    IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    OUT PVOID WorkerFactoryInformation,
    IN ULONG WorkerFactoryInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryInstallUILanguage(
    OUT PLANGID InstallUILanguageId);

extern "C" NTSTATUS SysNtQueryIntervalProfile(
    IN KPROFILE_SOURCE ProfileSource,
    OUT PULONG Interval);

extern "C" NTSTATUS SysNtQueryIoCompletion(
    IN HANDLE IoCompletionHandle,
    IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
    OUT PVOID IoCompletionInformation,
    IN ULONG IoCompletionInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryLicenseValue(
    IN PUNICODE_STRING ValueName,
    OUT PULONG Type OPTIONAL,
    OUT PVOID SystemData OPTIONAL,
    IN ULONG DataSize,
    OUT PULONG ResultDataSize);

extern "C" NTSTATUS SysNtQueryMultipleValueKey(
    IN HANDLE KeyHandle,
    IN OUT PKEY_VALUE_ENTRY ValueEntries,
    IN ULONG EntryCount,
    OUT PVOID ValueBuffer,
    IN PULONG BufferLength,
    OUT PULONG RequiredBufferLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryMutant(
    IN HANDLE MutantHandle,
    IN MUTANT_INFORMATION_CLASS MutantInformationClass,
    OUT PVOID MutantInformation,
    IN ULONG MutantInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryOpenSubKeys(
    IN POBJECT_ATTRIBUTES TargetKey,
    OUT PULONG HandleCount);

extern "C" NTSTATUS SysNtQueryOpenSubKeysEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN ULONG BufferLength,
    OUT PVOID Buffer,
    OUT PULONG RequiredSize);

extern "C" NTSTATUS SysNtQueryPortInformationProcess();

extern "C" NTSTATUS SysNtQueryQuotaInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PFILE_USER_QUOTA_INFORMATION Buffer,
    IN ULONG Length,
    IN BOOLEAN ReturnSingleEntry,
    IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
    IN ULONG SidListLength,
    IN PSID StartSid OPTIONAL,
    IN BOOLEAN RestartScan);

extern "C" NTSTATUS SysNtQuerySecurityAttributesToken(
    IN HANDLE TokenHandle,
    IN PUNICODE_STRING Attributes OPTIONAL,
    IN ULONG NumberOfAttributes,
    OUT PVOID Buffer,
    IN ULONG Length,
    OUT PULONG ReturnLength);

extern "C" NTSTATUS SysNtQuerySecurityObject(
    IN HANDLE Handle,
    IN SECURITY_INFORMATION SecurityInformation,
    OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN ULONG Length,
    OUT PULONG LengthNeeded);

extern "C" NTSTATUS SysNtQuerySecurityPolicy(
    IN ULONG_PTR UnknownParameter1,
    IN ULONG_PTR UnknownParameter2,
    IN ULONG_PTR UnknownParameter3,
    IN ULONG_PTR UnknownParameter4,
    IN ULONG_PTR UnknownParameter5,
    IN ULONG_PTR UnknownParameter6);

extern "C" NTSTATUS SysNtQuerySemaphore(
    IN HANDLE SemaphoreHandle,
    IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
    OUT PVOID SemaphoreInformation,
    IN ULONG SemaphoreInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQuerySymbolicLinkObject(
    IN HANDLE LinkHandle,
    IN OUT PUNICODE_STRING LinkTarget,
    OUT PULONG ReturnedLength OPTIONAL);

extern "C" NTSTATUS SysNtQuerySystemEnvironmentValue(
    IN PUNICODE_STRING VariableName,
    OUT PVOID VariableValue,
    IN ULONG ValueLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQuerySystemEnvironmentValueEx(
    IN PUNICODE_STRING VariableName,
    IN LPGUID VendorGuid,
    OUT PVOID Value OPTIONAL,
    IN OUT PULONG ValueLength,
    OUT PULONG Attributes OPTIONAL);

extern "C" NTSTATUS SysNtQuerySystemInformationEx(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID SystemInformation OPTIONAL,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtQueryTimerResolution(
    OUT PULONG MaximumTime,
    OUT PULONG MinimumTime,
    OUT PULONG CurrentTime);

extern "C" NTSTATUS SysNtQueryWnfStateData(
    IN PCWNF_STATE_NAME StateName,
    IN PCWNF_TYPE_ID TypeId OPTIONAL,
    IN PVOID ExplicitScope OPTIONAL,
    OUT PWNF_CHANGE_STAMP ChangeStamp,
    OUT PVOID Buffer OPTIONAL,
    IN OUT PULONG BufferSize);

extern "C" NTSTATUS SysNtQueryWnfStateNameInformation(
    IN PCWNF_STATE_NAME StateName,
    IN PCWNF_TYPE_ID NameInfoClass,
    IN PVOID ExplicitScope OPTIONAL,
    OUT PVOID InfoBuffer,
    IN ULONG InfoBufferSize);

extern "C" NTSTATUS SysNtQueueApcThreadEx(
    IN HANDLE ThreadHandle,
    IN HANDLE UserApcReserveHandle OPTIONAL,
    IN PKNORMAL_ROUTINE ApcRoutine,
    IN PVOID ApcArgument1 OPTIONAL,
    IN PVOID ApcArgument2 OPTIONAL,
    IN PVOID ApcArgument3 OPTIONAL);

extern "C" NTSTATUS SysNtRaiseException(
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN BOOLEAN FirstChance);

extern "C" NTSTATUS SysNtRaiseHardError(
    IN NTSTATUS ErrorStatus,
    IN ULONG NumberOfParameters,
    IN ULONG UnicodeStringParameterMask,
    IN PULONG_PTR Parameters,
    IN ULONG ValidResponseOptions,
    OUT PULONG Response);

extern "C" NTSTATUS SysNtReadOnlyEnlistment(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtRecoverEnlistment(
    IN HANDLE EnlistmentHandle,
    IN PVOID EnlistmentKey OPTIONAL);

extern "C" NTSTATUS SysNtRecoverResourceManager(
    IN HANDLE ResourceManagerHandle);

extern "C" NTSTATUS SysNtRecoverTransactionManager(
    IN HANDLE TransactionManagerHandle);

extern "C" NTSTATUS SysNtRegisterProtocolAddressInformation(
    IN HANDLE ResourceManager,
    IN LPGUID ProtocolId,
    IN ULONG ProtocolInformationSize,
    IN PVOID ProtocolInformation,
    IN ULONG CreateOptions OPTIONAL);

extern "C" NTSTATUS SysNtRegisterThreadTerminatePort(
    IN HANDLE PortHandle);

extern "C" NTSTATUS SysNtReleaseKeyedEvent(
    IN HANDLE KeyedEventHandle,
    IN PVOID KeyValue,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtReleaseWorkerFactoryWorker(
    IN HANDLE WorkerFactoryHandle);

extern "C" NTSTATUS SysNtRemoveIoCompletionEx(
    IN HANDLE IoCompletionHandle,
    OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
    IN ULONG Count,
    OUT PULONG NumEntriesRemoved,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    IN BOOLEAN Alertable);

extern "C" NTSTATUS SysNtRemoveProcessDebug(
    IN HANDLE ProcessHandle,
    IN HANDLE DebugObjectHandle);

extern "C" NTSTATUS SysNtRenameKey(
    IN HANDLE KeyHandle,
    IN PUNICODE_STRING NewName);

extern "C" NTSTATUS SysNtRenameTransactionManager(
    IN PUNICODE_STRING LogFileName,
    IN LPGUID ExistingTransactionManagerGuid);

extern "C" NTSTATUS SysNtReplaceKey(
    IN POBJECT_ATTRIBUTES NewFile,
    IN HANDLE TargetHandle,
    IN POBJECT_ATTRIBUTES OldFile);

extern "C" NTSTATUS SysNtReplacePartitionUnit(
    IN PUNICODE_STRING TargetInstancePath,
    IN PUNICODE_STRING SpareInstancePath,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtReplyWaitReplyPort(
    IN HANDLE PortHandle,
    IN OUT PPORT_MESSAGE ReplyMessage);

extern "C" NTSTATUS SysNtRequestPort(
    IN HANDLE PortHandle,
    IN PPORT_MESSAGE RequestMessage);

extern "C" NTSTATUS SysNtResetEvent(
    IN HANDLE EventHandle,
    OUT PULONG PreviousState OPTIONAL);

extern "C" NTSTATUS SysNtResetWriteWatch(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN ULONG RegionSize);

extern "C" NTSTATUS SysNtRestoreKey(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtResumeProcess(
    IN HANDLE ProcessHandle);

extern "C" NTSTATUS SysNtRevertContainerImpersonation();

extern "C" NTSTATUS SysNtRollbackComplete(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtRollbackEnlistment(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtRollbackRegistryTransaction(
    IN HANDLE RegistryHandle,
    IN BOOL Wait);

extern "C" NTSTATUS SysNtRollbackTransaction(
    IN HANDLE TransactionHandle,
    IN BOOLEAN Wait);

extern "C" NTSTATUS SysNtRollforwardTransactionManager(
    IN HANDLE TransactionManagerHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtSaveKey(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle);

extern "C" NTSTATUS SysNtSaveKeyEx(
    IN HANDLE KeyHandle,
    IN HANDLE FileHandle,
    IN ULONG Format);

extern "C" NTSTATUS SysNtSaveMergedKeys(
    IN HANDLE HighPrecedenceKeyHandle,
    IN HANDLE LowPrecedenceKeyHandle,
    IN HANDLE FileHandle);

extern "C" NTSTATUS SysNtSecureConnectPort(
    OUT PHANDLE PortHandle,
    IN PUNICODE_STRING PortName,
    IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
    IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
    IN PSID RequiredServerSid OPTIONAL,
    IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
    OUT PULONG MaxMessageLength OPTIONAL,
    IN OUT PVOID ConnectionInformation OPTIONAL,
    IN OUT PULONG ConnectionInformationLength OPTIONAL);

extern "C" NTSTATUS SysNtSerializeBoot();

extern "C" NTSTATUS SysNtSetBootEntryOrder(
    IN PULONG Ids,
    IN ULONG Count);

extern "C" NTSTATUS SysNtSetBootOptions(
    IN PBOOT_OPTIONS BootOptions,
    IN ULONG FieldsToChange);

extern "C" NTSTATUS SysNtSetCachedSigningLevel(
    IN ULONG Flags,
    IN SE_SIGNING_LEVEL InputSigningLevel,
    IN PHANDLE SourceFiles,
    IN ULONG SourceFileCount,
    IN HANDLE TargetFile OPTIONAL);

extern "C" NTSTATUS SysNtSetCachedSigningLevel2(
    IN ULONG Flags,
    IN ULONG InputSigningLevel,
    IN PHANDLE SourceFiles,
    IN ULONG SourceFileCount,
    IN HANDLE TargetFile OPTIONAL,
    IN PVOID LevelInformation OPTIONAL);

extern "C" NTSTATUS SysNtSetContextThread(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context);

extern "C" NTSTATUS SysNtSetDebugFilterState(
    IN ULONG ComponentId,
    IN ULONG Level,
    IN BOOLEAN State);

extern "C" NTSTATUS SysNtSetDefaultHardErrorPort(
    IN HANDLE PortHandle);

extern "C" NTSTATUS SysNtSetDefaultLocale(
    IN BOOLEAN UserProfile,
    IN LCID DefaultLocaleId);

extern "C" NTSTATUS SysNtSetDefaultUILanguage(
    IN LANGID DefaultUILanguageId);

extern "C" NTSTATUS SysNtSetDriverEntryOrder(
    IN PULONG Ids,
    IN PULONG Count);

extern "C" NTSTATUS SysNtSetEaFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaBufferSize);

extern "C" NTSTATUS SysNtSetHighEventPair(
    IN HANDLE EventPairHandle);

extern "C" NTSTATUS SysNtSetHighWaitLowEventPair(
    IN HANDLE EventPairHandle);

extern "C" NTSTATUS SysNtSetIRTimer(
    IN HANDLE TimerHandle,
    IN PLARGE_INTEGER DueTime OPTIONAL);

extern "C" NTSTATUS SysNtSetInformationDebugObject(
    IN HANDLE DebugObject,
    IN DEBUGOBJECTINFOCLASS InformationClass,
    IN PVOID Information,
    IN ULONG InformationLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtSetInformationEnlistment(
    IN HANDLE EnlistmentHandle,
    IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
    IN PVOID EnlistmentInformation,
    IN ULONG EnlistmentInformationLength);

extern "C" NTSTATUS SysNtSetInformationJobObject(
    IN HANDLE JobHandle,
    IN JOBOBJECTINFOCLASS JobObjectInformationClass,
    IN PVOID JobObjectInformation,
    IN ULONG JobObjectInformationLength);

extern "C" NTSTATUS SysNtSetInformationKey(
    IN HANDLE KeyHandle,
    IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    IN PVOID KeySetInformation,
    IN ULONG KeySetInformationLength);

extern "C" NTSTATUS SysNtSetInformationResourceManager(
    IN HANDLE ResourceManagerHandle,
    IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
    IN PVOID ResourceManagerInformation,
    IN ULONG ResourceManagerInformationLength);

extern "C" NTSTATUS SysNtSetInformationSymbolicLink(
    IN HANDLE Handle,
    IN ULONG Class,
    IN PVOID Buffer,
    IN ULONG BufferLength);

extern "C" NTSTATUS SysNtSetInformationToken(
    IN HANDLE TokenHandle,
    IN TOKEN_INFORMATION_CLASS TokenInformationClass,
    IN PVOID TokenInformation,
    IN ULONG TokenInformationLength);

extern "C" NTSTATUS SysNtSetInformationTransaction(
    IN HANDLE TransactionHandle,
    IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
    IN PVOID TransactionInformation,
    IN ULONG TransactionInformationLength);

extern "C" NTSTATUS SysNtSetInformationTransactionManager(
    IN HANDLE TransactionHandle,
    IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
    IN PVOID TransactionInformation,
    IN ULONG TransactionInformationLength);

extern "C" NTSTATUS SysNtSetInformationVirtualMemory(
    IN HANDLE ProcessHandle,
    IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
    IN ULONG_PTR NumberOfEntries,
    IN PMEMORY_RANGE_ENTRY VirtualAddresses,
    IN PVOID VmInformation,
    IN ULONG VmInformationLength);

extern "C" NTSTATUS SysNtSetInformationWorkerFactory(
    IN HANDLE WorkerFactoryHandle,
    IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    IN PVOID WorkerFactoryInformation,
    IN ULONG WorkerFactoryInformationLength);

extern "C" NTSTATUS SysNtSetIntervalProfile(
    IN ULONG Interval,
    IN KPROFILE_SOURCE Source);

extern "C" NTSTATUS SysNtSetIoCompletion(
    IN HANDLE IoCompletionHandle,
    IN ULONG CompletionKey,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN NTSTATUS CompletionStatus,
    IN ULONG NumberOfBytesTransfered);

extern "C" NTSTATUS SysNtSetIoCompletionEx(
    IN HANDLE IoCompletionHandle,
    IN HANDLE IoCompletionPacketHandle,
    IN PVOID KeyContext OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    IN NTSTATUS IoStatus,
    IN ULONG_PTR IoStatusInformation);

extern "C" NTSTATUS SysNtSetLdtEntries(
    IN ULONG Selector0,
    IN ULONG Entry0Low,
    IN ULONG Entry0Hi,
    IN ULONG Selector1,
    IN ULONG Entry1Low,
    IN ULONG Entry1Hi);

extern "C" NTSTATUS SysNtSetLowEventPair(
    IN HANDLE EventPairHandle);

extern "C" NTSTATUS SysNtSetLowWaitHighEventPair(
    IN HANDLE EventPairHandle);

extern "C" NTSTATUS SysNtSetQuotaInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PFILE_USER_QUOTA_INFORMATION Buffer,
    IN ULONG Length);

extern "C" NTSTATUS SysNtSetSecurityObject(
    IN HANDLE ObjectHandle,
    IN SECURITY_INFORMATION SecurityInformationClass,
    IN PSECURITY_DESCRIPTOR DescriptorBuffer);

extern "C" NTSTATUS SysNtSetSystemEnvironmentValue(
    IN PUNICODE_STRING VariableName,
    IN PUNICODE_STRING Value);

extern "C" NTSTATUS SysNtSetSystemEnvironmentValueEx(
    IN PUNICODE_STRING VariableName,
    IN LPGUID VendorGuid,
    IN PVOID Value OPTIONAL,
    IN ULONG ValueLength,
    IN ULONG Attributes);

extern "C" NTSTATUS SysNtSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID SystemInformation,
    IN ULONG SystemInformationLength);

extern "C" NTSTATUS SysNtSetSystemPowerState(
    IN POWER_ACTION SystemAction,
    IN SYSTEM_POWER_STATE MinSystemState,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtSetSystemTime(
    IN PLARGE_INTEGER SystemTime,
    OUT PLARGE_INTEGER PreviousTime OPTIONAL);

extern "C" NTSTATUS SysNtSetThreadExecutionState(
    IN EXECUTION_STATE ExecutionState,
    OUT PEXECUTION_STATE PreviousExecutionState);

extern "C" NTSTATUS SysNtSetTimer2(
    IN HANDLE TimerHandle,
    IN PLARGE_INTEGER DueTime,
    IN PLARGE_INTEGER Period OPTIONAL,
    IN PT2_SET_PARAMETERS Parameters);

extern "C" NTSTATUS SysNtSetTimerEx(
    IN HANDLE TimerHandle,
    IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
    IN OUT PVOID TimerSetInformation OPTIONAL,
    IN ULONG TimerSetInformationLength);

extern "C" NTSTATUS SysNtSetTimerResolution(
    IN ULONG DesiredResolution,
    IN BOOLEAN SetResolution,
    OUT PULONG CurrentResolution);

extern "C" NTSTATUS SysNtSetUuidSeed(
    IN PUCHAR Seed);

extern "C" NTSTATUS SysNtSetVolumeInformationFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID FileSystemInformation,
    IN ULONG Length,
    IN FSINFOCLASS FileSystemInformationClass);

extern "C" NTSTATUS SysNtSetWnfProcessNotificationEvent(
    IN HANDLE NotificationEvent);

extern "C" NTSTATUS SysNtShutdownSystem(
    IN SHUTDOWN_ACTION Action);

extern "C" NTSTATUS SysNtShutdownWorkerFactory(
    IN HANDLE WorkerFactoryHandle,
    IN OUT PLONG PendingWorkerCount);

extern "C" NTSTATUS SysNtSignalAndWaitForSingleObject(
    IN HANDLE hObjectToSignal,
    IN HANDLE hObjectToWaitOn,
    IN BOOLEAN bAlertable,
    IN PLARGE_INTEGER dwMilliseconds OPTIONAL);

extern "C" NTSTATUS SysNtSinglePhaseReject(
    IN HANDLE EnlistmentHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtStartProfile(
    IN HANDLE ProfileHandle);

extern "C" NTSTATUS SysNtStopProfile(
    IN HANDLE ProfileHandle);

extern "C" NTSTATUS SysNtSubscribeWnfStateChange(
    IN PCWNF_STATE_NAME StateName,
    IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
    IN ULONG EventMask,
    OUT PLARGE_INTEGER SubscriptionId OPTIONAL);

extern "C" NTSTATUS SysNtSuspendProcess(
    IN HANDLE ProcessHandle);

extern "C" NTSTATUS SysNtSuspendThread(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount);

extern "C" NTSTATUS SysNtSystemDebugControl(
    IN DEBUG_CONTROL_CODE Command,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength OPTIONAL);

extern "C" NTSTATUS SysNtTerminateEnclave(
    IN PVOID BaseAddress,
    IN BOOLEAN WaitForThread);

extern "C" NTSTATUS SysNtTerminateJobObject(
    IN HANDLE JobHandle,
    IN NTSTATUS ExitStatus);

extern "C" NTSTATUS SysNtTestAlert();

extern "C" NTSTATUS SysNtThawRegistry();

extern "C" NTSTATUS SysNtThawTransactions();

extern "C" NTSTATUS SysNtTraceControl(
    IN ULONG FunctionCode,
    IN PVOID InputBuffer OPTIONAL,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer OPTIONAL,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnLength);

extern "C" NTSTATUS SysNtTranslateFilePath(
    IN PFILE_PATH InputFilePath,
    IN ULONG OutputType,
    OUT PFILE_PATH OutputFilePath OPTIONAL,
    IN OUT PULONG OutputFilePathLength OPTIONAL);

extern "C" NTSTATUS SysNtUmsThreadYield(
    IN PVOID SchedulerParam);

extern "C" NTSTATUS SysNtUnloadDriver(
    IN PUNICODE_STRING DriverServiceName);

extern "C" NTSTATUS SysNtUnloadKey(
    IN POBJECT_ATTRIBUTES DestinationKeyName);

extern "C" NTSTATUS SysNtUnloadKey2(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtUnloadKeyEx(
    IN POBJECT_ATTRIBUTES TargetKey,
    IN HANDLE Event OPTIONAL);

extern "C" NTSTATUS SysNtUnlockFile(
    IN HANDLE FileHandle,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PULARGE_INTEGER ByteOffset,
    IN PULARGE_INTEGER Length,
    IN ULONG Key);

extern "C" NTSTATUS SysNtUnlockVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID * BaseAddress,
    IN PSIZE_T NumberOfBytesToUnlock,
    IN ULONG LockType);

extern "C" NTSTATUS SysNtUnmapViewOfSectionEx(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress OPTIONAL,
    IN ULONG Flags);

extern "C" NTSTATUS SysNtUnsubscribeWnfStateChange(
    IN PCWNF_STATE_NAME StateName);

extern "C" NTSTATUS SysNtUpdateWnfStateData(
    //IN PCWNF_STATE_NAME StateName,
    IN PVOID StateName,
    IN PVOID Buffer OPTIONAL,
    IN ULONG Length OPTIONAL,
    IN PCWNF_TYPE_ID TypeId OPTIONAL,
    IN PVOID ExplicitScope OPTIONAL,
    IN WNF_CHANGE_STAMP MatchingChangeStamp,
    IN ULONG CheckStamp);

extern "C" NTSTATUS SysNtVdmControl(
    IN VDMSERVICECLASS Service,
    IN OUT PVOID ServiceData);

extern "C" NTSTATUS SysNtWaitForAlertByThreadId(
    IN HANDLE Handle,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtWaitForDebugEvent(
    IN HANDLE DebugObjectHandle,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL,
    OUT PVOID WaitStateChange);

extern "C" NTSTATUS SysNtWaitForKeyedEvent(
    IN HANDLE KeyedEventHandle,
    IN PVOID Key,
    IN BOOLEAN Alertable,
    IN PLARGE_INTEGER Timeout OPTIONAL);

extern "C" NTSTATUS SysNtWaitForWorkViaWorkerFactory(
    IN HANDLE WorkerFactoryHandle,
    OUT PVOID MiniPacket);

extern "C" NTSTATUS SysNtWaitHighEventPair(
    IN HANDLE EventHandle);

extern "C" NTSTATUS SysNtWaitLowEventPair(
    IN HANDLE EventHandle);

extern "C" NTSTATUS SysNtAcquireCMFViewOwnership(
    OUT BOOLEAN TimeStamp,
    OUT BOOLEAN TokenTaken,
    IN BOOLEAN ReplaceExisting);

extern "C" NTSTATUS SysNtCancelDeviceWakeupRequest(
    IN HANDLE DeviceHandle);

extern "C" NTSTATUS SysNtClearAllSavepointsTransaction(
    IN HANDLE TransactionHandle);

extern "C" NTSTATUS SysNtClearSavepointTransaction(
    IN HANDLE TransactionHandle,
    IN ULONG SavePointId);

extern "C" NTSTATUS SysNtRollbackSavepointTransaction(
    IN HANDLE TransactionHandle,
    IN ULONG SavePointId);

extern "C" NTSTATUS SysNtSavepointTransaction(
    IN HANDLE TransactionHandle,
    IN BOOLEAN Flag,
    OUT ULONG SavePointId);

extern "C" NTSTATUS SysNtSavepointComplete(
    IN HANDLE TransactionHandle,
    IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

extern "C" NTSTATUS SysNtCreateSectionEx(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL,
    IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
    IN ULONG ExtendedParametersCount);

extern "C" NTSTATUS SysNtCreateCrossVmEvent();

extern "C" NTSTATUS SysNtGetPlugPlayEvent(
    IN HANDLE EventHandle,
    IN PVOID Context OPTIONAL,
    OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
    IN ULONG EventBufferSize);

extern "C" NTSTATUS SysNtListTransactions();

extern "C" NTSTATUS SysNtMarshallTransaction();

extern "C" NTSTATUS SysNtPullTransaction();

extern "C" NTSTATUS SysNtReleaseCMFViewOwnership();

extern "C" NTSTATUS SysNtWaitForWnfNotifications();

extern "C" NTSTATUS SysNtStartTm();

extern "C" NTSTATUS SysNtSetInformationProcess(
    IN HANDLE DeviceHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    IN PVOID ProcessInformation,
    IN ULONG Length);

extern "C" NTSTATUS SysNtRequestDeviceWakeup(
    IN HANDLE DeviceHandle);

extern "C" NTSTATUS SysNtRequestWakeupLatency(
    IN ULONG LatencyTime);

extern "C" NTSTATUS SysNtManageHotPatch(
    IN ULONG UnknownParameter1,
    IN ULONG UnknownParameter2,
    IN ULONG UnknownParameter3,
    IN ULONG UnknownParameter4);

extern "C" NTSTATUS SysNtContinueEx(
    IN PCONTEXT ContextRecord,
    IN PKCONTINUE_ARGUMENT ContinueArgument);

typedef struct _SYSCALL {
    WORD wSyscallNr;
    DWORD dwCryptedHash;
    PVOID pRecycled;
} SYSCALL, * PSYSCALL;

typedef struct _VX_TABLE {
    SYSCALL SysNtAccessCheck;
    SYSCALL SysNtWorkerFactoryWorkerReady;
    SYSCALL SysNtAcceptConnectPort;
    SYSCALL SysNtMapUserPhysicalPagesScatter;
    SYSCALL SysNtWaitForSingleObject;
    SYSCALL SysNtCallbackReturn;
    SYSCALL SysNtReadFile;
    SYSCALL SysNtDeviceIoControlFile;
    SYSCALL SysNtWriteFile;
    SYSCALL SysNtRemoveIoCompletion;
    SYSCALL SysNtReleaseSemaphore;
    SYSCALL SysNtReplyWaitReceivePort;
    SYSCALL SysNtReplyPort;
    SYSCALL SysNtSetInformationThread;
    SYSCALL SysNtSetEvent;
    SYSCALL SysNtClose;
    SYSCALL SysNtQueryObject;
    SYSCALL SysNtQueryInformationFile;
    SYSCALL SysNtOpenKey;
    SYSCALL SysNtEnumerateValueKey;
    SYSCALL SysNtFindAtom;
    SYSCALL SysNtQueryDefaultLocale;
    SYSCALL SysNtQueryKey;
    SYSCALL SysNtQueryValueKey;
    SYSCALL SysNtAllocateVirtualMemory;
    SYSCALL SysNtQueryInformationProcess;
    SYSCALL SysNtWaitForMultipleObjects32;
    SYSCALL SysNtWriteFileGather;
    SYSCALL SysNtCreateKey;
    SYSCALL SysNtFreeVirtualMemory;
    SYSCALL SysNtImpersonateClientOfPort;
    SYSCALL SysNtReleaseMutant;
    SYSCALL SysNtQueryInformationToken;
    SYSCALL SysNtRequestWaitReplyPort;
    SYSCALL SysNtQueryVirtualMemory;
    SYSCALL SysNtOpenThreadToken;
    SYSCALL SysNtQueryInformationThread;
    SYSCALL SysNtOpenProcess;
    SYSCALL SysNtSetInformationFile;
    SYSCALL SysNtMapViewOfSection;
    SYSCALL SysNtAccessCheckAndAuditAlarm;
    SYSCALL SysNtUnmapViewOfSection;
    SYSCALL SysNtReplyWaitReceivePortEx;
    SYSCALL SysNtTerminateProcess;
    SYSCALL SysNtSetEventBoostPriority;
    SYSCALL SysNtReadFileScatter;
    SYSCALL SysNtOpenThreadTokenEx;
    SYSCALL SysNtOpenProcessTokenEx;
    SYSCALL SysNtQueryPerformanceCounter;
    SYSCALL SysNtEnumerateKey;
    SYSCALL SysNtOpenFile;
    SYSCALL SysNtDelayExecution;
    SYSCALL SysNtQueryDirectoryFile;
    SYSCALL SysNtQuerySystemInformation;
    SYSCALL SysNtOpenSection;
    SYSCALL SysNtQueryTimer;
    SYSCALL SysNtFsControlFile;
    SYSCALL SysNtWriteVirtualMemory;
    SYSCALL SysNtCloseObjectAuditAlarm;
    SYSCALL SysNtDuplicateObject;
    SYSCALL SysNtQueryAttributesFile;
    SYSCALL SysNtClearEvent;
    SYSCALL SysNtReadVirtualMemory;
    SYSCALL SysNtOpenEvent;
    SYSCALL SysNtAdjustPrivilegesToken;
    SYSCALL SysNtDuplicateToken;
    SYSCALL SysNtContinue;
    SYSCALL SysNtQueryDefaultUILanguage;
    SYSCALL SysNtQueueApcThread;
    SYSCALL SysNtYieldExecution;
    SYSCALL SysNtAddAtom;
    SYSCALL SysNtCreateEvent;
    SYSCALL SysNtQueryVolumeInformationFile;
    SYSCALL SysNtCreateSection;
    SYSCALL SysNtFlushBuffersFile;
    SYSCALL SysNtApphelpCacheControl;
    SYSCALL SysNtCreateProcessEx;
    SYSCALL SysNtCreateThread;
    SYSCALL SysNtIsProcessInJob;
    SYSCALL SysNtProtectVirtualMemory;
    SYSCALL SysNtQuerySection;
    SYSCALL SysNtResumeThread;
    SYSCALL SysNtTerminateThread;
    SYSCALL SysNtReadRequestData;
    SYSCALL SysNtCreateFile;
    SYSCALL SysNtQueryEvent;
    SYSCALL SysNtWriteRequestData;
    SYSCALL SysNtOpenDirectoryObject;
    SYSCALL SysNtAccessCheckByTypeAndAuditAlarm;
    SYSCALL SysNtWaitForMultipleObjects;
    SYSCALL SysNtSetInformationObject;
    SYSCALL SysNtCancelIoFile;
    SYSCALL SysNtTraceEvent;
    SYSCALL SysNtPowerInformation;
    SYSCALL SysNtSetValueKey;
    SYSCALL SysNtCancelTimer;
    SYSCALL SysNtSetTimer;
    SYSCALL SysNtAccessCheckByType;
    SYSCALL SysNtAccessCheckByTypeResultList;
    SYSCALL SysNtAccessCheckByTypeResultListAndAuditAlarm;
    SYSCALL SysNtAccessCheckByTypeResultListAndAuditAlarmByHandle;
    SYSCALL SysNtAcquireProcessActivityReference;
    SYSCALL SysNtAddAtomEx;
    SYSCALL SysNtAddBootEntry;
    SYSCALL SysNtAddDriverEntry;
    SYSCALL SysNtAdjustGroupsToken;
    SYSCALL SysNtAdjustTokenClaimsAndDeviceGroups;
    SYSCALL SysNtAlertResumeThread;
    SYSCALL SysNtAlertThread;
    SYSCALL SysNtAlertThreadByThreadId;
    SYSCALL SysNtAllocateLocallyUniqueId;
    SYSCALL SysNtAllocateReserveObject;
    SYSCALL SysNtAllocateUserPhysicalPages;
    SYSCALL SysNtAllocateUuids;
    SYSCALL SysNtAllocateVirtualMemoryEx;
    SYSCALL SysNtAlpcAcceptConnectPort;
    SYSCALL SysNtAlpcCancelMessage;
    SYSCALL SysNtAlpcConnectPort;
    SYSCALL SysNtAlpcConnectPortEx;
    SYSCALL SysNtAlpcCreatePort;
    SYSCALL SysNtAlpcCreatePortSection;
    SYSCALL SysNtAlpcCreateResourceReserve;
    SYSCALL SysNtAlpcCreateSectionView;
    SYSCALL SysNtAlpcCreateSecurityContext;
    SYSCALL SysNtAlpcDeletePortSection;
    SYSCALL SysNtAlpcDeleteResourceReserve;
    SYSCALL SysNtAlpcDeleteSectionView;
    SYSCALL SysNtAlpcDeleteSecurityContext;
    SYSCALL SysNtAlpcDisconnectPort;
    SYSCALL SysNtAlpcImpersonateClientContainerOfPort;
    SYSCALL SysNtAlpcImpersonateClientOfPort;
    SYSCALL SysNtAlpcOpenSenderProcess;
    SYSCALL SysNtAlpcOpenSenderThread;
    SYSCALL SysNtAlpcQueryInformation;
    SYSCALL SysNtAlpcQueryInformationMessage;
    SYSCALL SysNtAlpcRevokeSecurityContext;
    SYSCALL SysNtAlpcSendWaitReceivePort;
    SYSCALL SysNtAlpcSetInformation;
    SYSCALL SysNtAreMappedFilesTheSame;
    SYSCALL SysNtAssignProcessToJobObject;
    SYSCALL SysNtAssociateWaitCompletionPacket;
    SYSCALL SysNtCallEnclave;
    SYSCALL SysNtCancelIoFileEx;
    SYSCALL SysNtCancelSynchronousIoFile;
    SYSCALL SysNtCancelTimer2;
    SYSCALL SysNtCancelWaitCompletionPacket;
    SYSCALL SysNtCommitComplete;
    SYSCALL SysNtCommitEnlistment;
    SYSCALL SysNtCommitRegistryTransaction;
    SYSCALL SysNtCommitTransaction;
    SYSCALL SysNtCompactKeys;
    SYSCALL SysNtCompareObjects;
    SYSCALL SysNtCompareSigningLevels;
    SYSCALL SysNtCompareTokens;
    SYSCALL SysNtCompleteConnectPort;
    SYSCALL SysNtCompressKey;
    SYSCALL SysNtConnectPort;
    SYSCALL SysNtConvertBetweenAuxiliaryCounterAndPerformanceCounter;
    SYSCALL SysNtCreateDebugObject;
    SYSCALL SysNtCreateDirectoryObject;
    SYSCALL SysNtCreateDirectoryObjectEx;
    SYSCALL SysNtCreateEnclave;
    SYSCALL SysNtCreateEnlistment;
    SYSCALL SysNtCreateEventPair;
    SYSCALL SysNtCreateIRTimer;
    SYSCALL SysNtCreateIoCompletion;
    SYSCALL SysNtCreateJobObject;
    SYSCALL SysNtCreateJobSet;
    SYSCALL SysNtCreateKeyTransacted;
    SYSCALL SysNtCreateKeyedEvent;
    SYSCALL SysNtCreateLowBoxToken;
    SYSCALL SysNtCreateMailslotFile;
    SYSCALL SysNtCreateMutant;
    SYSCALL SysNtCreateNamedPipeFile;
    SYSCALL SysNtCreatePagingFile;
    SYSCALL SysNtCreatePartition;
    SYSCALL SysNtCreatePort;
    SYSCALL SysNtCreatePrivateNamespace;
    SYSCALL SysNtCreateProcess;
    SYSCALL SysNtCreateProfile;
    SYSCALL SysNtCreateProfileEx;
    SYSCALL SysNtCreateRegistryTransaction;
    SYSCALL SysNtCreateResourceManager;
    SYSCALL SysNtCreateSemaphore;
    SYSCALL SysNtCreateSymbolicLinkObject;
    SYSCALL SysNtCreateThreadEx;
    SYSCALL SysNtCreateTimer;
    SYSCALL SysNtCreateTimer2;
    SYSCALL SysNtCreateToken;
    SYSCALL SysNtCreateTokenEx;
    SYSCALL SysNtCreateTransaction;
    SYSCALL SysNtCreateTransactionManager;
    SYSCALL SysNtCreateUserProcess;
    SYSCALL SysNtCreateWaitCompletionPacket;
    SYSCALL SysNtCreateWaitablePort;
    SYSCALL SysNtCreateWnfStateName;
    SYSCALL SysNtCreateWorkerFactory;
    SYSCALL SysNtDebugActiveProcess;
    SYSCALL SysNtDebugContinue;
    SYSCALL SysNtDeleteAtom;
    SYSCALL SysNtDeleteBootEntry;
    SYSCALL SysNtDeleteDriverEntry;
    SYSCALL SysNtDeleteFile;
    SYSCALL SysNtDeleteKey;
    SYSCALL SysNtDeleteObjectAuditAlarm;
    SYSCALL SysNtDeletePrivateNamespace;
    SYSCALL SysNtDeleteValueKey;
    SYSCALL SysNtDeleteWnfStateData;
    SYSCALL SysNtDeleteWnfStateName;
    SYSCALL SysNtDisableLastKnownGood;
    SYSCALL SysNtDisplayString;
    SYSCALL SysNtDrawText;
    SYSCALL SysNtEnableLastKnownGood;
    SYSCALL SysNtEnumerateBootEntries;
    SYSCALL SysNtEnumerateDriverEntries;
    SYSCALL SysNtEnumerateSystemEnvironmentValuesEx;
    SYSCALL SysNtEnumerateTransactionObject;
    SYSCALL SysNtExtendSection;
    SYSCALL SysNtFilterBootOption;
    SYSCALL SysNtFilterToken;
    SYSCALL SysNtFilterTokenEx;
    SYSCALL SysNtFlushBuffersFileEx;
    SYSCALL SysNtFlushInstallUILanguage;
    SYSCALL SysNtFlushInstructionCache;
    SYSCALL SysNtFlushKey;
    SYSCALL SysNtFlushProcessWriteBuffers;
    SYSCALL SysNtFlushVirtualMemory;
    SYSCALL SysNtFlushWriteBuffer;
    SYSCALL SysNtFreeUserPhysicalPages;
    SYSCALL SysNtFreezeRegistry;
    SYSCALL SysNtFreezeTransactions;
    SYSCALL SysNtGetCachedSigningLevel;
    SYSCALL SysNtGetCompleteWnfStateSubscription;
    SYSCALL SysNtGetContextThread;
    SYSCALL SysNtGetCurrentProcessorNumber;
    SYSCALL SysNtGetCurrentProcessorNumberEx;
    SYSCALL SysNtGetDevicePowerState;
    SYSCALL SysNtGetMUIRegistryInfo;
    SYSCALL SysNtGetNextProcess;
    SYSCALL SysNtGetNextThread;
    SYSCALL SysNtGetNlsSectionPtr;
    SYSCALL SysNtGetNotificationResourceManager;
    SYSCALL SysNtGetWriteWatch;
    SYSCALL SysNtImpersonateAnonymousToken;
    SYSCALL SysNtImpersonateThread;
    SYSCALL SysNtInitializeEnclave;
    SYSCALL SysNtInitializeNlsFiles;
    SYSCALL SysNtInitializeRegistry;
    SYSCALL SysNtInitiatePowerAction;
    SYSCALL SysNtIsSystemResumeAutomatic;
    SYSCALL SysNtIsUILanguageComitted;
    SYSCALL SysNtListenPort;
    SYSCALL SysNtLoadDriver;
    SYSCALL SysNtLoadEnclaveData;
    SYSCALL SysNtLoadKey;
    SYSCALL SysNtLoadKey2;
    SYSCALL SysNtLoadKeyEx;
    SYSCALL SysNtLockFile;
    SYSCALL SysNtLockProductActivationKeys;
    SYSCALL SysNtLockRegistryKey;
    SYSCALL SysNtLockVirtualMemory;
    SYSCALL SysNtMakePermanentObject;
    SYSCALL SysNtMakeTemporaryObject;
    SYSCALL SysNtManagePartition;
    SYSCALL SysNtMapCMFModule;
    SYSCALL SysNtMapUserPhysicalPages;
    SYSCALL SysNtMapViewOfSectionEx;
    SYSCALL SysNtModifyBootEntry;
    SYSCALL SysNtModifyDriverEntry;
    SYSCALL SysNtNotifyChangeDirectoryFile;
    SYSCALL SysNtNotifyChangeDirectoryFileEx;
    SYSCALL SysNtNotifyChangeKey;
    SYSCALL SysNtNotifyChangeMultipleKeys;
    SYSCALL SysNtNotifyChangeSession;
    SYSCALL SysNtOpenEnlistment;
    SYSCALL SysNtOpenEventPair;
    SYSCALL SysNtOpenIoCompletion;
    SYSCALL SysNtOpenJobObject;
    SYSCALL SysNtOpenKeyEx;
    SYSCALL SysNtOpenKeyTransacted;
    SYSCALL SysNtOpenKeyTransactedEx;
    SYSCALL SysNtOpenKeyedEvent;
    SYSCALL SysNtOpenMutant;
    SYSCALL SysNtOpenObjectAuditAlarm;
    SYSCALL SysNtOpenPartition;
    SYSCALL SysNtOpenPrivateNamespace;
    SYSCALL SysNtOpenProcessToken;
    SYSCALL SysNtOpenRegistryTransaction;
    SYSCALL SysNtOpenResourceManager;
    SYSCALL SysNtOpenSemaphore;
    SYSCALL SysNtOpenSession;
    SYSCALL SysNtOpenSymbolicLinkObject;
    SYSCALL SysNtOpenThread;
    SYSCALL SysNtOpenTimer;
    SYSCALL SysNtOpenTransaction;
    SYSCALL SysNtOpenTransactionManager;
    SYSCALL SysNtPlugPlayControl;
    SYSCALL SysNtPrePrepareComplete;
    SYSCALL SysNtPrePrepareEnlistment;
    SYSCALL SysNtPrepareComplete;
    SYSCALL SysNtPrepareEnlistment;
    SYSCALL SysNtPrivilegeCheck;
    SYSCALL SysNtPrivilegeObjectAuditAlarm;
    SYSCALL SysNtPrivilegedServiceAuditAlarm;
    SYSCALL SysNtPropagationComplete;
    SYSCALL SysNtPropagationFailed;
    SYSCALL SysNtPulseEvent;
    SYSCALL SysNtQueryAuxiliaryCounterFrequency;
    SYSCALL SysNtQueryBootEntryOrder;
    SYSCALL SysNtQueryBootOptions;
    SYSCALL SysNtQueryDebugFilterState;
    SYSCALL SysNtQueryDirectoryFileEx;
    SYSCALL SysNtQueryDirectoryObject;
    SYSCALL SysNtQueryDriverEntryOrder;
    SYSCALL SysNtQueryEaFile;
    SYSCALL SysNtQueryFullAttributesFile;
    SYSCALL SysNtQueryInformationAtom;
    SYSCALL SysNtQueryInformationByName;
    SYSCALL SysNtQueryInformationEnlistment;
    SYSCALL SysNtQueryInformationJobObject;
    SYSCALL SysNtQueryInformationPort;
    SYSCALL SysNtQueryInformationResourceManager;
    SYSCALL SysNtQueryInformationTransaction;
    SYSCALL SysNtQueryInformationTransactionManager;
    SYSCALL SysNtQueryInformationWorkerFactory;
    SYSCALL SysNtQueryInstallUILanguage;
    SYSCALL SysNtQueryIntervalProfile;
    SYSCALL SysNtQueryIoCompletion;
    SYSCALL SysNtQueryLicenseValue;
    SYSCALL SysNtQueryMultipleValueKey;
    SYSCALL SysNtQueryMutant;
    SYSCALL SysNtQueryOpenSubKeys;
    SYSCALL SysNtQueryOpenSubKeysEx;
    SYSCALL SysNtQueryPortInformationProcess;
    SYSCALL SysNtQueryQuotaInformationFile;
    SYSCALL SysNtQuerySecurityAttributesToken;
    SYSCALL SysNtQuerySecurityObject;
    SYSCALL SysNtQuerySecurityPolicy;
    SYSCALL SysNtQuerySemaphore;
    SYSCALL SysNtQuerySymbolicLinkObject;
    SYSCALL SysNtQuerySystemEnvironmentValue;
    SYSCALL SysNtQuerySystemEnvironmentValueEx;
    SYSCALL SysNtQuerySystemInformationEx;
    SYSCALL SysNtQueryTimerResolution;
    SYSCALL SysNtQueryWnfStateData;
    SYSCALL SysNtQueryWnfStateNameInformation;
    SYSCALL SysNtQueueApcThreadEx;
    SYSCALL SysNtRaiseException;
    SYSCALL SysNtRaiseHardError;
    SYSCALL SysNtReadOnlyEnlistment;
    SYSCALL SysNtRecoverEnlistment;
    SYSCALL SysNtRecoverResourceManager;
    SYSCALL SysNtRecoverTransactionManager;
    SYSCALL SysNtRegisterProtocolAddressInformation;
    SYSCALL SysNtRegisterThreadTerminatePort;
    SYSCALL SysNtReleaseKeyedEvent;
    SYSCALL SysNtReleaseWorkerFactoryWorker;
    SYSCALL SysNtRemoveIoCompletionEx;
    SYSCALL SysNtRemoveProcessDebug;
    SYSCALL SysNtRenameKey;
    SYSCALL SysNtRenameTransactionManager;
    SYSCALL SysNtReplaceKey;
    SYSCALL SysNtReplacePartitionUnit;
    SYSCALL SysNtReplyWaitReplyPort;
    SYSCALL SysNtRequestPort;
    SYSCALL SysNtResetEvent;
    SYSCALL SysNtResetWriteWatch;
    SYSCALL SysNtRestoreKey;
    SYSCALL SysNtResumeProcess;
    SYSCALL SysNtRevertContainerImpersonation;
    SYSCALL SysNtRollbackComplete;
    SYSCALL SysNtRollbackEnlistment;
    SYSCALL SysNtRollbackRegistryTransaction;
    SYSCALL SysNtRollbackTransaction;
    SYSCALL SysNtRollforwardTransactionManager;
    SYSCALL SysNtSaveKey;
    SYSCALL SysNtSaveKeyEx;
    SYSCALL SysNtSaveMergedKeys;
    SYSCALL SysNtSecureConnectPort;
    SYSCALL SysNtSerializeBoot;
    SYSCALL SysNtSetBootEntryOrder;
    SYSCALL SysNtSetBootOptions;
    SYSCALL SysNtSetCachedSigningLevel;
    SYSCALL SysNtSetCachedSigningLevel2;
    SYSCALL SysNtSetContextThread;
    SYSCALL SysNtSetDebugFilterState;
    SYSCALL SysNtSetDefaultHardErrorPort;
    SYSCALL SysNtSetDefaultLocale;
    SYSCALL SysNtSetDefaultUILanguage;
    SYSCALL SysNtSetDriverEntryOrder;
    SYSCALL SysNtSetEaFile;
    SYSCALL SysNtSetHighEventPair;
    SYSCALL SysNtSetHighWaitLowEventPair;
    SYSCALL SysNtSetIRTimer;
    SYSCALL SysNtSetInformationDebugObject;
    SYSCALL SysNtSetInformationEnlistment;
    SYSCALL SysNtSetInformationJobObject;
    SYSCALL SysNtSetInformationKey;
    SYSCALL SysNtSetInformationResourceManager;
    SYSCALL SysNtSetInformationSymbolicLink;
    SYSCALL SysNtSetInformationToken;
    SYSCALL SysNtSetInformationTransaction;
    SYSCALL SysNtSetInformationTransactionManager;
    SYSCALL SysNtSetInformationVirtualMemory;
    SYSCALL SysNtSetInformationWorkerFactory;
    SYSCALL SysNtSetIntervalProfile;
    SYSCALL SysNtSetIoCompletion;
    SYSCALL SysNtSetIoCompletionEx;
    SYSCALL SysNtSetLdtEntries;
    SYSCALL SysNtSetLowEventPair;
    SYSCALL SysNtSetLowWaitHighEventPair;
    SYSCALL SysNtSetQuotaInformationFile;
    SYSCALL SysNtSetSecurityObject;
    SYSCALL SysNtSetSystemEnvironmentValue;
    SYSCALL SysNtSetSystemEnvironmentValueEx;
    SYSCALL SysNtSetSystemInformation;
    SYSCALL SysNtSetSystemPowerState;
    SYSCALL SysNtSetSystemTime;
    SYSCALL SysNtSetThreadExecutionState;
    SYSCALL SysNtSetTimer2;
    SYSCALL SysNtSetTimerEx;
    SYSCALL SysNtSetTimerResolution;
    SYSCALL SysNtSetUuidSeed;
    SYSCALL SysNtSetVolumeInformationFile;
    SYSCALL SysNtSetWnfProcessNotificationEvent;
    SYSCALL SysNtShutdownSystem;
    SYSCALL SysNtShutdownWorkerFactory;
    SYSCALL SysNtSignalAndWaitForSingleObject;
    SYSCALL SysNtSinglePhaseReject;
    SYSCALL SysNtStartProfile;
    SYSCALL SysNtStopProfile;
    SYSCALL SysNtSubscribeWnfStateChange;
    SYSCALL SysNtSuspendProcess;
    SYSCALL SysNtSuspendThread;
    SYSCALL SysNtSystemDebugControl;
    SYSCALL SysNtTerminateEnclave;
    SYSCALL SysNtTerminateJobObject;
    SYSCALL SysNtTestAlert;
    SYSCALL SysNtThawRegistry;
    SYSCALL SysNtThawTransactions;
    SYSCALL SysNtTraceControl;
    SYSCALL SysNtTranslateFilePath;
    SYSCALL SysNtUmsThreadYield;
    SYSCALL SysNtUnloadDriver;
    SYSCALL SysNtUnloadKey;
    SYSCALL SysNtUnloadKey2;
    SYSCALL SysNtUnloadKeyEx;
    SYSCALL SysNtUnlockFile;
    SYSCALL SysNtUnlockVirtualMemory;
    SYSCALL SysNtUnmapViewOfSectionEx;
    SYSCALL SysNtUnsubscribeWnfStateChange;
    SYSCALL SysNtUpdateWnfStateData;
    SYSCALL SysNtVdmControl;
    SYSCALL SysNtWaitForAlertByThreadId;
    SYSCALL SysNtWaitForDebugEvent;
    SYSCALL SysNtWaitForKeyedEvent;
    SYSCALL SysNtWaitForWorkViaWorkerFactory;
    SYSCALL SysNtWaitHighEventPair;
    SYSCALL SysNtWaitLowEventPair;
    SYSCALL SysNtCreateSectionEx;
    SYSCALL SysNtCreateCrossVmEvent;
    SYSCALL SysNtSetInformationProcess;
    SYSCALL SysNtManageHotPatch;
    SYSCALL SysNtContinueEx;
    BOOL isResolved;
} VX_TABLE, * PVX_TABLE;

extern "C" VOID SyscallPrepare(WORD wSyscallNr, PVOID pRecycled);
unsigned long djb2_unicode(const wchar_t* str);
unsigned long djb2(unsigned char* str);
unsigned long xor_hash(unsigned long hash);
WCHAR* toLower(WCHAR* str);

class SystemCalls {
public:
    VX_TABLE SysTable;
    PPEB ThisPeb;
    BOOL ResolveSyscall(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD dwCryptedHash, PSYSCALL pSyscall);
    void ResolveSyscallTable();
};
