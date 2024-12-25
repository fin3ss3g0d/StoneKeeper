#pragma once
#include <Windows.h>
#include <vector>

#define JUMP_STUB_SIZE 13
#define RTLEXITUSERPROCESS_HOOK 0
#define RTLALLOCATEHEAP_HOOK 1
#define RTLREALLOCATEHEAP_HOOK 2
#define RTLFREEHEAP_HOOK 3

struct RestoreBufferEntry {
    bool populated = false;
	std::vector<BYTE> buffer;
};

struct RestoreJumpBufferEntry {
	bool populated = false;
	PVOID buffer = nullptr;
    size_t size = 0;
};

struct RestoreBuffer {
    RestoreBufferEntry RtlExitUserProcess;
    RestoreBufferEntry RtlAllocateHeap;
    RestoreBufferEntry RtlReAllocateHeap;
    RestoreBufferEntry RtlFreeHeap;
    RestoreBufferEntry EtwEventWrite;
    RestoreBufferEntry AmsiScanBuffer;
    RestoreBufferEntry AmsiOpenSession;
}; 

struct RestoreJumpBuffer {
    RestoreJumpBufferEntry RtlExitUserProcess;
    RestoreJumpBufferEntry RtlAllocateHeap;
    RestoreJumpBufferEntry RtlReAllocateHeap;
    RestoreJumpBufferEntry RtlFreeHeap;
};

class PatcherAndHooker {
public:
    static PatcherAndHooker& Get() {
        static PatcherAndHooker patcherAndHooker; // Guaranteed to be destroyed and instantiated on first use.
        return patcherAndHooker;
    }

    // Public members

    // Public methods
    static void DoPatches(bool restore);
    static void PrepareHook(bool restore, int choice);
    static void HookHeapFunctions(bool restore);

    // Delete copy/move constructors and assignment operators
    PatcherAndHooker(PatcherAndHooker const&) = delete;
    void operator=(PatcherAndHooker const&) = delete;
    PatcherAndHooker(PatcherAndHooker&&) = delete;
    void operator=(PatcherAndHooker&&) = delete;

private:
    PatcherAndHooker();

    // Private methods
    static void PatchETW(bool restore);
    static void PatchAMSI(bool restore);    
    static size_t GetStubSize(PVOID address);
    static void InstallHook(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, DWORD dwCryptedHash, LPVOID jumpAddress, bool restore, RestoreBufferEntry* restoreBuffer, RestoreJumpBufferEntry* restoreJumpBuffer);    
    static PVOID HookedRtlAllocateHeap(HANDLE HeapHandle, ULONG Flags, SIZE_T Size);
    static PVOID HookedRtlReAllocateHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress, SIZE_T Size);
    static BOOLEAN HookedRtlFreeHeap(HANDLE HeapHandle, ULONG Flags, PVOID BaseAddress);
    static int64_t HookedRtlExitUserProcess(int64_t status);

    // Private members
    static bool AmsiLoaded;
    static RestoreBuffer RestoreBuffers;
    static RestoreJumpBuffer RestoreJumpBuffers;
    static CRITICAL_SECTION CriticalSection;
};