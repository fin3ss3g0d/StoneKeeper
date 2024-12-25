#pragma once
#include <Windows.h>
#include <array>

#define MAX_HEAP_ALLOCATIONS 10 * 1000000 // Enough for 10 million (~381.47 MB) HeapAllocation structures
#define RTL_HEAP_BUSY 0x0001
// Forward declaration of the pointer type
struct _RTL_HEAP_WALK_ENTRY;  // Declare the structure name
typedef _RTL_HEAP_WALK_ENTRY* PRTL_HEAP_WALK_ENTRY;  // Declare the pointer type

// 40 bytes each
struct HeapAllocation {
    HANDLE HeapHandle;
    ULONG Flags;
    SIZE_T Size;
    PVOID BaseAddress;
    void* ReturnAddress;
};

class StackHeapCrypt {
public:
    static StackHeapCrypt& Get() {
        static StackHeapCrypt stackHeapCrypt; // Guaranteed to be destroyed and instantiated on first use.
        return stackHeapCrypt;
    }

    // Public members
    static HeapAllocation HeapAllocations[MAX_HEAP_ALLOCATIONS];
    static int HeapAllocationsIndex;

    // Public methods
    static void EncryptDecryptStacksAndHeaps(bool encrypt);

    // Delete copy/move constructors and assignment operators
    StackHeapCrypt(StackHeapCrypt const&) = delete;
    void operator=(StackHeapCrypt const&) = delete;
    StackHeapCrypt(StackHeapCrypt&&) = delete;
    void operator=(StackHeapCrypt&&) = delete;

private:
    StackHeapCrypt() {};

    // Private methods
    static void SuspendThreadsAndEncryptStacks();
    static void ChaCha20EncryptDecryptStack(void* stack_top, void* stack_base, const unsigned char* key, const unsigned char* nonce);
    static void ResumeThreadsAndDecryptStacks();
    static void EncryptDecryptHeaps();
    static bool ShouldEncryptAllocation(HeapAllocation* allocation, PRTL_HEAP_WALK_ENTRY entry);

    // Private members
};