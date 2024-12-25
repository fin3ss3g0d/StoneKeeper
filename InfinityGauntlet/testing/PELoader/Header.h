#pragma once
#include <Windows.h>
#include <vector>
#include <winternl.h>
#include <stdexcept>
#include <string>
#include <iostream>

// Function prototype for NtUnmapViewOfSection
extern "C" NTSTATUS NTAPI NtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// Function prototype for NtAllocateVirtualMemory
extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Function prototype for NtWriteVirtualMemory
extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
);

extern "C" VOID InvokeImage(size_t EntryPoint);