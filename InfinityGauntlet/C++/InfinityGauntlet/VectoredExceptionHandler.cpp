#include "VectoredExceptionHandler.hpp"
#include "Win32.hpp"

VectoredExceptionHandler::VectoredExceptionHandler(int type) {
    pRtlAddVectoredExceptionHandler _pRtlAddVectoredExceptionHandler = (pRtlAddVectoredExceptionHandler)Win32::NtdllTable.pRtlAddVectoredExceptionHandler.pAddress;

    // Install the handler based on the type
    switch (type) {
    case INCREMENT_RIP:
        handler = _pRtlAddVectoredExceptionHandler(0, IncrementRipVectoredHandler);
        break;
    }
}

VectoredExceptionHandler::~VectoredExceptionHandler() {
    pRtlRemoveVectoredExceptionHandler _pRtlRemoveVectoredExceptionHandler = (pRtlRemoveVectoredExceptionHandler)Win32::NtdllTable.pRtlRemoveVectoredExceptionHandler.pAddress;

    // Remove the handler on destruction
    _pRtlRemoveVectoredExceptionHandler(handler);
}

LONG CALLBACK VectoredExceptionHandler::IncrementRipVectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // Check for an access violation exception
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // Debug
        std::cerr << "Access violation caught by vectored exception handler." << std::endl;

        // Attempt to fix or skip the issue
        // This example merely advances the instruction pointer, which can lead to further issues.
#ifdef _M_X64
// 64-bit: Increment the instruction pointer.
        pExceptionInfo->ContextRecord->Rip += 1;
#elif defined(_M_IX86)
// 32-bit: Increment the instruction pointer.
        pExceptionInfo->ContextRecord->Eip += 1;
#endif

        return EXCEPTION_CONTINUE_EXECUTION; // Continue execution
    }

    // Handle other exceptions normally
    return EXCEPTION_CONTINUE_SEARCH;
}