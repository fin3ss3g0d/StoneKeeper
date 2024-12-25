#include <iostream>
#include <windows.h>

#define INCREMENT_RIP 1

class VectoredExceptionHandler {
public:
    VectoredExceptionHandler(int type);
    ~VectoredExceptionHandler();

private:
    static LONG CALLBACK IncrementRipVectoredHandler(PEXCEPTION_POINTERS pExceptionInfo);
    PVOID handler;
};