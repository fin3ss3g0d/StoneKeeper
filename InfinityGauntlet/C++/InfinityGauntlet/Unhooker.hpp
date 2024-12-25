#pragma once
#include "Syscalls.hpp"

class Unhooker {
public:
    static Unhooker& Get() {
        static Unhooker unhooker; // Guaranteed to be destroyed and instantiated on first use.
        return unhooker;
    }

    // Public methods
    static void DoUnhook();

    // Delete copy/move constructors and assignment operators
    Unhooker(Unhooker const&) = delete;
    void operator=(Unhooker const&) = delete;
    Unhooker(Unhooker&&) = delete;
    void operator=(Unhooker&&) = delete;

private:
    Unhooker() {}

    // Private methods
    static void Unhook(PLDR_DATA_TABLE_ENTRY hModule);

    // Private members
};