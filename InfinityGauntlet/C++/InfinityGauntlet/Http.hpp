#pragma once
#include <string>
#include <Windows.h>

class SecureString;
class SecureWideString;

class Http {
public:
    static Http& Get() {
        static Http http; // Guaranteed to be destroyed and instantiated on first use.
        return http;
    }

    // Public members
    static SecureWideString RegisterPath;
    static SecureWideString TasksPath;
    static SecureWideString ErrorPath;

    // Public methods
    static void PopulateVariables();
    static std::pair<int, SecureString> Get(LPCWSTR domain, LPCWSTR path, DWORD port);
    static SecureString Post(LPCWSTR domain, LPCWSTR path, DWORD port, const SecureString& idata);

    // Delete copy/move constructors and assignment operators
    Http(Http const&) = delete;
    void operator=(Http const&) = delete;
    Http(Http&&) = delete;
    void operator=(Http&&) = delete;

private:
    Http() {
        PopulateVariables();
    }

    // Private members
    
    // Private methods    
};