#include "Windows.h"
#include "WinHttp.h"
#include <vector>
#include <iostream>
#include <stdexcept>
#include <memory>

std::string Get(LPCWSTR domain, LPCWSTR path, DWORD port) {
    DWORD dwSize = 0, dwDownloaded = 0;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(L"Thor Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession)
        throw std::runtime_error("Failed in WinHttpConnect");

    hConnect = WinHttpConnect(hSession, domain, port, 0);
    if (!hConnect)
        throw std::runtime_error("Failed in WinHttpConnect");

    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, NULL);
    if (!hRequest)
        throw std::runtime_error("Failed in WinHttpOpenRequest");

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        throw std::runtime_error("Failed in WinHttpSendRequest");

    if (!WinHttpReceiveResponse(hRequest, NULL))
        throw std::runtime_error("Failed in WinHttpReceiveResponse");

    std::vector<unsigned char> buf;

    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            throw std::runtime_error("Error in WinHttpQueryDataAvailable");

        std::unique_ptr<char[]> pszOutBuffer(new char[dwSize + 1]);
        ZeroMemory(pszOutBuffer.get(), dwSize + 1);

        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer.get(), dwSize, &dwDownloaded))
            throw std::runtime_error("Error in WinHttpReadData");

        buf.insert(buf.end(), pszOutBuffer.get(), pszOutBuffer.get() + dwDownloaded);
    } while (dwSize > 0);

    if (buf.empty())
        throw std::runtime_error("Failed in retrieving the data with GET");

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    // Convert the buffer to std::string
    std::string result(buf.begin(), buf.end());
    return result;
}

std::string Post(LPCWSTR domain, LPCWSTR path, DWORD port, const std::string& idata) {
    DWORD headersLength = -1, dwSize = 0, dwDownloaded = 0, dwBytesWritten = 0;
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(L"Thor Agent/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        throw std::runtime_error("Failed in WinHttpConnect");
    }

    hConnect = WinHttpConnect(hSession, domain, port, 0);
    if (!hConnect) {
        throw std::runtime_error("Failed in WinHttpOpenRequest");
    }

    hRequest = WinHttpOpenRequest(hConnect, L"POST", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest)
        throw std::runtime_error("Failed to open request");

    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)idata.c_str(), idata.size(), idata.size(), 0);
    if (!bResults) {
        throw std::runtime_error("Failed in WinHttpSendRequest");
    }

    bResults = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        throw std::runtime_error("Failed in WinHttpReceiveResponse");
    }

    std::vector<unsigned char> buf;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            throw std::runtime_error("Error in WinHttpQueryDataAvailable");
        }

        std::unique_ptr<char[]> pszOutBuffer(new char[dwSize + 1]);
        ZeroMemory(pszOutBuffer.get(), dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer.get(), dwSize, &dwDownloaded)) {
            throw std::runtime_error("Error in WinHttpReadData");
        }

        buf.insert(buf.end(), pszOutBuffer.get(), pszOutBuffer.get() + dwDownloaded);
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    std::string result(buf.begin(), buf.end());
    return result;
}
