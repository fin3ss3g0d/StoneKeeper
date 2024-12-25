#include <string>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <windows.h>
#include <wincrypt.h>
#include <cstring>
#include <iomanip>

std::string base64_encode(const std::vector<unsigned char>& input) {
    DWORD base64Size = 0;
    if (!CryptBinaryToStringA(input.data(), input.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Size)) {
        std::cerr << "CryptBinaryToStringA failed with error code: " << GetLastError() << std::endl;
        return "";
    }

    std::vector<char> base64Vector(base64Size);
    if (!CryptBinaryToStringA(input.data(), input.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64Vector.data(), &base64Size)) {
        std::cerr << "CryptBinaryToStringA failed with error code: " << GetLastError() << std::endl;
        return "";
    }

    return std::string(base64Vector.begin(), base64Vector.end());
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    DWORD binarySize = 0;
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binarySize, NULL, NULL)) {
        throw std::runtime_error("CryptStringToBinaryA failed with error code: " + std::to_string(GetLastError()));
    }

    std::vector<unsigned char> binaryVector(binarySize);
    if (!CryptStringToBinaryA(input.c_str(), 0, CRYPT_STRING_BASE64, binaryVector.data(), &binarySize, NULL, NULL)) {
        throw std::runtime_error("CryptStringToBinaryA failed with error code: " + std::to_string(GetLastError()));
    }

    return binaryVector;
}

// Function to decode a hex string to bytes
std::vector<unsigned char> decodeHex(const std::string& hex) {
    size_t len = hex.length();
    std::vector<unsigned char> bytes;

    for (size_t i = 0; i < len; i += 2) {
        unsigned char byte = (unsigned char)stoi(hex.substr(i, 2), nullptr, 16);
        bytes.push_back(byte);
    }

    return bytes;
}

// Function to perform XOR decryption
std::vector<unsigned char> xorDecrypt(const std::vector<unsigned char>& input, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> output(input.size());
    size_t keyLen = key.size();

    for (size_t i = 0; i < input.size(); i++) {
        output[i] = input[i] ^ key[i % keyLen];
    }

    return output;
}

int XORTest() {
    // Replace with your XOR encrypted AES key hex string and XOR key hex string
    std::string encryptedAESKeyHex = "7ec2de582023d2d9dc660c656b1bf9f9505998547011653d4d478f16c3a4af71";
    std::string xorKeyHex = "7728784929b94b71d19e1fcea315270eecac31aac2bf0a694954234135310503";

    std::vector<unsigned char> encryptedAESKeyBytes = decodeHex(encryptedAESKeyHex);
    std::vector<unsigned char> xorKeyBytes = decodeHex(xorKeyHex);

    std::vector<unsigned char> decryptedAESKey = xorDecrypt(encryptedAESKeyBytes, xorKeyBytes);

    // Print the decrypted AES key in hex format
    for (auto b : decryptedAESKey) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return 0;
}

std::string AESEncrypt(const std::vector<unsigned char>& data, const std::vector<unsigned char>& masterKey) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    std::vector<unsigned char> cipher;

    try {
        constexpr DWORD BLOCK_SIZE = 16;
        DWORD dataLen = static_cast<DWORD>(data.size());

        DWORD totalRange = ((dataLen + BLOCK_SIZE - 1) / BLOCK_SIZE) * BLOCK_SIZE;
        std::vector<BYTE> cipherAlloc(totalRange);
        std::memcpy(cipherAlloc.data(), data.data(), data.size());

        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("CryptAcquireContextW failed");
        }

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            throw std::runtime_error("CryptCreateHash failed");
        }

        if (!CryptHashData(hHash, (BYTE*)masterKey.data(), static_cast<DWORD>(masterKey.size()), 0)) {
            throw std::runtime_error("CryptHashData failed");
        }

        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            throw std::runtime_error("CryptDeriveKey failed");
        }

        if (!CryptEncrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, cipherAlloc.data(), &dataLen, totalRange)) {
            throw std::runtime_error("CryptEncrypt failed");
        }

        cipher.assign(cipherAlloc.begin(), cipherAlloc.begin() + totalRange);

        // Clean up resources
        if (hProv) CryptReleaseContext(hProv, 0);
        if (hHash) CryptDestroyHash(hHash);
        if (hKey) CryptDestroyKey(hKey);

        return base64_encode(cipher);
    }
    catch (const std::runtime_error& e) {
        // Clean up resources in case of failure
        if (hProv) CryptReleaseContext(hProv, 0);
        if (hHash) CryptDestroyHash(hHash);
        if (hKey) CryptDestroyKey(hKey);

        throw;
    }
}

std::string AESDecrypt(const std::string& base64Data, const std::vector<unsigned char>& masterKey) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    std::vector<unsigned char> plain;

    try {
        // Decode Base64 to binary
        DWORD binarySize = 0;
        if (!CryptStringToBinaryA(base64Data.c_str(), 0, CRYPT_STRING_BASE64, NULL, &binarySize, NULL, NULL)) {
            throw std::runtime_error("CryptStringToBinaryA failed to get buffer size");
        }

        std::vector<unsigned char> binaryData(binarySize);
        if (!CryptStringToBinaryA(base64Data.c_str(), 0, CRYPT_STRING_BASE64, binaryData.data(), &binarySize, NULL, NULL)) {
            throw std::runtime_error("CryptStringToBinaryA failed to decode Base64");
        }

        // Initialize cryptographic service provider
        if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            throw std::runtime_error("CryptAcquireContextW failed");
        }

        // Create hash object
        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            throw std::runtime_error("CryptCreateHash failed");
        }

        // Hash the master key
        if (!CryptHashData(hHash, (BYTE*)masterKey.data(), static_cast<DWORD>(masterKey.size()), 0)) {
            throw std::runtime_error("CryptHashData failed");
        }

        // Derive encryption key from hash
        if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
            throw std::runtime_error("CryptDeriveKey failed");
        }

        DWORD totalRange = static_cast<DWORD>(binaryData.size());
        std::vector<BYTE> plainAlloc(totalRange);
        std::memcpy(plainAlloc.data(), binaryData.data(), binaryData.size());

        // Decrypt the data
        if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, TRUE, 0, plainAlloc.data(), &totalRange)) {
            throw std::runtime_error("CryptDecrypt failed");
        }

        // Convert decrypted data to std::string
        std::string decryptedString(plainAlloc.begin(), plainAlloc.begin() + totalRange);

        // Clean up resources
        if (hProv) CryptReleaseContext(hProv, 0);
        if (hHash) CryptDestroyHash(hHash);
        if (hKey) CryptDestroyKey(hKey);

        return decryptedString;
    }
    catch (const std::runtime_error& e) {
        // Clean up resources in case of failure
        if (hProv) CryptReleaseContext(hProv, 0);
        if (hHash) CryptDestroyHash(hHash);
        if (hKey) CryptDestroyKey(hKey);

        // Re-throw the caught exception
        throw;
    }
}

int main() {
    std::vector<unsigned char> data = { 0x48, 0x65, 0x6c, 0x6c, 0x6f };  // "Hello"
    std::vector<unsigned char> cipher;
    std::vector<unsigned char> decrypted;
    std::vector<unsigned char> masterKey = { 0x6b, 0x65, 0x79 };  // "key"

    try {
        std::string base64String = AESEncrypt(data, masterKey);
        std::cout << "Base64 Encrypted String: " << base64String << std::endl;
        std::string decryptedString = AESDecrypt(base64String, masterKey);
        std::cout << "Decrypted String: " << decryptedString << std::endl;
    }
    catch (const std::runtime_error& e) {
		std::cerr << "Error: " << e.what() << '\n';
		return 1;
	}    

    return XORTest();
}
