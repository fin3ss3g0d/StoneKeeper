#pragma once

class SecureString;
// Forward declaration of the SecureVector template class
template<typename T> class SecureVector;

class Crypt {
public:
    static Crypt& Get() {
        static Crypt crypt; // Guaranteed to be destroyed and instantiated on first use.
        return crypt;
    }

    // Public methods
    static void PrintHex(const char* label, const unsigned char* buf, size_t len);
    // Decrypts the AES key using Instance::XorKey
    static SecureVector<unsigned char> DecodeHex(const SecureString& hex);
    static SecureString AesEncrypt(const SecureString& data, const SecureVector<unsigned char>& key, const SecureVector<unsigned char>& iv);
    static SecureString AesDecrypt(const SecureString& data, const SecureVector<unsigned char>& key, const SecureVector<unsigned char>& iv, bool isHex);
    static SecureVector<unsigned char> XorEncryptDecrypt(const SecureVector<unsigned char>& input, const SecureVector<unsigned char>& key);
    static void GenerateChaCha20KeyAndNonce();
    static void ChaCha20EncryptDecryptInPlace(unsigned char* data, size_t data_len, const unsigned char* key, const unsigned char* nonce);
    static int GenerateRandomInteger(int min, int max);
    static SecureString GenerateRandomString(size_t length);

    // Public members
    static SecureVector<unsigned char> ChaCha20Key;
    static SecureVector<unsigned char> ChaCha20Nonce;

    // Delete copy/move constructors and assignment operators
    Crypt(Crypt const&) = delete;
    void operator=(Crypt const&) = delete;
    Crypt(Crypt&&) = delete;
    void operator=(Crypt&&) = delete;

private:
    Crypt() {};

    // Private methods
    static SecureString base64_encode(const SecureVector<unsigned char>& input);
    static int calcDecodeLength(const char* b64input, int length);
    static SecureVector<unsigned char> base64_decode(const SecureString& input);

    // Private members
};
