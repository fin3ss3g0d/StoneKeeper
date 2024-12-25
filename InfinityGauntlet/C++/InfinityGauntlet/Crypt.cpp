#include "Crypt.hpp"
#include "Instance.hpp"
#include "Win32.hpp"
#include "StringCrypt.hpp"
#include "SecureException.hpp"
#include "SecureVector.hpp"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>

SecureVector<unsigned char> Crypt::ChaCha20Key(32);
SecureVector<unsigned char> Crypt::ChaCha20Nonce(12);

// Utility function to print a buffer in hex
void Crypt::PrintHex(const char* label, const unsigned char* buf, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    std::cout << std::endl;
}

int Crypt::GenerateRandomInteger(int min, int max) {
    if (min > max) {
        // Handle error: invalid range
        throw SecureException(StringCrypt::DecryptString(StringCrypt::OUTOFRANGEERROR_CRYPT));
    }

    unsigned int range = static_cast<unsigned int>(max) - min + 1; // +1 because we want inclusive range
    unsigned int randomNumber = 0;

    // Generate a secure random number until it fits within the range [0, max - min]
    do {
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&randomNumber), sizeof(randomNumber)) != 1) {
            // Handle error: random generation failed
            throw SecureException(StringCrypt::DecryptString(StringCrypt::RANDOMBYTESGENERATIONERROR_CRYPT));
        }
        // Remove the excess bits to ensure uniform distribution within the range
        randomNumber %= range;
    } while (randomNumber + min > max); // This check prevents integer overflow

    return static_cast<int>(randomNumber) + min;
}

SecureString Crypt::GenerateRandomString(size_t length) {
    const SecureString charset = StringCrypt::DecryptString(StringCrypt::NUMBERSUPPERLOWER_CRYPT);
    SecureString random_string;

    // Check if charset is not empty to avoid division by zero
    if (charset.empty()) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::CHARSETISEMPTY_CRYPT));
    }

    for (size_t i = 0; i < length; ++i) {
        unsigned char random_byte;
        do {
            // Generate a single random byte
            if (RAND_bytes(&random_byte, sizeof(random_byte)) != 1) {
                // Handle error: random generation failed
                throw SecureException(StringCrypt::DecryptString(StringCrypt::RANDOMBYTESGENERATIONERROR_CRYPT));
            }
            // Ensure the byte is within the range of the charset
        } while (random_byte >= charset.size() * (256 / charset.size()));

        // Use the random byte to pick a character from charset and append it
        random_string.append(charset[random_byte % charset.size()]);
    }

    return random_string;
}

SecureString Crypt::base64_encode(const SecureVector<unsigned char>& input) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_NEWFORBASE64FAILED_CRYPT));
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == nullptr) {
        BIO_free_all(b64);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_NEWFORMEMORYBUFFERFAILED_CRYPT));
    }

    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines - write everything in one line
    if (BIO_write(bio, input.data(), input.size()) <= 0) {
        BIO_free_all(bio);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_WRITEFAILED_CRYPT));
    }

    if (BIO_flush(bio) <= 0) {
        BIO_free_all(bio);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_FLUSHFAILED_CRYPT));
    }

    BIO_get_mem_ptr(bio, &bufferPtr);
    if (bufferPtr == nullptr) {
        BIO_free_all(bio);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_GET_MEM_PTRFAILED_CRYPT));
    }

    SecureString encodedString(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encodedString;
}

SecureVector<unsigned char> Crypt::base64_decode(const SecureString& input) {
    BIO* bio, * b64;
    SecureVector<unsigned char> output;

    int decodeLen = calcDecodeLength(input.c_str(), input.size());
    output.resize(decodeLen, '\0'); // Resize the output buffer

    bio = BIO_new_mem_buf(input.c_str(), input.size());
    if (bio == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_NEW_MEM_BUFFAILED_CRYPT));
    }

    b64 = BIO_new(BIO_f_base64());
    if (b64 == nullptr) {
        BIO_free_all(bio);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_NEWFORBASE64FAILED_CRYPT));
    }

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer

    int length = BIO_read(bio, output.data(), output.size());
    if (length <= 0) {
        BIO_free_all(bio);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::BIO_READFAILED_CRYPT));
    }
    output.resize(length); // Resize to actual data length read

    BIO_free_all(bio);

    return output;
}

int Crypt::calcDecodeLength(const char* b64input, int length) {
    if (length < 2 || (length & 3) != 0) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDBASE64INPUTLENGTH_CRYPT));
    }

    int padding = 0;

    // Check for trailing '=''s as padding
    if (b64input[length - 1] == '=' && b64input[length - 2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[length - 1] == '=') //last char is =
        padding = 1;

    return (int)length * 0.75 - padding;
}

SecureVector<unsigned char> Crypt::DecodeHex(const SecureString& hex) {
    size_t len = hex.size();
    SecureVector<unsigned char> bytes;

    for (size_t i = 0; i < len; i += 2) {
        if (i + 1 >= len) {
            throw SecureException(StringCrypt::DecryptString(StringCrypt::HEXSTRINGHASODDLENGTH_CRYPT));
        }

        unsigned char byte = (SecureString::hexCharToByte(hex[i]) << 4)
            + SecureString::hexCharToByte(hex[i + 1]);
        bytes.push_back(byte);
    }

    return bytes;
}

// Function to perform XOR decryption
SecureVector<unsigned char> Crypt::XorEncryptDecrypt(const SecureVector<unsigned char>& input, const SecureVector<unsigned char>& key) {
    SecureVector<unsigned char> output(input.size());
    size_t keyLen = key.size();

    for (size_t i = 0; i < input.size(); i++) {
        output[i] = input[i] ^ key[i % keyLen];
    }

    return output;
}

// Function to generate a 256-bit key and a 96-bit nonce
void Crypt::GenerateChaCha20KeyAndNonce() {
    // Generate the key
    if (RAND_bytes(ChaCha20Key.data(), ChaCha20Key.size()) != 1) {
        // Handle error: the random number generator failed
        throw SecureException(StringCrypt::DecryptString(StringCrypt::ERRORGENERATINGCHACHA20KEY_CRYPT));
    }

    // Generate the nonce
    if (RAND_bytes(ChaCha20Nonce.data(), ChaCha20Nonce.size()) != 1) {
        // Handle error: the random number generator failed
        throw SecureException(StringCrypt::DecryptString(StringCrypt::ERRORGENERATINGCHACHA20NONCE_CRYPT));
    }

    // Print the generated key and nonce in hexadecimal format
    //PrintHex("Key: ", ChaCha20Key.data(), ChaCha20Key.size());
    //PrintHex("Nonce: ", ChaCha20Nonce.data(), ChaCha20Nonce.size());
}

void Crypt::ChaCha20EncryptDecryptInPlace(unsigned char* data, size_t data_len, const unsigned char* key, const unsigned char* nonce) {
    if (!data || data_len == 0) {
		// Handle error: no data to encrypt
        return;
	}

    EVP_CIPHER_CTX* ctx;
    int len;
    int out_len;

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        // Handle error: context initialization failed
        throw SecureException(StringCrypt::DecryptString(StringCrypt::EVP_CIPHER_CTX_NEWFAILED_CRYPT));
    }

    // Initialize the encryption operation with ChaCha20
    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce);

    // Provide the message to be encrypted, using the same buffer for input and output.
    if (!EVP_EncryptUpdate(ctx, data, &len, data, data_len)) {
        // Handle error: encryption failed
        EVP_CIPHER_CTX_free(ctx);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::CHACHA20ENCRYPTIONDECRYPTIONFAILED_CRYPT));
    }

    out_len = len;

    // Finalize the encryption. Not needed for ChaCha20 as it doesn't use padding.
    // Including it here for completeness, but it's unnecessary for stream ciphers like ChaCha20.
    if (!EVP_EncryptFinal_ex(ctx, data + len, &len)) {
        // Handle error: finalization failed
        EVP_CIPHER_CTX_free(ctx);
        throw SecureException(StringCrypt::DecryptString(StringCrypt::CHACHA20FINALIZATIONFAILED_CRYPT));
    }

    out_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    // Output for debugging purposes; remove or adjust as necessary.
    //printf("Encrypted in-place, length: %d\n", out_len);
}

SecureString Crypt::AesEncrypt(const SecureString& data, const SecureVector<unsigned char>& key, const SecureVector<unsigned char>& iv) {
    // Get the plaintext as a vector of unsigned chars
    SecureVector<unsigned char> plaintext(data.begin(), data.end());

    // Buffer for ciphertext using vector
    SecureVector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);

    // Buffer for the decrypted text using vector
    SecureVector<unsigned char> decrypted(plaintext.size()  + 1);

    // Buffer for the tag
    unsigned char tag[16];  // 128 bit tag

    // Encrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
    size_t ciphertext_len = outlen;

    // Finalize Encryption
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen);
    ciphertext_len += outlen;

    // Get the tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    //PrintHex("Tag: ", tag, sizeof(tag));

    // Clean up encryption context
    EVP_CIPHER_CTX_free(ctx);

    // Create a new vector with the exact size of the ciphertext
    SecureVector<unsigned char> exactSizeCiphertext(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    // Append the tag to the exactSizeCiphertext vector
    exactSizeCiphertext.insert(exactSizeCiphertext.end(), tag, tag + sizeof(tag));
    // Now exactSizeCiphertext contains the ciphertext followed by the tag, with no extra padding

    //PrintHex("Ciphertext: ", exactSizeCiphertext.data(), exactSizeCiphertext.size());

    return base64_encode(exactSizeCiphertext);
}

SecureString Crypt::AesDecrypt(const SecureString& data, const SecureVector<unsigned char>& key, const SecureVector<unsigned char>& iv, bool isHex) {
    SecureVector<unsigned char> ciphertextWithTag;

    if (isHex) {
		ciphertextWithTag = DecodeHex(data);
	}
    else {
		ciphertextWithTag = base64_decode(data);
	}

    // Separate ciphertext and tag
    SecureVector<unsigned char> ciphertext(ciphertextWithTag.begin(), ciphertextWithTag.end() - 16);
    SecureVector<unsigned char> tag(ciphertextWithTag.end() - 16, ciphertextWithTag.end());

    // Buffer for the decrypted text
    SecureVector<unsigned char> decrypted(ciphertext.size());

    // Decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    int outlen;
    EVP_DecryptUpdate(ctx, decrypted.data(), &outlen, ciphertext.data(), ciphertext.size());
    int decrypted_len = outlen;

    // Set expected tag value
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());

    // Finalize Decryption
    int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + outlen, &outlen);

    // Clean up decryption context
    EVP_CIPHER_CTX_free(ctx);

    return SecureString(decrypted.begin(), decrypted.end());
}

/*
int XORTest() {
    // Replace with your XOR encrypted AES key hex string and XOR key hex string
    SecureString encryptedAESKeyHex = "7ec2de582023d2d9dc660c656b1bf9f9505998547011653d4d478f16c3a4af71";
    SecureString xorKeyHex = "7728784929b94b71d19e1fcea315270eecac31aac2bf0a694954234135310503";

    SecureVector<unsigned char> encryptedAESKeyBytes = DecodeHex(encryptedAESKeyHex);
    SecureVector<unsigned char> xorKeyBytes = DecodeHex(xorKeyHex);

    SecureVector<unsigned char> decryptedAESKey = XorDecrypt(encryptedAESKeyBytes, xorKeyBytes);

    // Print the decrypted AES key in hex format
    for (auto b : decryptedAESKey) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }

    return 0;
}

int main() {
    SecureVector<unsigned char> data = { 0x48, 0x65, 0x6c, 0x6c, 0x6f };  // "Hello"
    SecureVector<unsigned char> cipher;
    SecureVector<unsigned char> decrypted;
    SecureVector<unsigned char> masterKey = { 0x6b, 0x65, 0x79 };  // "key"

    try {
        SecureString base64String = AesEncrypt(data, masterKey);
        std::cout << "Base64 Encrypted String: " << base64String << std::endl;
        SecureString decryptedString = AesDecrypt(base64String, masterKey);
        std::cout << "Decrypted String: " << decryptedString << std::endl;
    }
    catch (const SecureException& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return XORTest();
}
*/
