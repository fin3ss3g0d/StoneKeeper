#include <openssl/evp.h>
#include <iostream>
#include <vector>
#include <cstring>

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

// Utility function to print a buffer in hex
void print_hex(const char* label, const unsigned char* buf, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
    }
    std::cout << std::endl;
}

// Utility function to convert a hex string to a byte vector
std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

int main() {
    // Initialize key and IV (normally you'd generate these securely)
    //unsigned char key[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };
    //unsigned char iv[12] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x61, 0x62 };
    //std::vector<unsigned char> key = hex_to_bytes("30313233343536373839616263646566");    
    //std::vector<unsigned char> iv = hex_to_bytes("313233343536373839306162");
    std::vector<unsigned char> key = hex_to_bytes("f4c1af2472d6fbe8bc2f12f28926a0f4a3a046755dab2b9faf513f82f5cb342b");
    std::vector<unsigned char> iv = hex_to_bytes("0e266d1fa0b89a66bf1a210e");

    // Sample plaintext
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    size_t plaintext_len = strlen((char*)plaintext);

    // Buffer for ciphertext using vector
    std::vector<unsigned char> ciphertext(plaintext_len + EVP_MAX_BLOCK_LENGTH);    

    // Buffer for the decrypted text using vector
    std::vector<unsigned char> decrypted(plaintext_len + 1);

    // Buffer for the tag
    unsigned char tag[16];  // 128 bit tag

    // Encrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    //EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL);
    //EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    //print_hex("Key: ", key, sizeof(key));
    //print_hex("IV: ", iv, sizeof(iv));
    print_hex("Key: ", key.data(), key.size());
    print_hex("IV: ", iv.data(), iv.size());

    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext, plaintext_len);
    size_t ciphertext_len = outlen;

    // Finalize Encryption
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen);
    ciphertext_len += outlen;

    // Get the tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);

    // Clean up encryption context
    EVP_CIPHER_CTX_free(ctx);

    print_hex("Ciphertext: ", ciphertext.data(), ciphertext_len); // Use ciphertext_len for accurate length
    // Create a new vector with the exact size of the ciphertext
    std::vector<unsigned char> exactSizeCiphertext(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
    // Append the tag to the exactSizeCiphertext vector
    exactSizeCiphertext.insert(exactSizeCiphertext.end(), tag, tag + sizeof(tag));
    // Now exactSizeCiphertext contains the ciphertext followed by the tag, with no extra padding
    print_hex("Ciphertext with tag: ", exactSizeCiphertext.data(), exactSizeCiphertext.size());
    print_hex("Tag: ", tag, sizeof(tag));

    // Decrypt
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL);
    //EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data());

    EVP_DecryptUpdate(ctx, decrypted.data(), &outlen, ciphertext.data(), ciphertext_len);
    int decrypted_len = outlen;

    // Set expected tag value
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);

    // Finalize Decryption
    int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + outlen, &outlen);

    // Clean up decryption context
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        // Decryption successful
        decrypted_len += outlen;
        decrypted[decrypted_len] = '\0'; // Properly null-terminate the string
        print_hex("Decrypted: ", decrypted.data(), decrypted_len);
        std::cout << "Decrypted text: " << decrypted.data() << std::endl;
    }
    else {
        // Decryption failed
        std::cerr << "Decryption failed" << std::endl;
    }

    return 0;
}

/*int main() {
    // Initialize key and IV (use the same as in your Go program)
    std::string keyHex = "30313233343536373839616263646566";
    std::string ivHex = "313233343536373839306162";
    // The ciphertextWithTagHex should be the output from your Go program
    std::string ciphertextWithTagHex = "7a0203e2c5953f848f39b12adeb79737124f97c33aad6077d9e1ad960ee09e216621a87a50b6c4ec6aca1b0483d65badf07d904d9bd7ca490b0fd8";

    // Convert hex strings to byte vectors
    std::vector<unsigned char> key = hex_to_bytes(keyHex);
    std::vector<unsigned char> iv = hex_to_bytes(ivHex);
    std::vector<unsigned char> ciphertextWithTag = hex_to_bytes(ciphertextWithTagHex);

    // Separate ciphertext and tag
    std::vector<unsigned char> ciphertext(ciphertextWithTag.begin(), ciphertextWithTag.end() - 16);
    std::vector<unsigned char> tag(ciphertextWithTag.end() - 16, ciphertextWithTag.end());

    // Buffer for the decrypted text
    std::vector<unsigned char> decrypted(ciphertext.size());

    // Decrypt
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
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

    if (ret > 0) {
        // Decryption successful
        decrypted_len += outlen;
        decrypted[decrypted_len] = '\0'; // Properly null-terminate the string
        print_hex("Decrypted: ", decrypted.data(), decrypted_len);
        std::cout << "Decrypted text: " << decrypted.data() << std::endl;
    }
    else {
        // Decryption failed
        std::cerr << "Decryption failed" << std::endl;
    }

    return 0;
}*/
