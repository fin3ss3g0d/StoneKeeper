#include "SecureString.hpp"
#include "SecureVector.hpp"
#include "SecureException.hpp"
#include "StringCrypt.hpp"
#include "Win32.hpp"
#include "VectoredExceptionHandler.hpp"
#include <openssl/rand.h>

// Constructor for direct initialization with a C-string
SecureString::SecureString(const char* str) {
    if (str == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NULLPOINTERPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT));
    }
    length = strlen(str);
    capacity = length + 1;  // Set capacity
    data = new char[capacity];
    std::copy(str, str + length, data);
    data[length] = '\0';  // Null-terminating the string
}

// Constructor for initialization with a data pointer and length
SecureString::SecureString(const char* bytes, size_t len) {
    if (bytes == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NULLPOINTERPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT));
    }
    length = len;
    capacity = length + 1;  // Plus one for null-terminator
    data = new char[capacity];
    std::memcpy(data, bytes, length);  // Use memcpy to copy the bytes
    data[length] = '\0';  // Null-terminating the string
}

// Template constructor definition
template <typename Iter>
SecureString::SecureString(Iter begin, Iter end) {
    if (begin == end) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::EMPTYRANGEPASSEDTOSECURESTRINGCONSTRUCTOR_CRYPT));
    }
    length = std::distance(begin, end);
    capacity = length + 1;
    data = new char[capacity];
    std::copy(begin, end, data);
    data[length] = '\0'; // Null-terminate the string
}

// Assigns a new value to the string, replacing its current contents.
void SecureString::assign(const char* str, size_t len) {
    if (str == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NULLPOINTERPASSEDTOSECURESTRINGASSIGN_CRYPT));
    }

    if (len >= capacity) {
        destroy();
        capacity = len + 1;
        data = new char[capacity];
    }

    std::copy(str, str + len, data);
    length = len;
    data[length] = '\0'; // Null-terminating the string
}

// Assigns a new value to the string, replacing its current contents.
// This version of assign converts from SecureWideString iterators
template <typename Iter>
void SecureString::assign(Iter begin, Iter end) {
    if (begin == end) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::EMPTYRANGEPASSEDTOSECURESTRINGASSIGN_CRYPT));
    }

    size_t newLength = std::distance(begin, end);
    if (newLength >= capacity) {
        destroy();
        capacity = newLength + 1;
        data = new char[capacity];
    }

    length = 0;
    for (Iter it = begin; it != end; ++it) {
        // Simple conversion, assuming each wchar_t can be represented as a single char.
        // This might not be valid for characters outside the ASCII range.
        data[length++] = static_cast<char>(*it);
    }
    data[length] = '\0'; // Null-terminating the string
}

// Explicit template instantiation for std::string iterator types
template SecureString::SecureString(std::string::iterator, std::string::iterator);
template SecureString::SecureString(std::string::const_iterator, std::string::const_iterator);

// Explicit template instantiation for std::vector<char> iterator types
template SecureString::SecureString(std::vector<char>::iterator, std::vector<char>::iterator);
template SecureString::SecureString(std::vector<char>::const_iterator, std::vector<char>::const_iterator);

// Explicit template instantiation for std::vector<unsigned char> iterator types
template SecureString::SecureString(std::vector<unsigned char>::iterator, std::vector<unsigned char>::iterator);
template SecureString::SecureString(std::vector<unsigned char>::const_iterator, std::vector<unsigned char>::const_iterator);

// Explicit template instantiation for SecureVector<unsigned char> begin and end methods
template SecureString::SecureString(unsigned char*, unsigned char*);
template SecureString::SecureString(const unsigned char*, const unsigned char*);

// Explicit template instantiation for char* & wchar_t* iterator types
template void SecureString::assign<char*>(char*, char*);
template void SecureString::assign<const char*>(const char*, const char*);
template void SecureString::assign<wchar_t*>(wchar_t*, wchar_t*);
template void SecureString::assign<const wchar_t*>(const wchar_t*, const wchar_t*);

// Method to convert a single hex character to its byte value
unsigned char SecureString::hexCharToByte(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    throw SecureException(StringCrypt::DecryptString(StringCrypt::INVALIDHEXCHARACTER_CRYPT));
}

void SecureString::scramble() {
    if (Win32::NtdllTable.isResolved) {
        // Add exception handler for scrambling if resolved
        VectoredExceptionHandler veh(INCREMENT_RIP);
    }

    if (data == nullptr || length == 0) {
        return;
    }

    for (size_t i = 0; i < length; ++i) {
        unsigned char random_byte;
        if (RAND_bytes(&random_byte, sizeof(random_byte)) != 1) {
            // Handle error: the random byte was not generated successfully
            throw SecureException(StringCrypt::DecryptString(StringCrypt::RANDOMBYTESGENERATIONERROR_CRYPT));
        }

        // Mix with pseudo-random data from a cryptographically secure source
        data[i] ^= static_cast<char>(random_byte);

        // Apply a series of complex and randomized bitwise operations
        char randomOperation = static_cast<char>(random_byte);
        if (randomOperation & 1) data[i] = ~data[i];
        if (randomOperation & 2) data[i] = (data[i] << 5) | (data[i] >> 3);
        if (randomOperation & 4) data[i] ^= 0x55;
        if (randomOperation & 8) data[i] = (data[i] << 1) | (data[i] >> 7);
        if (randomOperation & 16) data[i] ^= static_cast<char>(random_byte);
        if (randomOperation & 32) data[i] = (data[i] << 4) | (data[i] >> 4);
        if (randomOperation & 64) data[i] = ~data[i] ^ 0xAA;
        if (randomOperation & 128) data[i] = (data[i] << 7) | (data[i] >> 1);
    }
}

// Subscript operator for non-const objects
// Provides access to individual characters of the string by index.
char& SecureString::operator[](size_t index) {
    if (index >= length) {
        // Throws an exception if the index is out of range.
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }
    return data[index]; // Returns a reference to the character.
}

// Subscript operator for const objects
// Provides read-only access to individual characters of the string by index.
const char& SecureString::operator[](size_t index) const {
    if (index >= length) {
        // Throws an exception if the index is out of range.
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }
    return data[index]; // Returns a const reference to the character.
}