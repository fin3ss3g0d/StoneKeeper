#include "SecureWideString.hpp"
#include "SecureException.hpp"
#include "StringCrypt.hpp"
#include <openssl/rand.h>

// Constructor for direct initialization with a wide C-string
SecureWideString::SecureWideString(const wchar_t* str) {
    if (str == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT));
    }
    length = std::wcslen(str);
    data = new wchar_t[length + 1];
    std::copy(str, str + length, data);
    data[length] = L'\0'; // Null-terminating the string
}

// Constructor for initialization with a narrow C-string
SecureWideString::SecureWideString(const char* str) {
    if (str == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT));
    }

    // Calculate the length of the input string
    size_t strLength = strlen(str);

    // Allocate memory for the wide string
    length = strLength;
    data = new wchar_t[length + 1];

    // Convert each character to wide char
    for (size_t i = 0; i < length; ++i) {
        data[i] = static_cast<wchar_t>(str[i]);
    }
    data[length] = L'\0'; // Null-terminating the wide string
}

// Constructor for initialization with a wide C-string and length
SecureWideString::SecureWideString(const wchar_t* buffer, size_t len) {
    if (buffer == nullptr) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::NULLPOINTERPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT));
    }

    length = len;
    data = new wchar_t[length + 1]; // +1 for null terminator

    std::copy(buffer, buffer + length, data);
    data[length] = L'\0'; // Null-terminating the string
}

// Constructor from iterators
template<typename Iter>
SecureWideString::SecureWideString(Iter begin, Iter end) {
    if (begin == end) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::EMPTYRANGEPASSEDTOSECUREWIDESTRINGCONSTRUCTOR_CRYPT));
    }

    // Determine the type of the iterator
    if constexpr (std::is_same_v<typename std::iterator_traits<Iter>::value_type, char>) {
        // Handle conversion from char to wchar_t
        length = std::distance(begin, end);
        data = new wchar_t[length + 1];

        for (size_t i = 0; i < length; ++i) {
            data[i] = static_cast<wchar_t>(begin[i]); // Simple cast, or use a more sophisticated conversion if needed
        }
    }
    else {
        // Handle wchar_t iterators (as before)
        length = std::distance(begin, end);
        data = new wchar_t[length + 1];
        std::copy(begin, end, data);
    }
    data[length] = L'\0'; // Null-terminating the string
}

// Append a range of characters specified by iterators
template <typename Iter>
void SecureWideString::append(Iter begin, Iter end) {
    if (begin == end) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::EMPTYRANGEPASSEDTOSECUREWIDESTRINGAPPEND_CRYPT));
    }

    size_t appendLength = std::distance(begin, end);
    size_t newLength = length + appendLength;

    wchar_t* newData = new wchar_t[newLength + 1]; // +1 for null terminator

    // Copy existing data
    std::copy(data, data + length, newData);

    // Copy new data
    std::copy(begin, end, newData + length);

    newData[newLength] = L'\0'; // Null-terminate the string

    // Clean up old data and update pointers
    destroy();
    data = newData;
    length = newLength;
}

// Explicit template instantiation for char* iterator types
template SecureWideString::SecureWideString(char*, char*);
template SecureWideString::SecureWideString(const char*, const char*);

// Explicit template instantiation for wchar_t* iterator types
template void SecureWideString::append(wchar_t*, wchar_t*);
template void SecureWideString::append(const wchar_t*, const wchar_t*);

void SecureWideString::scramble() {
    for (size_t i = 0; i < length; ++i) {
        unsigned char random_bytes[sizeof(wchar_t)];
        if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
            // Handle error: the random bytes were not generated successfully
            throw SecureException(StringCrypt::DecryptString(StringCrypt::RANDOMBYTESGENERATIONERROR_CRYPT));
        }

        // Convert bytes to a wchar_t
        wchar_t random_value = 0;
        for (size_t j = 0; j < sizeof(wchar_t); ++j) {
            random_value |= (static_cast<wchar_t>(random_bytes[j]) << (j * 8));
        }

        // Mix with pseudo-random data from a cryptographically secure source
        data[i] ^= random_value;

        // Apply a series of complex and randomized bitwise operations
        wchar_t randomOperation = random_value;
        if (randomOperation & 1) data[i] = ~data[i];
        if (randomOperation & 2) data[i] = (data[i] << 5) | (data[i] >> (sizeof(wchar_t) * 8 - 5));
        if (randomOperation & 4) data[i] ^= 0x5555;
        if (randomOperation & 8) data[i] = (data[i] << 1) | (data[i] >> (sizeof(wchar_t) * 8 - 1));
        if (randomOperation & 16) data[i] ^= random_value;
        if (randomOperation & 32) data[i] = (data[i] << 4) | (data[i] >> (sizeof(wchar_t) * 8 - 4));
        if (randomOperation & 64) data[i] = ~data[i] ^ 0xAAAA;
        if (randomOperation & 128) data[i] = (data[i] << 7) | (data[i] >> (sizeof(wchar_t) * 8 - 7));
    }
}

wchar_t& SecureWideString::operator[](size_t index) {
    if (index >= length) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }
    return data[index];
}

const wchar_t& SecureWideString::operator[](size_t index) const {
    if (index >= length) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }
    return data[index];
}