#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <random>

class SecureString {
public:
    // Constructor for direct initialization with a C-string
    SecureString(const char* str) {
        if (str == nullptr) {
            throw std::invalid_argument("Null pointer passed to SecureString constructor");
        }
        length = strlen(str);
        data = new char[length + 1];
        std::copy(str, str + length, data);
        data[length] = '\0'; // Null-terminating the string
    }

    SecureString(size_t size) {
        length = size;
        data = new char[length + 1]; // +1 for null terminator
        std::fill_n(data, length + 1, '\0');
    }

    ~SecureString() {
        destroy();
        data = nullptr;
        length = 0;
    }

    // Return iterator to the beginning of the string
    char* begin() {
        return data;
    }

    // Return const iterator to the beginning of the string
    const char* begin() const {
        return data;
    }

    // Return iterator to one past the end of the string
    char* end() {
        return data + length;
    }

    // Return const iterator to one past the end of the string
    const char* end() const {
        return data + length;
    }

    const char* c_str() const {
        return data;
    }

    size_t size() const {
        return length;
    }

    // Method to check if the string is empty
    bool empty() const {
        return length == 0;
    }

    // Method to convert a single hex character to its byte value
    static unsigned char hexCharToByte(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        throw std::invalid_argument("Invalid hex character");
    }

    // Corrected append method
    void append(const char* str) {
        if (str == nullptr) return;

        size_t strLength = strlen(str);
        char* newData = new char[length + strLength + 1]; // +1 for null-terminator

        // Copy the original data to the new buffer
        std::copy(data, data + length, newData);

        // Copy the new string (str) to the end of the new buffer
        std::copy(str, str + strLength, newData + length);

        // Securely destroy the old data
        destroy();

        // Update the length to the new length
        length += strLength;

        // Null-terminate the new string
        newData[length] = '\0';

        // Point data to the new buffer
        data = newData;
    }

    // Move constructor
    // Allows the secure transfer of resources from one SecureString object to another.
    // It is marked noexcept to indicate it won't throw exceptions.
    SecureString(SecureString&& other) noexcept : data(nullptr), length(0) {
        // Swap the data and length members with those of the other object.
        // This effectively transfers the ownership of the resources to the current object.
        std::swap(data, other.data);
        std::swap(length, other.length);
    }

    // Move assignment operator
    // Assigns a new value to an existing SecureString, transferring resources.
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) { // Checks for self-assignment
            // Securely destroys the current object's data.
            destroy();

            // Resets data and length to a safe state before transferring resources.
            data = nullptr;
            length = 0;

            // Swaps the data and length members with those of the other object.
            std::swap(data, other.data);
            std::swap(length, other.length);
        }
        return *this; // Returns a reference to this string.
    }

    // Copy constructor
    // Creates a new SecureString as a copy of another.
    // This is used when a new SecureString is created from an existing one.
    SecureString(const SecureString& other) : length(other.length), data(new char[other.length + 1]) {
        // Copies the data from the other string into this new one.
        std::copy(other.data, other.data + other.length, data);
        // Null-terminates the new string.
        data[length] = '\0';
    }

    // Copy assignment operator
    // Assigns a new value to an existing SecureString from another SecureString.
    SecureString& operator=(const SecureString& other) {
        if (this != &other) { // Checks for self-assignment
            // Creates a new data array to hold the copy
            char* newData = new char[other.length + 1];
            // Copies the data from the other string into the new array.
            std::copy(other.data, other.data + other.length, newData);
            // Null-terminates the new string.
            newData[other.length] = '\0';

            // Securely destroys the old data of this string.
            destroy();

            // Updates this string's data and length to the new values.
            data = newData;
            length = other.length;
        }
        return *this; // Returns a reference to this string.
    }

    // Subscript operator for non-const objects
    // Provides access to individual characters of the string by index.
    char& operator[](size_t index) {
        if (index >= length) {
            // Throws an exception if the index is out of range.
            throw std::out_of_range("Index out of range");
        }
        return data[index]; // Returns a reference to the character.
    }

    // Subscript operator for const objects
    // Provides read-only access to individual characters of the string by index.
    const char& operator[](size_t index) const {
        if (index >= length) {
            // Throws an exception if the index is out of range.
            throw std::out_of_range("Index out of range");
        }
        return data[index]; // Returns a const reference to the character.
    }

private:
    char* data;
    size_t length;

    void scramble() {
        std::random_device rd; // Cryptographically secure random number generator

        for (size_t i = 0; i < length; ++i) {
            // Mix with pseudo-random data from a cryptographically secure source
            data[i] ^= static_cast<char>(rd());

            // Apply a series of complex and randomized bitwise operations
            char randomOperation = static_cast<char>(rd());
            if (randomOperation & 1) data[i] = ~data[i];
            if (randomOperation & 2) data[i] = (data[i] << 5) | (data[i] >> 3);
            if (randomOperation & 4) data[i] ^= 0x55;
            if (randomOperation & 8) data[i] = (data[i] << 1) | (data[i] >> 7);
            if (randomOperation & 16) data[i] ^= static_cast<char>(rd());
            if (randomOperation & 32) data[i] = (data[i] << 4) | (data[i] >> 4);
            if (randomOperation & 64) data[i] = ~data[i] ^ 0xAA;
            if (randomOperation & 128) data[i] = (data[i] << 7) | (data[i] >> 1);
        }

        // Further shuffle the data
        std::shuffle(data, data + length, std::mt19937(rd()));
    }

    void wipe() {
        // Securely wipe the memory
        std::fill_n(data, length, '\0');
        // Alternatively, use a more secure wiping method if available.
    }

    void destroy() {
        scramble();
        wipe();
        delete[] data;
    }
};
