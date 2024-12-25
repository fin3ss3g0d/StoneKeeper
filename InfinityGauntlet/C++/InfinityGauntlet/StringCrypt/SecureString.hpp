#pragma once
#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <random>

class SecureString {
public:
    // Default constructor
    SecureString() : data(new char[1]), length(0), capacity(1) {
        data[0] = '\0';  // Null-terminating the string
    }

    // Constructor for direct initialization with a C-string
    SecureString(const char* str) {
        if (str == nullptr) {
            throw std::invalid_argument("Null pointer passed to SecureString constructor");
        }
        length = strlen(str);
        capacity = length + 1;  // Set capacity
        data = new char[capacity];
        std::copy(str, str + length, data);
        data[length] = '\0';  // Null-terminating the string
    }

    // Constructor with a specified size
    SecureString(size_t size) : length(size), capacity(size + 1) {
        data = new char[capacity];  // Allocate memory based on capacity
        std::fill_n(data, length, '\0');  // Fill the string with null characters
        data[length] = '\0';  // Ensure null termination
    }

    template <typename Iter>
    SecureString(Iter begin, Iter end) {
        // Calculate the size from the distance between iterators
        length = std::distance(begin, end);

        // Set capacity. It should be at least length + 1 for the null terminator
        capacity = length + 1;

        // Allocate memory for the string based on the capacity
        data = new char[capacity];

        // Copy the elements from the range into data
        std::copy(begin, end, data);

        // Null-terminate the string
        data[length] = '\0';
    }

    ~SecureString() {
        destroy();
        data = nullptr;
        length = 0;
        capacity = 0;
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

    void append(const char* str) {
        if (str == nullptr) return;

        size_t strLength = strlen(str);

        // Check if the current capacity is enough to hold the new string
        if (length + strLength >= capacity) {
            // Increase the capacity to accommodate the new string plus null terminator
            size_t newCapacity = length + strLength + 1;
            char* newData = new char[newCapacity];

            // Copy the original data to the new buffer
            std::copy(data, data + length, newData);

            // Update the capacity and securely destroy the old data
            capacity = newCapacity;
            destroy();

            // Update the data pointer
            data = newData;
        }

        // Append the new string to the end of the current string
        std::copy(str, str + strLength, data + length);

        // Update the length and null-terminate the new string
        length += strLength;
        data[length] = '\0';
    }

    void append(const char* buf, size_t bufLength) {
        if (buf == nullptr || bufLength == 0) return;

        // Check if the current capacity is enough to hold the new string
        if (length + bufLength >= capacity) {
            // Increase the capacity to accommodate the new string plus null terminator
            size_t newCapacity = length + bufLength + 1;
            char* newData = new char[newCapacity];

            // Copy the original data to the new buffer
            std::copy(data, data + length, newData);

            // Update the capacity and securely destroy the old data
            capacity = newCapacity;
            destroy();

            // Update the data pointer
            data = newData;
        }

        // Append the new buffer content to the end of the current string
        std::copy(buf, buf + bufLength, data + length);

        // Update the length and null-terminate the new string
        length += bufLength;
        data[length] = '\0';
    }

    // Overload of append method for single 'char' type
    void append(char ch) {
        char str[2] = { ch, '\0' };  // Create a temporary C-style string
        append(str);  // Reuse the existing append logic for C-style strings
    }

    void reserve(size_t new_capacity) {
        if (new_capacity <= capacity) {
            return; // The current capacity is sufficient.
        }

        char* newData = new char[new_capacity];
        std::copy(data, data + length, newData);
        capacity = new_capacity;

        // Securely destroy the old data
        destroy();

        data = newData;
    }

    SecureString substr(size_t pos, size_t len) const {
        if (pos >= length) {
            return SecureString(); // Return an empty SecureString if pos is out of bounds.
        }

        size_t effectiveLength = (std::min)(len, length - pos);
        SecureString result(effectiveLength); // Create a SecureString with the effective length

        // Copy the substring into the result
        std::copy(data + pos, data + pos + effectiveLength, result.data);
        result.data[effectiveLength] = '\0'; // Null-terminate the result
        result.length = effectiveLength; // Set the correct length
        // No need to set capacity as it's already set by the constructor

        return result;
    }

    void escapeNewlines() {
        SecureString result;
        result.reserve(this->size() * 2);  // Reserve twice the size to accommodate potential escapes

        for (size_t i = 0; i < this->size(); ++i) {
            if (this->data[i] == '\n') {
                result.append("\\n");  // Append escaped newline
            }
            else {
                result.append(this->data[i]);  // Append current character
            }
        }

        *this = std::move(result);  // Replace the current string with the result
    }

    // Move constructor
    // Allows the secure transfer of resources from one SecureString object to another.
    // It is marked noexcept to indicate it won't throw exceptions.
    SecureString(SecureString&& other) noexcept
        : data(nullptr), length(0), capacity(0) {
        std::swap(data, other.data);
        std::swap(length, other.length);
        std::swap(capacity, other.capacity);
    }

    // Move assignment operator
    // Assigns a new value to an existing SecureString, transferring resources.
    SecureString& operator=(SecureString&& other) noexcept {
        if (this != &other) {
            destroy();
            data = nullptr;
            length = 0;
            capacity = 0;
            std::swap(data, other.data);
            std::swap(length, other.length);
            std::swap(capacity, other.capacity);
        }
        return *this;
    }

    // Copy constructor
    // Creates a new SecureString as a copy of another.
    // This is used when a new SecureString is created from an existing one.
    SecureString(const SecureString& other)
        : length(other.length), capacity(other.length + 1), data(new char[other.capacity]) {
        std::copy(other.data, other.data + other.length, data);
        data[length] = '\0';
    }

    // Copy assignment operator
    // Assigns a new value to an existing SecureString from another SecureString.
    SecureString& operator=(const SecureString& other) {
        if (this != &other) {
            char* newData = new char[other.length + 1];
            std::copy(other.data, other.data + other.length, newData);
            newData[other.length] = '\0';
            destroy();
            data = newData;
            length = other.length;
            capacity = other.length + 1;
        }
        return *this;
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
    size_t capacity;

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
