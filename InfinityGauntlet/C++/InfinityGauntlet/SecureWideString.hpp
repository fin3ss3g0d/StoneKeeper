#include <cwchar>     // For std::wcslen
#include <algorithm>  // For std::fill_n, std::shuffle
#include <random>     // For std::mt19937, std::random_device

class SecureWideString {
public:
    // Default constructor
    SecureWideString() : data(new wchar_t[1]), length(0) {
        data[0] = L'\0';  // Null-terminating the wide string
    }

    // Constructor for direct initialization with a wide C-string
    SecureWideString(const wchar_t* str);

    // Constructor for initialization with a narrow C-string
    SecureWideString(const char* str);

    SecureWideString(size_t size) {
        length = size;
        data = new wchar_t[length + 1]; // +1 for null terminator
        std::fill_n(data, length + 1, L'\0');
    }

    // Constructor for initialization with a wide C-string and length
    SecureWideString(const wchar_t* buffer, size_t len);

    // Constructor from iterators
    template<typename Iter>
    SecureWideString(Iter begin, Iter end);

    ~SecureWideString() {
        destroy();
        data = nullptr;
        length = 0;
    }

    // Return iterator to the beginning of the wide string
    wchar_t* begin() {
        return data;
    }

    // Return const iterator to the beginning of the wide string
    const wchar_t* begin() const {
        return data;
    }

    // Return iterator to one past the end of the wide string
    wchar_t* end() {
        return data + length;
    }

    // Return const iterator to one past the end of the wide string
    const wchar_t* end() const {
        return data + length;
    }

    const wchar_t* c_str() const {
        return data;
    }

    size_t size() const {
        return length;
    }

    // Method to check if the string is empty
    bool empty() const {
        return length == 0;
    }

    void append(const wchar_t* str) {
        if (str == nullptr) return;

        size_t strLength = wcslen(str);
        wchar_t* newData = new wchar_t[length + strLength + 1];

        std::copy(data, data + length, newData);
        std::copy(str, str + strLength, newData + length);

        destroy();  // Securely destroy the old data

        length += strLength;
        newData[length] = L'\0';
        data = newData;
    }

    template <typename Iter>
    void append(Iter begin, Iter end);

    // Copy constructor
    SecureWideString(const SecureWideString& other) : length(other.length), data(new wchar_t[other.length + 1]) {
        std::copy(other.data, other.data + other.length, data);
        data[length] = L'\0'; // Null-terminating the wide string
    }

    // Copy assignment operator
    SecureWideString& operator=(const SecureWideString& other) {
        if (this != &other) {
            wchar_t* newData = new wchar_t[other.length + 1];
            std::copy(other.data, other.data + other.length, newData);
            newData[other.length] = L'\0';

            destroy(); // Securely destroy the old data

            data = newData;
            length = other.length;
        }
        return *this;
    }

    // Move semantics
    SecureWideString(SecureWideString&& other) noexcept : data(nullptr), length(0) {
        std::swap(data, other.data);
        std::swap(length, other.length);
    }

    SecureWideString& operator=(SecureWideString&& other) noexcept {
        if (this != &other) {
            destroy();

            data = nullptr;
            length = 0;

            std::swap(data, other.data);
            std::swap(length, other.length);
        }
        return *this;
    }

    wchar_t& operator[](size_t index);

    const wchar_t& operator[](size_t index) const;

private:
    wchar_t* data;
    size_t length;

    void scramble();

    void wipe() {
        std::fill_n(data, length, L'\0');
    }

    void destroy() {
        scramble();
        wipe();
        delete[] data;
    }
};
