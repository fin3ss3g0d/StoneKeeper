#pragma once
#include <cstddef>
#include <memory>

// First, typedef the function pointer type for readability
typedef void (*FunctionPtrType)();

template<typename T>
struct SecureDeleter {
    size_t capacity;  // Member variable to store the size

    // Default constructor
    SecureDeleter() : capacity(0) {}

    // Constructor to initialize the deleter with the size
    SecureDeleter(size_t size) : capacity(size) {}

    // Function call operator for deletion
    void operator()(T* ptr);
};

template<typename T>
class SecureVector {
private:
    std::unique_ptr<T[], SecureDeleter<T>> data_;
    size_t capacity;
    size_t currentSize;
    
public:
    SecureVector();
    explicit SecureVector(size_t initialSize); // New constructor

    // Move constructor
    SecureVector(SecureVector&& other) noexcept = default;
    // Move assignment operator
    SecureVector& operator=(SecureVector&& other) noexcept = default;

    // Constructor from a range specified by iterators
    template<typename InputIterator>
    SecureVector(InputIterator first, InputIterator last);

    // Default destructor is fine here; it will call the custom deleter automatically
    ~SecureVector() = default;

    void resize(size_t newSize, const T& value = T()); // New resize method

    void insert(T* position, T* first, T* last);

    T* data();
    const T* data() const;

    T* begin();
    T* end();

    // Method to check if the vector is empty
    bool empty() const {
        return currentSize == 0;
    }

    void push_back(const T& value);
    T& operator[](size_t index);
    const T& operator[](size_t index) const;
    size_t size() const;
};
