#include "SecureVector.hpp"
#include "StringCrypt.hpp"
#include "SecureException.hpp"
#include <openssl/rand.h>
#include <algorithm>
#include <cstring>

template<typename T>
SecureVector<T>::SecureVector()
    : data_(nullptr, SecureDeleter<T>(0)), capacity(0), currentSize(0) {}

template<typename T>
SecureVector<T>::SecureVector(size_t initialSize)
    : capacity(initialSize), currentSize(initialSize) {
    if (initialSize > 0) {
        T* rawPtr = new T[initialSize]();
        data_ = std::unique_ptr<T[], SecureDeleter<T>>(rawPtr, SecureDeleter<T>(initialSize));
    }
}

template<typename T>
template<typename InputIterator>
SecureVector<T>::SecureVector(InputIterator first, InputIterator last)
    : capacity(std::distance(first, last)), currentSize(capacity) {
    if (capacity > 0) {
        T* rawPtr = new T[capacity]();
        std::copy(first, last, rawPtr);
        data_ = std::unique_ptr<T[], SecureDeleter<T>>(rawPtr, SecureDeleter<T>(capacity));
    }
}

template<typename T>
void SecureVector<T>::push_back(const T& value) {
    if (currentSize >= capacity) {
        size_t newCapacity = capacity == 0 ? 1 : capacity * 2;
        T* newData = new T[newCapacity]();
        if (data_ != nullptr) {
            std::copy(data_.get(), data_.get() + currentSize, newData);
        }
        data_ = std::unique_ptr<T[], SecureDeleter<T>>(newData, SecureDeleter<T>(newCapacity)); // Wrap the new array
        capacity = newCapacity;
    }
    data_.get()[currentSize++] = value; // Use .get() to access the raw pointer
}

template<typename T>
void SecureVector<T>::resize(size_t newSize, const T& value) {
    if (newSize > capacity) {
        T* newData = new T[newSize](); // Manually allocate memory

        // Move the existing data to the new array
        std::move(data_.get(), data_.get() + currentSize, newData);

        // Initialize the rest of the new elements with the specified value
        std::fill(newData + currentSize, newData + newSize, value);

        // Replace the old data with the new array
        data_ = std::unique_ptr<T[], SecureDeleter<T>>(newData, SecureDeleter<T>(newSize)); // Wrap the new array with unique_ptr
        capacity = newSize;
    }
    else if (newSize < currentSize) {
        // If the new size is smaller, handle the excess elements as needed
        // This might involve wiping or scrambling the excess elements
        // Note: The actual memory size of the array does not change in this case
        //printf("New size is smaller!\n");
    }
    currentSize = newSize;
}

template<typename T>
void SecureVector<T>::insert(T* position, T* first, T* last) {
    size_t insertCount = std::distance(first, last);
    if (insertCount == 0) {
        return; // Nothing to insert
    }

    size_t posIndex = std::distance(data_.get(), position);
    if (posIndex > currentSize) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }

    size_t newSize = currentSize + insertCount;
    if (newSize > capacity) {
        T* newData = new T[newSize](); // Manually allocate memory

        // Copy the existing data up to the insertion point
        std::copy(data_.get(), data_.get() + posIndex, newData);

        // Copy the elements to be inserted
        std::copy(first, last, newData + posIndex);

        // Copy the remaining elements
        std::copy(data_.get() + posIndex, data_.get() + currentSize, newData + posIndex + insertCount);

        data_ = std::unique_ptr<T[], SecureDeleter<T>>(newData, SecureDeleter<T>(newSize)); // Wrap the new array
        capacity = newSize;
    }
    else {
        // Shift existing elements to make room for the new elements
        std::copy_backward(data_.get() + posIndex, data_.get() + currentSize, data_.get() + newSize);

        // Copy the elements to be inserted
        std::copy(first, last, data_.get() + posIndex);
    }
    currentSize = newSize;
}

template<typename T>
T* SecureVector<T>::begin() {
    return data_.get(); // Pointer to the first element
}

template<typename T>
T* SecureVector<T>::end() {
    return data_.get() + currentSize; // Pointer to one past the last element
}

template<typename T>
T* SecureVector<T>::data() {
    return data_.get(); // Return a pointer to the first element
}

template<typename T>
const T* SecureVector<T>::data() const {
    return data_.get(); // Return a const pointer to the first element
}

template<typename T>
size_t SecureVector<T>::size() const {
    return currentSize;
}

template<typename T>
T& SecureVector<T>::operator[](size_t index) {
    if (index >= currentSize) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }
    return data_.get()[index]; // Use get() to access the raw pointer
}

template<typename T>
const T& SecureVector<T>::operator[](size_t index) const {
    if (index >= currentSize) {
        throw SecureException(StringCrypt::DecryptString(StringCrypt::INDEXOUTOFRANGE_CRYPT));
    }
    return data_.get()[index]; // Use get() for const access to the raw pointer
}

// Define the function call operator of the SecureDeleter
template<typename T>
void SecureDeleter<T>::operator()(T* ptr) {
    if (ptr != nullptr) {
        //printf("SecureDeleter called! Capacity: %d\n", capacity);

        if constexpr (std::is_same<T, unsigned char>::value) {
            for (size_t i = 0; i < capacity; ++i) {
                unsigned char random_byte;
                if (RAND_bytes(&random_byte, sizeof(random_byte)) != 1) {
                    // Handle error: the random byte was not generated successfully
                    // Error handling logic here
                    continue;
                }

                // Mix with pseudo-random data from a cryptographically secure source
                ptr[i] ^= static_cast<unsigned char>(random_byte);

                // Apply a series of complex and randomized bitwise operations
                unsigned char randomOperation = static_cast<unsigned char>(random_byte);
                if (randomOperation & 1) ptr[i] = ~ptr[i];
                if (randomOperation & 2) ptr[i] = (ptr[i] << 5) | (ptr[i] >> 3);
                if (randomOperation & 4) ptr[i] ^= 0x55;
                if (randomOperation & 8) ptr[i] = (ptr[i] << 1) | (ptr[i] >> 7);
                if (randomOperation & 16) ptr[i] ^= static_cast<unsigned char>(random_byte);
                if (randomOperation & 32) ptr[i] = (ptr[i] << 4) | (ptr[i] >> 4);
                if (randomOperation & 64) ptr[i] = ~ptr[i] ^ 0xAA;
                if (randomOperation & 128) ptr[i] = (ptr[i] << 7) | (ptr[i] >> 1);
            }
            // Securely wipe the memory by overwriting with zeros
            std::fill_n(ptr, _msize(ptr) / sizeof(T), 0); // Platform-specific size retrieval
            // Alternative: std::fill_n(ptr, capacity, static_cast<T>(0));
        }
        else if constexpr (std::is_same<T, FunctionPtrType>::value) {
			// Securely wipe the memory by overwriting with zeros
            std::fill_n(ptr, _msize(ptr) / sizeof(T), static_cast<T>(nullptr));
		}

        // Free the memory
        delete[] ptr;
    }
}

// Explicit template instantiation for the constructor with iterators
template SecureVector<unsigned char>::SecureVector(char*, char*);
template SecureVector<unsigned char>::SecureVector(const char*, const char*);
template SecureVector<unsigned char>::SecureVector(unsigned char*, unsigned char*);
template SecureVector<unsigned char>::SecureVector(const unsigned char*, const unsigned char*);

// Explicit template instantiation for the insert method
template void SecureVector<char>::insert(char*, char*, char*);
template void SecureVector<unsigned char>::insert(unsigned char*, unsigned char*, unsigned char*);

// Explicit template instantiation for the begin & end method
template unsigned char* SecureVector<unsigned char>::begin();
template unsigned char* SecureVector<unsigned char>::end();
template FunctionPtrType* SecureVector<FunctionPtrType>::begin();
template FunctionPtrType* SecureVector<FunctionPtrType>::end();

// Explicit template instantiation for the entire class
template class SecureVector<unsigned char>;
template class SecureVector<FunctionPtrType>;

// Explicit template instantiation for SecureDeleter with unsigned char
template struct SecureDeleter<unsigned char>;
template struct SecureDeleter<FunctionPtrType>;
