#include "SecureException.hpp"
#include "SecureString.hpp"

SecureException::SecureException(const SecureString& msg)
    : message(new SecureString(msg)) {}

// Move constructor
SecureException::SecureException(SecureException&& other) noexcept
    : message(std::move(other.message)) {}

SecureException::~SecureException() noexcept {}

const char* SecureException::what() const noexcept {
    return message->c_str(); // Assuming SecureString has a c_str() method
}
