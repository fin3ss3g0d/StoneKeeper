#include <exception>
#include <memory>

class SecureString;

class SecureException : public std::exception {
private:
    std::unique_ptr<SecureString> message;

public:
    SecureException(const SecureString& msg);
    SecureException(SecureException&& other) noexcept;
    virtual ~SecureException() noexcept;
    virtual const char* what() const noexcept;
};
