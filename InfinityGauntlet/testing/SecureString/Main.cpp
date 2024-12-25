#include "SecureString.hpp"
#include "SecureWideString.hpp"

void Test() {
    SecureString string1("Hello World!");
    SecureString string2 = string1;
}

int main() {
    Test();
    getchar();
    return 0;
}
