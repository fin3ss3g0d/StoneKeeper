#include "windows.h"
#include "stdio.h"
#include "stdlib.h" // For strtol

unsigned long djb2(unsigned char* str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; // hash * 33 + c

    return hash;
}

unsigned long xor_hash(unsigned long hash, unsigned long key) {
    return hash ^ key;
}

int main(int argc, char** argv) {

    if (argc < 3) // Check for 2 arguments now
    {
        printf("USAGE: %s <FUNCTION_NAME> <KEY>", argv[0]);
        return -1;
    }

    unsigned char* name = (unsigned char*)argv[1];
    unsigned long key = strtoul(argv[2], NULL, 0); // Convert second argument to unsigned long
    unsigned long hash = djb2(name);
    unsigned long hash_crypted = xor_hash(hash, key);

    printf("0x%x\n", hash_crypted);

    return 0;
}
