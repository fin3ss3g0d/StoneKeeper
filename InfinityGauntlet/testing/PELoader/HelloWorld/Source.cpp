#include <stdio.h>

int main(int argc, char** argv) {
    // Check if there are more than 1 arguments (the first argument is the program name itself)
    if (argc > 1) {
        printf("Command-line arguments found:\n");
        // Start from 1 to skip the program name
        for (int i = 1; i < argc; i++) {
            printf("Argument %d: %s\n", i, argv[i]);
        }
    }
    else {
        printf("No command-line arguments found.\n");
    }

    return 0;
}
