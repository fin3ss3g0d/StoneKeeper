.CODE

; LOAD_CONTEXT* is passed in RDX
IoCompletionCallback PROC
    ; Extract the 'DllName' member (first member of the structure) to RCX
    mov rcx, [rdx]       ; Moves the address pointed to by DllName into RCX

    ; Extract the 'pLoadLibraryA' member (second member of the structure) into RAX
    mov rax, [rdx + 8]   ; Assumes 64-bit pointers, so offset is 8 bytes

    ; Now RCX contains the address of the dll string,
    ; and RAX contains the address to jump to (pLoadLibraryA)

    xor rdx, rdx        ; Clear RDX

    ; Jump to LoadLibraryA address, avoiding call instruction and return address placement on stack
    jmp rax
IoCompletionCallback ENDP

END