.CODE

; Assuming MyParams* is passed in RDX
ExtractAndJump PROC
    ; Extract the 'dll' member (first member of the structure) to RCX
    mov rcx, [rdx]       ; Moves the address pointed to by dll into RCX    

    ; Extract the 'pLoadLibraryA' member (second member of the structure) into RAX
    mov r10, [rdx + 8]   ; Assumes 64-bit pointers, so offset is 8 bytes

    ; Now RCX contains the address of the dll string,
    ; and RAX contains the address to jump to (pLoadLibraryA)

    mov rdx, 0

    ; For demonstration purposes only: perform the jump
    ; This is generally unsafe without proper setup
    jmp r10

ExtractAndJump ENDP

END