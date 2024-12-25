.CODE

; PROXY_LOAD_PARAMS* is passed in RDX
ExtractAndJump PROC
    ; Extract the 'dllName' member (first member of the structure) to RCX
    mov rcx, [rdx]       ; Moves the address pointed to by dllName into RCX    

    ; Extract the 'pLoadLibraryA' member (second member of the structure) into R10
    mov r10, [rdx + 8]   ; Assumes 64-bit pointers, so offset is 8 bytes

    ; Now RCX contains the address of the dll string,
    ; and R10 contains the address to jump to (pLoadLibraryA)
    
    ; Now clear RDX

    mov rdx, 0

    ; Jump to the pLoadLibraryA function
    jmp r10

ExtractAndJump ENDP

END