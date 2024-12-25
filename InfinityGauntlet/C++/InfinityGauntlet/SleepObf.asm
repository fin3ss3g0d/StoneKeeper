
.CODE

; To calculate the distance of arguments in accordance to rsp and their original offsets:
; Calculate all adjustments made to the stack in bytes and add that to the original offset value in bytes of the argument
; The total will be the correct distance, then convert that to hexadecimal
; Perform stack spoofing by overwriting the return address with zero aka ZeroTrace based on https://github.com/mgeeky/ThreadStackSpoofer
PentaNtWaitAndDelayZeroTrace PROC
    ; Assuming rsp points to the return address upon function entry (original calculation)
    ; Accessing arguments five through ten after the initial stack setup (testing)
    ;mov rax, [rsp + 28h] ; Access arg5 (fifth argument)
    ;mov rbx, [rsp + 30h] ; Access arg6 (sixth argument)
    ;mov rcx, [rsp + 38h] ; Access arg7 (seventh argument)
    ;mov rdx, [rsp + 40h] ; Access arg8 (eighth argument)
    ;mov r8,  [rsp + 48h] ; Access arg9 (ninth argument)
    ;mov r9,  [rsp + 50h] ; Access arg10 (tenth argument)
    ;mov r10, [rsp + 58h] ; Access arg11 (eleventh argument)

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Save the original value of r12 (shadow space fixer gadget)
    mov r12, r8                                        ; Move the shadow space fixer gadget into r12

    push rbx										   ; Save the original value of rbx (NtWaitForSingleObject address) (arg6)
    push r13                                           ; Save the original value of r13 (PLARGE_INTEGER) (arg5)
    push r14                                           ; Save the original value of r14 - return address

    mov r14, qword ptr [rsp + 48h]                     ; Store the original value of RSP in r14 - return address (40x1 + 8x4)
    mov qword ptr [rsp + 48h], 0					   ; Set the return address to 0 to spoof the call stack    
    ;mov qword ptr [rsp + 48h], r14

    mov r10, OFFSET end_label                          ; Place the address of end_label into r10
    push r10                                           ; Push r10 (end_label) onto the stack
    
    mov rbx, [rsp + 80h]                               ; Set up NtWaitForSingleObject address in rbx (arg6 - PVOID) (40x1 + 8x5 + 48 (30h))
    mov r13, [rsp + 78h]                               ; Set up PLARGE_INTEGER in r13 (arg5 - PLARGE_INTEGER) (40x1 + 8x5 + 40 (28h))

    mov r10, [rsp + 88h]                               ; Set up NtDelayExecution address in r10 (arg7 - PVOID) (40x1 + 8x5 + 56 (38h))
    push r10                                           ; Push NtDelayExecution address onto the stack

    mov r10, 1										   ; Set up the first argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER - INFINITE) onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtDelayExecution return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call
    
    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 110h]                              ; Set up the first argument as the fourth timer object (arg11 - HANDLE) (40x2 + 8x13 + 88 (58h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 178h]                              ; Set up the first argument as the third timer object (arg10 - HANDLE) (40x3 + 8x22 + 80 (50h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 1E0h]                              ; Set up the first argument as the second timer object (arg9 - HANDLE) (40x4 + 8x31 + 72 (48h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    mov rcx, [rsp + 240h]                              ; Set up the first argument as the first timer object (arg8 - HANDLE) (40x5 + 8x39 + 64 (40h))
    mov rdx, 1										   ; Set up the second argument as TRUE
    mov r8, r13										   ; Set up the third argument as arg5 (PLARGE_INTEGER)

    jmp rbx                                            ; Jump to NtWaitForSingleObject

end_label:
    mov qword ptr [rsp + 48h], r14
    pop r14                                            ; Restore the original value of r14
    pop r13                                            ; Restore the original value of r13        
    pop rbx 										   ; Restore the original value of rbx
    pop r12                                            ; Restore the original value of r12    
           
    add rsp, 28h                                       ; Adjust the stack pointer to remove 40 bytes of space and cleanup
    
    ret

PentaNtWaitAndDelayZeroTrace ENDP

SeptaNtWaitAndDelay PROC
    ; Assuming rsp points to the return address upon function entry (original calculation)
    ; Accessing arguments five through ten after the initial stack setup (testing)
    ;mov rax, [rsp + 28h] ; Access arg5 (fifth argument)
    ;mov rbx, [rsp + 30h] ; Access arg6 (sixth argument)
    ;mov rcx, [rsp + 38h] ; Access arg7 (seventh argument)
    ;mov rdx, [rsp + 40h] ; Access arg8 (eighth argument)
    ;mov r8,  [rsp + 48h] ; Access arg9 (ninth argument)
    ;mov r9,  [rsp + 50h] ; Access arg10 (tenth argument)
    ;mov r10, [rsp + 58h] ; Access arg11 (eleventh argument)
    ;mov r11, [rsp + 60h] ; Access arg12 (twelfth argument)
    ;mov r12, [rsp + 68h] ; Access arg13 (thirteenth argument)
    ;mov r13, [rsp + 70h] ; Access arg14 (fourteenth argument)

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space
    
    push r12                                           ; Save the original value of r12 (shadow space fixer gadget)
    mov r12, r8                                        ; Move the shadow space fixer gadget into r12

    push rbx										   ; Save the original value of rbx (NtWaitForSingleObject address) (arg6)
    push r13                                           ; Save the original value of r13 (PLARGE_INTEGER) (arg5)

    mov r10, OFFSET end_label                          ; Place the address of end_label into r10
    push r10                                           ; Push r10 (end_label) onto the stack
    
    mov rbx, [rsp + 78h]                               ; Set up NtWaitForSingleObject address in rbx (arg6 - PVOID) (40x1 + 8x4 + 48 (30h))
    mov r13, [rsp + 70h]                               ; Set up PLARGE_INTEGER in r13 (arg5 - PLARGE_INTEGER) (40x1 + 8x4 + 40 (28h))

    mov r10, [rsp + 80h]                               ; Set up NtDelayExecution address in r10 (arg7 - PVOID) (40x1 + 8x4 + 56 (38h))
    push r10                                           ; Push NtDelayExecution address onto the stack

    mov r10, 1										   ; Set up the first argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER - INFINITE) onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtDelayExecution return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 120h]                              ; Set up the first argument as the seventh timer object (arg14 - HANDLE) (40x2 + 8x12 + 112 (70h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 188h]                              ; Set up the first argument as the fourth timer object (arg13 - HANDLE) (40x3 + 8x21 + 104 (68h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 1F0h]                              ; Set up the first argument as the fourth timer object (arg12 - HANDLE) (40x4 + 8x30 + 96 (60h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call
    
    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 258h]                              ; Set up the first argument as the fourth timer object (arg11 - HANDLE) (40x5 + 8x39 + 88 (58h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 2C0h]                              ; Set up the first argument as the third timer object (arg10 - HANDLE) (40x6 + 8x48 + 80 (50h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
        
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h                                       ; Adjust the stack pointer to create 40 bytes of space

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    push rbx										   ; Push NtWaitForSingleObject address onto the stack
    mov r10, [rsp + 328h]                              ; Set up the first argument as the second timer object (arg9 - HANDLE) (40x7 + 8x57 + 72 (48h))
    push r10                                           ; Push timer handle onto the stack
    push rcx                                           ; Push rcx gadget onto the stack (pop rcx; ret)

    mov r10, 1										   ; Set up the second argument as TRUE
    push r10                                           ; Push TRUE onto the stack
    push rdx                                           ; Push rdx gadget onto the stack (pop rdx; ret)

    push r13                                           ; Push arg5 (PLARGE_INTEGER) onto the stack
    push r9                                            ; Push r8 gadget onto the stack (pop r8; ret)
    
    lea r10, [r9 + 2]                                  ; pop r8; ret + 2 = ret (NtWaitForSingleObject return - "ret" placed into r10)
    push r10                                           ; push r10 (ret) onto stack

    ; Initiate the next call

    sub rsp, 28h

    push r12                                           ; Push shadow fixer gadget onto the stack (add rsp, 20h; pop rdi; ret)
    mov rcx, [rsp + 388h]                              ; Set up the first argument as the first timer object (arg8 - HANDLE) (40x8 + 8x65 + 64 (40h))
    mov rdx, 1										   ; Set up the second argument as TRUE
    mov r8, r13										   ; Set up the third argument as arg5 (PLARGE_INTEGER)

    jmp rbx                                            ; Jump to NtWaitForSingleObject

end_label:
    pop r12                                            ; Restore the original value of r12    
    pop rbx 										   ; Restore the original value of rbx
    pop r13                                            ; Restore the original value of r13    
    add rsp, 28h                                       ; Adjust the stack pointer to remove 40 bytes of space and cleanup
    
    ret

SeptaNtWaitAndDelay ENDP

END
