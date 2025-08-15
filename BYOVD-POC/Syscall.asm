.code

DoSyscall PROC
    ; RCX = syscall index
    ; RDX = parameters array
    ; R8 = parameter count
    
    ; Save registers
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    ; Move syscall index to EAX
    mov eax, ecx
    
    ; Set up parameters based on count
    test r8, r8
    jz do_syscall
    
    ; Load first 4 parameters into registers
    mov rcx, qword ptr [rdx]        ; First parameter
    cmp r8, 1
    je do_syscall
    
    mov rdx, qword ptr [rdx + 8]    ; Second parameter
    cmp r8, 2
    je do_syscall
    
    mov r8, qword ptr [rdx + 16]    ; Third parameter (note: rdx was overwritten, need to recalculate)
    ; Fix: need to use original RDX
    pop r11  ; Get original parameter count
    pop r10  ; Get original parameters array  
    pop r9   ; Get original syscall index
    push r9
    push r10
    push r11
    
    mov rcx, qword ptr [r10]        ; First parameter
    cmp r11, 1
    je do_syscall
    
    mov rdx, qword ptr [r10 + 8]    ; Second parameter
    cmp r11, 2
    je do_syscall
    
    mov r8, qword ptr [r10 + 16]    ; Third parameter
    cmp r11, 3
    je do_syscall
    
    mov r9, qword ptr [r10 + 24]    ; Fourth parameter
    
    ; For more than 4 parameters, we need to push them onto the stack
    cmp r11, 4
    jle do_syscall
    
    ; Push additional parameters in reverse order
    mov rax, r11
    sub rax, 4
    lea r10, [r10 + 32]  ; Start from 5th parameter
    
push_loop:
    test rax, rax
    jz do_syscall
    dec rax
    push qword ptr [r10 + rax * 8]
    jmp push_loop
    
do_syscall:
    ; Restore syscall index
    pop r11  ; parameter count
    pop r10  ; parameters array
    pop rax  ; syscall index (was in RCX originally)
    
    ; Prepare for syscall
    mov r10, rcx
    syscall
    
    ; Clean up stack if we pushed extra parameters
    cmp r11, 4
    jle cleanup
    sub r11, 4
    lea rsp, [rsp + r11 * 8]
    
cleanup:
    ; Restore registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    
    ret
DoSyscall ENDP

END