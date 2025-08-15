; Simple syscall stub for x64 Windows
.code

; NTSTATUS DoSyscall(DWORD syscallIndex, PVOID* params, ULONG paramCount)
DoSyscall PROC
    ; syscallIndex in ECX, params in RDX, paramCount in R8
    mov eax, ecx        ; Move syscall number to EAX
    
    ; For now, support up to 4 parameters (covers most syscalls)
    test r8, r8
    jz execute_syscall
    
    ; Load parameters - Windows x64 calling convention
    mov rcx, qword ptr [rdx]        ; 1st param
    cmp r8, 1
    je execute_syscall
    
    push rdx                        ; Save original param array
    mov rdx, qword ptr [rdx + 8]    ; 2nd param
    cmp r8, 2  
    je execute_syscall_cleanup
    
    mov r9, qword ptr [rsp]         ; Get original param array
    mov r8, qword ptr [r9 + 16]     ; 3rd param
    cmp r8, 3
    je execute_syscall_cleanup
    
    mov r9, qword ptr [r9 + 24]     ; 4th param

execute_syscall_cleanup:
    add rsp, 8                      ; Clean up saved param array

execute_syscall:
    mov r10, rcx                    ; Windows syscall convention
    syscall
    ret
DoSyscall ENDP

END