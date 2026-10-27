.data
    wSystemCall DWORD 0
    qSyscallInsAddr QWORD 0

.code

    PUBLIC PrepareSyscall
    PrepareSyscall PROC
        ; RCX = 1st argument(DWORD ssn)
        ; RDX = 2st argument (PVOID syscallInstructionAddr)
        mov wSystemCall, ecx
        mov qSyscallInsAddr, rdx
        ret
    PrepareSyscall ENDP

    PUBLIC DoDirectSyscall
    DoDirectSyscall PROC
        mov r10, rcx
        mov eax, wSystemCall
        syscall
        ret 
    DoDirectSyscall ENDP

    PUBLIC DoIndirectSyscall
    DoIndirectSyscall PROC
        mov r10, rcx
        mov eax, wSystemCall
        jmp qword ptr [qSyscallInsAddr]
    DoIndirectSyscall ENDP

END