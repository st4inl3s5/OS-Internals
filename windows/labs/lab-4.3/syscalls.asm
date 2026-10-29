.data
    wSystemCall DWORD 0
    qSyscallInsAddr QWORD 0
    qGadgetAddr QWORD 0
    dwGadgetFrameSize DWORD 0
    qSavedRbx QWORD 0
    qRestoreStubPtr QWORD 0

.code

    PUBLIC PrepareSpoofedSyscall
    PrepareSpoofedSyscall PROC
        ; RCX = 1st argument(DWORD ssn)
        ; RDX = 2st argument (PVOID syscallInstructionAddr)
        ; R8 = gadgetAddr (KernelBase.dll jmp qword ptr [rbx])
        ; R9D = gadgetFrameSize
        mov wSystemCall, ecx
        mov qSyscallInsAddr, rdx
        mov qGadgetAddr, r8
        mov dwGadgetFrameSize, r9d
        ret
    PrepareSpoofedSyscall ENDP

    PUBLIC DoDirectSyscall
    DoDirectSyscall PROC
        mov r10, rcx
        mov eax, wSystemCall
        syscall
        ret 
    DoDirectSyscall ENDP

    PUBLIC DoSpoofedIndirectSyscall
    DoSpoofedIndirectSyscall PROC
        mov qSavedRbx, rbx
        mov eax, dwGadgetFrameSize
        sub rsp, rax
        mov r10, qword ptr [rsp + rax + 28h]
        mov qword ptr [rsp + 20h], r10
        mov r10, qword ptr [rsp + rax + 30h]
        mov qword ptr [rsp + 28h], r10
        push qGadgetAddr
        lea rax, RestoreAfterSyscall
        mov qRestoreStubPtr, rax
        lea rbx, qRestoreStubPtr
        mov r10, rcx
        mov eax, wSystemCall
        jmp qword ptr [qSyscallInsAddr]

    RestoreAfterSyscall:
        mov ecx, dwGadgetFrameSize
        add rsp, rcx
        mov rbx, qSavedRbx
        ret
    DoSpoofedIndirectSyscall ENDP

END