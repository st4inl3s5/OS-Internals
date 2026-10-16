#include <windows.h>
#include <iostream>

typedef long NTSTATUS;

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG PageProtection);
typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);

int main(int argc, char** argv)
{
    HMODULE ntdllModuleBase = GetModuleHandleA("ntdll.dll");
    FARPROC NtAllocateVirtualMemoryBase = GetProcAddress(ntdllModuleBase, "NtAllocateVirtualMemory");
    FARPROC NtProtectVirtualMemoryBase = GetProcAddress(ntdllModuleBase, "NtProtectVirtualMemory");
    printf("[+] Resolved native APIs: NtAllocateVirtualMemory: 0x%p, NtProtectVirtualMemory: 0x%p\n", NtAllocateVirtualMemoryBase, NtProtectVirtualMemoryBase);
    fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)NtAllocateVirtualMemoryBase;
    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)NtProtectVirtualMemoryBase;
    HANDLE currentProcessHandle = GetCurrentProcess();
    PVOID allocatedBaseAddress = NULL;
    SIZE_T allocatedRegionSize = 4096;
    NTSTATUS returnNtStatus;
    returnNtStatus = NtAllocateVirtualMemory(currentProcessHandle, &allocatedBaseAddress, 0, &allocatedRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(returnNtStatus != 0)
    {
        printf("[-] NtAllocateVirtualMemory failed: 0x%08X\n", returnNtStatus);
        return 1;
    }
    printf("[+] NtAllocateVirtualMemory allocated memory. Base: 0x%p, region size: %zu\n", allocatedBaseAddress, allocatedRegionSize);
    unsigned char asmShellcode[] = {0xB8, 0x39, 0x05, 0x00, 0x00, 0xC3};
    memcpy(allocatedBaseAddress, asmShellcode, 6);
    printf("[+] Shellcode copied to allocated base address.\n");
    typedef int (*fnShellcode)();
    fnShellcode Shellcode = (fnShellcode)allocatedBaseAddress;

    // Experiment A - Test Hardware DEP (Should be crash)
    //int retVal = Shellcode();
    //printf("[+] Shellcode function returned: %d\n", retVal);

    // Experiment B
    ULONG oldProtection = NULL;
    ULONG newProtection = PAGE_EXECUTE_READ;
    returnNtStatus = NtProtectVirtualMemory(currentProcessHandle, &allocatedBaseAddress, &allocatedRegionSize, newProtection, &oldProtection);
    if(returnNtStatus != 0)
    {
        printf("[-] NtProtectVirtualMemory failed: 0x%08X\n", returnNtStatus);
        return 1;
    }
    printf("[+] NtProtectVirtualMemory flipped memory protection 0x%X(RW) --> 0x%X(RX).\n", oldProtection, newProtection);
    int shellcodeRetVal = Shellcode();
    printf("[+] Shellcode function returned: %d\n", shellcodeRetVal);
    getchar();
    return 0;
}