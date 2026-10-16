#include <iostream>
#include <windows.h>

typedef long NTSTATUS;
typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);


int main(int argc, char** argv)
{
    HMODULE ntdllModuleBase = GetModuleHandleA("ntdll.dll");
    FARPROC NtAllocateVirtualMemoryBase = GetProcAddress(ntdllModuleBase, "NtAllocateVirtualMemory");
    printf("[+] NtAllocateVirtualMemory address: 0x%p\n", NtAllocateVirtualMemoryBase);
    fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)NtAllocateVirtualMemoryBase;
    PVOID allocatedBaseAddress = NULL;
    SIZE_T allocatedSize = 100;
    NTSTATUS ntStatus = NtAllocateVirtualMemory(GetCurrentProcess(), &allocatedBaseAddress, 0, &allocatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] Called NtAllocateVirtualMemory, returned NTSTATUS: 0x%08X\n", ntStatus);
    printf("[+] Allocated virtual base address: 0x%p, size: %llu\n", allocatedBaseAddress, allocatedSize);
    char* ex_str = "test12345";
    memcpy(allocatedBaseAddress, ex_str, strlen(ex_str));
    printf("[+] The string in the allocated virtual memory: %s\n", allocatedBaseAddress);
    getchar();
    return 0;
}