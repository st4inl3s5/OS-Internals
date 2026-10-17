#include <windows.h>
#include <iostream>

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA* Ldr;
} PEB;

HMODULE CustomGetModuleHandleW(const wchar_t* targetModuleName)
{
    PEB* programPEB = (PEB*)__readgsqword(0x60);
    PLIST_ENTRY listHead = &programPEB->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY currEntry = listHead->Flink;
    while(currEntry != listHead)
    {
        LDR_DATA_TABLE_ENTRY* currLdrEntry = (LDR_DATA_TABLE_ENTRY*)currEntry;
        if(!_wcsicmp(currLdrEntry->BaseDllName.Buffer, targetModuleName))
        {
            return (HMODULE)currLdrEntry->DllBase;
        }
        currEntry = currEntry->Flink;
    }
    return NULL;
}

int main()
{
    ULONG64 TEBAddress = __readgsqword(0x30);
    ULONG64 PEBAddress = __readgsqword(0x60);
    PEB* programPEB = (PEB*)PEBAddress;
    printf("[+] TEB Address: 0x%p, PEB Address: 0x%p, BeingDebugged: 0x%02X\n", TEBAddress, PEBAddress, programPEB->BeingDebugged);
    PLIST_ENTRY listHead = &programPEB->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY currEntry = listHead->Flink;
    int i = 0;
    while(currEntry != listHead)
    {
        LDR_DATA_TABLE_ENTRY* currLdrEntry = (LDR_DATA_TABLE_ENTRY*)currEntry;
        printf("--- LDR DATA TABLE ENTRY ---\n");
        printf("[+] ID: %d\n", i);
        printf("[+] BaseDllName: %ls, DllBase: 0x%p, SizeOfImage: %lu, FullDllName: %ls\n", currLdrEntry->BaseDllName.Buffer, currLdrEntry->DllBase, currLdrEntry->SizeOfImage, currLdrEntry->FullDllName.Buffer);
        printf("----------------------------\n");
        i += 1;
        currEntry = currEntry->Flink;
    }

    printf("--- Custom Function Prove ---\n");
    printf("[+] GetModuleHandleW returned: 0x%p for ntdll.dll\n", GetModuleHandleW(L"ntdll.dll"));
    printf("[+] CustomGetModuleHandleW returned: 0x%p for ntdll.dll\n", CustomGetModuleHandleW(L"ntdll.dll"));
    printf("[+] GetModuleHandleW returned: 0x%p for KERNEL32.DLL\n", GetModuleHandleW(L"KERNEL32.DLL"));
    printf("[+] CustomGetModuleHandleW returned: 0x%p for KERNEL32.DLL\n", CustomGetModuleHandleW(L"KERNEL32.DLL"));
    printf("-----------------------------\n");
    getchar();
    return 0;
}