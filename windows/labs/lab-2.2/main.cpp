#include <windows.h>
#include <iostream>
#include <wchar.h>
#include <stdlib.h>

typedef struct {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

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

HMODULE CustomGetModuleHandleA(const char* targetModuleName)
{
    ULONG64 pebAddress = __readgsqword(0x60);
    PPEB peb = (PPEB)pebAddress;
    PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
    PLIST_ENTRY currEntry = listHead->Flink;
    while(currEntry != listHead)
    {
        PLDR_DATA_TABLE_ENTRY currLdrEntry = (PLDR_DATA_TABLE_ENTRY)currEntry;
        char* currModuleName = (char*)calloc(currLdrEntry->BaseDllName.Length, sizeof(char*));
        wcstombs(currModuleName, currLdrEntry->BaseDllName.Buffer, currLdrEntry->BaseDllName.Length);
        if(!targetModuleName || !strcmpi(currModuleName, targetModuleName))
        {
            free(currModuleName);
            return (HMODULE)currLdrEntry->DllBase;
        }
        free(currModuleName);
        currEntry = currEntry->Flink;
    }
    return NULL;
}

FARPROC CustomGetProcAddress(HMODULE baseModule, const char* targetFuncName)
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
        if(!strcmp(currFuncName, targetFuncName))
        {
            printf("[+] %s found in loop index(i): %d, func index(ordinals[i]): %d\n", targetFuncName, i, ordinals[i]);
            return (FARPROC)(baseModuleAddress + funcRVAs[ordinals[i]]);
        }
    }
    return NULL;
}

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

FARPROC CustomGetProcAddressByHash(HMODULE baseModule, DWORD targetHash)
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
        if(HashStringDjb2(currFuncName) == targetHash)
        {
            printf("[+] 0x%08X found in loop index(i): %d, func index(ordinals[i]): %d\n", targetHash, i, ordinals[i]);
            return (FARPROC)(baseModuleAddress + funcRVAs[ordinals[i]]);
        }
    }
    return NULL;
}

int main()
{
    HMODULE ntDllHmodule = CustomGetModuleHandleA("ntdll.dll");
    printf("[+] CustomGetProcAddress(NtAllocateVirtualMemory) returned: 0x%p\n", CustomGetProcAddress(ntDllHmodule, "NtAllocateVirtualMemory"));
    printf("[+] GetProcAddress(NtAllocateVirtualMemory) returned: 0x%p\n", GetProcAddress(ntDllHmodule, "NtAllocateVirtualMemory"));
    printf("DJB2(NtAllocateVirtualMemory) = 0x%08X\n", HashStringDjb2("NtAllocateVirtualMemory"));
    printf("DJB2(NtProtectVirtualMemory) = 0x%08X\n", HashStringDjb2("NtProtectVirtualMemory"));
    printf("[+] CustomGetProcAddressByHash(0x6793C34C) returned: 0x%p\n", CustomGetProcAddressByHash(ntDllHmodule, 0x6793C34C));
    printf("[+] CustomGetProcAddressByHash(0x082962C8) returned: 0x%p\n", CustomGetProcAddressByHash(ntDllHmodule, 0x082962C8));
    return 0;
}