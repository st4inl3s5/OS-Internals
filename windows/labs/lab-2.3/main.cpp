#pragma comment(lib, "user32.lib")
#include <windows.h>
#include <wchar.h>
#include <iostream>

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

typedef LONG NTSTATUS;


typedef int(WINAPI *fnMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

typedef NTSTATUS(NTAPI *fnNtProtectVirtualMemory)(HANDLE processHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);

fnMessageBoxA g_OrigMessageBoxA = NULL;


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

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType){
    printf("[!] HookedMessageBoxA intercepted call! Original text: '%s', Original caption: '%s'\n", lpText, lpCaption);
    return g_OrigMessageBoxA(hWnd, "Hacked by IAT Hook!", "IAT Hooked!", MB_ICONWARNING | MB_OK);
}


int main()
{
    MessageBoxA(NULL, "Hello from normal main()!", "Normal Title", MB_OK);
    BYTE* mainBaseAddr = (BYTE*)CustomGetModuleHandleA(NULL);
    HMODULE ntdllBaseAddr = CustomGetModuleHandleA("ntdll.dll");
    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)CustomGetProcAddressByHash(ntdllBaseAddr, 0x082962C8);
    PIMAGE_DOS_HEADER mainImageDosHeader = (PIMAGE_DOS_HEADER)mainBaseAddr;
    PIMAGE_NT_HEADERS64 mainImageNtHeaders = (PIMAGE_NT_HEADERS64)(mainBaseAddr + mainImageDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR mainImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(mainBaseAddr + mainImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while(mainImageImportDescriptor->Name != 0)
    {
        const char* dllName = (const char*)(mainBaseAddr + mainImageImportDescriptor->Name);
        printf("[+] Imported DLL name found: %s\n", dllName);
        PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)(mainBaseAddr + mainImageImportDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA64 iatThunk = (PIMAGE_THUNK_DATA64)(mainBaseAddr + mainImageImportDescriptor->FirstThunk);
        while(origThunk->u1.AddressOfData != 0)
        {
            if(!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64))
            {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(mainBaseAddr + origThunk->u1.AddressOfData);
                printf("[+] Imported function name: %s, Target function address: 0x%llX\n", importByName->Name, iatThunk->u1.Function);
                if(!strcmp(importByName->Name, "MessageBoxA"))
                {
                    g_OrigMessageBoxA = (fnMessageBoxA)iatThunk->u1.Function;
                    ULONG oldProtection = NULL;
                    SIZE_T regionSize = sizeof(ULONGLONG);
                    PVOID protectAddr = &iatThunk->u1.Function;
                    NtProtectVirtualMemory(GetCurrentProcess(), &protectAddr, &regionSize, PAGE_READWRITE, &oldProtection);
                    printf("[+] MessageBoxA page permissions: RW\n");
                    iatThunk->u1.Function = (ULONGLONG)HookedMessageBoxA;
                    printf("[+] MessageBoxA hooked! Restoring the page permissions...\n");
                    NtProtectVirtualMemory(GetCurrentProcess(), &protectAddr, &regionSize, PAGE_READONLY, &oldProtection);
                    printf("[+] Page permissions restored: R\n");
                }
            }
            origThunk++;
            iatThunk++;
        }
        mainImageImportDescriptor++;
    }
    MessageBoxA(NULL, "Hello from normal main()! 2", "Normal Title 2", MB_OK);
    return 0;
}