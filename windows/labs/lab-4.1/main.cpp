#pragma comment(lib, "user32.lib")
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

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(HANDLE processHandle, 
    PVOID* BaseAddress, ULONG ZeroBits, PULONG RegionSize, 
    ULONG AllocationType, ULONG Protect);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(HANDLE processHandle, 
    PVOID* BaseAddress, PULONG NumberOfBytesToProtect, 
    ULONG NewAccessProtection, PULONG OldAccessProtection);

// Custom Function Templates

typedef BOOL(WINAPI* fnDllMain)(HINSTANCE hinstDLL, DWORD fdwReason, 
    LPVOID lpvReserved);

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

ULONG GetSectionProtection(DWORD characteristics)
{
    if(characteristics & IMAGE_SCN_MEM_EXECUTE)
    {
        if(characteristics & IMAGE_SCN_MEM_WRITE)
        {
            return PAGE_EXECUTE_READWRITE;
        }
        if(characteristics & IMAGE_SCN_MEM_READ)
        {
            return PAGE_EXECUTE_READ;
        }
        return PAGE_EXECUTE;
    }
    if(characteristics & IMAGE_SCN_MEM_WRITE)
    {
        return PAGE_READWRITE;
    }
    if(characteristics & IMAGE_SCN_MEM_READ)
    {
        return PAGE_READONLY;
    }
    return PAGE_NOACCESS;
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
            return (FARPROC)(baseModuleAddress + funcRVAs[ordinals[i]]);
        }
    }
    return NULL;
}

FARPROC CustomGetProcAddressByOrdinal(HMODULE baseModule, WORD ordinal)
{
    BYTE* baseModuleAddress = (BYTE*)baseModule;
    PIMAGE_DOS_HEADER moduleImageDosHeader = (PIMAGE_DOS_HEADER)baseModuleAddress;
    PIMAGE_NT_HEADERS64 moduleNtHeaders = (PIMAGE_NT_HEADERS64)(baseModuleAddress + moduleImageDosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY moduleExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(baseModuleAddress + moduleNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    WORD* ordinals = (WORD*)(baseModuleAddress + moduleExportDirectory->AddressOfNameOrdinals);
    DWORD* funcRVAs = (DWORD*)(baseModuleAddress + moduleExportDirectory->AddressOfFunctions);
    return (FARPROC)(baseModuleAddress + funcRVAs[ordinals[ordinal]]);
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

int main()
{
    GetDesktopWindow();
    HMODULE hNtdll = CustomGetModuleHandleA("ntdll.dll");
    fnNtAllocateVirtualMemory NtAllocateVirtualMemory = (fnNtAllocateVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x6793C34C);
    fnNtProtectVirtualMemory NtProtectVirtualMemory = (fnNtProtectVirtualMemory)CustomGetProcAddressByDjb2Hash(hNtdll, 0x082962C8);
    printf("[!] Nt functions resolved successfully.\n");
    HANDLE hFile = CreateFileA("testdll.dll", GENERIC_READ, 
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD sFile = GetFileSize(hFile, NULL);
    BYTE* rawPe = (BYTE*)malloc(sFile);
    DWORD bytesRead = NULL;
    if(!ReadFile(hFile, rawPe, sFile, &bytesRead, NULL))
    {
        printf("[-] Unexpected: test.dll couldn't read. Make sure it is present in the same directory with host program.\n");
        return 1;
    }
    printf("[+] Read testdll.dll, bytes read: %d\n", bytesRead);

    // Step 1: Parse the RAW PE Headers & Allocate SizeOfImage Bytes
    printf("[!] Initiating Step 1: Parse the RAW PE Headers & Allocate SizeOfImage Bytes\n");
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)rawPe;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)(rawPe + dosHeader->e_lfanew);
    BYTE* mappedBase = NULL;
    ULONG imageSize = ntHeaders->OptionalHeader.SizeOfImage;
    NTSTATUS ntStatus = NULL;
    ntStatus = NtAllocateVirtualMemory((HANDLE)-1, (PVOID*)&mappedBase, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(ntStatus != 0x00000000)
    {
        printf("[-] Unexpected: Couldn't allocate virtual memory, ntStatus: 0x%08X\n", ntStatus);
        return 1;
    }
    printf("[+] Allocated %d bytes of virtual memory for mapped base.\n", imageSize);

    // Step 2: Copy PE Headers & Stretch Each Section into mappedBase
    printf("[!] Initiating Step 2: Copy PE Headers & Stretch Each Section into mappedBase\n");
    memcpy(mappedBase, rawPe, ntHeaders->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for(WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        if(sectionHeader[i].SizeOfRawData > 0)
        {
            BYTE* destSection = mappedBase + sectionHeader[i].VirtualAddress;
            BYTE* srcSection = rawPe + sectionHeader[i].PointerToRawData;
            memcpy(destSection, srcSection, sectionHeader[i].SizeOfRawData);
        }
    }
    printf("[+] Copied and stretched each section into mappedBase.\n");

    // Step 3: Process Base Relocations
    printf("[!] Initiating Step 3: Process Base Relocations\n");
    LONGLONG delta = (LONGLONG)(mappedBase - (BYTE*)ntHeaders->OptionalHeader.ImageBase);
    IMAGE_DATA_DIRECTORY relocDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(delta != 0 && relocDir.VirtualAddress != 0 && relocDir.Size > 0)
    {
        PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)(mappedBase + relocDir.VirtualAddress);
        while(relocBlock->VirtualAddress)
        {
            DWORD count = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((BYTE*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
            for(DWORD i = 0; i < count; i++)
            {
                WORD type = entries[i] >> 12;
                WORD offset = entries[i] & 0x0FFF;
                if(type == IMAGE_REL_BASED_DIR64)
                {
                    ULONGLONG* patchAddr = (ULONGLONG*)(mappedBase + relocBlock->VirtualAddress + offset);
                    *patchAddr += delta;
                }
            }
            relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)relocBlock + relocBlock->SizeOfBlock);
        }
    }
    printf("[+] Processed base relocations using delta: 0x%llX\n", delta);

    // Step 4: Resolve Imports & Patch IAT
    printf("[!] Initiating Step 4: Resolve Imports & Patch IAT\n");
    IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(importDir.VirtualAddress != 0 && importDir.Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(mappedBase + importDir.VirtualAddress);
        while(importDesc->Name)
        {
            const char* dllName = (const char*)(mappedBase + importDesc->Name);
            HMODULE hDepModule = CustomGetModuleHandleA(dllName);
            if(!hDepModule)
            {
                // Module dependency not loaded by default,
                // hDepModule = GetModuleHandleA(dllName);
                // can be used, but we don't want EDR notifiers
                printf("[-] %s module not loaded by default, not triggering EDRs via GetModuleHandleA.\n", dllName);
                return 1;
            }
            PIMAGE_THUNK_DATA64 origThunk = (PIMAGE_THUNK_DATA64)(mappedBase + (importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk));
            PIMAGE_THUNK_DATA64 iatThunk = (PIMAGE_THUNK_DATA64)(mappedBase + importDesc->FirstThunk);
            while(origThunk->u1.AddressOfData != 0)
            {
                FARPROC funcAddr = NULL;
                if(IMAGE_SNAP_BY_ORDINAL64(origThunk->u1.Ordinal))
                {
                    WORD ordinal = (WORD)IMAGE_ORDINAL64(origThunk->u1.Ordinal);
                    funcAddr = CustomGetProcAddressByOrdinal(hDepModule, ordinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(mappedBase + origThunk->u1.AddressOfData);
                    funcAddr = CustomGetProcAddress(hDepModule, importByName->Name);
                }
                iatThunk->u1.Function = (ULONGLONG)funcAddr;
                origThunk++;
                iatThunk++;
            }
            importDesc++;
        }
    }
    printf("[+] Resolved imports and patched IAT.\n");

    // Step 5: Enforce Per-Section Memory Protections
    printf("[!] Initiating Step 5: Enforce Per-Section Memory Protections\n");
    WORD i;
    for(i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
    {
        PVOID secBase = mappedBase + sectionHeader[i].VirtualAddress;
        SIZE_T secSize = sectionHeader[i].Misc.VirtualSize;
        if(!secSize) {
            secSize = sectionHeader[i].SizeOfRawData;
        }
        ULONG protect = GetSectionProtection(sectionHeader[i].Characteristics);
        ULONG oldProtection = 0;
        ntStatus = NtProtectVirtualMemory((HANDLE)-1, &secBase, (PULONG)&secSize, protect, &oldProtection);
        if(ntStatus != 0x00000000)
        {
            printf("[-] Unexpected: Couldn't protect the memory at: 0x%p, error code: 0x%08X\n", secBase, ntStatus);
            return 1;
        }
    }
    printf("[+] Protected %d sections of virtual memory.\n", i);

    // Step 6: Call DllMain
    printf("[!] Initiating Step 6: Call AddressOfEntryPoint of testdll.dll\n");
    fnDllMain DllMain = (fnDllMain)(mappedBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
    DllMain((HINSTANCE)mappedBase, DLL_PROCESS_ATTACH, NULL);
    printf("[+] Called DllMain at 0x%p\n", DllMain);
    getchar();
    return 0;
}