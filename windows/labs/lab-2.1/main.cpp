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

void ParsePE(const char* peName)
{
    printf("---------- PARSING PE: %s ----------\n", peName);
    BYTE* peBase = (BYTE*)CustomGetModuleHandleA(peName);
    PIMAGE_DOS_HEADER peImageDosHeader = (PIMAGE_DOS_HEADER)peBase;
    printf("----- IMAGE DOS HEADER -----\n");
    if(peImageDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
    {
        printf("[+] DOS Magic is MZ: 0x%04X\n", peImageDosHeader->e_magic);
    }
    else {
        printf("[+] DOS Magic is not MZ: 0x%04X\n", peImageDosHeader->e_magic);
    }
    printf("[+] IMAGE_NT_HEADERS64 RVA location(e_lfanew): 0x%08X\n", peImageDosHeader->e_lfanew);
    PIMAGE_NT_HEADERS64 peNtHeaders = (PIMAGE_NT_HEADERS64)(peBase + peImageDosHeader->e_lfanew);
    printf("------------------------------\n");
    printf("----- IMAGE NT HEADERS64 -----\n");
    if(peNtHeaders->Signature == IMAGE_NT_SIGNATURE)
    {
        printf("[+] Image NT Header signature is PE: 0x%08X\n", peNtHeaders->Signature);
    }
    else {
        printf("[+] Image NT Header signature is not PE: 0x%08X\n", peNtHeaders->Signature);
    }
    printf("--- FileHeader ---\n");
    printf("[+] Machine: 0x%04X\n[+] NumberOfSections: %u\n[+] SizeOfOptionalHeader: %u\n", peNtHeaders->FileHeader.Machine, peNtHeaders->FileHeader.NumberOfSections, peNtHeaders->FileHeader.SizeOfOptionalHeader);
    printf("----------------------\n");
    printf("--- OptionalHeader ---\n");
    printf("[+] Magic: 0x%04X\n[+] Preferred ImageBase: 0x%llX vs Actual loaded base: 0x%p\n[+] RVA AddressOfEntryPoint: 0x%p, Actual AddressOfEntryPoint: 0x%p\n[+] SizeOfImage: 0x%08X\n[+] SectionAlignment: 0x%08X vs FileAlignment: 0x%08X\n", peNtHeaders->OptionalHeader.Magic, peNtHeaders->OptionalHeader.ImageBase, peBase, peNtHeaders->OptionalHeader.AddressOfEntryPoint, (peBase + peNtHeaders->OptionalHeader.AddressOfEntryPoint), peNtHeaders->OptionalHeader.SizeOfImage, peNtHeaders->OptionalHeader.SectionAlignment, peNtHeaders->OptionalHeader.FileAlignment);
    printf("- DataDirectory Dump -\n");
    printf("[+] IMAGE_DIRECTORY_ENTRY_EXPORT(DataDirectory[0]) - RVA: 0x%08X, Size: 0x%08X\n", peNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, peNtHeaders->OptionalHeader.DataDirectory[0].Size);
    printf("[+] IMAGE_DIRECTORY_ENTRY_IMPORT(DataDirectory[1]) - RVA: 0x%08X, Size: 0x%08X\n", peNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, peNtHeaders->OptionalHeader.DataDirectory[1].Size);
    printf("[+] IMAGE_DIRECTORY_ENTRY_EXCEPTION(DataDirectory[3]) - RVA: 0x%08X, Size: 0x%08X\n", peNtHeaders->OptionalHeader.DataDirectory[3].VirtualAddress, peNtHeaders->OptionalHeader.DataDirectory[3].Size);
    printf("[+] IMAGE_DIRECTORY_ENTRY_BASERELOC(DataDirectory[5]) - RVA: 0x%08X, Size: 0x%08X\n", peNtHeaders->OptionalHeader.DataDirectory[5].VirtualAddress, peNtHeaders->OptionalHeader.DataDirectory[5].Size);
    printf("[+] IMAGE_DIRECTORY_ENTRY_IAT(DataDirectory[12]) - RVA: 0x%08X, Size: 0x%08X\n", peNtHeaders->OptionalHeader.DataDirectory[12].VirtualAddress, peNtHeaders->OptionalHeader.DataDirectory[12].Size);
    printf("----------------------\n");
    printf("------------------------------\n");
    printf("----- IMAGE SECTION HEADERS -----\n");
    PIMAGE_SECTION_HEADER peSecHeader = IMAGE_FIRST_SECTION(peNtHeaders);
    for(int i = 0; i < peNtHeaders->FileHeader.NumberOfSections; i++)
    {
        printf("-----\n");
        printf("%.8s\n\tRVA: 0x%08x\n\tVirtualSize: 0x%08X\n\tPointerToRawData: 0x%08X\n\tSizeOfRawData: 0x%08X\n\tCharacteristics(raw): 0x%08X\n\tCharacteristics(human): [", peSecHeader->Name, peSecHeader->VirtualAddress, peSecHeader->Misc.VirtualSize, peSecHeader->PointerToRawData, peSecHeader->SizeOfRawData, peSecHeader->Characteristics);
        if(peSecHeader->Characteristics & IMAGE_SCN_MEM_READ)
        {
            printf("R");
        }
        if(peSecHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
        {
            printf("W");
        }
        if(peSecHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            printf("X");
        }
        printf("]\n-----\n");
        peSecHeader++;
    }
    printf("------------------------------------\n");
}

int main()
{
    //printf("CustomGetModuleHandleA returned: 0x%p\nGetModuleHandleA returned: 0x%p\n", CustomGetModuleHandleA("ntdll.dll"), GetModuleHandleA("ntdll.dll"));
    //printf("CustomGetModuleHandleA returned: 0x%p\nGetModuleHandleA returned: 0x%p\n", CustomGetModuleHandleA("KERNELBASE.DLL"), GetModuleHandleA("KERNELBASE.DLL"));
    //printf("CustomGetModuleHandleA returned: 0x%p\nGetModuleHandleA returned: 0x%p", CustomGetModuleHandleA(NULL), GetModuleHandleA(NULL));
    //ParsePE(NULL);
    ParsePE("ntdll.dll");
    return 0;
}