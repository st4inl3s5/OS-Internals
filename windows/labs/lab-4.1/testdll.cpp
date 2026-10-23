#include <windows.h>

const char* g_Message = "Hello from Manually Mapped testdll.dll!";
const char* g_Title   = "Lab 4.1 - Reflective / Manual Mapping";

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, g_Message, g_Title, MB_OK);
    }
    return TRUE;
}
