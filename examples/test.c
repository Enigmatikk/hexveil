#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "include/hexveil.h"


HEXVEIL_NOINLINE void test_function(void) {
    printf("Running protected function...\n");
    
    
    int64_t result = HEXVEIL_VM_ADD(100, 200);
    printf("VM Operation result: %lld\n", result);
    
    
    const char* protected_str = hexveil_encrypt_string_safe("This string is protected");
    printf("Protected string: %s\n", protected_str);
}


static int show_message(const char* title, const char* msg) {
    printf("Attempting to show message box...\n");
    
    HMODULE user32 = LoadLibraryA("user32.dll");
    if(!user32) {
        printf("Failed to load user32.dll (error: %lu)\n", GetLastError());
        return 0;
    }
    
    typedef int (WINAPI *MsgBoxFunc)(HWND, LPCSTR, LPCSTR, UINT);
    MsgBoxFunc msgbox = (MsgBoxFunc)GetProcAddress(user32, "MessageBoxA");
    if(!msgbox) {
        printf("Failed to get MessageBoxA (error: %lu)\n", GetLastError());
        FreeLibrary(user32);
        return 0;
    }
    
    printf("Showing message box...\n");
    int result = msgbox(NULL, msg, title, MB_OK | MB_ICONINFORMATION);
    
    FreeLibrary(user32);
    return result;
}

int main(void) {
    
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    
    printf("Starting HexVeil test...\n");
    
    
    srand((unsigned int)time(NULL));
    
    printf("Initializing protections...\n");
    
    
    hexveil_init_nanomites();
    HEXVEIL_PROTECT_FUNCTION(test_function);
    
    printf("Running test function...\n");
    test_function();
    
    printf("Showing final message...\n");
    show_message("HexVeil Test", 
        "Protection test complete!\n"
        "- VM Operations\n"
        "- String Protection\n"
        "- Basic Anti-Debug\n"
        "Try debugging now!");
    
    printf("Press Enter to exit...\n");
    getchar();
    
    return 0;
}
