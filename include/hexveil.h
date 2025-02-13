
/*  888    888                   888     888          d8b 888 
    888    888                   888     888          Y8P 888 
    888    888                   888     888              888 
    8888888888  .d88b.  888  888 Y88b   d88P  .d88b.  888 888 
    888    888 d8P  Y8b `Y8bd8P'  Y88b d88P  d8P  Y8b 888 888 
    888    888 88888888   X88K     Y88o88P   88888888 888 888 
    888    888 Y8b.     .d8""8b.    Y888P    Y8b.     888 888 
    888    888  "Y8888  888  888     Y8P      "Y8888  888 888
    
                        Made by Engimatikk <3             
    */


#ifndef HEXVEIL_H
#define HEXVEIL_H

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <time.h>


#if defined(_M_X64) || defined(__x86_64__)
    #define HEXVEIL_ARCH_X64
#elif defined(_M_IX86) || defined(__i386__)
    #define HEXVEIL_ARCH_X86
#else
    #error "Unsupported architecture"
#endif


#if defined(_MSC_VER)
    #define HEXVEIL_NOINLINE __declspec(noinline)
    #define HEXVEIL_ASM_BLOCK(x) __asm { x }
#else
    #define HEXVEIL_NOINLINE __attribute__((noinline))
    #define HEXVEIL_ASM_BLOCK(x) __asm__ __volatile__(x)
#endif


#define HEXVEIL_TRY if(1)
#define HEXVEIL_EXCEPT else if(0)


#define HEXVEIL_RND(min, max) \
    ((min) + (rand() % ((max) - (min) + 1)))


static inline char* hexveil_encrypt_string_safe(const char* str) {
    static char buffer[4096];
    static const uint32_t key = 0x12345678;
    size_t len = strlen(str);
    size_t i;
    
    for(i = 0; i < len && i < sizeof(buffer) - 1; i++) {
        buffer[i] = str[i] ^ (uint8_t)(key >> ((i & 3) * 8));
    }
    buffer[i] = '\0';
    
    return buffer;
}


static inline void* hexveil_alloc_safe(size_t size) {
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

static inline void hexveil_free_safe(void* ptr) {
    HeapFree(GetProcessHeap(), 0, ptr);
}


static inline bool hexveil_detect_debugger_safe(void) {
    return IsDebuggerPresent() != 0;
}


#define HEXVEIL_VM_ADD(a,b) ((a) + (b) ^ 0x12345678)
#define HEXVEIL_VM_SUB(a,b) ((a) - (b) ^ 0x87654321)
#define HEXVEIL_VM_MUL(a,b) ((a) * (b) ^ 0xFEDCBA98)
#define HEXVEIL_VM_DIV(a,b) ((b) ? ((a) / (b) ^ 0x89ABCDEF) : 0)


#define HEXVEIL_DEAD_CODE() do { \
    volatile int x = rand(); \
    volatile int y = rand(); \
    if(x > y) { x = y; } \
} while(0)


#define HEXVEIL_CLEAR_STACK() do { \
    volatile uint8_t stack[32] = {0}; \
    memset((void*)stack, 0, sizeof(stack)); \
} while(0)


static inline void hexveil_protect_code_section(void) {
    DWORD oldProtect;
    HMODULE hModule = GetModuleHandle(NULL);
    if(!hModule) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for(WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if(section[i].Characteristics & IMAGE_SCN_CNT_CODE) {
            VirtualProtect((BYTE*)hModule + section[i].VirtualAddress,
                          section[i].Misc.VirtualSize,
                          PAGE_EXECUTE_READ,
                          &oldProtect);
        }
    }
}

static inline void hexveil_corrupt_pe_headers(void) {
    HMODULE hModule = GetModuleHandle(NULL);
    if(!hModule) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    DWORD oldProtect;
    
    
    VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &oldProtect);
    
    
    dosHeader->e_res[0] ^= 0xFF;
    dosHeader->e_res[1] ^= 0xFF;
    
    
    VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), oldProtect, &oldProtect);
}


static inline bool hexveil_detect_vm(void) {
    bool detected = false;
    
    
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if(si.dwNumberOfProcessors < 2) {
        detected = true;
    }
    
    
    HKEY hKey;
    if(RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
                    "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",
                    0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        detected = true;
    }
    
    return detected;
}


typedef struct {
    uint32_t address;
    uint8_t original_byte;
    uint8_t key;
} Nanomite;

#define MAX_NANOMITES 1024
static Nanomite g_nanomites[MAX_NANOMITES];
static size_t g_nanomite_count = 0;


static inline void hexveil_add_nanomite(void* address) {
    if(g_nanomite_count >= MAX_NANOMITES) return;
    
    DWORD oldProtect;
    VirtualProtect(address, 1, PAGE_READWRITE, &oldProtect);
    
    Nanomite* n = &g_nanomites[g_nanomite_count++];
    n->address = (uint32_t)(uintptr_t)address;
    n->original_byte = *(uint8_t*)address;
    n->key = (uint8_t)rand();
    
    
    *(uint8_t*)address = 0xCC;
    
    VirtualProtect(address, 1, oldProtect, &oldProtect);
}


static LONG WINAPI hexveil_nanomite_handler(EXCEPTION_POINTERS* ep) {
    if(ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        uint32_t address = (uint32_t)(uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        
        
        for(size_t i = 0; i < g_nanomite_count; i++) {
            if(g_nanomites[i].address == address) {
                
                DWORD oldProtect;
                VirtualProtect((void*)(uintptr_t)address, 1, PAGE_READWRITE, &oldProtect);
                *(uint8_t*)(uintptr_t)address = g_nanomites[i].original_byte ^ g_nanomites[i].key;
                VirtualProtect((void*)(uintptr_t)address, 1, oldProtect, &oldProtect);
                
                
                #ifdef HEXVEIL_ARCH_X64
                ep->ContextRecord->Rip = address;
                #else
                ep->ContextRecord->Eip = address;
                #endif
                
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}


static inline void hexveil_init_nanomites(void) {
    AddVectoredExceptionHandler(1, hexveil_nanomite_handler);
}


#define HEXVEIL_PROTECT_FUNCTION(func) \
    do { \
        uint8_t* code = (uint8_t*)func; \
        for(size_t i = 0; i < 32; i += 5) { \
            hexveil_add_nanomite(code + i); \
        } \
    } while(0)


typedef enum {
    VM_OP_ADD = 0x1234,
    VM_OP_SUB = 0x2345,
    VM_OP_MUL = 0x3456,
    VM_OP_DIV = 0x4567,
    VM_OP_XOR = 0x5678,
    VM_OP_AND = 0x6789,
    VM_OP_OR  = 0x789A
} VMOperation;


static inline int64_t hexveil_vm_execute(VMOperation op, int64_t a, int64_t b) {
    int64_t result = 0;
    
    switch(op) {
        case VM_OP_ADD: result = a + b; break;
        case VM_OP_SUB: result = a - b; break;
        case VM_OP_MUL: result = a * b; break;
        case VM_OP_DIV: result = b ? a / b : 0; break;
        case VM_OP_XOR: result = a ^ b; break;
        case VM_OP_AND: result = a & b; break;
        case VM_OP_OR:  result = a | b; break;
    }
    
    
    result ^= 0x12345678;
    result = (result << 13) | (result >> 51);
    result ^= 0x87654321;
    
    return result;
}


#undef HEXVEIL_VM_ADD
#undef HEXVEIL_VM_SUB
#undef HEXVEIL_VM_MUL
#undef HEXVEIL_VM_DIV

#define HEXVEIL_VM_ADD(a,b) hexveil_vm_execute(VM_OP_ADD, (int64_t)(a), (int64_t)(b))
#define HEXVEIL_VM_SUB(a,b) hexveil_vm_execute(VM_OP_SUB, (int64_t)(a), (int64_t)(b))
#define HEXVEIL_VM_MUL(a,b) hexveil_vm_execute(VM_OP_MUL, (int64_t)(a), (int64_t)(b))
#define HEXVEIL_VM_DIV(a,b) hexveil_vm_execute(VM_OP_DIV, (int64_t)(a), (int64_t)(b))


static inline void* hexveil_generate_polymorphic_stub(void* target_func) {
    static const uint8_t templates[][16] = {
        
        {0x68, 0x00, 0x00, 0x00, 0x00,  
         0xFF, 0x24, 0x24},              
        
        {0xB8, 0x00, 0x00, 0x00, 0x00,  
         0xFF, 0xE0},                    
        
        {0x68, 0x00, 0x00, 0x00, 0x00,  
         0xC3},                          
    };

    size_t template_idx = rand() % 3;
    size_t template_size = template_idx == 0 ? 8 : (template_idx == 1 ? 7 : 6);
    
    void* stub = VirtualAlloc(NULL, template_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!stub) return NULL;
    
    
    memcpy(stub, templates[template_idx], template_size);
    
    
    *(uintptr_t*)((uint8_t*)stub + 1) = (uintptr_t)target_func;
    
    
    for(size_t i = template_size; i < 16; i++) {
        ((uint8_t*)stub)[i] = rand() & 0xFF;
    }
    
    return stub;
}


#define HEXVEIL_MUTATE_FUNCTION(func) \
    do { \
        uint8_t* code = (uint8_t*)func; \
        DWORD old; \
        VirtualProtect(code, 32, PAGE_EXECUTE_READWRITE, &old); \
        for(int i = 0; i < 32; i += 4) { \
            uint32_t key = HEXVEIL_RND(1, 0xFFFFFFFF); \
            *(uint32_t*)(code + i) ^= key; \
            *(uint32_t*)(code + i) = _rotl(*(uint32_t*)(code + i), i % 7); \
        } \
        VirtualProtect(code, 32, old, &old); \
    } while(0)


static inline char* hexveil_encrypt_string_advanced(const char* str) {
    static char buffer[4096];
    uint32_t key = 0x12345678;
    size_t len = strlen(str);
    
    for(size_t i = 0; i < len && i < sizeof(buffer) - 1; i++) {
        key = _rotl(key, 7) ^ 0xDEADBEEF;
        buffer[i] = str[i] ^ (key & 0xFF);
        key += buffer[i];
    }
    buffer[len] = '\0';
    
    return buffer;
}


#define HEXVEIL_BREAK_ANALYSIS() \
    do { \
        volatile int x = __rdtsc(); \
        if(x == 0) { \
            __debugbreak(); \
        } \
        Sleep(rand() % 10); \
        if(IsDebuggerPresent()) { \
            ExitProcess(1); \
        } \
    } while(0)


#define HEXVEIL_FAKE_PATH() \
    if(rand() & 1) { \
        volatile void* p = VirtualAlloc(0, 1, MEM_COMMIT, PAGE_READWRITE); \
        if(p) VirtualFree((void*)p, 0, MEM_RELEASE); \
        LoadLibraryA("kernel32.dll"); \
        GetProcAddress(GetModuleHandleA("kernel32.dll"), "Sleep"); \
    }


typedef struct {
    uint32_t key[4];
    uint32_t salt;
} StringKey;


typedef struct {
    char* data;
    size_t length;
    StringKey key;
} ProtectedString;


static inline ProtectedString* hexveil_encrypt_string_ex(const char* str) {
    ProtectedString* ps = (ProtectedString*)malloc(sizeof(ProtectedString));
    if(!ps) return NULL;
    
    
    ps->key.key[0] = HEXVEIL_RND(1, 0xFFFFFFFF);
    ps->key.key[1] = HEXVEIL_RND(1, 0xFFFFFFFF);
    ps->key.key[2] = HEXVEIL_RND(1, 0xFFFFFFFF);
    ps->key.key[3] = HEXVEIL_RND(1, 0xFFFFFFFF);
    ps->key.salt = HEXVEIL_RND(1, 0xFFFFFFFF);
    
    ps->length = strlen(str);
    ps->data = (char*)malloc(ps->length + 1);
    
    if(!ps->data) {
        free(ps);
        return NULL;
    }
    
    
    for(size_t i = 0; i < ps->length; i++) {
        uint32_t k = ps->key.key[i % 4];
        k = _rotl(k, i % 13) ^ ps->key.salt;
        ps->data[i] = str[i] ^ (k & 0xFF);
    }
    ps->data[ps->length] = '\0';
    
    return ps;
}

static inline char* hexveil_decrypt_string(ProtectedString* ps) {
    if(!ps || !ps->data) return NULL;
    
    static char buffer[4096];
    size_t max_len = sizeof(buffer) - 1;
    size_t len = ps->length < max_len ? ps->length : max_len;
    
    
    for(size_t i = 0; i < len; i++) {
        uint32_t k = ps->key.key[i % 4];
        k = _rotl(k, i % 13) ^ ps->key.salt;
        buffer[i] = ps->data[i] ^ (k & 0xFF);
    }
    buffer[len] = '\0';
    
    return buffer;
}


#define HEXVEIL_FLATTEN_BEGIN(state) \
    { \
        volatile int __state = (state); \
        volatile int __next_state = 0; \
        while(__state) { \
            switch(__state ^ HEXVEIL_RND(1, 1000)) {

#define HEXVEIL_FLATTEN_CASE(n, code) \
                case n: { \
                    HEXVEIL_BREAK_ANALYSIS(); \
                    code; \
                    __state = __next_state; \
                } break;

#define HEXVEIL_FLATTEN_END() \
                default: __state = 0; \
            } \
        } \
    }


static inline void hexveil_mutate_code_block(void* code, size_t size) {
    DWORD old;
    VirtualProtect(code, size, PAGE_EXECUTE_READWRITE, &old);
    
    
    for(int pass = 0; pass < 3; pass++) {
        for(size_t i = 0; i < size - 4; i += 4) {
            uint32_t key = HEXVEIL_RND(1, 0xFFFFFFFF);
            *(uint32_t*)((uint8_t*)code + i) ^= key;
            *(uint32_t*)((uint8_t*)code + i) = _rotl(*(uint32_t*)((uint8_t*)code + i), pass + 1);
            *(uint32_t*)((uint8_t*)code + i) += HEXVEIL_RND(1, 0xFF);
        }
    }
    
    VirtualProtect(code, size, old, &old);
}


#define HEXVEIL_ANTIDEBUG() \
    do { \
        static volatile int __guard = 0; \
        __guard++; \
        if(__guard != 1) ExitProcess(1); \
        if(IsDebuggerPresent()) ExitProcess(2); \
        CONTEXT ctx = {0}; \
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; \
        if(GetThreadContext(GetCurrentThread(), &ctx)) { \
            if(ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) ExitProcess(3); \
        } \
        BOOL dbg = FALSE; \
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &dbg); \
        if(dbg) ExitProcess(4); \
    } while(0)


static inline bool hexveil_verify_code_integrity(void* func, size_t size) {
    static uint32_t checksums[1024] = {0};
    static size_t checksum_count = 0;
    
    uint32_t sum = 0;
    uint8_t* code = (uint8_t*)func;
    
    for(size_t i = 0; i < size; i++) {
        sum = _rotl(sum, 7) ^ code[i];
    }
    
    if(checksum_count == 0) {
        checksums[checksum_count++] = sum;
        return true;
    }
    
    for(size_t i = 0; i < checksum_count; i++) {
        if(checksums[i] == sum) return true;
    }
    
    return false;
}


#define HEXVEIL_CALL(func, ...) \
    do { \
        void* stub = hexveil_generate_polymorphic_stub((void*)(func)); \
        if(!hexveil_verify_code_integrity((void*)(func), 32)) ExitProcess(5); \
        HEXVEIL_ANTIDEBUG(); \
        ((typeof(func))stub)(__VA_ARGS__); \
        VirtualFree(stub, 0, MEM_RELEASE); \
    } while(0)


static inline void* hexveil_randomize_instructions(void* func, size_t size) {
    uint8_t* code = (uint8_t*)func;
    uint8_t* new_code = (uint8_t*)VirtualAlloc(NULL, size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!new_code) return NULL;
    
    size_t j = 0;
    for(size_t i = 0; i < size; i++) {
        
        if(rand() % 3 == 0) {
            new_code[j] = 0x90; 
            new_code[j + 1] = 0xEB; 
            new_code[j + 2] = 0x01; 
            j += 3;
        }
        
        
        new_code[j] = code[i];
        j++;
        
        
        if(rand() % 4 == 0) {
            uint8_t temp = new_code[j - 1];
            uint8_t key = HEXVEIL_RND(1, 0xFF);
            temp ^= key;
            new_code[j - 1] = temp;
            new_code[j] = 0x34; 
            new_code[j + 1] = key;
            j += 2;
        }
    }
    
    return new_code;
}


static inline void hexveil_fake_upx_headers(void) {
    HMODULE hModule = GetModuleHandle(NULL);
    if(!hModule) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    DWORD oldProtect;
    VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), PAGE_READWRITE, &oldProtect);
    
    
    dosHeader->e_res[0] = 'U' | 0xFF;
    dosHeader->e_res[1] = 'P' | 0xFF;
    dosHeader->e_res[2] = 'X' | 0xFF;
    
    
    dosHeader->e_res[3] = '3' | 0xFF;
    dosHeader->e_res[4] = '.' | 0xFF;
    dosHeader->e_res[5] = '9' | 0xFF;
    
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    VirtualProtect(section, sizeof(IMAGE_SECTION_HEADER) * ntHeaders->FileHeader.NumberOfSections,
                  PAGE_READWRITE, &oldProtect);
    
    
    memcpy(section[0].Name, "UPX0", 4);
    memcpy(section[1].Name, "UPX1", 4);
    
    VirtualProtect(section, sizeof(IMAGE_SECTION_HEADER) * ntHeaders->FileHeader.NumberOfSections,
                  oldProtect, &oldProtect);
    VirtualProtect(dosHeader, sizeof(IMAGE_DOS_HEADER), oldProtect, &oldProtect);
}


static inline void hexveil_mutate_assembly(void* code, size_t size) {
    uint8_t* ptr = (uint8_t*)code;
    DWORD oldProtect;
    VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    for(size_t i = 0; i < size - 5; i++) {
        
        if(ptr[i] == 0x89) { 
            
            ptr[i] = 0x50 | (ptr[i+1] & 0x7); 
            ptr[i+1] = 0x58 | (ptr[i+1] >> 3); 
            i++;
        }
        else if(ptr[i] == 0x8B) { 
            
            ptr[i] = 0x8D;
        }
        
    }
    
    VirtualProtect(ptr, size, oldProtect, &oldProtect);
}


static inline void hexveil_add_junk_partition(void) {
    
    HMODULE hModule = GetModuleHandle(NULL);
    if(!hModule) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    
    size_t junkSize = HEXVEIL_RND(1024, 4096);
    void* junk = VirtualAlloc(NULL, junkSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if(junk) {
        
        for(size_t i = 0; i < junkSize; i++) {
            ((uint8_t*)junk)[i] = HEXVEIL_RND(0, 255);
        }
        
        
        uint8_t* code = (uint8_t*)junk;
        for(size_t i = 0; i < junkSize - 10; i += 10) {
            code[i] = 0x55; 
            code[i+1] = 0x89; 
            code[i+2] = 0xE5;
            
        }
    }
}


static inline void hexveil_flood_memory(void) {
    const size_t NUM_ALLOCS = 1000;
    const size_t MIN_SIZE = 1024;
    const size_t MAX_SIZE = 1024 * 1024;
    
    for(size_t i = 0; i < NUM_ALLOCS; i++) {
        size_t size = HEXVEIL_RND(MIN_SIZE, MAX_SIZE);
        void* mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if(mem) {
            
            for(size_t j = 0; j < size; j++) {
                ((uint8_t*)mem)[j] = HEXVEIL_RND(0, 255);
            }
        }
    }
}


static inline void* hexveil_compress_code(void* code, size_t size, size_t* out_size) {
    uint8_t* compressed = (uint8_t*)VirtualAlloc(NULL, size * 2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(!compressed) return NULL;
    
    size_t j = 0;
    uint8_t* src = (uint8_t*)code;
    
    for(size_t i = 0; i < size; i++) {
        
        if(i < size - 2 && src[i] == 0x89 && src[i+1] == 0xE5) {
            
            compressed[j++] = 0xF0; 
            i++;
        }
        else if(i < size - 3 && src[i] == 0x83 && src[i+1] == 0xEC) {
            
            compressed[j++] = 0xF1;
            compressed[j++] = src[i+2];
            i += 2;
        }
        else {
            compressed[j++] = src[i];
        }
    }
    
    *out_size = j;
    return compressed;
}


static inline void hexveil_fake_imports(void) {
    
    static const char* fake_dlls[] = {
        "python27.dll",
        "java.dll",
        "perl.dll",
        "ruby.dll",
        "php7.dll"
    };
    
    static const char* fake_functions[] = {
        "InitializeInterpreter",
        "CompileScript",
        "ExecuteCode",
        "LoadModule",
        "ParseString"
    };
    
    for(int i = 0; i < 5; i++) {
        HMODULE hMod = LoadLibraryA(fake_dlls[i]);
        if(hMod) {
            GetProcAddress(hMod, fake_functions[i]);
            
        }
    }
}


#define HEXVEIL_PROTECT_ALL() \
    do { \
        hexveil_fake_upx_headers(); \
        hexveil_add_junk_partition(); \
        hexveil_flood_memory(); \
        hexveil_fake_imports(); \
        size_t comp_size; \
        void* comp_code = hexveil_compress_code(main, 1024, &comp_size); \
        if(comp_code) { \
            hexveil_mutate_assembly(comp_code, comp_size); \
            VirtualFree(comp_code, 0, MEM_RELEASE); \
        } \
    } while(0)

#endif 
