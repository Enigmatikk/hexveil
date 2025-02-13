![logo](images/image.png)
                HexVeil - Advanced Code Protection Library
===========================================================

Overview
--------
HexVeil is a comprehensive code protection library designed to prevent reverse 
engineering, debugging, and analysis of Windows applications.

Core Features
------------

[+] Anti-Debug Protection
    - PEB flags detection
    - Hardware breakpoint detection
    - Thread context verification
    - Process environment checks
    - Remote debugger detection
    - Anti-VM detection

[+] Code Protection
    - Nanomite injection (INT3-based protection)
    - Polymorphic code generation
    - Instruction set randomization
    - Code mutation engine
    - Control flow flattening
    - Dead code injection

[+] Memory Protection
    - PE header protection
    - Import table obfuscation
    - Stack cleanup
    - Memory flooding
    - Section protection
    - Resource encryption

[+] String Protection
    - Multi-layer encryption
    - Dynamic key generation
    - String table obfuscation

Quick Start
----------
    #include "hexveil.h"

    int main() {
        HEXVEIL_PROTECT_ALL();  // Enable all protections
        
        HEXVEIL_TRY {
            // Your protected code here
        } 
        HEXVEIL_EXCEPT {
            // Handle tampering
        }
        
        return 0;
    }

Building
--------
    git clone https://github.com/Enigmatikk/hexveil
    cd hexveil
    gcc test.c -o test.exe -I. -O2 -Wall

Requirements
-----------
- Windows 7 or later
- MinGW or MSVC compiler
- x86/x64 architecture

Usage Examples
-------------

[+] Function Protection
    // Protect function with polymorphic stub
    void* protected_func = hexveil_generate_polymorphic_stub(original_function);

    // Add nanomite protection
    HEXVEIL_PROTECT_FUNCTION(function_name);

[+] String Protection
    // Basic string protection
    const char* protected_str = hexveil_encrypt_string_safe("secret");

    // Advanced string protection
    ProtectedString* secure_str = hexveil_encrypt_string_ex("critical data");
    char* decrypted = hexveil_decrypt_string(secure_str);

[+] Anti-Analysis
    // Add protection layers
    HEXVEIL_BREAK_ANALYSIS();
    HEXVEIL_FAKE_PATH();
    HEXVEIL_ANTIDEBUG();

Advanced Features
---------------
[+] VM Operations
    - Protected arithmetic operations
    - Custom instruction set
    - Operation result mutation
    - Bit rotation protection

[+] Code Mutation
    - Dynamic stub generation
    - Multiple template patterns
    - Instruction substitution
    - Assembly level mutations

[+] PE Protection
    - UPX header simulation
    - Section name obfuscation
    - Header corruption
    - Import table mutation

Important Notes
-------------
- This library is designed for Windows applications only
- Some features require administrator privileges
- May trigger antivirus software
- Not suitable for kernel-mode drivers
- Use in production environments requires thorough testing

License
-------
Free for non-commercial use. Commercial license required for business use.
Modifications allowed with attribution.

Author
------
Made by Engimatikk

Disclaimer
---------
This tool is for educational purposes only. Users are responsible for complying 
with all applicable laws and regulations.

===============================================================================
                            HexVeil v1.0 (2024)
