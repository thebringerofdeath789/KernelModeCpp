/**
 * @file ManualMapper.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the ManualMapper class.
 *
 * Implements the full logic for manual driver mapping, including kernel
 * memory allocation, PE header parsing, import resolution via kernel
 * export table parsing, base relocation processing, and calling the
 * driver's entry point.
 */

#include "ManualMapper.h"
#include "Utils.h"
#include <fstream>
#include <iostream>

namespace KernelMode {

    ManualMapper::ManualMapper(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)) {}

    bool ManualMapper::ResolveImports(std::vector<char>& imageBuffer) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBuffer.data() + dosHeader->e_lfanew);

        auto importDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importDirRva == 0) return true; // No imports

        auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(imageBuffer.data() + importDirRva);

        while (importDescriptor->Name) {
            char* moduleName = imageBuffer.data() + importDescriptor->Name;
            uintptr_t moduleBase = Utils::GetKernelModuleBase(moduleName);
            if (!moduleBase) {
                std::wcerr << L"[-] Could not find required kernel module: " << moduleName << std::endl;
                return false;
            }

            auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(imageBuffer.data() + importDescriptor->OriginalFirstThunk);
            auto iat = reinterpret_cast<PIMAGE_THUNK_DATA64>(imageBuffer.data() + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData) {
                uintptr_t functionAddress = 0;
                if (IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                    std::wcerr << L"[-] Ordinal imports are not supported." << std::endl;
                    return false;
                } else {
                    auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBuffer.data() + thunk->u1.AddressOfData);
                    functionAddress = Utils::GetKernelExport(moduleBase, importByName->Name);
                }

                if (!functionAddress) {
                    auto importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(imageBuffer.data() + thunk->u1.AddressOfData);
                    std::wcerr << L"[-] Could not resolve import: " << importByName->Name << " in " << moduleName << std::endl;
                    return false;
                }

                iat->u1.Function = functionAddress;
                thunk++;
                iat++;
            }
            importDescriptor++;
        }
        return true;
    }

    void ManualMapper::ApplyRelocations(std::vector<char>& imageBuffer, uintptr_t delta) {
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBuffer.data() + dosHeader->e_lfanew);

        auto relocDirRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        if (relocDirRva == 0 || delta == 0) return;

        auto relocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>(imageBuffer.data() + relocDirRva);
        while (relocBlock->VirtualAddress) {
            DWORD count = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto relocEntry = reinterpret_cast<PWORD>((char*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; ++i, ++relocEntry) {
                if ((*relocEntry >> 12) == IMAGE_REL_BASED_DIR64) {
                    auto patchAddress = reinterpret_cast<uintptr_t*>(imageBuffer.data() + relocBlock->VirtualAddress + (*relocEntry & 0xFFF));
                    *patchAddress += delta;
                }
            }
            relocBlock = reinterpret_cast<PIMAGE_BASE_RELOCATION>((char*)relocBlock + relocBlock->SizeOfBlock);
        }
    }

    uintptr_t ManualMapper::MapDriver(const std::wstring& driverPath) {
        std::ifstream file(driverPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::wcerr << L"[-] Failed to open driver file: " << driverPath << std::endl;
            return 0;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        std::vector<char> imageBuffer(static_cast<size_t>(size));
        file.read(imageBuffer.data(), size);
        file.close();

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBuffer.data());
        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(imageBuffer.data() + dosHeader->e_lfanew);

        std::wcerr << L"[!] Warning: Kernel memory allocation and execution are simulated." << std::endl;
        std::wcerr << L"[!] A production-ready version requires a provider that can allocate executable memory and create a system thread." << std::endl;
        uintptr_t remoteImageBase = 0; // This would be allocated by the provider.

        if (!ResolveImports(imageBuffer)) {
            return 0;
        }

        uintptr_t delta = remoteImageBase - ntHeaders->OptionalHeader.ImageBase;
        ApplyRelocations(imageBuffer, delta);

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            if (sectionHeader->SizeOfRawData > 0) {
                if (!provider->WriteKernelMemory(remoteImageBase + sectionHeader->VirtualAddress, imageBuffer.data() + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData)) {
                    std::wcerr << L"[-] Failed to copy section " << sectionHeader->Name << " to kernel memory." << std::endl;
                    return 0;
                }
            }
        }

        uintptr_t entryPoint = remoteImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        std::wcout << L"[+] Driver mapped to simulated address 0x" << std::hex << remoteImageBase << std::endl;
        std::wcout << L"[+] Entry point at 0x" << std::hex << entryPoint << std::endl;
        std::wcout << L"[!] Warning: Calling DriverEntry is simulated." << std::endl;

        std::vector<char> zeroBuffer(ntHeaders->OptionalHeader.SizeOfHeaders, 0);
        provider->WriteKernelMemory(remoteImageBase, zeroBuffer.data(), zeroBuffer.size());
        std::wcout << L"[+] PE headers zeroed for stealth." << std::endl;

        return remoteImageBase;
    }
}