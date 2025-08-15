/**
 * @file Process.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the Process class.
 *
 * The Process class provides functionalities for kernel-level process
 * manipulation, primarily focusing on Direct Kernel Object Manipulation (DKOM)
 * techniques for process hiding.
 */

#pragma once

#include "Providers/IProvider.h"
#include <memory>
#include <Windows.h>

namespace KernelMode {
    /**
     * @class Process
     * @brief Manages DKOM-based process operations.
     *
     * This class uses a given provider to read/write kernel memory to
     * perform actions like hiding a process from standard enumeration tools
     * by unlinking it from the kernel's active process list.
     */
    class Process {
    public:
        /**
         * @brief Constructs a Process manager with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit Process(std::shared_ptr<Providers::IProvider> provider);

        /**
         * @brief Hides a process by its ID using DKOM.
         * @param pid The Process ID of the process to hide.
         * @return True if the process was hidden successfully, false otherwise.
         */
        bool HideProcess(DWORD pid);

    private:
        /**
         * @brief Gets the kernel EPROCESS address for a given Process ID.
         * @param pid The Process ID to look up.
         * @return The EPROCESS address, or 0 if not found.
         */
        uintptr_t GetEprocessAddress(DWORD pid);

        /**
         * @brief Dynamically finds the offset of the ActiveProcessLinks member in the EPROCESS structure.
         * @return The offset if found, 0 otherwise.
         */
        uintptr_t GetActiveProcessLinksOffset();

        std::shared_ptr<Providers::IProvider> provider;
        uintptr_t activeProcessLinksOffset;
    };
}