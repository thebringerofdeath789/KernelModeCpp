/**
 * @file Utils.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the Utils namespace.
 *
 * The Utils namespace provides a collection of helper functions for
 * interacting with the Windows kernel and drivers. This includes
 * functionalities like managing services (drivers), retrieving kernel
 * module information, and other common tasks required by the toolkit.
 */

#pragma once

#include <Windows.h>
#include <string>
#include <cstdint>

namespace KernelMode {
    namespace Utils {
        /**
         * @brief Gets the base address of a kernel module.
         * @param moduleName The name of the kernel module (e.g., "ntoskrnl.exe").
         * @return The base address of the module, or 0 if not found.
         */
        uintptr_t GetKernelModuleBase(const std::string& moduleName);

        /**
         * @brief Gets the address of an exported function from a kernel module.
         * @param moduleBase The base address of the kernel module.
         * @param functionName The name of the function to find.
         * @return The address of the function, or 0 if not found.
         */
        uintptr_t GetKernelExport(uintptr_t moduleBase, const std::string& functionName);

        /**
         * @brief Creates and starts a Windows service for a driver.
         * @param serviceName The desired name for the service.
         * @param driverPath The full path to the driver file.
         * @return A handle to the service, or nullptr on failure.
         */
        SC_HANDLE CreateDriverService(const std::wstring& serviceName, const std::wstring& driverPath);

        /**
         * @brief Stops and deletes a Windows service.
         * @param serviceHandle A handle to the service to remove.
         * @return True if the service was stopped and deleted, false otherwise.
         */
        bool RemoveDriverService(SC_HANDLE serviceHandle);
    }
}