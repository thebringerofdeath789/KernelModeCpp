/**
 * @file IProvider.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the IProvider interface.
 *
 * The IProvider interface defines a standard contract for all vulnerable
 * driver providers. It ensures that each provider implements a consistent
 * set of functionalities for loading, unloading, and interacting with the
 * kernel, such as reading and writing kernel memory.
 */

#pragma once

#include <Windows.h>
#include <cstdint>

namespace KernelMode {
    namespace Providers {
        /**
         * @class IProvider
         * @brief Interface for vulnerable driver providers.
         *
         * This pure virtual class defines the methods that any provider must
         * implement to be used by the toolkit. This includes initializing
         * and deinitializing the driver, and performing kernel memory
         * read/write operations.
         */
        class IProvider {
        public:
            virtual ~IProvider() = default;

            /**
             * @brief Initializes the provider and loads the vulnerable driver.
             * @return True if initialization is successful, false otherwise.
             */
            virtual bool Initialize() = 0;

            /**
             * @brief Deinitializes the provider and unloads the driver.
             */
            virtual void Deinitialize() = 0;

            /**
             * @brief Reads a specified amount of memory from a kernel address.
             * @param address The kernel address to read from.
             * @param buffer The buffer to store the read data.
             * @param size The number of bytes to read.
             * @return True if the read operation is successful, false otherwise.
             */
            virtual bool ReadKernelMemory(uintptr_t address, void* buffer, size_t size) = 0;

            /**
             * @brief Writes a specified amount of memory to a kernel address.
             * @param address The kernel address to write to.
             * @param buffer The buffer containing the data to write.
             * @param size The number of bytes to write.
             * @return True if the write operation is successful, false otherwise.
             */
            virtual bool WriteKernelMemory(uintptr_t address, void* buffer, size_t size) = 0;

            /**
             * @brief Reads a pointer-sized value from a kernel address.
             * @tparam T The type of the value to read (e.g., uint64_t).
             * @param address The kernel address to read from.
             * @param value The variable to store the read value.
             * @return True if the read is successful, false otherwise.
             */
            template<typename T>
            bool ReadKernelMemory(uintptr_t address, T& value) {
                return ReadKernelMemory(address, &value, sizeof(T));
            }

            /**
             * @brief Writes a pointer-sized value to a kernel address.
             * @tparam T The type of the value to write (e.g., uint64_t).
             * @param address The kernel address to write to.
             * @param value The value to write.
             * @return True if the write is successful, false otherwise.
             */
            template<typename T>
            bool WriteKernelMemory(uintptr_t address, T value) {
                return WriteKernelMemory(address, &value, sizeof(T));
            }
        };
    }
}