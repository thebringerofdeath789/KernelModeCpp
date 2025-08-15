/**
 * @file Callbacks.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the Callbacks class.
 *
 * The Callbacks class provides functionality for enumerating and removing
 * kernel callback routines, a common technique for AV/EDR evasion. It
 * targets process, thread, and image load notification routines.
 */

#pragma once

#include "Providers/IProvider.h"
#include <memory>
#include <vector>
#include <string>

namespace KernelMode {

    // Undocumented kernel structure for callback routines.
    // The actual structure is EX_CALLBACK_ROUTINE_BLOCK, but we only need the routine pointer.
    // We will treat the callback array as an array of these pointers.
    using PCALLBACK_ROUTINE = PVOID;

    /**
     * @class Callbacks
     * @brief Manages kernel callback enumeration and removal.
     *
     * This class uses a provider to find and patch kernel callback arrays,
     * effectively unhooking monitoring routines registered by security software.
     */
    class Callbacks {
    public:
        /**
         * @brief Constructs a Callbacks manager with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit Callbacks(std::shared_ptr<Providers::IProvider> provider);

        /**
         * @brief Enumerates all registered process creation callback routines.
         * @return A vector of addresses, where each address points to a callback routine.
         */
        std::vector<uintptr_t> EnumerateProcessCallbacks();

        /**
         * @brief Removes a specific process creation callback routine.
         * @param routineAddress The address of the callback routine to remove.
         * @return True if the callback was found and removed, false otherwise.
         */
        bool RemoveProcessCallback(uintptr_t routineAddress);

    private:
        /**
         * @brief Finds the address of the PspCreateProcessNotifyRoutine array.
         * @return The address of the array, or 0 if not found.
         */
        uintptr_t FindProcessNotifyRoutineArray();

        /**
         * @brief A generic function to enumerate callbacks from a given array.
         * @param arrayAddress The kernel address of the callback array.
         * @param maxCallbacks The maximum number of entries in the array.
         * @return A vector of callback routine addresses.
         */
        std::vector<uintptr_t> EnumerateCallbacks(uintptr_t arrayAddress, int maxCallbacks);

        /**
         * @brief A generic function to remove a callback from a given array.
         * @param arrayAddress The kernel address of the callback array.
         * @param routineAddress The address of the routine to remove.
         * @param maxCallbacks The maximum number of entries in the array.
         * @return True if the callback was found and removed, false otherwise.
         */
        bool RemoveCallback(uintptr_t arrayAddress, uintptr_t routineAddress, int maxCallbacks);

        std::shared_ptr<Providers::IProvider> provider;
        uintptr_t processNotifyRoutineArray;
    };
}