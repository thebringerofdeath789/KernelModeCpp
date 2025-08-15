/**
 * @file DSE.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the DSE class.
 *
 * The DSE class provides functionality to disable and restore Driver
 * Signature Enforcement (DSE) by patching the g_CiOptions kernel variable.
 * It relies on a provider for kernel memory access.
 */

#pragma once

#include "Providers/IProvider.h"
#include <cstdint>
#include <memory>

namespace KernelMode {
    /**
     * @class DSE
     * @brief Manages Driver Signature Enforcement (DSE) bypass operations.
     *
     * This class encapsulates the logic to find the g_CiOptions kernel
     * variable, disable DSE by writing to it, and restore its original
     * value.
     */
    class DSE {
    public:
        /**
         * @brief Constructs a DSE manager with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit DSE(std::shared_ptr<Providers::IProvider> provider);

        /**
         * @brief Disables Driver Signature Enforcement.
         * @return True if DSE was successfully disabled, false otherwise.
         */
        bool Disable();

        /**
         * @brief Restores Driver Signature Enforcement to its original state.
         * @return True if DSE was successfully restored, false otherwise.
         */
        bool Restore();

    private:
        /**
         * @brief Finds the kernel address of the g_CiOptions variable.
         * @return True if the address was found, false otherwise.
         */
        bool FindCiOptions();

        std::shared_ptr<Providers::IProvider> provider;
        uintptr_t ciOptionsAddress;
        int originalCiOptions;
    };
}