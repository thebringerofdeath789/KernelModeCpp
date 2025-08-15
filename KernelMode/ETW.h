/**
 * @file ETW.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the ETW class.
 *
 * The ETW class provides functionality for disabling Event Tracing for Windows
 * components that are commonly used by security products for monitoring.
 */

#pragma once

#include "Providers/IProvider.h"
#include <string>
#include <memory>

namespace KernelMode {
    /**
     * @class ETW
     * @brief Manages EDR evasion techniques related to ETW.
     *
     * This class uses a provider to find and patch kernel data structures
     * related to ETW, primarily to disable security-related logging.
     */
    class ETW {
    public:
        /**
         * @brief Constructs an ETW manager with a given provider.
         * @param provider A shared pointer to an active IProvider for kernel memory operations.
         */
        explicit ETW(std::shared_ptr<Providers::IProvider> provider);

        /**
         * @brief Disables the ETW Threat Intelligence provider by nullifying its handle.
         * @return True if the provider was successfully disabled, false otherwise.
         */
        bool DisableThreatIntelligenceProvider();

    private:
        /**
         * @brief Finds the address of the EtwpThreatIntProvRegHandle variable in kernel memory.
         * @return The address of the handle, or 0 if not found.
         */
        uintptr_t FindThreatIntProviderHandle();

        std::shared_ptr<Providers::IProvider> provider;
    };
}