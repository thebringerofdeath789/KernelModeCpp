/**
 * @file DefenderDisabler.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the DefenderDisabler class.
 *
 * The DefenderDisabler class provides functionality for disabling Microsoft
 * Defender services and registry settings.
 */

#pragma once

#include <Windows.h>
#include <string>

namespace KernelMode {
    /**
     * @class DefenderDisabler
     * @brief Manages operations to disable Microsoft Defender.
     *
     * This class encapsulates methods to stop and disable Defender services
     * and to set registry values that turn off its protection features.
     */
    class DefenderDisabler {
    public:
        /**
         * @brief Attempts to disable Microsoft Defender's key components.
         * @return True if all operations appear to succeed, false otherwise.
         */
        static bool Disable();

    private:
        /**
         * @brief Stops and disables a given Windows service.
         * @param serviceName The name of the service to target.
         * @return True on success, false on failure.
         */
        static bool StopAndDisableService(const std::wstring& serviceName);

        /**
         * @brief Sets a registry DWORD value to disable a Defender feature.
         * @param subKey The registry subkey path.
         * @param valueName The name of the value to set.
         * @return True on success, false on failure.
         */
        static bool SetRegistryDword(const std::wstring& subKey, const std::wstring& valueName);
    };
}