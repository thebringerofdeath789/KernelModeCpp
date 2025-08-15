/**
 * @file Uninstaller.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the Uninstaller class.
 *
 * The Uninstaller class provides functions to forcibly remove driver
 * services and their files from the system, even if they are protected.
 */

#pragma once

#include <Windows.h>
#include <string>

namespace KernelMode {
    /**
     * @class Uninstaller
     * @brief Manages the forced uninstallation of drivers.
     *
     * This class encapsulates the logic to stop a driver's service, delete
     * its registry configuration, and remove its file from disk. These
     * operations require high privileges.
     */
    class Uninstaller {
    public:
        /**
         * @brief Attempts to forcibly uninstall a driver.
         * @param serviceName The name of the driver's service.
         * @return True if all operations appear to succeed, false otherwise.
         */
        static bool ForceUninstallDriver(const std::wstring& serviceName);
    };
}