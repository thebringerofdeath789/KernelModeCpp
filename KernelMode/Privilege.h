/**
 * @file Privilege.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains declarations for privilege manipulation functions.
 */

#pragma once

#include <Windows.h>
#include <string>

namespace KernelMode {
    /**
     * @class Privilege
     * @brief Manages Windows privileges and token operations.
     */
    class Privilege {
    public:
        /**
         * @brief Enables a specific privilege for the current process.
         * @param privilegeName The name of the privilege to enable.
         * @return True if the privilege was enabled successfully.
         */
        static bool EnablePrivilege(const std::wstring& privilegeName);

        /**
         * @brief Steals a SYSTEM token and impersonates it.
         * @return True if successful.
         */
        static bool StealSystemToken();

        /**
         * @brief Spawns a SYSTEM shell.
         */
        static void SpawnSystemShell();
    };
}