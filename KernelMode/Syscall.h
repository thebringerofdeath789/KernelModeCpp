/**
 * @file Syscall.h
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the declaration of the Syscall class.
 *
 * The Syscall class provides functionality for finding and executing
 * direct syscalls to bypass user-mode API hooking.
 */

#pragma once

#include <Windows.h>
#include <string>
#include <unordered_map>

// External definition for the assembly syscall stub
extern "C" NTSTATUS DoSyscall(DWORD syscallIndex, PVOID* params, ULONG paramCount);

namespace KernelMode {
    /**
     * @class Syscall
     * @brief Manages the dynamic resolution and execution of direct syscalls.
     */
    class Syscall {
    public:
        /**
         * @brief Gets the singleton instance of the Syscall manager.
         * @return A reference to the Syscall manager instance.
         */
        static Syscall& GetInstance();

        /**
         * @brief Gets the syscall index for a given NT function name.
         * @param functionName The name of the function (e.g., "NtCreateFile").
         * @return The syscall index, or -1 if not found.
         */
        DWORD GetSyscallIndex(const std::string& functionName);

    private:
        Syscall(); // Private constructor for singleton
        ~Syscall() = default;
        Syscall(const Syscall&) = delete;
        Syscall& operator=(const Syscall&) = delete;

        std::unordered_map<std::string, DWORD> syscallMap;
    };
}