/**
 * @file main.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief Main entry point for the KernelMode toolkit.
 *
 * This file contains the main function which initializes and runs the
 * proof-of-concept menu. It performs an initial check for
 * administrator privileges before proceeding.
 */

#include "PocMenu.h"
#include <iostream>
#include <Windows.h>

/**
 * @brief Checks if the current process is running with administrator privileges.
 * @return True if running as admin, false otherwise.
 */
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsGroup;

    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &administratorsGroup))
    {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }

    return isAdmin == TRUE;
}

/**
 * @brief The main entry point of the application.
 * @return 0 on successful execution, 1 on error.
 */
int main() {
    if (!IsRunningAsAdmin()) {
        std::wcerr << L"[-] This program requires administrator privileges. Please run as administrator." << std::endl;
        // Pause to allow user to see the message before console closes
        system("pause");
        return 1;
    }

    try {
        KernelMode::PocMenu menu;
        menu.Run();
    } catch (const std::exception& e) {
        std::cerr << "An unhandled exception occurred: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "An unknown unhandled exception occurred." << std::endl;
        return 1;
    }

    return 0;
}