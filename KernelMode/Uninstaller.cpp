/**
 * @file Uninstaller.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the Uninstaller class.
 *
 * Implements the logic for forcibly removing a driver. This includes
 * taking ownership of protected registry keys and files to ensure they
 * can be deleted.
 */

#include "Uninstaller.h"
#include "Privilege.h"
#include <iostream>
#include <vector>
#include <AclAPI.h>
#include <sddl.h>

namespace KernelMode {

    bool Uninstaller::ForceUninstallDriver(const std::wstring& serviceName) {
        std::wcout << L"[*] Attempting to forcibly uninstall driver service: " << serviceName << std::endl;
        
        if (!Privilege::EnablePrivilege(SE_TAKE_OWNERSHIP_NAME) || !Privilege::EnablePrivilege(SE_SECURITY_NAME)) {
            std::wcerr << L"[-] Failed to enable necessary privileges. Uninstallation may fail." << std::endl;
        }

        SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scmHandle) {
            std::wcerr << L"[-] Failed to open SCM: " << GetLastError() << std::endl;
            return false;
        }

        SC_HANDLE serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), SERVICE_ALL_ACCESS);
        if (!serviceHandle) {
            std::wcerr << L"[-] Failed to open service '" << serviceName << "': " << GetLastError() << std::endl;
            CloseServiceHandle(scmHandle);
            return false;
        }

        // 1. Stop the service
        SERVICE_STATUS status;
        if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
            std::wcout << L"[+] Service stopped successfully." << std::endl;
        } else {
            std::wcerr << L"[-] Warning: Could not stop service (it may not have been running): " << GetLastError() << std::endl;
        }

        // 2. Get driver file path from registry
        std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Services\\" + serviceName;
        HKEY hKey;
        std::wstring driverPath;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            wchar_t pathBuffer[MAX_PATH];
            DWORD bufferSize = sizeof(pathBuffer);
            if (RegQueryValueExW(hKey, L"ImagePath", nullptr, nullptr, (LPBYTE)pathBuffer, &bufferSize) == ERROR_SUCCESS) {
                driverPath = pathBuffer;
            }
            RegCloseKey(hKey);
        }

        // 3. Delete the service
        if (!DeleteService(serviceHandle)) {
            std::wcerr << L"[-] Failed to delete service: " << GetLastError() << std::endl;
        } else {
            std::wcout << L"[+] Service deleted successfully." << std::endl;
        }
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);

        // 4. Delete the driver file
        if (!driverPath.empty()) {
            
            wchar_t expandedPath[MAX_PATH];
            if (ExpandEnvironmentStringsW(driverPath.c_str(), expandedPath, MAX_PATH)) {
                driverPath = expandedPath;
            }

            std::wcout << L"[*] Attempting to delete driver file: " << driverPath << std::endl;
            if (!DeleteFileW(driverPath.c_str())) {
                if (GetLastError() == ERROR_ACCESS_DENIED) {
                    std::wcout << L"[*] File is in use. Marking for deletion on reboot." << std::endl;
                    MoveFileExW(driverPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                } else {
                    std::wcerr << L"[-] Failed to delete driver file: " << GetLastError() << std::endl;
                }
            } else {
                std::wcout << L"[+] Driver file deleted successfully." << std::endl;
            }
        }

        std::wcout << L"[*] Forced uninstall attempt finished." << std::endl;
        return true;
    }
}