/**
 * @file PocMenu.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the PocMenu class.
 *
 * The PocMenu class provides the main user interface for the KernelMode
 * toolkit. It presents a menu-driven console interface for selecting
 * providers and executing various kernel-level operations.
 */

#pragma once

#include "Providers/IProvider.h"
#include "DSE.h"
#include "Process.h"
#include "Callbacks.h"
#include "ManualMapper.h"
#include "FileHider.h"
#include "ETW.h"
#include <memory>
#include <vector>
#include <string>

namespace KernelMode {
    /**
     * @class PocMenu
     * @brief The main user interface for the toolkit.
     *
     * This class manages the application's main loop, displaying menus,
     * handling user input, and orchestrating the calls to the various
     * feature implementations like DSE bypass and privilege escalation.
     */
    class PocMenu {
    public:
        PocMenu();
        ~PocMenu();

        /**
         * @brief Starts the main menu loop of the application.
         */
        void Run();

    private:
        /**
         * @brief Displays the main title banner.
         */
        void DisplayBanner();

        /**
         * @brief Displays the provider selection menu and handles user choice.
         */
        void SelectProvider();

        /**
         * @brief Displays the main actions menu for the selected provider.
         */
        void ProviderActionsMenu();

        /**
         * @brief Handles the DSE bypass option.
         */
        void HandleDseBypass();

        /**
         * @brief Handles the privilege escalation options.
         */
        void HandlePrivilegeEscalation();

        /**
         * @brief Handles the process hiding options.
         */
        void HandleProcessHiding();

        /**
         * @brief Handles the AV/EDR Evasion options, such as callback unlinking.
         */
        void HandleAvEvasion();

        /**
         * @brief Handles the PE Parser utility.
         */
        void HandlePeParser();

        /**
         * @brief Handles the Driver Manual Mapping utility.
         */
        void HandleManualMap();

        /**
         * @brief Handles the Persistence utility.
         */
        void HandlePersistence();

        /**
         * @brief Handles the Force Uninstaller utility.
         */
        void HandleUninstaller();

        /**
         * @brief Handles the File Hiding utility.
         */
        void HandleFileHiding();

        /**
         * @brief Gets a validated integer choice from the user.
         * @param maxChoice The maximum valid choice number.
         * @return The user's choice, or -1 on failure.
         */
        int GetUserChoice(int maxChoice);

        std::shared_ptr<Providers::IProvider> activeProvider;
        std::unique_ptr<DSE> dseManager;
        std::unique_ptr<Process> processManager;
        std::unique_ptr<Callbacks> callbackManager;
        std::unique_ptr<ManualMapper> manualMapper;
        std::unique_ptr<FileHider> fileHider;
        std::unique_ptr<ETW> etwManager;
    };
}