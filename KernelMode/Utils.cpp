/**
 * @file Utils.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the Utils namespace.
 *
 * Implements the helper functions for kernel and driver interactions,
 * such as finding kernel module base addresses and managing driver services.
 */

#include "Utils.h"
#include <iostream>
#include <vector>
#include <Psapi.h>
#include <winternl.h>

// Undocumented SYSTEM_INFORMATION_CLASS value
#define SystemModuleInformation 11

// Function prototype for NtQuerySystemInformation
typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Structures for NtQuerySystemInformation
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

namespace KernelMode {
    namespace Utils {

        uintptr_t GetKernelModuleBase(const std::string& moduleName) {
            ULONG modulesSize = 0;
            std::vector<char> modulesBuffer;
            NTSTATUS status = 0;

            // NtQuerySystemInformation is the de-facto way to get kernel module info.
            // We must call it twice: once to get the required buffer size, and a second
            // time to get the actual data.
            auto NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
            if (!NtQuerySystemInformation) {
                std::wcerr << L"[-] Could not resolve NtQuerySystemInformation." << std::endl;
                return 0;
            }

            // First call to get the size
            status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, nullptr, 0, &modulesSize);
            if (modulesSize == 0) {
                std::wcerr << L"[-] Failed to get system module information size." << std::endl;
                return 0;
            }

            modulesBuffer.resize(modulesSize);

            // Second call to get the data
            status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, modulesBuffer.data(), modulesSize, nullptr);
            if (status != 0) { // 0 is STATUS_SUCCESS
                std::wcerr << L"[-] NtQuerySystemInformation failed with status: " << std::hex << status << std::endl;
                return 0;
            }

            auto modules = (PRTL_PROCESS_MODULES)modulesBuffer.data();
            for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
                std::string currentModuleName = (char*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName;
                if (_stricmp(currentModuleName.c_str(), moduleName.c_str()) == 0) {
                    return (uintptr_t)modules->Modules[i].ImageBase;
                }
            }

            return 0;
        }

        uintptr_t GetKernelExport(uintptr_t moduleBase, const std::string& functionName) {
            // This function must parse the PE header of the kernel module in user-space memory
            // to find the export address. We first load the module into our own address space.
            HMODULE moduleHandle = LoadLibraryExA((LPCSTR)moduleBase, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (!moduleHandle) {
                // This is expected since we are giving it a kernel address.
                // We need the file path to load it properly. This is a simplification.
                // A full implementation would read the PE headers directly from kernel memory.
                // For now, we assume ntoskrnl.exe is the target and load it from disk.
                char systemPath[MAX_PATH];
                GetSystemDirectoryA(systemPath, MAX_PATH);
                strcat_s(systemPath, "\\ntoskrnl.exe");
                moduleHandle = LoadLibraryExA(systemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (!moduleHandle) {
                    std::wcerr << L"[-] Failed to load ntoskrnl.exe into user space: " << GetLastError() << std::endl;
                    return 0;
                }
            }

            uintptr_t functionAddress = (uintptr_t)GetProcAddress(moduleHandle, functionName.c_str());
            if (!functionAddress) {
                FreeLibrary(moduleHandle);
                return 0;
            }

            // The address from GetProcAddress is relative to the user-space loaded module.
            // We need to calculate the RVA and add it to the real kernel module base.
            uintptr_t rva = functionAddress - (uintptr_t)moduleHandle;
            uintptr_t kernelFunctionAddress = moduleBase + rva;

            FreeLibrary(moduleHandle);
            return kernelFunctionAddress;
        }

        SC_HANDLE CreateDriverService(const std::wstring& serviceName, const std::wstring& driverPath) {
            SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
            if (!scmHandle) {
                std::wcerr << L"[-] Failed to open SCM: " << GetLastError() << std::endl;
                return nullptr;
            }

            SC_HANDLE serviceHandle = CreateServiceW(
                scmHandle,
                serviceName.c_str(),
                serviceName.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                driverPath.c_str(),
                nullptr, nullptr, nullptr, nullptr, nullptr
            );

            if (!serviceHandle) {
                if (GetLastError() == ERROR_SERVICE_EXISTS) {
                    serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), SERVICE_ALL_ACCESS);
                }
                else {
                    std::wcerr << L"[-] Failed to create service: " << GetLastError() << std::endl;
                    CloseServiceHandle(scmHandle);
                    return nullptr;
                }
            }

            if (!StartServiceW(serviceHandle, 0, nullptr)) {
                if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
                    std::wcerr << L"[-] Failed to start service: " << GetLastError() << std::endl;
                    CloseServiceHandle(serviceHandle);
                    CloseServiceHandle(scmHandle);
                    // Attempt cleanup
                    DeleteService(serviceHandle);
                    return nullptr;
                }
            }

            CloseServiceHandle(scmHandle);
            return serviceHandle;
        }

        bool RemoveDriverService(SC_HANDLE serviceHandle) {
            if (!serviceHandle) return false;

            SERVICE_STATUS serviceStatus;
            ControlService(serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus);

            if (!DeleteService(serviceHandle)) {
                if (GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE) {
                     std::wcerr << L"[-] Failed to delete service: " << GetLastError() << std::endl;
                     CloseServiceHandle(serviceHandle);
                     return false;
                }
            }

            CloseServiceHandle(serviceHandle);
            return true;
        }
    }
}