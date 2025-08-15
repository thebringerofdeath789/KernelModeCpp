/**
 * @file PEParser.cpp
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the implementation of the PEParser class.
 *
 * Implements the logic for reading a PE file, validating its signatures
 * (MZ and PE), and printing formatted information about its various
 * headers to the console.
 */

#include "PEParser.h"
#include <iostream>
#include <fstream>
#include <iomanip>

namespace KernelMode {

    PEParser::PEParser(std::wstring filePath)
        : filePath(std::move(filePath)), dosHeader(nullptr), ntHeaders(nullptr) {}

    bool PEParser::Parse() {
        std::ifstream file(this->filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::wcerr << L"[-] Failed to open file: " << this->filePath << std::endl;
            return false;
        }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        this->fileBuffer.resize(static_cast<size_t>(size));
        if (!file.read(this->fileBuffer.data(), size)) {
            std::wcerr << L"[-] Failed to read file into buffer." << std::endl;
            return false;
        }

        if (this->fileBuffer.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::wcerr << L"[-] File is too small to be a PE file." << std::endl;
            return false;
        }

        this->dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(this->fileBuffer.data());
        if (this->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::wcerr << L"[-] Invalid DOS signature (MZ)." << std::endl;
            return false;
        }

        if (this->fileBuffer.size() < this->dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS64)) {
            std::wcerr << L"[-] File is too small to contain NT headers." << std::endl;
            return false;
        }

        this->ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>(this->fileBuffer.data() + this->dosHeader->e_lfanew);
        if (this->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::wcerr << L"[-] Invalid NT signature (PE)." << std::endl;
            return false;
        }

        if (this->ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            std::wcerr << L"[-] Only 64-bit PE files are supported by this parser." << std::endl;
            return false;
        }

        return true;
    }

    void PEParser::DisplayHeaders() {
        if (!this->dosHeader || !this->ntHeaders) {
            std::wcerr << L"[-] PE file not parsed. Call Parse() first." << std::endl;
            return;
        }

        auto print_field = [](const std::string& name, auto value) {
            std::cout << "  " << std::left << std::setw(25) << name
                      << ": 0x" << std::hex << value << " (" << std::dec << value << ")" << std::endl;
        };

        std::cout << "\n--- PE Header Information for: ";
        std::wcout << this->filePath << L" ---\n";

        std::cout << "\n[+] DOS Header\n";
        print_field("Magic", this->dosHeader->e_magic);
        print_field("NT Header Offset", this->dosHeader->e_lfanew);

        std::cout << "\n[+] NT Signature\n";
        print_field("Signature", this->ntHeaders->Signature);

        std::cout << "\n[+] File Header\n";
        print_field("Machine", this->ntHeaders->FileHeader.Machine);
        print_field("Number of Sections", this->ntHeaders->FileHeader.NumberOfSections);
        print_field("Time/Date Stamp", this->ntHeaders->FileHeader.TimeDateStamp);
        print_field("Size of Optional Header", this->ntHeaders->FileHeader.SizeOfOptionalHeader);
        print_field("Characteristics", this->ntHeaders->FileHeader.Characteristics);

        std::cout << "\n[+] Optional Header\n";
        print_field("Magic", this->ntHeaders->OptionalHeader.Magic);
        print_field("Address of Entry Point", this->ntHeaders->OptionalHeader.AddressOfEntryPoint);
        print_field("Image Base", this->ntHeaders->OptionalHeader.ImageBase);
        print_field("Section Alignment", this->ntHeaders->OptionalHeader.SectionAlignment);
        print_field("File Alignment", this->ntHeaders->OptionalHeader.FileAlignment);
        print_field("Size of Image", this->ntHeaders->OptionalHeader.SizeOfImage);
        print_field("Size of Headers", this->ntHeaders->OptionalHeader.SizeOfHeaders);
        print_field("Subsystem", this->ntHeaders->OptionalHeader.Subsystem);
        print_field("Number of RVA and Sizes", this->ntHeaders->OptionalHeader.NumberOfRvaAndSizes);

        std::cout << "\n[+] Section Headers\n";
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(this->ntHeaders);
        for (WORD i = 0; i < this->ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
            std::cout << "  [" << i << "] " << sectionHeader->Name << "\n";
            print_field("  - Virtual Size", sectionHeader->Misc.VirtualSize);
            print_field("  - Virtual Address", sectionHeader->VirtualAddress);
            print_field("  - Size of Raw Data", sectionHeader->SizeOfRawData);
            print_field("  - Pointer to Raw Data", sectionHeader->PointerToRawData);
            print_field("  - Characteristics", sectionHeader->Characteristics);
        }
        std::cout << "\n--- End of PE Information ---\n";
    }
}