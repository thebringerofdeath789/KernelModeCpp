/**
 * @file PEParser.h
 * @author Gregory King
 * @date August 13, 2025
 * @brief This file contains the declaration of the PEParser class.
 *
 * The PEParser class provides functionality to read and parse the headers
 * of a Portable Executable (PE) file, such as a kernel driver, from disk.
 * It can display detailed information about the file's structure.
 */

#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace KernelMode {
    /**
     * @class PEParser
     * @brief A utility to parse and display PE file headers.
     *
     * This class loads a file into memory and provides methods to parse and
     * display its DOS, NT, and section headers. It is designed to work with
     * 64-bit PE files, such as kernel drivers.
     */
    class PEParser {
    public:
        /**
         * @brief Constructs a PEParser for a given file path.
         * @param filePath The path to the PE file to be parsed.
         */
        explicit PEParser(std::wstring filePath);

        /**
         * @brief Parses the PE file.
         * @return True if the file is a valid PE file and was parsed successfully, false otherwise.
         */
        bool Parse();

        /**
         * @brief Displays the parsed PE header information to the console.
         */
        void DisplayHeaders();

    private:
        std::wstring filePath;
        std::vector<char> fileBuffer;
        PIMAGE_DOS_HEADER dosHeader;
        PIMAGE_NT_HEADERS64 ntHeaders;
    };
}