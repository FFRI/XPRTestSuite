/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */
#import <Foundation/Foundation.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

void execute_memory(void* memory, int machoSize, const char* functionName, int argumentCount, char** arguments, const char* backingFilePath) {
    NSObjectFileImage fileImage = NULL;
    NSModule module = NULL;
    NSSymbol symbol = NULL;

    *((uint8_t*)memory + 12) =  MH_BUNDLE;
    
    NSCreateObjectFileImageFromMemory(memory, machoSize, &fileImage);
    if (!fileImage) {
        perror("Failed to call NSCreateObjectFileImageFromMemory");
        return;
    }
    else {
        printf("NSCreateObjectFileImageFromMemory success!\n");
    }
    
    module = NSLinkModule(fileImage, backingFilePath, NSLINKMODULE_OPTION_NONE);
    if (!module) {
        perror("Failed to call NSLinkModule");
        return;
    }
    else {
        printf("NSLinkModule success!\n");
    }
    
    symbol = NSLookupSymbolInModule(module, functionName);
    if (!symbol) {
        perror("Failed to call NSLookupSymbolInModule");
        return;
    }
    else {
        printf("NSLookupSymbolInModule success!\n");
    }
    
    puts("Going to entry point");
    int(*entry)(int, char**) = (int(*)(int, char**)) NSAddressOfSymbol(symbol);
    entry(argumentCount, arguments);

    printf("Cleaning up with NSUnLinkModule and NSDestroyObjectFileImage\n");
    NSUnLinkModule(module, NSUNLINKMODULE_OPTION_NONE);
    NSDestroyObjectFileImage(fileImage);
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s <path_to_macho> <backing file path>\n", argv[0]);
        return 1;
    }

    const char* path = argv[1];
    // convert path to absolute path
    char* absolutePath = realpath(path, NULL);
    if (absolutePath == NULL) {
        printf("Failed to get absolute path\n");
        return EXIT_FAILURE;
    }

    printf("Absolute path: %s\n", absolutePath);

    // read file into memory
    FILE* file = fopen(absolutePath, "r");
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* fileContents = (char*)malloc(fileSize);
    fread(fileContents, 1, fileSize, file);
    fclose(file);

    const char* backingFilePath = argv[2];
    execute_memory(fileContents, fileSize, "_main", 0, NULL, backingFilePath);
    return EXIT_SUCCESS;
}
