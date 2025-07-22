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
#include <custom_dlfcn.h>
#include <copyfile.h>

char* mainExecutablePath = NULL;

void cleanup(int sig) {
    puts("Cleaning up");
    unlink(mainExecutablePath);
    exit(0);
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s <path_to_macho>\n", argv[0]);
        return 1;
    }

    // convert path to absolute path
    mainExecutablePath = realpath(argv[0], NULL);
    if (mainExecutablePath == NULL) {
        printf("Failed to get absolute path\n");
        return EXIT_FAILURE;
    }

    // printf("mainExecutablePath: %s\n", mainExecutablePath);
    // puts("Modifying dylib info");
    // dyld_all_image_infos* all_images = get_all_image_infos();
    // modify_dylib_info(all_images, mainExecutablePath, "/bin/ls");

    puts("Deleting myself to simulate in-memory payload");
    unlink(mainExecutablePath);

    puts("Creating a fake backing file");
    copyfile("/bin/ls", mainExecutablePath, NULL, COPYFILE_ALL);

    puts("Registering cleanup handler to remove the fake backing file when SIGINT is received");
    struct sigaction sa;
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // read file into memory
    const char* payloadPath = argv[1];
    FILE* file = fopen(payloadPath, "r");
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* fileContents = (char*)malloc(fileSize);
    fread(fileContents, 1, fileSize, file);
    fclose(file);

    try {
        *((uint8_t*)fileContents + 12) =  MH_DYLIB;
        // LoadedLibraryScanner detects the following loaded libraries
        void* baseAddr = dlopen_from_memory(fileContents, "/System/Library/PrivateFrameworks/FMCore.framework", fileSize);
        printf("baseAddr: %p\n", baseAddr);
        baseAddr = dlopen_from_memory(fileContents, "/System/Library/Frameworks/CoreLocation.framework/CoreLocation", fileSize);
        printf("baseAddr: %p\n", baseAddr);
        baseAddr = dlopen_from_memory(fileContents, "/System/Library/Frameworks/AVFoundation.framework/AVFoundation", fileSize);
        printf("baseAddr: %p\n", baseAddr);
        CFRunLoopRun();
    } catch (const char* e) {
        printf("Error: %s\n", e);
    }

    return EXIT_SUCCESS;
}
