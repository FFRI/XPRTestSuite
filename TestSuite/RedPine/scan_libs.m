/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <stdlib.h>

typedef id (*VMUProcessDescriptionInitWithTask)(id self, SEL _cmd, mach_port_t task, BOOL getBinariesList);
typedef id (*VMUProcessDescriptionBinaryImagesDescription)(id self, SEL _cmd);
typedef id (*VMUProcessDescriptionParseBinaryImagesDescription)(Class self, SEL _cmd, id description);

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc != 2) {
            NSLog(@"Usage: %s <PID>", argv[0]);
            return 1;
        }

        pid_t pid = atoi(argv[1]);
        if (pid <= 0) {
            NSLog(@"Invalid PID: %s", argv[1]);
            return 1;
        }

        mach_port_t task;
        kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
        if (kr != KERN_SUCCESS) {
            NSLog(@"Failed to get task port for PID %d: %s", pid, mach_error_string(kr));
            return 1;
        }

        void *symbolicationHandle = dlopen("/System/Library/PrivateFrameworks/Symbolication.framework/Symbolication", RTLD_LAZY);
        if (!symbolicationHandle) {
            NSLog(@"Failed to load Symbolication.framework");
            return 1;
        }

        Class VMUProcessDescription = NSClassFromString(@"VMUProcessDescription");
        if (!VMUProcessDescription) {
            NSLog(@"Failed to find VMUProcessDescription class");
            dlclose(symbolicationHandle);
            return 1;
        }

        SEL initWithTaskSelector = NSSelectorFromString(@"initWithTask:getBinariesList:");
        if (!initWithTaskSelector) {
            NSLog(@"Failed to find initWithTask:getBinariesList: selector");
            dlclose(symbolicationHandle);
            return 1;
        }

        id processDescription = [[VMUProcessDescription alloc] init];
        if (!processDescription) {
            NSLog(@"Failed to create VMUProcessDescription instance");
            dlclose(symbolicationHandle);
            return 1;
        }

        VMUProcessDescriptionInitWithTask initWithTaskImp = (VMUProcessDescriptionInitWithTask)[processDescription methodForSelector:initWithTaskSelector];
        id result = initWithTaskImp(processDescription, initWithTaskSelector, task, YES);
        if (!result) {
            NSLog(@"initWithTask:getBinariesList: returned nil");
            dlclose(symbolicationHandle);
            return 1;
        }

        SEL binaryImagesDescriptionSelector = NSSelectorFromString(@"binaryImagesDescription");
        if (!binaryImagesDescriptionSelector) {
            NSLog(@"Failed to find binaryImagesDescription selector");
            dlclose(symbolicationHandle);
            return 1;
        }

        VMUProcessDescriptionBinaryImagesDescription binaryImagesDescriptionImp = (VMUProcessDescriptionBinaryImagesDescription)[result methodForSelector:binaryImagesDescriptionSelector];
        id binaryImagesDescription = binaryImagesDescriptionImp(result, binaryImagesDescriptionSelector);
        if (!binaryImagesDescription) {
            NSLog(@"binaryImagesDescription returned nil");
        } else {
            NSLog(@"binaryImagesDescription: %@", binaryImagesDescription);
        }

        SEL parseBinaryImagesDescriptionSelector = NSSelectorFromString(@"parseBinaryImagesDescription:");
        if (!parseBinaryImagesDescriptionSelector) {
            NSLog(@"Failed to find parseBinaryImagesDescription: selector");
            dlclose(symbolicationHandle);
            return 1;
        }

        VMUProcessDescriptionParseBinaryImagesDescription parseBinaryImagesDescriptionImp = (VMUProcessDescriptionParseBinaryImagesDescription)[VMUProcessDescription methodForSelector:parseBinaryImagesDescriptionSelector];
        id parsedDescription = parseBinaryImagesDescriptionImp(VMUProcessDescription, parseBinaryImagesDescriptionSelector, binaryImagesDescription);
        if (!parsedDescription) {
            NSLog(@"parseBinaryImagesDescription: returned nil");
        } else {
            NSLog(@"Parsed binary images description: %@", parsedDescription);
        }

        dlclose(symbolicationHandle);
    }

    return 0;
}
