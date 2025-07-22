/*
 * (c) FFRI Security, Inc., 2025 / Author: FFRI Security, Inc.
 *
 * This program is used to enumerate the application extensions.
 *
 * Usage:
 *   clang -framework Foundation -o enum_appex enum_appex.m
 *   ./enum_appex
 */
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        void *coreServicesHandle = dlopen("/System/Library/Frameworks/CoreServices.framework/CoreServices", RTLD_LAZY);
        if (!coreServicesHandle) {
            NSLog(@"Failed to load CoreServices.framework");
            return -1;
        }

        Class LSApplicationExtensionRecord = objc_getClass("LSApplicationExtensionRecord");
        if (!LSApplicationExtensionRecord) {
            NSLog(@"LSApplicationExtensionRecord class not found");
            dlclose(coreServicesHandle);
            return -1;
        }

        SEL enumeratorSelector = NSSelectorFromString(@"enumeratorWithOptions:");
        if (![LSApplicationExtensionRecord respondsToSelector:enumeratorSelector]) {
            NSLog(@"enumeratorWithOptions: method not found");
            dlclose(coreServicesHandle);
            return -1;
        }

        unsigned long long options = 0;
        id enumerator = ((id (*)(id, SEL, unsigned long long))objc_msgSend)(LSApplicationExtensionRecord, enumeratorSelector, options);
        
        if (![enumerator isKindOfClass:[NSEnumerator class]]) {
            NSLog(@"Return type is not NSEnumerator");
            dlclose(coreServicesHandle);
            return -1;
        }

        for (id element in enumerator) {
            NSLog(@"Element: %@", element);
        }

        dlclose(coreServicesHandle);
    }
    return 0;
}