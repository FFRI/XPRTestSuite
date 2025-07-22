# Custom Mach-O Image Loader with in-memory Mach-O loader

## Overview

This is a modified version of [the Custom Mach-O Image Loader](https://github.com/octoml/macho-dyld). We have added the following feature:
- Support for loading Mach-O files from memory (based on [Patrick Wardle's reflective loader implementation](https://github.com/pwardle/ReflectiveLoader))
    - The only difference is the addition of functions that allow specifying a backing file when loading Mach-O files from memory.


For more details, please refer to our [Black Hat USA 2025 presentation materials](https://www.blackhat.com/us-25/briefings/schedule/index.html#xunprotect-reverse-engineering-macos-xprotect-remediator-44791).

## How to build & install

```
% mkdir build
% cd build
% cmake -DCMAKE_BUILD_TYPE=Release ../
% cmake --build .
% sudo make install
```

## How to use

```c++
#include <cstdio>
#include <cstdlib>
#include <custom_dlfcn.h>

int main(int argc, char** argv) {
    // Read the specified Mach-O file into memory
    const char* payloadPath = argv[1];
    FILE* file = fopen(payloadPath, "r");
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char* fileContents = (char*)malloc(fileSize);
    fread(fileContents, 1, fileSize, file);
    fclose(file);

    // Load the Mach-O file from memory
    // The backing file is specified as "/System/Library/PrivateFrameworks/FMCore.framework"
    void* baseAddr = dlopen_from_memory(fileContents, "/System/Library/PrivateFrameworks/FMCore.framework", fileSize);
}
```

## Author

Koh M. Nakagawa (@tsunek0h) &copy; FFRI Security, Inc. 2025

## License

All source files and implementations are provided under an [Apple Public Source License][APSL].
API header file is provided under [Apache License v2](./LICENSE), which is the same license as the original project.

[APSL]: https://opensource.apple.com/license/apsl

----

**The README below is from the original project.**

## Custom Mach-O Image Loader. Tolerant to unsigned modules.

### Purpose of this module
This is a simplified version of dynamic linker inherited from original Apple sources.
The key difference is in a switched off signature check for loaded binaries. iOS platform
doesn't provide mechanic to load unsigned binary, but you may need it for some developer
purposes like benchmarking/testing code with real device. Using of this linker version
let you get around this limitation.

This library exposes next symbols:
 - custom_dlopen
 - custom_dlclose
 - custom_dlsym
 - custom_dlerror

Use it instead of original Posix version.

### Known limitations
- Load only by absolute path
- There is no recurrent dependencies loading (all required modules should be
  preloaded in process before)
- Works only on system with enabled JIT permissions. Ex: iOS under debugger.
- Only RTLD_LAZY mode is supported 

### Borrowed files
- ImageLoader.h
- ImageLoader.cpp
- ImageLoaderMachO.h
- ImageLoaderMachO.cpp
- ImageLoaderMachOCompressed.h
- ImageLoaderMachOCompressed.cpp

All specific changes of original Apple code are under conditional compilation with 
`#if UNSIGN_TOLERANT` macros. All classes are moved into namespace "isolator" 
to avoid intersection with original symbols from libdyld.

The file `dyld_stubs.cpp` contains some utils and other stub functions to make this code 
compilable. Most of them has no implementation, just for signature compatibility.

### Link to original sources
https://opensource.apple.com/source/dyld/dyld-832.7.3

### Licence
All source files and implementations are provided under an [Apple Public Source License][APSL].
API header file is provided under [Apache License v2][ALv2].

[APSL]: https://opensource.apple.com/license/apsl
[ALv2]: https://www.apache.org/licenses/LICENSE-2.0
