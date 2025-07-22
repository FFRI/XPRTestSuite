# RedPine

## About this scanning module

XProtectRemediatorRedPine is a scanning module that detects RedPine, which is believed to be the TriangleDB macOS implant.

XProtectRemediatorRedPine has two types of detection logic:

**1. In-memory Mach-O YARA scanner**

This scanner analyzes the memory of the main module of processes (excluding platform binaries) to detect RedPine. The memory scan uses the [redpine.yara](./redpine.yara) rule, which targets the `__TEXT` section of each process. This YARA rule is stored in an encrypted format. Processes that match the rule are not terminated; they are reported only to Apple.

⚠️ Note: [redpine.yara](./redpine.yara) also matches the TriangleDB iOS implant.

**2. LoadedLibrary scanner**

This is described by the RemediationBuilder DSL as follows:

```swift
RedPineScanner {
    Process {
        ProcessIsAppleSigned(false)
        HasLoadedLibrary("/System/Library/PrivateFrameworks/FMCore.framework")
        HasLoadedLibrary("/System/Library/Frameworks/CoreLocation.framework/CoreLocation")
        HasLoadedLibrary("/System/Library/Frameworks/AVFoundation.framework/AVFoundation")
        HasLoadedLibrary("/usr/lib/libsqlite3.dylib")
    }.reportOnly()
}
```

`HasLoadedLibrary` is used to check if the target process has loaded the specified library. This check is performed as follows:

The `VMUProcessDescription` class from the `Symbolication.framework` is used to retrieve information about loaded libraries.
This class calls the `task_info` function to access the `task_dyld_info` structure of the target process, which in turn provides access to the embedded `dyld_all_image_infos` structure.
The `dyld_all_image_infos` structure includes information about the full paths of all loaded libraries.
This information is used to determine whether detection should occur, based on a match with the `HasLoadedLibrary` parameter.

Accessing the `task_dyld_info` structure of a target process requires the `com.apple.system-task-ports.read` entitlement.
Accordingly, XProtectRemediatorRedPine includes this entitlement as shown below:

```
% codesign -dv --entitlements - /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorRedPine 
Executable=/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediatorRedPine
Identifier=com.apple.XProtectFramework.plugins.RedPine
Format=Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=8748 flags=0x12200(kill,library-validation,runtime) hashes=262+7 location=embedded
Signature size=4412
Info.plist entries=3
TeamIdentifier=not set
Runtime Version=13.3.0
Sealed Resources=none
Internal requirements count=1 size=92
[Dict]
	[Key] com.apple.private.endpoint-security.submit.xp
	[Value]
		[Bool] true
	[Key] com.apple.private.kernel.global-proc-info
	[Value]
		[Bool] true
	[Key] com.apple.private.tcc.allow
	[Value]
		[Array]
			[String] kTCCServiceSystemPolicyAppBundles
	[Key] com.apple.private.xprotect.pluginservice
	[Value]
		[Bool] true
	[Key] com.apple.system-task-ports.read
	[Value]
		[Bool] true
```

Notable thing of `RedPineScanner` is that **directory (/System/Library/PrivateFrameworks/FMCore.framework) and symbolic links (/System/Library/Frameworks/CoreLocation.framework/CoreLocation, /System/Library/Frameworks/AVFoundation.framework/AVFoundation) are specified as the `HasLoadedLibrary` parameter, not library paths**. Why? I summarized my hypothesis in the Black Hat USA 2025 presentation. For more details, please refer to [the presentation materials](https://www.blackhat.com/us-25/briefings/schedule/index.html#xunprotect-reverse-engineering-macos-xprotect-remediator-44791).

## Related samples

- [Dissecting TriangleDB, a Triangulation spyware implant](https://securelist.com/triangledb-triangulation-implant/110050/)