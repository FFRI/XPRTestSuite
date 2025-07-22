# SnowDrift (a.k.a., CloudMensis)

## About this scanning module

XProtectRemediatorSnowDrift is a scanning module that detects SnowDrift, a macOS spyware also known as CloudMensis. The detection logic is described using RemediationBuilder as follows:

```swift
// This may be a bug in XProtectRemediatorSnowDrift. It always returns 0 results.
// See https://stackoverflow.com/questions/1341590/no-results-in-spotlight-in-searches-against-kmditempath
let comAppleiTunesInfoPlistFiles = XProtectPluginAPIPath.search(predicate: NSPredicate(format: "%K LIKE %@", NSMetadataItemPathKey, "*/Library/Preferences/com.apple.iTunesInfo*.plist"), scope: [NSMetadataQueryLocalComputerScope])

let windowServerFiles = XProtectPluginAPIPath.search(predicate: NSPredicate(format: "kMDItemFSName == \"WindowServer\" OR kMDItemFSName == \"windowserver\" OR kMDItemFSName == \"loginwindow\" OR kMDItemFSName == \".Standard.tcc\" OR kMDItemFSName == \".CrashRep\" OR kMDItemFSName == \".CFUserTextDecoding\" OR kMDItemFSName == \"_MACOS_LOAD.sig\""), scope: [NSMetadataQueryLocalComputerScope])
// isAppleSigned() is a function that checks if a file is signed by Apple (by checking the code signature requirement, "anchor apple").
// This filter is likely introduced to avoid repeated false positives of XProtectRemediatorSnowDrift warnings (see https://eclecticlight.co/2022/09/19/snowdrift-warnings-are-they-malware/)
let windowServerFilesNonAppleSigned = windowServerFiles.filter { !isAppleSigned($0)}

var buffer = [CChar](repeating: 0, count: 0x400)
confstr(_CS_DARWIN_USER_CACHE_DIR, &buffer, 0x400)
let cacheDir = String(validatingUTF8: buffer)!
let webcontent_dylib_path = URL(fileURLWithPath: cacheDir).appendingPathComponent("com.apple.WebKit.WebContent+com.apple.Safari/com.apple.speech.speechsynthesisd/webcontent.dylib").path

let targetFiles = [
    "/Library/Logs/DiagnosticReports/.Analytics-Journal.core_analytics",
    "/Library/Application%20Support/Apple/Fonts/iWork/.Standard.ttc",
    "~/Library/Application%20Support/com.apple.spotlight/Resources_V3/.CrashRep",
    "~/Library/Containers/com.apple.Notes/Data/Library/.CFUserTextDecoding",
    "/Library/WebServer/share/httpd/manual/WindowServer",
    "~/Library/Containers/com.apple.FaceTime/Data/Library/windowserver",
    "~/Library/Containers/com.apple.languageassetd/loginwindow",
    "/Library/Preferences/com.apple.iTunesInfo29.plist",
    "/Library/Preferences/com.apple.iTunesInfo.plist",
]

let yaraSnowDrift = """
private rule mach_magic
{
    condition:
        uint32(0) == 0xfeedface
        or uint32(0) == 0xcefaedfe
}
private rule mach64_magic
{
    condition:
        uint32(0) == 0xfeedfacf
        or uint32(0) == 0xcffaedfe
}
private rule fat_mach_magic
{
    condition:
        uint32(0) == 0xcafebabe
        or uint32(0) == 0xbebafeca
}
private rule fat_mach64_magic
{
    condition:
        uint32(0) == 0xcafebabf
        or uint32(0) == 0xbfbafeca
}
private rule Macho
{
    condition:
        mach_magic
        or mach64_magic
        or fat_mach_magic
        or fat_mach64_magic
}
rule multi_snowdrift {
    strings:
        $snowdrift_pcloud_object = /\/MainTask\/BaD\/.{10,100}\/pCloud.o/
        $pcloud = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
        $manage_cloud = "-[Management initCloud:access_token:]"
        $globs = "*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.hwp;*.hwpx;*.csv;*.pdf;*.rtf;*.amr;*.3gp;*.m4a;*.txt;*.mp3;*.jpg;*.eml;*.emlx"
    condition:
        Macho and 2 of them
}
"""

SnowDriftRemediator {
    Service(tag: nil) {
        ExecutableYara(YaraMatcher(yaraSnowDrift))
    }
    for targetFile in targetFiles {
        File(path: targetFile) {} // Delete unconditionally
    }
    File(path: webcontent_dylib_path) {} // Delete unconditionally
    for comAppleiTunesInfoPlistFile in comAppleiTunesInfoPlistFiles {
        File(path: comAppleiTunesInfoPlistFile) {}.reportOnly()
    }
    for windowServerFile in windowServerFilesNonAppleSigned {
        File(path: windowServerFile) {}.reportOnly()
    }
    File(path: "~/Library/LaunchAgents/.com.apple.softwareupdate.plist") {} // Delete unconditionally
    File(path: "~/Library/ApplicationSupport/SyncServices/softwareupdate") {
        FileYara(YaraMatcher(yaraSnowDrift))
    }
    File(path: "~/Library/Logs/imis.log") {
    }.reportOnly()
}
```

## Samples detected by this scanning module

- [I see what you did there: A look at the CloudMensis macOS spyware](https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/)