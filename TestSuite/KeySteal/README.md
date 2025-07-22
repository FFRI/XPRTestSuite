# KeySteal

## About this scanning module

XProtectRemediatorKeySteal is a scanning module designed to remove KeySteal, a malware specimen that steals data from the macOS Keychain.

The YARA rule (XProtect_MACOS_KEYSTEAL_A) is identical to the one included in XProtect.yara. The detection logic is as follows:

```swift
let keyStealYara = """
rule XProtect_MACOS_KEYSTEAL_A {
    strings:
        // data:application/x-apple-aspen-mobileprovision;base64,%@
        $ = { 64 61 74 61 3A 61 70 70 6C 69 63 61 74 69 6F 6E 2F 78 2D 61 70 70 6C 65 2D 61 73 70 65 6E 2D 6D 6F 62 69 6C 65 70 72 6F 76 69 73 69 6F 6E 3B 62 61 73 65 36 34 2C 25 40 }
        // newdev newid gogogo
        $ = { 00 6E 65 77 64 65 76 00 6E 65 77 69 64 00 67 6F 67 6F 67 6F 00 }
        // {"data":"%@"}
        $ = { 7B 22 64 61 74 61 22 3A 22 25 40 22 7D }
    condition:
        _macho and all of them and filesize < 1MB
}
"""

KeyStealRemediator {
    Service(tag: nil) {
        ExecutablePath(.PatternGroup([".*/Library/.*"]))
        ExecutableYara(YaraMatcher(keyStealYara))
    }
    File(path: "/Library/Caches/com.apple.server") {
        MaxFileSize(32)
    }
    File(path: "/Library/Caches/com.apple.server") {
        MinFileSize(32)
    }.reportOnly(true)
}
```

Note: The file `/Library/Caches/com.apple.server` is not mentioned in Trend Micro’s write-up, which suggests that this scanning module may also target samples other than the one discussed in the report.

## Samples detected by this scanning module

- [Pilfered Keys: Free App Infected by Malware Steals Keychain Data](https://www.trendmicro.com/en_us/research/22/k/pilfered-keys-free-app-infected-by-malware-steals-keychain-data.html)
- [The Mac Malware of 2022 👾 A comprehensive analysis of the year's new malware](https://objective-see.org/blog/blog_0x71.html#-keysteal)
