# SheepSwap

## About this scanning module

XProtectRemediatorSheepSwap is a scanning module that detects SheepSwap, a variant of Adload adware.

The detection logic of XProtectRemediatorSheepSwap changes depending on whether it is executed as root or not. Here we show the logic when executed as a user. The logic when executed as root is extremely complex, so we did not analyze it.

The detection logic is described using RemediationBuilder as follows:

<details>
<summary>Remediation logic described with RemediationBuilder DSL (click to expand)</summary>

```swift
let sheepSwapYara1 = """
rule sheepswap_variant_1 {
    strings:
        $x1 = "lastHeartbeat"
        $x2 = "sessionGuid"
        $x3 = "extensionId"
        $x4 = "userGuid"
    condition:
        filesize < 200000 and all of them
}
rule sheepswap_variant_2 {
    strings:
        $x1 = { F3 0F 6F 54 F8 20 66 0F EB D0 F3 0F 6F 44 F8 30 66 0F EB C1 }
        $x2 = "myDomain"
        $x3 = "settingsManager"
        $x4 = "poopi"
    condition:
        filesize < 200000 and all of them
}
rule sheepswap_variant_3 {
    strings:
        // Byte sequence from function 0x100006AAA
        $x1 = { 49 FF C7 31 D2 4C 89 F8 48 F7 B5 E8 FE FF FF 48 3B 53 10 }
        // Byte sequence from function 0x1000D1A7A
        $x2 = { 48 BF 49 4F 50 6C 61 74 66 6F 48 BE 72 6D 55 55 49 44 00 EE}
        // Byte sequence from function 0x100045530
        $x3 = { 48 89 55 C8 0F B6 44 13 20 4C 8B B5 50 FF FF FF 48 8B 8D 58 FF FF FF 48 89 CA 48 C1 EA 3E 80 FA 01 74 2D }
    condition:
        // Yes, this filesize is larger per the MRTv3 remediation
        filesize < 2000000 and all of them
}
rule macos_new_sheepswap
{
    strings:
        $x1 = "spmDomain"
        $x2 = "extIdParam"
        $x3 = "idParam"
        $x4 = "loggingUrl"
        $x5 = "srchProxyURL"
        $x6 = "getLoggingUrl"
        $x7 = "SafariExtensionViewController"
        $x8 = "popoverViewController"
    condition:
        filesize < 500KB and all of them
}
rule macos_sheepswap_strings {
    strings:
        $x1 = "getStateOfSafariExtensionWithIdentifier:completionHandler:"
        $x2 = "showPreferencesForExtensionWithIdentifier:completionHandler:"
        $x3 = "initWithBase64EncodedString:options:"
        $x4 = "setLaunchPath:"
        $x5 = "shown"
        $x6 = "enabled"
        $x7 = "_swift"
    condition:
        filesize < 300KB and all of them
}
private rule Macho {
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}
rule macos_sheepswap_randomized_bundleID {
    strings:
        $x_1 = /com\.[a-zA-Z]{4,100}[0-9]{1,5}[a-zA-Z]{4,100}/
        $x_2 = /com\.[a-zA-Z]{,100}[0-9]{1,5}[a-zA-Z]{10,100}/
        $s_1 = "getStateOfSafariExtensionWithIdentifier:completionHandler:"
        $s_2 = "showPreferencesForExtensionWithIdentifier:completionHandler:"
        $s_3 = "initWithBase64EncodedString:options:"
        $s_4 = "setLaunchPath:"
        $ss = "SUPERSTR"
        $sws = "_swift"
    condition:
        Macho and any of ($x_*) and (2 of ($s_*) or (any of ($s_*) and $ss)) and $sws and filesize < 1500KB
}
rule macos_sheepswap_new_bunldeID {
    strings:

            $str_selector_1 = "getStateOfSafariExtensionWithIdentifier:completionHandler:"
            $str_selector_2 = "showPreferencesForExtensionWithIdentifier:completionHandler:"
            $str_swift = "_swift"
            $common_1 = {0011223060293080015342544370105443701053425342534258447030601541}
            $common_2 = {4152415241524152415241524252426023437030534470107010600F44700870}

        condition:
            Macho and all of ($str_*) and #str_swift > 84 and any of ($common_*) and filesize < 1500KB
}
private rule JavaScript {
    meta:
        //yl ignore-meta
        description = "private rule to match JavaScript code"

    strings:
        $indicator_1 = /function([ \t]*|[ \t]+[\w]+[ \t]*)\([\w \t,]*\)[ \t]*\{/
        $indicator_2 = /\beval[ \t]*\(/
        $indicator_3 = /new[ \t]+ActiveXObject\(/
        $indicator_4 = /xfa\.((resolve|create)Node|datasets|form)/
        $indicator_5 = /\.oneOfChild/
    
    condition:
        any of them
}
rule macos_sheepswap_obfuscated_scripts {
    strings:
        $stringA = "brandId"
        $stringB = "srchProxyURL"
        $stringC = "contentRuntimeUrl"
        $stringD = "redurl"
        $stringE = "extensionId"
        $stringF = "userGuid"
        $stringG = "srchMatchData"
        $stringH = "window.safari.extension.dispatchMessage"
        $stringI = "arguments.callee.toString().split(String.fromCharCode(32))[1].slice(0,-2)"

    condition:
        JavaScript and 8 of them and #stringI > 30 and filesize < 30KB
}
rule macos_sheepswap_main_binary {
    strings:
        $mainFunc = { 48 8b 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 49 89 c4 48 89 df e8 ?? ?? ?? ?? 48 89 cb 48 89 c7 48 89 d6 48 89 da e8 ?? ?? ?? ?? 49 89 c6 48 89 df e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? be 18 00 00 00 ba 07 00 00 00 48 8d 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 c3 4c 89 6b 10 48 8d 05 ?? ?? ?? ?? 48 89 45 b0 48 89 5d b8 48 8b 05 ?? ?? ?? ?? 48 89 45 90 c7 45 98 00 00 00 42 c7 45 9c 00 00 00 00 0f 28 45 80 0f 11 45 a0 48 8d 7d 90 e8 ?? ?? ?? ?? 49 89 c7 4c 89 ef e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 48 8b 35 ?? ?? ?? ?? 4c 89 e7 4c 89 f2 4c 89 f9 e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? 48 8b 3d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b 35 ?? ?? ?? ?? 48 89 c7 f3 0f 7e 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? ff 55 c8 a8 01 }

        $mainBlock1 = { e8 ?? ?? ?? ?? 41 80 e7 01 44 88 78 10 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 48 89 4b 20 48 89 43 28 48 ?? ?? ?? ?? ?? ?? 48 89 03 48 ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 66 48 0f 6e c0 48 ?? ?? ?? ?? ?? ?? 66 48 0f 6e c8 66 0f 6c c8 f3 0f 7f 4b 10 48 89 df e8 ?? ?? ?? ?? 49 89 c7 48 ?? ?? ?? e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? 4c 89 e2 4c 89 f9 e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? }
        $mainBlock2 = { 48 89 c3 4c 8b 7d b8 4c 89 ef e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c 89 e7 4c 89 f2 48 89 d9 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 f7 e8 ?? ?? ?? ?? }

        $mainBlock3  = { 49 8B ?? 00 4C 89 ?? E8 37 ?? 00 00 48 8D ?? ?? ?? 00 00 48 39 C3 74 ?? 48 8D ?? ?? ?? 00 00 48 BE 00 00 00 00 00 00 00 80 48 09 ?? 48 BF 30 00 00 00 00 00 00 D0 FF 55 ?? EB ?? 48 8D ?? ?? ?? 00 00 48 BE 00 00 00 00 00 00 00 80 48 09 ?? 48 BF 30 00 00 00 00 00 00 D0 E8 6F ?? 00 00 }

        $mainBlock4  = { 49 BE 00 00 00 00 00 00 00 ?? 66 49 0F 6E C6 66 0F 73 ?? ?? 66 0F ?? ?? A0 49 8B ?? ?? 48 89 ?? ?? 48 85 C0 48 8B ?? ?? 4C 89 7D D0 0F 84 ?? ?? 00 00 48 8B ?? ?? 48 89 ?? ?? 48 85 C0 0F 84 ?? ?? 00 00 48 FF ?? ?? 31 D2 48 8D ?? ?? ?? 00 00 66 48 0F 6E C0 48 8D ?? ?? ?? FF FF 66 48 0F 6E C8 66 0F 6C C8 66 0F 7F 8D 20 FF FF FF 45 31 ?? 66 2E 0F ?? ?? ?? 00 00 00 ?? 0F 1F ?? 00 ?? }
        $methodA = "showPreferencesForExtensionWithIdentifier:completionHandler:"
        $methodB = "getStateOfSafariExtensionWithIdentifier:completionHandler:"
        $stringA = "macbuilder_builds"
        $stringB = "LocalSafariAppExt"
        $stringC = "searchHistory"
        $stringD = "matchDataTimer"
        $stringE = "openPref"
        $stringF = "getSystemUUID"
        $stringG = "processInfo"
        $stringH = "arguments"
        $stringI = "_IOServiceMatching"
        $stringJ = {48 BF 49 4F 50 6C 61 74 66 6F 48 BE 72 6D 55 55 49 44 00 EE}
    condition:
        Macho and (filesize < 200KB) and (1 of ($main*)) and (all of ($method*)) and (2 of ($string*))
}
rule macos_sheepswap_safari_extension
{
    strings:
        $a = { 73 65 61 72 63 68 [2-12] 2e 61 6b 61 6d 61 69 68 64 2e 6e 65 74 2f }
        $b1 = { 49 be 79 73 00 00 00 00 00 ea 49 ?? ?? ?? ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 89 d8 e8 ?? ?? ?? ?? be 02 00 00 00 4c 89 e7 e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 81 c6 f5 00 00 00 48 89 df 4c 89 ee 4c 89 f2 e8 ?? ?? ?? ?? 49 89 dd e8 ?? ?? ?? ?? 49 89 c7 41 ?? ?? ?? ?? 4c 89 e3 49 c7 c4 ff ff ff ff 49 d3 e4 49 f7 d4 4d 21 e7 4c 89 f8 48 c1 e8 06 48 ?? ?? ?? ?? 4c 0f a3 f8 0f 83 ?? ?? ?? ?? }
        $b2 = { 4c 89 ef e8 ?? ?? ?? ?? 48 ?? 61 62 70 2d 64 61 74 61 48 be 00 00 00 00 00 00 00 e8 e8 ?? ?? ?? ?? 49 89 c4 48 ?? ?? ?? ?? ?? ?? 48 85 ff 75 ?? }
        $b3 = { 49 89 c6 48 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 49 89 c7 4c 8b 6d b8 4c 89 ef e8 ?? ?? ?? ?? 48 8b bd 20 ff ff ff 4c 89 ee e8 ?? ?? ?? ?? 49 89 c4 48 ?? ?? ?? ?? ?? ?? 4c 89 ff 48 89 c2 48 89 d9 e8 ?? ?? ?? ?? 48 89 c3 4c 89 ef e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 48 85 db 0f 84 ?? ?? ?? ?? }
        $b4 = { 48 8d b5 a0 fd ff ff 48 89 c7 e8 ?? ?? ?? ?? 4c 89 fa 48 89 55 a8 49 89 c7 0f 28 ?? ?? ?? ?? ?? 41 0f 11 47 10 48 ?? ?? ?? ?? ?? ?? 66 48 0f 6e c0 b8 02 00 00 00 66 48 0f 6e c8 66 0f 6c c1 66 0f 7f 4d c0 }
        $b5 = { 49 ff c7 31 d2 4c 89 f8 48 f7 75 c0 48 8b 5d c8 48 3b 53 10 0f 82 ?? ?? ?? ?? }
        $c1 = { 6c 61 73 74 48 65 61 72 74 62 65 61 74 }
        $c2 = { 73 65 73 73 69 6f 6e 47 75 69 64 }
        $c3 = { 65 78 74 65 6e 73 69 6f 6e 49 64 }
        $c4 = { 75 73 65 72 47 75 69 64 }
        $c5 = { 41 70 70 45 78 74 48 65 61 72 74 62 65 61 74 }
        $c6 = { 69 73 4e 65 77 53 65 61 72 63 68 }
        $c7 = { 73 65 6e 64 48 65 61 72 74 62 65 61 74 }
        $c8 = { 53 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 48 61 6e 64 6c 65 72 }
        $c9 = { 6d 65 73 73 61 67 65 52 65 63 65 69 76 65 64 }
        $d1 = { 48 89 CA 48 83 E2 FC 48 8D 5A ?? 48 89 DF 48 C1 EF ?? 48 FF C7 89 FE 83 E6 ?? 48 83 FB 0C 73 18 66 0F EF C0 31 FF 66 0F EF C9 48 85 F6 }
        $e1 = { 5f 49 4f 53 65 72 76 69 63 65 47 65 74 4d 61 74 63 68 69 6e 67 53 65 72 76 69 63 65 }
        $e2 = { 5f 49 4f 53 65 72 76 69 63 65 4d 61 74 63 68 69 6e 67 }
        $e3 = { 53 46 53 61 66 61 72 69 50 61 67 65 50 72 6f 70 65 72 74 69 65 73 }
        $f1 = { 48 B8 53 55 50 45 52 53 54 52 48 89 85 ?? FE FF FF 48 B8 49 4E 47 44 55 44 45 EF }
        $f2 = { 49 FF C7 31 D2 4C 89 F8 48 F7 [2-5] 48 3B 53 10 }
        $f3 = { 48 BF 49 4F 50 6C 61 74 66 6F 48 BE 72 6D 55 55 49 44 00 EE }
        $f4 = { 48 89 55 C8 0F B6 44 13 20 4C 8B B5 50 FF FF FF 48 8B 8D 58 FF FF FF 48 89 CA 48 C1 EA 3E 80 FA 01 74 2D }
        $f5 = { 48 B8 59 57 30 54 64 53 54 52 }

    condition:
        Macho and (filesize < 2MB) and ((($a or any of ($b*)) and (2 of ($c*))) or (any of ($d*) and (all of ($e*))) or ((all of ($e*)) and 4 of ($f*))) and #c8 > 10 
}
"""

let sheepSwapYara2 ="""
rule hunt_sheepswap_extension_obfuscation {
    strings:
        $stringBefore = "_$sSS5index6beforeSS5IndexVAD_tF"
        $stringAfter = "_$sSS5index5afterSS5IndexVAD_tF"
        $stringCount = "_$sSS5countSivg"
        $immStringMov = { 49 ?? ?? ?? ?? ?? 28 29 00 ee 49}
        $extensionClass = "extension22SafariExtensionHandler"
        $extensionSelector = "messageReceivedWithName:fromPage:userInfo:"
    condition:
        all of them
}
private rule Macho {
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}
rule hunt_macos_sheepswap_randomized_bundleID {
    strings:
        $x_1 = /com\.[a-zA-Z]{4,100}[0-9]{1,5}[a-zA-Z]{4,100}/
        $x_2 = /com\.[a-zA-Z]{,100}[0-9]{1,5}[a-zA-Z]{10,100}/
        $x_3 = /com\.[a-zA-Z]{12,100}[0-9]{1,5}/
        $x_4 = /com\.[0-9]{1,5}[a-zA-Z]{1,5}[0-9]{1,5}[a-zA-Z]{,12}/
        $s_1 = "getStateOfSafariExtensionWithIdentifier:completionHandler:"
        $s_2 = "showPreferencesForExtensionWithIdentifier:completionHandler:"
        $s_3 = "initWithBase64EncodedString:options:"
        $s_4 = "setLaunchPath:"
        $ss = "SUPERSTR"
        $sws = "_swift"
    condition:
        Macho and any of ($x_*) and (2 of ($s_*) or (any of ($s_*) and $ss)) and $sws and filesize < 1500KB
}
"""

let sheepSwapYara3 = """
private rule JavaScript {
    meta:
        //yl ignore-meta
        description = "private rule to match JavaScript code"

    strings:
        $indicator_1 = /function([ \t]*|[ \t]+[\w]+[ \t]*)\([\w \t,]*\)[ \t]*\{/
        $indicator_2 = /\beval[ \t]*\(/
        $indicator_3 = /new[ \t]+ActiveXObject\(/
        $indicator_4 = /xfa\.((resolve|create)Node|datasets|form)/
        $indicator_5 = /\.oneOfChild/
    
    condition:
        any of them
}
rule hunt_macos_sheepswap_obfuscated_scripts {
    strings:
        $stringA = "addEventListener"
        $stringB = "window.safari.extension.dispatchMessage"
        $stringC = "window.navigator.userAgent"
        $stringD = "data.reasonId"
        $stringE = "Math.round"
        $stringF = "compressToBase64"
        $stringG = "String.fromCharCode"
        $stringH = "arguments.callee.toString()."

    condition:
        JavaScript and all of them and #stringG > 30 and #stringH > 30 and filesize < 30KB
}
rule hunt_macos_sheepswap_js_expand_set {
    strings:
        $expand = /return expand\(.{1,8}\);/
        $fncDecode = /return fncDecode\(.{4}\);/
    condition:
        #fncDecode > 5 and for (#fncDecode - 4) i in (2..#fncDecode) : (@fncDecode[i] - @fncDecode[i-1] < 180) or #expand > 5 and for (#expand - 4) i in (2..#expand) : (@expand[i] - @expand[i-1] < 180)
}
rule hunt_macos_sheepswap_obfuscated_js {
    strings:
        $a = "arguments.callee.toString().split"
        $b = "cidx < cdstr.length"
        $c = "(str, base, offset)"
        $d = "decompressFromBase64: function(b)"
        $e = "decompressFromEncodedURIComponent: function(b)"
    condition:
        any of them and filesize < 50KB
}
rule hunt_macos_sheepswap_strings {
        strings:
        $a = "srchProxyURL"
        $b = "srchMatchData"
        $c = "navHist"
        $d = "matchDataTimer"
    condition:
        any of them and filesize < 50KB
}
"""

SheepSwapRemediator {
    SafariAppExtension {
        ExtensionBinaryYara(YaraMatcher(sheepSwapYara1))
    }
    SafariAppExtension {
        ExtensionBinaryYara(YaraMatcher(sheepSwapYara2))
        JavaScriptYara(YaraMatcher(sheepSwapYara3))
    }
    SafariAppExtension {
        JavaScriptYara(YaraMatcher(sheepSwapYara3))
    }.reportOnly()
    SafariAppExtension {
        ExtensionBinaryYara(YaraMatcher(sheepSwapYara2))
    }.reportOnly()
}
```
</details>

The enumeration of SafariAppExtension targets for detection utilizes the `LSApplicationExtensionRecord` class from the CoreServices framework. A sample application that uses this class to enumerate App Extensions is available at [enum_appex.m](enum_appex.m).

## Samples detected by this scanning module

- [Shlayer Trojan attacks one in ten macOS users](https://securelist.com/shlayer-for-macos/95724/)
