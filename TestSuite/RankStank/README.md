# RankStank

## About this scanning module

XProtectRemediatorRankStank is a scanning module designed to detect RankStank, payloads associated with the 3CX supply chain attack.

The 2nd stage payload process is killed by [XProtectRemediatorRoachFlight](../RoachFlight).

## Detection logic

XProtectRemediatorRankStank has the following detection logic:

```swift
// This YARA rule is encrypted
let rankStankYara = """
rule macos_rankstank {
    strings:
        $injected_func = "_run_avcodec"
        $xor_decrypt = { 80 b4 04 ?? ?? 00 00 7a }
        $stringA = "%s/.main_storage"
        $stringB = ".session-lock"
        $stringC = "%s/UpdateAgent"
    condition:
        2 of them
}
"""

RankStankRemediator {
    File(path: "/Applications/3CX Desktop App.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries/libffmpeg.dylib") {
        FileYara(YaraMatcher(rankStankYara))
    }
    // NOTE: File(predicate: NSPredicate, @FileRemediationBuilder fileRemediationBuilder: @escaping () -> [AnyFileCondition]) seems broken. So, file remediation based on NSPredicate is not performed.
    File(predicate: NSPredicate(format: "kMDItemDisplayName == 'libffmpeg.dylib'")) {
        FileYara(YaraMatcher(rankStankYara))
    }
    File(path: "~/Library/Application Support/3CX Desktop App/.main_storage") {
        // emptyArray (it means that if this file exists, it will be deleted unconditionally)
    }
    File(path: "~/Library/Application Support/3CX Desktop App/UpdateAgent") {
        // emptyArray (it means that if this file exists, it will be deleted unconditionally)
    }
}
```

## Samples detected by this scanning module

- [Ironing out (the macOS) details of a Smooth Operator (Part I)](https://objective-see.org/blog/blog_0x73.html)
