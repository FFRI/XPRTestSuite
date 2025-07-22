# Bundlore

## About this scanning module

XProtectRemediatorBundlore is a scanning module that detects and remediates notorious Bundlore adware samples.

The remediation logic described with RemediationBuilder DSL is as follows:

```swift
let bundloreYara = """
private rule Macho {
    condition:
        ((uint32be(0)==0xCEFAEDFE or uint32be(0)==0xCFFAEDFE or uint32be(0)==0xFEEDFACE or uint32be(0)==0xFEEDFACF) or (uint32be(0)==0xCAFEBABE and uint32(4) < 0x14000000))
rule XProtect_MACOS_BUNDLORE_MMLR {
    strings:
        $a = { 42 72 6F 77 73 65 72 20 73 65 74 74 69 6E 67 73 20 77 69 6C 6C 20 62 65 20 63 68 61 6E 67 65 64 20 74 6F 20 61 6C 6C 6F 77 20 74 68 65 20 73 6F 66 74 77 61 72 65 20 74 6F 20 6F 70 65 72 61 74 65 }
        $b1 = { 76 69 72 74 75 61 6C 62 6F 78 }
        $b2 = { 76 6D 77 61 72 65 }
        $b3 = { 70 61 72 61 6C 6C 65 6C 73 }
    condition:
        Macho and filesize < 5MB and all of them
rule XProtect_MACOS_BUNDLORE_CLKGN {
    strings:
        $a = { 5F 6D 61 63 2E 70 68 70 3F 63 6C 69 63 6B 69 64 3D }
        $b1 = { 43 68 72 6F 6D 65 20 4D 61 73 74 65 72 20 50 72 65 66 65 72 65 6E 63 65 73 }
        $b2 = { 53 79 6E 63 44 61 74 61 2E 73 71 6C 69 74 65 33 }
        $c1 = { 66 61 72 69 2E 61 70 70 2F 43 6F 6E 74 65 6E 74 73 2F 49 6E 66 6F 2E 70 6C 69 73 74 }
        $c2 = { 41 70 70 6C 65 20 47 6C 6F 62 61 6C 20 44 6F 6D 61 69 6E }
    condition:
        Macho and filesize < 5MB and any of ($a*) and any of ($b*) and any of ($c*)
rule XProtect_MACOS_BUNDLORE_MDPLST {
    strings:
        $a = { 64 61 74 61 57 69 74 68 50 72 6F 70 65 72 74 79 4C 69 73 74 3A }
        $b_1 = { 31 FF E9 ?? ?? ?? ?? 0F 1F 84 00 ?? ?? ?? ?? 4C 8D 7B ?? 49 21 DF 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 9D ?? ?? ?? ?? 4C 8D AD ?? ?? ?? ?? 4C 89 EF 48 89 DE E8 ?? ?? ?? ?? 49 89 C4 48 8B 7D ?? FF 15 ?? ?? ?? ?? 48 89 45 ?? 4C 89 E7 48 89 DE E8 ?? ?? ?? ?? 49 89 C4 4C 89 EF E8 ?? ?? ?? ?? 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 7D ?? 4C 89 F6 E8 ?? ?? ?? ?? 48 89 C3 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 35 ?? ?? ?? ?? 48 8B 7D ?? 4C 89 E2 48 89 D9 E8 ?? ?? ?? ?? 48 8B 7D ?? 48 8B 05 ?? ?? ?? ?? 49 89 C5 FF D0 4C 89 E7 E8 ?? ?? ?? ?? 48 89 DF 41 FF D5 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 7D ?? 48 89 7D ?? 4C 89 F9 4D 85 FF 0F 85 ?? ?? ?? ?? 48 8B 45 ?? 48 FF C0 0F 80 ?? ?? ?? ?? 48 3B 45 ?? 0F 8D ?? ?? ?? ?? 48 8B 4D ?? 48 8B 0C C1 48 85 C9 74 ?? 48 89 C7 E9 ?? ?? ?? ?? 48 8D 78 ?? }
        $b_2 = { 49 89 DC 48 85 DB 0F 85 ?? ?? ?? ?? 4C 89 C8 48 FF C0 0F 80 ?? ?? ?? ?? 48 3B 45 ?? 0F 8D ?? ?? ?? ?? 48 8B 4D ?? 4C 8B 24 C1 4D 85 E4 74 ?? 49 89 C7 EB ?? 4C 8D 78 ?? 4C 3B 7D ?? 0F 8D ?? ?? ?? ?? 48 8B 4D ?? 4C 8B 64 C1 ?? 4D 85 E4 75 ?? 4C 8D 78 ?? 4C 3B 7D ?? 0F 8D ?? ?? ?? ?? 48 8B 4D ?? 4C 8B 64 C1 ?? 4D 85 E4 75 ?? 48 83 C0 ?? 48 3B 45 ?? 0F 8D ?? ?? ?? ?? 4D 89 CF 0F 1F 00 48 8B 45 ?? 4E 8B 64 F8 ?? 4D 85 E4 75 ?? 49 8D 47 ?? 49 83 C7 ?? 4C 3B 7D ?? 49 89 C7 7C ?? E9 ?? ?? ?? ?? }
        $b_3 = { 0F 8D ?? ?? ?? ?? 49 8B 5C CF ?? 48 85 DB 0F 84 ?? ?? ?? ?? 48 89 CF 48 85 DB 75 ?? 0F 1F 40 ?? B8 ?? ?? ?? ?? 48 8D 4B ?? 48 21 CB 48 89 5D ?? 48 89 7D ?? 48 C1 E7 ?? 48 01 C7 49 8B 47 ?? 48 89 F9 48 C1 E1 ?? 4C 8B 34 08 48 8B 5C 08 ?? 48 C1 E7 ?? 49 03 7F ?? 4C 89 E6 E8 ?? ?? ?? ?? 4C 89 B5 ?? ?? ?? ?? 48 89 9D ?? ?? ?? ?? 4C 89 E7 48 8D B5 ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 DF E8 ?? ?? ?? ?? EB ?? }
    condition:
        Macho and filesize < 5MB and $a and any of ($b*)
rule XProtect_MACOS_BUNDLORE_APSCPT {
    strings:
        $a = { 74 65 6C 6C 20 61 70 70 6C 69 63 61 74 69 6F 6E 20 27 53 61 66 61 72 69 27 0A 09 09 74 72 79 0A 09 09 09 69 66 20 77 69 6E 64 6F 77 73 20 69 73 20 7B 7D 20 74 68 65 6E 20 72 65 6F 70 65 6E 0A 09 09 09 72 65 70 65 61 74 20 77 69 74 68 20 69 20 66 72 6F 6D 20 31 20 74 6F 20 31 35 0A 09 09 09 09 69 66 20 77 69 6E 64 6F 77 73 20 69 73 20 6E 6F 74 20 65 71 75 61 6C 20 74 6F 20 7B 7D 20 74 68 65 6E 20 65 78 69 74 20 72 65 70 65 61 74 0A 09 09 09 09 64 65 6C 61 79 20 31 0A 09 09 09 65 6E 64 20 72 65 70 65 61 74 0A 09 09 09 74 65 6C 6C 20 66 69 72 73 74 20 77 69 6E 64 6F 77 20 74 6F 20 74 65 6C 6C 20 66 69 72 73 74 20 74 61 62 20 74 6F 20 73 65 74 20 6A 73 52 65 73 75 6C 74 20 74 6F 20 64 6F 20 4A 61 76 61 53 63 72 69 70 74 20 27 64 6F 63 75 6D 65 6E 74 2E 72 65 61 64 79 53 74 61 74 65 3B 27 0A 09 09 6F 6E 20 65 72 72 6F 72 20 74 68 65 20 65 72 72 4D 73 67 20 6E 75 6D 62 65 72 20 74 68 65 20 65 72 72 4E 75 6D 0A 09 09 09 73 65 74 20 6A 73 52 65 73 75 6C 74 20 74 6F 20 65 72 72 4E 75 6D 0A 09 09 65 6E 64 20 74 72 79 0A 09 65 6E 64 20 74 65 6C 6C }
    condition:
        Macho and filesize < 5MB and any of them
rule XProtect_MACOS_BUNDLORE_BRSHJKCMM {
    strings:
        $a1 = { 50 6C 69 73 74 55 74 69 6C 73 }
        $a2 = { 53 61 66 61 72 69 53 61 76 65 4F 70 74 69 6F 6E 73 }
        $b1 = { 64 61 74 61 57 69 74 68 50 72 6F 70 65 72 74 79 4C 69 73 74 3A 66 6F 72 6D 61 74 3A 6F 70 74 69 6F 6E 73 3A 65 72 72 6F 72 3A }
        $b2 = { 64 61 74 61 57 69 74 68 4A 53 4F 4E 4F 62 6A 65 63 74 3A 6F 70 74 69 6F 6E 73 3A 65 72 72 6F 72 3A }
        $b3 = { 73 65 74 46 72 6F 6E 74 6D 6F 73 74 3A }
        $b4 = { 63 6C 69 63 6B 41 74 3A }
        $b5 = { 73 65 74 43 75 72 72 65 6E 74 54 61 62 3A }
        $b6 = { 69 6E 69 74 57 69 74 68 42 61 73 65 36 34 45 6E 63 6F 64 65 64 53 74 72 69 6E 67 3A 6F 70 74 69 6F 6E 73 3A }
    condition:
        Macho and filesize < 5MB and all of them
"""

BundloreRemediator {
    Service(tag: nil) {
        ExecutableIsUntrusted(true)
        ExecutableYara(YaraMatcher(bundloreYara))
    }.deleteBundleToo()

    // This also registers onMatchCallbacks 10008f9e0 (for XPR v149)
    Service(tag: nil) {
        ExecutableIsUntrusted(true)
        ExecutablePath(.Pattern(".*/(confup|macOSOTA|SofTruster|UpToDateMac|zapdate|webtools|.?MMSPROT)(/|$)"))
    }.reportOnly()

    File(searchDir:"~/Applications", regexp: ".*/(confup|macOSOTA|SofTruster|UpToDateMac|zapdate|webtools|.?MMSPROT)(/|$)", searchDepth: 3)  {
        MinFileSize(constraint: 102400)
        MaxFileSize(constraint: 5242880)
        FileMacho(true)
        FileNotarised(false)
        FileYara(YaraMatcher(bundloreYara))
    }

    File(searchDir:"~/Applications", regexp: ".*/(confup|macOSOTA|SofTruster|UpToDateMac|zapdate|webtools|.?MMSPROT)(/|$)", searchDepth: 3)  {
        FileNotarised(false)
    }.reportOnly()
}
```
