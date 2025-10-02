# Adload

## About this scanning module

XProtectRemediatorAdload is a scanning module that detects and remediates well-known Adload adware.

This scanning module implements the following remediation logic:

<details>
<summary>Remediation logic described with RemediationBuilder DSL (click to expand)</summary>

```swift
let adloadYara = """
    import "hash"
    import "macho"
    private rule Macho
    {
        meta:
            description = "private rule to match Mach-O binaries"
        condition:
            uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
    }
    private rule _plist
    {
        strings:
            $a1 = "<?xml"
            $a2 = "DOCTYPE plist"
            $b = "bplist"
        condition:
            ($a1 at 0 and $a2 in (0..100)) or $b at 0
    }
    rule XProtect_AdLoad_A : dropper
    {
        strings:
            $a1 = {73 65 74 4F 66 66 65 72 55 72 6C}
            $a2 = {73 65 74 4F 66 66 65 72 50 61 74 68}
            $a3 = {73 65 74 4F 66 66 65 72 4E 61 6D 65}
            $a4 = {2F 74 6D 70 2F 50 72 6F 64 75 63 74 2E 64 6D 67}
        condition:
            Macho and filesize < 40000 and (all of ($a*))
    }
    rule XProtect_AdLoad_B : dropper
    {
        strings:
            $a1 = {73 65 74 49 6E 73 74 61 6C 6C 46 69 6E 69 73 68 65 64 54 65 78 74}
            $a2 = {73 65 74 46 69 6E 69 73 68 54 69 63 6B 49 6D 61 67 65 56 69 65 77}
            $a3 = {4F 66 66 65 72 43 6F 6E 74 72 6F 6C 6C 65 72}
            $a4 = {26 4F 46 46 45 52 5F 49 44 3D 25 40}
        condition:
            Macho and filesize < 400000 and (all of ($a*))
    }
    rule XProtect_AdLoad_B_1 : dropper
    {
        strings:
            $a1 = {48 8B ?? ?? ?? ?? ?? 48 8D 5D B8 48 89 03 C7 43 08 00 00 00 C2 C7 43 0C 00 00 00 00 48 8D ?? ?? ?? ?? ?? 48 89 43 10 48 8D ?? ?? ?? ?? ?? 48 89 43 18 4C 89 F7 ?? ?? ?? ?? ?? ?? 48 89 43 20 4C 89 FF 48 89 DE ?? ?? ?? ?? ?? 4C 89 FF ?? ?? ?? 48 8B 7B 20 ?? ?? ??
    48 83 C4 30}
            $b1 = {67 65 74 53 61 66 61 72 69 56 65 72 73 69 6F 6E}
        condition:
            Macho and filesize < 300000 and $a1 and $b1
    }
    rule macos_adload_launcher
    {
      strings:
        $code = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $code2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $code3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $code4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $code5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $code6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $code7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $code8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $code9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $code10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $code11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $code12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $code13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $code14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $code15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $stringA = "Admin Success: %@"
        $stringB = "Error: %@"
        $stringC = "@@AppPath@@/Contents/MacOS"
        $stringD = "runApp"
      condition:
        Macho and filesize < 15MB and (any of ($code*)) and (any of ($string*))
    }
    rule macos_adload_main
    {
      strings:
        $code = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $code2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $code3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $code4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $code5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $code6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $code7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $code8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $code9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $code10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $code11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $code12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $code13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $code14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $code15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $stringA = "WebView"
        $stringB = "JSExport"
        $stringC = "_TransformProcessType"
      condition:
        Macho and filesize < 15MB and (any of ($code*)) and (any of ($string*))
    }
    rule macos_adload_agent
    {
      strings:
        $code = { (48 | 49) 63 ?? 41 32 ?? ?? (88 8D ?? ?? ?? ?? 48 | 48) ?? ?? 74 ?? 88 ?? 48 ?? ?? ?? eb ?? }
        $code2 = { 48 8b [2-5] 48 89 ?? 48 f7 d? 48 01 c? 44 88 ?? ?? 48 8b [2-5] 48 89 c? 48 f7 d? 48 03 [2-5] ( 44 88 | 88 0c ) [1-2] 4? 83 f? ?? }
        $code3 = { b1 ?? 41 be 01 00 00 00 4c 8d bd 7f ff ff ff 44 89 eb eb ?? }
        $code4 = { 41 ff c? 90 49 63 c? 48 ?? ?? ?? ?? ?? ?? ( 44 32 34 0a 48 39 d8 74 ?? | 32 0c 02 88 8d 7f ff ff ff 48 8b 45 88 48 3b 45 90 74 ?? ) }
        $code5 = { 90 0f 57 c0 4c 8d 65 80 41 0f 29 04 24 49 c7 44 24 }
        $code6 = { ff cb 90 48 63 c3 48 ?? ?? ?? ?? ?? ?? 32 0c 02 48 8b 85 78 ff ff ff 48 3b 45 80 74 ?? }
        $code7 = { 45 85 ?? 41 8d 4? ff b? ?? ?? ?? ?? 0f 4e c? 4? 8a ?? ?? b0 4? ff c? 4? 89 c6 }
        $code8 = { 44 8a 74 05 b0 48 ff c0 48 89 85 ( a0 fa | 38 f4 ) ff ff }
        $code9 = { 46 8a ?4 ?? b0 49 63 c5 48 ?? ?? ?? ?? ?? ?? 8a 04 08 88 85 ?8 f5 ff ff 4? 89 ?d ?8 fa ff ff 4? 89 ?d ?0 fa ff ff 48 83 a5 ?8 fa ff ff 00 4? 89 ?f 6a ?? 5e e8 ?? ?? ?? ?? 44 32 ?? ?8 f5 ff ff 44 88 ?5 ?0 f5 ff ff 48 8d bd ?? fa ff ff 48 8d b5 ?0 f5 ff ff e8 ?? ?? ?? ?? 4? 8? ?? 4? 8d ?5 }
        $code10 = { 90 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 44 89 ff e8 ?? ?? ?? ?? 48 89 df 48 8d b5 08 f6 ff ff e8 ?? ?? ?? ?? 48 8b 85 b0 fa ff ff 0f b6 78 10 e8 ?? ?? ?? ?? 90 48 89 df e8 ?? ?? ?? ?? 49 ff c? }
        $code11 = { 83 c2 fc 85 d2 6a ?? 58 0f 4e d0 4c 89 ef 48 89 de 6a ff 59 e8 ?? ?? ?? ?? 48 89 df e8 ?? ?? ?? ?? 4c 89 ef e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff 48 8d b5 98 f5 ff ff e8 ?? ?? ?? ?? 48 8d bd 78 fa ff ff e8 ?? ?? ?? ?? 49 ff c6 }
        $code12 = { 0F 57 C0 0F 29 45 B0 48 C7 45 ?? 00 00 00 00 41 BD ?? 00 00 00 41 B6 ?? 31 DB BF ?? 00 00 00 31 C0 41 BF ?? 00 00 00 EB ??45 85 FF 41 8D ?? ?? 41 0F 4E CD 44 0F B6 ?? ?? ?? ?? FF FF 48 8B 45 ?? 48 8B ?? ?? 48 FF C7 41 89 CF 90 90 49 63 CF 46 32 ?? ?? }
        $code13 = { 48 63 c3 48 ?? ?? ?? ?? ?? ?? 8a 04 08 42 32 44 2d b0 88 85 70 ff ff ff [2-6] f? 4c 89 e6 e8 ?? ?? ?? ?? 85 db 8d 43 ff 89 c3 ?? [0-4] 0f 4e d? 4c 89 ff 89 de e8 ?? ?? ?? ?? 4c 89 ff e8 ?? ?? ?? ?? 49 ff c5 }
        $code14 = { 85 db 41 0f 4e dc 42 8a 4c 2d b0 49 ff c5 }
        $code15 = { 49 63 c7 48 ?? ?? ?? ?? ?? ?? 8a 04 08 32 44 1d b0 88 85 70 ff ff ff 4c 89 f7 4c 89 ee e8 ?? ?? ?? ?? 45 85 ff 41 8d 47 ff 41 0f 4e c4 48 ff c3 41 89 c7 }
        $stringA = "WebView"
        $stringB = "JSExport"
      condition:
        Macho and filesize < 15MB and (any of ($code*)) and #stringA == 0 and #stringB == 0
    }
    rule macos_smolgolf_adload_dropper
    {
        strings:
            $varName = "main.DownloadURL"
            $libraryName = "github.com/denisbrodbeck/machineid.ID"
            $execCommand = "os/exec.Command"
        condition:
            Macho and all of them
    }
    rule macos_smolgolf_adload_dropper_mrt
    {
            strings:
            $string_1 = "net.isDomainName"
            $string_2 = "net.absDomainName"
            $string_3 = "_ioctl"
            $string_4 = "_getnameinfo"
            $string_5 = "_getaddrinfo"
            $string_6 = "_getattrlist"
            $string_7 = "net.equalASCIIName"
            $string_8 = "github.com/denisbrodbeck/machineid"
            $string_9 = "ioreglstatmkdirmonthpanic"
            $string_10 = "runtime.panicSliceB"
            $string_11 = "_getnameinfo"
            $string_12 = "cpuid"
            $string_13 = "url.UserPassword"
            $string_14 = "127.0.0.1:53"
            $string_15 = "syscall.Getsockname"
            $string_16 = "main.DownloadURL"
            $string_17 = "/etc/hosts"
            $string_18 = "/Library/LaunchDaemons/%s.plist"
            $string_19 = "/tmp0x%x"
        condition:
            Macho and filesize < 10MB and all of them
    }
    rule macos_gardna_agent
    {
        strings:
            $logString = "error executing commands"
            $binPathA = "/bin/cat"
            $binPathB = "/bin/bash"
            $swift5 = "__swift5_typeref"
        condition:
            filesize < 100KB and Macho and all of them
    }
    rule macos_gardna_agent_b
    {
        strings:
            $code = { 48 8d b5 58 ff ff ff e8 ?? ?? ?? ?? 49 89 c4 66 0f 6f 05 09 3e 00 00 f3 0f 7f 40 10 4c 8d 68 20 44 88 78 20 48 8d 58 21 48 8b 7d c8 e8 ?? ?? ?? ?? 4c 89 ef 48 89 de 4c 8d 6d 90 e8 ?? ?? ?? ?? 4c 89 e7 e8 ?? ?? ?? ?? 48 8b 5d 80 48 ff c3 70 ?? }
        condition:
            filesize < 200KB and Macho and $code
    }
    rule macos_magicplant_dropper
    {
        strings:
            $code = { 48 8d ?? ?? f? ff ff e8 ?? ?? ?? ?? eb ?? 48 8d ?? ?? f? ff ff e8 ?? ?? ?? ?? eb ?? 48 ?? ?? ?? ?? ?? ?? 48 89 85 b0 fe ff ff 48 8d bd b0 fe ff ff be 02 00 00 00 e8 ?? ?? ?? ?? eb ?? }
        condition:
            Macho and $code
    }
    rule macos_magicplant_dropper_function : adware
    {
        strings:
            $decode_routine = { 55 48 89 E5 41 57 41 56 53 48 83 EC 48 49 89 FE 48 8B 05 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8D 05 ?? ?? ?? ?? 48 89 45 A8 4C 8B 7D A8 48 C7 45 B0 00 00 00 00 48 8B 45 B0 48 83 F8 12 73 40 48 8B 75 B0 4C 89 FF E8 ?? ?? ?? ?? 0F B6 18 4C 89 FF 48 83 C7 12 48 8B 75 B0 E8 ?? ?? ?? ?? 0F B6 00 29 C3 88 5D BF 8A 45 BF 48 8B 4D B0 88 44 0D C0 48 8B 45 B0 48 83 C0 01 48 89 45 B0 EB B6 48 8D 75 C0 48 89 F2 48 83 C2 11 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 45 E0 48 8B 0D ?? ?? ?? ?? 48 8B 09 48 29 C1 75 02 EB 05 E8 ?? ?? ?? ?? 48 83 C4 48 5B 41 5E 41 5F 5D C3 }
        condition:
            Macho and $decode_routine and filesize < 250KB
    }
    rule macos_magicplant_dropper_obfuscated_function : adware
    {
        strings:
            $function = {
                A8 01 75 02 EB 21 C6 03
                01 48 8D 7D D8 BE 01 00
                00 00 ?? ?? ?? ?? ?? 48
                8B 45 D8 48 89 43 08 48
                89 DF ?? ?? ?? ?? ?? 48
                89 DF ?? ?? ?? ?? ?? A8
                01 75 02 EB 4E 48 8B 5B
                08 48 8B 75 D0 4C 8D 75
                80 4C 89 F7 ?? ?? ?? ??
                ?? 48 89 DF 4C 89 F6 ??
                ?? ?? ?? ?? [0-2] 48 89
                C3 [0-2] 48 8D 7D 80 ??
                ?? ?? ?? ??
            }
        condition:
            Macho and filesize < 250KB and $function
    }
    rule macos_adload_python_dropper
    {
        strings:
            $shebang = "#!"
            $iokit_1 = "IOKit"
            $iokit_2 = "IOServiceGetMatchingService"
            $iokit_3 = "IOServiceMatching"
            $iokit_4 = "IORegistryEntryCreateCFProperty"
            $iokit_5 = "IOPlatformExpertDevice"
            $method_1 = "rmtree"
            $method_2 = "load_source"
            $method_3 = "encryptText"
            $method_4 = "decryptText"
            $method_5 = "encryptList"
            $method_6 = "decryptList"
            $method_7 = "check_call"
            $method_8 = "endswith"
            $method_9 = "mac_ver"
            $string_1 = "chmod"
            $string_2 = "/dev/null"
            $string_3 = "key"
            $string_4 = "commands"
            $string_5 = "uuid"
            $string_6 = "machineID"
            $string_7 = "open"
            $string_8 = "sessionID"
            $string_9 = "appName"
            $string_10 = "curl"
            $string_11 = "/tmp"
            $string_12 = "unzip"
            $string_13 = "/Volumes"
            $string_14 = "--args"
        condition:
            $shebang at 0 and (4 of ($iokit_*)) and (7 of ($method_*)) and (10 of ($string_*))
    }
    rule macos_biter_dropper : adware
    {
        strings:
            $import1 = "\x00_chmod\x00"
            $import2 = "\x00___error\x00"
            //mov     esi, 1FFh
            //mov     rdi, rbx
            //call    _chmod
            //call    ___error
            //cmp     dword ptr [rax], 2
            //jnz     short loc_100001B63
            //cmp     dword ptr [rbx], 0FEEDFACFh
            $constant_bytes1 = { BE FF 01 00 00 48 ?? ?? E8 ?? 2B 00 00 E8 ?? ?? 00 00 83 38 02 75 ?? 81 ?? CF FA ED FE }
            //0x100001ED3
            //mov     edx, 1000h
            //xor     ecx, ecx        ; Logical Exclusive OR
            //mov     rdi, offset __mh_execute_header ; char *
            //lea     rsi, [rbp+var_30] ; Load Effective Address
            //call    _UChYXG9cVC     ; Call Procedure
            //mov     r14, [rbp+var_30]
            $constant_bytes2 = { BA 00 10 00 00 31 C9 48 BF 00 00 00 00 01 00 00 00 48 ?? ?? D0 E8 ?? ?? FF FF 4C 8B 75 }
            //xor     [rdi+rdx], al   ; Logical Exclusive OR
            //add     eax, 6
            //cmp     eax, 0FEh
            //cmovg   eax, ecx
            //inc     rdi
            //cmp     rsi, rdi
            $variable_bytes1 = { 30 ?? ?? 83 C0 ?? 3D FE 00 00 00 0F 4F C1 48 FF C7 48 39 FE 75 EA }
            //xor     byte ptr [rax+rcx], 66h
            //inc     rax
            //cmp     rsi, rax
            //jnz     short loc_100001DA1
            //mov     ebx, cs:dword_1000072EC
            //cmp     ebx, 8
            //jz      short loc_100001DC2
            //mov     cs:dword_1000072EC, 8
            $variable_bytes2 = { 80 ?? ?? ?? 48 FF C0 48 39 C6 75 ?? 8B ?? ?? ?? 00 00 83 ?? ?? }
            //mov     esi, 19h
            //mov     edx, 4D6D6F72h
            //call    ZzFRNiwpMydyR0E ; Call Procedure
            $variable_bytes3 = { BE 19 00 00 00 BA 72 6F 6D 4D E8 ?? FE FF FF }
        condition:
            Macho and filesize < 1MB and all of ($import*) and all of ($constant_bytes*) and any of ($variable_bytes*)
    }
    rule    macos_biter_second_stage : adware
    {
        strings:
            $import_1 = "_IORegistryEntryFromPath"
            $import_2 = "_kIOMasterPortDefault"
            $import_3 = "_DASessionCreate"
            $import_4 = "_DADiskCreateFromVolumePath"
            $import_5 = "_time"
            $import_6 = "_gethostuuid"
            $import_7 = "_getxattr"
            $import_8 = "_iconv"
            $string_1 = "failed malloc"
            $string_2 = ".cloudfront.net/"
            $string_3 = "s3.amazonaws.com/"
            $string_4 = "/Contents/MacOS/* && open -a \""
            $string_5 = "\" \"/Volumes/Player\""
            $string_6 = "An error occurred"
            $string_7 = "please close and try again"
            $string_8 = "cloudfront.net/sd/?c=yWRybQ==&u="
            $string_9 = "&s=$session_guid&o="
            $string_10 = "com.apple.metadata:kMDItemWhereFroms"
            $string_11 = "chmod 77"
            $string_12 = "/tmp/ins"
        condition:
            Macho and filesize < 500KB and 6 of ($import*) and 9 of ($string*)
    }
    rule macos_biter_b_dropper : adware
    {
        strings:
            $import_1 = "\x00_getsectiondata\x00"
            $import_2 = "\x00_pthread_getspecific\x00"
            $import_3 = "\x00_pthread_key_create\x00"
            $import_4 = "\x00_sigaction\x00"
            //mov     [rbp+var_70], rax
            //mov     edx, 59h ; 'Y'
            //mov     eax, 1
            //jmp     short loc_100001DDE ; Jump
            //align 10h
            //add     rax, 2          ; Add
            //mov     edx, ecx
            //cmp     rax, 1EBF5h     ; Compare Two Operands
            //jz      short loc_100001E10 ; Jump if Zero (ZF=1)
            //xor     [rax+r14-1], dl ; Logical Exclusive OR
            //add     edx, 17h        ; Add
            $bytes1 = { 48 89 ?? ?? BA ?? 00 00 00 B8 ?? 00 00 00 EB ?? 66 0F 1F ?? 00 00 00 00 00 48 83 C0 ?? 89 CA 48 ?? ?? ?? ?? 00 74 ?? 42 30 54 ?? ?? 83 C2 ?? }
        condition:
            Macho and filesize < 1MB and all of ($import*) and all of ($bytes*)
    }
    rule macos_biter_b_dropper_xprotect
    {
        strings:
            //_pthread_key_create._pthread_once._pthread_setspecific._sigaction._siglongjmp._sigset
            $a1 = { 70 74 68 72 65 61 64 5f 6b 65 79 5f 63 72 65 61 74 65 00 90 00 72 f8 01 15 40 5f 70 74 68 72 65 61 64 5f 6f 6e 63 65 00 90 00 72 80 02 15 40 5f 70 74 68 72 65 61 64 5f 73 65 74 73 70 65 63 69 66 69 63 00 90 00 72 88 02 15 40 5f 73 69 67 61 63 74 69 6f 6e 00 90 00 72 90 02 15 40 5f 73 69 67 6c 6f 6e 67 6a 6d 70 00 90 00 72 98 02 15 40 5f 73 69 67 73 65 74 6a 6d 70 }
            //<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
            $a2 = { 3c 6b 65 79 3e 63 6f 6d 2e 61 70 70 6c 65 2e 73 65 63 75 72 69 74 79 2e 63 73 2e 61 6c 6c 6f 77 2d 75 6e 73 69 67 6e 65 64 2d 65 78 65 63 75 74 61 62 6c 65 2d 6d 65 6d 6f 72 79 3c 2f 6b 65 79 3e }
            //_signal_handler
            $a3 = { 5f 73 69 67 6e 61 6c 5f 68 61 6e 64 6c 65 72 }
            //_try_catch_init
            $a4 = { 5f 74 72 79 5f 63 61 74 63 68 5f 69 6e 69 74 }
            //0x100001DD0 at f9615ce5f1038afd4e19d3e35643c98af1a2ee53d9bf45958c84e5a7c4529e62
            $a5 = { BA ?? 00 00 00 B8 01 00 00 00 EB ?? 66 0F 1F 84 00 ?? ?? 00 00 48 83 C0 02 89 CA 48 3D ?? ?? ?? ?? 74 ?? 42 30 54 30 ?? 83 C2 ?? 31 C9 BE 00 00 00 00 81 FA FE 00 00 00 7F ?? 89 D6 42 30 34 30 83 C6 ?? 81 FE FE 00 00 00 7F ?? 89 F1 EB ?? }
        condition:
            Macho and filesize < 500KB and all of them
    }
    rule macos_adload_downloader_dec2020_strings
    {
        strings:
            $method1 = "_TtC9Installer14ViewController"
            $method2 = "_TtC9Installer11AppDelegate"
            $import1 = "swift_getExistentialTypeMetadata"
            $import2 = "swift_getTypeContextDescriptor"
            $import3 = "swift_getObjCClassMetadata"
            $import4 = "objc_addLoadImageFunc"
        condition:
            Macho and filesize > 350KB and filesize < 3MB and all of them
    }
    rule macos_adload_d {
        strings:
            $string_1 = "@_inflateInit2_\x00"
            //"1.2.11.rb.r+b.integer.string.data.real.date.false.true.array.dict.key.plist.bplist00"
            $string_2 = { 312E322E313100776200726200722B6200696E746567657200737472696E670064617461007265616C00646174650066616C736500747275650061727261790064696374006B657900706C6973740062706C6973743030 }
            $string_3 = "_uuid_unparse\x00"
            $string_4 = "_IOServiceGetMatchingService\x00"
            $string_5 = "regex_error"
            $string_6 = "IOMACAddress"
            $string_7 = "IOPlatformSerialNumber"
            $string_8 = "IOEthernetInterface"
            $string_9 = "BerTagged"
        condition:
            Macho and filesize < 20MB and 8 of them
    }
    rule macos_adload_e {
        strings:
            $string_1 = "\x00_uuid_generate_random\x00"
            $string_2 = "\x00_system\x00"
            $string_3 = "\x00_syslog\x00"
            $string_4 = "\x00_SecKeyGenerateSymmetric\x00"
            $string_5 = "application/x-www-form-urlencoded"
            $string_6 = "berContents"
            $string_7 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            $string_8 = "BerTaggedData"
            $string_9 = "getSystemVer"
        condition:
            Macho and filesize < 500KB and all of them
    }
    rule macos_adload_f {
        strings:
            $string_1 = "main.copyFile"
            $string_2 = "main.createPlist"
            $string_3 = "syscall.Recvmsg"
            $string_4 = "syscall.SendmsgN"
            $string_5 = "_sysctl"
            $string_6 = "_ioctl"
            $string_7 = "_execve"
            $string_8 = "_getuid"
            $string_9 = "_recvmsg"
            $string_10 = "_sendmsg"
            $string_11 = "_getgrgid_r"
            $string_12 = "_getgrnam_r"
            $string_13 = "_getpwnam_r"
            $string_14 = "_getpwuid_r"
            $string_15 = "can't scan type: chrome-extension_corrupt"
            $string_16 = "ExtensionInstallForcelist"
            $string_17 = "cfprefsd"
            $string_18 = "killallpanic"
        condition:
            Macho and filesize < 5MB and all of them
    }
    rule macos_adload_search_daemon {
        strings:
            $string_1 = "_uuid_generate_random"
            $string_2 = "_uuid_unparse"
            $string_3 = "_sysctl"
            $string_4 = "_syslog"
            $string_5 = "_getxattr"
            $string_6 = "_getgrgid"
            $string_7 = "_getpwuid"
            $string_8 = "_SecTransformExecute"
            $string_9 = "_IOServiceMatching"
            $string_10 = "_IOServiceGetMatchingServices"
            $string_11 = "BerTagged"
            $string_12 = "berContent"
            $string_13 = "berLengthBytes"
            $string_14 = "IOPlatformUUID"
            $string_15 = "IOEthernetInterface"
            $string_16 = "IOPlatformSerialNumber"
        condition:
            Macho and filesize < 2MB and all of them
    }
    rule macos_adload_wwxf_objc
    {
        strings:
            $a1 = "ShellView"
            $a2 = "okEvt"
            $a3 = "closeEvt"
            $a4 = "cancelEvt"
            $a5 = "runModal:"
            $a6 = "Opt:"
            $a7 = "crabs:"
            $a8 = "Tmp:"
        condition:
            Macho and 3 of them and filesize < 200KB
    }
    rule macos_adload_c_dropper : adware
    {
        strings:
            $shebang = "#!"
            $string_1 = "mktemp -d /tmp"
            $string_2 = "head -n 1 | rev)"
            $string_3 = "U2FsdGVkX1"
            $string_4 = "-256-cbc"
            $string_5 = "killall Terminal "
        condition:
            $shebang at 0 and all of ($string_*)
    }
    rule macos_adload_shell_script_obfuscation
    {
        strings:
            $shebang = "#!/bin/bash"
            // This regex targets the definitions
            // G="a";F="c";Q="d";H="e";V="l";Z="m";X="n";T="o";J="p";K="s";
            $defs = /([A-Z]{1}\=\"[a-z]{1}\"\;){5,}/
            // This targets the substitution:
            // ${T}${J}${H}${X}${K}${K}${V}
            $subs = /(\$\{[A-Z]{1}\}){5,}/
        condition:
            $shebang at 0 and filesize < 100KB and all of them
    }
    rule macos_adload_fantacticmarch : dropper
    {
        strings:
            $kotlin_1 = "_krefs:kotlin"
            $kotlin_2 = "_kfun:kotlinx"
            $method_1 = "getVolumeInfo"
            $method_2 = "createProcess"
            $method_3 = "runCommand"
            $method_4 = "getDirectories"
            $method_5 = "writeBinary"
            $method_6 = "makeFileExecutable"
            $import_1 = "_gethostuuid"
            $import_2 = "_chmod"
            $strings_1 = "bash"
            $strings_2 = "volumes"
            $strings_3 = "executablePath"
        condition:
            Macho and filesize < 50000000 and all of ($kotlin*) and 4 of ($method*) and all of ($import*) and all of ($strings*)
    }
    rule macos_adload_d_xor_obfuscation
    {
        strings:
            $symbol1 = "_TransformProcessType"
                $symbol2 = "_inflateInit"
                $code1 = { 90 4? 63 c? 48 8? 0d ?? ?? 00 00 32 14 08 4c 39 fb }
                $code2 = { 49 63 c6 48 8d 0d ?? ?? 00 00 44 32 3c 08 90 48 8b 85 78 ff ff ff 48 3b 45 80 }
                $code3 = { ff cb [0-2] 48 63 c3 48 8b (15 | 0d) ?? ?? 00 (00 | 00 44) 32 ?? ?? 48 8b ?5 [1-4] 48 3b ?5 }
        condition:
            Macho and all of ($symbol*) and any of ($code*)
    }
    rule macos_adload_daemon_obfuscation
    {
        strings:
            $symbolA = "_CFHTTPMessageCreateRequest"
            $symbolB = "_CFHTTPMessageSetHeaderFieldValue"
            $symbolE = "basic_string"
            $codeA = { 8a 44 19 ff 8b 0c 19 44 01 e9 28 c8 88 45 d7 48 8b 4d a8 48 3b 4d b0 }
            // 100080c98  8a51ff             mov     dl, byte [rcx-0x1]
            // 100080c9b  8a18               mov     bl, byte [rax]
            // 100080c9d  8859ff             mov     byte [rcx-0x1], bl
            // 100080ca0  8810               mov     byte [rax], dl
            // 100080ca2  48ffc8             dec     rax
            // 100080ca5  4839c1             cmp     rcx, rax
            // 100080ca8  488d4901           lea     rcx, [rcx+0x1]
            // 100080cac  72ea               jb      0x100080c98
            $codeB = { 8a 51 ff
                       8a 18
                       88 59 ff
                       88 10
                       48 ff c8
                       48 39 c1
                       48 8d 49 01
                       72 ea }
        condition:
            Macho and (#codeA + #codeB) > 70 and all of ($symbol*)
    }
    rule macos_adload_nautilus_dropper
    {
        strings:
            $shebang = "#!"
            $string_1 = "mktemp -t"
            //tail -c
            $string_2 = {74 61 69 6c [1-2] 2d 63}
            //funzip -<PASSWORD> > $
            $string_3 = { 24 30 [1-3] 7c [1-3] 66 75 6e 7a 69 70 [1-3] 2d [5-9] [1-3] 3e [1-3] 24 }
            //chmod +x
            $string_4 = { 63 68 6d 6f 64 [1-3] 2b 78 }
            //killall Terminal
            $string_5 = { 6b 69 6c 6c 61 6c 6c [1-3] 54 65 72 6d 69 6e 61 6c }
            //ZIP header
            $string_6 = { 50 4b 03 04 14 }
        condition:
            filesize < 100KB and $shebang at 0 and all of ($string*)
    }
    rule macos_adload_nautilus_dropper_xprotect
    {
        strings:
            //#!
            $a1 = { 23 21 }
            //mktemp -t
            $b1 = { 6d 6b 74 65 6d 70 20 2d 74 }
            //tail -c
            $b2 = { 74 61 69 6c [1-2] 2d 63 }
            //funzip -<PASSWORD> > $
            $b3 = { 24 30 [1-3] 7c [1-3] 66 75 6e 7a 69 70 [1-3] 2d [5-9] [1-3] 3e [1-3] 24 }
            //chmod +x
            $b4 = { 63 68 6d 6f 64 [1-3] 2b 78 }
            //killall Terminal
            $b5 = { 6b 69 6c 6c 61 6c 6c [1-3] 54 65 72 6d 69 6e 61 6c }
            //ZIP header
            $b6 = { 50 4b 03 04 14 }
        condition:
            filesize < 100KB and $a1 at 0 and all of ($b*)
    }
    rule macos_adload_nautilus_installer: adware
    {
        strings:
            $decode_routine = { 55 48 89 E5 41 57 41 56 53 48 83 EC 48 49 89 FE 48 8B 05 ?? ?? ?? ?? 48 8B 00 48 89 45 E0 48 8D 05 ?? ?? ?? ?? 48 89 45 A8 4C 8B 7D A8 48 C7 45 B0 00 00 00 00 48 8B 45 B0 48 83 F8 12 73 40 48 8B 75 B0 4C 89 FF E8 ?? ?? ?? ?? 0F B6 18 4C 89 FF 48 83 C7 12 48 8B 75 B0 E8 ?? ?? ?? ?? 0F B6 00 29 C3 88 5D BF 8A 45 BF 48 8B 4D B0 88 44 0D C0 48 8B 45 B0 48 83 C0 01 48 89 45 B0 EB B6 48 8D 75 C0 48 89 F2 48 83 C2 11 4C 89 F7 E8 ?? ?? ?? ?? 48 8B 45 E0 48 8B 0D ?? ?? ?? ?? 48 8B 09 48 29 C1 75 02 EB 05 E8 ?? ?? ?? ?? 48 83 C4 48 5B 41 5E 41 5F 5D C3 }
        condition:
            Macho and $decode_routine and filesize < 250KB
    }
    rule macos_adload_nautilus_obfuscated_function : adware
    {
        strings:
            $function1 = { A8 01 75 02 EB 21 C6 03 01 48 8D 7D D8 BE 01 00 00 00 ?? ?? ?? ?? ?? 48 8B 45 D8 48 89 43 08 48 89 DF ?? ?? ?? ?? ?? 48 89 DF ?? ?? ?? ?? ?? A8 01 75 02 EB 4E 48 8B 5B 08 48 8B 75 D0 4C 8D 75 80 4C 89 F7 ?? ?? ?? ?? ?? 48 89 DF 4C 89 F6 ?? ?? ?? ?? ?? EB 00 48 89 C3 48 8D 7D 80 ?? ?? ?? ?? ?? }
        condition:
            Macho and filesize < 250KB and $function1
    }
    rule macos_adload_nautilus_xprotect
    {
        strings:
            // _getxattr
            $import_v1_1 = { 5f 67 65 74 78 61 74 74 72 }
            // _system
            $import_v1_2 = { 5f 73 79 73 74 65 6d }
            //_uuid_generate_random
            $import_v1_3 = { 5f 75 75 69 64 5f 67 65 6e 65 72 61 74 65 5f 72 61 6e 64 6f 6d }
            // _TransformProcessType
            $import_v2_1 = { 5f 54 72 61 6e 73 66 6f 72 6d 50 72 6f 63 65 73 73 54 79 70 65 }
            // _access._chmod._dlclose._dlopen._dlsym._fclose._feof._fflush._fgets._fopen._fread._free._fseek._fseeko._ftello._fwrite
            $import_v2_2 = { 5f 61 63 63 65 73 73 00 5f 63 68 6d 6f 64 00 5f 64 6c 63 6c 6f 73 65 00 5f 64 6c 6f 70 65 6e 00 5f 64 6c 73 79 6d 00 5f 66 63 6c 6f 73 65 00 5f 66 65 6f 66 00 5f 66 66 6c 75 73 68 00 5f 66 67 65 74 73 00 5f 66 6f 70 65 6e 00 5f 66 72 65 61 64 00 5f 66 72 65 65 00 5f 66 73 65 65 6b 00 5f 66 73 65 65 6b 6f 00 5f 66 74 65 6c 6c 6f 00 5f 66 77 72 69 74 65 00 5f 6b 43 46 41 6c 6c 6f 63 61 74 6f 72 }
            $string_1 = { A8 01 75 02 EB 21 C6 03 01 48 8D 7D D8 BE 01 00 00 00 ?? ?? ?? ?? ?? 48 8B 45 D8 48 89 43 08 48 89 DF ?? ?? ?? ?? ?? 48 89 DF ?? ?? ?? ?? ?? A8 01 75 02 EB 4E 48 8B 5B 08 48 8B 75 D0 4C 8D 75 80 4C 89 F7 ?? ?? ?? ?? ?? 48 89 DF 4C 89 F6 ?? ?? ?? ?? ?? EB 00 48 89 C3 48 8D 7D 80 ?? ?? ?? ?? ??  }
        condition:
            Macho and filesize < 250KB and (all of ($import_v1*) or all of ($import_v2*)) and $string_1
    }
    rule macos_adload_dropper_custom_upx
    {
        strings:
            $custom_upx_1 = "rgbTEXT"
            $custom_upx_2 = "!bgr"
        condition:
            Macho and filesize < 500KB and $custom_upx_1 in (0..1024) and $custom_upx_2 in (0..1024)
    }
    rule macos_adload_dropper_custom_upx_unpacked
    {
        strings:
            $string_1 = "s3.amazonaws.com"
            $string_2 = "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
            $string_3 = "select LSQuarantineAgentBundleIdentifier, LSQuarantineDataURLString from LSQuarantineEvent"
            $import_1 = "_$s10Foundation3URLV15fileURLWithPath"
            // sab/nib/
            // mov     rax, 7361622F6E69622Fh
            // mov     [rbx+20h], rax
            $bytes_1 = { 48 B8 2F 62 69 6E 2F 62 61 73 48 ?? ?? 20 }
            // 777 domhc
            // mov     rsi, 373720646F6D6863h
            // mov     rdx, 0EB00000000222037h
            $bytes_2 = { 48 BE 63 68 6D 6F 64 20 37 37 48 ?? 37 20 22 00 00 00 00 ?? }
            // hsab/nib/
            // mov     rdi, 7361622F6E69622Fh
            // mov     rsi, 0E900000000000068h
            $bytes_3 = { 48 BF 2F 62 69 6E 2F 62 61 73 48 ?? 68 00 00 00 00 00 00 ?? }
        condition:
            Macho and filesize < 500KB and all of them
    }
    rule macos_adload_macho_deobfuscation_code
    {
        strings:
            // code responsible for deobfuscating macho stored in __data
            $code = {
                42 30 4C 30 FF
                8D 51 29
                81 F9 D5 00 00 00
                41 0F 4F D4
                42 30 14 30
                8D 4A 29
                81 FA D5 00 00 00
                41 0F 4F CC
                48 83 C0 02
                48 3D 01 74 05 00
                75
            }
        condition:
            Macho and filesize < 600KB and $code
    }
    rule macos_adload_swift_dropper_strings
    {
        strings:
            $stringA = "_old_sa"
            $stringB = "_env_key"
            $objective_c = "@_objc_retain"
            $libz = "/libz.1.dylib"
        condition:
            Macho and filesize < 600KB and all of them
    }
    rule macos_adload_kotlin_agent
    {
        strings:
            $ioreg_cmd = "ioreg -rd1 -c IOPlatformExpertDevice | awk '/IOPlatformUUID/ { split($0, line, \"\\\"\"); printf(\"%s\", line[4]); }'" wide
            $kotlin = "_kfun:#main()"
        condition:
            Macho and all of them
    }
    rule macos_adload_gardna_c
    {
        strings:
            $bash = "/bin/bash"
            $cat = "/bin/cat"
            $swift = "_swift"
            $guardian = "guardian"
        condition:
            Macho and filesize < 100KB and all of them
    }
    rule macos_airplay_app
    {
        strings:
            $pathA = "com.activitymoniter.agent.plist"
            $pathB = "Library/Application Support/.amoniter"
            $cmdA = "sleep 5; rm -rf \"%@\""
            $cmdB = "/usr/bin/unzip"
            $cmdC = "/bin/sh"
        condition:
            Macho and filesize < 100KB and 1 of ($path*) and 2 of ($cmd*)
    }
    rule macos_magicplant_executable_in_const
    {
        strings:
            $segmentA = "__TEXT"
            $segmentB = "__PAGEZERO"
            $cpp_symbolA = "char_traits"
            $cpp_symbolB = "basic_string"
            $objc_symbolA = "_TransformProcessTyp" // Objective-C API for making application hidden; TransformProcessType(0);
            $objc_symbolB = "_CCCrypt"
        condition:
        // Match samples that contains "__TEXT" and "__PAGEZERO" (which indicated an embedded binary), certain C++ and Objective-C symbols in the "__const" section and "__TEXT" segment.
        Macho and filesize < 1MB and for any segment_index in (0 .. macho.number_of_segments - 1):
            (   for any section_index in (0 .. macho.segments[segment_index].nsects - 1):
                (
                    macho.segments[segment_index].sections[section_index].segname == "__TEXT" and
                    macho.segments[segment_index].sections[section_index].sectname == "__const" and
                    for all of them: (
                            $ in (
                                macho.segments[segment_index].sections[section_index].offset ..
                                macho.segments[segment_index].sections[section_index].offset + macho.segments[segment_index].sections[section_index].size
                            )
                    )
                )
            )
    }
    rule macos_toydrop_a {
        strings:
            // Looking for webView usage and an API used to invoke shell commands
            $webView = "webView:decidePolicyForNavigationAction:decisionHandler:"
            $nstask = "NSTask"
            $process = "_pclose\x00_popen"
            // Code that subtracts 0x6d1
            $codeA = { ( 19 | 17 ) 6d 1b ( d1 | 51 ) }
            $codeB = { 44 8d b4 08 25 f9 ff ff }
            // Code that negates a byte loaded from memory
            $codeD = { 89 16 40 38 e9 03 29 2a }
            $codeE = { 41 8a 14 0e f6 d2 88 14 08 }
            $codeF = { 5a 07 00 91 88 03 13 4a }
        condition:
            Macho and #webView > 1 and ($nstask or $process) and (1 of ($code*)) and filesize < 500KB
    }
    rule macos_toydrop_b {
        strings:
            $webview = "webview.New"
            $base64 = "encoding/base64.(*Encoding).DecodeString"
            // Code that xors a key against a byte loaded from a string
            $code = { (45 | 46) 0f b6 ( 2c | 24 ) ( 02 | 22 ) 45 31 ( ea | e1 ) }
        condition:
            Macho and all of them
    }
    rule macos_toydrop_a_obfuscation_code
    {
        strings:
            $codeA = {
                48 63 85 ?? ?? ?? ??
                8B 84 85 ?? ?? ?? ??
                88 85 ?? ?? ?? ??
                8A 85 ?? ?? ?? ??
                48 63 8D ?? ?? ?? ??
                88 84 0D ?? ?? ?? ??
                8B 85 ?? ?? ?? ??
                83 C0 01
                89 85 ?? ?? ?? ??
            }
            $codeB = {
                66 ( 41 0f | 0F ) ( 6F | 6f 44 ) ( 04 | 05 ) 0?
                66 0F 38 00 C1
                ( 66 41 0F 7E 45 ?? | 66 0F 7e 03 )
                ( 48 | 49 ) 83 C? 10
                ( 48 | 49 ) 83 C? 04
                ( 4? 81 F? | 48 3D ??) [3-4]
                75 ??
            }
        condition:
            Macho and any of them
    }
    rule macos_toydrop_a_agent_strings
    {
        strings:
            $stringA = "_GoKnuckles"
            $stringB = "_HearthI"
            $stringC = "_getNLS"
            $stringD = "_rrStr"
        condition:
            Macho and (2 of them)
    }
    rule macos_adload_dropper_cpp_function
    {
        strings:
            // 100003a6b  e8c0fe0000         call    _memchr
            // 100003a70  4885c0             test    rax, rax
            // 100003a73  7423               je      0x100003a98
            //
            // 100003a75  4889c3             mov     rbx, rax
            // 100003a78  4889c7             mov     rdi, rax
            // 100003a7b  4c89fe             mov     rsi, r15
            // 100003a7e  4c89e2             mov     rdx, r12
            // 100003a81  e8b0fe0000         call    _memcmp
            // 100003a86  85c0               test    eax, eax
            // 100003a88  7416               je      0x100003aa0
            //
            // 100003a8a  48ffc3             inc     rbx
            // 100003a8d  4c89f2             mov     rdx, r14
            // 100003a90  4829da             sub     rdx, rbx
            // 100003a93  4c39e2             cmp     rdx, r12
            // 100003a96  7dc5               jge     0x100003a5d
            $code = {
                    e8 c0 fe 00 00 48 85 c0
                    74 23 48 89 c3 48 89 c7
                    4c 89 fe 4c 89 e2 e8 b0
                    fe 00 00 85 c0 74 16 48
                    ff c3 4c 89 f2 48 29 da
                    4c 39 e2 7d c5
                }
        condition:
            Macho and $code
    }
    rule macos_smolgolf_adload_dropper_B
    {
        strings:
            $str1 = "_os/exec.init.0.func1"
            $str2 = "_net/http.http2h1ServerKeepAlivesDisabled"
            $str3 = "compareSearchAddrTo"
            $str4 = "obfuscatedTicketAge"
            $str5 = "(*ReqProxyConds).Do.func1"
            $str6 = "copyOrWarn"
        condition:
            Macho and all of them and filesize <7MB
    }
    rule macos_toydrop_pkg_null_padded_trailer : dropper
    {
        condition:
            100KB < filesize and filesize < 3MB
            and uint32be(0) == 0x78617221
            and uint32be(filesize-4) < filesize - 32 - 16 - 50
            and uint32be(filesize-4) > 0x30000
            and for all i in (1..32): (uint8(uint32be(filesize-4)-i) == 0x00)
            and for all i in (0..5): (uint16(uint32be(filesize-4)+ 32 + 16 + i*2) != 0x0000)
    }
    rule macos_adload_mitmproxy_goproxy : adware
    {
        strings:
            $mod_goproxy_func1 = "sendNoIntercept"
            $mod_goproxy_func2 = "generateCertificate"
            $main_func1 = "loadConfigFromArgs"
            $main_func2 = "sendPageVisit"
            $listen_port = ":8080"
            $str_goproxy_func1 = "ReqHostMatches"
            $str1 = "//search.yahoo/etc/protocols127"
            $str2 = "Repeat searchReset"
            $str3 = "v + / @ P [ \t%T%d%v(\") )()\n*."
        condition:
            Macho and any of ($mod_goproxy_func*) and any of ($main_func*) and $listen_port and 2 of ($str*) and filesize < 10MB
    }
    rule macos_adload_mitmproxy_goproxy_b {
        strings:
            $listen_port = ":8080"
            $mod_goproxy_func1 = "sendNoIntercept"
            $mod_goproxy_func2 = "generateCertificate"
            $main_func1 = "loadConfigFromArgs"
            $proxy = "/goproxy/proxy.go"
            $regex_apple = "apple.*avx512f"
            $regex_icloud = "icloud.*if-matchif-range"
            $regex_allgall = "^.*$allgallp"
        condition:
            Macho and 4 of them
    }
    rule macos_adload_mitmproxy_goproxy_c {
        strings:
            $mitm_always = ".AlwaysMitm"
            $mitm_connect = ".MitmConnect"
            $mitm_cooldown = ".cleanCooldown"
            $mitm_sendNoIntercept = ".sendNoIntercept"
            $regex_apple = "apple.*avx512f"
            $regex_icloud = "icloud.*if-matchif-range"
            $regex_allgall = "^.*$allgallp"
            $config_json = "configuration.json"
            $comms_pv = "p/v"
            $comms_MCExt_GP = "MCExt_GP"
        condition:
            Macho and
            any of ($mitm_*) and
            any of ($regex_*) and
            ($config_json or any of ($comms_*))
    }
    rule macos_adload_mitmproxy_pyinstaller
    {
        strings:
            $mitm = "mitmproxy"
            $str_pyz = "out00-PYZ.pyz"
            $str_MEI = "_MEIPASS"
            $str_pyi_tmpdir = "pyi-runtime-tmpdir"
            $str_partial1 = "gnoreEnvironmentFlag" fullword
            $str_partial2 = "ythonHome" fullword
        condition:
            Macho and all of them and #mitm > 150 and filesize < 20MB
    }
    rule macos_adload_search_daemon_qls
    {
        strings:
            // 100043640  b9bbb1b03c         mov     ecx, 0x3cb0b1bb
            // 100043645  49894d28           mov     qword [r13+0x28], rcx  {0x3cb0b1bb}
            // 100043649  49894550           mov     qword [r13+0x50], rax  {0x0}
            // 10004364d  49894548           mov     qword [r13+0x48], rax  {0x0}
            // 100043651  49894540           mov     qword [r13+0x40], rax  {0x0}
            // 100043655  49894538           mov     qword [r13+0x38], rax  {0x0}
            // 100043659  49894530           mov     qword [r13+0x30], rax  {0x0}
            // 10004365d  49894d58           mov     qword [r13+0x58], rcx  {0x3cb0b1bb}
            // 100043661  49898580000000     mov     qword [r13+0x80], rax  {0x0}
            // 100043668  49894578           mov     qword [r13+0x78], rax  {0x0}
            // 10004366c  49894570           mov     qword [r13+0x70], rax  {0x0}
            // 100043670  49894568           mov     qword [r13+0x68], rax  {0x0}
            // 100043674  49894560           mov     qword [r13+0x60], rax  {0x0}
            // 100043678  baa7abaa32         mov     edx, 0x32aaaba7
            $obf_code = {
                b9 ?? ?? ?? ?? 49 89 4d
                28 49 89 45 50 49 89 45
                48 49 89 45 40 49 89 45
                38 49 89 45 30 49 89 4d
                58 49 89 85 80 00 00 00
                49 89 45 78 49 89 45 70
                49 89 45 68 49 89 45 60
                ba ?? ?? ?? ??
            }
            // "raiseUnimplemented"
            $s_unique = { 72 61 69 73 65 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 }
        condition:
            Macho and filesize < 2MB and all of them
    }
    rule macos_adload_search_agent_qls_str
    {
        strings:
            $str_1 = "HOME="
            $str_2 = "Dispaly=:0"
            $str_3 = "_putenv"
            $str_unique = "raiseUnimplemented"
        condition:
            Macho and filesize < 1MB and all of them
    }
    rule macos_adload_search_agent_qls
    {
        strings:
            // 10002db05  b8bbb1b03c         mov     eax, 0x3cb0b1bb
            // 10002db0a  49894528           mov     qword [r13+0x28], rax  {0x3cb0b1bb}
            // 10002db0e  4983655000         and     qword [r13+0x50], 0x0
            // 10002db13  4983654800         and     qword [r13+0x48], 0x0
            // 10002db18  4983654000         and     qword [r13+0x40], 0x0
            // 10002db1d  4983653800         and     qword [r13+0x38], 0x0
            // 10002db22  4983653000         and     qword [r13+0x30], 0x0
            // 10002db27  49894558           mov     qword [r13+0x58], rax  {0x3cb0b1bb}
            // 10002db2b  4983a58000000000   and     qword [r13+0x80], 0x0
            // 10002db33  4983657800         and     qword [r13+0x78], 0x0
            // 10002db38  4983657000         and     qword [r13+0x70], 0x0
            // 10002db3d  4983656800         and     qword [r13+0x68], 0x0
            // 10002db42  4983656000         and     qword [r13+0x60], 0x0
            // 10002db47  b9a7abaa32         mov     ecx, 0x32aaaba7
            $obf_code = {
                b8 ?? ?? ?? ?? 49 89 45
                28 49 83 65 50 00 49 83
                65 48 00 49 83 65 40 00
                49 83 65 38 00 49 83 65
                30 00 49 89 45 58 49 83
                a5 80 00 00 00 00 49 83
                65 78 00 49 83 65 70 00
                49 83 65 68 00 49 83 65
                60 00 b9 ?? ?? ?? ??
            }
            // "raiseUnimplemented"
            $s_unique = { 72 61 69 73 65 55 6e 69 6d 70 6c 65 6d 65 6e 74 65 64 }
        condition:
            Macho and all of them and filesize < 500KB
    }
    rule macos_adload_search_qls_combo
    {
        strings:
            $string_1 = "_uuid_generate_random"
            $string_2 = "_uuid_unparse"
            $string_3 = "_sysctl"
            $string_4 = "_syslog"
            $string_5 = "_getgrgid"
            $string_6 = "_getpwuid"
            $string_7 = "_SecTransformExecute"
            $string_8 = "_IOServiceMatching"
            $string_9 = "_IOServiceGetMatchingService"
            $string_10 = "BerTagged"
            $string_11 = "berContent"
            $string_12 = "berLengthBytes"
            $string_13 = "IOPlatformUUID"
            $string_14 = "IOPlatformSerialNumber"
        condition:
            Macho and filesize < 2MB and all of them
    }
    rule macos_adload_golang {
        strings:
            $func_main = "_main.main" // Is GoLang
            $target_bundle = "/Library/Application Support/Google/Chrome/"
            $prefs_plist_extension_force = "ExtensionInstallForcelist"
            $prefs_plist_extension_url = "https://clients2.google.com/service/update2/crx"
            $command_killall = "killall"
            $command_cfprefs = "cfprefs"
            /* From 25bffeab797bc8c7558525b3f11e6a8c51ad0c746acf5ae2e39edf5d20813406
            0119e1ec      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1"
            0119e1ec      ".0.dtd\">\n"
            0119e1ec      "<plist version=\"1.0\">\n"
            0119e1ec      "\t<dict>\n"
            0119e1ec      "\t\t<key>ExtensionInstallForcelist</key>\n"
            0119e1ec      "\t\t<array>\n"
            0119e1ec      "\t\t\t<string>{{.ExtID}};https://clients2.google.com/service/update2/crx</string>\n"
            0119e1ec      "\t\t</array>\n"
            0119e1ec      "\t</dict>\n"
            0119e1ec      "</plist>\n", 0
            */
        condition:
            Macho and
            all of ($func_*) and
            all of ($command_*) and
            $target_bundle and
            all of ($prefs_plist_extension_*)
    }
    rule macos_adload_g_fragment {
        strings:
            $framgment_thing = "=?CLMNPS"
            $chrome_url = "https://clients2.google.com/service/update2/crx"
        condition:
            Macho and
            all of them
    }
    rule macos_adload_g_extension_plist {
        strings:
            $command = "ExtensionInstallForcelist"
            $chrome_url = "https://clients2.google.com/service/update2/crx"
            $prefs_plist_golang_pattern_dhelp = "{{.DHelp}}" fullword
            $prefs_plist_golang_pattern_extension_id = "{{.ExtID}}" fullword
            $prefs_plist_golang_pattern_chelp = "{{.CHelp}}" fullword
            $prefs_plist_golang_pattern_ehelp = "{{.EHelp}}"
        condition:
            Macho and
            $command and $chrome_url and any of ($prefs_plist_*)
    }
    rule macos_adload_g_bundle {
        strings:
            $func_main = "_main.main"
            $target_bundle = "/Library/Application Support/Google/Chrome/"
            $command_killall = "killall"
            $command_cfprefs = "cfprefs"
        condition:
            Macho and
            all of them
    }
    rule macos_adload_g_go_funcs {
        strings:
            $func_main = "_main.main" // Is GoLang
            $func_create_plist = "_main.createPlist" // This may not always be present
            $func_copy_file = "_main.copyFile" // This is not always present
        condition:
           Macho and
           all of them
    }
    rule macos_adload_g_chrome_constants {
        strings:
            $chrome_string_corrupt = "chrome-extension_corrupt"
            $chrome_string_local_storage = ".localstorageasync"
            $prefs_plist_extension_force = "ExtensionInstallForcelist"
        condition:
            Macho and
            all of them
    }
    rule macos_adload_calypso_obfuscation
    {
        strings:
            // 100003760  55                 push    rbp {__saved_rbp}
            // 100003761  4889e5             mov     rbp, rsp {__saved_rbp}
            // 100003764  4157               push    r15 {__saved_r15}
            // 100003766  4156               push    r14 {__saved_r14}
            // 100003768  4155               push    r13 {__saved_r13}
            // 10000376a  4154               push    r12 {__saved_r12}
            // 10000376c  53                 push    rbx {__saved_rbx}
            // 10000376d  50                 push    rax {var_38}
            // 10000376e  4989ff             mov     r15, rdi
            // 100003771  488b17             mov     rdx, qword [rdi]
            // 100003774  4c8b6708           mov     r12, qword [rdi+0x8]
            // 100003778  4929d4             sub     r12, rdx
            // 10000377b  4c89e0             mov     rax, r12
            // 10000377e  48ffc0             inc     rax
            // 100003781  0f88ac000000       js      0x100003833
            //
            // 100003787  498b5f10           mov     rbx, qword [r15+0x10]
            // 10000378b  4829d3             sub     rbx, rdx
            // 10000378e  48b9feffffffffff
mov     rcx, 0x3ffffffffffffffe
            // 100003798  4839cb             cmp     rbx, rcx
            // 10000379b  7716               ja      0x1000037b3
            //
            // 10000379d  4801db             add     rbx, rbx
            // 1000037a0  4839c3             cmp     rbx, rax
            // 1000037a3  480f42d8           cmovb   rbx, rax
            // 1000037a7  4885db             test    rbx, rbx
            // 1000037aa  7511               jne     0x1000037bd
            //
            // 1000037ac  31db               xor     ebx, ebx  {0x0}
            // 1000037ae  4531ed             xor     r13d, r13d  {0x0}
            // 1000037b1  eb21               jmp     0x1000037d4
            //
            // 1000037b3  48bbffffffffffff
mov     rbx, 0x7fffffffffffffff
            //
            // ...
            // 100003833  4c89ff             mov     rdi, r15
            $obf_code = {
                55 48 89 e5 41 57 41 56
                41 55 41 54 53 50 49 89
                ff 48 8b 17 4c 8b 67 08
                49 29 d4 4c 89 e0 48 ff
                c0 0f 88 ?? ?? ?? ?? 49
                8b 5f 10 48 29 d3 48 ??
                ?? ?? ?? ?? ?? ?? ?? ??
                48 39 cb 77 ?? 48 01 db
                48 39 c3 48 0f 42 d8 48
                85 db 75 ?? 31 db 45 31
                ed eb ?? 48 ?? ?? ?? ??
                ?? ?? ?? ?? ?? 48 89 df
                49 89 d6 49 89 f5 e8 ??
                ?? ?? ?? 4c 89 ee 4c 89
                f2 49 89 c5 4c 01 eb 8a
                06 4f 8d 74 25 01 41 88
                46 ff 4d 85 e4 7e ?? 4c
                89 ef 48 89 55 d0 48 8b
                75 d0 4c 89 e2 e8 ?? ??
                ?? ?? 48 8b 55 d0 4d 89
                2f 4d 89 77 08 49 89 5f
                10 48 85 d2 74 ?? 48 89
                d7 48 83 c4 08 5b 41 5c
                41 5d 41 5e 41 5f 5d e9
                ?? ?? ?? ?? 48 83 c4 08
                5b 41 5c 41 5d 41 5e 41
                5f 5d c3 4c 89 ff
            }
            // "VIDTEX_STR"
            $s_unique = { 56 49 44 54 45 58 5f 53 54 52 }
        condition:
            Macho and filesize < 5MB and all of them
    }
    rule macos_adload_websearchstride_strings
    {
        strings:
            $str_1 = "m_cursor - m_start >= 2"
            $str_2 = "fill_line_buffer"
            $str_3 = "BerTagged"
            $str_4 = "missing or wrong low surrogate"
        condition:
            Macho and all of them and filesize < 14MB
    }
    rule macos_adload_websearchstride_xor
    {
        strings:
            // 16834b04958e9295724c5522627f6b43e574688334a26922d9f806eb8db3ba7b
            // 100042394  320c18             xor     cl, byte [rax+rbx]
            // 100042397  888d9ff3ffff       mov     byte [rbp-0xc61 {var_c69}], cl
            // 10004239d  488b45b8           mov     rax, qword [rbp-0x48 {s_13}]
            // 1000423a1  483b45c0           cmp     rax, qword [rbp-0x40 {var_48_2}]
            // 1000423a5  7408               je      0x1000423af
            //
            // 1000423a7  8808               mov     byte [rax], cl
            // 1000423a9  48ff45b8           inc     qword [rbp-0x48 {s_13}]
            // 1000423ad  eb0b               jmp     0x1000423ba
            //
            // 1000423af  4c89ff             mov     rdi, r15 {s_4}
            // 1000423b2  4c89ee             mov     rsi, r13 {var_c69}
            // 1000423b5  e8c61afcff         call    sub_100003e80
            //
            // 1000423ba  4883fb0d           cmp     rbx, 0xd
            // 1000423be  75c4               jne     0x100042384
            // fd66a805358c9d3ccb43a5ff78f4b7a45dd8d6d9dbf087a1c9618cb938cfc352
            // 100041a65  320c18             xor     cl, byte [rax+rbx]
            // 100041a68  888d30f3ffff       mov     byte [rbp-0xcd0 {s}], cl
            // 100041a6e  488b8578f3ffff     mov     rax, qword [rbp-0xc88 {var_c90}]
            // 100041a75  483b8580f3ffff     cmp     rax, qword [rbp-0xc80 {var_c88_1}]
            // 100041a7c  740b               je      0x100041a89
            //
            // 100041a7e  8808               mov     byte [rax], cl
            // 100041a80  48ff8578f3ffff     inc     qword [rbp-0xc88 {var_c90}]
            // 100041a87  eb0b               jmp     0x100041a94
            //
            // 100041a89  4c89ff             mov     rdi, r15 {s_2}
            // 100041a8c  4c89f6             mov     rsi, r14 {s}
            // 100041a8f  e85c1dfcff         call    sub_1000037f0
            //
            // 100041a94  4883fb0f           cmp     rbx, 0xf
            // 100041a98  75bb               jne     0x100041a55
            $xor = {
                32 0c 18 88 8d ?? f3 ff
                ff 48 8b ?5 ?8 ?? ?? ??
                ?? ?? ?? 88 08 48 ff 45
                b8 eb ?? 4c 89 ff 4c 89
                ?? [0-1] e8 ?? ?? ?? ??
                48 ?? ?? ?? 75 ??
            }
        condition:
           Macho and all of them
    }
    rule macos_adload_pdfcreator
    {
        strings:
            // 10000195b  4632243b           xor     r12b, byte [rbx+r15]
            // 10000195f  488b4580           mov     rax, qword [rbp-0x80 {var_88}]
            // 100001963  488b4d88           mov     rcx, qword [rbp-0x78 {var_88+0x8}]
            // 100001967  4889ca             mov     rdx, rcx
            // 10000196a  48c1ea3e           shr     rdx, 0x3e
            // ...
            // 100001a20  4632643da0         xor     r12b, byte [rbp+r15-0x60 {var_68}]
            // 100001a25  488b4580           mov     rax, qword [rbp-0x80 {var_88}]
            // 100001a29  488b4d88           mov     rcx, qword [rbp-0x78 {var_88+0x8}]
            // 100001a2d  4889ca             mov     rdx, rcx
            // 100001a30  48c1ea3e           shr     rdx, 0x3e
            $code = { 46 32 ?4 3? [0-1] 48 8b 45 80 48 8b 4d 88 48 89 ca 48 c1 ea 3e }
            $s = "initWithBase64EncodedString:options:"
        condition:
            Macho and all of them
    }
    rule macos_adload_common_data {
        strings:
                $ = { 34 0c be 0f 00 7b 08 b6 }
                $ = { 0f 00 b5 01 08 ae 0f 00 }
                $ = { 90 02 10 ac 0f 00 bb 02 }
                $ = { 32 e3 0f 00 fc 02 10 aa }
                $ = { 0f 00 a7 03 16 dc 0f 00 }
                $ = { c0 03 10 a8 0f 00 eb 03 }
                $ = { 08 a6 0f 00 f6 03 10 a4 }
                $ = { 0f 00 a1 04 08 90 0f 00 }
                $ = { fd 04 08 de 0f 00 88 05 }
                $ = { 10 8e 0f 00 b3 05 08 8c }
                $ = { 0f 00 fb 05 08 de 0f 00 }
                $ = { 86 06 10 ea 0e 00 b1 06 }
                $ = { 16 da 0f 00 ca 06 10 e5 }
                $ = { 0e 00 f5 06 37 c6 0f 00 }
                $ = { af 07 10 e3 0e 00 da 07 }
                $ = { 08 e1 0e 00 b6 08 08 de }
                $ = { 0f 00 c1 08 10 8a 0f 00 }
                $ = { ec 08 61 f9 0f 00 dc 09 }
                $ = { 10 88 0f 00 87 0a 08 86 }
                $ = { 0f 00 9e 0a 10 de 0f 00 }
                $ = { b1 0b 49 e5 0f 00 9d 0c }
                $ = { 0f ec 0e 00 aa 0e 05 c6 }
        condition:
            Macho and 3 of them
    }
    rule xprotect_macos_adload_common_data {
        strings:
            $common_data = {34 0c be 0f 00 7b 08 b6}
        condition:
            Macho and all of them
    }
    rule macos_adload_format_strings {
        strings:
            $format_1 = "_Tt%cSs%zu%.*s%s"
            $format_2 = "_Tt%c%zu%.*s%zu%.*s%s"
            //$escapes = " \n\r\t\x0c\x0b"
            $escapes = {20 0a 0d 09 0c 0b}
            // Any of these
            $optional_path = ".app/Contents/MacOS/"
            $optional_zip_header = {504b03040a0000000000}
            $optional_deobfuscate_string_function = "DecompressString"
            $optional_lsgetapp = "LSGetApplicationForURL"
            $optional_uuid = "_uuid_generate_random"
        condition:
            Macho and
            all of ($format_*) and $escapes and
            any of ($optional_*) and
            filesize < 5MB
    }
    rule macos_adload_random_bytes {
        strings:
            $ = {240CA84A00F42505A64A00B2260CA54D00D72605A34D00EC260BA14A00F227059E4D008B290BC65000EA290BC85000B82A0C994D00E52A0CF44C00DC2D1AE84C00A42E0CC84C00DA2E0CAA4C00BF300C9E4C00F83013924C00C53108864C00863208FA4B00F032FF01914F00A5350EFC49009A361AD54B00B43613B74B00C73621994B008638168D4B00C3}
            $ = {3E46AC089C01AC0270C402C402D602D602D602447A465E3199020CBE0280026250EA063E8202CE0187014DA601060A1406484A0C20484A06464CBE04514D4C8606E2027F4C4D060A14484ABA013C4A20303020302A20303420303AA91C4D96048C01F801E002D802860192044CD001FE01334DD40220303C}
            $ = {220CB44A00FF241AAC4A00C7250C904A00FD250CF64900BE2725E04900962818DB4900DF280CE3470084290CE14700872A05DF4700C52A0CD64900EA2A05D14900FF2A0BDA4700852C05CC49009E2D0BC14F00FD2D0BC34F00CB2E0CC74900F82E0CC54900E1311AC34900A9320CC14900DF320CBF49}
            $ = {5400BD4405AC5600D6450BE55C00B5460BE75C0083470CA75600B0470C865600994A1AFE5500E14A0CE25500974B0CC85500E14C13C05500F44C27B45C009B4D249F5500BF4D249F5400E34D23855400864E23EB5300A94EB503D15300DE510F0000ED510CCC5300FB510CC753}
            $ = {5900C6210CF75800CD241AEF580095250CD35800CB250CB95800B02718B15800F9270CE454009E280CE25400A12905E05400DF290CA95800842A05A75800992A0BDB54009F2B05A25800B82C0BE15F00972D}
            $ = {4400B02F0CB84400A43118AF4400ED310CCF410098320CCD41009B3305CB4100E433059944008234059744009B340FC64100A535058D4400B7360FE84A009A370FEA4A00EC370C88440099380CE643}
            $ = {E13918844B00AA3A0CFA4900CF3A0CF84900D23B05F64900903C0CFF4A00B53C05FA4A00CA3C0BF14900D03D05F54A00E93E0BC25000C83F0BC4500096400CF0}
            $ = {3F0083070CB53B00B0070C943B00B70A1A8C3B00FF0A0CF03A00B50B0CD63A00A30D18CE3A00EC0D0CA43700910E0CA23700940F05A03700D20F0CC63A00F70F05C43A008C100B9B3700921105BF3A00AB120BAD3E008A130BAF3E00D8130CBA3A0085140C993A008017}
            $ = {240CF65600B5250CF45600F82618CA5600EB2718BF6000BB280CF75D00E02808F55D00D62908EC5D00972A08C76000B42A08C96000C82A0EEE5D00D12B13D16000EA2C13C06300D12D13C26300A72E0C996000DB2E0C9E60}
            $ = {310CD73700F7310CBD3700C2340BF84000F23411B8380083355E0000E1350CF43600EF350CEF3600FD350CEA36008B360CE5360099360CE03600A7360CDB3600B5360C}
            $ = {280C803700862905FE3600C4290CA83800E92905A63800FE290BF93600842B05A138009D2C0BD13B00FC2C0BD33B00CA2D0C9C3800F72D0CFB370080311AF337}
            $ = {4D4C8606E2027F4C4D060A14484ABA013C4A20303020302A20303420303AA91C4D96048C01F801E002D802860192044CD001FE01334DD40220303C42443C4244}
            $ = {6100E93D0BDB6700A33E0CF86100DF3E13DC6100F93E15BF6100E2410CB96A00F541088A5F008C4208ED5E00AB420AD35E00FE421892610083440C8D6100AD450BFB6600E7450C886100AA4613836100BD4615E46000A6490CCE5E00B94908AF5E00D04908925E00EF490AF85D00D54A0C9563009E4B08FE6400AE4B18CA6200B34C0CC56200DD4D0B9F6900974E0CC06200DA4E13A46200ED4E15876200D6510C896000E9}
            $ = {0000B35A0CF35D00C15A0CEE5D00CF5A0CE95D00DD5A0CE45D00EB5A0CDF5D00F95A0CDA5D00875B0CCE5E00955B0CD56B00A35B0CA76B00B15B0CD55D00BF5B0CCE5E00CD5B0CD05D00DB5B0CCB5D00EC5B0CA56A00FD5B05806700875C0C916600985C0C9B6600A95C0C966600BA5C05926500C45C059A6300CE5C0CC06200DF}
            $ = {842605B96A00B426058C6600E62625E76600902713E26600A32715C36600F7290CBB6A008A2A08C96500A12A08AC6500C02A0A926500932B13876600A62B15E86500FA2D0CB96A008D2E08D16300A42E08B46300C32E0A9A63009D2F05E76600C12F0FDA6400843013AE5F00B53031DA64}
            $ = {0574860924A40DEA02E0033C42B00236C4023C42C802607A30FA0138E40772F201D401D601800152C60DDA018A015AB0018604F602E602CA02C302797EBC039C01C2047E5A86018804DA022E36188A01}
            $ = {056A0B0D230BD22077103033DD11A701F00B2F12DE01F92CA20C58C904D504D703141222800ED60B9F14E70FDE063354103010300A0A0B323863B404D70300}
            $ = {3C32CA2DD72D8D6CDB925CD30659CA4905A5C1E06B452F8290CBCD812A6CD92812C3CE34974A70115818AC3F50EEE06184665759D2FB63CAE394C260D05FC8E556B2B4A31747250F1811F50EF161268DD487404AE72FD34FC87BD590CC18DDE7BB}
            $ = {3809A14000F4381380500087390C854000B63909904100843C3CDC4E00C03C16F44800D63C16D34800A13D0CCE4800C63E09954100E63E09B34100893F099A41009E3F09FB3F00A93F0CF63F00B73F0CF13F00C53F09EC3F00D03F0CEF4700DE3F0CE44100EA3F}
            $ = {B7DA17276B66812AB432E7D67540C63E8AF136A062BE92B438F74178B0EE444462E97AA564F90B86A6BFFBB4B97ACA9BD14F5C8F43E4CDD3C93C7D3B96803D9D2817DCE3E693EA5FB21DCAA63F84C8A78C83CE0B}
            $ = {B534271143F1E4CDEAE556DF49C37D646CDEFC777BE9B095635119DA76E2D379D86633D5B4B07A67E0B3907B89FB6AA16B06BBCF9A27DB864A8D9705A9CC308DE9A50A11CDC9902162C3177AA2}
            $ = {F9650E098C1BDFDBA3AFEE4CCAC2B147A7312E01831DAF7DC55C5DB757B3729D2267AB28828F9CBA7B7ED9599403A2BCDE5422D6BF901B147BCE68F961C0158238AB466A14}
            $ = {E5081DB0230387090CC4230398090CD82303B6091DEC2303D8090C802403E9090C942403870A1DA82403A90A0CBC2403BA0A0CD02403D80A1DE42403FA0A0CF824038B0B0C8C2503AB0B1DA02503CD0B0CB42503DE0B0CC82503FC0B1DDC25039E0C0CF02503AF0C0C842603CD0C1D982603EF0C0CAC2603800D0CC02603A00D1DD42603C20D0CE82603D30D0CFC2603E40D219027038A0E0CA427039B0E0CB82703AC0E21CC2703D20E0CE02703E30E0CF42703830F1D882803A50F0C9C2803B60F0CB02803C70F21C42803ED0F0CD82803FE0F0CEC2803A81029802903DB102194290381110CA8290392110CBC2903B2110FD02903C61121E42903EC110CF82903FD110C8C2A038E1213A02A03A61221B42A03CC120CC82A03DD120CDC2A03871329F02A03BA1321842B03E0130C982B03F1130CAC2B039B1429C02B03CE1421D42B03F4140CE82B0385150CFC2B0396150C902C03A7150CA42C03B8151AB82C03D71521CC2C03FD15EF01E02C03F1171AF42C03931F1DAC2103D33411F83403AD350CAF3603DC351AC33603F635C3}
            $ = {BF03B804D60205FC071FC80B03E608CB03E20B03B60C13AC0E03CE0C15BA0E03E80D16E20B03830E13E00E03870FAC03E20B03B81213AE1403D01215BC1403EA1316E20B03851413E21403891572E20B03801613A91603D0160FE20B03DF168401}
            // $ = "deEERPS2_JS5_EvEEDTcldsdeclsr3std3__1E7forwardIT0_Efp0_Efp_spclsr3std3__1E7forwardIT1_Efp1_EEEOT_OSB_DpOSC_"
            $ = {8D1FF6FFFF9090486385B4F6FFFF89C2FFC28995B4F6FFFF488BB5B8F6FFFF31D248F7F6488DBD98F6FFFF4889D6E8}
            $ = {B30D05BA1C00B80D180000D00D05C91C00D50D110000E60D2FD81C00950E340000C90E05961D00CE0E140000E20E0AA81D00EC0E150000810F05961D00860F110000970F05961D009C0F0D0000A90F05C31D00AE0F140000C20F05D51D00C70F180000DF0F05E41D00E40F1F}
            $ = {306030501050201020201040203020105020203030201040203050403040D007B003D003708004D0078004C003D003C003B003D003B003C003C003E03AA003C0}
            $ = {A51405BD2000AA141B0000C51418CC2000DD142B0000881505AB20008D15140000A1150AF02000AB15150000C01505AB2000C5150D0000D215058B2100D71514}
            $ = {8E0B1B861B00A90B330000DC0B05BC1B00E10B0D0000EE0B05CE1B00F30B0D0000800C2EDD1B00AE0C140000C20C18EC1B00DA0C2E0000880D05991C008D0D0D}
            $ = {24E0028004B003203030A0042030401030203020201010205030306030501050201020201040203020105020203030201040203050403040D007B003D0037080}
            $ = {A20E01FE0408930D03BA055DA20E019E0608F00C03DA064AA20E01AB0708CD0C03E70749A20E01B70808AA0C0381095DA20E01E50908870C03AF0A5DA20E01930B08E4}
            $ = {C1E83E88C188CA80EA0148897DF8488975F0884DEF8855EE740EEB008A45EF2C028845ED7421EB5448B8FFFFFFFFFFFFFF3F488B4DF04821C14889CFE8254B0000488945}
            $ = {000089C148FFC90F90C248898D60FEFFFF88955FFEFFFF0F801808000031C089C1488B9560FEFFFF4829D1400F90C648FFC9400F90C74883F9004088B55EFEFFFF}
            $ = {6E0025020000000400C0A6010000000000009034E001502030A01C50302080016080016010F01E5030503050900160505020102080012020D0195060101080054020E0025010409001403020200000000000}
            $ = {0050220002802200008024000190240000302500017025000440320000903200011033000390350001F035000250370001B0370000C03800013039000219010301190B040100}
            $ = {800970900420508017C008A006F00FA03050505050205090016070F013800160A00120E005B00380066010E0017080025030503090015050800150A001106010602010504050405050504050505050501010101010301020203030106010306000}
            $ = {70404883C60F4883E6F04889E74829F74889FC488BB560FFFFFF4C8B46F84D8B48404983C10F4983E1F04989E24D29CA4C89D44989E34D29CB4C89DC4C895DE84889E34C29CB4889DC48895DE04C8B8D68}
            $ = {C1E83E88C188CA80EA0148897DF8488975F0884DEF8855EE740EEB008A45EF2C028845ED741DEB4248B8FFFFFFFFFFFFFF3F488B4DF04821C14889CFE8DD0A00}
            $ = {00000036ab000000d341000000db1b000000de33000000258d000000dc1c000000d227000000de4100000090d0ffffffe958000000d8570000007cbc000000cc1400000034bc0000004585000000bb03000000b327000000d7170000001b}
        condition:
            Macho and any of them
    }
    rule macos_adload_c2_constants {
        strings:
            // This is the header from C2 communication
            $smc_header = "smc100"
            // List of escapes used in the C2
            //$escape_string = " \n\r\t\f\v"
            $escape_string = { 20 0a 0d 09 0c 0b 00 }
            // Arrow used in logging
            $arrow = "-> "
            // Parameter used in C2 request
            $m_parameter = "m="
        condition:
            Macho and (
                $smc_header and
                $escape_string and
                ($arrow or $m_parameter)
            )
    }
    rule macos_adload_search_daemon_b
    {
        strings:
            $string_1 = "fill_line_buffer"
            $string_2 = "setBerTagValue:"
            $string_3 = "m_cursor - m_start >= 2"
        condition:
            Macho and all of them and filesize < 2MB
    }
    rule macos_xprotect_adload_search_daemon_b_common
    {
        strings:
            $string_1 = {3A40BA7F03C03B16996C038E3C088A6C03D53C2CF27603A13E16FB6B03EF3E08EC6B03B63F25C57503FB4016DD6B03C94108CE6B0390422C987403B04330A16B03E34308B46A039F4508AF6A03A74547C078039346168F6903E14608806903A8472CB47003ED4819F16803BE4908E26803874A1FA06F03BF4B19D36803904C08C46803D74C25DA6D039C4E16B56803EA4E08A66803B14F25}
            $string_2 = {5B0AB5950303AB5C0AB3950303BC5D088BDA0203815E13EBE20203AC5E35DFF30203C9601ED3E20203E7600CBEE20203AB610AB9E20203E36215E1FA0203F86281020000F9640AED930303BB650AEB930303CC660886DA0203916713AEE20203BC6735A3F30203D9692196E20203FA690CFEE10203BE}
            $string_3 = {5B0BFD860103EB5B08C1820103A25C0CFD860103BF5C0CBB7803CB5C0C996403D75C1DF96303F45C0FE66303BF5D12936603F45F0FCB7E03AC600FE16305BB6016C56305FB610CA86C05A6620CC06303B7620CBB6303C8620CFA82}
            $string_4 = {03EC3A08894B03B13B13D54B03E73B35A84F03A93E13B24B03C83E14964B03EB3E13ED4A03A83F08E54A05B83F088E4B05DB3F07964D058C450AE84F03994508FF4C03A1450AEB4C03CD4518B54C}
        condition:
            Macho and all of them and filesize < 2MB
    }
    rule macos_adload_search_daemon_c
    {
        strings:
            $string_1 = "fill_line_buffer"
            $string_2 = "strequal"
            $string_3 = "m_cursor - m_start >= 2"
            $string_4 = "convert_buffer_utf"
            $string_5 = "kIOMasterPortDefault"
            $string_6 = "kMDItemWhereFroms"
        condition:
            Macho and all of them and filesize < 4MB
    }
    rule macos_xprotect_adload_search_daemon_c_common
    {
        strings:
            $string_1 = {0FB55700D3340F9C57008C350FA15A00B23560C05A00D1360FA15A00F736B102C05A00BE4339915400FE430CB45000B04432FB5300E9440CAF50009B4532E55300D4450CAA5000864632815300BF460CA55000F14632D25200AA470CA05000DC4732DA5000E3480F945000E449188F5000FC499D030000994D0C8A5000A74D0C855000B54D0C805000C34D0CFB4F00D14D0CF64F00DF4D0CF14F00ED4D0CEC4F00FB4D0CE74F00894E0CE24F00974E0CDD4F00A54E1A975500C14E1A925500DD4E1A8D5500F94E1A885500954F1A835500B44F1FD84F00B35508BD5501CC550CED5501D85508E55501E055980800}
            $string_2 = {0A0CE7B10103BB0A16C8B10103FD0A1AA9B10103970B0CF6AF0103930C47A9B20103B40D1AC4AF0103CE0D0C91AE0103B00E13E9B10103CE0E0CF9AD0103DA0E13E1AD0103AE129D01DBB80103FE14FD01F0B10103}
            $string_3 = {2F00FA211AB42F0094220C842E00A022C1090000E12B09E02D00EF2B09DB2D00FD2B09D62D008B2C09D12D00992C09CC2D00A72C09C72D00B52C09C22D00C02C09BD2D00CB2C17B13000E42C17923000FD2C09EA2D}
            $string_4 = {4640DC4C00C2460F0000D146088A4C00D946230000FC4613854C008F4713DF4B00F2479B02DC4C009C4A2B9A4C00CC4A43DC4C00944B1FDA4B00B84B0CE34C00}
            $string_5 = {2100E5080BAA1C00980908A11C00E80916CD2000870B0B981C00BA0B088F1C008A0C1ADE1F00AD0D0B861C00E00D08FD1B00B00E1AEF1E00FD0F08F41B00AD100BEB1B008011EA04A12300A5160EF21A00971713BF}
            $string_6 = {A94D0CF14F00B74D0CEC4F00C54D0CE74F00D34D0CE24F00E14D0CDD4F00EF4D0CD84F00FD4D0CD34F008B4E0CCE4F00994E0CC94F00A74E0CC44F00B54E1AA85500D14E1AA35500ED4E1A9E5500894F1A995500A54F1AF35400875508915501BC550CDD5501C85508D55501D055980800}
            $string_7 = {00FF9B6D015D2513F30A034D1AC50A03670CFB0803C9020FB80B03B10408A70803FA0543830B03EE0613B80B0384070CAC080390078901000099080CA70803A508E403}
            $string_8 = {B81313943C00CB131AB73B0084161AA13B009E160CC83900C4171AC93600DE170C983500C0180EB63900C41E1AFB3400DE1E0CCA3300C01F0EB63900CE1FBC02}
            $string_9 = {3D009E2B970F0000B53A09AA3D00C33A09A83D00D13A09A63D00DC3A09A43D00E73A09A23D00F23A09A03D00FD3A099E3D00883B099C3D00933B099A3D009E3B09983D00A93B09963D00B43B09943D00BF3B09923D00CA3B09903D00D53B17B83D00EE3B17B63D00873C17B43D00A03C17B23D00B93C17B03D00D23C}
        condition:
            Macho and 4 of them and filesize < 4MB
    }
    rule macos_adload_weird_plutil {
        strings:
            $weird_plutil = "================== PlUtil - runAppleScript error result: "
        condition:
            Macho and any of them
    }
    rule macos_adload_dylibs {
        strings:
            $dylib_pled = "@rpath/pled.dylib"
            $dylib_smsf = "@rpath/smsf.dylib"
            $dylib_asu = "@rpath/asu.dylib"
        condition:
            Macho and any of them
    }
"""

let pathPatterns = ["/Library/Application Support/", "/Library/ApplicationSupport/", ".mitmproxy", "/tmp/", "Install.command"]

AdloadRemediator {
    Service(tag: nil) {
        ServiceExecutable {
            FileMacho(true)
            FileNotarised(false)
            FileYara(YaraMatcher(adloadYara))
        }
    }
    .followUpRemediation(ProxyRemediation(reportOnly: false, hosts: ["localhost", "0.0.0.0", "::1", "127.0.0.1"], ports: [8080]))
    .onMatchCallbacks([func_0x00000001000901e0, func_0x00000001000901e0])

    for pathPattern in pathPatterns {
        Process {
            ProcessIsNotarised(false)
            ProcessMainExecutable {
                FilePath(.StringContains(pathPattern))
                FileYara(YaraMatcher(adloadYara))
            }
        }
    }
    
    // enumCrontabExecutables is a function that parses the crontab file and returns a list of registered executables
    // Note: function symbols of XProtectRemediatorAdload are stripped, so the function name does not express the actual function name
    for file in enumCrontabExecutables("~/.crontab") {
        File(path: file) {
            FileMacho(true)
            FileNotarised(false)
            FileYara(YaraMatcher(adloadYara))
        }
    }
}
```
</details>
