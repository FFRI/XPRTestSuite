# WaterNet

## About this scanning module

XProtectRemediatorWaterNet is a scanning module designed to detect WaterNet, a payload associated with the Adload malware.

This scanning module implements the following detection logic:

```swift
let waterNetYara = """
private rule Macho
{
    meta:
        description = "private rule to match Mach-O binaries"
    condition:
        uint32(0) == 0xfeedface or uint32(0) == 0xcefaedfe or uint32(0) == 0xfeedfacf or uint32(0) == 0xcffaedfe or uint32(0) == 0xcafebabe or uint32(0) == 0xbebafeca
}
rule macos_waternet
{
    strings:
        $stringA = "connectToProxyManager"
        $stringB = "connectToDestination"
        $stringC = "heartbeatSender"
        $stringD = "connectToCnc"
        $stringE = "proxit.com/peer"
        $stringF = "_client.com/utils/hostinfo."
        $stringG = "proxit_traffic"
        $stringH = /config.Build[A-Za-z]{3}Address/
    condition:
        Macho and 2 of them
}
rule macos_waternet_b
{
    strings:
        $stringA = "cnc.HeartbeatRequest"
        $stringB = "TrafficZsetName"
        $stringC = "proxit_traffic"
        $stringD = "_client/config.ProxyManagerTLS"
        $stringE = "github.com/wille/osutil.kernelVersion"
    condition:
        Macho and 2 of them
}
"""

WaterNetRemediator {
    File(searchDir: "~/Library/Application Support", regexp: "/(([a-zA-Z0-9]{19,40})|([a-zA-Z0-9]{39}/[a-zA-Z0-9]{39}))/(helper|main|m|h)$", searchDepth: 3) {
        FileYara(YaraMatcher(waterNetYara))
        MaxFileSize(constraint: 20971520)
    }
    File(searchDir: "~/Library/Application Support", regexp: "/(([a-zA-Z0-9]{7,18})|([a-zA-Z0-9]{41,})|([a-zA-Z0-9]{40,}/[a-zA-Z0-9]{40,}))/(helper|main|m|h)$", searchDepth: 3) {
        // emptyArray
    }.reportOnly()
}
```

## Samples detected by this scanning module

- [Mac systems turned into proxy exit nodes by AdLoad](https://cybersecurity.att.com/blogs/labs-research/mac-systems-turned-into-proxy-exit-nodes-by-adload)
