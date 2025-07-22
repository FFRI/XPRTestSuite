# Eicar

## About this scanning module

EICAR is a test file that is used to test antivirus software. XProtectRemediatorEicar is a scanning module that detects EICAR test files and removes them.

XProtectRemediatorEicar contains three plugin classes: `EicarPlugin`, `EicarBPlugin`, and `EicarBehaviorPlugin`. Each of these plugins is instantiated and executed sequentially at the entry point. (While XProtectRemediator modules typically define only a single plugin class per module, both XProtectRemediatorEicar and XProtectRemediatorTrovi are exceptions to this rule.)
Here, we focus on the detection logic implemented in the `EicarPlugin` class. The following detection logic is implemented with RemediationBuilder DSL in `EicarPlugin`:

```swift
// YARA rule is encrypted
let eicarYara = """
rule EICAR: Example Test {
    meta:
        name = "EICAR.A"
        version = 1337
        enabled = true
    strings:
        $eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"
    condition:
        $eicar_substring
}
"""

EicarRemediator {
    File(path: "/tmp/eicar") {
        MinFileSize(68)
        FileYara(YaraMatcher(eicarYara))
    }
}
```

After execution, the `/tmp/eicar` file will be removed.
