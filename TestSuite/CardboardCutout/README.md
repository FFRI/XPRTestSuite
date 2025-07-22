# CardboardCutout

## About this scanning module

This scanning module implements the following remediation logic:

```swift
CardboardCutoutRemediator {
    Service(tag: nil) {
        ExecutableIsUntrusted(true)
        ExecutableRevoked(true)
    }
}
```

This logic detects registered services that meet the following conditions:

- The registered executable is untrusted.
    - This means that either the code identifier cannot be obtained, or the code's certificate array is empty.
    - Code signing information is retrieved using the `SecStaticCodeCreateWithPathAndAttributes` and `SecCodeCopySigningInformation` functions.
- The registered executable's Notarization ticket has been revoked.
    - This is determined by checking whether `CFErrorGetCode` after the `SecAssessmentTicketLookup` function call returns `EACCES`.
    - For more details, please refer to section "3 Code Signing" in [Patrick Wardle's The Art of Mac Malware Volume 2](https://nostarch.com/art-mac-malware-v2).

Based on this logic alone, it is unclear which malware family is being targeted. The logic appears to be generic and broadly applicable.

XProtectRemediatorCardboardCutout contains the following string as encrypted form, but we couldn't find any evidence that this string is used during the remediation process:

```
Hello Plugin Developer!
```