# BadGacha

## About this scanning module

XProtectRemediatorBadGacha has two types of detection logic as follows:

**1. Detection logic for processes without a backing file (removed at XPR version 135)**

This remediation logic identifies processes that do not have a corresponding backing file on disk. Such processes are flagged in report-only mode (reported to Apple), and no remediation actions are taken.

```swift
BadGachaRemediator {
    Process {
        ProcessHasBackingFile(false)
    }.reportOnly()
}
```

**2. Logic to detect background images that "guide" Gatekeeper bypass**

This remediation logic is designed to identify background images that may be used to trick users into disabling Gatekeeper and executing malware. This logic works as follows:

(1)	Enumeration of candidate background images:

Background images are extracted from currently mounted volumes that satisfy either of the following conditions:
- Image files located at the volume root with a filename prefix of .background.
- Image files located inside a directory named .background at the volume root

(2)	Text recognition:

Each candidate image is processed using [VNRecognizeTextRequest](https://developer.apple.com/documentation/vision/vnrecognizetextrequest) of Vision framework to extract any embedded text messages.

(3) Keyword-Based Detection:

The extracted text is scanned for specific keywords or character patterns associated with Gatekeeper bypass techniques. If such content is detected, an alert is raised. No remediation action is performed.

```
right-click
right click
option click
choose open
click open
press open
unidentified developer
are you sure you want
will always allow it
run on this mac
```

It’s important to note that **this logic is not triggered at the moment a DMG file is mounted.** Instead, it can only detect suspicious background image files during XProtectRemediator’s periodic scans.

## Samples detected by this scanning module

- [CrowdStrike Uncovers New MacOS Browser Hijacking Campaign](https://www.crowdstrike.com/blog/how-crowdstrike-uncovered-a-new-macos-browser-hijacking-campaign/)
- [Security Bite: Self-destructing macOS malware strain disguised as legitimate Mac app](https://9to5mac.com/2024/02/29/security-bite-self-destructing-macos-malware-strain-disguised-as-legitimate-mac-app/)
- [How AMOS macOS Stealer Avoids Detection](https://www.kandji.io/blog/amos-macos-stealer-analysis)
- [Malware: Cuckoo Behaves Like Cross Between Infostealer and Spyware](https://www.kandji.io/blog/malware-cuckoo-infostealer-spyware)
