# XProtect Remediator Test Suite

A collection of scripts and documents to help future XProtect Remediator (XPR) research, presented at [Black Hat USA 2025](https://blackhat.com/us-25/briefings/schedule/#xunprotect-reverse-engineering-macos-xprotect-remediator-44791)

## About This Repository

This repository contains:
- The scripts to create harmless minimal files and processes that reproduce the remediation of each scanning module of XPR
- The documents that describe the reverse-engineered XPR remediation (or detection) logic using the [RemediationBuilder DSL](https://github.com/FFRI/RemediationBuilderDSLSpec)

These scripts and documents were created for verification purposes of our reverse engineering of XPR. We hope that this repository will be useful for security researchers who conduct XPR analysis in the future and want to understand under what conditions remediation occurs.

**NOTE: Please run these scripts in a virtualized environment.**

## Preparation

To reveal `<private>` entries in the Unified Logs, follow the steps outlined in the article below.

[Unified Logs: How to Enable Private Data](https://www.jamf.com/blog/unified-logs-how-to-enable-private-data/)

## How to Use

Navigate to `cd TestSuite/<module_name>` and execute `./run.sh`.

```
cd TestSuite/Adload
./run.sh --test-case service
```

Some test cases require root privileges to run. However, they are basically designed to run with user privileges.

```
cd TestSuite/RedPine
sudo ./run.sh --test-case redpine
```

To reproduce XPR remediation/remediation, open a new terminal and run

```
/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect
```

or

```
/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediator<module_name> # (e.g., XProtectRemediatorAdload)
```

## Verified Versions

| Module Name | Verified Version(s) | Script | Document |
| --- | --- | --- | --- |
| Adload | 145 | ✅ | ✅ |
| BadGacha | 133, 145 | ✅ | ✅ |
| Bundlore | 149 | ✅ | ✅ |
| CardboardCutout | 145 |  | ✅ |
| ColdSnap | 145 | ✅ | ✅ |
| Eicar | 145 | ✅ | ✅ |
| KeySteal | 145 | ✅ | ✅ |
| Pirrit | 145 | ✅ | ✅ |
| RedPine | 141 | ✅ | ✅ |
| RoachFlight | 145 |  | ✅ |
| RankStank | 145 | ✅ | ✅ |
| SheepSwap | 145 | ✅ | ✅ |
| SnowDrift | 145 | ✅ | ✅ |
| WaterNet | 145 | ✅ | ✅ |

## Author

Koh M. Nakagawa (@tsunek0h) &copy; FFRI Security, Inc. 2025

## License

[Apache version 2.0](./LICENSE)
