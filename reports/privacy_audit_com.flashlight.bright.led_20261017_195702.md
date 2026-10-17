# CAPRA 2.0 - Privacy Risk Audit Report
**Project:** Context-Aware Mobile App Privacy Risk Analyzer (CAPRA)  
**Institution:** Vishwakarma Institute of Technology, Pune (CS-AI Dept, Group 8)  
**Audit Timestamp:** `2026-10-17 14:27:02 UTC`  
---

## 1. Executive Summary

| Metric | Value |
| :--- | :--- |
| **Application Name** | **Super Bright LED Flashlight** |
| **Package Identifier** | `com.flashlight.bright.led` |
| **Risk Verdict** | **🔴 CRITICAL RISK** |
| **Composite Privacy Risk Score** | **`98 / 100`** |
| **Raw Penalty Points** | `251` pts (Ceiling: 160) |
| **Functional Category** | `Flashlight` (Utility application intended to toggle the camera flash or screen illumination.) |

### Composite Risk Score Attribution

| Component | Weight | Raw Risk % | Contribution |
| :--- | :---: | :---: | :---: |
| **Contextual Heuristics** (Omraj) | 50% | 100% | +50.0 pts |
| **Machine Learning** (Ishan) | 35% | 0% | +0.0 pts |
| **Attack Surface & Static** (Suraj) | 15% | 66.7% | +10.0 pts |
| **Threat Intel Critical Override** | Override | 100% | **Normalized to High/Critical** |

## 2. Application Identity & Cryptographic Hashes

- **File Path:** `synthetic://demo/malicious_flashlight.apk`
- **Version:** 1.0.0-demo (Code: `1`)
- **API Targets:** Target SDK `29` | Min SDK `21`
- **Components Registered:** 2 Activities, 1 Services, 1 Receivers, 0 Providers
- **Exported Attack Surface:** `3` total exported (`2` unprotected)
- **SHA-256:** `b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01`
- **SHA-1:** `N/A`
- **MD5:** `N/A`

## 3. Threat Intelligence & Reputation (Suraj's Module)

- **Threat Status:** `MALICIOUS` [VIRUSTOTAL_API]
- **Reputation Summary:** Flagged Adware / Data Exfiltration Signature
- **VirusTotal Live Detection:** **48 / 65** security vendors flagged this hash
- **Suggested Threat Label:** `Trojan.AndroidOS.Joker`
- **VirusTotal Analysis URL:** [https://www.virustotal.com/gui/file/b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01](https://www.virustotal.com/gui/file/b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01)
- **Malware Family:** `Joker (Bread)` (Billing Fraud / Toll Adware)
- **Severity:** `High`

## 4. Contextual Permission Evaluation (Omraj's Module)

**Baseline Evaluation against Category: `Flashlight`**

### ⚠️ Suspicious Permissions / Category Mismatches

| Permission | Penalty | Risk Rationale |
| :--- | :---: | :--- |
| `INTERNET` | +20 pts | A torch app should operate purely locally without outbound internet transmission. |
| `ACCESS_FINE_LOCATION` | +35 pts | Fine GPS location is entirely unrelated to torch functionality; classic sign of location ad-monetization. |
| `READ_CONTACTS` | +40 pts | Accessing user contact records is malicious/excessive for a flashlight. |
| `READ_EXTERNAL_STORAGE` | +25 pts | Reading files from external shared memory is unnecessary for torch operation. |

### 🚨 Dangerous Permission Combinations (Collusion / Exfiltration)

- **Local Storage Exfiltration Risk** (`Data Exfiltration`, +30 pts)
  - **Co-occurring Permissions:** `INTERNET + READ_EXTERNAL_STORAGE`
  - **Security Impact:** App can read arbitrary private files, documents, or photos from storage and transmit them to external internet servers.
- **Address Book Harvesting Risk** (`Data Exfiltration`, +35 pts)
  - **Co-occurring Permissions:** `INTERNET + READ_CONTACTS`
  - **Security Impact:** App can read full contact names, emails, phone numbers, and exfiltrate the user's social graph over the network.
- **Covert Visual Surveillance Risk** (`Visual Surveillance`, +35 pts)
  - **Co-occurring Permissions:** `CAMERA + INTERNET`
  - **Security Impact:** Ability to capture camera frames combined with internet transmission allows unauthorized image/video streaming.
- **Continuous Location Exfiltration Risk** (`Geolocation Tracking`, +25 pts)
  - **Co-occurring Permissions:** `ACCESS_FINE_LOCATION + INTERNET`
  - **Security Impact:** High-precision GPS coordinates can be streamed to cloud analytics or third-party ad brokers to establish physical movement patterns.

### Standard Expected Baseline Permissions (3)

`CAMERA`, `FLASHLIGHT`, `WAKE_LOCK`

## 5. Machine Learning Permission Risk Estimation (Ishan's Module)

- **Trained Model:** `GradientBoosting` (EMPIRICAL (sample_android_malware_dataset.csv))
- **Inference Risk Probability:** **`0.0%`** (`Benign Profile`)

### Active Permission Feature Attribution

| Permission Feature | Gini Importance | Relative Contribution |
| :--- | :---: | :---: |
| `CAMERA` | 0.0000 | +0.0% |
| `WAKE_LOCK` | 0.0000 | +0.0% |
| `INTERNET` | 0.0000 | +0.0% |
| `ACCESS_FINE_LOCATION` | 0.0000 | +0.0% |
| `READ_CONTACTS` | 0.0000 | +0.0% |


## 6. Advanced Static Analysis & Attack Surface (Suraj & Omraj)

### Embedded Third-Party Trackers (4 Detected)

| Tracker Name | Category | Signature Namespace |
| :--- | :--- | :--- |
| **Google AdMob** | Advertising | `None` |
| **InMobi** | Advertising | `None` |
| **Flurry** | Analytics | `None` |
| **Unity3D Ads** | Advertising | `None` |

### Network Surface & String Pool Inspection

- **Total URLs Extracted:** `8`
- **Cleartext Insecure HTTP Endpoints:** `3`
- **Hardcoded Public IPs:** `198.51.100.42`
  - ⚠️ Identified 3 cleartext HTTP endpoint(s), exposing user traffic to MitM interception.
  - ⚠️ Hardcoded public IP addresses detected (198.51.100.42), bypassing domain name verification.

### Bytecode Security Signals

- ⚠️ Dynamic Code Loading (DCL) detected (dalvik/system/DexClassLoader). May execute uninspected external payloads.

### 🚨 Privacy Egress Reachability Pathways

Identified `2` source-to-sink reachability pathway(s) connecting sensitive device hardware or telemetry to network egress sinks.


## 7. Key Findings & Actionable Recommendations

### Primary Risk Findings
- CRITICAL THREAT (VirusTotal): 48/65 AV engines flagged sample as 'Joker (Bread)'. (Permalink: https://www.virustotal.com/gui/file/b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01)
- Requested 4 suspicious permission(s) anomalous for Flashlight: INTERNET, ACCESS_FINE_LOCATION, READ_CONTACTS, READ_EXTERNAL_STORAGE.
- Exfiltration Hazard: Local Storage Exfiltration Risk - App can read arbitrary private files, documents, or photos from storage and transmit them to external internet servers.
- Exfiltration Hazard: Address Book Harvesting Risk - App can read full contact names, emails, phone numbers, and exfiltrate the user's social graph over the network.
- Exfiltration Hazard: Covert Visual Surveillance Risk - Ability to capture camera frames combined with internet transmission allows unauthorized image/video streaming.
- Exfiltration Hazard: Continuous Location Exfiltration Risk - High-precision GPS coordinates can be streamed to cloud analytics or third-party ad brokers to establish physical movement patterns.
- Attack Surface Exposure: 2 exported component(s) have no permission guards.
- Third-Party Trackers: Detected 4 tracking/ad SDK(s) (Google AdMob, InMobi, Flurry...).
- Network Exposure: Identified 3 cleartext HTTP endpoint(s), exposing user traffic to MitM interception.
- Network Exposure: Hardcoded public IP addresses detected (198.51.100.42), bypassing domain name verification.
- Security Configuration: Dynamic Code Loading (DCL) detected (dalvik/system/DexClassLoader). May execute uninspected external payloads.
- Reachability & Taint: Identified 2 potential data exfiltration path(s) bridging sensitive sources to network egress sinks.
- Reachability & Taint: Direct intra-procedural leakage detected: same method queries sensitive device data and transmits via network.

### Actionable Hardening Recommendations
1. CRITICAL: Immediate quarantine required. Known malware hash signature detected.
1. Isolate device from network and check for unauthorized data exfiltration.

---
*Generated by CAPRA v2.0 (Context-Aware Mobile App Privacy Risk Analyzer) | VIT Pune CS-AI Group 8*