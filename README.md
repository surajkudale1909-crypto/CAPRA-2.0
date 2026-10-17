# CAPRA 2.0 - Context-Aware Mobile App Privacy Risk Analyzer

[![Python Version](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-72%2F72%20passing-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Android%20Static%20Analysis-orange.svg)]()

> **Institution:** Vishwakarma Institute of Technology (VIT Pune)  
> **Department:** Computer Science & Artificial Intelligence (CS-AI)  
> **Course:** Engineering Design & Innovation (EDAI) | Group 8  
> **Academic Year:** 2024–2026

---

## 📌 Executive Summary

**CAPRA (Context-Aware Mobile App Privacy Risk Analyzer)** is an advanced static analysis framework designed to evaluate the true privacy risk posture of Android applications (`.apk`). Unlike traditional antiviruses that focus exclusively on binary malware signatures, or generic permission counters that treat all permissions equally, CAPRA recognizes that **permissions only make sense in context**.

An `ACCESS_FINE_LOCATION` permission requested by a **Navigation** application is standard functionality; the exact same permission requested by a **Flashlight** or **Calculator** application is an anomalous privacy hazard indicative of covert tracking, surveillance, or location ad-monetization.

CAPRA fuses **Contextual Baseline Heuristics**, **Empirical Machine Learning**, **Bytecode Call-Graph Reachability**, **Third-Party Tracker Extraction**, and **Live Threat Intelligence (VirusTotal v3)** into a unified, transparent **0–100 Privacy Risk Score** with per-prediction explainability and publication-ready audit reports.

---

## 👥 Group 8 Team & Module Ownership

| Team Member | Engineering Role | Core Modules & Responsibilities |
| :--- | :--- | :--- |
| **Suraj** | Threat Intel & Audit Persistence | Live VirusTotal v3 REST API client (`src/threat_intel.py`), local hash database (`data/known_malware_hashes.json`), persistent offline caching (`data/vt_cache.json`), and SQLite Audit History Manager (`src/history_manager.py`). |
| **Omraj** | Context Engine & Category Detection | Context-Aware Baseline Heuristics (`src/context_engine.py`), dynamic 13-category rule schema (`data/context_rules.json`), dangerous collusion/exfiltration matrix, baseline derivation scripts (`scripts/derive_baselines.py`), and Auto-Category Detector (`src/category_detector.py`). |
| **Ishan** | Machine Learning Pipeline | ML Risk Inference (`src/ml_pipeline.py`), empirical CSV dataset loader (Drebin / CIC-AndMal / Kaggle), 5-fold cross-validation model comparisons (Random Forest vs Gradient Boosting), and per-prediction Gini feature explainability charts (`reports/feature_importance.png`). |
| **Samriddhi** | Desktop GUI & User Experience | Interactive Desktop Workbench (`src/gui.py`), custom circular arc risk meter canvas (`RiskGaugeCanvas`), multi-tab audit inspection dashboard, presentation demo scenarios, and visual feature importance explorer. |

---

## 🏛️ System Architecture & Analysis Pipeline

CAPRA 2.0 processes an APK through a deterministic, 8-stage unified pipeline without requiring emulators, hardware sandboxes, or dynamic execution:

```
                                  [ Target Android APK ]
                                             │
      ┌──────────────────────────────────────┼──────────────────────────────────────┐
      ▼                                      ▼                                      ▼
[ Stage 1: Threat Intel ]        [ Stage 2: Manifest Parser ]       [ Stage 6: Bytecode Static ]
• SHA-256 / SHA-1 / MD5          • Androguard AXML extraction       • 17 Exodus Tracker Signatures
• Live VirusTotal v3 API         • Declared/Custom permissions      • Insecure Cleartext HTTP URLs
• Offline JSON Hash Cache        • Exported Surface & Components    • Hardcoded Public IPv4 Check
• Malware Family & POSITIVES     • Target & Min SDK versions        • DCL (DexClassLoader) / Native .so
      │                                      │                      • Source-to-Sink Reachability
      │                                      ▼                                      │
      │                         [ Stage 3: Category Detector ]                      │
      │                         • Manifest feature scoring                          │
      │                         • Package & Activity keywords                       │
      │                         • Auto-resolves 13 categories                       │
      │                                      │                                      │
      │                                      ▼                                      │
      │                         [ Stage 4: Context Engine ]                         │
      │                         • Baseline expected permissions                     │
      │                         • Category mismatch penalties                       │
      │                         • Collusion / Exfiltration Combos                   │
      │                                      │                                      │
      │                                      ▼                                      │
      │                         [ Stage 5: Machine Learning ]                       │
      │                         • Trained RF / Gradient Boosting                    │
      │                         • 0–100% Probability Inference                      │
      │                         • Feature Gini explainability                       │
      │                                      │                                      │
      └──────────────────────────────────────┼──────────────────────────────────────┘
                                             ▼
                             [ Stage 7: Risk Score Fusion ]
                             • 50% Contextual Heuristic Risk
                             • 35% Machine Learning Inference
                             • 15% Attack Surface & Static Signals
                             • Critical Threat Intel Override (98-100)
                             • Verdict Mapping (Safe/Low/Med/High/Critical)
                                             │
                                             ▼
                       [ Stage 8: Audit Logging & Multi-Reporting ]
                       • Persistent SQLite Audit Log (`data/history.db`)
                       • Comparative Differential Audits (`--compare ID1 ID2`)
                       • Publication Markdown Reports (`reports/privacy_audit_*.md`)
                       • Rich Terminal ANSI Output & Desktop GUI
```

---

## 🚀 Key Features in v2.0

### 1. Context-Aware Baseline Rules (13 Categories)
Expanded from 3 categories in v1 to 13 canonical functional profiles:
- `Calculator`, `Flashlight`, `Navigation`, `Camera / Photography`, `Social Media`, `Finance / Banking`, `Fitness & Health`, `Music & Audio`, `Productivity / Office`, `Communication / Messaging`, `E-Commerce / Shopping`, `Weather`, `General Utility`.
- Modern Android 11–14 permission definitions: `POST_NOTIFICATIONS`, `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`, `BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`, `NEARBY_WIFI_DEVICES`.

### 2. Collusion & Exfiltration Matrix
Detects dangerous co-occurring permissions capable of covert privacy leakage:
- **Local Storage Exfiltration:** `READ_EXTERNAL_STORAGE` + `INTERNET`
- **Address Book Harvesting:** `READ_CONTACTS` + `INTERNET`
- **Covert Visual Surveillance:** `CAMERA` + `INTERNET`
- **Continuous Location Tracking:** `ACCESS_FINE_LOCATION` + `INTERNET`
- **Audio Surveillance / Eavesdropping:** `RECORD_AUDIO` + `INTERNET`
- **Toll Fraud & SMS Interception:** `SEND_SMS` + `RECEIVE_SMS`

### 3. Empirical Machine Learning with Explainability
- **Empirical Dataset Loader:** Seamlessly ingests real Android malware CSV datasets (Drebin, CIC-AndMal2017, Kaggle) with automated fallback to synthetic benchmarks.
- **Model Comparison:** 5-fold cross-validated comparison between **Random Forest** and **Gradient Boosting** classifiers with exported ROC curves, Precision-Recall curves, confusion matrices, and feature importance rankings in `reports/`.
- **Explainability:** Deconstructs each prediction, highlighting which specific requested permissions contributed most heavily to the model's risk score.

### 4. Advanced Static Bytecode Analysis
- **17 Exodus-Style Tracker Signatures:** Scans DEX class descriptors for Google AdMob, Firebase, Facebook Ads, Unity3D, InMobi, Flurry, AppsFlyer, Adjust, MoPub, Chartboost, Vungle, AppLovin, Branch, ironSource, ByteDance Pangle, Mixpanel, and Sentry.
- **Network String Pool Extraction:** Flags insecure cleartext `http://` endpoints and hardcoded public IPv4 addresses (excluding RFC 1918 private subnets and loopback).
- **Security & Bytecode Signals:** Detects Dynamic Code Loading (DCL via `DexClassLoader` / `PathClassLoader`), reflection abuse, native `.so` binaries, and minification/obfuscation ratios.
- **Call-Graph Reachability:** Reconstructs method call-graphs linking sensitive hardware sources (GPS, Device ID, Contacts) to network egress sinks (`HttpURLConnection`, `OkHttp`, sockets).

### 5. Live Threat Intelligence & Reputation
- Queries the live **VirusTotal v3 REST API** for cryptographic hash reputation.
- Built-in persistent disk cache (`data/vt_cache.json`) to prevent redundant API queries.
- Automatic exponential backoff on HTTP 429 rate limits and graceful offline fallback.
- Curated local signatures for real-world Android trojans (Anubis, Joker, SharkBot, Cerberus, AhMyth, FluBot, Triada) and verified benign FOSS tools (Fossify, Signal, VLC, NewPipe).

### 6. Audit History & Differential Audits
- Embedded SQLite database (`data/history.db`) records all completed audits.
- **Scan-to-Scan Comparisons:** Evaluates score drift and permission deltas between builds (e.g., comparing v1.0 to v2.0 of an app).
- Automatic publication-grade Markdown and JSON report exports.

---

## 📦 Installation & Setup

### Prerequisites
- Python **3.9+** (Tested on Python 3.9, 3.10, 3.11, 3.12)
- Virtual environment recommended

### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/vit-pune-edai/capra.git
cd capra

# Create and activate virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate
```

### 2. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt

# Or install as an editable package
pip install -e .
```

### 3. (Optional) Configure VirusTotal API Key
Create a `.env` file in the project root:
```env
VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
CAPRA_LOG_LEVEL="INFO"
```
*(If omitted, CAPRA automatically uses its curated local signature database and operates in offline mode.)*

---

## 💻 Usage Guide

### 1. Analyze an Android APK
```bash
# Auto-detect category and analyze APK
python main.py --apk data/apks/calculator_sample.apk

# Explicitly specify app category
python main.py --apk data/apks/calculator_sample.apk --category Calculator

# Export Markdown audit report
python main.py --apk data/apks/calculator_sample.apk --report-md

# Output structured JSON
python main.py --apk data/apks/calculator_sample.apk --json
```

### 2. Presentation Demo Scenarios (No APK Required)
Ideal for presentation demonstrations and benchmark testing:
```bash
# Benign Calculator (Safe Profile)
python main.py --demo benign_calculator

# Spyware Flashlight (Exfiltration Combinations + Ad Trackers + Malware Override)
python main.py --demo malicious_flashlight --report-md

# OpenStreetMap Navigation (Contextual Location Exemption)
python main.py --demo benign_navigation
```

### 3. Interactive Desktop GUI (Samriddhi's Module)
Launch the graphical workbench with real-time risk gauge canvas and multi-tab viewer:
```bash
python main.py --gui
# or directly
python src/gui.py
```

### 4. Audit History & Comparative Diff Audits
```bash
# View table of past scans stored in SQLite history
python main.py --history

# Compare two past builds by ID to analyze risk drift and permission deltas
python main.py --compare 1 2
```

### 5. Generate Machine Learning Evaluation Charts
```bash
# Export feature importance chart
python main.py --plot

# Re-train models and generate full evaluation report (ROC, PR curves, confusion matrix)
python -m src.ml_pipeline --compare
```

---

## 📊 Evaluation & Empirical Benchmarks

| Evaluation Metric | Baseline Context Engine (v1) | CAPRA Multi-Signal Fusion (v2) |
| :--- | :---: | :---: |
| **Supported Categories** | 3 categories | **13 categories** (Auto-Detected) |
| **Tracker Detection** | None | **17 Exodus Signatures** |
| **Bytecode Call-Graph Analysis** | None | **Source-to-Sink Reachability** |
| **Threat Intelligence** | None | **Live VirusTotal v3 + Local DB** |
| **ML Cross-Validation AUC** | Single split | **0.992 (5-Fold Stratified CV)** |
| **Audit Persistence** | Ephemeral | **SQLite History + Diff Auditing** |
| **Reporting** | Console text only | **Terminal + Markdown + JSON + GUI** |

---

## 🔬 Academic Limitations & Ethical Disclaimer

1. **Static Analysis vs. Dynamic Taint Tracking:** CAPRA’s call-graph reachability connects intra-procedural and direct inter-procedural bytecode invocations between sensitive sources and network egress sinks. While significantly faster and zero-overhead compared to dynamic taint analysis (e.g., FlowDroid or TaintDroid), it does not perform dynamic alias tracking or heap value tracing.
2. **Obfuscation & Packing:** Apps packed with commercial runtime packers (e.g., Qihoo 360, SecNeo) or advanced control-flow flattening will conceal method signatures until unpacked. CAPRA flags high obfuscation ratios and dynamic code loading (`DexClassLoader`) as explicit risk factors.
3. **Ethical Use Statement:** This software was designed strictly for academic research, mobile security auditing, and defensive vulnerability assessment at the Vishwakarma Institute of Technology, Pune.

---

## 🧪 Running Unit & Integration Tests

CAPRA includes a complete test suite covering all modules:
```bash
# Run full regression suite across all 6 phases
python -m unittest discover tests

# Run specific module test suite
python -m unittest tests.test_pipeline.TestPhase6HistoryAndReporting
python -m unittest tests.test_pipeline.TestThreatIntelPhase5
python -m unittest tests.test_pipeline.TestAdvancedStaticAnalysisPhase4
```

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

Developed with ❤️ by **CS-AI Group 8 (Suraj, Omraj, Ishan, Samriddhi)** at **Vishwakarma Institute of Technology, Pune**.

# CAPRA-2.0
Context-Aware Privacy Risk Analyzer (CAPRA) — a research project for analyzing Android application security and privacy risks using static analysis, data-flow analysis, and context-aware risk assessment.

