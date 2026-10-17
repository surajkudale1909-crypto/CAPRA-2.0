# Test APK Repository (`data/apks/`)

This directory is designated for storing sample Android Application Packages (`.apk` files) used to benchmark and evaluate the **Context-Aware Mobile App Privacy Risk Analyzer**.

## Recommended Benchmark Categories & Samples

For the mid-semester evaluation, the team should collect 2–4 representative APKs across categories:

1. **Calculator Apps**:
   - *Benign baseline*: Open-source offline calculator (e.g., Simple Calculator from F-Droid).
   - *Over-privileged / Suspicious*: Calculator requesting `INTERNET`, `READ_EXTERNAL_STORAGE`, or `ACCESS_FINE_LOCATION`.
2. **Flashlight Apps**:
   - *Benign baseline*: Minimal torch app requesting only `CAMERA` / `FLASHLIGHT` / `WAKE_LOCK`.
   - *Adware / Data Harvester*: Flashlight requesting `READ_CONTACTS`, `READ_PHONE_STATE`, `ACCESS_FINE_LOCATION`, and `INTERNET`.
3. **Navigation / Map Apps**:
   - *Benign baseline*: OpenStreetMap / Organic Maps requesting `ACCESS_FINE_LOCATION` and `INTERNET` (contextually justified).
   - *Privacy-violating*: Map app requesting intrusive unneeded permissions like `READ_SMS` or `RECORD_AUDIO`.

## Recommended Sources for Benign / Real-World APKs
- **F-Droid**: https://f-droid.org (Open source, metadata-verified APKs)
- **APKMirror**: https://www.apkmirror.com (Direct from Google Play Store)
- **Android FOSS Samples**: GitHub open-source Android projects
