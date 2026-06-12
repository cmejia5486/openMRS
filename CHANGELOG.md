# Changelog

All notable changes to ChartLite are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.0.0] - 2026-03-08

### Added
- Voice-first clinical documentation with offline ASR (ONNX wav2vec2)
- On-device LLM extraction using Qwen 3.5 via llama.cpp (built from source)
- Hardware-aware model selection: 0.8B for <3GB RAM, 2B for 3+GB RAM
- Cloud LLM extraction via Claude API with automatic offline fallback
- Three-tier extraction fallback: Gemini Nano -> Qwen -> Claude -> Regex
- Hallucination guard: validates all ICD-10 and formulary codes against reference data
- Encrypted local database (Room + SQLCipher, AES-256)
- Encrypted SMS encounter sync (AES-256-GCM + PBKDF2)
- Clinical decision support: drug-allergy, drug-drug, dosage, vital alerts
- Insurance claim engine: ICD-10 to CPT/HCPCS mapping, E/M level scoring
- SOAP note generation from structured encounter data
- Multi-station clinic workflow: triage, consultation, pharmacy, billing
- Patient queue management across stations
- Facility analytics dashboard
- 8-character base28 patient IDs (KFMT-4WRN format)
- Bluetooth/WiFi Direct peer-to-peer sync
- South Africa market: 515 drugs (STG/EML), 300 ICD-10 codes, SAMA tariffs
- Ethiopia and Malawi country configurations ready
- Comprehensive test suite (344 unit tests)

### Security
- All credentials stored in EncryptedSharedPreferences (AES-256-GCM)
- On-device LLM inference by default (no data leaves device)
- Cloud extraction requires explicit user opt-in
- Auto-unload LLM from RAM after inference to prevent OOM
- Memory pressure handling via ComponentCallbacks2