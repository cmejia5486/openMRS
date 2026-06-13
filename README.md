# ChartLite

Voice-first clinical documentation for primary healthcare. Record patient encounters by voice, get structured clinical data automatically, and work fully offline on low-cost Android devices.

Built for sub-Saharan Africa first, expanding globally.

## Features

- **Voice-to-Clinical Data** - Record encounters, get ICD-10 diagnoses, medications, vitals, and follow-up plans extracted automatically
- **Ambient Scribing** - Capture full patient-doctor conversations and generate formatted clinical summaries with markdown rendering
- **Omnilingual Offline ASR** - Meta Omnilingual ASR (1600+ languages) runs on-device via ONNX Runtime. Supports Zulu, Xhosa, Amharic, Chichewa, and all other target languages offline. 300M model (365 MB) for low-end devices, 1B model (1 GB) for higher accuracy
- **On-Device LLM Extraction** - Qwen 3.5 runs entirely on-device via llama.cpp (built from source) with flash attention, Q8 KV cache, and on-device RAG retrieval; no internet required
- **Smart Context Retrieval** - TF-IDF vector store indexes 300 ICD-10 codes and 515 formulary drugs, retrieves only relevant entries per transcript (80% context reduction)
- **Battery-Aware Batched Inference** - Extraction queue processes multiple patient transcripts in a single model load; urgent cases (referrals/emergencies) bypass the queue for immediate processing
- **Selectable Clinical Extraction** - Qwen 3.5 on-device or a selected Claude, OpenAI, or Gemini cloud model, with Regex fallback when model extraction is unavailable
- **Offline-First Architecture** - SQLCipher-encrypted local database, works without any network connection
- **SMS as Portable Health Record** - V4 binary encoding (92 bytes, 1 SMS) carries the current visit plus accumulated health history: chronic conditions, abnormal vitals, allergies, growth metrics, immunization records, and clinical status flags (HIV, TB, pregnancy, malaria, etc.). AES-256-GCM encrypted with optional PIN for shared-phone privacy
- **Insurance Claims** - ICD-10 to CPT/HCPCS mapping, E/M level scoring (2021 MDM guidelines), SOAP note generation, PDF export
- **Clinical Decision Support** - Drug-allergy checks, drug-drug interactions, dosage validation, vital sign alerts
- **Multi-Station Workflow** - Reception, triage, consultation, pharmacy, and billing stations with patient queue management and role-based routing
- **Facility Directory & Referrals** - Searchable facility directory with filtering by type, service, and province; integrated referral generation with urgency levels
- **Peer-to-Peer Sync** - Same-facility bulk sync and cross-facility patient-scoped sync via Bluetooth/WiFi Direct, with automatic PIN stripping for privacy
- **Growth Charts & Immunizations** - Pediatric growth tracking with WHO z-scores, immunization history, encoded in SMS health records
- **Multi-Country Support** - South Africa (active), Ethiopia, Malawi (ready), Kenya, Nigeria, US, UK, India (planned)

## Architecture

ChartLite is organized into 8 modules:

| Module | Directory | Purpose |
|--------|-----------|---------|
| ASR | `asr/` | Meta Omnilingual ASR (1600+ langs, ONNX CTC) + cloud fallback (Gemini, OpenAI, Deepgram) |
| Clinical Extraction | `extraction/` | Qwen (on-device RAG) or a selected Claude/OpenAI/Gemini cloud model, plus Regex fallback |
| Local Database | `database/` | Room + SQLCipher encrypted schema (17 entities, v15), FHIR R4 export on-demand |
| SMS Health Record | `sms/` | V4 binary encode (92 bytes) with health history, growth, immunization + AES-256-GCM |
| Clinical Decision Support | `cdss/` | Drug-allergy, drug-drug, dosage, vital alerts |
| Patient ID | `patientid/` | 8-character base28 IDs (e.g., KFMT-4WRN) |
| Billing | `billing/` | ICD-10 &rarr; CPT engine, SOAP notes, PDF export, SAMA tariffs |
| Sync | `sync/` | Bluetooth/WiFi P2P + cross-facility sync + 3-tier connectivity |

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed design documentation.

## Requirements

- Android 8.0+ (SDK 26)
- 3 GB RAM minimum (4 GB recommended for larger models)
- ~365 MB storage for ASR model (Omnilingual 300M int8) + ~533 MB for on-device LLM (Qwen 3.5 0.8B Q4_K_M)
- Microphone permission for voice recording

## Quick Start

### Prerequisites

- [Android Studio](https://developer.android.com/studio) (Ladybug or later)
- JDK 17 (bundled with Android Studio)
- Android SDK 36

### Build

```bash
git clone https://github.com/prismindanalytics/chartlite.git
cd chartlite

# Build debug APK
./gradlew assembleDebug

# Run unit tests
./gradlew testDebugUnitTest

# Install on connected device
./gradlew installDebug
```

### Configuration

1. **On-Device LLM**: Download the appropriate Qwen 3.5 model during setup or in Settings (533 MB for devices with <4 GB RAM, 1.28 GB for 4+ GB RAM). The RAG vector store indexes automatically on first launch.

2. **Cloud Extraction (optional)**: In Settings, enter API keys for Claude, OpenAI, or Gemini to enable cloud-based extraction with automatic offline fallback.

3. **Cloud ASR (optional)**: Select from Gemini Flash Lite (recommended for African accents), OpenAI gpt-4o Transcribe, or Deepgram Nova for higher-accuracy transcription when online.

4. **SMS Health Record (optional)**: Configure Twilio credentials in Settings for encrypted SMS. Each SMS sent becomes a portable health record containing the patient's complete significant clinical history. Patients can set an optional PIN for shared-phone privacy.

5. **ASR Model (Omnilingual)**: Download Meta Omnilingual ASR in setup or Settings (365 MB for <4 GB RAM, 1 GB for 4+ GB RAM). Supports 1600+ languages offline. Models can also be sideloaded from USB/SD card for zero-connectivity deployments.

## Screens

ChartLite has 30 screens covering the full clinical workflow:

**Clinical Workflow**: Home, Patient Registration, Patient Search, Patient Summary (vitals trending, conditions, meds), Patient Timeline (encounter history with edit/PIN management), Encounter Recording (voice + vitals), Encounter Review (Summary / Claim / SOAP tabs)

**Specialty**: Immunization Tracking, Growth Charts (WHO z-scores), Family Planning, Lab Orders, Appointments, Appointment Reminders, Referrals (integrated with facility directory), Clinical Protocols, Pharmacy & Stock Management

**Facility & Sync**: Facility Dashboard (analytics, DHIS2 export), Facility Directory (searchable, filterable), Sync (P2P + cross-facility), DHIS2 Export

**SMS & Records**: SMS Decrypt (read portable health records), SMS History

**Admin**: Setup (onboarding wizard), Login, Lock Screen, Settings (AI, speech, operations, regions, admin), User Management, Extraction Queue, Queued Extraction Review

## Project Structure

```
app/src/main/kotlin/com/chartlite/app/
  App.kt                    # Application root, dependency wiring
  config/AppConfig.kt       # Encrypted credential storage
  asr/                      # Speech recognition (ONNX + cloud fallback)
  extraction/               # Clinical data extraction pipeline
    ExtractionOrchestrator.kt   # 6-strategy fallback chain coordinator
    ClinicalVectorStore.kt      # TF-IDF vector store for on-device RAG
    ExtractionQueue.kt          # Batched inference queue with urgent path
    QwenExtractionStrategy.kt   # On-device Qwen via llama.cpp + RAG
    ClaudeExtractionStrategy.kt # Cloud Claude API extraction
    OpenAIExtractionStrategy.kt # Cloud OpenAI extraction
    GeminiExtractionStrategy.kt # Cloud Gemini extraction
    GeminiNanoExtractionStrategy.kt # On-device Gemini Nano (AI Edge)
    RegexExtractionStrategy.kt  # Keyword/regex fallback (always works)
    ToonFormat.kt               # TOON parser (40-60% token savings vs JSON)
    LlmModelManager.kt          # Model download + llama.cpp lifecycle
    LlmResponseParser.kt        # TOON + JSON parsing + hallucination guard
  database/                 # Room + SQLCipher (17 entities, v15 schema)
  sms/                      # SMS portable health record
    BinaryEncoder.kt            # V1-V4 encoding (V4: growth, immunization, status flags)
    PatientHealthSummary.kt     # Aggregates chronic conditions + abnormal vitals
    SMSEncryption.kt            # AES-256-GCM with PBKDF2 key derivation
    SMSSender.kt                # Dual provider (Twilio + native SIM)
  cdss/                     # Clinical decision support alerts
  billing/                  # Claims, SOAP notes, PDF export, tariffs
  patientid/                # Patient ID generation
  sync/                     # Peer-to-peer + cross-facility sync
  ui/screens/               # 30 Jetpack Compose screens
  ui/components/            # Reusable components (MarkdownText, PinPad, etc.)
app/src/main/assets/
  formulary/za_formulary.json   # 515 South African drugs
  icd10/phc_top300.json         # 300 primary healthcare ICD-10 codes
llm/                        # Native llama.cpp JNI bridge module
  src/main/cpp/chartlite_llm.cpp  # Flash attention, Q8 KV cache, batch threading
```

## SMS as Portable Health Record

Each SMS sent to a patient is a self-contained, encrypted health record. The patient stores only the latest SMS and it contains all significant clinical details from every visit. Any clinician can decrypt it with the patient's phone number, with an optional PIN for shared-phone scenarios.

**V4 wire format (92 bytes, 1 SMS):**
- **Current encounter**: date, 3 diagnoses, 3 medications, vitals, allergies, follow-up
- **Health history**: chronic conditions (ICD-10 codes seen in 2+ visits), most recent abnormal vitals with dates, cumulative allergy flags, total visit count
- **Growth & immunization**: latest weight/height, WHO growth z-scores, up to 3 recent immunization records
- **Clinical status flags** (16-bit): HIV, TB, pregnancy, syphilis, hepatitis B, malaria, anemia, sickle cell, and more
- **Encryption**: AES-256-GCM (PBKDF2 key from phone number, optional phone+PIN mode)

See the [SMS Health Record documentation](https://chartlite.health) for a detailed walkthrough.

## Security

- **Forced admin setup** - First-use requires creating an admin account before any access
- **Role-based access control (RBAC)** - 6 roles (Admin, Doctor, Nurse, Pharmacist, Community Health Worker, Registration Clerk) with per-route and per-station guards
- **PIN authentication** - PBKDF2-hashed PINs with salt, lockout after 5 failed attempts (2-minute cooldown)
- **Biometric authentication** - Optional fingerprint/face unlock
- **SQLCipher encryption** - All local data encrypted at rest (AES-256)
- **Encrypted credentials** - EncryptedSharedPreferences (AES-256-SIV + AES-256-GCM) for API keys and settings
- **Audit logging** - All clinical and administrative actions logged with user, timestamp, and affected data
- **Duplicate username prevention** - Enforced at both creation and facility-join flows
- **Sync privacy** - Patient PINs automatically stripped from cross-facility sync payloads

## On-Device AI Pipeline

| Component | Model | Size | Purpose |
|-----------|-------|------|---------|
| ASR (low-end) | Omnilingual 300M int8 | 365 MB | 1600+ language speech recognition |
| ASR (mid-range) | Omnilingual 1B int8 | 1.03 GB | Higher accuracy ASR |
| ASR (English) | Moonshine Tiny/Base v2 | 43-140 MB | Lightweight English-specific |
| LLM (low-end) | Qwen 3.5 0.8B Q4_K_M | 533 MB | Clinical extraction on 3 GB RAM |
| LLM (mid-range) | Qwen 3.5 2B | 1.28 GB | Higher accuracy extraction |
| RAG | TF-IDF vector store | In-memory | 300 ICD-10 + 515 drugs, cosine similarity retrieval |

**Optimizations**: Flash attention, Q8_0 KV cache, configurable batch/generation threads, model auto-unload after 30s idle, batched inference queue (load model once for N patients).

## Clinical Data

| Dataset | Size | Source |
|---------|------|--------|
| ICD-10 codes | 300 | WHO primary healthcare subset |
| Formulary drugs | 515 | South Africa STG/EML (S1-S6 schedules) |
| CPT mappings | 40+ | ICD-10 category &rarr; CPT |
| E/M levels | 5 | 2021 MDM guidelines |
| SAMA tariffs | ZAR + USD | South Africa medical aid rates |
| Local language terms | Zulu, Xhosa, Amharic | Community health worker input |

## Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

For security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [llama.cpp](https://github.com/ggml-org/llama.cpp) - LLM inference engine, built from source for latest model support
- [Meta Omnilingual ASR](https://huggingface.co/csukuangfj/sherpa-onnx-omnilingual-asr-1600-languages-300M-ctc-int8-2025-11-12) - 1600+ language speech recognition via sherpa-onnx ONNX export (Apache 2.0)
- [ONNX Runtime](https://onnxruntime.ai/) - On-device speech recognition inference
- [SQLCipher](https://www.zetetic.net/sqlcipher/) - Encrypted local database
- South Africa National Department of Health - Standard Treatment Guidelines and Essential Medicines List
