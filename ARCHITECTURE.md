# ChartLite Architecture

## System Overview

ChartLite is a voice-first clinical documentation app designed for offline-first operation on low-cost Android devices. The system converts spoken patient encounters into structured clinical data through a multi-tier extraction pipeline.

```
                         +-----------------+
                         |   Voice Input   |
                         +--------+--------+
                                  |
                         +--------v--------+
                         |   ASR Engine    |
                         | (ONNX / Google) |
                         +--------+--------+
                                  |
                              transcript
                                  |
                   +--------------v--------------+
                   |   Extraction Orchestrator   |
                   |                             |
                   |  +-- Vector Store (RAG) --+ |
                   |  | TF-IDF index: 815 codes| |
                   |  | Top-K retrieval/query  | |
                   |  +------------------------+ |
                   |         |                   |
                   |  Qwen 3.5 (RAG + TOON I/O) |
                   |         |                   |
                   |         v                   |
                   |  Claude API (cloud, opt.)   |
                   |         |                   |
                   |         v                   |
                   |  Regex (always available)   |
                   +--------------+--------------+
                                  |
                        StructuredEncounter
                                  |
              +-------------------+-------------------+
              |                   |                   |
     +--------v--------+ +-------v-------+ +---------v--------+
     |      CDSS       | |   Room + SC   | |     Billing      |
     | Drug/Vital Alert| | SQLCipher DB  | | ICD-10 -> CPT    |
     +-----------------+ +-------+-------+ | SOAP Notes       |
                                 |         +------------------+
                          +------+------+
                          |             |
                   +------v----+ +-----v------+
                   | SMS Sync  | | BT/WiFi    |
                   | AES-256   | | Peer Sync  |
                   +-----------+ +------------+
```

## Module Details

### M1: ASR (`asr/`)

Dual-mode automatic speech recognition.

- **Offline**: ONNX Runtime with wav2vec2 model, CTC decoding
- **Online**: Google Speech Recognition API fallback
- **Hardware-aware model selection**: Smaller model for devices with <3 GB RAM
- **Key files**: `ASREngine.kt`, `OnnxASRPipeline.kt`, `ModelDownloader.kt`

### M2: Clinical Extraction (`extraction/`)

Strategy-pattern pipeline that extracts structured clinical data from transcripts, enhanced with on-device RAG retrieval and token-efficient I/O.

**Runtime extraction chain** (each strategy gets up to 90 seconds):
1. **Selected primary model** - Either Qwen 3.5 on-device, or a selected Claude, OpenAI, or Gemini cloud model
2. **Qwen 3.5 + RAG** - Added as a fallback only when AI mode is `auto`
3. **Regex** - Keyword/fuzzy matching, always available as the final fallback

**On-device RAG pipeline**: A TF-IDF vector store (`ClinicalVectorStore`) indexes all 815 ICD-10 codes and formulary drugs at app startup (~20-50ms). Per transcript, cosine similarity retrieves the 10-15 most relevant entries, reducing reference tokens from ~6,000 to ~400-800 and freeing 80% of the 8K context window for longer transcripts and better generation.

**TOON output format**: LLM output uses Token-Oriented Object Notation — a pipe-delimited, indentation-based format achieving ~40-60% token savings vs JSON. `LlmResponseParser` tries TOON first, then falls back to JSON parsing for robustness.

**Batched inference queue**: `ExtractionQueue` collects transcripts during a clinic session and processes them in a single batch (model loads once for N patients). Urgent encounters (referrals/emergencies) bypass the queue for immediate single extraction.

**Hallucination guard**: `LlmResponseParser` validates every ICD-10 code and formulary code against loaded reference data. Invalid codes are silently dropped.

**Key files**: `ExtractionOrchestrator.kt`, `ClinicalVectorStore.kt`, `ExtractionQueue.kt`, `ToonFormat.kt`, `QwenExtractionStrategy.kt`, `LlmModelManager.kt`, `LlmResponseParser.kt`, `ExtractionPromptBuilder.kt`

### M3: Local Database (`database/`)

Encrypted local storage using Room with SQLCipher.

- **Encryption**: AES-256 via SQLCipher, device-derived passphrase
- **Schema**: Native relational model optimized for on-device speed; FHIR R4 Bundles generated on-demand for external systems (DHIS2, OpenMRS)
- **Key files**: `AppDatabase.kt`, `EncounterDao.kt`, `PatientDao.kt`, `DataExporter.kt`, `FHIRValidator.kt`

### M4: Encrypted SMS (`sms/`)

Encounter data transmission over SMS for areas with no internet but cellular coverage.

- **Encoding**: 92-byte binary encoding of encounter data
- **Encryption**: AES-256-GCM with PBKDF2 key derivation
- **Transport**: Native SIM SMS or Twilio API
- **Key files**: `BinaryEncoder.kt`, `SMSEncryption.kt`, `TwilioSMSProvider.kt`

### M5: Clinical Decision Support (`cdss/`)

Real-time safety alerts during encounter documentation.

- Drug-allergy interaction checks
- Drug-drug interaction detection
- Dosage validation against formulary ranges
- Vital sign abnormality alerts (age/context-aware)
- **Key files**: `CDSSEngine.kt`, `DrugInteractionChecker.kt`, `VitalAlertEngine.kt`

### M6: Patient ID (`patientid/`)

Deterministic 8-character IDs in base28 format (e.g., KFMT-4WRN).

- Collision-resistant for facility-level patient volumes
- Easy to read aloud and write on paper forms
- **Key file**: `PatientIdGenerator.kt`

### M7: Billing (`billing/`)

Insurance claim generation from structured encounter data.

- ICD-10 to CPT/HCPCS code mapping (40+ categories)
- E/M level scoring (2021 MDM guidelines, 5 levels)
- SOAP note generation from structured data
- SAMA tariff tables (ZAR + USD)
- **Key files**: `ClaimEngine.kt`, `SOAPNoteGenerator.kt`

### M8: Sync (`sync/`)

Multi-transport facility synchronization.

- **Tier 1**: Offline (local database only)
- **Tier 2**: Bluetooth/WiFi Direct peer-to-peer
- **Tier 3**: Internet (API sync when available)
- **Key files**: `SyncEngine.kt`, `BluetoothSyncProvider.kt`

## Data Flow

### Recording an Encounter

```
1. User taps Record on EncounterRecordScreen
2. ASREngine starts capturing audio
3. Audio -> ONNX wav2vec2 -> transcript text
4. User taps Stop
5. Transcript queued in ExtractionQueue (or immediate if urgent)
6. ExtractionOrchestrator.extract(transcript)
   a. ClinicalVectorStore retrieves top-K ICD-10 codes + drugs for this transcript
   b. ExtractionPromptBuilder builds RAG prompt (relevant codes + TOON output schema)
   c. Try Qwen on-device LLM (RAG prompt, TOON output)
   d. Try Claude API (if API key configured + connectivity)
   e. Fall back to regex extraction (always works)
7. LlmResponseParser parses TOON output (JSON fallback), validates codes
8. CDSSEngine checks for drug interactions and vital alerts
9. StructuredEncounter saved to encrypted Room database
10. User reviews on EncounterReviewScreen (Summary/Claim/SOAP tabs)
```

### Multi-Station Clinic Workflow

```
Reception -> Triage -> Consultation -> Pharmacy -> Billing
    |           |           |              |          |
 Register    Vitals     Diagnose      Dispense    Claim
 Patient   Chief Cmpt  Prescribe     Verify      Generate
            Queue       Follow-up     Stock       SOAP Note
```

Each station creates an encounter linked to the same visit. Patient queues manage the flow between stations.

## Security Model

| Layer | Mechanism |
|-------|-----------|
| Database | SQLCipher AES-256 with device-derived key |
| Credentials | EncryptedSharedPreferences (AES-256-GCM) |
| SMS Data | AES-256-GCM + PBKDF2 key derivation |
| App Access | Optional biometric authentication |
| LLM Inference | On-device by default (no data leaves device) |
| Cloud LLM | Opt-in only, with explicit consent dialog |

## Device Targets

| Device | RAM | LLM Model | ASR Model |
|--------|-----|-----------|-----------|
| Galaxy A03 (baseline) | 2 GB | Qwen 3.5 0.8B Q4 (560 MB) | wav2vec2 small |
| Galaxy A14 (mid) | 4 GB | Qwen 3.5 2B Q4 (1.5 GB) | wav2vec2 base |
| Any device 6+ GB | 6+ GB | Qwen 3.5 2B Q4 (1.5 GB) | wav2vec2 base |

## Key Design Decisions

1. **Offline-first**: Every feature works without internet. Cloud features are opt-in enhancements.
2. **Strategy pattern for extraction**: New LLM backends can be added by implementing `ExtractionStrategy` interface without changing existing code.
3. **On-device RAG over static prompts**: Instead of stuffing all 815 reference entries into every prompt (~6K tokens, 80% of context), a TF-IDF vector store retrieves only the 10-15 most relevant codes per transcript (~400-800 tokens). This frees context for longer transcripts and better generation quality.
4. **TOON format for LLM I/O**: Token-Oriented Object Notation (pipe-delimited, indentation-based) reduces structured output tokens by ~40-60% vs JSON, with automatic JSON fallback for robustness.
5. **Batched inference for battery**: Transcripts queue during a session and process in a single batch — model loads once for N patients instead of N times. Urgent cases bypass the queue.
6. **Hallucination guard**: LLM output is never trusted blindly. Every code is validated against loaded reference data.
7. **Auto-unload after inference**: On-device LLM is unloaded from RAM immediately after use to prevent OOM on low-RAM devices.
8. **FHIR R4 export-on-demand**: Clinical data stored natively for speed; FHIR R4 Bundles generated only when exporting to external systems (DHIS2, OpenMRS).
9. **Binary SMS encoding**: 92 bytes per encounter allows critical data transmission even on 2G networks.
