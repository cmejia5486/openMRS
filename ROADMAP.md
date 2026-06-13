# ChartLite Roadmap

## v1 — Core Clinical Workflow (Current Release)

The v1 release focuses on delivering a rock-solid experience for the core clinical workflow:

1. **Voice to Text** — Hold-to-dictate ASR (offline ONNX + cloud fallback)
2. **Text to Structured Note** — LLM extraction of diagnoses, medications, vitals, allergies
3. **Patient Record Retention** — Encrypted SMS sent to patient's phone as portable health record
4. **Cross-Facility Portability** — Decrypt SMS at a new facility to import patient history
5. **Patient Registration** — Voice-assisted or manual patient registration with ID generation
6. **Patient Timeline** — Encounter history with vitals trends, problem list, follow-ups

---

## v2 — Planned Features (Hidden in v1, Ready for Development)

The following features exist in the codebase but are hidden from the v1 UI to keep the experience focused. Each has navigation routes, data models, and partial implementations ready to re-enable.

### Clinical Workflow Extensions

| Feature | Status | Files | Notes |
|---------|--------|-------|-------|
| **Extraction Queue (Batch Processing)** | Implemented, hidden | `ExtractionQueueScreen.kt`, `QueuedExtractionReviewScreen.kt`, `ExtractionQueue.kt` | Process multiple encounters offline in batch. Useful for end-of-day catch-up. |
| **Clinical Protocols** | Implemented, hidden | `ClinicalProtocolScreen.kt`, `ClinicalProtocolEngine.kt` | Evidence-based clinical decision support (IMCI, malaria, HIV, TB protocols). |
| **Claim Preview / Billing** | Implemented, hidden | `EncounterReviewScreen.kt` Tab 1 | ICD-10 → CPT mapping, E/M level calculation, SAMA tariff generation. |
| **Referral Management** | Implemented, hidden | `ReferralScreen.kt`, `ReferralRepository.kt`, `ReferralEntity.kt` | Track referrals with urgency levels, destination facilities, and status. |

### Facility Management

| Feature | Status | Files | Notes |
|---------|--------|-------|-------|
| **Facility Dashboard** | Implemented, hidden | `FacilityDashboardScreen.kt` | Encounter counts (daily/weekly/monthly), top diagnoses, top medications, DHIS2 export. |
| **Appointments** | Implemented, hidden | `AppointmentScreen.kt`, `AppointmentRepository.kt` | Schedule and manage patient appointments. |
| **Appointment Reminders** | Implemented, hidden | `AppointmentReminderScreen.kt`, `AppointmentReminder.kt` | Automated SMS reminders for upcoming appointments. |
| **Stock Management** | Implemented, hidden | `StockScreen.kt` | Track medication and supply inventory levels. |
| **Facility Directory** | Implemented, hidden | `FacilityDirectoryScreen.kt`, `FacilityDirectory.kt` | Browse facilities in network for referrals. |
| **User Management** | Implemented, hidden | Settings > Admin category | Multi-user facility setup with roles. |

### Specialized Clinical Modules

| Feature | Status | Files | Notes |
|---------|--------|-------|-------|
| **Pharmacy / Dispensing** | Implemented, hidden | `PharmacyScreen.kt` | Multi-station pharmacy workflow. |
| **Lab Orders** | Implemented, hidden | `LabOrderScreen.kt`, `LabOrderRepository.kt` | Order and track laboratory tests. |
| **Immunization Tracking** | Implemented, hidden | `ImmunizationScreen.kt`, `ImmunizationRepository.kt` | Vaccine administration records with schedule tracking. |
| **Family Planning** | Implemented, hidden | `FamilyPlanningScreen.kt`, `FPRepository.kt` | Contraceptive method counseling and commodity dispensing. |
| **Growth Charts** | Implemented, hidden | `GrowthChartScreen.kt`, `GrowthRepository.kt` | WHO Z-score pediatric growth monitoring with sparklines. |
| **DHIS2 Export** | Implemented, hidden | `FacilityDashboardScreen.kt` | National health information system reporting. |

### Settings Categories (Hidden in v1)

| Category | What it contains |
|----------|-----------------|
| **Operations** | SMS provider config (Twilio), clinic workflow settings, multi-station mode |
| **Regions** | Country pack selection, locale expansion |
| **Admin** | User accounts, facility setup, data management |

---

## How to Re-enable Features for v2

All hidden features are gated by the `V2_FEATURES_ENABLED` flag in `HomeScreen.kt` and `SettingsScreen.kt`. To re-enable:

1. Set `const val V2_FEATURES_ENABLED = true` in `HomeScreen.kt`
2. Set `const val V2_SETTINGS_ENABLED = true` in `SettingsScreen.kt`
3. Set `const val V2_REVIEW_TABS_ENABLED = true` in `EncounterReviewScreen.kt`

Or selectively enable individual features by uncommenting their grid items.

---

## v3 — Future Vision

- Real-time collaborative multi-facility sync
- Offline-first P2P data sharing between facilities
- AI-powered clinical audit and quality improvement
- Integration with national health registries
- Telemedicine consultation support
