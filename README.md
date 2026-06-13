# 🇼 UgandaEMR Mobile App

**UgandaEMR Mobile** is an Android application built to support **offline FHIR-based data collection**, patient management, and encounter recording in healthcare facilities across Uganda. The app uses the [Android FHIR SDK](https://github.com/google/android-fhir) to enable standards-based interoperability and integrates with the [UgandaEMR](https://ugandaemr.org) backend via [OpenMRS FHIR](https://wiki.openmrs.org/display/projects/FHIR+Module).

---

## 📲 Features

* ✅ FHIR-based Patient registration, visits, and encounters
* ✅ Form rendering using [FHIR SDC](https://build.fhir.org/ig/HL7/sdc/) questionnaires
* ✅ Offline-first with encrypted local FHIR storage
* ✅ Secure user authentication and session management
* ✅ Data synchronization with OpenMRS-compatible FHIR server
* ✅ Modular, testable codebase with modern Android architecture

---

## 🏗️ Architecture Overview

The app follows **Clean Architecture** and integrates the **Android FHIR SDK**:

```
UI (Jetpack Compose)
   ↓
ViewModel (StateFlow)
   ↓
UseCase (Business logic)
   ↓
FHIRRepository (Data layer)
   ↓
Android FHIR Engine (local store) + Remote FHIR API (OpenMRS)
```

### 🔧 Tech Stack

* 🧱 Jetpack Compose (UI)
* 🏧 MVVM + Use Cases + Hilt
* 📦 Android FHIR Engine (SDK)
* 🌐 OpenMRS FHIR API (DSTU3/R4)
* 📂 Encrypted SharedPreferences + DataStore
* 📲 WorkManager (sync)
* 🔐 Secure local FHIR storage

---

## 🧹 Modules

| Module            | Description                                     |
| ----------------- | ----------------------------------------------- |
| `app`             | Main navigation & entry point                   |
| `core-fhir`       | FHIR engine config, DAO wrappers                |
| `core-ui`         | Shared UI components, theme, typography         |
| `core-network`    | FHIR REST client config                         |
| `core-domain`     | Use cases, models, validators                   |
| `feature-auth`    | Login & token management                        |
| `feature-patient` | Patient list, search, registration (FHIR-based) |
| `feature-form`    | SDC Questionnaire rendering + response mapping  |
| `feature-sync`    | Background sync, sync status                    |

---

## ⚙️ Getting Started

### ✅ Prerequisites

* Android Studio Hedgehog or later
* JDK 11
* Kotlin 1.9+
* Gradle 8+
* FHIR-compatible OpenMRS server

### 🚀 Setup

```bash
git clone https://github.com/your-org/ugandaemr-mobile.git
cd ugandaemr-mobile
./gradlew sync
```

Open in Android Studio and run the `app` module on an emulator or device.

---

## 🧪 Testing

Run unit tests:

```bash
./gradlew testDebugUnitTest
```

Run UI tests:

```bash
./gradlew connectedDebugAndroidTest
```

---

## 🔐 Security

* FHIR data is stored in the **encrypted local FHIR database**
* All credentials are securely handled via `EncryptedSharedPreferences`
* HTTPS enforced using `network_security_config.xml`

---

## 🔄 Sync & Versioning

* Uses **WorkManager** for scheduled sync jobs
* `versionCode` = Git commit count
* `versionName` = latest Git tag (e.g. `v1.0.3`)

Example tagging:

```bash
git tag v1.3.0
git push origin v1.3.0
```

---

## 📒 FHIR-Specific Details

* ✅ SDC-compliant forms rendered via `QuestionnaireFragment`
* ✅ QuestionnaireResponse mapped to FHIR resources before submission
* ✅ Uses `DefaultResourceMapper` and `QuestionnaireViewModelFactory`
* ✅ Custom mappings supported via extensions or transformers
* ✅ Offline-first using `FhirEngine.getInstance(context)`

---

## 📟 Documentation

* [Android FHIR SDK Docs](https://github.com/google/android-fhir)
* [OpenMRS FHIR Module](https://wiki.openmrs.org/display/projects/FHIR+Module)
* [HL7 SDC IG](https://build.fhir.org/ig/HL7/sdc/)
* [Jetpack Compose](https://developer.android.com/jetpack/compose)

---

## 🧑🏾‍💻 Contributing

We welcome contributions! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for setup and coding guidelines.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👥 Maintained by

> METS Program - Uganda
