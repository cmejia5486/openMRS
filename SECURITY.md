# Security Policy

## Reporting a Vulnerability

ChartLite handles sensitive health data. We take security seriously.

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, email security concerns to: **security@chartlite.health**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

## Security Measures

### Data at Rest
- Local database encrypted with SQLCipher (AES-256)
- Database passphrase derived from device-specific identifiers
- Credentials stored in Android EncryptedSharedPreferences (AES-256-GCM)
- `android:allowBackup="false"` prevents cloud backup of encrypted data

### Data in Transit
- SMS data encrypted with AES-256-GCM + PBKDF2 key derivation
- Cloud API calls use HTTPS/TLS
- Peer-to-peer sync uses encrypted channels

### On-Device Processing
- Clinical extraction runs on-device by default (Qwen via llama.cpp)
- No patient data leaves the device unless cloud extraction is explicitly enabled
- Cloud extraction requires user opt-in with consent dialog

### Code Validation
- All ICD-10 codes validated against loaded reference data
- All formulary codes validated against loaded drug database
- LLM outputs are never trusted without validation (hallucination guard)

## Responsible Disclosure

We follow coordinated disclosure. After a fix is released, we welcome public discussion of the vulnerability to help the broader healthcare software community.
