# Contributing to ChartLite

Thank you for your interest in contributing to ChartLite! This project aims to improve healthcare documentation in resource-constrained settings, and every contribution helps.

## Getting Started

### Development Environment

1. **Android Studio** Ladybug (2024.2) or later
2. **JDK 17** (bundled with Android Studio)
3. **Android SDK 36** (install via SDK Manager)

### Setup

```bash
git clone https://github.com/prismindanalytics/chartlite.git
cd chartlite
```

Open the project in Android Studio. Gradle sync will download all dependencies automatically.

### Build and Test

```bash
# Build debug APK
./gradlew assembleDebug

# Run unit tests (must pass before submitting PR)
./gradlew testDebugUnitTest
```

## How to Contribute

### Reporting Bugs

Open a [GitHub Issue](https://github.com/prismindanalytics/chartlite/issues/new?template=bug_report.md) with:
- Device model and Android version
- Steps to reproduce
- Expected vs actual behavior
- Logs if available (`adb logcat -s ChartLite`)

### Suggesting Features

Open a [GitHub Issue](https://github.com/prismindanalytics/chartlite/issues/new?template=feature_request.md) describing:
- The problem you're solving
- Your proposed solution
- Which module(s) are affected

### Submitting Code

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/your-feature`
3. **Make your changes** following the style guidelines below
4. **Add or update tests** for your changes
5. **Run tests**: `./gradlew testDebugUnitTest` (all must pass)
6. **Build**: `./gradlew assembleDebug` (must compile cleanly)
7. **Commit** with a clear message (see commit guidelines)
8. **Push** and open a Pull Request

### Pull Request Guidelines

- Keep PRs focused on a single change
- Reference related issues in the PR description
- Include before/after screenshots for UI changes
- Ensure all CI checks pass
- Be responsive to review feedback

## Code Style

### Kotlin

- Follow [Kotlin coding conventions](https://kotlinlang.org/docs/coding-conventions.html)
- Use `camelCase` for functions and variables, `PascalCase` for classes
- Add KDoc comments on public classes and functions
- Use `data class` for DTOs and value objects
- Prefer `val` over `var`; prefer immutable collections

### Architecture

- Each module (`asr/`, `extraction/`, `database/`, etc.) should be self-contained
- Use the strategy pattern for pluggable backends (see `ExtractionStrategy`)
- New extraction backends implement `ExtractionStrategy` interface
- Database changes require a Room migration
- All clinical data must be validated against loaded formulary/ICD-10 data

### Testing

- Unit tests go in `app/src/test/`
- Name test classes `{ClassName}Test.kt`
- Test both happy paths and edge cases
- Clinical extraction tests should include transcript samples

## Commit Messages

Follow this format:

```
Short summary (imperative mood, <72 chars)

Optional longer description explaining the "why" behind the change.
Reference issues with "Fixes #123" or "Relates to #456".
```

Examples:
- `Add drug-drug interaction alerts for ARV combinations`
- `Fix false positive diagnosis when transcript contains greetings`
- `Improve Qwen inference latency on low-RAM devices`

## Module Guide

If you're looking for where to contribute:

| Area | Directory | Good First Issues |
|------|-----------|-------------------|
| Speech Recognition | `asr/` | Model fine-tuning, language support |
| Clinical Extraction | `extraction/` | New extraction strategies, prompt tuning |
| Database | `database/` | FHIR export improvements, migrations |
| SMS Sync | `sms/` | Protocol optimizations, new transports |
| Decision Support | `cdss/` | New drug interaction rules, dosage checks |
| Billing | `billing/` | Country-specific tariff tables |
| UI | `ui/` | Accessibility, responsive layouts |
| Country Expansion | `config/` | New country formularies, ICD-10 localizations |

## Security

For security vulnerabilities, **do not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
