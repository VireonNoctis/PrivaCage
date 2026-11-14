# PrivacySentry assessment

**Reviewed:** 14 November 2026  
**Upstream:** [allenymt/PrivacySentry](https://github.com/allenymt/PrivacySentry)  
**Decision:** retain as a research reference; do not add it as a PrivaCage runtime dependency.

## What it is

PrivacySentry is an Android application-build instrumentation tool. It is designed to help an Android app developer identify and optionally change selected sensitive API calls made by code included in that app's build.

Its repository describes four main parts:

- **Gradle plugin:** uses ASM and the Booster transform framework to inspect and rewrite bytecode during the Android build.
- **Annotations:** mark proxy classes and methods that should replace selected method invocations.
- **Runtime hook SDK:** initializes the recorder, handles privacy-consent state and receives observations from the inserted proxy calls.
- **Proxy implementations:** provide replacement methods for a catalogue of selected sensitive APIs, with custom proxies available to the app developer.

The documented output includes method names, timestamps, call stacks and aggregate counts. The project describes Logcat and local XLS report output, including separate process output. It also documents optional reflection matching and package exclusions.

This is useful for **instrumenting the app that includes the plugin**. It is not a general Android service that can rewrite or observe every other installed app.

## What it does not give PrivaCage

PrivacySentry does not provide a supported stock-Android API for intercepting arbitrary API calls made by unrelated installed apps. Its bytecode transformation runs when the target app is built; it cannot retrofit another publisher's already-installed APK from an ordinary sandboxed PrivaCage process.

The documented limits matter:

- Dynamically loaded code is outside the documented coverage.
- Reflection interception is optional, disabled by default, and relies on matching configured class/method strings visible in the target bytecode.
- A configured package blacklist skips transformation for those packages; calls in those skipped classes are therefore not covered.
- It does not establish that a sensitive API call transmitted personal data off-device or was used for an abusive purpose.
- Some older field, constructor and class-replacement paths are documented as deprecated, unstable or no longer maintained.
- The example app recommends disabling file-result output in production because call-stack records can contain sensitive application context.

An observed method invocation, a value returned to an app, a network transfer and a privacy violation are four different claims. PrivaCage must not collapse them into a single “tracking detected” result.

## Compatibility and maintenance check

The upstream README currently documents this integration baseline:

| Component | Upstream documented version |
|---|---:|
| Android Gradle Plugin | 8.0+ (8.2.0 recommended) |
| Gradle | 8.0+ |
| Kotlin | 1.8.10+ |
| Compile SDK | 34+ |
| Minimum Android SDK | 19+ |
| Published dependency example | `1.3.7_v820_beta4` |

The upstream plugin module's build file declares an AGP 8.0.0 compile-only dependency and Booster 5.1.0. PrivaCage's current Android build uses AGP 8.10.1, Kotlin 2.2.20, compile SDK 36 and Gradle 8.14. The repository does not provide evidence that this exact newer toolchain combination has been validated with PrivacySentry. A version range in a README is not a compatibility test.

The upstream repository is not marked archived and carries an MIT license. Its latest commit at review time was `c705b3f588ceff579b829a4a829552ee038c450b`, dated 30 December 2025. The GitHub repository metadata reported its most recent push on that date when checked on 14 November 2026. This is a maintenance signal to monitor, not proof that the code is insecure or unusable.

## PrivaCage decision

**Do not embed PrivacySentry in the production PrivaCage APK.** It would instrument PrivaCage's own included code, not create whole-device visibility, and its runtime/file logging would add data-collection and release-maintenance risk. It would also add another bytecode transformer to a modern AGP/Kotlin build without a verified compatibility matrix.

Keep it as a reference when reviewing Android-sensitive API inventories and the difference between static indicators and runtime observations. If a future developer-only experiment is justified, it must be isolated from release variants, default to no persistent call-stack output, be explicitly enabled by a developer/test build, and pass the current AGP/Kotlin matrix plus app-behavior regression tests before use. That experiment is not part of this implementation.

## Sources

- [PrivacySentry repository and README](https://github.com/allenymt/PrivacySentry)
- [Architecture analysis](https://github.com/allenymt/PrivacySentry/blob/main/docs/architecture.md)
- [Developer/build guide](https://github.com/allenymt/PrivacySentry/blob/main/CLAUDE.md)
- [Gradle plugin build file](https://github.com/allenymt/PrivacySentry/blob/main/plugin-sentry/build.gradle)
- [MIT license](https://github.com/allenymt/PrivacySentry/blob/main/LICENSE)
- [Latest upstream commit reviewed](https://github.com/allenymt/PrivacySentry/commit/c705b3f588ceff579b829a4a829552ee038c450b)

This is an engineering compatibility and scope assessment, not a security audit of the upstream repository.
