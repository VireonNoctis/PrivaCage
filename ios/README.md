# iOS companion: implementation boundary

**Status:** no executable iOS app target exists in this repository yet. This file is a capability/acceptance boundary, not a SwiftUI implementation.

## What can be built without unsupported entitlements

- An explanatory privacy-settings guide that opens user-mediated iOS Settings.
- A user-selected file import workflow for privacy reports or images, with local processing, preview-before-save, and explicit delete-original/import actions.
- Static App Store privacy-label comparison using dated developer disclosures, clearly distinguished from measured runtime behavior.
- A rights-request draft workflow with the same draft-versus-submitted-versus-response distinctions, once shared policy logic and source review are suitable for Swift.
- JPEG/PNG/WebP metadata cleanup only where a tested parser verifies the output and the original stays unchanged.

## What must not be claimed

Apple's App Privacy Report is a user-facing system report. It is not a general public API for arbitrary apps to read the complete underlying report database. Network Extension providers require the applicable entitlement and configuration and do not expose other apps' arbitrary sensor, clipboard, contacts, photo, or API calls. A domain contact is not proof that an app sent a particular personal field.

Do not add UI controls that purport to revoke another app's permissions, inspect every installed app, observe every sensor read, or provide whole-device traffic control unless an approved public API plus working implementation and tests establish that exact capability.

## Required inputs before an executable target is considered complete

1. A Mac with a supported Xcode toolchain and signing/configuration environment.
2. A real iOS app target and deployment target.
3. A reviewed entitlement/distribution decision for any Network Extension provider.
4. A platform capability matrix tied to current Apple documentation.
5. Unit tests plus simulator and physical-device validation for file imports, settings handoffs, privacy, and failure states.
6. Privacy disclosure and retention review for any user-imported reports.

**Current blocker:** this repository has no `ios/` app project, the current environment cannot build/sign Xcode targets, and no Network Extension entitlement has been verified. Therefore this milestone records the supported design boundary and acceptance criteria only. It does not claim iOS runtime functionality.
