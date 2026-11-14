# Platform applications

This directory contains PrivaCage's platform-facing client projects.

- `android/` — Android application and its Gradle modules.
- `ios/` — iOS capability boundary and acceptance notes; no executable iOS target exists yet.
- `web/` — Svelte 5 + TypeScript browser console.

Shared libraries, catalogues, and server-side services remain outside this directory: `android-core/`, `shared/`, and `web-backend/`. Keep platform-specific manifests, source sets, assets, and build configuration inside the corresponding app project.
