# Platform applications

Every platform client follows the same high-level layout:

```text
apps/
├── android/
│   ├── main/
│   └── test/
├── ios/
│   ├── main/
│   └── test/
├── web/
│   ├── main/
│   └── test/
└── windows/
    ├── main/
    └── test/
```

Platform build configuration and project-specific documentation live at the platform root. Shared data, portable cryptographic protocols and server-side services remain outside this directory in `shared/` and `web-backend/`. The Android Kotlin/JVM engine is part of `apps/android/`, not a separate root module.

Platform source and test contents belong in direct feature folders beneath `main/` and `test/`. For example, Android uses `main/dns/`, `main/interface/`, `test/dns/` and `test/interface/`; language package names are not mirrored as directories. The language-specific exception is Windows Go unit tests: package tests that inspect unexported implementation details remain alongside their package in `windows/main/`, as required by Go. `windows/test/` holds cross-package integration tests.
