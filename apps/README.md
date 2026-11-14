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

Platform build configuration and project-specific documentation live at the platform root. Shared libraries, catalogues, and server-side services remain outside this directory: `android-core/`, `shared/`, and `web-backend/`.

Platform source and test contents belong in the corresponding `main/` and `test/` folders. The language-specific exception is Windows Go unit tests: package tests that inspect unexported implementation details remain alongside their package in `windows/main/`, as required by Go. `windows/test/` holds cross-package integration tests.
