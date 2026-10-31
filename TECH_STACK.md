# Automated technology stack

The detailed report is generated from tracked source files, manifests and GitHub Linguist during the **Repository health** workflow. It is uploaded as the `privacage-tech-stack-<commit-sha>` workflow artifact (30-day retention).

The report is deliberately generated in CI rather than pushed by a bot. PrivaCage's daily integration policy permits one consolidated `main` commit per Europe/Dublin calendar day; background jobs must not create a second commit. When a report needs to be part of the checked-in tree, refresh it in that day's planned integration commit.

The detector excludes documentation-only roadmap mentions from implementation claims. Language byte shares describe the repository as a whole, not an individual's authorship. Framework detection is an inference from committed manifests and source imports, not proof that a feature is enabled at runtime.
