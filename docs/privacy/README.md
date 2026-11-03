# PrivaCage legal and privacy documents

**Document set:** 0.1-draft  
**Prepared:** 3 November 2026  
**Status:** Draft for project-owner and qualified legal review. **Not release-ready.**

These documents describe the current repository implementation, not every item in the long-term roadmap. They must be reviewed whenever a data flow, permission, network endpoint, provider integration, relay deployment, retention period, or platform capability changes.

## Release blockers

Do not publish these documents as the final legal terms until the project owner completes and verifies every item below.

- **Controller:** replace [CONTROLLER LEGAL NAME / ENTITY] with the actual person or legal entity that determines the purposes and means of any processing for the released app and services.
- **Contact:** replace [PRIVACY CONTACT EMAIL] and [POSTAL ADDRESS] with monitored, valid contact details.
- **DPO / representative:** determine whether a Data Protection Officer or EU/EEA representative is legally required. Do not invent an appointment or say that one exists unless it does.
- **Lawful bases:** have the controller document a lawful basis for each processing operation. Do not assume consent, contract, or legitimate interests without analysing the actual facts.
- **Service inventory:** identify any production website host, reverse proxy, relay operator, AI providers recommended or preconfigured in the app, support channels, app-store distribution, and any other actual recipient. The current Android BYO-key model sends requests directly to the provider selected by the user.
- **Deployment:** state which relay endpoints, if any, are operated by the project owner. The repository relay defaults to loopback and is not itself a centrally operated PrivaCage user-account service.
- **Effective date and version:** set a real effective date and publish a change history before treating the documents as binding.

## Documents

- [Terms of Service](TERMS_OF_SERVICE.md)
- [Privacy Policy](PRIVACY_POLICY.md)
- [Strict No-Telemetry Policy](NO_TELEMETRY_POLICY.md)
- [Data Retention and Encryption](DATA_RETENTION_AND_ENCRYPTION.md)
- [Authority and Legal-Request Policy](AUTHORITY_REQUESTS.md)
- [External Services and Data Flows](EXTERNAL_SERVICES.md)

The Android app reads these files from its packaged assets. They are not fetched from a remote policy server. A release must package the same reviewed versions that are published in the repository.

## Implementation boundary

Current code can enforce local encryption for particular stores and can prevent certain analytics/crash-reporting SDKs from being added unnoticed. It cannot guarantee that Android, an OEM, a network provider, a third-party AI provider, a user-configured relay host, or an externally opened website collects nothing. The policy documents explain these boundaries rather than using an absolute “zero data ever leaves the device” claim.

## Change control

Any proposed change that adds telemetry, an account, a remote data store, a new permission, a new provider, new relay hosting, new log retention, or a new disclosure purpose must include:

1. a documented purpose and data inventory;
2. a security and privacy review;
3. an update to this document set;
4. an explicit user choice where the feature sends user data to an external destination;
5. a regression check that enforces the no-telemetry policy; and
6. legal review where the change affects the controller's obligations or the privacy notice.

## Legal references for review

- [GDPR, Regulation (EU) 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/) — including Articles 5, 6, 13–14, 23, 25, 32 and 48.
- [Irish Data Protection Act 2018, section 41 — revised text](https://revisedacts.lawreform.ie/eli/2018/act/7/section/41/revised/en/html). The Law Reform Commission's consolidated version is updated to 16 July 2026.
- [EDPB Guidelines 02/2024 on Article 48 GDPR — final version 2.1, adopted 4 June 2025](https://www.edpb.europa.eu/documents/guideline/guidelines-022024-on-article-48-gdpr_en).
- [Irish Data Protection Commission — Transparency](https://www.dataprotection.ie/en/organisations/know-your-obligations/transparency).
- [Irish Data Protection Commission — The right to be informed](https://www.dataprotection.ie/en/individuals/know-your-rights/right-be-informed-transparency-article-13-14-gdpr).

These links are reference material, not a legal opinion that this draft complies with every law applicable to the eventual controller or deployment.
