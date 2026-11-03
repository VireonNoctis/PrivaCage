# External Services and Data Flows

**Version:** 0.1-draft  
**Prepared:** 3 November 2026

This inventory separates requests made for a user-requested feature from product telemetry. The app must not add a new external recipient without updating this document and the Privacy Policy.

## 1. AI API providers

The Android client currently has a provider-specific, opt-in text adapter for OpenAI, Anthropic, Google Gemini, Cohere, Mistral, Groq, DeepSeek, OpenRouter, xAI, Together AI, Fireworks AI and Hugging Face Inference.

The user must save a provider API token, allow the task, paste text and separately confirm each request. The request contains only the pasted text as user content plus fixed task instructions. The locally stored intended-use note and the app label/package ID from the review queue are not attached automatically; users must paste any app context they want the provider to receive. No app inventory, DNS history, rights tracker, files or device settings are attached automatically.

The user-provided token is encrypted locally with Android Keystore-backed AES-256-GCM at rest, but it is present in application memory and is sent to the provider as authentication. The provider can see the pasted text, fixed task instructions and ordinary connection metadata. The provider's own terms, retention, training, billing and transfer settings apply. OpenAI's official key-safety guidance advises against deploying API keys in mobile apps; this direct BYO-key path is an opt-in personal-use convenience, not a recommended production secret-management design. Source checked 3 November 2026: [OpenAI API key safety guidance](https://help.openai.com/en/articles/5112595-best-practices-for-api-key-safety).

The list is explicit, not a claim that every AI company shares one protocol. Providers that use different authentication schemes, such as signed regional requests, require a separate adapter.

## 2. DNS resolver

The user supplies the resolver address. While DNS filtering is active, supported domain queries are sent to that resolver. The resolver can see the query name, record type and the network source address as observed by the resolver. DNS-over-TLS protects the connection in transit and verifies the certificate hostname but does not hide query contents from the resolver.

The feature is DNS-only and does not capture arbitrary HTTPS, app-owned DoH/DoQ, direct-IP or all IPv6 traffic. This is not a full-device VPN.

## 3. Sync relay

The user configures a relay URL, space and capability. Device messages are signed and recipient-encrypted before upload. The relay transports and stores opaque packets, not readable profile contents.

The relay nevertheless sees message IDs, space IDs, public device cards/fingerprints, timestamps/cursors, payload lengths and access patterns. The relay operator and any reverse proxy/host may see ordinary connection metadata.

The repository relay defaults to loopback. It does not create a central user-account service. Anyone who deploys it publicly is responsible for securing the host, TLS termination, administrator credentials, access controls, backups, logging and its own privacy notice.

## 4. Browser, app store and source links

App-policy URLs, source evidence, legal references and app-store pages open through Android's system browser or an installed app. The destination receives the ordinary connection metadata and any information the user supplies there. PrivaCage does not intercept the browser session or automatically crawl private app screens.

## 5. Web workspace

The Svelte web workspace presents the embedded tracker catalogue and derived catalogue information through a Rust/Axum API. The API defaults to 127.0.0.1 and does not ingest live device activity. It contains no product analytics SDK. A public deployment changes the exposure: the deployment operator must assess authentication, TLS, rate limits, host logging and access to any reverse-proxy logs.

## 6. No third-party telemetry vendors

No analytics, advertising, attribution, session-replay or remote crash-reporting vendor is intentionally integrated into the Android client. The Go validate-android-privacy command scans Android build files, manifests and app source for known SDK and advertising-ID markers. This is a static regression check, not proof against every possible hand-written telemetry implementation or platform-level diagnostic.
