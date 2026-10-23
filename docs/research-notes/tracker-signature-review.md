# Tracker signature review — evidence-backed starter catalog

**Reviewed:** 2026-10-23  
**Scope:** Eleven curated endpoint indicators across analytics, behavioral analytics, advertising, and mobile attribution. This remains a small starter set, not a comprehensive tracker blocklist.

## Records

### `google-analytics-collection`

- **Domain:** `google-analytics.com`
- **Classification:** Google Analytics collection endpoint
- **Confidence/status:** High / active
- **Evidence:** Google's Measurement Protocol reference documents HTTPS event collection at `www.google-analytics.com/mp/collect` and `region1.google-analytics.com/mp/collect`. Google's troubleshooting guide also identifies `google-analytics.com/g/collect` requests as Analytics collection traffic.
- **Sources:**
  - https://developers.google.com/analytics/devguides/collection/protocol/ga4/reference
  - https://developers.google.com/analytics/devguides/collection/ga4/troubleshoot?community_post=true

### `analytics-google-collection`

- **Domain:** `analytics.google.com`
- **Classification:** Alternate Google Analytics collection endpoint
- **Confidence/status:** Medium / review
- **Evidence:** Google's troubleshooting guide identifies `analytics.google.com/g/collect` as an Analytics request endpoint.
- **Why review:** A domain match alone does not identify which app initiated a lookup, prove that a request completed, or establish what data was sent. The broader hostname may serve other Analytics functions, so it must not be silently promoted into a hard-block rule.
- **Source:** https://developers.google.com/analytics/devguides/collection/ga4/troubleshoot?community_post=true

### `microsoft-clarity-collection`

- **Domain:** `www.clarity.ms`
- **Classification:** Microsoft Clarity behavioral analytics collection endpoint
- **Confidence/status:** High / active
- **Evidence:** Microsoft's Clarity setup documentation identifies POST requests to `https://www.clarity.ms/collect` as collection traffic.
- **Source:** https://learn.microsoft.com/en-us/clarity/setup-and-installation/clarity-setup
- **Caveat:** This associates the hostname with a known service endpoint; it does not identify the initiating app by itself or reveal the HTTPS payload. The catalog does not imply that Clarity is suitable for every audience or use case.

### `posthog-hosted-event-capture`

- **Domains:** `us.i.posthog.com`, `eu.i.posthog.com`
- **Classification:** PostHog hosted event-capture endpoints
- **Confidence/status:** High / active
- **Evidence:** PostHog's hosted troubleshooting guide names these US and EU API hosts for event capture.
- **Source:** https://posthog.com/docs/product-analytics/troubleshooting
- **Caveat:** Self-hosted deployments and custom API hosts may not match these names. A match does not establish which data was transmitted.

### `google-ads-measurement-endpoints`

- **Domains:** `googleadservices.com`, `googlesyndication.com`
- **Classification:** Google Ads measurement/advertising service domains
- **Confidence/status:** High / active
- **Evidence:** Google's Google tag setup documentation recommends checking requests to these domains when verifying Google Ads tags.
- **Source:** https://developers.google.com/tag-platform/gtagjs
- **Caveat:** These are broad service domains; a match does not prove profiling or the content of a request. Blocking may break ad-supported functionality or conversion measurement.

### `google-floodlight-doubleclick`

- **Domain:** `doubleclick.net`
- **Classification:** Google Floodlight / DoubleClick domain
- **Confidence/status:** Medium / review
- **Evidence:** Google's Google tag setup documentation lists `doubleclick.net` as a destination to inspect when verifying Floodlight traffic.
- **Source:** https://developers.google.com/tag-platform/gtagjs
- **Why review:** The domain is broad and shared across services. Keep it review-only; it must not silently become a hard block or enter the explicit active-domain import path.

### `pinterest-tag-conversion`

- **Domain:** `ct.pinterest.com`
- **Classification:** Pinterest Tag conversion / page-event endpoint
- **Confidence/status:** High / active
- **Evidence:** Pinterest's official Tag documentation includes `https://ct.pinterest.com/v3/` pixel URLs for page-view and conversion events.
- **Source:** https://developers.pinterest.com/docs/track-conversions/pinterest-tag/
- **Caveat:** This identifies a documented Tag endpoint. It does not identify the initiating app on its own or establish the data in any particular request.

## Interpretation and enforcement limits

- These records identify known service endpoints, not malware and not proof that a particular app collected personal data.
- A domain match cannot reveal HTTPS URL paths, payloads, event contents, or whether a request completed.
- The Android app bundles the shared catalog and shows each record's status, confidence, verification date, and evidence. The user can explicitly import active domain indicators into local rules. Review and retired entries are excluded by that action.
- Imported domain rules do not establish which app made a query, and DNS-level matching cannot enforce SDK class/package indicators.
- Blocking an endpoint can break analytics, ad-supported functions, login flows, or conversion measurement. Users need a reviewable rule and an undo path.
- The validator checks schema and URL structure, not source availability, accuracy, or continued validity. Confidence and status require human evidence review; automated schema checks do not certify truth.
- These entries are based on the cited official documentation; they are not a claim that the set is comprehensive or that all vendor endpoints are covered.


### `amplitude-event-ingestion`

- **Domains:** `api2.amplitude.com`, `api.eu.amplitude.com`
- **Classification:** Amplitude HTTP V2 analytics event-ingestion hosts
- **Confidence/status:** High / active
- **Evidence:** Amplitude's HTTP V2 API reference documents the default host and the EU data-residency host for event ingestion.
- **Source:** https://www.amplitude.com/docs/apis/analytics/http-v2
- **Caveat:** SDK configuration, regional routing, first-party proxies, and server-side forwarding can change the observed host. A domain match does not establish event contents or identify the initiating app.

### `segment-event-ingestion`

- **Domain:** `api.segment.io`
- **Classification:** Twilio Segment Tracking API / Analytics.js event-ingestion endpoint
- **Confidence/status:** High / active
- **Evidence:** Segment's official engineering article documents Analytics.js track/identify calls sending data to `api.segment.io`.
- **Source:** https://segment.com/blog/twilio-segment-edge-sdk/
- **Caveat:** First-party proxies, regional/custom endpoints, and server-side forwarding may not match. A hostname match does not reveal which properties were sent or prove that a particular app collected personal data.


### `appsflyer-mobile-attribution`

- **Domain:** `appsflyersdk.com`
- **Classification:** AppsFlyer mobile SDK communication endpoint
- **Confidence/status:** Medium / review
- **Evidence:** AppsFlyer's official iOS troubleshooting guide recommends `appsflyersdk.com` for SDK traffic in the documented TLS configuration.
- **Source:** https://dev.appsflyer.com/hc/docs/troubleshooting-ios
- **Why review:** The source supports an association with SDK communication in a described configuration, but does not establish that this hostname is exclusively an attribution endpoint across all SDK versions and deployments. Do not bulk-import it as a blocking rule until scope is reviewed.


### `mixpanel-event-ingestion`

- **Domains:** `api.mixpanel.com`, `api-eu.mixpanel.com`, `api-in.mixpanel.com`
- **Classification:** Mixpanel event/profile ingestion endpoints
- **Confidence/status:** High / active
- **Evidence:** Mixpanel's official Track Event API documents event ingestion. Its tracking-proxy documentation identifies the default host and regional hosts for EU and India residency.
- **Sources:** https://developer.mixpanel.com/reference/track-event
- **Caveat:** Regional selection, custom proxies, and SDK changes can alter the observed host. A hostname match does not reveal event contents or identify which app initiated the request.


### `mixpanel-event-ingestion`

- **Domains:** `api.mixpanel.com`, `api-eu.mixpanel.com`, `api-in.mixpanel.com`
- **Classification:** Mixpanel event-ingestion endpoints, including regional hosts
- **Confidence/status:** High / active
- **Evidence:** Mixpanel's official Track Event API documents event ingestion; Mixpanel's official tracking-proxy repository identifies the default API host and regional EU/India host choices.
- **Sources:** https://developer.mixpanel.com/reference/track-event and https://github.com/mixpanel/tracking-proxy
- **Caveat:** Regional selection, SDK versions, custom proxies, and server-side forwarding may alter observed hosts. A domain match does not reveal event contents or establish which application initiated the request.

## SDK package wildcard semantics

The catalog accepts exact dotted package/class names and terminal `.*` or `.**` patterns. In static DEX scanning, terminal wildcards are represented by a package-prefix string match in dotted and slash-separated forms. This improves coverage but remains a string heuristic: a hit does not prove that a class was loaded or executed. Wildcards in the middle of a pattern are rejected by the validator because the scanner does not implement their semantics.
