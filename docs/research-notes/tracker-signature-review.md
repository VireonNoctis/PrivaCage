# Tracker signature review — initial analytics endpoints

**Reviewed:** 2026-10-21  
**Scope:** Two Google Analytics collection-domain indicators. This is a deliberately small starting point, not a comprehensive tracker blocklist.

## Records

### `google-analytics-collection`

- **Domain:** `google-analytics.com`
- **Classification:** Analytics collection endpoint
- **Confidence/status:** High / active
- **Evidence:** Google's Measurement Protocol reference documents HTTPS event collection at `www.google-analytics.com/mp/collect` and `region1.google-analytics.com/mp/collect`. Google's troubleshooting guide also identifies `google-analytics.com/g/collect` requests as Analytics collection traffic.
- **Sources:**
  - https://developers.google.com/analytics/devguides/collection/protocol/ga4/reference
  - https://developers.google.com/analytics/devguides/collection/ga4/troubleshoot?community_post=true

### `analytics-google-collection`

- **Domain:** `analytics.google.com`
- **Classification:** Alternate Analytics collection endpoint
- **Confidence/status:** Medium / review
- **Evidence:** Google's troubleshooting guide identifies `analytics.google.com/g/collect` as an Analytics request endpoint.
- **Why review:** A domain match alone does not identify which app initiated a lookup, prove that a request completed, or establish what data was sent. The broader hostname may serve other Analytics functions, so it must not be silently promoted into a hard-block rule.
- **Source:** https://developers.google.com/analytics/devguides/collection/ga4/troubleshoot?community_post=true

## Interpretation and enforcement limits

- These records identify known service endpoints, not malware and not proof that a particular app collected personal data.
- DNS matching can show that a hostname was queried by traffic visible to the resolver path; it cannot reveal the HTTPS request path or payload.
- Blocking an analytics endpoint can break analytics features on sites or in apps. Any future integration must show the exact rule, its evidence, and a user-controlled way to undo it.
- The Android app currently uses only domains entered by the user. It does **not** load this shared database yet.
- The validator checks schema and URL syntax. It does not verify source availability, evaluate source quality, or assign confidence; those require human review.
- No third-party blocklist data has been copied into these records. The entries are authored from the cited official Google documentation.
