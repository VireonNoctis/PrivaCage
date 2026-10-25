# 09 — Stalkerware, Coercive Monitoring and User Safety

**Research status:** safety-oriented product note, 25 October 2026  
**Decision this note supports:** make monitoring-risk checks helpful without escalating danger or falsely accusing legitimate tools.

## 1. The core design risk

A person concerned about monitoring may share a device, have a controlling partner/family member/employer, or have account access monitored elsewhere. Installing a privacy tool, changing a permission, disabling a device administrator, deleting history or receiving a prominent “spyware detected” notification can alert the other person. A technically correct detection can still be unsafe if the interaction reveals it.

PrivaCage must not assume that the person holding the device has full control over it. Safety is not achieved by hiding a process and silently operating; stealth behavior can itself be abused and can make a legitimate tool resemble stalkerware. Prefer transparent, user-controlled, low-trace choices.

## 2. What can be checked, and how to label it

Potentially useful user-guided review items include:

- Apps with sensitive permissions that the user does not recognize.
- Accessibility services, notification access, usage access, device-admin/device-management privileges and VPN configurations that the user can inspect in Settings.
- Newly installed or sideloaded packages, where platform visibility and available metadata allow inspection.
- Unknown account sessions or connected devices in important service accounts, handled through the provider's official security screens.
- Persistent background activity or unusual network destinations, but only where PrivaCage has a verified signal.

Each item needs a benign-use note. Accessibility can support assistive technology and automation; device management can be legitimate on work/school devices; VPNs and notification listeners have legitimate use cases. None of these is sufficient alone to diagnose stalkerware. Do not present a list of permissions as proof of spying.

## 3. Safety-first interaction requirements

- **Before scanning:** explain what the scan reads, whether any network requests are made, what is saved, what appears in notifications, and how to exit.
- **Neutral labels:** use “review this service” or “unrecognized privileged access” rather than automatically saying “your partner installed spyware.”
- **No automatic removal:** removing a monitoring app or admin role can notify an operator, break device management, destroy evidence or change a dangerous situation. Show verified system controls and let the user decide.
- **Optional sensitive notifications:** make notification content neutral by default and let the user disable alerts or use a generic label. Avoid promising that notifications can be completely hidden from all device-management surfaces.
- **No cloud upload by default:** do not send app inventory, scan result, location, domain history or user identity to a server to “check” for stalkerware.
- **No forced account:** core checks should work locally without creating a PrivaCage account.
- **No automatic contact with an alleged abuser or device administrator.**
- **Safe exit:** provide a quick way to leave the screen without creating a new confirmation dialog or shareable summary. Explain that opening or downloading information can still leave device/browser history depending on platform behavior.
- **Avoid unsafe promises:** do not claim that a device is safe simply because no indicator was found.

## 4. Evidence and confidence

Potential findings should have exact provenance and an uncertainty label. Example:

> “A service with accessibility access is enabled. This permission can be used by legitimate assistive tools and automation. PrivaCage cannot determine intent from this fact alone. Review the service name and publisher only when it is safe to do so.”

For a known malicious package signature, show the match source, package identity, signature/database version, and whether it was an exact hash/signature match or a broader heuristic. Do not infer who installed it or why.

## 5. Incident response guidance

This feature should point to trusted specialist resources with a safe-device warning, not direct users into a generic checklist that assumes they can safely change settings. Offer neutral text that allows a user to pause and seek help from a device they believe is safe. The app should not automatically send a report or contact a service on the user's behalf. Review specialist guidance and jurisdiction-specific safeguarding practices before shipping an incident-response flow.

Do not put a detailed “how to secretly monitor someone” explanation into the user interface or developer docs. The purpose is protection and recovery, not building a stealth monitor or teaching evasion.

## 6. Testing abuse cases

- A controlling person opens app history, notifications or recent apps after the scan.
- The scan finds a legitimate accessibility tool and does not falsely accuse it.
- A device is managed by an employer/school and the app explains that policy may restrict changes.
- Network is unavailable; scan remains local and does not invent remote verification.
- User chooses not to save results; no report is retained or uploaded.
- User exits during an alert; no forced confirmation or automatic share action appears.
- A finding is uncertain; the user can view evidence without a high-pressure red banner.

## 7. Acceptance criteria

- No finding claims a person installed or operates monitoring software without evidence.
- The app never automatically disables an administrator/accessibility service or contacts another party.
- Default notifications do not disclose exact scan results.
- Local-only operation is enforced and tested for the scan path.
- A “no findings” result includes a clear statement that detection coverage is incomplete.
- Specialist safety content is reviewed before any claim about safe removal or evidence preservation.