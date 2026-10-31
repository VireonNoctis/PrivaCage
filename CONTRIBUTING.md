# Contributing to PrivaCage

Contributions should make privacy claims more accurate and protections more enforceable. A smaller verified change is better than a feature that only looks functional.

## Before opening a change

- Explain the user-facing problem and platform/API involved.
- Check existing modules and issues before creating parallel implementations.
- Identify OS version, privilege level, entitlement, and distribution restrictions.
- Add tests for parsers, policy decisions, and failure paths.
- Document what the feature cannot observe or enforce.
- Never add secrets, personal data, real user traffic captures, or identifying logs.

## Tracker signature contributions

A signature is an indicator, not a verdict that an app is malicious. Each proposed entry must include:

1. A stable, unique ID.
2. The component/service name and category.
3. At least one concrete indicator, such as a documented SDK package pattern or a domain associated with the component.
4. Public evidence URLs supporting the association.
5. A last-verified date in ISO YYYY-MM-DD format.
6. A confidence level and explanation in the pull request.
7. A status: active, review, or retired.

Do not submit a domain merely because it sounds like advertising infrastructure. Do not claim that a signature proves data collection, a network request, or malicious intent. If evidence conflicts or is stale, use review or omit the entry.

The validator checks structure and, in CI, requires the `last_verified` date to be within 180 days. This freshness gate does not prove that a source is accurate, online, or still describes the same endpoint. Revisit sources and update the review date only after checking the supporting evidence; human review remains required.

## Code requirements

- No mock data presented as live output.
- No swallowed exceptions or success messages before the OS confirms an action.
- Prefer public APIs and least privilege.
- Do not claim arbitrary permission revocation unless it actually works on the target OS.
- Avoid collecting payloads, clipboard contents, precise location, or identifiers unless genuinely required and explicitly opted into.
- Keep logs minimal, local, and retention-controlled.
- Test malformed input and unavailable permissions/services.
- Do not claim support for OS versions or devices that have not been tested.

## Pull request checklist

- [ ] The implementation performs the described operation.
- [ ] Evidence and platform limitations are documented.
- [ ] Tests cover normal, malformed, and failure cases.
- [ ] No secrets, telemetry, or unnecessary personal data were added.
- [ ] Documentation does not overstate observed or blocked activity.
- [ ] Tracker entries include sources and review dates.

## Daily integration cadence

- Keep routine development on the default `main` branch as one consolidated commit per Europe/Dublin calendar day.
- Open a pull request only when that day's complete, meaningful change exceeds 5,000 changed lines. Do not split work to evade the threshold or pad changes to reach it.
- For a qualifying pull request, consolidate the day's work and use a squash merge only after the exact head has passed its required checks and its patch has been reviewed. Do not merge stale, overlapping or failing changes just to clear the queue.
- A workflow must not independently commit or push generated files to `main`; generate reports as artifacts or include refreshed output in the day's single integration commit.
- Large goals mean complete, tested vertical slices across implementation, regression coverage, documentation, and honest capability limits—not raw line-count targets. Keep privileged/destructive operations out of routine automation.
- At the start of each workday, inspect the default-branch head, all open pull requests, current-head checks, issues, roadmap and relevant architecture/security docs. At the end, report the commit, changed scope, exact checks and remaining external validation.
