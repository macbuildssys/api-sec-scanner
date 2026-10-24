# How severity is decided

The old method was a home made imitation of CVSS that gave every endpoint the same answer. This scanner replaces it with four separate questions, each answered from evidence.

## 1. How bad is the flaw itself? CVSS 4.0

Each check has a base vector, for example `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`. The score comes from the `cvss` library, which uses the official macrovector tables.

Some vectors are adjusted by what the scan saw. For example, privileges required is PR:L only when the endpoint is secured, and PR:N when it is public.

Bands: 0.1 to 3.9 Low, 4.0 to 6.9 Medium, 7.0 to 8.9 High, 9.0 and above Critical.

## 2. How much does it matter here? Asset profile

The profile maps to the CVSS 4.0 environmental metrics CR, IR and AR (confidentiality, integrity and availability requirements).

* Secret, credentials, financial, health or pii data raises confidentiality to High.
* Internal data gives Medium. Public data gives Low.
* Availability low, normal or critical maps to L, M or H.

Because "not defined" counts as High in CVSS 4.0, a profile can only lower a score. That keeps the default scan cautious.

## 3. What counts as a finding? Evidence only

A weakness is listed only when the scanner saw it: a request that must fail succeeded, the answers differ the way the flaw predicts, the target called back, a leaked file has the right content, or a response header or certificate shows the problem. Guesses are not reported.

Best practice gaps with no exploit behind them (a missing Content-Security-Policy, a public API document) are listed at Info level. They get no CVSS score and never raise the overall rating.

## 4. What should we do? Decision

Modeled on CISA SSVC. Minor issues (Low and Info) are always routine. Inputs:

* Automatable: AV:N, AC:L, AT:N, PR:N and UI:N all hold.
* Technical impact: partial or total, from the vector.
* Mission impact: low, medium or high, from the profile.

Outputs: Act (fix now), Attend (escalate to the owner), Track* (watch closely) and Track (routine).

## Known vulnerabilities use the published score

For software versions the target announces, the score is the one OSV.dev or the NVD publishes for the advisory (CVSS 4.0, 3.1, 3.0 or 2.0, newest first). The highest score among the advisories for a component is used. The asset profile is not applied to these scores, because the profile's requirement metrics are defined for CVSS 4.0 vectors. The decision step reads the published vector the same way as ours.

## Overall rating and exposure index

* Rating: the worst scored weakness.
* Exposure index: findings are combined with a noisy OR into a 0 to 100 number. Use it to see whether a scan is better or worse than the last one. It is not a probability.

## Why not DREAD or a homemade score

DREAD rates five factors by gut feeling, so two reviewers give different answers. CVSS 4.0 defines each metric precisely, is maintained by FIRST, and gives the same vector the same score everywhere.

## Standards used

* OWASP API Security Top 10 2023 (still the latest API edition)
* OWASP Top 10:2025 (injection maps to A05:2025, because the API list has no injection category)
* CWE
* MITRE ATT&CK Enterprise v20.0, bundled as `api_scanner/data/attack_subset.json`
