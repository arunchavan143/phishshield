# PhishShield

PhishShield is an explainable URL investigation console for SOC triage and threat-intelligence review. It is designed to help an analyst understand **why** a URL deserves attention, which checks were completed, what evidence came from each source, and what action should follow.

> PhishShield is a triage and investigation aid. A low score is not proof that a URL is safe, and a high score is not a substitute for containment, sandboxing, or incident-response procedures.

## Industry-oriented design

The current architecture uses a layered evidence model rather than a single opaque heuristic. It separates local URL analysis, bounded HTTP behavior, DNS collection, optional reputation lookups, risk aggregation, and the analyst interface. Every scored observation has a stable rule ID, category, severity, score contribution, confidence, source, and collection status.

The product distinguishes **risk score**, **collection coverage**, and per-rule heuristic confidence annotations. These are not calibrated detection probabilities. A URL may have a low local score while reputation data is unavailable, or a high score based on strong local evidence while the network lookup failed. The dashboard shows those distinctions instead of presenting a green result as a guarantee of safety.

The design follows a layered-defense approach recommended by the UK National Cyber Security Centre and emphasizes suspicious links, unexpected requests, independent verification, and reporting as described by CISA [1] [2]. NIST’s Phish Scale is a method for rating the human difficulty of detecting phishing emails, not a direct URL-malware score; PhishShield therefore does not mislabel its machine triage score as a NIST Phish Scale rating [3].

## Detection and evidence layers

| Layer | Examples of signals | Output |
|---|---|---|
| URL identity | IP literals, IDN/punycode, Unicode hostnames, brand-term impersonation, typosquat similarity, suspicious TLDs, deep subdomains | Explainable evidence objects with rule IDs |
| Obfuscation | Host entropy, long hostnames, encoded syntax, embedded credentials, unusual ports, sensitive query keys | Evidence severity and score contribution |
| Social engineering | Credential, payment, recovery, login, verification, and update language | Contextual weak-to-medium signals, never standalone proof |
| Network behavior | Redirect count, cross-domain redirects, final destination, HTTP status, latency, redirect-limit errors | Bounded network evidence and failure state |
| Infrastructure | DNS addresses and collection status | Resolved infrastructure and collection coverage |
| Reputation | Optional provider match, clean result, error, or disabled state | Provider, timestamp, threat type, and provenance |
| Analyst workflow | Recommended actions, case JSON export, evidence ledger, redirect path | Reviewable disposition rather than a bare color |

## Important privacy and safety controls

HTTP requests use short configurable timeouts, a configurable redirect limit, streamed responses, and a dedicated research user agent. PhishShield does not download page bodies or execute JavaScript. Reputation lookups are **opt-in** and disabled by default because sending a URL to an external provider can expose investigative data and may have compliance implications.

Google’s Safe Browsing documentation describes a simple remote Lookup API and a privacy-focused local Update API. It also states that Safe Browsing API v4 is for non-commercial use and that commercial use should use Web Risk [4]. PhishShield therefore requires an explicit environment key and analyst opt-in for the optional Safe Browsing integration. Production deployments should select a provider and license appropriate to their organization.

Do not open suspicious URLs in a normal browser, submit credentials, or use this tool as a substitute for an isolated malware-analysis environment. Use known-good bookmarks or independently sourced contact methods to verify claimed brands.

## Features

The dashboard provides four severity bands—LOW, MEDIUM, HIGH, and CRITICAL—with a 0–100 score, evidence confidence, and collection coverage. The evidence ledger shows rule ID, severity, contribution, confidence, detail, source, and status. Redirects are shown as a path, infrastructure evidence includes DNS results, recommendations summarize the next analyst actions, and the complete schema-versioned report can be exported as JSON.

The default local rules include IP literals, IDN and Unicode hostnames, brand-term impersonation, typosquat likeness, suspicious TLDs, deep subdomain chains, long hostnames, high entropy, suspicious terms, encoded syntax, non-standard ports, plaintext HTTP, sensitive query keys, multiple redirects, cross-domain redirects, HTTP errors, and redirect-limit failures.

## Installation

```bash
git clone https://github.com/arunchavan143/phishshield.git
cd phishshield
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-lock.txt
```

## Run the console

```bash
streamlit run app.py
```

Open `http://localhost:8501`, enter an `http://` or `https://` URL, choose the investigation controls, and select **Run investigation**. Reputation lookup remains disabled unless you intentionally enable it in the sidebar.

## Optional reputation configuration

For a non-commercial Safe Browsing evaluation, configure the key in the process environment:

```bash
export PHISHSHIELD_SAFE_BROWSING_KEY="your-key"
streamlit run app.py
```

The key is never displayed in the dashboard. Enabling the sidebar option sends the investigated URL to the provider. Do not enable this for sensitive URLs unless your organization has approved the data flow.

## Testing

Install development dependencies and run the deterministic regression suite:

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

The suite covers URL validation, IDN and brand signals, explainable evidence, coverage confidence, DNS and network failures, severity boundaries, opt-in reputation behavior, and provider-match provenance. Network calls are mocked in tests.

## Project structure

```text
app.py                 Streamlit analyst console
engine.py              Multi-signal URL, HTTP, DNS, and evidence engine
risk.py                Centralized severity bands and score aggregation
reputation.py          Opt-in reputation-provider abstraction
intelligence.py        Optional public IP enrichment helper
tests/                 Deterministic regression tests
requirements.txt       Runtime dependencies
requirements-dev.txt   Runtime plus test dependencies
```

## Known limitations and next production steps

The current repository is a local analyst console, not a multi-user case-management service. Before production deployment, add authentication and authorization, immutable audit logs, encrypted case storage, provider rate limiting, outbound egress controls, independent network enforcement for cloud-hosted deployments, a job queue for long-running collection, structured observability, CI security scanning, and a versioned policy/rule configuration store.

A mature deployment should also add TLS-certificate inspection, passive DNS or WHOIS history from approved providers, favicon and page-structure analysis in a disposable browser sandbox, malware/reputation feeds, domain-age signals, allowlists with governance, analyst feedback, calibration against a labeled corpus, and a formal false-positive/false-negative evaluation process. Those features should be integrated as provenance-rich providers rather than hidden inside one score function.

## References

[1]: https://www.cisa.gov/audiences/small-and-medium-businesses/secure-your-business/teach-employees-avoid-phishing "CISA: Teach Employees to Avoid Phishing"
[2]: https://www.ncsc.gov.uk/guidance/phishing "UK NCSC: Phishing attacks: defending your organisation"
[3]: https://www.nist.gov/publications/nist-phish-scale-user-guide "NIST Phish Scale User Guide"
[4]: https://developers.google.com/safe-browsing/v4 "Google Safe Browsing API v4"

## Version 3.1: investigation reliability and safer collection

Python 3.11 or newer is required. CI runs on Python 3.11 and 3.12. The bundled Public Suffix List is used without a background list download, including private suffix boundaries such as hosted-site tenants.

The collector now rejects non-public destinations, checks every redirect, and connects to a validated IP while preserving TLS hostname verification. Active target collection is restricted to ports 80/443. A blocked destination is a collection-policy event and does not itself prove phishing. Partial redirect observations are retained when collection fails. See [SECURITY.md](SECURITY.md) for enforcement details and deployment limits.

**Static analysis only** disables DNS, target HTTP, and reputation calls. **Collect HTTP and follow redirects** controls target HTTP collection; disabling it still permits the DNS check. Optional public-IP enrichment remains an explicit separate action.

### Reports, coverage, and scoring

Schema 3.1 adds a case UUID, engine and ruleset versions, collection settings, per-check states, redirect-hop HTTP status and connected address, and the destination associated with each static observation. Redirect destinations receive the same static analysis as the input URL, including a destination blocked before fetching.

Collection coverage reports completed **enabled** checks. Disabled checks are listed but excluded from the denominator; a requested but unconfigured reputation provider is incomplete. A 100% collection result does not establish detection accuracy. `detection_confidence` remains null. The old `confidence` field is retained only as a deprecated coverage alias.

Repeated rules across redirect hops contribute their maximum weight once. Unicode and punycode are one IDN signal, preventing double counting. The 0–100 score remains a heuristic triage scale, not a probability of phishing.

### Analyst workflow

* Results persist across enrichment, notes, download, and sidebar interactions.
* Session history retains the latest 20 cases; selecting a case does not rescan it.
* Each case has analyst notes and a disposition separate from the automated risk band.
* Defanged IOC text is ready to copy. Query values are redacted in those IOCs.
* JSON exports redact query values and remove fragments by default. Explicitly select full URL export when needed. Paths and notes are retained, so review exports before sharing.
* Session history is temporary. Download cases you need to keep.

### Offline rule evaluation

```bash
python evaluate.py
python evaluate.py path/to/approved-corpus.json --threshold 30
```

Each corpus row contains `url`, boolean `expected_review`, and optional `source`. The command performs static analysis only and returns a confusion matrix, precision/recall for the selected triage threshold, and case-level outcomes. The bundled examples are synthetic expectations and deliberately include a lexical blind spot. Their metrics must not be advertised as real-world detection accuracy. Production calibration needs an independently labeled, representative corpus, separate tuning/holdout sets, and false-positive/false-negative analysis.

### Quality checks

```bash
python -m pytest -q
python -m ruff check .
python -m bandit -q -r . -x ./tests
python -m pip_audit -r requirements.txt
```

Tests block live socket connections and DNS by default. They cover special-purpose IPs, mixed DNS answers, alternate IP notation, DNS pinning, TLS hostname preservation, target deadlines, redirect limits and partial evidence, export redaction, provider failures, and Streamlit reruns. GitHub Actions runs tests/lint/static security checks, dependency auditing, and secret scanning. Dependabot checks Python dependencies and pinned workflow actions weekly.

Further deployments should add durable encrypted case storage, access control, governed policies, audited analyst feedback, and an isolated content-analysis worker. Additional reputation, domain-age, certificate, and screenshot providers need approved credentials and separate privacy controls. No license is selected by this update; the owner should choose the intended license before offering third-party reuse.

`requirements-lock.txt` records the tested runtime dependency snapshot; `requirements.txt` declares compatible version ranges. Install the snapshot for reproducible setup.
