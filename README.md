# PhishShield

PhishShield is a lightweight SOC-style URL investigation dashboard for triaging suspicious links. It combines transparent URL indicators with bounded redirect analysis and optional IP enrichment so an analyst can quickly understand why a URL received its score.

## What changed in the modernized version

The project now separates URL analysis, risk scoring, domain enrichment, and the Streamlit interface. Input URLs are validated before network access, redirect requests use a bounded timeout and redirect limit, response bodies are not downloaded, and network failures are reported instead of silently swallowed. The risk rules are centralized in `risk.py` and covered by automated tests.

Unused `python-whois` and `dnspython` dependencies were removed because the previous code did not use them. The dashboard now exposes matched keywords, registered domain, status code, response time, redirect count, final URL, and a downloadable JSON report.

## Features

- Transparent 0–100 URL risk score with low-risk, suspicious, and high-risk verdicts.
- Hostname entropy, IP-literal, suspicious-keyword, redirect, and HTTP-status indicators.
- Redirect path visualization and tabular redirect chain.
- DNS resolution and lightweight IP organization, location, and country enrichment.
- Raw JSON metadata view and downloadable investigation report.
- Short timeouts, bounded redirects, explicit HTTP(S) validation, and visible network errors.

> A low-risk score is not proof that a website is safe. PhishShield is an investigation aid, not a malware sandbox or a replacement for organizational threat-intelligence controls.

## Installation

```bash
git clone https://github.com/arunchavan143/phishshield.git
cd phishshield
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the dashboard

```bash
streamlit run app.py
```

Open `http://localhost:8501` in a browser, enter an `http://` or `https://` URL, and select **Start investigation**.

## Run tests

Install development dependencies and run the regression suite:

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

The tests cover URL normalization, suspicious indicators, IP-literal detection, bounded network failures, and score boundaries. Network calls are mocked in tests so the suite is deterministic.

## Project structure

```text
app.py                 Streamlit dashboard and visualizations
engine.py              URL validation, static indicators, and redirect metadata
intelligence.py        DNS resolution and IP enrichment
risk.py                Centralized, testable risk-scoring rules
tests/                 Automated regression tests
requirements.txt       Runtime dependencies
requirements-dev.txt   Runtime plus test dependencies
```

## Limitations

PhishShield does not execute JavaScript, submit forms, capture screenshots, inspect page content, query passive DNS history, or connect to commercial threat-intelligence feeds. Network enrichment may be unavailable in restricted environments, and results can change as a URL or domain changes.

## License

No license is currently declared for this repository. Add an explicit license before distributing or incorporating the project into another product.
