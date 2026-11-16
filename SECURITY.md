# Security model

PhishShield is a local, single-analyst investigation tool. Run it in an isolated analysis environment. It is not an authenticated multi-user service.

## Outbound collection

* HTTP(S) target collection uses ports 80 and 443 only. Static analysis can still inspect URLs with other ports.
* Every observed redirect is parsed again. All DNS answers must be public; mixed public/private answers are rejected.
* Connections use the validated IP literal directly, with the original HTTP Host and verified TLS hostname. There is no second hostname lookup during connection, environment proxy, cookie jar, Referer, or target authentication.
* Target collection reads HTTP/1.x headers only, at most 64 KiB, with no page-body read or JavaScript execution. Informational responses, exotic HTTP behavior, and unsupported redirects can result in incomplete evidence.
* DNS waiting and every target socket operation use a shared time budget. OS DNS lookups cannot be forcibly cancelled portably; at most eight resolver workers may remain outstanding globally.
* This application policy supplements network isolation. It cannot inspect custom NAT/translation routes, privileged host configuration, or compromised routing infrastructure. Hosted deployments still require enforced outbound firewall policy and authentication.
* Reputation and public-IP enrichment are explicit opt-ins to fixed providers. These provider clients use request timeouts; provider completion is not a strict wall-clock guarantee. The investigation budget is enforced for target DNS/HTTP, and reputation receives only the remaining budget as its request timeout.

## Data handling

Full URLs exist in browser-session report memory. History is limited to 20 cases and is not durable case storage. Analyst notes and dispositions are session-local until exported. Default exports redact URL query values and remove fragments. Hostnames, paths, analyst notes, and infrastructure data remain and must be reviewed before sharing. Full URL export requires explicit selection.

Reputation error messages exclude raw exception strings and API keys. A provider no-match is not proof of safety. Neither risk weights nor per-rule confidence values are calibrated probabilities. `confidence` in schema 3.1 is a deprecated compatibility alias for collection coverage; `detection_confidence` is null.

## Reporting a vulnerability

Do not post live credentials or sensitive investigation URLs in public issues. For a non-sensitive issue, provide the affected commit, reproduction using reserved example domains and mocked network responses, expected behavior, and observed behavior. Request a private channel from the maintainer before sharing sensitive details.
