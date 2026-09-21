# Security Audit — Suricata × Wazuh SOC Dashboard

> **Author:** Subhikshan Rajkumar
>
> An end-to-end review of the dashboard, its ingestion pipeline, the Wazuh API
> client, the deployment surface (Docker/Streamlit), and the lab provisioning
> scripts. Findings are reported at their true severity; remediations applied in
> this pass are listed, and residual/accepted risks are documented with rationale
> so the security posture is explicit for the dissertation.

## 1. Scope & method

| Area | What was reviewed |
|------|-------------------|
| **Injection** | `eval`/`exec`/`pickle`/`os.system`/`subprocess`/`shell=True` — none present anywhere in `src/` or `lab/*.py`. No SQL layer. |
| **Output encoding (XSS)** | Every `unsafe_allow_html=True` sink (`theme.py`, `app.py`) traced to its data source. |
| **SSRF / outbound** | Wazuh API/Indexer client, optional webhook, threat-intel enrichment. |
| **TLS** | Verification policy, certificate handling, warning suppression. |
| **Secrets** | Credential handling in `config.py`/`auth.py`; committed files scanned; image build inputs. |
| **File handling** | Upload path, gzip handling, JSON parsing, path traversal. |
| **AuthN/Z** | Login gate, constant-time comparison, audit logging. |
| **Deployment** | Dockerfile (privilege, build context), `docker-compose.yml`, `.streamlit/config.toml`. |
| **Lab scripts (root)** | `install_*.sh`, `run_attacks.sh` — quoting, injection, integrity, isolation. |

Method: static read of all 24 `src/` modules + lab scripts, data-flow tracing of
each raw-HTML sink, and dynamic verification via the full test suite (`make
verify`: ruff, black, mypy, pytest, app smoke-render).

## 2. Findings remediated in this pass

### F-1 · Inconsistent output encoding at HTML sinks — *Low (defense-in-depth)*
`theme.header()` and `theme.kpi_row()` interpolated text, and colour values, into
`unsafe_allow_html` markup **without** the `html.escape()` that `theme.table()`
already applied. The same applied to the threat-intel verdict rendered in the
incident drill-down (`app.py`), whose value can originate from an
operator-supplied `threat_intel.json` feed.

No call site fed attacker-controlled text into these helpers *today* (KPI values
are computed numbers; chip text is a fixed enum), so this was a latent sink rather
than a live exploit — but it is exactly the kind of sink that becomes stored XSS
the moment a future KPI/chip surfaces an alert-derived string (e.g. a top
signature or country name).

**Fix:** all text is now `html.escape()`-d and all colours pass a `_safe_color()`
allow-list (hex / `rgb(a)` / CSS keyword only — anything else collapses to
`currentColor`, preventing both attribute breakout and CSS injection). Pinned by
`tests/test_security.py`.

### F-2 · Secrets could be baked into the container image — *Medium*
The Dockerfile uses `COPY . .`, and `.dockerignore` did not exclude
`.streamlit/secrets.toml` / `.env`. A developer who used Streamlit's documented
secret store (or a local `.env`) before building would have shipped those
credentials inside the published image.

**Fix:** `.dockerignore` now excludes `**/secrets.toml`, `.env`/`*.env`, and
`.claude/`. (`data/`, `.git/`, `.venv/` were already excluded — so the audit log
and any uploaded captures were never in the image.)

### F-3 · XSRF protection not pinned — *Low*
`.streamlit/config.toml` relied on Streamlit's *default* cross-site-request-forgery
protection. Disabling CORS in Streamlit also silently disables XSRF, so the
protection was one config change away from being lost.

**Fix:** `enableXsrfProtection = true` is now set explicitly, with a comment noting
the login gate is off by default and the app should be fronted with auth before
being exposed beyond localhost.

## 3. Verified clean (no change required)

- **No code-execution primitives** — confirmed by exhaustive grep; the two
  `python3` heredocs in the lab scripts pass data as `argv`, never interpolating
  shell input into code.
- **Path traversal** — `ingest.save_uploaded_file()` reduces the upload name to
  `os.path.basename()` and writes only under `UPLOAD_DIR`.
- **Malformed-input resilience** — every JSON reader and `normalize_alerts()`
  skip-and-count bad records instead of aborting; one odd alert never breaks a
  batch.
- **Outbound request hygiene** — every `requests` call carries an explicit
  `timeout`; retries use a bounded backoff policy; the Indexer client paginates
  with a deterministic `search_after` tiebreaker.
- **SSRF** — the only outbound targets are operator-configured (`WAZUH_*`,
  `SOC_WEBHOOK_URL`); no request URL is built from alert/ingest content. Online
  threat-intel is off unless explicitly enabled *and* keyed.
- **AuthN** — username and password hash are compared with
  `hmac.compare_digest` (constant time); the plaintext is never stored; an
  unconfigured-but-enabled gate fails closed (denies).
- **Audit logging** — entries are written via `json.dumps` (newline-safe), so a
  crafted username cannot forge log lines.
- **PDF export** — dynamic strings (IPs, signatures) go into reportlab `Table`
  cells, which render literally (no markup parsing); `&` is pre-escaped where text
  reaches a `Paragraph`.
- **No committed secrets** — `config/*.json`, `data/ui_prefs.json` and the repo
  tree scanned; credentials come only from environment variables.
- **Dependency vulnerabilities** — `pip-audit` against the pinned
  `requirements.txt` reported **no known vulnerabilities** at the time of this
  audit (now enforced continuously in CI; see §5).
- **Container least privilege** — image runs as a non-root UID (10001).
- **Lab scripts** — `set -euo pipefail` + root checks; variables quoted; the
  attack runner requires interactive confirmation and is documented lab-only
  (isolated host-only network, Computer Misuse Act 1990, harmless EICAR payloads).

## 4. Residual / accepted risks (documented, not defects)

| Risk | Rationale for acceptance |
|------|--------------------------|
| **TLS verification defaults to `false`** (`WAZUH_VERIFY_SSL`) | Lab Wazuh stacks use self-signed certs; the app prints an explicit "TLS verification is OFF" warning and the docs instruct `WAZUH_VERIFY_SSL=true` with a CA bundle for production. |
| **Login gate off by default; container binds `0.0.0.0`** | Required so the demo/tests are not gated and the container is reachable. Mitigation documented: set `SOC_AUTH_ENABLED=true` or front with an authenticating reverse proxy before network exposure. |
| **Password hashing is unsalted SHA-256** | A pragmatic single-user gate; the hash is never the primary control (the reverse proxy / network isolation is). Changing the scheme would break the documented `SOC_AUTH_PASSWORD_HASH` workflow. Use a high-entropy password; for multi-analyst use, delegate auth to SSO. |
| **`urllib3` InsecureRequestWarning suppressed globally** | Avoids log spam against self-signed lab certs; only reachable when verification is already disabled by operator choice. |

## 5. Ongoing assurance

- **Dependency CVE scanning — implemented.** A dedicated `security` job in CI
  (`.github/workflows/ci.yml`) runs `pip-audit -r requirements.txt` against the
  advisory database on every push/PR, failing the build the moment a known
  vulnerability is disclosed in a pinned runtime dependency — even with no code
  change. Run it locally with `make audit`. It is intentionally kept **out of**
  `make verify` so that gate stays network-free and deterministic for offline use.
- **Output-encoding regression guard.** Keep the `make verify` gate (including
  `tests/test_security.py`) green on every change — it pins the F-1 fixes.
- **Before any production deployment:** enable auth, set `WAZUH_VERIFY_SSL=true`,
  and place the dashboard behind TLS-terminating, authenticating ingress.
