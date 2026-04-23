"""Shared severity, CVSS/exposure, and compliance text injected into audit prompts."""

from __future__ import annotations

SEVERITY_RUBRIC = """\
SEVERITY DEFINITIONS — be strict and consistent. Pick the LOWEST band that
honestly fits; do not inflate.

  critical: Direct, immediate, unauthenticated impact. Blast radius = whole app
    or all users. Exploitable today, no chained conditions. Examples:
    - Live production secret committed (real AKIA*, sk_live_, ghp_, real DB URL).
    - Pre-auth RCE (eval/exec/popen/shell on attacker-controlled input).
    - SQL injection on a public endpoint exposing user data.
    - Authentication completely bypassable (alg=none accepted, no signature check).
    - publicly_accessible=true on a database holding user data.
    - 0.0.0.0/0 SSH/RDP on production infra.

  high: Exploitable with mild friction (needs a user account, a specific input
    shape, or chaining 2 small steps). Blast radius = many users or sensitive
    data. Examples:
    - SQL injection behind login.
    - Broken object-level authorization (IDOR) on user data.
    - MD5 / SHA1 used for password hashing or session tokens.
    - JWT with no expiry, or week+ expiry, or weak/default secret.
    - Server-side request forgery to internal network.
    - cors origin '*' on an authenticated API that returns user data.
    - Stored XSS in user-rendered content.
    - Public S3 bucket with non-trivial PII.

  medium: Realistic exploit chain but limited blast radius, OR a security
    control gap that materially weakens defense-in-depth. Examples:
    - Missing rate limit on /login or /reset (enables credential stuffing).
    - Missing CSRF protection on state-changing endpoints.
    - Verbose error messages leaking stack traces or internal paths.
    - Outdated dependency with a known CVE in a code path that IS reachable.
    - Missing security headers (CSP, HSTS, X-Frame-Options) on a real app.
    - Reflected XSS that requires social engineering.
    - Insecure deserialization on internal-only data.

  low: Best-practice violation, information disclosure, or hardening gap with
    no plausible direct exploit. Examples:
    - DEBUG=True committed to a config file.
    - Missing HttpOnly / SameSite on a non-session cookie.
    - Hardcoded EXAMPLE / TEST / FAKE credentials clearly labelled as such.
    - Tech-stack disclosure in HTTP headers (Server, X-Powered-By).
    - Outdated dependency with a CVE that is NOT reachable from app code.
    - TODO/FIXME comments referencing security work.

Calibration anchors (so the score makes sense across repos):
  - A typical hackathon / early-stage repo should have 0-2 critical, 2-6 high,
    4-10 medium, and the rest low.
  - If you find yourself emitting >3 critical findings, re-read each one and
    ask: is this REALLY pre-auth RCE / live secret / data-takeover? If not,
    drop it to high.
  - Hardcoded "EXAMPLE", "test", "dummy", "fake" credentials -> low at most
    (or skip if obviously a fixture).
  - Vulnerabilities only triggerable in dev mode (DEBUG=True path) -> max medium.
  - Set is_true_positive=False (don't drop the finding entirely) if you're
    less than ~70% sure it's exploitable in production.
"""

CVSS_AND_EXPOSURE_RUBRIC = """\
CVSS BASE SCORE — for every finding, fill `cvss_base` with a concrete
number in the band that matches your chosen `severity`:

  Critical: 9.0  9.5  10.0          (pick 9.0 by default)
  High:     7.0  7.5  8.0  8.5      (pick 7.5 by default)
  Medium:   4.0  5.0  6.0  6.5      (pick 5.0 by default)
  Low:      1.0  2.0  3.0           (pick 2.0 by default)

You do NOT need to compute the full CVSS vector. Just pick a number in
the right band. Move ABOVE the default only when BOTH conditions hold:
  (a) exploitation is mechanical / no chained conditions, AND
  (b) impact is total (full data takeover, full account takeover, RCE).

If you can't justify (a) AND (b), stay at the band default.

EXPOSURE — for every finding, fill `exposure` with where this code
actually runs in the deployed system. This is a context multiplier
applied during scoring; it does NOT change severity.

  production — Live request handlers, production routers/controllers,
    production IaC, production auth code, production DB layer, prod
    CI/CD workflows, anything in the main package that ships to users.

  internal — Admin tools, internal scripts, ops tooling, debug-only
    endpoints, anything that exists in prod but only privileged staff
    can hit.

  test — Anything under `tests/`, `__tests__/`, `spec/`, files matching
    `*_test.*` / `test_*.*`, `conftest.py`, fixtures. The bug is real
    but the code never serves a user.

  example — Sample / demo / tutorial code in `examples/`, `samples/`,
    `demo/`, `cookbook/`, notebooks intended as documentation.

  doc — Documentation snippets in `docs/`, README code blocks, sphinx
    sample apps, anything that ships only as text for humans to read.

CRITICAL CALIBRATION FOR FRAMEWORK / LIBRARY REPOS (FastAPI, Django,
React, etc.):
  - These repos rarely have `production` code at all — they ARE the
    framework, they don't run a service. Most findings will be in
    test/example/doc and should be tagged accordingly.
  - A hardcoded "secret" in `tests/test_security.py` is `exposure: test`
    even if the secret looks scary. Don't tag it production.
  - An `eval()` in `examples/advanced/custom_response.py` is
    `exposure: example` — it's pedagogical code, not a deployed app.

Be honest. The scoring engine multiplies CVSS by an exposure factor:
production=1.0, internal=0.6, test=0.15, example=0.05, doc=0.03. So
mis-tagging a doc snippet as production turns a 7.0 into 7.0 instead
of 0.21 — and the user loses trust in the whole report.
"""

COMPLIANCE_INSTRUCTIONS = """\
COMPLIANCE REFERENCES — for every finding, attach the compliance controls
it actually violates. Each reference is an OBJECT with three fields.

AUDIENCE NOTE: the reader is a startup founder or non-security engineer,
NOT a CISO. Your summary and your URL must both be useful to someone who
has 30 seconds to understand the issue. Homepage / framework-root URLs
are USELESS — link to the SPECIFIC control or article.

  id:      Short identifier shown to the user. Use canonical, recognisable
           form. Examples:
             "OWASP A01:2021"           "OWASP A03:2021"           "OWASP API1:2023"
             "GDPR Art. 32"             "GDPR Art. 5"
             "CCPA §1798.150"
             "SOC 2 CC6.1"              "SOC 2 CC7.2"
             "ISO 27001 A.9.2"          "ISO 27001 A.12.4"
             "NIST SP 800-53 AC-2"      "NIST SP 800-53 SC-13"
             "PCI DSS 6.5.1"            "PCI DSS 8.2.3"
             "HIPAA §164.312(a)(1)"

  summary: ONE sentence, ≤ 30 words, plain English. Two parts in one breath:
             (a) what the control requires, in concrete terms a non-expert
                 can act on, AND
             (b) why the founder should care (regulatory exposure, customer
                 trust, audit blocker, fine size — whichever is most real).
           Avoid jargon. No "shall", no "ensure that", no acronyms unless
           defined. Examples:
             OWASP A01:2021 →
               "Make sure logged-in users can only access their own data —
                broken access control is the #1 cause of data breaches in
                modern web apps."
             GDPR Art. 32 →
               "EU law requires real technical safeguards (encryption, access
                control) on personal data; failures can mean fines of up to
                4% of global annual revenue."
             SOC 2 CC6.1 →
               "Auditors will ask how you restrict who can reach production
                data; without proper access controls, you cannot pass a
                SOC 2 Type II audit — which most enterprise customers require."

  url:     A DEEP link to the specific control or article — NOT a homepage.
           This is non-negotiable: a founder clicking "Open standard" must
           land on text that explains THIS issue, not a directory page.

           Use these patterns. Replace the placeholder with the right value:

             OWASP Top 10 (Web):
               https://owasp.org/Top10/A0X_2021-Slug-With-Underscores/
               Real examples:
                 https://owasp.org/Top10/A01_2021-Broken_Access_Control/
                 https://owasp.org/Top10/A02_2021-Cryptographic_Failures/
                 https://owasp.org/Top10/A03_2021-Injection/
                 https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
                 https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/

             OWASP API Top 10 (2023):
               https://owasp.org/API-Security/editions/2023/en/0xaX-slug-name/
               Real examples:
                 https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
                 https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
                 https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/

             OWASP Cheatsheets (best operational guidance):
               https://cheatsheetseries.owasp.org/cheatsheets/<TOPIC>_Cheat_Sheet.html
               Real examples:
                 https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
                 https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
                 https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
                 https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
                 https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
                 https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html

             GDPR (deep article links):
               https://gdpr-info.eu/art-XX-gdpr/
               Real examples:
                 https://gdpr-info.eu/art-32-gdpr/   (security of processing)
                 https://gdpr-info.eu/art-5-gdpr/    (principles)
                 https://gdpr-info.eu/art-25-gdpr/   (privacy by design)
                 https://gdpr-info.eu/art-33-gdpr/   (breach notification)

             CCPA (specific section):
               https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.XXX
               Real example:
                 https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150

             NIST SP 800-53 (specific control):
               https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=XX-N
               Real examples:
                 https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-2
                 https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-13

             HIPAA (Cornell deep links):
               https://www.law.cornell.edu/cfr/text/45/164.XXX
               Real example:
                 https://www.law.cornell.edu/cfr/text/45/164.312   (technical safeguards)
                 https://www.law.cornell.edu/cfr/text/45/164.308   (administrative safeguards)

           Frameworks WITHOUT freely available deep links — use these
           founder-readable explainers (curated, plain-language) when
           a deep authoritative link does NOT exist:

             SOC 2 (specific TSC):
               https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
                 (official PDF — points to the criterion, but PDF root)
               If unsure, set url to null — DO NOT link to the AICPA homepage.

             ISO 27001:
               https://www.iso.org/standard/27001  or set url to null.
               The standard text is paywalled; do not pretend otherwise.

             PCI DSS (specific requirement):
               https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf
                 (PDF — open and Ctrl+F the requirement number)
               If unsure, set url to null.

  HARD RULES on URLs:
    - NEVER link to a framework HOMEPAGE (https://owasp.org/, https://gdpr-info.eu/,
      https://csrc.nist.gov/, https://www.iso.org/). That is useless to the
      reader and an instant credibility hit.
    - NEVER guess a URL. If you can't construct the deep link from the
      patterns above, set url to null and let the summary do the work.
    - URLs you produce must be syntactically plausible — use the EXACT
      patterns above with the right placeholders filled in.
    - When in doubt between two URL choices, prefer the OWASP Cheatsheet
      over the Top-10 page (the cheatsheet has actionable code guidance).

Rules on quantity:
  - Only attach a control if it is REALLY violated by this specific finding.
    Do not pad the list to look thorough.
  - Typical finding has 1–3 references. More than 4 is almost always padding.
  - For pure code-quality issues with no compliance angle, return an empty list.
"""
