"""Normalize compliance refs and back-fill missing ``url`` fields for the report UI.

Regex scanners emit ``compliance: ["OWASP-A03", "SOC2-CC6.1"]`` (strings). The
synthesize step coerces those to objects. LLMs often omit ``url``; we attach
canonical links when the ``id`` matches known patterns.
"""

from __future__ import annotations

import re
from typing import Any

# Scanner short tags and common forms → deep links.
_ID_TO_URL: dict[str, str] = {
    "OWASP-A01": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
    "OWASP-A02": "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
    "OWASP-A03": "https://owasp.org/Top10/A03_2021-Injection/",
    "OWASP-A04": "https://owasp.org/Top10/A04_2021-Insecure_Design/",
    "OWASP-A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
    "OWASP-A06": "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
    "OWASP-A07": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    "OWASP-A08": "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
    "OWASP-A09": "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
    "OWASP-A10": "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
    "GDPR-Art.5": "https://gdpr-info.eu/art-5-gdpr/",
    "GDPR-Art.13": "https://gdpr-info.eu/art-13-gdpr/",
    "GDPR-Art.32": "https://gdpr-info.eu/art-32-gdpr/",
    "CCPA-§1798": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150",
    "CCPA-§1798.100": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.100",
    "CCPA-§1798.150": "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.150",
    "NIST SP 800-53 AC-2": "https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-2",
    "NIST SP 800-53 SC-13": "https://csrc.nist.gov/projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-13",
}

_TSC_PDF = (
    "https://www.aicpa-cima.com/resources/download/"
    "2017-trust-services-criteria-with-revised-points-of-focus-2022"
)
_ID_TO_URL["SOC2-CC6.1"] = _TSC_PDF
_ID_TO_URL["SOC2-CC6.6"] = _TSC_PDF
_ID_TO_URL["SOC2-CC7.1"] = _TSC_PDF
_ID_TO_URL["SOC2-CC7.2"] = _TSC_PDF
_ID_TO_URL["ISO27001-A.9"] = "https://www.iso.org/standard/54534.html"
_ID_TO_URL["ISO27001-A.12"] = "https://www.iso.org/standard/54534.html"

_GDPR_KNOWN_ART = frozenset({"5", "13", "25", "32", "33"})


def _norm_key(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def _lookup_exact(raw: str) -> str | None:
    if raw in _ID_TO_URL:
        return _ID_TO_URL[raw]
    raw_l = raw.lower()
    for k, u in _ID_TO_URL.items():
        if k.lower() == raw_l:
            return u
    return None


def _guess_url_for_id(id_str: str) -> str | None:
    if not id_str:
        return None
    raw = _norm_key(id_str)
    hit = _lookup_exact(raw)
    if hit:
        return hit

    m = re.match(r"OWASP\s*A(0[1-9]|10)\s*:\s*2021", raw, re.IGNORECASE)
    if m:
        return _ID_TO_URL.get(f"OWASP-A{m.group(1)}")

    m2 = re.search(r"OWASP-?\s*A(0[1-9]|10)\b", raw, re.IGNORECASE)
    if m2:
        return _ID_TO_URL.get(f"OWASP-A{m2.group(1)}")

    if "gdpr" in raw.lower():
        m3 = re.search(r"Art\.?\s*(\d+)", raw, re.IGNORECASE)
        if m3 and m3.group(1) in _GDPR_KNOWN_ART:
            return f"https://gdpr-info.eu/art-{m3.group(1)}-gdpr/"

    if "ccpa" in raw.lower():
        if "1798.100" in raw or "1798-100" in raw:
            return _ID_TO_URL.get("CCPA-§1798.100")
        if "1798.150" in raw or "1798-150" in raw:
            return _ID_TO_URL.get("CCPA-§1798.150")

    m4 = re.search(r"800-53[:\s]+([A-Z]{1,3})-?\s*(\d+)", raw, re.IGNORECASE)
    if m4:
        fam, num = m4.group(1).upper(), m4.group(2)
        ctrl = f"{fam}-{num}"
        return (
            f"https://csrc.nist.gov/projects/risk-management/sp800-53-controls/"
            f"release-search#!/control?version=5.1&number={ctrl}"
        )

    if re.search(r"SOC\s*2|Trust Services", raw, re.IGNORECASE) and re.search(
        r"CC\s*[67]\.\d", raw, re.IGNORECASE
    ):
        return _TSC_PDF

    return None


def coerce_compliance_item(ref: Any) -> dict | None:
    """Turn strings or partial dicts into a plain dict ``{id, summary, url}``."""
    if isinstance(ref, str):
        s = _norm_key(ref)
        if not s:
            return None
        return {
            "id": s,
            "summary": "",
            "url": _guess_url_for_id(s),
        }
    if isinstance(ref, dict):
        rid = ref.get("id")
        if not rid:
            return None
        u = ref.get("url")
        u = u if isinstance(u, str) and u.strip() else None
        out = {
            "id": _norm_key(str(rid)),
            "summary": str(ref.get("summary") or "").strip(),
            "url": u,
        }
        if not out["url"]:
            out["url"] = _guess_url_for_id(out["id"])
        return out
    return None


def enrich_compliance_list(items: list[Any]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for ref in items:
        d = coerce_compliance_item(ref)
        if not d:
            continue
        if d["id"] in seen:
            continue
        seen.add(d["id"])
        out.append(d)
    return out
