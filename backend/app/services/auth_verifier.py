"""Independent SPF/DKIM/DMARC verification (AUTH-VERIFY).

This module VERIFIES authentication — it does not merely parse an upstream
MX's Authentication-Results. Parse-only is not verification: a parsed
"spf=pass" is the receiving MX's claim about some earlier hop, while an
independent check re-evaluates SPF against DNS, re-validates the DKIM
signature cryptographically, and re-applies DMARC policy + alignment here.

Core rules enforced everywhere:
- unavailable != pass. A check that could not run (offline mode, DNS failure,
  missing dependency, no headers) yields status "unavailable" with risk 0 and
  an info indicator — it never counts as a pass.
- pass != safe. Every pass explanation carries the caveat that compromised
  legitimate accounts pass SPF/DKIM/DMARC.

All third-party imports (dnspython, dkimpy, pyspf) are guarded; a missing
library degrades that check to "unavailable", never to "pass" or a crash.
"""

from __future__ import annotations

import base64
import email.parser
import email.utils
import ipaddress
import logging
import re
from typing import Any, Optional

from app.services.dns_resolver import (
    DNSResolver,
    DNSUnavailable,
    LookupBudget,
    LookupBudgetExceeded,
    base_domain,
    get_default_resolver,
)

logger = logging.getLogger("cyberguard.auth.verify")

try:  # optional: production-grade SPF evaluator (uses its own dnspython I/O)
    import spf as _pyspf  # type: ignore
except Exception:  # pragma: no cover - exercised only without pyspf
    _pyspf = None

try:  # optional: DKIM crypto verification
    import dkim as _dkimpy  # type: ignore
except Exception:  # pragma: no cover - exercised only without dkimpy
    _dkimpy = None

PASS_NOT_SAFE_NOTE = (
    "auth pass does not prove benign — compromised legitimate accounts pass SPF/DKIM/DMARC"
)

_STATUS_TEXT = {
    "pass": "SPF pass",
    "fail": "SPF fail",
    "softfail": "SPF softfail",
    "neutral": "SPF neutral",
    "none": "no SPF record",
    "permerror": "SPF permerror",
    "unavailable": "SPF could not be verified",
}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def domain_of(sender: str) -> str:
    """Extract the domain from 'a@b', 'Name <a@b>', or 'a@b'."""
    if not sender:
        return ""
    addr = sender
    if "<" in sender and ">" in sender:
        addr = sender.split("<", 1)[1].rsplit(">", 1)[0]
    addr = addr.strip()
    if "@" in addr:
        return addr.rsplit("@", 1)[1].strip().lower().rstrip(".")
    return addr.lower().rstrip(".") if "." in addr else ""


def org_domain(domain: str) -> str:
    return base_domain(domain or "")


def _aligned(a: str, b: str, mode: str = "relaxed") -> bool:
    a, b = (a or "").lower().rstrip("."), (b or "").lower().rstrip(".")
    if not a or not b:
        return False
    if mode == "strict":
        return a == b
    return org_domain(a) == org_domain(b)


def extract_sender_ip(headers: dict[str, str]) -> Optional[str]:
    """Best-effort connecting-IP extraction from the first (topmost) Received
    header — the first untrusted hop as recorded by our own MX."""
    received = ""
    for k, v in (headers or {}).items():
        if k.lower() == "received":
            received = v or ""
            break
    if not received:
        return None
    m = re.search(r"\[([0-9a-fA-F.:]+)\]", received)
    if not m:
        m = re.search(r"\bfrom\s+\S+\s+\((?:[^)]*?)@?([0-9a-fA-F.:]+)\)", received)
    if not m:
        return None
    candidate = m.group(1)
    try:
        return str(ipaddress.ip_address(candidate.strip("[]")))
    except ValueError:
        return None


def _parse_header_block(raw_headers: str) -> dict[str, str]:
    msg = email.parser.Parser().parsestr(raw_headers, headersonly=True)
    return {str(k).lower(): str(v) for k, v in msg.items()}


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

def _spf_evaluator(
    ip: str,
    domain: str,
    sender: str,
    resolver: DNSResolver,
    budget: LookupBudget,
    depth: int = 0,
) -> dict[str, Any]:
    """Limited SPF check_host(): ip4/ip6/a/mx/include/exists/redirect/all.

    Macros are not expanded (best-effort literal lookup); pyspf handles the
    full grammar when the default dnspython transport is available.
    """
    if depth > 10:
        return {"status": "permerror", "reason": "SPF include/redirect depth exceeded", "domain": domain}
    txts = resolver.resolve(domain, "TXT")
    records = []
    for t in txts:
        cleaned = re.sub(r'"([^"]*)"', r"\1", t).strip()  # join dnspython quoted chunks
        if cleaned.lower().startswith("v=spf1"):
            records.append(cleaned)
    if not records:
        return {"status": "none", "reason": f"no SPF (v=spf1) TXT record on {domain}", "domain": domain}
    record = records[0]
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"status": "permerror", "reason": f"unparseable sender IP {ip!r}", "domain": domain}

    def mech_target(mech: str, default: str) -> str:
        body = mech.split(":", 1)[1] if ":" in mech else mech.split("/", 1)[0] if "/" in mech else ""
        body = body.split("/", 1)[0]
        return body or default

    def ip_present(target: str) -> bool:
        families = ("A",) if ip_obj.version == 4 else ("AAAA",)
        for fam in families:
            try:
                answers = resolver.resolve(target, fam)
            except DNSUnavailable:
                raise
            for ans in answers:
                for candidate in re.findall(r"[0-9a-fA-F.:]+", re.sub(r'"([^"]*)"', r"\1", ans)):
                    try:
                        if ipaddress.ip_address(candidate) == ip_obj:
                            return True
                    except ValueError:
                        continue
        return False

    redirect: Optional[str] = None
    for raw_term in record.split()[1:]:
        term = raw_term.strip()
        low = term.lower()
        if low.startswith("redirect="):
            redirect = term.split("=", 1)[1]
            continue
        if "=" in term.split(":", 1)[0] and low.startswith(("exp=",)):
            continue
        qualifier = "+"
        mech = term
        if term and term[0] in "+-~?":
            qualifier, mech = term[0], term[1:]
        m = mech.lower()
        matched = False
        if m == "all":
            matched = True
        elif m.startswith("ip4:"):
            try:
                matched = ip_obj.version == 4 and ip_obj in ipaddress.ip_network(mech[4:], strict=False)
            except ValueError:
                return {"status": "permerror", "reason": f"bad ip4 network {mech[4:]!r}", "domain": domain}
        elif m.startswith("ip6:"):
            try:
                matched = ip_obj.version == 6 and ip_obj in ipaddress.ip_network(mech[4:], strict=False)
            except ValueError:
                return {"status": "permerror", "reason": f"bad ip6 network {mech[4:]!r}", "domain": domain}
        elif m == "a" or m.startswith("a:") or m.startswith("a/"):
            budget.tick("a")
            matched = ip_present(mech_target(mech, domain))
        elif m == "mx" or m.startswith("mx:") or m.startswith("mx/"):
            budget.tick("mx")
            target = mech_target(mech, domain)
            matched = False
            mx_answers = resolver.resolve(target, "MX")[:10]
            for mx in mx_answers:
                budget.tick("mx-a")
                host = re.sub(r'"([^"]*)"', r"\1", mx).split()[-1].rstrip(".")
                if host and ip_present(host):
                    matched = True
                    break
        elif m.startswith("include:"):
            budget.tick("include")
            sub = _spf_evaluator(ip, mech.split(":", 1)[1], sender, resolver, budget, depth + 1)
            if sub["status"] == "pass":
                matched = True
            elif sub["status"] == "none":
                return {"status": "permerror", "reason": f"include:{mech[8:]} target has no SPF record", "domain": domain}
        elif m.startswith("exists:"):
            budget.tick("exists")
            answers = resolver.resolve(mech.split(":", 1)[1], "A")
            matched = len(answers) > 0
        else:
            continue  # unknown mechanism/modifier: skip (lenient, documented)
        if matched:
            status = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
            return {"status": status, "reason": f"matched {raw_term}", "domain": domain}

    if redirect:
        budget.tick("redirect")
        return _spf_evaluator(ip, redirect, sender, resolver, budget, depth + 1)
    return {"status": "neutral", "reason": "no SPF mechanism matched", "domain": domain}


def verify_spf(
    envelope_from: Optional[str],
    sender_ip: Optional[str],
    domain: Optional[str],
    resolver: Optional[DNSResolver] = None,
) -> dict[str, Any]:
    """Independent SPF verification against DNS. Pyspf is preferred when the
    default dnspython transport is in use (full RFC 7208 grammar + lookup
    cap); otherwise the limited in-house evaluator runs over the injected
    resolver. No IP or no domain => unavailable, never pass/fail."""
    resolver = resolver or get_default_resolver()
    domain = (domain or domain_of(envelope_from or "")).lower().rstrip(".")
    if not domain:
        return _unavailable("no sender domain available for SPF")
    if not sender_ip:
        return _unavailable(
            "no sender IP available (no Received chain) — SPF cannot be evaluated"
        )
    try:
        ipaddress.ip_address(sender_ip)
    except ValueError:
        return _unavailable(f"unparseable sender IP {sender_ip!r}")

    if _pyspf is not None and resolver.uses_default_transport:
        try:
            result, _code, reason = _pyspf.check(
                i=sender_ip,
                s=envelope_from or f"postmaster@{domain}",
                h=domain,
                timeout=resolver.timeout,
            )
            if result == "temperror":
                return _unavailable(f"SPF temporary DNS error: {reason}")
            return {"status": str(result), "reason": str(reason or "")[:200], "domain": domain}
        except DNSUnavailable as exc:
            return _unavailable(str(exc))
        except Exception as exc:  # pyspf internal error -> fall back
            logger.warning("pyspf crashed (%s); using limited SPF evaluator", exc)

    try:
        from app.core.config import get_settings

        budget = LookupBudget(get_settings().SPF_MAX_DNS_LOOKUPS)
        return _spf_evaluator(
            sender_ip, domain, envelope_from or f"postmaster@{domain}", resolver, budget
        )
    except LookupBudgetExceeded as exc:
        return {"status": "permerror", "reason": str(exc), "domain": domain}
    except DNSUnavailable as exc:
        return _unavailable(str(exc))


# ---------------------------------------------------------------------------
# DKIM
# ---------------------------------------------------------------------------

def _txt_record_bytes(value: str) -> bytes:
    """dnspython to_text() renders TXT as quoted chunks: '"a" "b"'. Join to a
    single logical record (the format dkimpy's dnsfunc expects)."""
    chunks = re.findall(r'"([^"]*)"', value)
    return "".join(chunks).encode("utf-8") if chunks else value.encode("utf-8")


def _dkim_signature_headers(raw_message: bytes) -> list[dict[str, str]]:
    msg = email.parser.BytesParser().parsebytes(raw_message, headersonly=True)
    tags = []
    for header, value in msg.items():
        if str(header).lower() != "dkim-signature":
            continue
        tags.append({
            t.split("=", 1)[0].strip().lower(): t.split("=", 1)[1].strip()
            for t in str(value).split(";")
            if "=" in t
        })
    return tags


def verify_dkim(
    raw_message: Optional[bytes],
    resolver: Optional[DNSResolver] = None,
    reconstructed: bool = False,
) -> dict[str, Any]:
    """Cryptographically validate every DKIM-Signature in raw_message.

    DNS key retrieval goes through our resolver (cache/breaker/offline). A
    signature that fails against a RECONSTRUCTED message is reported as
    unavailable (normalization may have altered signed bytes) rather than
    fail, so the realtime path cannot manufacture false +25 fails.
    """
    resolver = resolver or get_default_resolver()
    if raw_message is None:
        return _unavailable("no raw message bytes available for DKIM verification")
    if _dkimpy is None:
        return _unavailable("dkimpy not installed — DKIM crypto verification unavailable")

    signatures = _dkim_signature_headers(raw_message)
    if not signatures:
        return {"status": "none", "reason": "no DKIM-Signature header", "d": None}

    any_fail = False
    fail_reason = ""
    for idx, tags in enumerate(signatures):
        d = tags.get("d") or ""
        s = tags.get("s") or ""
        if not d or not s:
            any_fail = True
            fail_reason = "DKIM-Signature missing d=/s= tag"
            continue
        qname = f"{s}._domainkey.{d}"
        try:
            txts = resolver.resolve(qname, "TXT")
        except DNSUnavailable as exc:
            return _unavailable(f"DKIM key lookup failed for {qname}: {exc}")
        key_records = [_txt_record_bytes(t) for t in txts if _txt_record_bytes(t).startswith(b"v=DKIM1") or b"p=" in _txt_record_bytes(t)]
        if not key_records:
            # Signature names a selector with no published key: the signature
            # cannot be valid, but key rotation makes this ambiguous — no score.
            return {"status": "neutral", "reason": f"no DKIM key published at {qname}", "d": d, "selector": s}

        def dnsfunc(name: str, timeout: int = 5, _rec: bytes = key_records[0], **_kw: Any) -> bytes:
            return _rec

        verifier = _dkimpy.DKIM(raw_message)
        try:
            ok = bool(verifier.verify(dnsfunc=dnsfunc, idx=idx))
        except Exception as exc:
            ok = False
            fail_reason = f"{type(exc).__name__}: {exc}"
        if ok:
            return {"status": "pass", "reason": f"DKIM signature valid (d={d})", "d": d, "selector": s}
        any_fail = True
        fail_reason = fail_reason or f"DKIM signature invalid (d={d})"

    if any_fail:
        if reconstructed:
            return _unavailable(
                "DKIM signature did not verify against the reconstructed message; "
                "normalization may have altered signed bytes — treated as unverified, not failed"
            )
        return {"status": "fail", "reason": fail_reason or "DKIM signature invalid", "d": signatures[0].get("d")}
    return {"status": "neutral", "reason": "DKIM signatures present but unverifiable", "d": signatures[0].get("d")}


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def verify_dmarc(
    from_domain: Optional[str],
    spf_res: dict[str, Any],
    dkim_res: dict[str, Any],
    resolver: Optional[DNSResolver] = None,
) -> dict[str, Any]:
    """Fetch _dmarc.<from_domain> (falling back to the organizational domain),
    parse the policy, and re-apply RFC 7489 alignment locally."""
    resolver = resolver or get_default_resolver()
    from_domain = (from_domain or "").lower().rstrip(".")
    if not from_domain:
        return {"status": "unavailable", "reason": "no From domain for DMARC", "policy": None}
    if (
        spf_res.get("status") == "unavailable"
        and dkim_res.get("status") == "unavailable"
    ):
        # RFC 7489 pass/fail needs at least one evaluated authentication
        # mechanism; with neither, DMARC cannot "fail" — it is unavailable.
        # This also keeps header-less (manual) scans DNS-free and score-free.
        return {
            "status": "unavailable",
            "reason": "no SPF or DKIM results available to evaluate DMARC alignment",
            "policy": None,
        }

    record: Optional[str] = None
    try:
        for cand in dict.fromkeys([from_domain, org_domain(from_domain)]):
            if not cand:
                continue
            txts = resolver.resolve(f"_dmarc.{cand}", "TXT")
            for t in txts:
                cleaned = re.sub(r'"([^"]*)"', r"\1", t).strip()
                compact = cleaned.replace(" ", "").upper()
                if "V=DMARC1" in compact:
                    record = cleaned
                    break
            if record:
                break
    except DNSUnavailable as exc:
        return {"status": "unavailable", "reason": f"DMARC record lookup failed: {exc}", "policy": None}

    if not record:
        return {"status": "none", "reason": f"no DMARC record for {from_domain}", "policy": None, "domain": from_domain}

    tags = {
        t.split("=", 1)[0].strip().lower(): t.split("=", 1)[1].strip()
        for t in record.split(";")
        if "=" in t
    }
    policy = (tags.get("p") or "none").lower()
    adkim = (tags.get("adkim") or "relaxed").lower()
    aspf = (tags.get("aspf") or "relaxed").lower()

    spf_aligned = (
        spf_res.get("status") == "pass"
        and bool(spf_res.get("domain"))
        and _aligned(str(spf_res.get("domain")), from_domain, aspf)
    )
    dkim_aligned = (
        dkim_res.get("status") == "pass"
        and bool(dkim_res.get("d"))
        and _aligned(str(dkim_res.get("d")), from_domain, adkim)
    )
    status = "pass" if (spf_aligned or dkim_aligned) else "fail"
    return {
        "status": status,
        "policy": policy,
        "record": record[:200],
        "domain": from_domain,
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "reason": (
            "aligned via " + ("SPF" if spf_aligned else "DKIM")
            if status == "pass"
            else "neither SPF nor DKIM passes and aligns with the From domain"
        ),
    }


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def _score_and_indicators(
    spf_res: dict[str, Any],
    dkim_res: dict[str, Any],
    dmarc_res: dict[str, Any],
) -> tuple[int, list[dict[str, Any]]]:
    """AUTH-VERIFY scoring: spf fail +30 / softfail +15; dkim fail +25;
    dmarc fail p=reject +35 / p=quarantine +25 / p=none +10; alignment fail
    +20; all pass 0. Unavailable statuses score 0 and emit info indicators."""
    risk = 0
    indicators: list[dict[str, Any]] = []

    spf_status = spf_res.get("status")
    if spf_status == "fail":
        risk += 30
        indicators.append({
            "type": "auth_spf_fail", "severity": "high", "weight": 30,
            "description": f"Independent SPF verification failed: {spf_res.get('reason', '')}"[:200],
        })
    elif spf_status == "softfail":
        risk += 15
        indicators.append({
            "type": "auth_spf_softfail", "severity": "medium", "weight": 15,
            "description": f"Independent SPF verification softfailed: {spf_res.get('reason', '')}"[:200],
        })
    elif spf_status == "unavailable":
        indicators.append({
            "type": "auth_spf_unavailable", "severity": "info", "weight": 0,
            "description": f"SPF could not be independently verified: {spf_res.get('reason', '')}"[:200],
        })

    dkim_status = dkim_res.get("status")
    if dkim_status == "fail":
        risk += 25
        indicators.append({
            "type": "auth_dkim_fail", "severity": "high", "weight": 25,
            "description": f"Independent DKIM verification failed: {dkim_res.get('reason', '')}"[:200],
        })
    elif dkim_status == "unavailable":
        indicators.append({
            "type": "auth_dkim_unavailable", "severity": "info", "weight": 0,
            "description": f"DKIM could not be independently verified: {dkim_res.get('reason', '')}"[:200],
        })

    dmarc_status = dmarc_res.get("status")
    if dmarc_status == "fail":
        policy = (dmarc_res.get("policy") or "none").lower()
        add = {"reject": 35, "quarantine": 25}.get(policy, 10)
        risk += add
        indicators.append({
            "type": "auth_dmarc_fail",
            "severity": "high" if policy in ("reject", "quarantine") else "medium",
            "weight": add,
            "description": f"Independent DMARC verification failed (p={policy}): {dmarc_res.get('reason', '')}"[:200],
        })
        # Alignment fail is a distinct spoof signal only for enforcing
        # policies (p=reject/quarantine): p=none domains opted out of DMARC
        # enforcement, so misalignment there is already covered by the +10.
        if (
            policy in ("reject", "quarantine")
            and not (dmarc_res.get("spf_aligned") or dmarc_res.get("dkim_aligned"))
        ):
            risk += 20
            indicators.append({
                "type": "auth_alignment_fail", "severity": "high", "weight": 20,
                "description": "Authenticated domain is not aligned with the From domain "
                               "(possible spoof of a protected brand)",
            })
    elif dmarc_status == "unavailable":
        indicators.append({
            "type": "auth_dmarc_unavailable", "severity": "info", "weight": 0,
            "description": f"DMARC could not be independently verified: {dmarc_res.get('reason', '')}"[:200],
        })

    return min(risk, 100), indicators


def _build_explanation(spf_res: dict, dkim_res: dict, dmarc_res: dict, risk: int) -> str:
    parts = []
    for name, res in (("SPF", spf_res), ("DKIM", dkim_res), ("DMARC", dmarc_res)):
        status = res.get("status")
        detail = res.get("reason") or ""
        if name == "DMARC" and res.get("policy"):
            detail = f"policy p={res['policy']}; {detail}"
        parts.append(f"{name}: {status}" + (f" ({detail})" if detail else ""))
    text = "Independent authentication verification — " + "; ".join(parts) + f". Verification risk contribution: {risk}/100."
    if any(r.get("status") == "pass" for r in (spf_res, dkim_res, dmarc_res)):
        text += f" {PASS_NOT_SAFE_NOTE}."
    return text


def verify_all(ctx: dict[str, Any], resolver: Optional[DNSResolver] = None) -> dict[str, Any]:
    """Run all three independent checks for one message context.

    ctx keys: sender, headers (dict), body_text (str), optional raw_message
    (bytes) and raw_headers (str). Returns {spf, dkim, dmarc, indicators,
    risk_score, source, explanation} with source in
    "independent" | "unavailable".
    """
    resolver = resolver or get_default_resolver()
    headers = dict(ctx.get("headers") or {})
    body_text = ctx.get("body_text") or ctx.get("body") or ""
    sender = ctx.get("sender") or ""
    from_domain = domain_of(sender)
    raw_message: Optional[bytes] = ctx.get("raw_message")
    raw_headers: Optional[str] = ctx.get("raw_headers")

    if raw_headers and not raw_message:
        parsed = _parse_header_block(raw_headers)
        headers = {**headers, **parsed}
        header_bytes = raw_headers.encode("utf-8", "replace")
        body_bytes = body_text.encode("utf-8", "replace") if body_text else b""
        raw_message = header_bytes + (b"\r\n\r\n" + body_bytes if body_bytes else b"")

    envelope_from = (headers.get("return-path") or "").strip().strip("<>") or sender
    sender_ip = ctx.get("sender_ip") or extract_sender_ip(headers)

    if resolver.offline:
        offline_reason = "DNS offline mode (DNS_OFFLINE=true) — independent verification skipped"
        spf_res = _unavailable(offline_reason)
        dkim_res = _unavailable(offline_reason)
        dmarc_res = {"status": "unavailable", "reason": offline_reason, "policy": None}
        risk, indicators = _score_and_indicators(spf_res, dkim_res, dmarc_res)
        return {
            "spf": spf_res, "dkim": dkim_res, "dmarc": dmarc_res,
            "indicators": indicators, "risk_score": risk,
            "source": "unavailable",
            "explanation": _build_explanation(spf_res, dkim_res, dmarc_res, risk),
        }

    spf_res = verify_spf(envelope_from, sender_ip, from_domain, resolver)

    if raw_message:
        dkim_res = verify_dkim(raw_message, resolver)
    elif headers:
        reconstructed = b"".join(
            f"{k}: {v}\r\n".encode("utf-8", "replace") for k, v in headers.items()
        ) + (b"\r\n" + body_text.encode("utf-8", "replace") if body_text else b"")
        dkim_res = verify_dkim(reconstructed, resolver, reconstructed=True)
    else:
        dkim_res = _unavailable("no message headers available for DKIM verification")

    dmarc_res = verify_dmarc(from_domain, spf_res, dkim_res, resolver)

    risk, indicators = _score_and_indicators(spf_res, dkim_res, dmarc_res)
    ran = [
        r for r in (spf_res, dkim_res, dmarc_res)
        if r.get("status") not in (None, "unavailable")
    ]
    source = "independent" if ran else "unavailable"
    return {
        "spf": spf_res, "dkim": dkim_res, "dmarc": dmarc_res,
        "indicators": indicators, "risk_score": risk,
        "source": source,
        "explanation": _build_explanation(spf_res, dkim_res, dmarc_res, risk),
    }


def verify_or_parse(
    signals: dict[str, Any],
    ctx: dict[str, Any],
    resolver: Optional[DNSResolver] = None,
) -> dict[str, Any]:
    """Realtime entry point (analysis_service): try independent verification;
    if unavailable, fall back to the MX-parsed Authentication-Results that
    fetch_service stored in signals, marked source="mx_parsed". The fallback
    reuses the legacy indicator types and applies the same scoring table so
    parse and verify produce comparable risk."""
    result = verify_all(ctx, resolver)
    if result.get("source") != "unavailable":
        return result

    spf_p = str(signals.get("spf") or "").lower()
    dkim_p = str(signals.get("dkim") or "").lower()
    dmarc_p = str(signals.get("dmarc") or "").lower()
    if not (spf_p or dkim_p or dmarc_p):
        return result  # nothing parsed either — stay "unavailable"

    indicators: list[dict[str, Any]] = []
    risk = 0
    if spf_p == "fail":
        risk += 30
        indicators.append({"type": "spf_fail", "severity": "high", "weight": 15,
                           "description": f"Sender Policy Framework (SPF) check failed ({spf_p})"})
    elif spf_p == "softfail":
        risk += 15
        indicators.append({"type": "spf_softfail", "severity": "medium", "weight": 10,
                           "description": f"Sender Policy Framework (SPF) softfail ({spf_p})"})
    if dkim_p == "fail":
        risk += 25
        indicators.append({"type": "dkim_fail", "severity": "medium", "weight": 10,
                           "description": f"DKIM digital signature failed ({dkim_p})"})
    if dmarc_p == "fail":
        risk += 35  # policy unknown at parse time: worst case per AUTH-VERIFY table
        indicators.append({"type": "dmarc_fail", "severity": "high", "weight": 15,
                           "description": f"DMARC authentication failed ({dmarc_p}; policy unknown at parse time)"})

    return {
        "spf": {"status": spf_p or "unavailable", "reason": "parsed from Authentication-Results"},
        "dkim": {"status": dkim_p or "unavailable", "reason": "parsed from Authentication-Results"},
        "dmarc": {"status": dmarc_p or "unavailable", "reason": "parsed from Authentication-Results", "policy": None},
        "indicators": indicators,
        "risk_score": min(risk, 100),
        "source": "mx_parsed",
        "explanation": (
            "Independent verification was unavailable; authentication states are the receiving "
            "MX's parsed Authentication-Results (parse-only, not independently verified)."
        ),
    }


def manual_auth_section(
    sender: str,
    body: str,
    raw_headers: Optional[str],
    resolver: Optional[DNSResolver] = None,
) -> dict[str, Any]:
    """Manual/paste path (D4): verification runs only when the caller supplies
    raw_headers. Absence yields the auth_headers_missing info indicator and a
    response warning — never a pass."""
    if not raw_headers or not raw_headers.strip():
        warning = "SPF/DKIM/DMARC cannot be verified: manual text scan carries no message headers"
        return {
            "verification": {
                "spf": _unavailable("no message headers"),
                "dkim": _unavailable("no message headers"),
                "dmarc": {"status": "unavailable", "reason": "no message headers", "policy": None},
                "indicators": [],
                "risk_score": 0,
                "source": "unavailable",
                "explanation": warning,
            },
            "indicators": [{
                "type": "auth_headers_missing", "severity": "info", "weight": 0,
                "description": warning,
            }],
            "warnings": [warning],
        }
    result = verify_all({"sender": sender, "body_text": body, "raw_headers": raw_headers}, resolver)
    return {"verification": result, "indicators": list(result.get("indicators") or []), "warnings": []}
