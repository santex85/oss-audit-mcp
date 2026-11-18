"""Pure helpers: SPDX licence classification, CVSS v3 base score, OSV advisory summarising."""
import math
import re

STRONG = ("GPL", "EUPL", "OSL", "CC-BY-SA", "SLEEPYCAT", "RPL", "QPL")
NETWORK = ("AGPL", "SSPL", "RPSL")
WEAK = ("LGPL", "MPL", "EPL", "CDDL", "CPL", "MS-RL", "CECILL-C", "APSL")
PERMISSIVE = ("MIT", "APACHE", "BSD", "ISC", "ZLIB", "UNLICENSE", "0BSD", "CC0", "PSF", "PYTHON", "BSL-1.0",
              "ARTISTIC", "WTFPL", "UPL", "MIT-0", "X11", "POSTGRESQL", "NCSA", "BLUEOAK", "UNICODE", "OFL", "HPND")
FLAGGED = ("GPL", "AGPL", "LGPL", "MPL", "EPL")  # families explicitly flagged as copyleft


def _classify_id(lid: str) -> str:
    u = lid.upper().replace("+", "").strip("() ")
    if not u:
        return "unknown"
    if u in ("NON-STANDARD", "NOASSERTION", "UNKNOWN"):
        return "unknown"
    if any(u.startswith(p) for p in NETWORK):
        return "network-copyleft"
    if any(u.startswith(p) for p in WEAK):
        return "weak-copyleft"
    if any(u.startswith(p) for p in STRONG):
        return "strong-copyleft"
    if any(u.startswith(p) for p in PERMISSIVE):
        return "permissive"
    if u.startswith("LICENSEREF") or u.startswith("CC-BY-NC") or u.startswith("BUSL") or u.startswith("ELASTIC"):
        return "other/proprietary"
    return "unknown"


_RANK = {"permissive": 0, "weak-copyleft": 1, "strong-copyleft": 2, "network-copyleft": 3, "other/proprietary": 2,
         "unknown": 4}


def classify_expression(expr: str) -> dict:
    """Classify one SPDX expression. 'A OR B' -> the least restrictive option; 'A AND B' -> the most restrictive."""
    ids = [t for t in re.split(r"\s+(?:AND|OR|WITH)\s+|[()]", expr or "") if t.strip()]
    ids = [i.strip() for i in ids if i.strip()]
    if " WITH " in (expr or ""):  # exception ids (e.g. Classpath-exception-2.0) are not licences
        ids = [i for i in ids if "EXCEPTION" not in i.upper()]
    cats = {i: _classify_id(i) for i in ids}
    if not cats:
        return {"category": "unknown", "ids": []}
    if " OR " in expr and " AND " not in expr:
        cat = min(cats.values(), key=lambda c: _RANK[c])
    else:
        cat = max(cats.values(), key=lambda c: _RANK[c])
    return {"category": cat, "ids": ids, "perId": cats}


def license_summary(licenses: list[str]) -> dict:
    """Combine the licence list deps.dev returns for one version into a flag set."""
    if not licenses:
        return {"licenses": [], "category": "unknown", "copyleft": None, "copyleftFamilies": [],
                "permissiveAlternative": False, "note": "no licence detected"}
    parts = [classify_expression(e) for e in licenses]
    cat = max((p["category"] for p in parts), key=lambda c: _RANK[c])
    all_ids = [i for p in parts for i in p["ids"]]
    # anchored match: "LGPL-2.1" is reported as LGPL only, not also as GPL
    families = sorted({f for i in all_ids for f in FLAGGED if re.match(rf"^{f}(-|$)", i.upper().replace("+", ""))})
    copyleft_ids = [i for p in parts for i, c in (p.get("perId") or {}).items() if "copyleft" in c]
    perm_alt = any(" OR " in e for e in licenses) and cat == "permissive" and bool(copyleft_ids)
    out = {"licenses": licenses, "category": cat, "copyleft": "copyleft" in cat,
           "copyleftFamilies": families, "permissiveAlternative": perm_alt}
    if perm_alt:
        out["note"] = "dual-licensed: a permissive option exists alongside " + ", ".join(copyleft_ids)
    elif cat == "unknown":
        out["note"] = "licence not recognised (e.g. 'non-standard'); review manually"
    return out


# ---------------- CVSS v3.x base score ----------------
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62},
      "CIA": {"H": .56, "L": .22, "N": 0}}


def _roundup(x: float) -> float:
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def cvss3_score(vector: str) -> float | None:
    try:
        m = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": .85, "L": .68 if scope_changed else .62, "H": .5 if scope_changed else .27}[m["PR"]]
        iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
        expl = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        return _roundup(min((1.08 if scope_changed else 1) * (impact + expl), 10))
    except (KeyError, ValueError, IndexError):
        return None


def severity_label(score: float | None) -> str | None:
    if score is None:
        return None
    return "NONE" if score == 0 else "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def summarise_vuln(v: dict, pkg_name: str, include_details: bool = False) -> dict:
    sev = (v.get("database_specific") or {}).get("severity")
    sev = {"MODERATE": "MEDIUM"}.get(sev, sev)
    score, vector = None, None
    for s in v.get("severity") or []:
        if s.get("type") in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
            vector = s.get("score")
            score = cvss3_score(vector or "")
        elif s.get("type") == "CVSS_V4" and not vector:
            vector = s.get("score")
    fixed, ranges = [], []
    for a in v.get("affected") or []:
        pn = ((a.get("package") or {}).get("name") or "")
        if pn and pn.lower().replace("_", "-") != pkg_name.lower().replace("_", "-"):
            continue
        for r in a.get("ranges") or []:
            ev = r.get("events") or []
            fixed += [e["fixed"] for e in ev if "fixed" in e]
            intro = [e["introduced"] for e in ev if "introduced" in e]
            ranges.append({"introduced": intro[0] if intro else None,
                           "fixed": next((e["fixed"] for e in ev if "fixed" in e), None),
                           "lastAffected": next((e["last_affected"] for e in ev if "last_affected" in e), None)})
    out = {
        "id": v.get("id"), "aliases": v.get("aliases") or [], "summary": v.get("summary") or (v.get("details") or "")[:200],
        "severity": sev or severity_label(score) or "UNKNOWN", "cvssScore": score, "cvssVector": vector,
        "published": v.get("published"), "modified": v.get("modified"),
        "fixedVersions": sorted(set(fixed))[:20], "affectedRanges": ranges[:10],
        "withdrawn": v.get("withdrawn"), "url": f"https://osv.dev/vulnerability/{v.get('id')}",
    }
    if include_details:
        out["details"] = (v.get("details") or "")[:4000]
        out["references"] = [r.get("url") for r in (v.get("references") or [])][:15]
    return out


_PREF = ("GHSA-", "CVE-", "GO-", "RUSTSEC-", "PYSEC-")


def dedupe_vulns(items: list[dict]) -> list[dict]:
    """Merge advisories that alias each other (e.g. GHSA-x and PYSEC-y for the same CVE); keep the GHSA record."""
    items = sorted(items, key=lambda x: next((i for i, p in enumerate(_PREF) if x["id"].startswith(p)), 9))
    seen: set = set()
    out = []
    for it in items:
        keys = {it["id"], *it["aliases"]}
        if keys & seen:
            for o in out:
                if keys & ({o["id"], *o["aliases"]}):
                    o.setdefault("alsoKnownAs", []).append(it["id"])
                    if o["severity"] == "UNKNOWN" and it["severity"] != "UNKNOWN":
                        o["severity"], o["cvssScore"] = it["severity"], it["cvssScore"]
                    break
            seen |= keys
            continue
        seen |= keys
        out.append(it)
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4, "UNKNOWN": 5}
    out.sort(key=lambda x: (order.get(x["severity"], 5), x.get("published") or ""))
    return out
