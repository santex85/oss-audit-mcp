"""OSS Audit MCP server: open-source package due diligence (licences, release health, OpenSSF Scorecard, dependents,
known vulnerabilities) for npm, PyPI, Go, Maven, Cargo and NuGet.

Data: deps.dev API v3 (Google Open Source Insights; data CC-BY 4.0) and OSV.dev API v1. Both keyless and read-only.
Informational only: not legal advice about licences and not a substitute for a full security review.
"""
import asyncio
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

sys.path.insert(0, os.path.dirname(__file__))
from analysis import dedupe_vulns, license_summary, summarise_vuln  # noqa: E402

logging.getLogger("httpx").setLevel(logging.WARNING)

mcp = FastMCP("oss-audit", host=os.environ.get("HOST", "0.0.0.0"), port=int(os.environ.get("PORT", "8080")))

UA = "oss-audit-mcp/0.1 (+MCP server; reads public deps.dev and OSV.dev APIs)"
DEPS = "https://api.deps.dev"
OSV = "https://api.osv.dev/v1"
HTTP_TIMEOUT = 30
CALL_TIMEOUT = 120
MAX_BYTES = 12_000_000
MAX_LICENSE_ITEMS = 50
MAX_COMPARE = 10
MAX_VULNS = 100
OSV_PAGES = 3
CONCURRENCY = 6

ECOSYSTEMS = {  # input -> (deps.dev system, OSV ecosystem)
    "npm": ("npm", "npm"), "pypi": ("pypi", "PyPI"), "go": ("go", "Go"), "maven": ("maven", "Maven"),
    "cargo": ("cargo", "crates.io"), "nuget": ("nuget", "NuGet"),
}
ALIASES = {"python": "pypi", "pip": "pypi", "golang": "go", "crates": "cargo", "crates.io": "cargo", "rust": "cargo",
           "node": "npm", "js": "npm", "java": "maven", "dotnet": "nuget", ".net": "nuget"}

ATTRIBUTION = ("Package, licence, dependents and Scorecard data from deps.dev (Open Source Insights by Google), "
               "licensed CC-BY 4.0. Vulnerability data from OSV.dev (osv.dev).")
DISCLAIMER = ("Automated informational summary. Not legal advice on licence compliance and not a complete security "
              "audit. Licence data is detected from package metadata and can be incomplete or wrong.")


class ApiError(Exception):
    pass


class NotFound(ApiError):
    pass


class Api:
    def __init__(self):
        self.c = httpx.AsyncClient(headers={"User-Agent": UA, "Accept": "application/json"}, timeout=HTTP_TIMEOUT)
        self.sem = asyncio.Semaphore(CONCURRENCY)

    async def close(self):
        await self.c.aclose()

    async def req(self, method: str, url: str, body: dict | None = None):
        async with self.sem:
            async with self.c.stream(method, url, json=body) as r:
                if r.status_code == 404:
                    raise NotFound(f"not found: {url}")
                if r.status_code >= 400:
                    raise ApiError(f"HTTP {r.status_code} from {url}")
                buf = bytearray()
                async for chunk in r.aiter_bytes():
                    buf += chunk
                    if len(buf) > MAX_BYTES:
                        raise ApiError(f"response from {url} exceeded {MAX_BYTES} bytes")
        return json.loads(bytes(buf))


def _eco(ecosystem: str) -> str:
    e = (ecosystem or "").strip().lower()
    e = ALIASES.get(e, e)
    if e not in ECOSYSTEMS:
        raise ApiError(f"unsupported ecosystem {ecosystem!r}; use one of {', '.join(ECOSYSTEMS)}")
    return e


def _pkg_url(eco: str, name: str) -> str:
    return f"{DEPS}/v3/systems/{ECOSYSTEMS[eco][0]}/packages/{quote(name, safe='')}"


_PSEUDO = re.compile(r"\d{14}-[0-9a-f]{12}$")  # Go pseudo-versions (untagged commits)
_PRE = re.compile(r"(?i)(dev|alpha|beta|rc|pre|preview|snapshot|canary|next|nightly|insiders)|\d(a|b)\d+$|-")


def _is_pre(v: str) -> bool:
    return bool(_PRE.search(v.split("+", 1)[0]))


def _repo_of(vinfo: dict) -> str | None:
    return next((p["projectKey"]["id"] for p in vinfo.get("relatedProjects") or []
                 if p.get("relationType") == "SOURCE_REPO"), None)


def _days_since(ts: str | None) -> int | None:
    if not ts:
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).days
    except ValueError:
        return None


async def _osv_vulns(api: Api, eco: str, name: str, version: str | None, include_details=False) -> tuple[list, bool]:
    body = {"package": {"name": name, "ecosystem": ECOSYSTEMS[eco][1]}}
    if version:
        body["version"] = version
    raw, truncated = [], False
    for _ in range(OSV_PAGES):
        d = await api.req("POST", f"{OSV}/query", body)
        raw += d.get("vulns") or []
        tok = d.get("next_page_token")
        if not tok:
            break
        body["page_token"] = tok
    else:
        truncated = True
    items = [summarise_vuln(v, name, include_details) for v in raw if not v.get("withdrawn")]
    return dedupe_vulns(items), truncated


def _sev_counts(vulns: list[dict]) -> dict:
    c: dict = {}
    for v in vulns:
        c[v["severity"]] = c.get(v["severity"], 0) + 1
    return c


async def _report(api: Api, eco: str, name: str, version: str | None, full: bool = True) -> dict:
    pkg = await api.req("GET", _pkg_url(eco, name))
    canonical = (pkg.get("packageKey") or {}).get("name") or name
    versions = [v for v in pkg.get("versions") or [] if not _PSEUDO.search(v["versionKey"]["version"])]
    default = next((v for v in versions if v.get("isDefault")), None)
    dated = sorted((v for v in versions if v.get("publishedAt")), key=lambda v: v["publishedAt"])
    stable = [v for v in dated if not _is_pre(v["versionKey"]["version"])]
    if default and _is_pre(default["versionKey"]["version"]) and stable:
        default = stable[-1]  # registry default is a pre-release: report the newest stable release instead
    newest = dated[-1] if dated else default
    target = version or (default or newest or {}).get("versionKey", {}).get("version")
    if not target:
        raise ApiError("package has no versions")
    vinfo = await api.req("GET", f"{_pkg_url(eco, canonical)}/versions/{quote(target, safe='')}")

    repo = _repo_of(vinfo)
    latest_ver = (default or newest or {}).get("versionKey", {}).get("version")
    if not repo and latest_ver and latest_ver != target:  # older versions often lack repo metadata
        try:
            repo = _repo_of(await api.req("GET", f"{_pkg_url(eco, canonical)}/versions/{quote(latest_ver, safe='')}"))
        except ApiError:
            pass

    async def project():
        if not repo:
            return None
        try:
            return await api.req("GET", f"{DEPS}/v3/projects/{quote(repo, safe='')}")
        except ApiError:
            return None

    async def dependents():
        try:
            return await api.req("GET", f"{DEPS}/v3alpha/systems/{ECOSYSTEMS[eco][0]}/packages/{quote(canonical, safe='')}"
                                        f"/versions/{quote(target, safe='')}:dependents")
        except ApiError:
            return None

    proj, deps, (vulns, vtrunc) = await asyncio.gather(project(), dependents(),
                                                       _osv_vulns(api, eco, canonical, target))
    year_ago = [v for v in dated if (_days_since(v["publishedAt"]) or 99999) <= 365]
    lic = license_summary(vinfo.get("licenses") or [])
    sc = (proj or {}).get("scorecard")
    checks = {c["name"]: c.get("score") for c in (sc or {}).get("checks") or []}
    scorecard = sc and {
        "overallScore": sc.get("overallScore"), "date": sc.get("date"),
        "checks": checks if full else {k: checks.get(k) for k in ("Maintained", "Code-Review", "Vulnerabilities",
                                                                 "Security-Policy", "Branch-Protection") if k in checks},
    }
    days_latest = _days_since((newest or {}).get("publishedAt"))
    flags = []
    if vinfo.get("isDeprecated"):
        flags.append(f"version deprecated: {vinfo.get('deprecatedReason') or 'no reason given'}")
    if days_latest is not None and days_latest > 730:
        flags.append(f"no release in {days_latest} days")
    if lic["category"] == "unknown":
        flags.append("licence unknown/non-standard")
    elif lic["copyleft"]:
        flags.append(f"copyleft licence ({lic['category']})")
    hi = sum(1 for v in vulns if v["severity"] in ("HIGH", "CRITICAL"))
    if hi:
        flags.append(f"{hi} HIGH/CRITICAL known vulnerabilities in {target}")
    elif vulns:
        flags.append(f"{len(vulns)} known vulnerabilities in {target}")
    if sc and sc.get("overallScore") is not None and sc["overallScore"] < 4:
        flags.append(f"low OpenSSF Scorecard ({sc['overallScore']})")
    if checks.get("Maintained") == 0:
        flags.append("Scorecard 'Maintained' check is 0 (no recent activity)")
    if version and latest_ver and version != latest_ver:
        flags.append(f"not the default/latest version ({latest_ver})")
    if not repo:
        flags.append("no source repository linked")

    out = {
        "ecosystem": eco, "name": canonical, "version": target, "versionPublishedAt": vinfo.get("publishedAt"),
        "latestVersion": latest_ver, "latestVersionPublishedAt": (default or {}).get("publishedAt"),
        "latestReleaseAt": (newest or {}).get("publishedAt"),
        "daysSinceLatestRelease": days_latest, "releasesLast12Months": len(year_ago), "versionsTotal": len(versions),
        "firstReleaseAt": dated[0]["publishedAt"] if dated else None, "deprecated": vinfo.get("isDeprecated"),
        "license": lic,
        "dependents": deps and {**{k: deps.get(k) for k in ("dependentCount", "directDependentCount",
                                                            "indirectDependentCount")},
                                **({"note": "0 can mean deps.dev has not computed dependents for this package/version"}
                                   if not deps.get("dependentCount") else {})},
        "repository": repo and {
            "id": repo, "stars": (proj or {}).get("starsCount"), "forks": (proj or {}).get("forksCount"),
            "openIssues": (proj or {}).get("openIssuesCount"), "license": (proj or {}).get("license"),
        },
        "scorecard": scorecard,
        "vulnerabilities": {"count": len(vulns), "bySeverity": _sev_counts(vulns), "truncated": vtrunc,
                            "items": [{k: v[k] for k in ("id", "severity", "cvssScore", "summary", "fixedVersions")}
                                      for v in vulns[: (25 if full else 5)]]},
        "flags": flags,
        "links": {"depsDev": f"https://deps.dev/{ECOSYSTEMS[eco][0]}/{quote(canonical, safe='')}/{quote(target, safe='')}",
                  **{l["label"].lower(): l["url"] for l in (vinfo.get("links") or [])[:6] if l.get("label")}},
    }
    if not full:
        out.pop("links")
    return out


async def _run(fn):
    api = Api()
    try:
        return await asyncio.wait_for(fn(api), timeout=CALL_TIMEOUT)
    except asyncio.TimeoutError:
        return {"error": f"timed out after {CALL_TIMEOUT}s"}
    except NotFound as e:
        return {"error": str(e)}
    except ApiError as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        await api.close()


@mcp.tool()
async def package_report(ecosystem: str, name: str, version: str | None = None) -> dict:
    """Due-diligence report for one open-source package version.

    ecosystem: one of npm, pypi, go, maven, cargo, nuget.
    name: package name as published. Examples: npm "express" or "@types/node"; pypi "requests"; go module
      "github.com/gin-gonic/gin"; maven "group:artifact" e.g. "org.apache.logging.log4j:log4j-core"; cargo "serde";
      nuget "Newtonsoft.Json".
    version: exact version string (e.g. "4.21.2", Go "v1.9.1"); default = the registry's default/latest version.
    Returns licence(s) with copyleft classification, latest version and release recency, releases in the last
    12 months, dependents count (deps.dev), linked repository stars/forks/issues, OpenSSF Scorecard (overall +
    per-check), known vulnerabilities from OSV.dev with severity and fixed versions, and red-flag list.
    """
    async def run(api):
        e = _eco(ecosystem)
        r = await _report(api, e, name.strip(), (version or "").strip() or None)
        return {**r, "attribution": ATTRIBUTION, "disclaimer": DISCLAIMER}
    return await _run(run)


def _parse_item(item) -> tuple[str, str, str | None]:
    if isinstance(item, dict):
        return item.get("ecosystem", ""), item.get("name", ""), item.get("version")
    s = str(item).strip()
    if ":" not in s:
        raise ApiError(f"bad item {s!r}: use 'ecosystem:name@version'")
    eco, rest = s.split(":", 1)
    at = rest.rfind("@")
    if at > 0:
        return eco, rest[:at], rest[at + 1:] or None
    return eco, rest, None


@mcp.tool()
async def check_licenses(packages: list[str | dict]) -> dict:
    """Licence table for up to 50 packages, with a copyleft flag (GPL/AGPL/LGPL/MPL/EPL and similar).

    packages: items as strings "ecosystem:name@version" (version optional -> default version), e.g.
      "npm:express@4.21.2", "pypi:requests", "npm:@angular/core@17.0.0", "maven:org.hibernate:hibernate-core@5.6.15.Final",
      "go:github.com/gin-gonic/gin@v1.9.1", "cargo:serde", "nuget:Newtonsoft.Json@13.0.3";
      or objects {"ecosystem": "npm", "name": "express", "version": "4.21.2"}.
    Returns {"rows": [{package, version, licenses, category (permissive | weak-copyleft | strong-copyleft |
    network-copyleft | other/proprietary | unknown), copyleft, copyleftFamilies, permissiveAlternative, error}],
    "summary": counts per category, "copyleftPackages": [...]}.
    """
    async def run(api):
        if len(packages) > MAX_LICENSE_ITEMS:
            raise ApiError(f"at most {MAX_LICENSE_ITEMS} packages per call (got {len(packages)})")

        async def one(item):
            try:
                eco, name, ver = _parse_item(item)
                e = _eco(eco)
                name = name.strip()
                if not ver:
                    pkg = await api.req("GET", _pkg_url(e, name))
                    d = next((v for v in pkg.get("versions") or [] if v.get("isDefault")), None)
                    if not d:
                        raise ApiError("no default version")
                    name, ver = pkg["packageKey"]["name"], d["versionKey"]["version"]
                vi = await api.req("GET", f"{_pkg_url(e, name)}/versions/{quote(ver, safe='')}")
                ls = license_summary(vi.get("licenses") or [])
                return {"package": f"{e}:{vi['versionKey']['name']}", "version": ver,
                        **{k: ls[k] for k in ("licenses", "category", "copyleft", "copyleftFamilies",
                                              "permissiveAlternative")}, **({"note": ls["note"]} if "note" in ls else {})}
            except Exception as ex:  # per-row errors do not fail the table
                return {"package": str(item if not isinstance(item, dict) else f"{item.get('ecosystem')}:{item.get('name')}"),
                        "error": str(ex)}

        rows = await asyncio.gather(*[one(p) for p in packages])
        summary: dict = {}
        for r in rows:
            k = r.get("category", "error")
            summary[k] = summary.get(k, 0) + 1
        return {"rows": rows, "summary": summary,
                "copyleftPackages": [f"{r['package']}@{r['version']}" for r in rows if r.get("copyleft")],
                "attribution": ATTRIBUTION, "disclaimer": DISCLAIMER}
    return await _run(run)


@mcp.tool()
async def vulnerabilities(ecosystem: str, name: str, version: str | None = None, include_details: bool = False,
                          limit: int = 50) -> dict:
    """Known vulnerabilities (OSV.dev advisories) for a package, or for one exact version.

    ecosystem: npm, pypi, go, maven, cargo or nuget. name: as in package_report.
    version: exact version -> only advisories affecting it; omitted -> every advisory ever filed for the package.
    include_details: add advisory text (capped at 4,000 chars) and reference URLs.
    limit: max advisories returned (1-100, default 50).
    Advisories that alias each other (GHSA/PYSEC/CVE for the same issue) are merged. Each item has id, aliases,
    summary, severity (GitHub rating, else derived from the CVSS v3 vector), cvssScore, fixedVersions, url.
    Sorted CRITICAL -> HIGH -> MEDIUM -> LOW -> UNKNOWN.
    """
    limit = max(1, min(int(limit), MAX_VULNS))

    async def run(api):
        e = _eco(ecosystem)
        vulns, trunc = await _osv_vulns(api, e, name.strip(), (version or "").strip() or None, include_details)
        return {"ecosystem": e, "name": name, "version": version, "count": len(vulns), "bySeverity": _sev_counts(vulns),
                "returned": min(limit, len(vulns)), "truncatedUpstream": trunc, "vulnerabilities": vulns[:limit],
                "note": None if vulns else "No advisories in OSV for this query. That does not prove the package is safe.",
                "attribution": ATTRIBUTION}
    return await _run(run)


@mcp.tool()
async def compare_packages(ecosystem: str, names: list[str]) -> dict:
    """Side-by-side health comparison of up to 10 alternative packages in one ecosystem (default versions).

    ecosystem: npm, pypi, go, maven, cargo or nuget.
    names: e.g. ["axios", "got", "node-fetch"] or ["requests", "httpx", "aiohttp"]. "name@version" pins a version.
    Returns {"table": [{name, version, latestReleaseAt, daysSinceLatestRelease, releasesLast12Months, license,
    licenseCategory, dependents, stars, scorecard, maintainedCheck, vulnsInVersion, highOrCritical, deprecated,
    flags}], "highlights": {...best per metric}}. Errors are reported per row.
    """
    async def run(api):
        if not names or len(names) > MAX_COMPARE:
            raise ApiError(f"pass 1-{MAX_COMPARE} package names")
        e = _eco(ecosystem)

        async def one(n):
            nm, _, ver = n.strip().rpartition("@") if n.strip().rfind("@") > 0 else (n.strip(), "", "")
            try:
                r = await _report(api, e, nm, ver or None, full=False)
            except Exception as ex:
                return {"name": n, "error": str(ex)}
            sc = r.get("scorecard") or {}
            return {
                "name": r["name"], "version": r["version"], "latestReleaseAt": r["latestReleaseAt"],
                "daysSinceLatestRelease": r["daysSinceLatestRelease"], "releasesLast12Months": r["releasesLast12Months"],
                "license": ", ".join(r["license"]["licenses"]) or None, "licenseCategory": r["license"]["category"],
                "dependents": (r.get("dependents") or {}).get("dependentCount"),
                "stars": (r.get("repository") or {}).get("stars"), "scorecard": sc.get("overallScore"),
                "maintainedCheck": (sc.get("checks") or {}).get("Maintained"),
                "vulnsInVersion": r["vulnerabilities"]["count"],
                "highOrCritical": sum(v for k, v in r["vulnerabilities"]["bySeverity"].items() if k in ("HIGH", "CRITICAL")),
                "deprecated": r["deprecated"], "flags": r["flags"],
            }

        table = await asyncio.gather(*[one(n) for n in names])
        ok = [t for t in table if "error" not in t]

        def best(key, hi=True):
            vals = [t for t in ok if t.get(key) is not None]
            if not vals:
                return None
            b = (max if hi else min)(vals, key=lambda t: t[key])
            return {"name": b["name"], key: b[key]}

        return {"ecosystem": e, "table": table,
                "highlights": {"mostDependents": best("dependents"), "highestScorecard": best("scorecard"),
                               "mostStars": best("stars"), "mostRecentRelease": best("daysSinceLatestRelease", hi=False),
                               "fewestVulns": best("vulnsInVersion", hi=False)},
                "attribution": ATTRIBUTION, "disclaimer": DISCLAIMER}
    return await _run(run)


from starlette.requests import Request  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "healthy"})


if __name__ == "__main__":
    mcp.run(transport=os.environ.get("MCP_TRANSPORT", "streamable-http"))
