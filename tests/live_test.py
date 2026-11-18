"""Live smoke test: calls every tool against the real APIs. Run: .venv/bin/python tests/live_test.py"""
import asyncio, json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import server  # noqa: E402
from analysis import cvss3_score, license_summary  # noqa: E402


def show(name, r, ok):
    s = json.dumps(r, ensure_ascii=False)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {len(s)} bytes | {s[:700]}\n")
    return bool(ok)


async def timed(name, coro):
    t = time.time()
    r = await coro
    return f"{name} ({time.time() - t:.1f}s)", r


async def main():
    res = []
    tools = await server.mcp.list_tools()
    res.append(show("list_tools", [t.name for t in tools], len(tools) == 4))

    ok = (cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
          and cvss3_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N") == 6.1
          and license_summary(["GPL-3.0-or-later"])["copyleft"] and not license_summary(["MIT OR Apache-2.0"])["copyleft"]
          and license_summary(["LGPL-2.1-only"])["copyleftFamilies"] == ["LGPL"])
    res.append(show("offline cvss/licence", "ok" if ok else "mismatch", ok))

    n, r = await timed("package_report npm express", server.package_report("npm", "express"))
    res.append(show(n, r, r.get("license", {}).get("category") == "permissive" and r.get("latestVersion")
                    and (r.get("dependents") or {}).get("dependentCount") and (r.get("scorecard") or {}).get("overallScore")))
    n, r = await timed("package_report pypi requests 2.19.0", server.package_report("pypi", "requests", "2.19.0"))
    res.append(show(n, r, r.get("vulnerabilities", {}).get("count", 0) >= 3 and r.get("flags")))
    n, r = await timed("package_report maven log4j-core 2.14.1",
                       server.package_report("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"))
    res.append(show(n, r, r.get("vulnerabilities", {}).get("bySeverity", {}).get("CRITICAL", 0) >= 1))
    n, r = await timed("package_report go gin", server.package_report("go", "github.com/gin-gonic/gin"))
    res.append(show(n, r, r.get("license", {}).get("licenses") and r.get("version", "").startswith("v")))
    n, r = await timed("package_report cargo serde", server.package_report("cargo", "serde"))
    res.append(show(n, r, r.get("license", {}).get("category") == "permissive"))
    n, r = await timed("package_report nuget Newtonsoft.Json", server.package_report("nuget", "Newtonsoft.Json"))
    res.append(show(n, r, r.get("license", {}).get("licenses")))
    n, r = await timed("package_report missing", server.package_report("npm", "zz-no-such-package-xq-123"))
    res.append(show(n, r, "error" in r))
    n, r = await timed("package_report bad eco", server.package_report("cobol", "x"))
    res.append(show(n, r, "error" in r))

    items = ["npm:express@4.21.2", "pypi:requests", "npm:@angular/core@17.0.0", "pypi:mysql-connector-python",
             "maven:org.hibernate:hibernate-core@5.6.15.Final", "go:github.com/gin-gonic/gin@v1.9.1", "cargo:serde",
             "nuget:Newtonsoft.Json@13.0.3", {"ecosystem": "npm", "name": "ghostscript4js"}, "pypi:PyQt5",
             "npm:no-such-pkg-zz-999"]
    n, r = await timed("check_licenses (11 items)", server.check_licenses(items))
    rows = r.get("rows", [])
    res.append(show(n, {"summary": r.get("summary"), "copyleft": r.get("copyleftPackages"),
                        "rows": [(x.get("package"), x.get("licenses"), x.get("category"), x.get("error")) for x in rows]},
                    len(rows) == 11 and len(r.get("copyleftPackages", [])) >= 2 and "error" in rows[-1]))
    n, r = await timed("check_licenses >50", server.check_licenses(["npm:a"] * 51))
    res.append(show(n, r, "error" in r))

    n, r = await timed("vulnerabilities npm lodash 4.17.15", server.vulnerabilities("npm", "lodash", "4.17.15"))
    res.append(show(n, r, r.get("count", 0) >= 3 and r["vulnerabilities"][0]["severity"] in ("CRITICAL", "HIGH")))
    n, r = await timed("vulnerabilities pypi django all", server.vulnerabilities("pypi", "django", limit=5,
                                                                              include_details=True))
    res.append(show(n, r, r.get("count", 0) > 50 and r.get("returned") == 5 and r["vulnerabilities"][0].get("details")))
    n, r = await timed("vulnerabilities cargo serde 1.0.200", server.vulnerabilities("cargo", "serde", "1.0.200"))
    res.append(show(n, r, r.get("count") == 0 and r.get("note")))

    n, r = await timed("compare_packages pypi", server.compare_packages("pypi", ["requests", "httpx", "aiohttp", "urllib3@1.26.0"]))
    t = r.get("table", [])
    res.append(show(n, r, len(t) == 4 and all("error" not in x for x in t) and r["highlights"]["mostDependents"]))
    n, r = await timed("compare_packages npm", server.compare_packages("npm", ["axios", "node-fetch", "got", "zz-none-x-1"]))
    t = r.get("table", [])
    res.append(show(n, r, len(t) == 4 and "error" in t[-1] and t[0].get("stars")))
    print(f"{sum(res)}/{len(res)} passed")


asyncio.run(main())
