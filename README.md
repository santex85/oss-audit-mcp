# OSS Audit MCP server (open-source package due diligence)

An MCP server that lets AI agents vet open-source dependencies before adoption, in a licence review, or during
technical due diligence. For **npm, PyPI, Go, Maven, Cargo (crates.io) and NuGet** it reports licences with copyleft
classification, release recency, dependents count, the linked repository's OpenSSF Scorecard, and known
vulnerabilities with severity and fixed versions. It reads deps.dev and OSV.dev live and needs no API key.

> **Not legal advice and not a full security audit.** Licence data is detected from package metadata and can be
> incomplete or wrong (e.g. `non-standard`). A clean vulnerability result only means OSV has no advisory, not that the
> code is safe.

## Tools

| Tool | What it does |
|---|---|
| `package_report` | One package version: licence + copyleft category, latest version, release recency, releases in the last 12 months, dependents, repo stars/forks/issues, OpenSSF Scorecard (overall + checks), OSV vulnerabilities, red flags |
| `check_licenses` | Licence table for up to 50 packages, with a copyleft flag (GPL/AGPL/LGPL/MPL/EPL and similar), category counts and per-row errors |
| `vulnerabilities` | OSV advisories for a package, or for one exact version. Aliases are merged, items are sorted by severity, and each has fixed versions |
| `compare_packages` | Side-by-side health table for up to 10 alternatives in one ecosystem, plus the best package per metric |

### Example calls

```jsonc
// package_report
{"ecosystem": "npm", "name": "express"}
//   -> 5.3.0, MIT (permissive), 115k dependents, repo 69.7k stars, Scorecard 8.5, 0 vulns, flags []
{"ecosystem": "maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}
//   -> 8 advisories incl. 2 CRITICAL (Log4Shell), flag "not the default/latest version (2.25.5)"
{"ecosystem": "go", "name": "github.com/gin-gonic/gin"}

// check_licenses (strings "ecosystem:name@version", version optional; or objects)
{"packages": ["npm:express@4.21.2", "pypi:requests", "maven:org.hibernate:hibernate-core@5.6.15.Final",
              "go:github.com/gin-gonic/gin@v1.9.1", "cargo:serde", "nuget:Newtonsoft.Json@13.0.3",
              {"ecosystem": "pypi", "name": "PyQt5"}]}
//   -> hibernate-core LGPL-2.1-or-later (weak-copyleft), PyQt5 GPL-3.0 (strong-copyleft), the rest permissive

// vulnerabilities
{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}        // 5 advisories: 3 HIGH, 2 MEDIUM
{"ecosystem": "pypi", "name": "django", "limit": 5, "include_details": true}   // all 160+ ever filed, top 5

// compare_packages
{"ecosystem": "pypi", "names": ["requests", "httpx", "aiohttp", "urllib3@1.26.0"]}
{"ecosystem": "npm", "names": ["axios", "node-fetch", "got"]}
```

Package naming: npm `express`, `@types/node`; PyPI `requests` (case-insensitive); Go module path
`github.com/gin-gonic/gin`; Maven `groupId:artifactId`; Cargo `serde`; NuGet `Newtonsoft.Json`. The ecosystem accepts
aliases such as `python`, `rust`, `crates.io`, `golang` and `dotnet`.

### Licence categories

`permissive` · `weak-copyleft` (LGPL, MPL, EPL, CDDL, …) · `strong-copyleft` (GPL, EUPL, OSL, CC-BY-SA, …) ·
`network-copyleft` (AGPL, SSPL) · `other/proprietary` (LicenseRef, BUSL, Elastic, CC-BY-NC) · `unknown`.
An `A OR B` expression takes the least restrictive option and sets `permissiveAlternative` when a copyleft option is
also offered. `A AND B` takes the most restrictive. `copyleftFamilies` lists GPL/AGPL/LGPL/MPL/EPL hits explicitly.
Licence exceptions (`WITH Classpath-exception-2.0`) are not weighed, so review those by hand.

### Severity

The GitHub advisory rating is used where OSV has one (MODERATE is shown as MEDIUM). Otherwise the server computes
the CVSS v3.x base score from the vector. CVSS v4-only advisories without a rating show `UNKNOWN`. Advisories that
alias each other (GHSA / PYSEC / CVE / GO / RUSTSEC) are merged into one entry, which keeps the GHSA record and lists
the others in `alsoKnownAs`.

## Limits and data caveats

- "Latest version" is the registry default. When that default is a pre-release (e.g. `1.0.0.dev6`), the newest
  stable release is used instead. `latestReleaseAt` is the newest publish of any version, including pre-releases. Go
  pseudo-versions (untagged commits) are excluded from version counts.
- Dependents come from deps.dev's **v3alpha** `:dependents` endpoint. It can change, and it returns 0 or nothing for
  some ecosystems/packages (e.g. Cargo `serde` shows 0; Go and NuGet return none). A note is added when the count is 0.
- Repository, stars and Scorecard depend on deps.dev linking a source repo. Older versions often lack the link, so
  the latest version's link is used as a fallback. Scorecard results are weekly snapshots.
- `vulnerabilities` without a version follows up to 3 OSV result pages. `truncatedUpstream` is set if more exist.
- Caps: 50 packages per `check_licenses` call, 10 per `compare_packages` call, 100 advisories returned, 6 concurrent
  upstream requests, 30 s HTTP timeout, 120 s per tool call, 12 MB per upstream response.

## Data sources and attribution

- **deps.dev API v3** (Open Source Insights, Google), `https://api.deps.dev`. Its generated data is licensed
  **CC-BY 4.0**, so every response carries an `attribution` field. Keep it when you redistribute results.
  Attribution: "Package, licence, dependents and Scorecard data from deps.dev (Open Source Insights by Google),
  licensed CC-BY 4.0."
- **OSV.dev API v1**, `https://api.osv.dev`. Advisory records are aggregated from upstream databases (GitHub
  Advisory Database, PyPA, Go, RustSec, …) under those sources' own licences. I did not check OSV's terms during this
  build. Check them before commercial use.
- The User-Agent is `oss-audit-mcp/0.1 (+MCP server; ...)`.

## Run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python src/server.py                         # streamable-http on 0.0.0.0:8080, endpoint /mcp
PORT=8097 .venv/bin/python src/server.py               # other port
MCP_TRANSPORT=stdio .venv/bin/python src/server.py     # stdio, for local MCP clients
.venv/bin/python tests/live_test.py                    # live smoke test of every tool
```

Environment variables: `HOST` (default `0.0.0.0`), `PORT` (default `8080`), `MCP_TRANSPORT` (`streamable-http`, `stdio` or `sse`; default `streamable-http`). No API key is needed.

`mcpize.yaml` describes the build and start commands for MCPize.

## Use with Claude Desktop or another MCP client

Local (stdio). Clone the repo, create the venv as above, then add this to `claude_desktop_config.json`
(or your client's MCP config), with the paths changed to where you cloned it:

```json
{
  "mcpServers": {
    "oss-audit": {
      "command": "/path/to/oss-audit-mcp/.venv/bin/python",
      "args": ["/path/to/oss-audit-mcp/src/server.py"],
      "env": {"MCP_TRANSPORT": "stdio"}
    }
  }
}
```

Remote (streamable HTTP). Run `.venv/bin/python src/server.py` on a server and point any client that supports
remote MCP servers at `http://<host>:8080/mcp`. `GET /health` returns `{"status": "healthy"}`.

## License

MIT, see [LICENSE](LICENSE). The data returned by the tools stays under the terms of its sources (see above).
