# tooling-mcp — MCP wrappers for offensive-security CLIs (nmap, nuclei, gobuster, ffuf, httpx, semgrep, trivy)

[![status](https://img.shields.io/badge/status-active-brightgreen)](#)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![mcp](https://img.shields.io/badge/MCP-1.x-6E40C9)](https://modelcontextprotocol.io)
[![transport](https://img.shields.io/badge/transport-stdio-informational)](#)
[![license](https://img.shields.io/badge/license-MIT-lightgrey)](#license)
[![scope](https://img.shields.io/badge/scope-authorized%20only-critical)](#safety--scope)

---

## 60-Second Overview

**What this is.** A single stdio MCP server (`server.py`) that exposes seven
offensive-security CLIs — `nmap`, `nuclei`, `gobuster`, `ffuf`, `httpx`,
`semgrep`, `trivy` — plus a `tool_health` probe, as structured MCP tools.

**Why it exists.** LLMs cannot run CLI tools. They can only call tools their
host exposes. If you want Claude Code (or any MCP client — Cursor, Codex,
Continue, Zed) to drive a pentest, each binary needs a wrapper that:

- builds its argv safely (no `shell=True`, no string concat),
- enforces a timeout ceiling,
- parses the tool's native output (nmap XML, nuclei JSONL, ffuf JSON,
  semgrep SARIF, trivy JSON) into a small dict the model can reason over.

Writing seven ad-hoc wrappers across projects is noise. This repo is the
one wrapper, registered once per workstation.

**Use case — Claude Desktop pentesting flow.** Operator says "I own
`192.0.2.10`, map it and look for low-hanging web vulns." Claude plans:

```
nmap(target=192.0.2.10, flags="-sV -sC -Pn")
  → sees :80, :443 open, nginx 1.18
httpx(target=https://192.0.2.10)
  → confirms live, grabs title + tech
gobuster(url=https://192.0.2.10, mode="dir")
  → finds /admin, /backup
nuclei(url=https://192.0.2.10, severity="critical,high")
  → runs the templates, returns findings
```

Four tool calls, zero shelling out from the model, structured results the
model can summarise. The operator reviews each call before it runs
(Claude Desktop asks).

---

## For Interviewers

### Problem statement

LLMs are good planners and bad terminals. Giving a model raw shell access
breaks on three axes:

1. **Capability** — the model has no shell; the host must expose each tool.
2. **Safety** — a model that assembles argv as a string is one hallucinated
   backtick away from `rm -rf`. Argv must be built as a list, never a string.
3. **Legibility** — raw nmap stdout, nuclei JSONL, trivy JSON (30 KB+) burn
   tokens and derail reasoning. Each tool needs a parser that returns the
   shape the model actually uses (open ports, finding counts by severity,
   SARIF path + summary).

`tooling-mcp` solves all three for seven standard offensive tools behind a
single MCP server. Register once (`claude mcp add ...`), use everywhere.

### Skills demonstrated

| Skill                          | Where in the code                                                      |
|--------------------------------|------------------------------------------------------------------------|
| MCP protocol (FastMCP, stdio)  | `server.py:31`, `server.py:91`, `server.py:304-305`                    |
| Subprocess isolation           | `server.py:55-75` — `subprocess.run`, list argv, no `shell=True`       |
| Argument whitelisting          | `server.py:186-187` (gobuster mode), `server.py:291-292` (trivy mode)  |
| Per-tool output parsing        | `server.py:127-153` XML, `server.py:167-178` JSONL, `server.py:266-278` SARIF |
| Timeout handling               | `server.py:51` `MAX_TIMEOUT`, `server.py:60` clamp, `server.py:70-71` catch |
| Pydantic schemas (via FastMCP) | Each `@mcp.tool()` — type hints auto-generate the input schema         |
| Env-override binary paths      | `server.py:36-43` — `NMAP_BIN`, `NUCLEI_BIN`, etc.                     |
| Structured error returns       | `server.py:71-75` — rc 124 timeout, rc 127 missing, rc 1 other         |

### Architecture

```
                        ┌──────────────────────────────────┐
                        │   MCP client (Claude Code,       │
                        │   Cursor, Codex, Zed, ...)       │
                        └──────────────┬───────────────────┘
                                       │ MCP over stdio
                                       │ (JSON-RPC frames)
                                       ▼
            ┌──────────────────────────────────────────────┐
            │  server.py  (FastMCP "tooling")              │
            │  ──────────────────────────────────────────  │
            │  @mcp.tool()  nmap        → _run → nmap bin  │
            │  @mcp.tool()  nuclei      → _run → nuclei    │
            │  @mcp.tool()  gobuster    → _run → gobuster  │
            │  @mcp.tool()  ffuf        → _run → ffuf      │
            │  @mcp.tool()  httpx       → _run → httpx     │
            │  @mcp.tool()  semgrep     → _run → semgrep   │
            │  @mcp.tool()  trivy       → _run → trivy     │
            │  @mcp.tool()  tool_health → version probe    │
            │                                              │
            │  _run(cmd, timeout):                         │
            │    subprocess.run(cmd, capture_output=True,  │
            │                   text=True, timeout=…)      │
            │    → {cmd, rc, stdout, stderr}               │
            └───────┬──────────────────────────────────────┘
                    │ argv list (never a shell string)
                    ▼
   ┌─────────┬─────────┬──────────┬──────┬───────┬─────────┬───────┐
   │  nmap   │ nuclei  │ gobuster │ ffuf │ httpx │ semgrep │ trivy │
   │ (XML)   │ (JSONL) │ (stdout) │(JSON)│(JSONL)│ (SARIF) │(JSON) │
   └─────────┴─────────┴──────────┴──────┴───────┴─────────┴───────┘
                    │   each binary writes native format
                    ▼
            ┌──────────────────────────────────────────────┐
            │  parsers in server.py                        │
            │  nmap:    xml.etree → {hosts:[{ip,ports}]}   │
            │  nuclei:  json.loads per line → [findings]   │
            │  ffuf:    read tmp JSON → results[]          │
            │  httpx:   json.loads per line → results[]    │
            │  semgrep: SARIF → {total, by_level, path}    │
            │  trivy:   json.loads(stdout) → report        │
            └──────────────────────────────────────────────┘
```

### Design decisions

**Subprocess, not Python bindings.** Each tool has a Python binding
somewhere (`python-nmap`, `semgrep` as a lib, etc.), and every one of them
lags the CLI by months and ships bugs the CLI already fixed. The CLI is the
canonical interface — operators debug the CLI, maintainers test the CLI,
exploit chains assume the CLI. Wrapping the binary means a `apt upgrade
nmap` is a free upgrade; a binding means I'm pinned to whatever version the
PyPI maintainer last published. Cost: one `subprocess.run` per call. Price
of a port scan: milliseconds of fork overhead vs. minutes of scan. Not a
contest.

**Arg injection prevention — argv list, no `shell=True`.** Every call site
uses `subprocess.run([bin, "-flag", "value", target], ...)`. The target
string could contain `;`, `|`, `$()`, backticks — none of them matter
because the shell is never invoked. `shlex.split(flags)` is used only for
the pre-set flag string (operator-supplied, not model-supplied in the
dangerous way), and even there the result is a list, concatenated into the
argv list, never serialised back. See `server.py:62`, `server.py:112`,
`server.py:235`. A hostile prompt that tries to inject
`"192.0.2.10; rm -rf /"` becomes a single argv element passed to `nmap`,
which rejects it as an invalid target. No shell, no injection.

**Timeout policy — hard ceiling, per-call override.** `MAX_TIMEOUT = 1800`
(30 min) in `server.py:51` is the floor-of-the-ceiling: every call clamps
its requested timeout down to this (`server.py:60`). The default per-tool
timeout is tuned to the tool: `nmap` 300s, `nuclei` 300s, `gobuster` 600s,
`ffuf` 600s, `httpx` 120s, `semgrep` 300s, `trivy` 300s. A model that asks
for `timeout=99999` gets 1800. A runaway subprocess returns `rc=124` with
`stderr="timeout after Ns"` (`server.py:70-71`) — the model gets a
first-class timeout signal, not a hang.

**Why temp files for XML/SARIF/ffuf-JSON, not stdout.** nmap can emit XML
to stdout (`-oX -`), but mixing XML with the human progress stream is
flaky; `-oX <path>` is the documented happy path. Semgrep SARIF files are
large (10–100 KB easily); returning the path + a summary keeps the MCP
response small (model doesn't need the full SARIF, humans do). Ffuf's JSON
output mode writes a file by design. Temp files are `delete=False` at
create then `os.unlink`'d in a `finally` — see `server.py:109-124` and
`server.py:213-228`.

**No scope guard in-process.** Deliberate. A scope allowlist here would
either be too strict (blocks legitimate internal targets) or too loose
(theatre). Scope lives upstream — the VPN config, the engagement rules,
the operator. This server trusts its caller; the caller is responsible for
authorization. The `## Safety / Scope` section below spells this out.

### Metrics

| Metric                 | Value                                                 |
|------------------------|-------------------------------------------------------|
| Tools exposed          | 7 CLI wrappers + 1 health probe = 8                   |
| LOC (`server.py`)      | 306                                                   |
| Runtime deps           | 1 (`mcp[cli]>=1.0,<2.0`)                              |
| Output formats parsed  | XML (nmap), JSONL (nuclei, httpx), JSON (ffuf, trivy), SARIF (semgrep), raw (gobuster) |
| Timeout ceiling        | 1800 s (30 min) hard cap, per-tool defaults below     |
| Transport              | stdio (JSON-RPC)                                      |
| Test suite             | none — see FAQ "where are the tests"                  |

---

## Quick Start

```bash
# 1. Clone + venv
git clone https://github.com/<you>/tooling-mcp.git
cd tooling-mcp
python3 -m venv venv
venv/bin/pip install -r requirements.txt

# 2. Verify binaries are on PATH (Kali ships most of these)
venv/bin/python -c "from server import tool_health; import json; print(json.dumps(tool_health(), indent=2))"

# 3. Register with Claude Code (user scope — available in every project)
claude mcp add --scope user tooling -- \
  $PWD/venv/bin/python $PWD/server.py

# 4. In Claude Code, first scan (replace with YOUR authorised target):
#    "Run nmap -sV against 192.0.2.10"
#    → Claude calls nmap(target="192.0.2.10", flags="-sV -Pn")
```

Expected `tool_health` output on Kali:

```json
{
  "nmap":     {"present": true, "path": "/usr/bin/nmap",     "version": "Nmap version 7.94SVN ..."},
  "nuclei":   {"present": true, "path": "/usr/bin/nuclei",   "version": "..."},
  "gobuster": {"present": true, "path": "/usr/bin/gobuster", "version": "..."},
  "ffuf":     {"present": true, "path": "/usr/bin/ffuf",     "version": "..."},
  "httpx":    {"present": true, "path": "/usr/bin/httpx",    "version": "..."},
  "semgrep":  {"present": true, "path": "/usr/local/bin/semgrep", "version": "..."},
  "trivy":    {"present": true, "path": "/usr/bin/trivy",    "version": "..."}
}
```

Any `present: false` → install that CLI (see Technical Reference below).
The server still starts; calls to a missing tool return `rc: 127, stderr:
"binary not found: ..."`.

---

## Tool Reference

All tools exposed via `@mcp.tool()` in `server.py`. Timeouts are seconds.

| Tool          | Required args         | Key optional args                                     | Default timeout | Returns                                                       |
|---------------|-----------------------|-------------------------------------------------------|-----------------|---------------------------------------------------------------|
| `tool_health` | —                     | —                                                     | 5 s each        | `{tool: {present, path, version}}`                            |
| `nmap`        | `target: str`         | `flags="-sV -sC -Pn -T4"`, `top_ports=1000`, `timeout=300` | 300 s      | `{cmd, rc, stderr, parsed: {hosts: [{ip, hostname, ports}]}}` |
| `nuclei`      | `url: str`            | `severity="critical,high,medium"`, `templates=""`, `timeout=300` | 300 s | `{cmd, rc, stderr, findings: [...], finding_count}`           |
| `gobuster`    | `url: str`            | `mode="dir"` ∈ `{dir, dns, vhost, fuzz}`, `wordlist=""`, `extensions=""`, `threads=10`, `timeout=600` | 600 s | `{cmd, rc, stdout, stderr}` |
| `ffuf`        | `url: str`            | `wordlist=""`, `mode="dir"` ∈ `{dir, raw}`, `filter_code="404"`, `timeout=600` | 600 s | `{cmd, rc, stderr, results: [...], result_count}` |
| `httpx`       | `target: str`         | `flags="-silent -status-code -title -tech-detect -json"`, `timeout=120` | 120 s | `{cmd, rc, stderr, results: [...]}` |
| `semgrep`     | `path: str`           | `config="auto"`, `timeout=300`                        | 300 s           | `{cmd, rc, stderr, summary: {total, by_level, sarif_path}}`   |
| `trivy`       | `target: str`         | `mode="image"` ∈ `{image, fs, repo, config}`, `severity="HIGH,CRITICAL"`, `timeout=300` | 300 s | `{cmd, rc, stderr, report: {...}}` |

Notes:

- `target` for `nmap` is any nmap target spec (host, CIDR, `file:targets.txt`).
- `url` for `nuclei` / `gobuster` / `ffuf` / `httpx` is a URL unless `mode="dns"`
  for gobuster (which treats it as a domain).
- `ffuf` with `mode="dir"` auto-appends `/FUZZ` if the URL doesn't contain it;
  `mode="raw"` requires `FUZZ` already in the URL.
- `semgrep` writes a SARIF to a tmp file and returns the path, not the full
  SARIF (SARIF files are too large for MCP response bodies).
- `trivy` modes: `image` (container image), `fs` (filesystem), `repo` (git repo),
  `config` (IaC misconfig scan).

---

## Examples

### 1. Recon chain — `nmap` → `ffuf` → `nuclei`

Operator says: "You can test `192.0.2.10`. Find open ports, enumerate web
content, scan for vulns."

```python
# Call 1 — port scan
nmap(target="192.0.2.10", flags="-sV -sC -Pn", top_ports=1000)
# → parsed.hosts[0].ports = [
#     {port: 22,  service: ssh,   product: OpenSSH, version: 8.9p1},
#     {port: 80,  service: http,  product: nginx,   version: 1.18.0},
#     {port: 443, service: https, product: nginx,   version: 1.18.0},
#   ]

# Call 2 — content discovery on the web port
ffuf(url="http://192.0.2.10/FUZZ",
     wordlist="/usr/share/wordlists/dirb/common.txt",
     filter_code="404")
# → results = [{url: /admin, status: 401, length: 42}, {url: /backup, ...}]

# Call 3 — vuln scan on the live URL
nuclei(url="http://192.0.2.10",
       severity="critical,high,medium")
# → findings = [{template-id: nginx-version, severity: info, matched-at: ...}, ...]
```

Three structured dicts. The model summarises; the human reviews each call.

### 2. SCA — Trivy container image scan

Operator: "Scan the production container for HIGH+CRITICAL CVEs."

```python
trivy(target="ghcr.io/acme/api:v2.3.1",
      mode="image",
      severity="HIGH,CRITICAL")
# → report.Results[*].Vulnerabilities = [
#     {VulnerabilityID: CVE-2024-XXXXX, PkgName: openssl, Severity: HIGH,
#      FixedVersion: 3.0.14-1, ...},
#     ...
#   ]
```

Pair with `cve-mcp` (sister project) to cross-reference each CVE against
EPSS / KEV / exploit-db.

### 3. SAST — Semgrep on a repo

Operator: "Run semgrep on `~/code/webapp`, give me the issue counts."

```python
semgrep(path="/home/tony/code/webapp", config="auto")
# → summary = {
#     total: 23,
#     by_level: {"error": 4, "warning": 12, "note": 7},
#     sarif_path: "/tmp/tmpXXXXXX.sarif"
#   }
```

Full SARIF stays on disk — the model gets counts, the operator opens the
file for triage. Pass the path to a SARIF viewer or into Defect Dojo /
GitHub Code Scanning.

### 4. Bonus — DNS subdomain brute

```python
gobuster(url="example.com",
         mode="dns",
         wordlist="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
         threads=20)
# → stdout: raw gobuster findings, one per line
```

Raw stdout is deliberate here — gobuster's DNS mode output is already
structured enough to parse downstream.

---

## Technical Reference

### Install — CLI prerequisites

Each tool's binary must be on `PATH` (or set `<TOOL>_BIN=/full/path`).

```bash
# Debian / Kali
sudo apt install nmap gobuster ffuf trivy

# ProjectDiscovery tools — Go install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# then: nuclei -update-templates

# Semgrep — pipx recommended
pipx install semgrep

# Wordlists
sudo apt install wordlists seclists
```

The server probes `shutil.which(<tool>)` at import time (`server.py:36-43`)
and falls back to a sensible path. Missing binaries don't block startup —
calls to a missing tool return `rc: 127`.

### Argument validation strategy

Three layers, defence in depth:

1. **Type coercion via FastMCP / Pydantic.** Each `@mcp.tool()` function
   signature declares types (`target: str`, `top_ports: int`,
   `mode: str`). FastMCP generates the JSON schema; the MCP client sends
   typed values; non-conforming calls fail at the protocol boundary.

2. **Mode whitelists for enum-like args.** `gobuster.mode` must be in
   `{"dir", "dns", "vhost", "fuzz"}` (`server.py:186-187`); `trivy.mode`
   must be in `{"image", "fs", "repo", "config"}` (`server.py:291-292`).
   Anything else returns `{"error": "invalid mode: <x>"}` without
   invoking the binary.

3. **Argv list, no shell.** Every `subprocess.run` call takes a list, not
   a string; `shell=True` appears nowhere in the codebase. The target
   string is one argv element — the shell is never invoked, so
   metacharacters (`;`, `|`, `$()`, backticks, newlines) are inert.
   `shlex.split(flags)` is used to tokenise the operator-set flag string
   into argv tokens, then those tokens join the argv list — the result
   never passes through a shell.

Wordlist args additionally get an `os.path.exists` guard (`server.py:189`,
`server.py:211`) so a model-hallucinated wordlist path returns an error
instead of a cryptic gobuster/ffuf failure.

### Timeout policy

- Hard ceiling: `MAX_TIMEOUT = 1800` seconds (`server.py:51`).
- Every call: `timeout = min(timeout, MAX_TIMEOUT)` (`server.py:60`).
- Per-tool defaults (seconds): nmap 300, nuclei 300, gobuster 600, ffuf
  600, httpx 120, semgrep 300, trivy 300, tool_health 5 per binary.
- Timeout result: `rc=124`, `stderr="timeout after Ns"`
  (`server.py:70-71`). The subprocess is killed by `subprocess.run`'s own
  timeout handling.

### Output parser locations

| Tool    | Format         | Parser                                 |
|---------|----------------|----------------------------------------|
| nmap    | XML (`-oX`)    | `_parse_nmap_xml()` — `server.py:127-153` (stdlib `xml.etree`) |
| nuclei  | JSONL (stdout) | inline — `server.py:167-178` (`json.loads` per line)           |
| ffuf    | JSON (file)    | inline — `server.py:219-224`                                   |
| httpx   | JSONL (stdout) | inline — `server.py:241-251`                                   |
| semgrep | SARIF (file)   | inline — `server.py:266-278` (count by `level`)                |
| trivy   | JSON (stdout)  | inline — `server.py:296-300`                                   |
| gobuster| raw stdout     | none — returned as-is                                          |

All parsers are stdlib-only. Zero extra dependencies.

### MCP registration

Claude Code (user scope, every project):

```bash
claude mcp add --scope user tooling -- \
  /home/tony/projects/tooling-mcp/venv/bin/python \
  /home/tony/projects/tooling-mcp/server.py
```

Cursor / Codex / Zed: add to the client's `mcpServers` config block,
transport `stdio`, command = python interpreter, args = `[server.py]`.

Verify from the client: ask "list your MCP tools" — you should see
`nmap`, `nuclei`, `gobuster`, `ffuf`, `httpx`, `semgrep`, `trivy`,
`tool_health` under the `tooling` server.

### Extending — adding a new CLI

To add `<newtool>`:

1. Add path resolution in the `TOOLS` dict at `server.py:35`:
   ```python
   "newtool": os.environ.get("NEWTOOL_BIN", shutil.which("newtool") or "newtool"),
   ```
2. Add a `@mcp.tool()`-decorated function below the existing seven. Pattern:
   ```python
   @mcp.tool()
   def newtool(target: str, flags: str = "...", timeout: int = 300) -> dict:
       """One-line description — the model sees this as the tool doc."""
       cmd = [TOOLS["newtool"], *shlex.split(flags), target]
       res = _run(cmd, timeout=timeout)
       # parse res["stdout"] into something structured
       return res
   ```
3. Restart the MCP server (Claude Code: `/mcp` → restart `tooling`).
4. Confirm with `tool_health` after extending it to include the new entry.

No registry file, no plugin system — one decorated function is the whole
contract. Adding one tool is ~20 lines.

---

## Safety / Scope

**Authorised scope only.** This server executes real scans against real
targets. Unauthorised scanning is illegal in most jurisdictions (US
CFAA 1030, UK Computer Misuse Act 1990, Canada Criminal Code s.342.1,
and equivalents). Only point it at systems you own or have explicit
written permission to test — HTB / THM machines, your own homelab, a
client under a signed SoW.

**No in-process scope guard.** The server has no allowlist / denylist of
targets. Scope enforcement is upstream — your VPN config, your engagement
rules, your judgement. This is deliberate: a token allowlist here would be
either too strict (blocking real work) or too loose (security theatre).
Trust is at the operator, not the wrapper.

**Output sanitation.** `stderr` is truncated to the last 2000 bytes
(`server.py:68`) to keep responses small and avoid leaking long verbose
error traces into model context. `stdout` is dropped after parsing for
tools that produce bulk structured output (`nuclei`, `httpx`, `trivy`)
to keep responses token-efficient.

**No `shell=True`, anywhere.** Every subprocess call is a list argv.
Model-supplied target strings become single argv elements; shell
metacharacters are inert. See `server.py:62`.

**No network calls from the server itself.** The server never opens a
socket, never calls out to a cloud API. All network traffic is from the
wrapped CLIs, on the operator's host, under the operator's network
policy.

**Review every call in your MCP client.** Claude Code / Claude Desktop
prompts for confirmation before invoking a tool. Leave this on. Read the
argv in the prompt. If the target isn't in scope, deny.

---

## Why This Was Built

Part of a four-piece AI-assisted pentesting portfolio:

- **p5-atlas** — autonomous HTB pipeline (6 agents, tiered Claude, auto mode).
- **cve-mcp** — CVE / EPSS / KEV lookup over MCP.
- **wazuh-mcp** — SIEM triage over MCP (query, pivot, acknowledge alerts).
- **tooling-mcp** (this repo) — the hands. Every other piece plans; this one
  acts on the box.

The thesis: a senior pentester's value is in the plan, not in retyping
`nmap -sV`. Give the LLM safe, structured access to the standard toolkit
and the plan becomes the only interesting part of the loop. The repo
exists because every other MCP tooling attempt I saw either (a) wrapped
one tool deeply, or (b) wrapped many tools shallowly with `shell=True`.
This splits the difference — seven tools, each parsed properly, each
argv-safe, in 306 lines.

---

## FAQ

**Q: Why not just let the model shell out via a generic `run_command` tool?**
A generic shell tool is a loaded gun pointed at the model's hallucinations.
A hallucinated flag is a mis-scan; a hallucinated `rm` is an incident.
Per-tool wrappers with typed args, mode whitelists, and timeout clamps
convert the gun into a nail gun — still dangerous, but only in the
direction it's pointed.

**Q: Why FastMCP instead of the lower-level MCP SDK?**
FastMCP generates the JSON schema from Python type hints and docstrings.
Eight tools, zero schema boilerplate. The lower-level SDK is worth it when
you need streaming / resources / prompts — this server is pure tools, so
FastMCP is the right rung.

**Q: Where are the tests?**
Not in the repo. The surface area is "subprocess runs, parsers parse" —
pragmatically covered by running the tool against a known target and
diffing the JSON. A proper test suite with fixture XML / SARIF / JSONL
blobs is a worthwhile addition and would live at `tests/test_parsers.py`;
it is not shipped because the parsers are stdlib-call-and-walk code that
breaks loudly when it breaks. YAGNI until a parser bug ships.

**Q: Can I use this with Claude Desktop (not Claude Code)?**
Yes — add it to `claude_desktop_config.json` under `mcpServers`, same
command + args. The server is transport-agnostic within stdio clients.

**Q: Will scans run as root?**
Only if your MCP client runs as root. The server inherits the client's
UID. `nmap -sS` needs raw sockets (root or `cap_net_raw`); other tools
run fine unprivileged. Give `nmap` the capability instead of running
Claude as root: `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)`.

**Q: What happens if a tool is missing when I call it?**
`_run` catches `FileNotFoundError` and returns `rc: 127, stderr:
"binary not found: <path>"` (`server.py:72-73`). The server does not
crash; the model gets a structured error and can tell the operator what
to install.

**Q: Can I add API-based tools (Shodan, VirusTotal) here?**
Yes but prefer a separate MCP server. The design principle of this one is
"wrap a CLI". API clients are a different shape (auth, rate limits, JSON
clients) and belong in their own server (see `cve-mcp` for an example).

**Q: Does this work on macOS / Windows?**
macOS: yes — install the CLIs via Homebrew, same code path.
Windows: untested. Subprocess should work; wordlist paths are
Linux-flavoured in defaults. Set `wordlist=` explicitly on Windows.

---

## License

MIT. See `LICENSE` if present, else assume MIT.

Operator is responsible for authorisation. The author is not liable for
misuse. If in doubt, don't run the scan.
