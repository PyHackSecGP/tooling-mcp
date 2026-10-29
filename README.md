# tooling-mcp

MCP server wrapping offensive-security CLIs: nmap, nuclei, gobuster, ffuf, httpx, semgrep, trivy. Any MCP client (Claude Code, Cursor, Codex) calls these as structured tools instead of shelling out ad-hoc.

## Authorization

**You are responsible for authorization.** This server executes real scans against real targets. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal in most jurisdictions.

## Tools

| Tool | Purpose | Output |
|---|---|---|
| `tool_health` | which binaries present + versions | dict |
| `nmap` | port scan + service version | parsed XML → JSON ports/services |
| `nuclei` | template-based vuln scanner | JSON findings |
| `gobuster` | directory / DNS / vhost brute | raw stdout |
| `ffuf` | web fuzzer | parsed JSON results |
| `httpx` | HTTP(S) probe | JSON per URL |
| `semgrep` | SAST scanner | SARIF summary + full SARIF path |
| `trivy` | container / fs vuln scanner | JSON report |

## Install

Tool binaries must be on PATH (or set `<TOOL>_BIN` env). On Kali most are preinstalled.

```bash
cd ~/projects/tooling-mcp
python3 -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/python -c "from server import tool_health; import json; print(json.dumps(tool_health(), indent=2))"
```

Install missing tools:

```bash
# nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
# subfinder, naabu similar
# trivy
sudo apt install trivy   # or go install github.com/aquasecurity/trivy/cmd/trivy@latest
```

## Register with Claude Code

```bash
claude mcp add --scope user tooling -- /home/tony/projects/tooling-mcp/venv/bin/python /home/tony/projects/tooling-mcp/server.py
```

## Env overrides

| Var | Override binary path |
|---|---|
| `NMAP_BIN`, `NUCLEI_BIN`, `GOBUSTER_BIN`, `FFUF_BIN`, `HTTPX_BIN`, `SEMGREP_BIN`, `TRIVY_BIN` | per-tool |

## Design notes

- `MAX_TIMEOUT = 1800` (30 min hard cap) prevents runaway subprocesses.
- Nmap XML parsing is zero-dep (`xml.etree`). Returns open ports with service / product / version.
- Nuclei is called with `-silent -json` → one JSON object per finding; parsed line-by-line.
- Semgrep writes SARIF to a temp file + returns path (keeps response small; SARIF files can be large). Summary includes `by_level` counts.
- ffuf results written to temp JSON then parsed back; raw stdout dropped from response.
- No scope guard against public targets — operator responsibility. Set up a VPN / scope list upstream if needed.
- All operations are via `subprocess.run` with explicit arg lists → no shell injection.

## Example — HTB recon flow

```
> I own 10.129.100.5, scan it
→ nmap(target="10.129.100.5", flags="-sV -sC -Pn")
→ for each http service: nuclei(url=...) + httpx(target=...) + gobuster(url=..., mode="dir")
```

## Related

Complements `cve-mcp` (vuln lookup) and `wazuh-mcp` (SIEM triage). Together: scan → find vulns → look up CVEs → check for alerts in SIEM.
