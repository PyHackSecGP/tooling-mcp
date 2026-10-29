#!/usr/bin/env python3
"""tooling-mcp — wrap offensive-security CLIs behind an MCP surface.

Transport: stdio. Each tool shells out to the local binary, captures stdout,
parses structured output when the tool produces JSON/XML/SARIF, and returns
a dict. All operations are opt-in: the operator is responsible for
authorization. See README.md for the authorization note.

Tools:
    tool_health()                        which binaries are present
    nmap(target, flags, timeout)         nmap XML -> JSON ports/services
    nuclei(url, severity, timeout)       nuclei JSON findings
    gobuster(url, mode, wordlist)        gobuster dir/dns/vhost
    ffuf(url, wordlist, mode)            ffuf fuzzing
    httpx(target, flags)                 httpx probe JSON
    semgrep(path, config)                semgrep SARIF path + summary
    trivy(target, mode)                  trivy image/fs/repo scan JSON
"""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP


# ── Config ────────────────────────────────────────────────────────────────────
TOOLS = {
    "nmap":     os.environ.get("NMAP_BIN",     shutil.which("nmap")     or "/usr/bin/nmap"),
    "nuclei":   os.environ.get("NUCLEI_BIN",   shutil.which("nuclei")   or "nuclei"),
    "gobuster": os.environ.get("GOBUSTER_BIN", shutil.which("gobuster") or "/usr/bin/gobuster"),
    "ffuf":     os.environ.get("FFUF_BIN",     shutil.which("ffuf")     or "/usr/bin/ffuf"),
    "httpx":    os.environ.get("HTTPX_BIN",    shutil.which("httpx")    or "/usr/bin/httpx"),
    "semgrep":  os.environ.get("SEMGREP_BIN",  shutil.which("semgrep")  or "semgrep"),
    "trivy":    os.environ.get("TRIVY_BIN",    shutil.which("trivy")    or "trivy"),
}

DEFAULT_WORDLISTS = {
    "dir":  "/usr/share/wordlists/dirb/common.txt",
    "dns":  "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "fuzz": "/usr/share/wordlists/dirb/common.txt",
}

MAX_TIMEOUT = 1800  # 30 min hard cap, prevents runaway


# ── Helpers ───────────────────────────────────────────────────────────────────
def _run(cmd: list[str], timeout: int, stdin: Optional[str] = None,
         env_extra: Optional[dict] = None) -> dict:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    timeout = min(timeout, MAX_TIMEOUT)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           input=stdin, env=env, timeout=timeout)
        return {
            "cmd":    shlex.join(cmd),
            "rc":     r.returncode,
            "stdout": r.stdout,
            "stderr": r.stderr[-2000:] if r.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"cmd": shlex.join(cmd), "rc": 124, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except FileNotFoundError:
        return {"cmd": shlex.join(cmd), "rc": 127, "stdout": "", "stderr": f"binary not found: {cmd[0]}"}
    except Exception as e:
        return {"cmd": shlex.join(cmd), "rc": 1, "stdout": "", "stderr": str(e)}


def _which_versions() -> dict:
    out = {}
    for name, path in TOOLS.items():
        if path and Path(path).exists():
            r = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
            v = (r.stdout + r.stderr).strip().splitlines()[0] if r.stdout or r.stderr else ""
            out[name] = {"present": True, "path": path, "version": v}
        else:
            out[name] = {"present": False, "path": None, "version": None}
    return out


# ── MCP ────────────────────────────────────────────────────────────────────────
mcp = FastMCP("tooling")


@mcp.tool()
def tool_health() -> dict:
    """Report which offensive-security binaries are present + their versions."""
    return _which_versions()


@mcp.tool()
def nmap(target: str, flags: str = "-sV -sC -Pn -T4", top_ports: int = 1000,
         timeout: int = 300) -> dict:
    """Run nmap scan. Returns parsed port/service JSON when XML parses, else raw.

    `target` is any nmap-acceptable target spec (host/CIDR/file:). `flags`
    MUST be used with authorization. Default includes `-Pn` to skip host
    discovery (useful for firewalled hosts).
    """
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
        xmlpath = f.name
    try:
        cmd = [TOOLS["nmap"], *shlex.split(flags), "--top-ports", str(top_ports),
               "-oX", xmlpath, target]
        res = _run(cmd, timeout=timeout)
        if res["rc"] != 0 and not Path(xmlpath).exists():
            return res
        parsed = _parse_nmap_xml(xmlpath)
        res["parsed"] = parsed
        return res
    finally:
        try:
            os.unlink(xmlpath)
        except Exception:
            pass


def _parse_nmap_xml(path: str) -> dict:
    try:
        root = ET.parse(path).getroot()
    except Exception as e:
        return {"error": f"xml parse: {e}"}
    hosts = []
    for h in root.findall("host"):
        addr_el = h.find("address")
        hostname_el = h.find("hostnames/hostname")
        ports = []
        for p in h.findall("ports/port"):
            state_el = p.find("state")
            svc_el = p.find("service")
            ports.append({
                "port":     int(p.get("portid") or 0),
                "protocol": p.get("protocol"),
                "state":    state_el.get("state") if state_el is not None else None,
                "service":  svc_el.get("name") if svc_el is not None else None,
                "product":  svc_el.get("product") if svc_el is not None else None,
                "version":  svc_el.get("version") if svc_el is not None else None,
            })
        hosts.append({
            "ip":       addr_el.get("addr") if addr_el is not None else None,
            "hostname": hostname_el.get("name") if hostname_el is not None else None,
            "ports":    [p for p in ports if p["state"] == "open"],
        })
    return {"hosts": hosts}


@mcp.tool()
def nuclei(url: str, severity: str = "critical,high,medium", templates: str = "",
           timeout: int = 300) -> dict:
    """Run nuclei scan. Returns parsed JSON findings.

    `templates` optional path/tag filter. Default severity trims noise.
    """
    cmd = [TOOLS["nuclei"], "-u", url, "-severity", severity, "-silent", "-json"]
    if templates:
        cmd.extend(["-t", templates])
    res = _run(cmd, timeout=timeout)
    findings = []
    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except Exception:
            continue
    res["findings"] = findings
    res["finding_count"] = len(findings)
    res.pop("stdout", None)
    return res


@mcp.tool()
def gobuster(url: str, mode: str = "dir", wordlist: str = "",
             extensions: str = "", threads: int = 10, timeout: int = 600) -> dict:
    """Run gobuster. mode = dir|dns|vhost|fuzz. Returns raw stdout."""
    if mode not in {"dir", "dns", "vhost", "fuzz"}:
        return {"error": f"invalid mode: {mode}"}
    wl = wordlist or DEFAULT_WORDLISTS.get("dir" if mode in ("dir","fuzz","vhost") else "dns")
    if not Path(wl).exists():
        return {"error": f"wordlist not found: {wl}"}
    cmd = [TOOLS["gobuster"], mode, "-w", wl, "-t", str(threads), "--no-progress"]
    if mode in {"dir", "vhost", "fuzz"}:
        cmd.extend(["-u", url])
    else:
        cmd.extend(["-d", url])
    if extensions and mode == "dir":
        cmd.extend(["-x", extensions])
    return _run(cmd, timeout=timeout)


@mcp.tool()
def ffuf(url: str, wordlist: str = "", mode: str = "dir",
         filter_code: str = "404", timeout: int = 600) -> dict:
    """ffuf fuzzing. url must contain FUZZ for mode=raw, else dir mode auto-appends /FUZZ.

    mode: dir | raw
    """
    if "FUZZ" not in url and mode == "dir":
        url = url.rstrip("/") + "/FUZZ"
    wl = wordlist or DEFAULT_WORDLISTS["fuzz"]
    if not Path(wl).exists():
        return {"error": f"wordlist not found: {wl}"}
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        outpath = f.name
    try:
        cmd = [TOOLS["ffuf"], "-u", url, "-w", wl, "-fc", filter_code,
               "-o", outpath, "-of", "json", "-s"]
        res = _run(cmd, timeout=timeout)
        try:
            data = json.loads(Path(outpath).read_text())
            res["results"] = data.get("results", [])
            res["result_count"] = len(res["results"])
        except Exception as e:
            res["parse_error"] = str(e)
        return res
    finally:
        try: os.unlink(outpath)
        except: pass


@mcp.tool()
def httpx(target: str, flags: str = "-silent -status-code -title -tech-detect -json",
          timeout: int = 120) -> dict:
    """httpx HTTP(S) probe. `target` can be URL, host, or file path (one per line)."""
    cmd = [TOOLS["httpx"], *shlex.split(flags)]
    if Path(target).is_file():
        cmd.extend(["-l", target])
    else:
        cmd.extend(["-u", target])
    res = _run(cmd, timeout=timeout)
    results = []
    for line in res["stdout"].splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except Exception:
            results.append({"raw": line})
    res["results"] = results
    res.pop("stdout", None)
    return res


@mcp.tool()
def semgrep(path: str, config: str = "auto", timeout: int = 300) -> dict:
    """Run semgrep on a path. Returns SARIF summary + path to full SARIF file.

    config: 'auto' (semgrep's bundled rules), or a specific ruleset like 'p/ci'.
    """
    with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
        sarif_path = f.name
    cmd = [TOOLS["semgrep"], "scan", "--config", config, "--sarif",
           "--sarif-output", sarif_path, "--quiet", path]
    res = _run(cmd, timeout=timeout)
    try:
        sarif = json.loads(Path(sarif_path).read_text())
        runs = sarif.get("runs", [])
        results = runs[0].get("results", []) if runs else []
        by_sev: dict[str, int] = {}
        for r in results:
            lvl = r.get("level", "warning")
            by_sev[lvl] = by_sev.get(lvl, 0) + 1
        res["summary"] = {
            "total":   len(results),
            "by_level": by_sev,
            "sarif_path": sarif_path,
        }
    except Exception as e:
        res["sarif_parse_error"] = str(e)
    return res


@mcp.tool()
def trivy(target: str, mode: str = "image", severity: str = "HIGH,CRITICAL",
          timeout: int = 300) -> dict:
    """Trivy scan.

    mode: image | fs | repo | config
    """
    if mode not in {"image", "fs", "repo", "config"}:
        return {"error": f"invalid mode: {mode}"}
    cmd = [TOOLS["trivy"], mode, "--severity", severity, "--format", "json",
           "--quiet", target]
    res = _run(cmd, timeout=timeout)
    try:
        res["report"] = json.loads(res["stdout"])
        res.pop("stdout", None)
    except Exception as e:
        res["parse_error"] = str(e)
    return res


if __name__ == "__main__":
    mcp.run()
