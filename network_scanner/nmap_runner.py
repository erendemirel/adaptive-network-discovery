from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

from network_scanner.models import NmapRunSummary, ScanHost, ScanPort
from network_scanner.script_extracts import extract_from_script_entries, merge_script_extracts

logger = logging.getLogger(__name__)


def _prefer_connect_scan() -> bool:
    if os.environ.get("ADAPTIVE_SCAN_FORCE_SYN", "").lower() in ("1", "true", "yes"):
        return False
    if os.environ.get("ADAPTIVE_SCAN_PREFER_CONNECT", "").lower() in ("1", "true", "yes"):
        return True
    return sys.platform == "win32"


def nmap_executable() -> str:
    return os.environ.get("NMAP_PATH", "nmap")


def _global_nmap_suffix() -> list[str]:
    raw = os.environ.get("ADAPTIVE_SCAN_NMAP_EXTRA", "").strip()
    if not raw:
        return []
    return shlex.split(raw, posix=sys.platform != "win32")


@dataclass
class RunContext:
    discovered_ports: list[int] = field(default_factory=list)
    extra_args: list[str] = field(default_factory=list)
    stealth: bool = False
    latency: str = "medium"
    large_network: bool = False
    # Slower templates + scan-delay + optional max-rate (XDR / sensitive networks)
    low_noise: bool = False
    # If True, use -sT for SYN-capable actions; if False, -sS; None = env/OS default
    prefer_connect: bool | None = None
    # Prefer IPv6 (nmap -6); also set ADAPTIVE_SCAN_IPV6=1
    ipv6: bool = False
    # Override --top-ports count for nmap_udp_scan (e.g. "12" when xdr_heavy)
    udp_top_ports: str | None = None
    # Clamped strategist (LLM) overrides; env/CLI remain baseline when unset.
    llm_timing: str | None = None
    llm_version_intensity: str | None = None
    llm_max_scan_rate: str | None = None
    llm_scan_delay: str | None = None
    llm_host_timeout: str | None = None


def _timing_template(latency: str, stealth: bool) -> str:
    if stealth:
        return "T2"
    return {"low": "T4", "medium": "T3", "high": "T2"}.get(latency, "T3")


def _ports_arg(ports: list[int], default_top: str = "1000") -> list[str]:
    if ports:
        return ["-p", ",".join(str(p) for p in sorted(set(ports)))]
    return ["--top-ports", default_top]


def _tcp_scan_type_syn_or_connect(ctx: RunContext) -> list[str]:
    if ctx.prefer_connect is True:
        return ["-sT"]
    if ctx.prefer_connect is False:
        return ["-sS"]
    return ["-sT"] if _prefer_connect_scan() else ["-sS"]


def _large_net_args(ctx: RunContext) -> list[str]:
    if not ctx.large_network:
        return []
    out: list[str] = []
    hg_min = os.environ.get("ADAPTIVE_SCAN_MIN_HOSTGROUP", "32")
    hg_max = os.environ.get("ADAPTIVE_SCAN_MAX_HOSTGROUP", "128")
    out.extend(["--min-hostgroup", hg_min, "--max-hostgroup", hg_max])
    mr = os.environ.get("ADAPTIVE_SCAN_MAX_SCAN_RATE", "").strip()
    if mr:
        out.extend(["--max-scan-rate", mr])
    return out


def _nmap_version_intensity(ctx: RunContext) -> str:
    """Lower intensity reduces probe chatter for -sV (XDR-friendly). Override via env."""
    if ctx.llm_version_intensity is not None and str(ctx.llm_version_intensity).strip():
        return str(ctx.llm_version_intensity).strip()
    v = os.environ.get("ADAPTIVE_SCAN_VERSION_INTENSITY", "").strip()
    if v:
        return v
    if ctx.low_noise:
        return "4"
    return "7"


def _build_nmap_base(ctx: RunContext) -> list[str]:
    exe = nmap_executable()
    if ctx.llm_timing:
        t = ctx.llm_timing
    elif ctx.low_noise:
        t = "T2"
    elif ctx.stealth:
        t = _timing_template(ctx.latency, True)
    else:
        t = _timing_template(ctx.latency, False)

    if ctx.llm_scan_delay:
        delay = ctx.llm_scan_delay
    elif ctx.low_noise:
        delay = os.environ.get("ADAPTIVE_SCAN_SCAN_DELAY", "250ms")
    elif ctx.stealth:
        delay = "50ms"
    else:
        delay = ""

    host_timeout = ctx.llm_host_timeout or os.environ.get(
        "ADAPTIVE_SCAN_HOST_TIMEOUT",
        "600s" if ctx.large_network else "300s",
    )
    parts: list[str] = [exe, f"-{t}", "--host-timeout", host_timeout]
    if delay:
        parts.extend(["--scan-delay", delay])
    rate_added = False
    llm_mr = (ctx.llm_max_scan_rate or "").strip()
    if llm_mr:
        parts.extend(["--max-scan-rate", llm_mr])
        rate_added = True
    if not rate_added and ctx.low_noise:
        mx = os.environ.get("ADAPTIVE_SCAN_XDR_MAX_SCAN_RATE", "").strip()
        if mx:
            parts.extend(["--max-scan-rate", mx])
            rate_added = True
    if not rate_added:
        gr = os.environ.get("ADAPTIVE_SCAN_GLOBAL_MAX_SCAN_RATE", "").strip()
        if gr:
            parts.extend(["--max-scan-rate", gr])
    parts.extend(_global_nmap_suffix())
    parts.extend(_large_net_args(ctx))
    ex = os.environ.get("ADAPTIVE_SCAN_EXCLUDE_PORTS", "").strip()
    if ex:
        parts.extend(["--exclude-ports", ex.replace(" ", "")])
    use_v6 = ctx.ipv6 or os.environ.get("ADAPTIVE_SCAN_IPV6", "").lower() in ("1", "true", "yes")
    if use_v6:
        parts.insert(1, "-6")
    return parts


def build_nmap_command(action: str, target: str, ctx: RunContext) -> list[str]:
    base = _build_nmap_base(ctx)

    ev = list(ctx.extra_args)
    ports = ctx.discovered_ports

    def tcp_type() -> list[str]:
        return _tcp_scan_type_syn_or_connect(ctx)

    # Host discovery
    if action == "nmap_ping":
        return base + ev + ["-sn", target]
    if action == "nmap_ping_tcp":
        return base + ev + ["-PS22,80,443,3389,8080", "-sn", target]
    if action == "nmap_ping_udp":
        return base + ev + ["-PU53,123,161,500", "-sn", target]
    if action == "nmap_no_ping":
        # Treat host as up; probe common TCP ports for liveness
        return base + ev + ["-Pn"] + tcp_type() + ["-p", "22,80,135,139,443,445,3389,8080", target]

    # Port scanning
    if action == "nmap_syn_scan":
        return base + ev + ["-Pn"] + tcp_type() + _ports_arg(ports, "1000") + [target]
    if action == "nmap_connect_scan":
        return base + ev + ["-Pn", "-sT"] + _ports_arg(ports, "1000") + [target]
    if action == "nmap_ack_scan":
        return base + ev + ["-Pn", "-sA", "-p", "80,443,8080,8443", target]
    if action == "nmap_window_scan":
        return base + ev + ["-Pn", "-sW", "-p", "80,443,8080,8443", target]
    if action == "nmap_udp_scan":
        top = (ctx.udp_top_ports or os.environ.get("ADAPTIVE_SCAN_UDP_TOP_PORTS", "")).strip()
        if not top:
            top = "20" if ctx.low_noise else "100"
        return base + ev + ["-Pn", "-sU", "--top-ports", top, target]
    if action == "nmap_top_ports":
        return base + ev + ["-Pn"] + tcp_type() + ["--top-ports", "1000", target]
    if action == "nmap_full_port_scan":
        return base + ev + ["-Pn"] + tcp_type() + ["-p-", target]

    # Service / scripts
    vi = _nmap_version_intensity(ctx)
    if action == "nmap_service_detection":
        pa = _ports_arg(ports, "200") if ports else ["--top-ports", "200"]
        return base + ev + ["-Pn"] + tcp_type() + ["-sV", "--version-intensity", vi] + pa + [target]
    if action == "banner_grab":
        pa = _ports_arg(ports, "200")
        return (
            base
            + ev
            + ["-Pn", "-sV", "--version-intensity", vi, "--script=banner"]
            + pa
            + [target]
        )
    if action == "tls_fingerprint":
        pp = ports if ports else [443]
        return (
            base
            + ev
            + ["-Pn", "-sV", "--version-intensity", vi]
            + ["-p", ",".join(str(p) for p in sorted(set(pp)))]
            + [
                "--script",
                "ssl-cert,ssl-enum-ciphers",
                target,
            ]
        )
    if action == "http_probe":
        return (
            base
            + ev
            + ["-Pn", "-sT", "-p", "80,8080,8000,8888"]
            + ["--script", "http-title,http-headers,http-server-header"]
            + [target]
        )
    if action == "https_probe":
        return (
            base
            + ev
            + ["-Pn", "-sT", "-p", "443,8443"]
            + ["--script", "http-title,http-headers,ssl-cert"]
            + [target]
        )

    raise ValueError(f"Not an executable nmap action: {action}")


_SCRIPT_OUT_LIMIT = 480


def _truncate_script_output(text: str, limit: int = _SCRIPT_OUT_LIMIT) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _parse_one_host(host_el: ET.Element) -> tuple[ScanHost | None, list[ScanPort]]:
    addr_el = host_el.find("address")
    if addr_el is None:
        return None, []
    addr = addr_el.get("addr", "")
    if not addr:
        return None, []
    status_el = host_el.find("status")
    status = status_el.get("state") if status_el is not None else None
    names = [hn.get("name", "") for hn in host_el.findall("hostnames/hostname") if hn.get("name")]
    host_scripts: list[dict[str, str]] = []
    hscript = host_el.find("hostscript")
    if hscript is not None:
        for sc in hscript.findall("script"):
            sid = sc.get("id") or ""
            out = _truncate_script_output(sc.get("output") or "")
            if sid or out:
                host_scripts.append({"id": sid, "output": out})

    scan_host = ScanHost(
        address=addr,
        status=status,
        hostnames=[n for n in names if n],
        host_scripts=host_scripts,
    )
    ports_out: list[ScanPort] = []
    ports_el = host_el.find("ports")
    if ports_el is None:
        return scan_host, ports_out

    for p in ports_el.findall("port"):
        proto = p.get("protocol", "tcp")
        portid = p.get("portid")
        if not portid:
            continue
        try:
            portnum = int(portid)
        except ValueError:
            continue
        st = p.find("state")
        state = st.get("state", "unknown") if st is not None else "unknown"
        svc = p.find("service")
        name = product = version = extrainfo = None
        if svc is not None:
            name = svc.get("name")
            product = svc.get("product")
            version = svc.get("version")
            extrainfo = svc.get("extrainfo")
        port_scripts: list[dict[str, str]] = []
        for sc in p.findall("script"):
            sid = sc.get("id") or ""
            out = _truncate_script_output(sc.get("output") or "")
            if sid or out:
                port_scripts.append({"id": sid, "output": out})
        ports_out.append(
            ScanPort(
                port=portnum,
                protocol=proto,
                state=state,
                host_address=addr,
                port_scripts=port_scripts,
                service_name=name,
                product=product,
                version=version,
                extrainfo=extrainfo,
            )
        )
    return scan_host, ports_out


def parse_nmap_xml(xml_text: str) -> NmapRunSummary:
    hosts: list[ScanHost] = []
    ports_out: list[ScanPort] = []
    warnings: list[str] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return NmapRunSummary(
            command=[],
            exit_code=-1,
            stderr_tail="",
            warnings=[f"XML parse error: {e}"],
        )

    for host_el in root.findall("host"):
        h, pl = _parse_one_host(host_el)
        if h is not None:
            hosts.append(h)
            ports_out.extend(pl)

    if len(hosts) > 2000:
        warnings.append("very_many_hosts_suggest_chunk_targets")

    return NmapRunSummary(
        command=[],
        exit_code=0,
        hosts=hosts,
        ports=ports_out,
        warnings=warnings,
    )


def parse_nmap_xml_file(path: str) -> NmapRunSummary:
    hosts: list[ScanHost] = []
    ports_out: list[ScanPort] = []
    warnings: list[str] = []
    try:
        for _event, elem in ET.iterparse(path, events=("end",)):
            if elem.tag != "host":
                continue
            h, pl = _parse_one_host(elem)
            if h is not None:
                hosts.append(h)
                ports_out.extend(pl)
            elem.clear()
    except ET.ParseError as e:
        return NmapRunSummary(
            command=[],
            exit_code=-1,
            stderr_tail="",
            warnings=[f"XML parse error: {e}"],
        )

    if len(hosts) > 2000:
        warnings.append("very_many_hosts_suggest_chunk_targets")

    return NmapRunSummary(
        command=[],
        exit_code=0,
        hosts=hosts,
        ports=ports_out,
        warnings=warnings,
    )


def run_nmap(
    action: str,
    target: str,
    ctx: RunContext | None = None,
) -> tuple[NmapRunSummary, str]:
    ctx = ctx or RunContext()
    if shutil.which(nmap_executable()) is None and not os.path.isfile(nmap_executable()):
        summary = NmapRunSummary(
            command=[],
            exit_code=127,
            stderr_tail="nmap not found in PATH; set NMAP_PATH",
            warnings=["nmap_missing"],
        )
        return summary, ""

    cmd = build_nmap_command(action, target, ctx)
    summary = NmapRunSummary(command=cmd, exit_code=0)
    timeout = float(os.environ.get("ADAPTIVE_SCAN_NMAP_TIMEOUT", "600"))
    preview_n = min(18, len(cmd))
    cmd_preview = " ".join(cmd[:preview_n])
    if len(cmd) > preview_n:
        cmd_preview += " …"
    logger.info(
        "nmap start action=%s target=%s ADAPTIVE_SCAN_NMAP_TIMEOUT=%ss cmd=%s",
        action,
        target,
        int(timeout) if timeout == int(timeout) else timeout,
        cmd_preview,
    )
    use_stdout = os.environ.get("ADAPTIVE_SCAN_NMAP_XML_STDOUT", "").lower() in (
        "1",
        "true",
        "yes",
    )

    try:
        if use_stdout:
            proc = subprocess.run(
                cmd + ["-oX", "-"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            summary.exit_code = proc.returncode
            summary.stderr_tail = (proc.stderr or "")[-4000:]
            xml_text = proc.stdout or ""
            parsed = parse_nmap_xml(xml_text)
        else:
            fd, xpath = tempfile.mkstemp(prefix="adscan_", suffix=".xml")
            os.close(fd)
            try:
                proc = subprocess.run(
                    cmd + ["-oX", xpath],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                summary.exit_code = proc.returncode
                summary.stderr_tail = (proc.stderr or "")[-4000:]
                parsed = parse_nmap_xml_file(xpath)
                xml_text = ""
            finally:
                try:
                    os.unlink(xpath)
                except OSError:
                    pass

        parsed.command = cmd
        parsed.exit_code = proc.returncode
        parsed.stderr_tail = summary.stderr_tail
        stderr = proc.stderr or ""
        if "You requested a scan type which requires root privileges" in stderr or (
            "QUITTING!" in stderr and "-sS" in " ".join(cmd)
        ):
            logger.warning("SYN scan failed privileges; will use connect scan on retry")
            parsed.warnings.append("syn_requires_privileges")
        logger.info(
            "nmap subprocess returned action=%s target=%s exit=%s hosts=%s ports=%s warnings=%s",
            action,
            target,
            proc.returncode,
            len(parsed.hosts),
            len(parsed.ports),
            parsed.warnings,
        )
        return parsed, xml_text
    except subprocess.TimeoutExpired:
        logger.warning(
            "nmap killed by subprocess timeout (ADAPTIVE_SCAN_NMAP_TIMEOUT=%ss) action=%s target=%s; "
            "no XML parsed. If nmap uses a larger --host-timeout or a /24 scan, raise this env var.",
            int(timeout) if timeout == int(timeout) else timeout,
            action,
            target,
        )
        summary.exit_code = 124
        summary.warnings.append("nmap_timeout")
        return summary, ""
    except OSError as e:
        summary.exit_code = 1
        summary.stderr_tail = str(e)
        summary.warnings.append("nmap_os_error")
        return summary, ""


def _per_host_from_ports(ports: list[ScanPort]) -> dict[str, dict[str, Any]]:
    by: dict[str, dict[str, Any]] = {}
    for p in ports:
        key = p.host_address or "_unknown"
        if key not in by:
            by[key] = {
                "address": key,
                "open_ports": [],
                "filtered_ports": [],
                "services": [],
                "notes": [],
                "scripts": [],
            }
        for scr in p.port_scripts:
            entry = {"scope": "port", "port": p.port, "id": scr.get("id", ""), "output": scr.get("output", "")}
            sig = ("port", p.port, entry["id"], entry["output"][:120])
            existing = {
                ("port", e.get("port"), e.get("id"), (e.get("output") or "")[:120]) for e in by[key]["scripts"]
            }
            if sig not in existing:
                by[key]["scripts"].append(entry)
        if p.state == "open":
            if p.port not in by[key]["open_ports"]:
                by[key]["open_ports"].append(p.port)
            by[key]["services"].append(
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service_name": p.service_name,
                    "product": p.product,
                    "version": p.version,
                    "extrainfo": p.extrainfo,
                }
            )
        elif p.state == "filtered":
            if p.port not in by[key]["filtered_ports"]:
                by[key]["filtered_ports"].append(p.port)
    for v in by.values():
        v["open_ports"] = sorted(v["open_ports"])
        v["filtered_ports"] = sorted(v["filtered_ports"])
    return by


def summary_to_result_dict(summary: NmapRunSummary) -> dict[str, Any]:
    open_ports = [p.port for p in summary.ports if p.state == "open"]
    filtered = [p.port for p in summary.ports if p.state == "filtered"]
    closed = [p.port for p in summary.ports if p.state == "closed"]
    host_up = any(h.status == "up" for h in summary.hosts) or bool(open_ports)
    services: list[dict[str, Any]] = []
    for p in summary.ports:
        if p.state != "open":
            continue
        services.append(
            {
                "port": p.port,
                "protocol": p.protocol,
                "host": p.host_address or None,
                "service_name": p.service_name,
                "product": p.product,
                "version": p.version,
                "extrainfo": p.extrainfo,
            }
        )

    by_host = _per_host_from_ports(summary.ports)
    # Align with ScanHost list (hosts with no port section still appear)
    for h in summary.hosts:
        if not h.address:
            continue
        if h.address not in by_host:
            by_host[h.address] = {
                "address": h.address,
                "open_ports": [],
                "filtered_ports": [],
                "services": [],
                "notes": [],
                "scripts": [],
            }
        row = by_host[h.address]
        for scr in h.host_scripts:
            entry = {"scope": "host", "id": scr.get("id", ""), "output": scr.get("output", "")}
            sig = ("host", None, entry["id"], entry["output"][:120])
            existing = {
                (e.get("scope"), e.get("port"), e.get("id"), (e.get("output") or "")[:120])
                for e in row["scripts"]
            }
            if sig not in existing:
                row["scripts"].append(entry)

    per_host = [by_host[k] for k in sorted(by_host.keys()) if k != "_unknown"]
    if "_unknown" in by_host:
        per_host.append(by_host["_unknown"])

    for row in per_host:
        ex = extract_from_script_entries(row.get("scripts") or [])
        if ex:
            row["script_extracts"] = ex

    anomalies: list[str] = list(summary.warnings)
    if summary.exit_code not in (0, 124):
        anomalies.append(f"nmap_exit_{summary.exit_code}")

    reachability_hints: list[str] = []
    if "nmap_timeout" in summary.warnings:
        reachability_hints.append("scan_timeout_results_may_be_partial")
    if not open_ports and filtered:
        reachability_hints.append(
            "no_open_ports_only_filtered_or_closed_may_be_firewall_rate_limit_or_xdr"
        )
    if not open_ports and not filtered and not host_up and summary.hosts:
        reachability_hints.append("host_entries_but_no_port_data_visibility_uncertain")

    return {
        "exit_code": summary.exit_code,
        "command": summary.command,
        "stderr_tail": summary.stderr_tail,
        "hosts": [h.model_dump() for h in summary.hosts],
        "host_count": len(summary.hosts) or len(per_host),
        "open_ports": sorted(set(open_ports)),
        "filtered_ports": sorted(set(filtered)),
        "closed_ports_sample": closed[:50],
        "services": services,
        "per_host": per_host,
        "anomalies": anomalies,
        "host_likely_up": host_up,
        "reachability_hints": reachability_hints,
    }


def merge_state_from_result(prev: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Merge nmap result into strategist current_state shape (multi-host aware)."""
    open_p = set(prev.get("discovered_ports", [])) | set(result.get("open_ports", []))
    filt = set(prev.get("filtered_ports", [])) | set(result.get("filtered_ports", []))
    svcs = list(prev.get("services", []))
    seen = {(s.get("port"), s.get("protocol"), s.get("host")) for s in svcs}
    for s in result.get("services", []):
        key = (s.get("port"), s.get("protocol", "tcp"), s.get("host"))
        if key not in seen:
            svcs.append(s)
            seen.add(key)

    prev_ph = {h["address"]: dict(h) for h in prev.get("per_host", []) if h.get("address")}
    for row in result.get("per_host") or []:
        addr = row.get("address")
        if not addr or addr == "_unknown":
            continue
        if addr not in prev_ph:
            prev_ph[addr] = {
                "address": addr,
                "open_ports": [],
                "filtered_ports": [],
                "services": [],
                "notes": [],
                "scripts": [],
            }
        cur = prev_ph[addr]
        if row.get("notes"):
            seen = list(cur.get("notes") or [])
            for n in row["notes"]:
                if n not in seen:
                    seen.append(n)
            cur["notes"] = seen
        cur["open_ports"] = sorted(set(cur.get("open_ports", [])) | set(row.get("open_ports", [])))
        cur["filtered_ports"] = sorted(
            set(cur.get("filtered_ports", [])) | set(row.get("filtered_ports", []))
        )
        ps = {(x.get("port"), x.get("protocol", "tcp")) for x in cur.get("services", [])}
        for svc in row.get("services", []):
            k2 = (svc.get("port"), svc.get("protocol", "tcp"))
            if k2 not in ps:
                cur.setdefault("services", []).append(svc)
                ps.add(k2)
        cur.setdefault("scripts", [])
        seen_scr = {
            (s.get("scope"), s.get("port"), s.get("id"), (s.get("output") or "")[:120])
            for s in cur["scripts"]
        }
        for scr in row.get("scripts") or []:
            sig = (scr.get("scope"), scr.get("port"), scr.get("id"), (scr.get("output") or "")[:120])
            if sig not in seen_scr:
                cur["scripts"].append(scr)
                seen_scr.add(sig)
        if len(cur["scripts"]) > 48:
            cur["scripts"] = cur["scripts"][:48]
        ex_row = row.get("script_extracts") or {}
        if ex_row or cur.get("script_extracts"):
            cur["script_extracts"] = merge_script_extracts(cur.get("script_extracts"), ex_row)

    per_host = [prev_ph[k] for k in sorted(prev_ph.keys())]

    host_status = prev.get("host_status", "unknown")
    if result.get("host_likely_up"):
        host_status = "up"
    elif result.get("open_ports"):
        host_status = "up"
    elif result.get("filtered_ports") and not result.get("open_ports"):
        if host_status == "unknown":
            host_status = "filtered"

    anomalies = list(prev.get("anomalies", []))
    for a in result.get("anomalies", []):
        if a not in anomalies:
            anomalies.append(a)

    host_count = max(len(per_host), int(result.get("host_count") or 0), prev.get("host_count", 0))

    indirect = list(prev.get("indirect_endpoints") or [])
    seen_ie = {(e.get("source"), e.get("address"), (e.get("note") or "")[:80]) for e in indirect}
    for e in result.get("indirect_endpoints") or []:
        if not isinstance(e, dict):
            continue
        sig = (e.get("source"), e.get("address"), (e.get("note") or "")[:80])
        if sig not in seen_ie:
            indirect.append(e)
            seen_ie.add(sig)

    rh = list(prev.get("reachability_hints") or [])
    for hint in result.get("reachability_hints") or []:
        if isinstance(hint, str) and hint not in rh:
            rh.append(hint)
    rh = rh[:40]

    return {
        "host_status": host_status,
        "discovered_ports": sorted(open_p),
        "filtered_ports": sorted(filt),
        "services": svcs,
        "anomalies": anomalies,
        "per_host": per_host,
        "host_count": host_count,
        "aggregate_notes": list(prev.get("aggregate_notes", [])),
        "indirect_endpoints": indirect,
        "reachability_hints": rh,
        "strategist_meta": dict(prev.get("strategist_meta") or {}),
        "scan_signals": dict(prev.get("scan_signals") or {}),
    }
