from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from network_scanner.auto_env import infer_initial_environment
from network_scanner.cidr_chunk import ipv4_subnets
from network_scanner.models import Environment
from network_scanner.orchestrator import AdaptiveScanner, OrchestratorConfig, OrchestratorResult
from network_scanner.seeds import load_host_lines

console = Console()

_DEFAULT_DB = Path.home() / ".cache" / "adaptive_scan" / "scan.db"


def _env_truthy(key: str) -> bool:
    return os.environ.get(key, "").strip().lower() in ("1", "true", "yes", "on")


def _env_path(key: str) -> Path | None:
    v = os.environ.get(key, "").strip()
    return Path(v) if v else None


def _apply_environment_profile(env: Environment, path: Path) -> Environment:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return env
    data = env.model_dump()
    for k, v in raw.items():
        if k in data:
            data[k] = v
    return Environment.model_validate(data)


def _build_environment_from_runtime(user_target: str) -> Environment:
    """Operator hints from env only; core posture is inferred plus per-step LLM adaptation."""
    env = infer_initial_environment(user_target)

    seed_hosts: list[str] = []
    sp = _env_path("ADAPTIVE_SCAN_SEED_HOSTS_FILE")
    if sp and sp.exists():
        seed_hosts = load_host_lines(sp)

    passive_hints: list[dict] = []
    known_subnets: list[str] = []
    topology_notes = ""
    tj = _env_path("ADAPTIVE_SCAN_TOPOLOGY_JSON")
    if tj and tj.exists():
        topo = json.loads(tj.read_text(encoding="utf-8"))
        if isinstance(topo, dict):
            ks = topo.get("known_subnets")
            if isinstance(ks, list):
                known_subnets = [str(x) for x in ks]
            tn = topo.get("topology_notes")
            if isinstance(tn, str):
                topology_notes = tn
            ie = topo.get("indirect_endpoints")
            if isinstance(ie, list):
                for item in ie:
                    if isinstance(item, dict):
                        passive_hints.append(dict(item))

    if _env_truthy("ADAPTIVE_SCAN_PASSIVE_ARP"):
        from network_scanner.passive_local import collect_arp_neighbors

        passive_hints.extend(collect_arp_neighbors())

    sid = (os.environ.get("ADAPTIVE_SCAN_SCANNER_ID", "") or "").strip()
    env = env.model_copy(
        update={
            "seed_hosts": seed_hosts,
            "known_subnets": known_subnets,
            "passive_hints": passive_hints,
            "topology_notes": topology_notes,
            "scanner_id": sid,
        }
    )

    prof = _env_path("ADAPTIVE_SCAN_PROFILE")
    if prof and prof.exists():
        env = _apply_environment_profile(env, prof)

    return env


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Adaptive Nmap discovery: one command; the strategist adapts scan posture each step. "
            "CLI flags are for output/cache only; use ADAPTIVE_SCAN_* env vars for advanced control."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Host, CIDR, or nmap target (optional if ADAPTIVE_SCAN_RESUME is set)",
    )
    parser.add_argument("--json-out", type=Path, default=None, help="Write full result JSON")
    parser.add_argument(
        "--ndjson-log",
        type=Path,
        default=None,
        help="Append one JSON line per completed scan iteration",
    )
    parser.add_argument(
        "--cache-ttl-seconds",
        type=float,
        default=0,
        help="Reuse identical nmap results from SQLite for this many seconds",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    resume = (os.environ.get("ADAPTIVE_SCAN_RESUME", "") or "").strip() or None
    db_path = _env_path("ADAPTIVE_SCAN_DB") or _DEFAULT_DB
    max_steps = int((os.environ.get("ADAPTIVE_SCAN_MAX_STEPS", "") or "25").strip() or "25")
    session_id = (os.environ.get("ADAPTIVE_SCAN_SESSION_ID", "") or "").strip() or None
    merge_state = _env_path("ADAPTIVE_SCAN_MERGE_STATE")
    merge_peer = (os.environ.get("ADAPTIVE_SCAN_MERGE_PEER_ID", "") or "").strip() or None
    resume_env_mode = (os.environ.get("ADAPTIVE_SCAN_RESUME_ENV", "checkpoint") or "checkpoint").strip()
    persist_connect = not _env_truthy("ADAPTIVE_SCAN_NO_PERSIST_CONNECT")
    llm_max_hosts = int((os.environ.get("ADAPTIVE_SCAN_LLM_MAX_HOSTS", "") or "128").strip() or "128")
    _llm_rs = (os.environ.get("ADAPTIVE_SCAN_LLM_RECENT_STEPS", "") or "5").strip() or "5"
    llm_max_recent_steps = int(_llm_rs) if _llm_rs.isdigit() else 5
    llm_max_recent_steps = max(0, min(24, llm_max_recent_steps))
    reload_interval = float((os.environ.get("ADAPTIVE_SCAN_RELOAD_SEEDS_INTERVAL", "") or "0").strip() or "0")
    reload_mtime = _env_truthy("ADAPTIVE_SCAN_RELOAD_SEEDS_MTIME")
    dry_run = _env_truthy("ADAPTIVE_SCAN_DRY_RUN")
    ipv6 = _env_truthy("ADAPTIVE_SCAN_IPV6")
    chunk_raw = (os.environ.get("ADAPTIVE_SCAN_CHUNK_IPV4_PREFIX", "") or "").strip()
    chunk_prefix = int(chunk_raw) if chunk_raw.isdigit() else None
    seed_path = _env_path("ADAPTIVE_SCAN_SEED_HOSTS_FILE")

    if args.cache_ttl_seconds > 0:
        os.environ["ADAPTIVE_SCAN_CACHE_TTL"] = str(args.cache_ttl_seconds)

    excl = (os.environ.get("ADAPTIVE_SCAN_EXCLUDE_PORTS", "") or "").strip()
    if excl:
        os.environ["ADAPTIVE_SCAN_EXCLUDE_PORTS"] = excl

    if resume:
        from network_scanner.db import ScanStore

        store = ScanStore(db_path)
        sess = store.get_session(resume)
        if not sess:
            console.print(f"[red]Unknown session[/red] {resume}")
            sys.exit(1)
        target = args.target or sess["target"]
        if args.target and args.target != sess["target"]:
            console.print(
                f"[red]Target mismatch:[/red] CLI {args.target!r} vs session {sess['target']!r}"
            )
            sys.exit(1)
    elif not args.target:
        console.print(
            "[red]target[/red] is required (or set ADAPTIVE_SCAN_RESUME for checkpoint resume)"
        )
        sys.exit(1)
    else:
        target = args.target

    if resume and chunk_prefix is not None:
        console.print("[red]ADAPTIVE_SCAN_RESUME cannot be combined with ADAPTIVE_SCAN_CHUNK_IPV4_PREFIX[/red]")
        sys.exit(1)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )

    user_target = target
    env = _build_environment_from_runtime(user_target)

    chunks: list[str] = [user_target]
    if chunk_prefix is not None:
        try:
            chunks = ipv4_subnets(user_target, chunk_prefix)
        except ValueError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)
    if dry_run and len(chunks) > 1:
        console.print("[yellow]Note:[/yellow] dry-run stops after the first chunk's first nmap action")

    mode = "resume" if resume else "new"
    console.print(f"[bold]Target[/bold] {user_target}  [dim]({mode}, session log: {db_path})[/dim]")
    if len(chunks) > 1:
        console.print(f"[dim]{len(chunks)} IPv4 chunks[/dim]")

    combined_history: list[dict] = []
    acc_fs: dict | None = None
    result: OrchestratorResult | None = None
    for ci, chunk_target in enumerate(chunks):
        if len(chunks) > 1:
            console.print(f"[bold]Chunk[/bold] {ci + 1}/{len(chunks)} [dim]{chunk_target}[/dim]")
        cfg = OrchestratorConfig(
            max_steps=max_steps,
            db_path=db_path,
            llm_max_hosts=llm_max_hosts,
            llm_max_recent_steps=llm_max_recent_steps,
            session_id=(session_id if ci == 0 else None) if len(chunks) > 1 else session_id,
            resume_session_id=resume,
            merge_state_path=merge_state if ci == 0 else None,
            merge_peer_scanner_id=merge_peer,
            resume_restore_environment=(resume_env_mode == "checkpoint"),
            persist_connect_after_syn_fail=persist_connect,
            ndjson_log_path=args.ndjson_log,
            initial_current_state=acc_fs,
            dry_run=dry_run,
            ipv6=ipv6,
            seed_hosts_path=seed_path,
            reload_seeds_interval_s=reload_interval,
            reload_seeds_on_mtime=reload_mtime,
        )
        scanner = AdaptiveScanner(cfg)
        try:
            result = scanner.run(chunk_target, environment=env)
        except (ValueError, OSError) as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(3)
        except Exception as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(3)
        if result.final_environment is not None:
            env = result.final_environment
        acc_fs = result.final_state
        for h in result.history:
            entry = dict(h)
            if len(chunks) > 1:
                entry["chunk_target"] = chunk_target
                entry["chunk_index"] = ci
            combined_history.append(entry)
        if result.dry_run:
            break

    assert result is not None
    if len(chunks) > 1:
        result = OrchestratorResult(
            session_id=result.session_id,
            target=chunk_target,
            final_state=acc_fs or result.final_state,
            history=combined_history,
            dry_run=result.dry_run,
            dry_run_nmap_argv=result.dry_run_nmap_argv,
            final_environment=result.final_environment,
        )

    console.print(f"[dim]session_id[/dim] [bold]{result.session_id}[/bold]")
    if result.dry_run and result.dry_run_nmap_argv:
        console.print("[dim]Dry-run nmap (not executed):[/dim]")
        q = shlex.join(result.dry_run_nmap_argv) if hasattr(shlex, "join") else " ".join(
            shlex.quote(x) for x in result.dry_run_nmap_argv
        )
        console.print(q)

    table = Table(title="Final state")
    table.add_column("Field")
    table.add_column("Value")
    fs = result.final_state
    table.add_row("host_status", str(fs.get("host_status")))
    table.add_row("discovered_ports", ", ".join(str(p) for p in fs.get("discovered_ports", [])) or "—")
    table.add_row("filtered_ports", ", ".join(str(p) for p in fs.get("filtered_ports", [])) or "—")
    table.add_row("services", str(len(fs.get("services", []))))
    console.print(table)

    out_env = result.final_environment if result.final_environment is not None else env
    if args.json_out:
        out_path = args.json_out.expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload: dict = {
            "session_id": result.session_id,
            "scanner_id": out_env.scanner_id,
            "target": user_target,
            "last_chunk_target": result.target,
            "environment": out_env.model_dump(mode="json"),
            "final_state": result.final_state,
            "history": result.history,
            "dry_run": result.dry_run,
            "dry_run_nmap_argv": result.dry_run_nmap_argv,
        }
        if len(chunks) > 1:
            payload["chunks"] = chunks
        out_path.write_text(
            json.dumps(payload, indent=2),
            encoding="utf-8",
        )
        console.print(f"[green]Wrote[/green] {out_path}")

    for h in result.history:
        r = h.get("result") or {}
        if r.get("anomalies") and "nmap_missing" in r["anomalies"]:
            sys.exit(2)


if __name__ == "__main__":
    main()
