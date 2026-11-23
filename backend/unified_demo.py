#!/usr/bin/env python3
"""Unified orchestration for infrastructure deployment + traffic/telemetry."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
WORKSPACE = Path(os.environ.get("INFOBLOX_DEMO_WORKSPACE", str(Path.home() / ".infoblox-demo"))).expanduser().resolve()
DEPLOY_TOOL = ROOT / "deployment" / "demo_tool.py"
DEPLOY_RUNTIME = WORKSPACE / "deployment"
GENERATED_CONFIG = WORKSPACE / "telemetry.config.yaml"


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def run(cmd: list[str], cwd: Path | None = None) -> int:
    print("+", " ".join(cmd))
    return subprocess.call(cmd, cwd=str(cwd or ROOT), env=os.environ.copy())


def deploy_cmd(config: Path, rest: list[str]) -> int:
    DEPLOY_RUNTIME.mkdir(parents=True, exist_ok=True)
    return run([sys.executable, str(DEPLOY_TOOL), "--config", str(config.resolve()), *rest], DEPLOY_RUNTIME)


def deployment_states() -> list[dict]:
    state_dir = DEPLOY_RUNTIME / "deployment-state"
    if not state_dir.exists():
        return []
    out = []
    for p in state_dir.glob("*.json"):
        try:
            x = json.loads(p.read_text(encoding="utf-8"))
            if x.get("phase") != "cleaned":
                out.append(x)
        except Exception:
            pass
    return out


def select_state(deployment_id: str | None) -> dict:
    states = deployment_states()
    if deployment_id:
        states = [s for s in states if s.get("deployment_id") == deployment_id]
    if len(states) != 1:
        ids = ", ".join(str(s.get("deployment_id")) for s in states) or "none"
        raise RuntimeError(f"Expected exactly one active deployment; found: {ids}. Use --deployment-id.")
    if states[0].get("phase") != "ready":
        raise RuntimeError(f"Deployment {states[0].get('deployment_id')} is not ready (phase={states[0].get('phase')}).")
    return states[0]


def local_ipv4() -> str:
    # No packets are sent by connect() for UDP; it selects the local route/address.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def build_telemetry_config(config_path: Path, state: dict) -> dict:
    parent = load_yaml(config_path)
    integ = parent.get("telemetry_integration", {})
    dns_ip = state.get("service_ip") or (state.get("service_network") or {}).get("dns")
    if not dns_ip:
        raise RuntimeError("Deployment state has no DNS service IP.")

    tenant_url = integ.get("tenant_url") or parent.get("infoblox", {}).get("base_url", "https://csp.infoblox.com")
    dhcp = integ.get("dhcp", {})
    services = parent.get("services", {})
    zones = integ.get("zones", {})
    safety = integ.get("safety", {})

    cfg = {
        "asset_source": {
            "base_url": tenant_url,
            "api_key_env": "INFOBLOX_API_KEY",
            "auth_scheme": integ.get("auth_scheme", "token"),
            "page_size": int(integ.get("page_size", 100)),
            "max_assets": int(integ.get("max_assets", 500)),
            "verify_tls": bool(integ.get("verify_tls", True)),
            "ip_selection": integ.get("ip_selection", {"private_only": True, "include_cidrs": [], "exclude_cidrs": []}),
        },
        "store": {"type": "json", "path": "state/assets.json"},
        "dns": {
            "server": dns_ip, "port": 53, "source_mode": integ.get("dns_source_mode", "spoof"),
            "domains_file": "state/tide_domains.json", "query_types": ["A"],
            "rate_per_asset": float(integ.get("rate_per_asset", 1.0)), "duration": float(integ.get("duration", 10)),
            "concurrency": int(integ.get("concurrency", 5)), "timeout": float(integ.get("dns_timeout", 2.0)),
        },
        "threat_defense": {
            "domains": [], "tide": {"enabled": True, "limit": int(integ.get("tide_limit", 100)), "category": "blocked"},
            "enabled_scenarios": integ.get("enabled_scenarios", ["normal-dns", "blocked-domain", "suspicious-domain", "mixed-workload"]),
        },
        "zones": {
            "enabled": bool(zones.get("enabled", True)), "query_devices": int(zones.get("query_devices", 5)),
            "wait_seconds": int(zones.get("wait_seconds", 90)), "negative_names": zones.get("negative_names", ["does-not-exist"]),
            "zones": zones.get("zones", [{"fqdn": "demo.internal.", "comment": "unified demo zone", "records": [
                {"name": "host1", "type": "A", "rdata": {"address": "10.99.0.10"}, "ttl": 300},
                {"name": "host2", "type": "A", "rdata": {"address": "10.99.0.11"}, "ttl": 300},
            ]}]),
        },
        "safety": {
            "allowed_dns_servers": [dns_ip], "allow_public_dns_server": False,
            "max_total_qps": int(safety.get("max_total_qps", 200)), "max_duration": int(safety.get("max_duration", 900)),
            "max_assets_per_run": int(safety.get("max_assets_per_run", 500)),
        },
        "reporting": {"output_dir": "reports", "state_dir": "state", "verification_buffer_minutes": 5},
        "logging": {"level": integ.get("log_level", "INFO")},
    }

    # DHCP is only enabled when the parent config supplies real DHCP deployment outputs.
    # DNS and DHCP are capabilities of the same deployed NIOS-XaaS service.
    server = dhcp.get("server") or (dns_ip if services.get("dhcp_enabled", True) else None)
    subnet = dhcp.get("subnet")
    range_start = dhcp.get("range_start")
    range_end = dhcp.get("range_end")
    if server:
        relay = dhcp.get("relay_agent_ip") or local_ipv4()
        cfg["dhcp"] = {
            "provider": "native", "server": server, "port": int(dhcp.get("port", 67)),
            "delay_between": float(dhcp.get("delay_between", 0.5)),
            "dra": {"relay_agent_ip": relay, "lease_dir": "state/dhcp", "send_hostname": True,
                    "timeout": int(dhcp.get("timeout", 30)), "verbose": bool(dhcp.get("verbose", True))},
        }
        if subnet and range_start and range_end:
            cfg["ipam"] = {
                "enabled": True, "ip_space": dhcp.get("ip_space", "unified-sales-demo"), "create_ip_space": True,
                "wait_seconds": int(dhcp.get("wait_seconds", 60)),
                "subnets": [{"address": subnet, "cidr": int(dhcp.get("cidr", 24)), "name": dhcp.get("subnet_name", "demo-subnet"),
                             "ranges": [{"start": range_start, "end": range_end, "name": dhcp.get("range_name", "demo-range")}]}],
            }
    return cfg


def write_telemetry_config(config_path: Path, deployment_id: str | None) -> Path:
    state = select_state(deployment_id)
    cfg = build_telemetry_config(config_path, state)
    GENERATED_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    GENERATED_CONFIG.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    print(f"Generated {GENERATED_CONFIG} for deployment {state['deployment_id']}")
    if "dhcp" not in cfg:
        print("DHCP capability is disabled or unavailable; enable services.dhcp_enabled and configure the demo DHCP subnet/range.")
    return GENERATED_CONFIG


def telemetry(rest: list[str], generated: Path) -> int:
    env = os.environ.copy()
    cmd = [sys.executable, "-m", "demo_cli.main", "--config", str(generated), *rest]
    print("+", " ".join(cmd))
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    return subprocess.call(cmd, cwd=str(WORKSPACE), env=env)


def main() -> int:
    ap = argparse.ArgumentParser(prog="demo", description="Unified Infoblox deployment + traffic/telemetry demo")
    ap.add_argument("--config", default=str(WORKSPACE / "config.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("doctor")
    p = sub.add_parser("deploy"); p.add_argument("--dry-run", action="store_true"); p.add_argument("--new", action="store_true"); p.add_argument("--deployment-id")
    p = sub.add_parser("status"); p.add_argument("--deployment-id")
    p = sub.add_parser("cleanup"); p.add_argument("--deployment-id")
    p = sub.add_parser("configure-telemetry"); p.add_argument("--deployment-id")
    p = sub.add_parser("prepare"); p.add_argument("--deployment-id")
    p = sub.add_parser("traffic"); p.add_argument("--deployment-id"); p.add_argument("--dry-run", action="store_true"); p.add_argument("--skip-dhcp", action="store_true")
    p = sub.add_parser("telemetry"); p.add_argument("--deployment-id"); p.add_argument("args", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    config = Path(a.config)
    if not config.is_absolute(): config = Path.cwd() / config
    if not config.exists():
        raise RuntimeError(f"User config not found: {config}. Run demo init first.")

    if a.cmd == "doctor": return deploy_cmd(config, ["doctor"])
    if a.cmd == "deploy":
        rest = ["deploy"] + (["--dry-run"] if a.dry_run else []) + (["--new"] if a.new else []) + (["--deployment-id", a.deployment_id] if a.deployment_id else [])
        rc = deploy_cmd(config, rest)
        if rc == 0 and not a.dry_run:
            try: write_telemetry_config(config, a.deployment_id)
            except Exception as e: print(f"Telemetry config warning: {e}", file=sys.stderr)
        return rc
    if a.cmd == "status": return deploy_cmd(config, ["status"] + (["--deployment-id", a.deployment_id] if a.deployment_id else []))
    if a.cmd == "cleanup": return deploy_cmd(config, ["cleanup"] + (["--deployment-id", a.deployment_id] if a.deployment_id else []))

    generated = write_telemetry_config(config, getattr(a, "deployment_id", None))
    if a.cmd == "configure-telemetry": return 0
    if a.cmd == "prepare": return telemetry(["prepare"], generated)
    if a.cmd == "traffic":
        cfg = load_yaml(generated)
        rest = ["run-demo", "--dry-run"] if a.dry_run else ["run-demo"]
        if a.skip_dhcp or "dhcp" not in cfg: rest.append("--skip-dhcp")
        if "ipam" not in cfg: rest.append("--skip-ipam")
        return telemetry(rest, generated)
    if a.cmd == "telemetry":
        rest = list(a.args)
        if rest and rest[0] == "--": rest = rest[1:]
        if not rest: raise RuntimeError("telemetry requires a demo CLI command after --")
        return telemetry(rest, generated)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        raise SystemExit(2)
