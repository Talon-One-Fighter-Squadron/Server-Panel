# =============================
# Dependency bootstrap (auto-installs if missing)
# =============================
import sys
import subprocess
import base64
import importlib.util

# pip package -> import module mapping (when they differ)
PIP_TO_IMPORT = {
    "discord.py": "discord",
    "Pillow": "PIL",
}

REQUIRED_PACKAGES = [
    "flask>=3.0.0",
    "psutil",
    "discord.py>=2.3.2",
    "Pillow>=10.0.0",
]


def _pip_name(pkg: str) -> str:
    return pkg.split(">=")[0].split("==")[0]

def _import_name(pip_name: str) -> str:
    return PIP_TO_IMPORT.get(pip_name, pip_name)

def ensure_package(pkg: str):
    pip_name = _pip_name(pkg)
    import_name = _import_name(pip_name)
    try:
        spec = importlib.util.find_spec(import_name)
    except ModuleNotFoundError:
        spec = None
    if spec is None:
        print(f"[bootstrap] Installing missing package: {pkg}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-user", pkg])

for _p in REQUIRED_PACKAGES:
    ensure_package(_p)

# =============================
# Normal imports
# =============================
import os
import time
import datetime
import re
import json
import shutil
import zipfile
import io
import threading
import urllib.request
import secrets
import uuid
import traceback
from pathlib import Path
from functools import wraps
from typing import Optional, Tuple


# =============================
# Windows Firewall management (best-effort, rules created/owned by panel only)
# =============================
import platform

FW_RULE_PREFIX = "NuclearOptionPanel::"
FW_GROUP = "Nuclear Option Server Panel"

# Avoid expensive PowerShell firewall churn on every page refresh.
# We only re-ensure cluster rules periodically; server-specific rules are still
# updated when servers are created/edited/deleted.
_FW_LAST_CLUSTER_ENSURE_TS = 0.0
_FW_CLUSTER_ENSURE_MIN_INTERVAL_SEC = 20.0

def _is_windows() -> bool:
    try:
        return platform.system().lower().startswith("win")
    except Exception:
        return False

def _fw_ps(cmd: str) -> tuple[int, str]:
    """Run a PowerShell command and return (rc, output). Best-effort."""
    if not _is_windows():
        return 0, ""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            capture_output=True,
            text=True,
        )
        out = (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
        return int(p.returncode), out.strip()
    except Exception as e:
        return 1, str(e)

def _fw_remove_rule(display_name: str) -> None:
    dn = display_name.replace("'", "''")
    _fw_ps(f"Get-NetFirewallRule -DisplayName '{dn}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue")

def _fw_add_rule(display_name: str, direction: str, protocol: str, port: int, remote_addr: str = "LocalSubnet", edge: bool = False, profile: str = "Any", program: str | None = None) -> None:
    dn = display_name.replace("'", "''")
    dirv = direction
    prot = protocol.upper()
    # Use LocalPort for BOTH inbound and outbound rules. This matters on systems where outbound is restricted.
    port_arg = f"-LocalPort {int(port)}"
    edge_arg = "-EdgeTraversalPolicy Allow" if edge and dirv.lower() == "inbound" else ""
    prog_arg = ""
    try:
        if program:
            p = str(program).strip()
            if p:
                # Quote single quotes for PowerShell strings.
                p = p.replace("'", "''")
                prog_arg = f" -Program '{p}'"
    except Exception:
        prog_arg = ""
    cmd = (
        f"New-NetFirewallRule -DisplayName '{dn}' -Group '{FW_GROUP}' -Direction {dirv} "
        f"-Action Allow -Protocol {prot} {port_arg}{prog_arg} -Profile {profile} -RemoteAddress {remote_addr} {edge_arg} -ErrorAction SilentlyContinue"
    )
    _fw_ps(cmd)



def _fw_add_program_rule(display_name: str, direction: str, program: str, remote_addr: str = "Any", profile: str = "Any") -> None:
    """Allow an executable in Windows Firewall so the first-run popup never appears.

    We intentionally do NOT bind this rule to specific ports; port-specific rules are handled separately.
    """
    try:
        dn = display_name.replace("'", "''")
        dirv = direction
        p = str(program or "").strip()
        if not p:
            return
        p = p.replace("'", "''")
        cmd = (
            f"New-NetFirewallRule -DisplayName '{dn}' -Group '{FW_GROUP}' -Direction {dirv} "
            f"-Action Allow -Program '{p}' -Profile {profile} -RemoteAddress {remote_addr} "
            f"-ErrorAction SilentlyContinue"
        )
        _fw_ps(cmd)
    except Exception:
        pass

def _fw_ensure_program_rule(display_name: str, direction: str, program: str, remote_addr: str = "Any", profile: str = "Any") -> None:
    try:
        _fw_remove_rule(display_name)
        _fw_add_program_rule(display_name, direction, program, remote_addr=remote_addr, profile=profile)
    except Exception:
        pass

def _fw_ensure_rule(display_name: str, direction: str, protocol: str, port: int, remote_addr: str = "LocalSubnet", edge: bool = False, program: str | None = None) -> None:
    try:
        _fw_remove_rule(display_name)
        _fw_add_rule(display_name, direction, protocol, port, remote_addr=remote_addr, edge=edge, program=program)
    except Exception:
        pass

def _fw_remove_server_rules(server_id: str) -> None:
    try:
        sid = str(server_id).strip()
        if not sid:
            return
        # Remove only rules created by the panel for this server (both legacy and current names).
        # Legacy (single rule per port/protocol):
        for kind in ("Game", "Query", "RemoteCommands"):
            for prot in ("TCP", "UDP"):
                _fw_remove_rule(f"{FW_RULE_PREFIX}Server::{sid}::{kind}::{prot}")
        # Current (separate inbound/outbound):
        for kind in ("Game", "Query"):
            for prot in ("TCP", "UDP"):
                _fw_remove_rule(f"{FW_RULE_PREFIX}Server::{sid}::{kind}::{prot}::In")
                _fw_remove_rule(f"{FW_RULE_PREFIX}Server::{sid}::{kind}::{prot}::Out")
        _fw_remove_rule(f"{FW_RULE_PREFIX}Server::{sid}::RemoteCommands::TCP")
        _fw_remove_rule(f"{FW_RULE_PREFIX}Server::{sid}::Program::In")
        _fw_remove_rule(f"{FW_RULE_PREFIX}Server::{sid}::Program::Out")
    except Exception:
        pass

def _fw_sync_server_rules(server: dict) -> None:
    """Create/update firewall rules for this server.

    - Game + Query ports: TCP+UDP inbound+outbound (so WAN and LAN clients can reach the server and responses are allowed)
    - RemoteCommands port: TCP inbound (LocalSubnet only, so you don't expose RCON to the internet)

    Notes:
      - If game/query ports are missing from servers.json (common when deploying with
        defaults), we still open the default ports to avoid "server invisible until
        firewall disabled" situations.
    """
    try:
        sid = str(server.get("id") or "").strip()
        if not sid:
            return
        _fw_remove_server_rules(sid)

        def _valid(p):
            try:
                if p is None or p == "":
                    return None
                n = int(p)
                return n if 1 <= n <= 65535 else None
            except Exception:
                return None

        gp = _valid(server.get("game_port"))
        qp = _valid(server.get("query_port"))
        rp = _valid(server.get("remote_commands_port"))

        if gp is None:
            gp = _valid(getattr(config, "DEFAULT_GAME_PORT", 7777))
        if qp is None:
            qp = _valid(getattr(config, "DEFAULT_QUERY_PORT", 27015))

        # Best effort program pinning (helps on some Windows firewall setups).
        exe_path = None
        try:
            inst = str(server.get("install_dir") or "").strip()
            if inst:
                cand = os.path.join(inst, "NuclearOptionServer.exe")
                if os.path.exists(cand):
                    exe_path = cand
        except Exception:
            exe_path = None


        # Pre-create program allow rules to prevent the Windows "Allow access" prompt on first listen.
        if exe_path:
            _fw_ensure_program_rule(f"{FW_RULE_PREFIX}Server::{sid}::Program::In", "Inbound", exe_path, remote_addr="Any")
            _fw_ensure_program_rule(f"{FW_RULE_PREFIX}Server::{sid}::Program::Out", "Outbound", exe_path, remote_addr="Any")

        if gp:
            for prot in ("TCP", "UDP"):
                _fw_ensure_rule(f"{FW_RULE_PREFIX}Server::{sid}::Game::{prot}::In", "Inbound", prot, gp, remote_addr="Any", edge=(prot == "UDP"), program=exe_path)
                _fw_ensure_rule(f"{FW_RULE_PREFIX}Server::{sid}::Game::{prot}::Out", "Outbound", prot, gp, remote_addr="Any", edge=False, program=exe_path)
        if qp:
            for prot in ("TCP", "UDP"):
                _fw_ensure_rule(f"{FW_RULE_PREFIX}Server::{sid}::Query::{prot}::In", "Inbound", prot, qp, remote_addr="Any", edge=(prot == "UDP"), program=exe_path)
                _fw_ensure_rule(f"{FW_RULE_PREFIX}Server::{sid}::Query::{prot}::Out", "Outbound", prot, qp, remote_addr="Any", edge=False, program=exe_path)
        if rp:
            _fw_ensure_rule(f"{FW_RULE_PREFIX}Server::{sid}::RemoteCommands::TCP", "Inbound", "TCP", rp, remote_addr="LocalSubnet", edge=False)
    except Exception:
        pass

def _fw_ensure_cluster_discovery_rules(http_port: int, discovery_port: int) -> None:
    """Ensure firewall allows LAN discovery + LAN join/approve traffic. Panel-owned rules only."""
    try:
        global _FW_LAST_CLUSTER_ENSURE_TS
        now = time.time()
        if now - float(_FW_LAST_CLUSTER_ENSURE_TS) < float(_FW_CLUSTER_ENSURE_MIN_INTERVAL_SEC):
            return
        _FW_LAST_CLUSTER_ENSURE_TS = now
        _fw_ensure_rule(f"{FW_RULE_PREFIX}Cluster::HTTP::{int(http_port)}::TCP", "Inbound", "TCP", int(http_port), remote_addr="LocalSubnet", edge=False)
        _fw_ensure_rule(f"{FW_RULE_PREFIX}Cluster::Discovery::{int(discovery_port)}::UDP::In", "Inbound", "UDP", int(discovery_port), remote_addr="LocalSubnet", edge=True)
        _fw_ensure_rule(f"{FW_RULE_PREFIX}Cluster::Discovery::{int(discovery_port)}::UDP::Out", "Outbound", "UDP", int(discovery_port), remote_addr="LocalSubnet", edge=False)
    except Exception:
        pass


def _fw_list_panel_rule_names() -> list[str]:
    """Return firewall rule display names that appear to be owned by the panel.

    We consider rules owned if either:
    - Rule Group matches FW_GROUP (preferred)
    - DisplayName starts with FW_RULE_PREFIX (legacy)
    """
    if not _is_windows():
        return []
    names: set[str] = set()

    def _load_json_list(ps: str) -> list[dict]:
        rc, out = _fw_ps(ps)
        if rc != 0 or not out:
            return []
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                return [data]
            if isinstance(data, list):
                return data
        except Exception:
            return []
        return []

    # Primary: group owned rules
    g = FW_GROUP.replace("'", "''")
    rows = _load_json_list(
        f"Get-NetFirewallRule -Group '{g}' -ErrorAction SilentlyContinue | Select-Object DisplayName,Group | ConvertTo-Json -Compress"
    )
    for r in rows:
        dn = str(r.get("DisplayName") or "").strip()
        if dn:
            names.add(dn)

    # Secondary: legacy prefix match (even if group isn't set)
    pref = (FW_RULE_PREFIX + "*").replace("'", "''")
    rows2 = _load_json_list(
        f"Get-NetFirewallRule -DisplayName '{pref}' -ErrorAction SilentlyContinue | Select-Object DisplayName,Group | ConvertTo-Json -Compress"
    )
    for r in rows2:
        dn = str(r.get("DisplayName") or "").strip()
        if dn:
            names.add(dn)

    return sorted(names)


def _fw_desired_rule_names_for_host() -> set[str]:
    """Compute the set of firewall rule display names that should exist on THIS host."""
    desired: set[str] = set()

    # Cluster/LAN discovery rules (owned by panel)
    http_port = int(getattr(config, "FLASK_PORT", 5000))
    discovery_port = int(DISCOVERY_PORT)
    desired.add(f"{FW_RULE_PREFIX}Cluster::HTTP::{http_port}::TCP")
    desired.add(f"{FW_RULE_PREFIX}Cluster::Discovery::{discovery_port}::UDP::In")
    desired.add(f"{FW_RULE_PREFIX}Cluster::Discovery::{discovery_port}::UDP::Out")

    # Local server Game/Query rules
    def _valid_port(v):
        try:
            if v is None or v == "":
                return None
            n = int(v)
            return n if 1 <= n <= 65535 else None
        except Exception:
            return None

    for s in (load_servers() or []):
        sid = str(s.get("id") or "").strip()
        if not sid:
            continue
        gp = _valid_port(s.get("game_port"))
        qp = _valid_port(s.get("query_port"))
        if gp:
            desired.add(f"{FW_RULE_PREFIX}Server::{sid}::Game::TCP")
            desired.add(f"{FW_RULE_PREFIX}Server::{sid}::Game::UDP")
        if qp:
            desired.add(f"{FW_RULE_PREFIX}Server::{sid}::Query::TCP")
            desired.add(f"{FW_RULE_PREFIX}Server::{sid}::Query::UDP")

    return desired


def _fw_cleanup_stale_panel_rules() -> tuple[int, int, list[str]]:
    """Remove stale panel-owned firewall rules.

    Returns (removed_count, kept_count, removed_names)
    """
    if not _is_windows():
        return 0, 0, []

    existing = _fw_list_panel_rule_names()
    desired = _fw_desired_rule_names_for_host()

    removed: list[str] = []
    kept = 0
    for dn in existing:
        if dn in desired:
            kept += 1
            continue
        _fw_remove_rule(dn)
        removed.append(dn)

    return len(removed), kept, removed


import psutil
import socket
from flask import Flask, jsonify, request, Response, render_template, session, redirect, url_for, abort

# Cluster (LAN)
from cluster import ClusterDiscovery, ClusterState, DISCOVERY_PORT, best_effort_local_ip, http_post_json

import config
import server_commands
from discord_bot import DiscordBotManager


# --- Path roots (stable regardless of current working directory) ---
BASE_DIR = Path(__file__).resolve().parent


# ---------------- Branding (accent color + logo) ----------------
BRANDING_PATH = BASE_DIR / "branding.json"
BRANDING_STATIC_DIR = BASE_DIR / "static" / "branding"
BRANDING_LOGO_PATH = BRANDING_STATIC_DIR / "logo.png"
BRANDING_DEFAULTS = {
    "accent": "#6c63ff",
    "accent2": "#b86bff",
}

def _load_branding() -> dict:
    data = {}
    try:
        if BRANDING_PATH.exists():
            data = _read_json_file(BRANDING_PATH) or {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        data = {}
    out = {**BRANDING_DEFAULTS, **data}
    out["has_logo"] = BRANDING_LOGO_PATH.exists()
    return out

def _save_branding(data: dict) -> None:
    if not isinstance(data, dict):
        return
    current = _load_branding()
    current.update({k: data[k] for k in data.keys()})
    clean = {
        "accent": current.get("accent") or BRANDING_DEFAULTS["accent"],
        "accent2": current.get("accent2") or BRANDING_DEFAULTS["accent2"],
    }
    _write_json_file(BRANDING_PATH, clean)

def _is_hex_color(s: str) -> bool:
    if not isinstance(s, str):
        return False
    return bool(re.fullmatch(r"#?[0-9a-fA-F]{6}", s.strip()))

def _normalize_hex(s: str) -> str:
    s = s.strip()
    if not s.startswith("#"):
        s = "#" + s
    return s.lower()

def _fit_logo_square_bytes(in_bytes: bytes, out_path: Path, size: int = 42) -> None:
    from PIL import Image, ImageOps
    import io
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with Image.open(io.BytesIO(in_bytes)) as im:
        im = im.convert("RGBA")
        fitted = ImageOps.fit(im, (size, size), method=Image.Resampling.LANCZOS, centering=(0.5, 0.5))
        fitted.save(out_path, format="PNG", optimize=True)

SERVERS_DIR = BASE_DIR / "servers"
TOOLS_DIR = BASE_DIR / "tools"
MISSIONS_DIR = BASE_DIR / "missions"
SERVERS_DIR.mkdir(parents=True, exist_ok=True)
TOOLS_DIR.mkdir(parents=True, exist_ok=True)
MISSIONS_DIR.mkdir(parents=True, exist_ok=True)

# -----------------------------
# Discord internal auth (localhost-only)
# -----------------------------
DISCORD_CONFIG_PATH = BASE_DIR / "discord_config.json"

def _load_or_create_discord_internal_secret() -> str:
    """
    Used to allow the local Discord bot process to call API endpoints without a browser session.
    Safety: only accepted from localhost, and requires this secret header.
    """
    try:
        if DISCORD_CONFIG_PATH.exists():
            data = json.loads(DISCORD_CONFIG_PATH.read_text(encoding="utf-8"))
            s = str(data.get("internal_secret", "") or "")
            if s:
                return s
    except Exception:
        pass
    # generate + persist
    s = secrets.token_urlsafe(32)
    try:
        existing = {}
        if DISCORD_CONFIG_PATH.exists():
            existing = json.loads(DISCORD_CONFIG_PATH.read_text(encoding="utf-8"))
        existing["internal_secret"] = s
        DISCORD_CONFIG_PATH.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except Exception:
        # if we can't persist, still return a secret for this run
        pass
    return s

DISCORD_INTERNAL_SECRET = _load_or_create_discord_internal_secret()

# Discord bot manager (optional)
discord_manager = DiscordBotManager(BASE_DIR)

# =============================
# Cluster (LAN)
# =============================
CLUSTER_FILE = BASE_DIR / "cluster.json"
_cluster_discovery = ClusterDiscovery()
_cluster_discovery.start()
cluster_state = ClusterState(CLUSTER_FILE, _cluster_discovery)

# Ensure node identity exists (node_id persists in cluster.json)
try:
    cluster_state.ensure_node_identity(
        node_name=os.environ.get("NO_PANEL_NODE_NAME") or os.environ.get("COMPUTERNAME") or "PanelNode",
        ip=best_effort_local_ip(),
        http_port=int(getattr(config, "FLASK_PORT", 5000)),
    )
except Exception:
    pass

# Best-effort: open firewall for LAN cluster discovery + join traffic on startup.
# (Only works when the process is elevated; we never touch non-panel rules.)
try:
    if _is_windows():
        _fw_ensure_cluster_discovery_rules(int(getattr(config, "FLASK_PORT", 5000)), int(DISCOVERY_PORT))
except Exception:
    pass



# =============================
# Cluster helpers for server ownership / deployment
# =============================
def _this_node_id() -> str:
    try:
        return str(cluster_state.state.get("this_node", {}).get("node_id") or "")
    except Exception:
        return ""

def _find_member_by_node_id(node_id: str) -> dict | None:
    try:
        for m in list(cluster_state.state.get("members", [])):
            if str(m.get("node_id") or "") == str(node_id):
                return m
    except Exception:
        pass
    return None

def _member_base_url(member: dict) -> str | None:
    try:
        ip = member.get("ip")
        port = member.get("http_port")
        if not ip or not port:
            return None
        return f"http://{ip}:{int(port)}"
    except Exception:
        return None

def _cluster_signed_post_to_member(member: dict, path: str, payload: dict, timeout: int = 20) -> dict:
    """POST JSON to a cluster member with HMAC headers."""
    base = _member_base_url(member)
    if not base:
        return {"success": False, "error": "Member missing ip/http_port"}
    url = base + path
    body_bytes = json.dumps(payload).encode("utf-8")
    headers = cluster_state.make_signed_headers("POST", path, body_bytes)
    try:
        return http_post_json(url, payload, headers=headers, timeout=timeout)
    except Exception as e:
        return {"success": False, "error": f"Request failed: {e}"}

# Built-in mission names (no files needed). Extend as desired.
BUILTIN_MISSIONS = [
    "Altercation",
    "Breakout",
    "Confrontation",
    "Domination",
    "Escalation",
    "Terminal Control",
]



# =============================
# Server instances storage (servers.json)
# =============================

class NoServersConfigured(RuntimeError):
    """Raised when an endpoint requires a managed server but none are configured."""

def _servers_file_path() -> Path:
    return BASE_DIR / getattr(config, "SERVERS_FILE", "servers.json")

def load_servers() -> list[dict]:
    p = _servers_file_path()
    if not p.exists():
        # Start empty: user must create their first server in the Server Management tab.
        p.write_text(json.dumps({"servers": []}, indent=2), encoding="utf-8")
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        servers = data.get("servers", []) or []
        return servers
    except Exception:
        return []

def save_servers(servers: list[dict]) -> None:
    p = _servers_file_path()
    p.write_text(json.dumps({"servers": servers}, indent=2), encoding="utf-8")


def _update_server_fields(server_id: str, updates: dict) -> None:
    """Update a server entry in servers.json by id.

    Used by several endpoints (including cluster proxy) to persist small fields
    like mission slots, password, MOTD settings, etc.
    """
    sid = (server_id or '').strip()
    if not sid:
        raise KeyError('Unknown server_id:')
    servers = load_servers()
    found = False
    for s in servers:
        if s.get('id') == sid:
            if updates:
                s.update(updates)
            found = True
            break
    if not found:
        raise KeyError(f'Unknown server_id: {sid}')
    save_servers(servers)
    # refresh local cache entry if present
    try:
        _SERVERS_VIEW_CACHE[sid] = next(ss for ss in servers if ss.get('id') == sid)
    except Exception:
        pass

def get_server_by_id(server_id: Optional[str]) -> dict:
    servers = load_servers()
    if not servers:
        raise NoServersConfigured("No servers configured. Create one in the Server Management tab first.")
    sid = (server_id or "").strip()
    if not sid:
        return servers[0]
    for s in servers:
        if s.get("id") == sid:
            return s
    # If a specific server_id was provided and not found locally, do NOT
    # fall back to the first server. That can cause operations intended for a
    # remote server (selected via the unified cluster list) to run against the
    # wrong local server.
    raise KeyError(f"Unknown server_id: {sid}")


# --- Cluster server view cache ---
# If a member is slow/unreachable, rebuilding the unified view can temporarily omit
# remote servers. The UI still has those server_ids selected, so remote actions
# should fall back to the last known mapping.
_SERVERS_VIEW_CACHE: dict[str, dict] = {}




def _find_server_by_id(server_id: Optional[str]) -> Optional[dict]:
    """Safe local server lookup. Returns None when server_id is unknown."""
    try:
        return get_server_by_id(server_id)
    except KeyError:
        return None

def _cache_servers_view(items: list[dict]) -> None:
    """Cache servers by id for remote proxy lookups."""
    global _SERVERS_VIEW_CACHE
    for s in items or []:
        sid = str(s.get("id") or "").strip()
        if sid:
            _SERVERS_VIEW_CACHE[sid] = s

def _is_server_running(install_dir: Optional[str]) -> bool:
    try:
        if not install_dir:
            return bool(find_running_server_exe())
        base = os.path.abspath(install_dir)
        for proc in psutil.process_iter(["name", "exe"]):
            try:
                if proc.info["name"] != SERVER_EXE_NAME:
                    continue
                exe = proc.info.get("exe") or ""
                if exe and os.path.abspath(exe).startswith(base):
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False
    except Exception:
        return False

def _server_install_dir_for(server: dict) -> Optional[str]:
    return server.get("install_dir") or find_server_install_dir()

def _server_bat_for(server_dir: Optional[str]) -> Optional[str]:
    if not server_dir:
        return None
    return find_start_bat(server_dir)

def _server_config_path_for(server_dir: Optional[str]) -> Optional[Path]:
    if not server_dir:
        return None
    p = Path(server_dir) / "DedicatedServerConfig.json"
    return p if p.is_file() else None

def _get_request_server_id() -> Optional[str]:
    if request.method == "GET":
        return request.args.get("server_id")
    try:
        data = request.get_json(silent=True) or {}
        return data.get("server_id")
    except Exception:
        return None


def _update_server_game_query_ports_local(server_id: str, game_port: Optional[int], query_port: Optional[int]) -> tuple[bool, Optional[str]]:
    """Update the stored Game/Query ports for a local server and best-effort apply them to DedicatedServerConfig.json.

    - game_port/query_port may be None to indicate "use defaults".
    """
    try:
        servers = load_servers() or []
        target = None
        for s in servers:
            if str(s.get("id") or "") == str(server_id):
                target = s
                break
        if not target:
            return False, "Server not found"

        target["game_port"] = game_port
        target["query_port"] = query_port
        save_servers(servers)

        # Best-effort: manage Windows Firewall rules for this server's ports (panel-owned rules only)
        try:
            _fw_sync_server_rules(target)
        except Exception:
            pass

        # Best-effort: apply overrides in DedicatedServerConfig.json if it exists.
        server_dir = _server_install_dir_for(target)
        cfg_path = _server_config_path_for(server_dir)
        if cfg_path and cfg_path.exists():
            try:
                cfg = _read_json_file(cfg_path) or {}
                # Game port
                if isinstance(cfg.get("Port"), dict):
                    if isinstance(game_port, int):
                        cfg["Port"]["IsOverride"] = True
                        cfg["Port"]["Value"] = int(game_port)
                    else:
                        # Clear override
                        cfg["Port"]["IsOverride"] = False
                # Query port
                if isinstance(cfg.get("QueryPort"), dict):
                    if isinstance(query_port, int):
                        cfg["QueryPort"]["IsOverride"] = True
                        cfg["QueryPort"]["Value"] = int(query_port)
                    else:
                        cfg["QueryPort"]["IsOverride"] = False
                _write_json_file(cfg_path, cfg)
            except Exception:
                # Don't fail the whole API call if config edit fails.
                pass

        return True, None
    except Exception as e:
        return False, str(e)


# =============================
# Flask app
# =============================
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = getattr(config, "SECRET_KEY", None) or os.environ.get("NO_PANEL_SECRET_KEY") or "CHANGE_ME_SECRET_KEY"

# Used to invalidate browser sessions on panel restart.
# Flask sessions are client-side cookies, so without this, a user may remain logged in
# until the cookie expires. By tying the session to a per-boot nonce, we force re-auth.
PANEL_BOOT_ID = secrets.token_urlsafe(16)



# =============================
# Auth (Session-based + users.json)
# =============================

USERS_FILE = BASE_DIR / "panel_users.json"
LOGIN_AUDIT_FILE = BASE_DIR / "login_attempts.json"
BLOCKED_IPS_FILE = BASE_DIR / "blocked_ips.json"
AUDIT_LOG_FILE = BASE_DIR / "panel_audit.jsonl"

DEFAULT_BOOTSTRAP_USERNAME = getattr(config, "USERNAME", "admin")
DEFAULT_BOOTSTRAP_PASSWORD = getattr(config, "PASSWORD", "changeme")

def _now_ts() -> float:
    return time.time()

def _iso_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    return xff or request.remote_addr or "unknown"

def _is_localhost() -> bool:
    ip = request.remote_addr or ""
    return ip in ("127.0.0.1", "::1")

def _load_json_file(path: Path, default):
    try:
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def _save_json_file(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _append_audit(event: str, details: dict) -> None:
    rec = {
        "ts": _now_ts(),
        "time": _iso_now(),
        "ip": _client_ip(),
        "user": session.get("username"),
        "event": event,
        "details": details or {},
    }
    with AUDIT_LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

from werkzeug.security import generate_password_hash, check_password_hash

def _ensure_user_store() -> None:
    if USERS_FILE.exists():
        return
    users = {
        "users": [
            {
                "username": DEFAULT_BOOTSTRAP_USERNAME,
                "password_hash": generate_password_hash(DEFAULT_BOOTSTRAP_PASSWORD),
                "role": "admin",
                "created_at": _iso_now(),
                "must_change_password": True,
            }
        ]
    }
    _save_json_file(USERS_FILE, users)

def _get_user(username: str) -> Optional[dict]:
    _ensure_user_store()
    data = _load_json_file(USERS_FILE, {"users": []})
    for u in data.get("users", []):
        if u.get("username", "").lower() == (username or "").lower():
            return u
    return None

def _get_users() -> list[dict]:
    """Return the full list of panel users.

    The cluster join approval flow may sync users to a newly joined member so the
    member node can immediately authenticate incoming coordinator calls.
    """
    _ensure_user_store()
    data = _load_json_file(USERS_FILE, {"users": []})
    users = data.get("users", [])
    return list(users) if isinstance(users, list) else []

def _set_users(users_list: list[dict]) -> None:
    _save_json_file(USERS_FILE, {"users": users_list})

def _blocked_ips() -> dict:
    return _load_json_file(BLOCKED_IPS_FILE, {"blocked": []})

def _is_ip_blocked(ip: str) -> bool:
    data = _blocked_ips()
    return any(x.get("ip") == ip for x in data.get("blocked", []))

def _block_ip(ip: str, reason: str) -> None:
    data = _blocked_ips()
    if any(x.get("ip") == ip for x in data.get("blocked", [])):
        return
    data["blocked"].append({"ip": ip, "blocked_at": _iso_now(), "reason": reason})
    _save_json_file(BLOCKED_IPS_FILE, data)
    _append_audit("ip_blocked", {"ip": ip, "reason": reason})

def _unblock_ip(ip: str) -> None:
    data = _blocked_ips()
    data["blocked"] = [x for x in data.get("blocked", []) if x.get("ip") != ip]
    _save_json_file(BLOCKED_IPS_FILE, data)
    _append_audit("ip_unblocked", {"ip": ip})

def _record_login_attempt(ip: str, username: str, success: bool) -> None:
    data = _load_json_file(LOGIN_AUDIT_FILE, {"attempts": []})
    attempts = data.get("attempts", [])
    attempts.append({
        "time": _iso_now(),
        "ts": _now_ts(),
        "ip": ip,
        "username": username or "",
        "success": bool(success),
    })
    attempts = attempts[-200:]
    data["attempts"] = attempts
    _save_json_file(LOGIN_AUDIT_FILE, data)

def _failed_count_for_ip(ip: str, window_seconds: int = 60 * 60) -> int:
    data = _load_json_file(LOGIN_AUDIT_FILE, {"attempts": []})
    now = _now_ts()
    count = 0
    for a in data.get("attempts", []):
        if a.get("ip") != ip:
            continue
        if a.get("success") is True:
            continue
        if now - float(a.get("ts", 0)) <= window_seconds:
            count += 1
    return count

@app.before_request
def _block_banned_ips_middleware():
    ip = _client_ip()

    # Force re-authentication after the panel process restarts.
    if session.get("username") and session.get("boot_id") != PANEL_BOOT_ID:
        session.clear()
        # For API calls, return 401 instead of redirect loops.
        if request.path.startswith("/api/") or request.path.startswith("/local/"):
            return jsonify({"success": False, "error": "Session expired. Please log in again."}), 401
        return redirect(url_for("login", next=request.path))

    if ip and _is_ip_blocked(ip) and not _is_localhost():
        if request.path == "/login" and request.method == "GET":
            return None
        return Response("Your IP is blocked from this panel.", 403)

def requires_login(role: Optional[str] = None):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            # Allow localhost Discord bot to call API endpoints without a browser session.
            # Restricted to localhost and requires X-Discord-Internal secret header.
            try:
                if _is_localhost():
                    dh = request.headers.get("X-Discord-Internal", "")
                    if dh and dh == DISCORD_INTERNAL_SECRET:
                        return fn(*args, **kwargs)
            except Exception:
                pass

            # Allow cluster-signed internal requests (coordinator <-> members)
            # without requiring a browser session.
            # This is critical for remote node control/proxy operations.
            try:
                body_bytes = request.get_data(cache=True) or b""
                ok, _reason = cluster_state.verify_signed_request(
                    request.method,
                    request.path,
                    body_bytes,
                    dict(request.headers),
                )
                if ok:
                    return fn(*args, **kwargs)
            except Exception:
                pass

            if not session.get("username"):
                return redirect(url_for("login", next=request.path))
            if role:
                u = _get_user(session.get("username"))
                if not u:
                    session.clear()
                    return redirect(url_for("login"))
                if role == "admin" and u.get("role") != "admin":
                    return Response("Admin access required.", 403)
            return fn(*args, **kwargs)
        return wrapped
    return deco


@app.get("/api/health")
def api_health():
    """Unauthenticated health check endpoint.

    This is used by cluster/coordinator diagnostics and external tooling
    to verify the node is reachable over the LAN without needing a login
    session.
    """
    return jsonify(
        success=True,
        node_id=cluster_state.node_id,
        node_name=cluster_state.node_name,
        is_coordinator=cluster_state.is_coordinator,
        cluster_enabled=bool(cluster_state.enabled),
        ts=int(time.time()),
    )


def requires_cluster_member_request(fn):
    """Allow only signed cluster member requests (HMAC headers).
    Used for /api/cluster/* endpoints that should only be callable by other nodes.
    """
    @wraps(fn)
    def wrapped(*args, **kwargs):
        try:
            body_bytes = request.get_data(cache=True) or b""
            ok, msg = cluster_state.verify_signed_request(
                request.method,
                request.path,
                body_bytes,
                dict(request.headers),
            )
            if not ok:
                return jsonify({"success": False, "error": msg}), 401
        except Exception as e:
            return jsonify({"success": False, "error": f"Cluster auth error: {e}"}), 401
        return fn(*args, **kwargs)
    return wrapped


# Some endpoints (like Gallery) use a lightweight boolean helper instead of
# the decorator above. Keep this helper for compatibility.
def _cluster_require_signed_request() -> bool:
    """Return True if the incoming request has a valid cluster HMAC signature."""
    try:
        body_bytes = request.get_data(cache=True) or b""
        ok, _msg = cluster_state.verify_signed_request(
            request.method,
            request.path,
            body_bytes,
            dict(request.headers),
        )
        return bool(ok)
    except Exception:
        return False


@app.get("/api/cluster/ping")
@requires_cluster_member_request
def api_cluster_ping():
    """Signed ping for coordinator<->member reachability tests."""
    return jsonify(success=True, node_id=cluster_state.node_id, ts=int(time.time()))




@app.route("/login", methods=["GET", "POST"])
def login():
    _ensure_user_store()
    ip = _client_ip()
    if request.method == "GET":
        return render_template("login.html", error=None, blocked=_is_ip_blocked(ip))
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "")
    if ip and _is_ip_blocked(ip) and not _is_localhost():
        return render_template("login.html", error="This IP is blocked.", blocked=True), 403

    user = _get_user(username)
    ok = bool(user) and check_password_hash(user.get("password_hash", ""), password)
    _record_login_attempt(ip, username, ok)

    if not ok:
        if ip and _failed_count_for_ip(ip) >= 3 and not _is_localhost():
            _block_ip(ip, "3 failed login attempts")
            return render_template("login.html", error="Too many failed attempts. IP blocked.", blocked=True), 403
        return render_template("login.html", error="Invalid username or password.", blocked=False), 401

    session["username"] = user["username"]
    session["role"] = user.get("role", "mod")
    session["boot_id"] = PANEL_BOOT_ID
    _append_audit("login_success", {"username": user["username"]})

    if user.get("must_change_password"):
        return redirect(url_for("first_run"))
    nxt = request.args.get("next") or "/"
    return redirect(nxt)

@app.route("/logout")
def logout():
    u = session.get("username")
    session.clear()
    if u:
        _append_audit("logout", {"username": u})
    return redirect(url_for("login"))

@app.route("/first-run", methods=["GET", "POST"])
@requires_login()
def first_run():
    u = _get_user(session.get("username"))
    if not u or not u.get("must_change_password"):
        return redirect(url_for("index"))
    if request.method == "GET":
        return render_template("first_run.html", error=None, current=u.get("username"))
    new_user = (request.form.get("new_username") or "").strip()
    new_pass = request.form.get("new_password") or ""
    if len(new_user) < 3 or len(new_pass) < 6:
        return render_template("first_run.html", error="Username must be 3+ chars and password 6+ chars.", current=u.get("username")), 400
    existing = _get_user(new_user)
    if existing and existing.get("username") != u.get("username"):
        return render_template("first_run.html", error="That username already exists.", current=u.get("username")), 400

    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    for usr in users_data:
        if usr.get("username", "").lower() == u.get("username","").lower():
            usr["username"] = new_user
            usr["password_hash"] = generate_password_hash(new_pass)
            usr["must_change_password"] = False
            break
    _set_users(users_data)
    session["username"] = new_user
    _append_audit("first_run_credentials_set", {"username": new_user})
    return redirect(url_for("index"))
# =============================
# Ports storage (ports.json)
# =============================
def _ports_file_path() -> Path:
    return BASE_DIR / getattr(config, "PORTS_FILE", "ports.json")

def save_ports(ports: list[dict]) -> None:
    p = _ports_file_path()
    payload = {"ports": ports}
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")

def load_ports() -> list[dict]:
    """
    Returns: [{"port": 7779, "name": "Default Server"}, ...]
    """
    p = _ports_file_path()
    if not p.exists():
        # Start empty. A port entry is created automatically when you create a server
        # in the Server Management tab.
        save_ports([])
        return []

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        ports = data.get("ports", [])
        out = []
        for item in ports:
            port = int(item["port"])
            name = str(item.get("name", f"Server {port}")).strip() or f"Server {port}"
            out.append({"port": port, "name": name})

        # unique ports
        seen = set()
        uniq = []
        for x in out:
            if x["port"] not in seen:
                uniq.append(x)
                seen.add(x["port"])

        return uniq
    except Exception:
        save_ports([])
        return []

def get_allowed_ports() -> list[int]:
    """Return the set of ports we allow remote commands on.

    Since the UI now selects a *server* (not a raw port), we allow:
      - any port listed in ports.json (legacy / manual entries)
      - any remote_commands_port defined on a server in servers.json
    """
    allowed: set[int] = set()

    # legacy/manual ports list
    try:
        for p in load_ports() or []:
            try:
                allowed.add(int(p.get("port")))
            except Exception:
                pass
    except Exception:
        pass

    # server-defined ports (primary path)
    try:
        data = load_servers()
        for s in data.get("servers", []) or []:
            try:
                allowed.add(int(s.get("remote_commands_port")))
            except Exception:
                pass
    except Exception:
        pass

    return sorted(allowed)


def validate_port(port) -> bool:
    try:
        return int(port) in get_allowed_ports()
    except Exception:
        return False


# =============================
# RemoteCommander helpers
# =============================
def create_remote_commander(port: int):
    # Remote commands bind to localhost in your setup
    return server_commands.RemoteCommander("127.0.0.1", int(port))

def get_commander_from_json(data: dict) -> Tuple[Optional[object], Optional[tuple]]:
    # Prefer explicit server_port, but allow server_id to select the port from servers.json
    port = data.get("server_port")
    if not validate_port(port):
        try:
            server = get_server_by_id(data.get("server_id"))
            fallback_port = server.get("remote_commands_port")
            if validate_port(fallback_port):
                port = fallback_port
            else:
                return None, (jsonify({"success": False, "error": f"Invalid server port: {port}"}), 400)
        except NoServersConfigured as e:
            return None, (jsonify({"success": False, "error": str(e)}), 400)
    return create_remote_commander(int(port)), None

def ok(status_code, response_body):
    return jsonify({"status_code": status_code, "response": response_body})


# =============================
# Auto-discovery: server EXE directory + BAT + config JSON
# =============================
SERVER_EXE_NAME = "NuclearOptionServer.exe"

def find_running_server_exe() -> Optional[str]:
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if proc.info["name"] == SERVER_EXE_NAME and proc.info["exe"]:
                return proc.info["exe"]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None

def find_server_install_dir() -> Optional[str]:
    exe = find_running_server_exe()
    if exe:
        return os.path.dirname(exe)

    candidates = [
        str(BASE_DIR),
        os.path.join(str(BASE_DIR), "NuclearOptionServer"),
        os.path.expanduser(r"~\Desktop\NuclearOptionServer"),
        os.path.expanduser(r"~\OneDrive\Desktop\NuclearOptionServer"),
    ]
    for c in candidates:
        if os.path.isfile(os.path.join(c, SERVER_EXE_NAME)):
            return c

    # bounded shallow scan under user home
    home = os.path.expanduser("~")
    max_depth = 4
    max_dirs_per_level = 30

    def walk_limited(root: str, depth: int) -> Optional[str]:
        if depth > max_depth:
            return None
        try:
            entries = list(os.scandir(root))
        except Exception:
            return None

        for e in entries:
            if e.is_file() and e.name.lower() == SERVER_EXE_NAME.lower():
                return root

        dirs = [e for e in entries if e.is_dir()]
        for d in dirs[:max_dirs_per_level]:
            found = walk_limited(d.path, depth + 1)
            if found:
                return found
        return None

    return walk_limited(home, 0)

def find_start_bat(server_dir: str) -> Optional[str]:
    if not server_dir or not os.path.isdir(server_dir):
        return None

    priority, fallback = [], []
    for name in os.listdir(server_dir):
        if not name.lower().endswith(".bat"):
            continue
        path = os.path.join(server_dir, name)
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().lower()
            if "nuclearoptionserver.exe" in content:
                if any(k in name.lower() for k in ("start", "run", "server")):
                    priority.append(path)
                else:
                    fallback.append(path)
        except Exception:
            continue

    priority.sort(key=lambda p: os.path.basename(p).lower())
    fallback.sort(key=lambda p: os.path.basename(p).lower())
    return priority[0] if priority else (fallback[0] if fallback else None)

def _server_dir(server_id: Optional[str] = None) -> str:
    server = get_server_by_id(server_id)
    d = _server_install_dir_for(server)
    if not d:
        raise RuntimeError("Could not locate NuclearOptionServer directory.")
    return d

def _config_path(server_id: Optional[str] = None) -> Path:
    return Path(_server_dir(server_id)) / "DedicatedServerConfig.json"

def _bat_path(server_id: Optional[str] = None) -> Path:
    d = _server_dir(server_id)
    bat = find_start_bat(d)
    if bat:
        return Path(bat)
    # fallback common name
    return Path(d) / "RunServer.bat"

def _read_text_smart(path: Path) -> tuple[str, str]:
    """Read text from a file while preserving common encodings (utf-8/utf-8-sig/utf-16)."""
    raw = path.read_bytes()

    # UTF-16 BOM
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        enc = "utf-16"
        return raw.decode(enc, errors="ignore"), enc

    # Heuristic: NUL bytes usually indicates UTF-16 without BOM
    if b"\x00" in raw[:200]:
        enc = "utf-16"
        return raw.decode(enc, errors="ignore"), enc

    enc = "utf-8-sig" if raw.startswith(b"\xef\xbb\xbf") else "utf-8"
    return raw.decode(enc, errors="ignore"), enc

def _write_text_smart(path: Path, text: str, encoding: str) -> None:
    """Write text back using the same encoding used when reading."""
    enc = (encoding or "utf-8").lower()
    if enc.startswith("utf-16"):
        path.write_text(text, encoding="utf-16")
    elif enc in ("utf-8-sig", "utf-8"):
        path.write_text(text, encoding=enc)
    else:
        path.write_text(text, encoding="utf-8")


def _read_json_file(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))

def _write_json_file(p: Path, data: dict) -> None:
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _parse_bat_settings(bat_text: str) -> dict:
    fps_m = re.search(r"(?i)\-limitframerate\s+(\d+)", bat_text)
    fps = int(fps_m.group(1)) if fps_m else None

    rc_m = re.search(r"(?i)\-ServerRemoteCommands(?:\s+(\d+))?", bat_text)
    rc_port = int(rc_m.group(1)) if (rc_m and rc_m.group(1)) else None

    return {"fps": fps, "remote_commands_port": rc_port}

def _set_bat_fps(bat_text: str, fps: int) -> tuple[str, bool]:
    if re.search(r"(?i)\-limitframerate\s+\d+", bat_text):
        new_text = re.sub(r"(?i)(\-limitframerate\s+)\d+", rf"\g<1>{fps}", bat_text)
        return new_text, (new_text != bat_text)

    # append to the exe launch line
    lines = bat_text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"(?i)\bNuclearOptionServer\.exe\b", line):
            lines[i] = line.rstrip() + f" -limitframerate {fps}"
            return "\n".join(lines) + ("\n" if bat_text.endswith("\n") else ""), True

    return bat_text, False

def _set_bat_remote_port(bat_text: str, port: int) -> tuple[str, bool, Optional[int]]:
    """
    Returns (new_text, changed, old_port_if_any)

    Handles robustly:
      -ServerRemoteCommands
      -ServerRemoteCommands 7779
      -ServerRemoteCommands <anything>   (fixes placeholders/blanks)
      (and adds it if missing)
    """
    old: Optional[int] = None

    m = re.search(r"(?i)\-ServerRemoteCommands(?:\s+(\S+))?", bat_text)
    if m and m.group(1):
        try:
            old = int(m.group(1))
        except Exception:
            old = None

    if m:
        new_text = re.sub(r"(?i)\-ServerRemoteCommands(?:\s+\S+)?", f"-ServerRemoteCommands {port}", bat_text)
        return new_text, (new_text != bat_text), old

    lines = bat_text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"(?i)\bNuclearOptionServer\.exe\b", line):
            lines[i] = line.rstrip() + f" -ServerRemoteCommands {port}"
            return "\n".join(lines) + ("\n" if bat_text.endswith("\n") else ""), True, old

    return bat_text, False, old


def _write_start_bat_settings(bat_path: str, fps: Optional[int] = None, remote_port: Optional[int] = None) -> None:
    """Best-effort helper used by Server Management create flow.

    Preserves common .bat encodings so SteamCMD-provided files don't get corrupted.
    """
    p = Path(bat_path)
    if not p.exists():
        return

    text, enc = _read_text_smart(p)
    new_text = text

    if fps is not None:
        new_text, _changed = _set_bat_fps(new_text, int(fps))
    if remote_port is not None:
        new_text, _changed2, _old = _set_bat_remote_port(new_text, int(remote_port))

    if new_text != text:
        _write_text_smart(p, new_text, enc)


def _sync_ports_tab_for_server(server_id: str, server_name: str, old_port: Optional[int], new_port: int):
    """
    Keep Ports tab in sync when a server's remote port changes.

    We store server_id inside each ports.json entry so we can reliably update/remove
    the correct entry even if names or ports collide.

    Behavior:
    - If an entry exists with matching server_id: update its port/name.
    - Else, if an entry matches old_port (and optionally name): update it and attach server_id.
    - Ensure no duplicates remain for this server_id.
    """
    ports = load_ports() or []
    ports = [p for p in ports if isinstance(p, dict) and "port" in p]

    def norm_name(x: str) -> str:
        return (x or "").strip().lower()

    # Find existing entry by server_id
    idx_sid = next((i for i, p in enumerate(ports) if str(p.get("server_id") or "") == str(server_id)), None)

    # Helper: find by port (first match)
    def find_by_port(port: int):
        return next((i for i, p in enumerate(ports) if int(p.get("port")) == int(port)), None)

    idx_old = find_by_port(old_port) if old_port else None
    idx_new = find_by_port(new_port)

    # Prefer server_id match
    if idx_sid is not None:
        ports[idx_sid]["port"] = int(new_port)
        ports[idx_sid]["name"] = server_name or ports[idx_sid].get("name") or f"Server {new_port}"
        ports[idx_sid]["server_id"] = str(server_id)
        # Remove duplicates for this server_id
        ports = [p for p in ports if str(p.get("server_id") or "") != str(server_id)] + [ports[idx_sid]]
        # Also remove any other entry with same port+name and no server_id (optional cleanup)
        cleaned=[]
        for p in ports:
            if str(p.get("server_id") or "")==str(server_id):
                cleaned.append(p); continue
            if int(p.get("port"))==int(new_port) and norm_name(p.get("name",""))==norm_name(server_name) and not p.get("server_id"):
                continue
            cleaned.append(p)
        save_ports(cleaned)
        return

    # No server_id entry yet: try to mutate old -> new and attach server_id
    if idx_old is not None and idx_new is None:
        ports[idx_old]["port"] = int(new_port)
        ports[idx_old]["name"] = server_name or ports[idx_old].get("name") or f"Server {new_port}"
        ports[idx_old]["server_id"] = str(server_id)
        save_ports(ports)
        return

    # If both exist, prefer new_port entry and attach server_id to it, remove old
    if idx_old is not None and idx_new is not None:
        ports[idx_new]["name"] = server_name or ports[idx_new].get("name") or f"Server {new_port}"
        ports[idx_new]["server_id"] = str(server_id)
        # remove old entry
        ports.pop(idx_old if idx_old < idx_new else idx_old)
        save_ports(ports)
        return

    # Ensure entry exists for new_port
    if idx_new is None:
        ports.append({"port": int(new_port), "name": server_name or f"Server {new_port}", "server_id": str(server_id)})
    else:
        ports[idx_new]["name"] = server_name or ports[idx_new].get("name") or f"Server {new_port}"
        ports[idx_new]["server_id"] = str(server_id)

    save_ports(ports)


# =============================
# SteamCMD auto-detection / auto-download
# =============================
def find_steamcmd() -> Optional[str]:
    p = shutil.which("steamcmd") or shutil.which("steamcmd.exe")
    if p and os.path.isfile(p):
        return p

    candidates = [
        r"C:\steamcmd\steamcmd.exe",
        r"C:\SteamCMD\steamcmd.exe",
        os.path.join(str(BASE_DIR), "steamcmd.exe"),
        os.path.join(str(BASE_DIR), "tools", "steamcmd", "steamcmd.exe"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    server_dir = find_server_install_dir()
    if server_dir:
        near = [
            os.path.join(server_dir, "steamcmd.exe"),
            os.path.join(server_dir, "steamcmd", "steamcmd.exe"),
            os.path.join(os.path.dirname(server_dir), "steamcmd", "steamcmd.exe"),
        ]
        for n in near:
            if os.path.isfile(n):
                return n

    return None

def ensure_steamcmd(download_dir: str) -> str:
    os.makedirs(download_dir, exist_ok=True)
    exe_path = os.path.join(download_dir, "steamcmd.exe")
    if os.path.isfile(exe_path):
        return exe_path

    url = "https://steamcdn-a.akamaihd.net/client/installer/steamcmd.zip"
    zip_path = os.path.join(download_dir, "steamcmd.zip")

    urllib.request.urlretrieve(url, zip_path)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(download_dir)

    if not os.path.isfile(exe_path):
        raise RuntimeError("SteamCMD download/extract finished but steamcmd.exe was not found.")
    return exe_path

def _run_bat_hidden_for_seconds(bat_path: str, cwd: str, seconds: int, output: list[str]) -> None:
    # Start BAT hidden (Windows), wait N seconds, then stop only server under cwd.
    seconds = max(1, int(seconds))
    try:
        creationflags = 0x08000000 if os.name == "nt" else 0
        output.append(f"First boot: starting '{bat_path}' (hidden) for {seconds}s...")
        subprocess.Popen(
            ["cmd.exe", "/c", str(bat_path)] if os.name == "nt" else [str(bat_path)],
            cwd=str(cwd),
            creationflags=creationflags,
        )
        time.sleep(seconds)
        _stop_server_processes_in_dir(Path(cwd), output)
    except Exception as e:
        output.append(f"First boot error: {e}")


def _stop_server_processes_in_dir(install_dir: Path, output: list[str]) -> None:
    # Stop ONLY NuclearOptionServer.exe processes whose executable path is inside install_dir.
    install_dir = install_dir.resolve()
    found = False

    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if (proc.info.get("name") or "").lower() != SERVER_EXE_NAME.lower():
                continue
            exe = proc.info.get("exe")
            if not exe:
                continue
            exe_path = Path(exe).resolve()
            if str(exe_path).lower().startswith(str(install_dir).lower()):
                found = True
                output.append(f"Stopping {SERVER_EXE_NAME} for {install_dir} (PID {proc.pid})...")
                proc.terminate()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(2)

    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if (proc.info.get("name") or "").lower() != SERVER_EXE_NAME.lower():
                continue
            exe = proc.info.get("exe")
            if not exe:
                continue
            exe_path = Path(exe).resolve()
            if str(exe_path).lower().startswith(str(install_dir).lower()):
                output.append(f"Force-killing {SERVER_EXE_NAME} for {install_dir} (PID {proc.pid})...")
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not found:
        output.append(f"No running {SERVER_EXE_NAME} found for: {install_dir}")


def _wait_for_file(path: Path, timeout_sec: int = 30) -> bool:
    end = time.time() + max(1, int(timeout_sec))
    while time.time() < end:
        if path.exists():
            return True
        time.sleep(0.5)
    return False

# =============================
# Routes
# =============================
@app.get("/")
@requires_login()
def index():
    ports = load_ports()
    allowed_ports = [p["port"] for p in ports]
    return render_template("index.html", ports=ports, allowed_ports=allowed_ports)


# ----- Ports API (Ports tab: Game/Query editor) -----
@app.get("/api/whoami")
@requires_login()
def api_whoami():
    return jsonify({"success": True, "username": session.get("username"), "role": session.get("role"), "is_local": (request.remote_addr in ("127.0.0.1","::1")), "ip": (request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.remote_addr)})


@app.get("/api/ports")
@requires_login("admin")
def api_get_ports():
    # Return per-server Game/Query ports (cluster-aware). This list is used by the Ports tab.
    servers = _build_servers_view()
    # Enrich with the editable port fields.
    by_id = {str(s.get("id") or ""): s for s in (load_servers() or [])}

    # If coordinator, also merge member-local editable fields from list_local responses.
    # _build_servers_view() already includes member servers, but list_local needs to provide
    # game_port/query_port so we can display/edit them.
    out = []
    for s in servers:
        sid = str(s.get("id") or "")
        base = dict(s)
        local_entry = by_id.get(sid)
        if local_entry:
            base["game_port"] = local_entry.get("game_port")
            base["query_port"] = local_entry.get("query_port")
        else:
            # Member entries are already expected to include these fields.
            base["game_port"] = s.get("game_port")
            base["query_port"] = s.get("query_port")
        out.append({
            "id": sid,
            "name": base.get("name"),
            "game_port": base.get("game_port"),
            "query_port": base.get("query_port"),
            "node_id": base.get("node_id"),
            "location": base.get("location"),
        })
    return jsonify({"success": True, "ports": out})

@app.post("/api/ports")
@requires_login("admin")
def api_set_ports():
    data = request.get_json(force=True, silent=True) or {}
    ports = data.get("ports", [])

    if not isinstance(ports, list):
        return jsonify({"success": False, "error": "ports must be a list"}), 400

    def _parse_port(v):
        if v is None or v == "":
            return None
        try:
            n = int(str(v).strip())
        except Exception:
            return "__invalid__"
        if n < 1 or n > 65535:
            return "__invalid__"
        return n

    # Build quick lookup of unified server list so we can route local vs member updates.
    unified = _build_servers_view()
    unified_by_id = {str(s.get("id") or ""): s for s in unified}

    # Validate and apply.
    for item in ports:
        sid = str(item.get("id") or "").strip()
        if not sid:
            continue

        gp = _parse_port(item.get("game_port"))
        qp = _parse_port(item.get("query_port"))
        if gp == "__invalid__" or qp == "__invalid__":
            return jsonify({"success": False, "error": f"Invalid port value for server {sid}. Ports must be blank or 1-65535."}), 400

        target = unified_by_id.get(sid)
        if not target:
            continue

        # Local update
        if target.get("location") != "remote":
            ok, err = _update_server_game_query_ports_local(sid, gp, qp)
            if not ok:
                return jsonify({"success": False, "error": err or "Failed to update ports"}), 500
            continue

        # Remote update (coordinator -> member)
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "Cannot edit remote server ports from a non-coordinator node."}), 400
        nid = str(target.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": f"Remote server owner not found for {sid}."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/servers/update_ports", {"server_id": sid, "game_port": gp, "query_port": qp}, timeout=15)
        if not isinstance(resp, dict) or not resp.get("success"):
            return jsonify({"success": False, "error": (resp.get("error") if isinstance(resp, dict) else "Bad response from member")}), 502

    # Return updated view for immediate UI refresh
    return jsonify({"success": True, "ports": api_get_ports().get_json().get("ports", [])})


# ----- Firewall cleanup (Ports tab helper) -----
@app.post("/api/firewall/cleanup")
@requires_login("admin")
def api_firewall_cleanup():
    """Remove stale Windows Firewall rules created by the panel.

    This is conservative: it only touches rules that appear owned by the panel
    (Group == FW_GROUP and/or DisplayName starts with FW_RULE_PREFIX).
    """
    if not _is_windows():
        return jsonify({"success": True, "message": "Not on Windows; no firewall rules to clean.", "removed_count": 0, "kept_count": 0, "removed": []})

    # Make sure the desired cluster rules exist before calculating staleness
    try:
        _fw_ensure_cluster_discovery_rules(int(getattr(config, "FLASK_PORT", 5000)), int(DISCOVERY_PORT))
        for s in (load_servers() or []):
            _fw_sync_server_rules(s)
    except Exception:
        pass

    removed_count, kept_count, removed = _fw_cleanup_stale_panel_rules()
    # Cap returned list size to keep responses light
    removed_preview = removed[:200]
    return jsonify({
        "success": True,
        "removed_count": int(removed_count),
        "kept_count": int(kept_count),
        "removed": removed_preview,
        "truncated": bool(len(removed) > len(removed_preview)),
    })



# ----- NOBlackBox (Tacview recorder) -----
NOBB_PLUGIN_DIRNAME = "NOBlackBox"
NOBB_CFG_FILENAME = "xyz.KopterBuzz.NOBlackBox.cfg"
NOBB_DEFAULT_CFG_PATH = Path(__file__).parent / "defaults" / "noblackbox.cfg"

def _nobb_resolve_server_root(install_dir: Path) -> Path:
    """Resolve the actual server root folder that contains BepInEx.
    Some users point install_dir at a child folder (or one level too high).
    We try a few nearby candidates and pick the first that has BepInEx/plugins or BepInEx/config.
    """
    try:
        install_dir = Path(install_dir)
    except Exception:
        return Path(install_dir)

    candidates: list[Path] = []
    if install_dir:
        candidates.append(install_dir)
        # one level up
        try:
            if install_dir.parent and install_dir.parent != install_dir:
                candidates.append(install_dir.parent)
        except Exception:
            pass
        # immediate children
        try:
            if install_dir.exists() and install_dir.is_dir():
                for child in install_dir.iterdir():
                    if child.is_dir():
                        candidates.append(child)
        except Exception:
            pass

    seen = set()
    for cand in candidates:
        try:
            c = cand.resolve()
        except Exception:
            c = cand
        if str(c) in seen:
            continue
        seen.add(str(c))
        bepinex = c / "BepInEx"
        if (bepinex / "plugins").exists() or (bepinex / "config").exists():
            return c
    return install_dir

def _nobb_get_paths(server: dict) -> tuple[Path, Path]:
    install_dir_raw = Path(server.get("install_dir") or "")
    server_root = _nobb_resolve_server_root(install_dir_raw)
    bepinex = server_root / "BepInEx"
    plugin_dir = bepinex / "plugins" / NOBB_PLUGIN_DIRNAME
    cfg_path = _nobb_find_cfg_path(server_root) or (bepinex / "config" / NOBB_CFG_FILENAME)
    return plugin_dir, cfg_path
def _nobb_debug_paths(server: dict) -> dict:
    """Return detailed path/debug info for NOBlackBox detection."""
    try:
        install_raw = Path(server.get("install_dir") or "")
    except Exception:
        install_raw = Path(str(server.get("install_dir") or ""))
    root = _nobb_resolve_server_root(install_raw)
    bepinex = root / "BepInEx"
    plugins = bepinex / "plugins"
    config = bepinex / "config"
    plugin_dir = plugins / NOBB_PLUGIN_DIRNAME
    found_cfg = _nobb_find_cfg_path(root)
    # Gather a small directory snapshot to help troubleshoot mismatched paths
    def _safe_list(p: Path, glob_pat: str = "*", limit: int = 25):
        out = []
        try:
            if p.exists() and p.is_dir():
                for i, item in enumerate(p.glob(glob_pat)):
                    if i >= limit:
                        break
                    out.append(item.name)
        except Exception:
            pass
        return out

    return {
        "install_dir_raw": str(install_raw),
        "resolved_root": str(root),
        "bepinex_dir": str(bepinex),
        "plugins_dir": str(plugins),
        "config_dir": str(config),
        "plugin_dir": str(plugin_dir),
        "exists": {
            "root": bool(root and root.exists()),
            "bepinex": bepinex.exists(),
            "plugins": plugins.exists(),
            "config": config.exists(),
            "plugin_dir": plugin_dir.exists(),
            "cfg_found": bool(found_cfg and found_cfg.exists()),
            "cfg_path_exists": bool((config / NOBB_CFG_FILENAME).exists()),
        },
        "cfg_found_path": str(found_cfg) if found_cfg else "",
        "dir_snapshot": {
            "root_items": _safe_list(root, "*", 30),
            "plugins_items": _safe_list(plugins, "*", 30),
            "plugin_dir_items": _safe_list(plugin_dir, "*", 30),
            "config_cfgs": _safe_list(config, "*.cfg", 30),
        },
    }

def _nobb_is_installed(server: dict) -> bool:
    """Detect whether the NOBlackBox *mod/plugin* is installed (DLL present).

    Note: Config presence alone is not treated as "installed" because a cfg may
    remain after uninstall or be copied in without the plugin.
    """
    install_dir_raw = Path(server.get("install_dir") or "")
    if not install_dir_raw:
        return False
    server_root = _nobb_resolve_server_root(install_dir_raw)

    bepinex = server_root / "BepInEx"
    plugins_dir = bepinex / "plugins"
    if not plugins_dir.exists():
        return False

    # Expected folder layout: BepInEx/plugins/NOBlackBox/*.dll
    expected = plugins_dir / NOBB_PLUGIN_DIRNAME
    if expected.exists() and any(p.suffix.lower() == ".dll" for p in expected.rglob("*.dll")):
        return True

    # Fallback: any DLL with 'noblackbox' in the name anywhere under plugins.
    for p in plugins_dir.rglob("*.dll"):
        try:
            if "noblackbox" in p.name.lower():
                return True
        except Exception:
            continue

    return False


def _nobb_has_config(server: dict) -> bool:
    """Detect whether the NOBlackBox config file exists (settings present)."""
    install_dir_raw = Path(server.get("install_dir") or "")
    if not install_dir_raw:
        return False
    server_root = _nobb_resolve_server_root(install_dir_raw)
    return _nobb_find_cfg_path(server_root) is not None

def _nobb_normalize_path(p: str) -> str:
    s = (p or "").strip()
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        s = s[1:-1].strip()
    # NOBlackBox config uses forward slashes; accept either.
    s = s.replace("\\", "/")
    # Ensure trailing slash for folders (most examples use it)
    if s and (not s.endswith("/")):
        s = s + "/"
    return s

def _nobb_cfg_to_dict(cfg_text: str) -> dict:
    out = {}
    for line in (cfg_text or "").splitlines():
        if "=" not in line:
            continue
        if line.lstrip().startswith("#"):
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if not k:
            continue
        out[k] = v
    return out

def _nobb_set_kv(cfg_text: str, key: str, value: str) -> str:
    # Replace first matching "key = ..." line (non-comment). If not found, append to end.
    pat = re.compile(rf"^(?P<prefix>\s*{re.escape(key)}\s*=\s*)(?P<val>.*)$", re.MULTILINE)
    if pat.search(cfg_text or ""):
        return pat.sub(rf"\g<prefix>{value}", cfg_text, count=1)
    # append
    return (cfg_text.rstrip() + "\n" + f"{key} = {value}" + "\n")

def _nobb_load_cfg(server: dict) -> str:
    _, cfg_path = _nobb_get_paths(server)
    if cfg_path.exists():
        try:
            return cfg_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            pass
    # seed from default template if present
    try:
        if NOBB_DEFAULT_CFG_PATH.exists():
            return NOBB_DEFAULT_CFG_PATH.read_text(encoding="utf-8", errors="replace")
    except Exception:
        pass
    return ""

def _nobb_save_cfg(server: dict, cfg_text: str) -> None:
    _, cfg_path = _nobb_get_paths(server)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(cfg_text, encoding="utf-8")


# --- NOBlackBox install helpers (automated BepInEx + NOBlackBox) ---

BEPINEX_ZIP_URL = "https://github.com/BepInEx/BepInEx/releases/download/v5.4.23.5/BepInEx_win_x64_5.4.23.5.zip"
NOBB_RELEASE_ZIP_URL = "https://github.com/KopterBuzz/NOBlackBox/releases/download/0.3.8.2/NOBlackBox-0.3.8.2.zip"

# Persisted per-server desired NOBlackBox settings (e.g., OutputPath) so installs can apply them
NOBB_SETTINGS_PATH = BASE_DIR / "noblackbox_settings.json"

_NOBB_JOB_LOCK = threading.Lock()
_NOBB_JOBS: dict[str, dict] = {}  # server_id -> {"lines":[...], "done":bool, "success":bool, "error":str|None, "ts":float}

def _nobb_settings_load() -> dict:
    try:
        if NOBB_SETTINGS_PATH.exists():
            return json.loads(NOBB_SETTINGS_PATH.read_text(encoding="utf-8", errors="replace") or "{}")
    except Exception:
        pass
    return {}

def _nobb_settings_save(data: dict) -> None:
    try:
        NOBB_SETTINGS_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def _nobb_settings_merge(server_id: str, values: dict) -> None:
    if not server_id:
        return
    data = _nobb_settings_load()
    cur = data.get(server_id, {}) if isinstance(data.get(server_id, {}), dict) else {}
    for k, v in (values or {}).items():
        kk = str(k).strip()
        if not kk:
            continue
        cur[kk] = v
    data[server_id] = cur
    _nobb_settings_save(data)

def _nobb_job_init(server_id: str) -> None:
    with _NOBB_JOB_LOCK:
        _NOBB_JOBS[server_id] = {"lines": [], "done": False, "success": False, "error": None, "ts": time.time()}

def _nobb_job_add(server_id: str, line: str) -> None:
    if not server_id:
        return
    msg = (line or "").strip()
    if not msg:
        return
    with _NOBB_JOB_LOCK:
        job = _NOBB_JOBS.setdefault(server_id, {"lines": [], "done": False, "success": False, "error": None, "ts": time.time()})
        job["lines"].append(msg)
        job["ts"] = time.time()
        # Keep log bounded
        if len(job["lines"]) > 250:
            job["lines"] = job["lines"][-250:]

def _nobb_job_finish(server_id: str, success: bool, error: str | None = None) -> None:
    with _NOBB_JOB_LOCK:
        job = _NOBB_JOBS.setdefault(server_id, {"lines": [], "done": False, "success": False, "error": None, "ts": time.time()})
        job["done"] = True
        job["success"] = bool(success)
        job["error"] = (error or None)
        job["ts"] = time.time()

def _nobb_job_get(server_id: str) -> dict:
    with _NOBB_JOB_LOCK:
        j = _NOBB_JOBS.get(server_id) or {}
        return {
            "success": True,
            "server_id": server_id,
            "done": bool(j.get("done")),
            "ok": bool(j.get("success")),
            "error": j.get("error"),
            "lines": list(j.get("lines") or []),
        }

def _download_bytes(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "NuclearOptionPanel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def _extract_zip_bytes(zip_bytes: bytes, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        # Extract all, allowing overwrite
        for member in z.infolist():
            # ZipSlip guard
            p = Path(member.filename)
            if p.is_absolute() or ".." in p.parts:
                continue
            z.extract(member, dest_dir)

def _install_bepinex_into_server_dir(install_dir: Path, output: list[str]) -> None:
    output.append(f"Downloading BepInEx from: {BEPINEX_ZIP_URL}")
    data = _download_bytes(BEPINEX_ZIP_URL, timeout=60)
    output.append(f"Extracting BepInEx into: {install_dir}")
    _extract_zip_bytes(data, install_dir)
    output.append("BepInEx extracted.")

def _install_noblackbox_into_plugins(plugin_target_dir: Path, output: list[str]) -> None:
    plugin_target_dir.mkdir(parents=True, exist_ok=True)
    output.append(f"Downloading NOBlackBox from: {NOBB_RELEASE_ZIP_URL}")
    data = _download_bytes(NOBB_RELEASE_ZIP_URL, timeout=60)
    # Extract into a temp folder first, then copy files into plugin_target_dir root
    tmp_root = Path(__file__).parent / "tools" / "tmp_nobb_release"
    try:
        if tmp_root.exists():
            shutil.rmtree(tmp_root, ignore_errors=True)
    except Exception:
        pass
    _extract_zip_bytes(data, tmp_root)

    # Some releases may include a NOBlackBox folder, some may put dlls at root.
    # We copy everything (files/dirs) from the extracted root into plugin_target_dir.
    roots = [tmp_root]
    # If archive has a single top-level directory, use it as root
    children = [p for p in tmp_root.iterdir()] if tmp_root.exists() else []
    if len(children) == 1 and children[0].is_dir():
        roots = [children[0]]

    src_root = roots[0]
    output.append(f"Installing NOBlackBox files into: {plugin_target_dir}")
    for item in src_root.iterdir():
        dst = plugin_target_dir / item.name
        if item.is_dir():
            if dst.exists():
                shutil.rmtree(dst, ignore_errors=True)
            shutil.copytree(item, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dst)

    # Ensure we actually have a DLL
    if not any(p.suffix.lower() == ".dll" for p in plugin_target_dir.rglob("*.dll")):
        raise RuntimeError("NOBlackBox install completed but no .dll was found in the plugin folder.")

def _run_server_for_seconds(install_dir: Path, seconds: int, output: list[str]) -> None:
    # Start using the same hidden-window method as the normal Start button.
    _start_server_from_bat(str(install_dir), output)
    output.append(f"Waiting {seconds}s for plugin/config generation...")
    time.sleep(max(1, int(seconds)))
    _stop_server_processes_in_dir(install_dir, output)
    output.append("Stopped server after generation run.")

def _nobb_find_cfg_path(install_dir: Path) -> Optional[Path]:
    cfg_dir = install_dir / "BepInEx" / "config"
    if not cfg_dir.exists():
        return None
    # prefer exact known filename if present
    exact = cfg_dir / NOBB_CFG_FILENAME
    if exact.exists():
        return exact
    # otherwise search for any config that contains NOBlackBox in the name
    for p in cfg_dir.glob("*NOBlackBox*.cfg"):
        if p.is_file():
            return p
    # fallback: case-insensitive scan
    for p in cfg_dir.glob("*.cfg"):
        if "noblackbox" in p.name.lower():
            return p
    return None

def _nobb_find_release_zip_url(timeout: int = 12) -> str:
    # Best-effort HTML scrape of GitHub releases/latest to find a .zip asset.
    url = "https://github.com/KopterBuzz/NOBlackBox/releases/latest"
    with urllib.request.urlopen(url, timeout=timeout) as r:
        html = r.read().decode("utf-8", errors="replace")
    # Prefer an asset that looks like the mod zip
    m = re.search(r'href="(?P<href>/KopterBuzz/NOBlackBox/releases/download/[^"]+?\.zip)"', html)
    if not m:
        # fallback: any zip in the page
        m = re.search(r'href="(?P<href>[^"]+?\.zip)"', html)
    if not m:
        raise RuntimeError("Could not find a .zip asset on the GitHub releases/latest page.")
    href = m.group("href")
    if href.startswith("http"):
        return href
    return "https://github.com" + href

def _nobb_download_and_extract_zip(zip_url: str, dest_dir: Path, timeout: int = 30) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    tmp_zip = dest_dir / "noblackbox_download.zip"
    urllib.request.urlretrieve(zip_url, tmp_zip)  # nosec (trusted source chosen by user or GitHub)
    extract_dir = dest_dir / "extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir, ignore_errors=True)
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(tmp_zip, "r") as zf:
        zf.extractall(extract_dir)
    return extract_dir

def _nobb_install_local(server: dict) -> dict:
    """
    Fully automated install:
      1) If BepInEx/plugins does not exist -> download/extract BepInEx into install dir, run server ~10s, stop.
      2) Create BepInEx/plugins/NOBlackBox, extract NOBlackBox release zip contents into it.
      3) Run server ~10s, stop (generates cfg under BepInEx/config/*NOBlackBox*.cfg)
    """
    install_dir = Path(server.get("install_dir") or "")
    if not install_dir.exists():
        return {"success": False, "error": f"Install dir not found: {install_dir}"}

    bepinex_dir = install_dir / "BepInEx"
    plugins_dir = bepinex_dir / "plugins"
    config_dir = bepinex_dir / "config"
    output: list[str] = []

    # Step 1: ensure BepInEx exists
    if not plugins_dir.exists():
        output.append("BepInEx not found for this server. Downloading and installing BepInEx...")
        try:
            _install_bepinex_into_server_dir(install_dir, output=output)
        except Exception as e:
            return {"success": False, "error": f"Failed to install BepInEx: {e}", "output": output}

        # Run once to let BepInEx generate directories/config
        try:
            _run_server_for_seconds(install_dir, seconds=10, output=output)
        except Exception as e:
            return {"success": False, "error": f"BepInEx installed but initial run failed: {e}", "output": output}


    # BepInEx 5.4.23.5 zip does not ship an empty plugins folder; it is normally created on first run.
    # To make the install resilient (and to match our panel's expectations), ensure it exists.
    try:
        plugins_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    # Re-check
    if not plugins_dir.exists():
        return {"success": False, "error": f"BepInEx plugins folder still not found after install: {plugins_dir}", "output": output}

    # Step 2: install NOBlackBox plugin
    nbb_dir = plugins_dir / NOBB_PLUGIN_DIRNAME
    nbb_dir.mkdir(parents=True, exist_ok=True)

    try:
        _install_noblackbox_into_plugins(nbb_dir, output=output)
    except Exception as e:
        return {"success": False, "error": f"Failed to install NOBlackBox: {e}", "output": output}

    # Step 3: run once to generate cfg
    try:
        _run_server_for_seconds(install_dir, seconds=10, output=output)
    except Exception as e:
        return {"success": False, "error": f"NOBlackBox installed but config generation run failed: {e}", "output": output}

    # Locate cfg and apply any saved settings (so OutputPath set in UI persists across installs)
    cfg_path = _nobb_find_cfg_path(install_dir)
    try:
        sid = str(server.get("id") or "").strip()
        saved = _nobb_settings_load().get(sid, {}) if sid else {}
        if isinstance(saved, dict) and saved and cfg_path and cfg_path.exists():
            cfg_text = cfg_path.read_text(encoding="utf-8", errors="replace")
            for k, v in saved.items():
                key = str(k).strip()
                if not key:
                    continue
                vv = v
                if key == "OutputPath":
                    vv = _nobb_normalize_path(str(vv))
                if isinstance(vv, bool):
                    vv = "true" if vv else "false"
                cfg_text = _nobb_set_kv(cfg_text, key, str(vv))
            cfg_path.write_text(cfg_text, encoding="utf-8")
            output.append("Applied saved NOBlackBox settings to generated config.")
    except Exception:
        pass

    return {
        "success": True,
        "installed": True,
        "plugin_dir": str(nbb_dir),
        "cfg_path": str(cfg_path) if cfg_path else "",
        "output": output,
    }


def _nobb_uninstall_local(server: dict) -> dict:
    plugin_dir, cfg_path = _nobb_get_paths(server)
    removed = []
    try:
        if plugin_dir.exists():
            shutil.rmtree(plugin_dir, ignore_errors=True)
            removed.append(str(plugin_dir))
        # Keep cfg by default (so settings persist), but remove if asked later.
        return {"success": True, "removed": removed}
    except Exception as e:
        return {"success": False, "error": f"Uninstall failed: {e}"}

@app.get("/api/noblackbox/status")
@requires_login()
def api_noblackbox_status():
    sid = request.args.get("server_id", "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    # Remote servers are handled by coordinator -> member proxy
    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/noblackbox/status", {"server_id": sid}, timeout=20)
        return jsonify(resp)

    plugin_dir, cfg_path = _nobb_get_paths(server)
    return jsonify({
        "success": True,
        # "installed" refers to the plugin/mod presence (DLL), not just config.
        "installed": _nobb_is_installed(server),
        "plugin_dir": str(plugin_dir),
        "cfg_path": str(cfg_path),
        "has_config": _nobb_has_config(server),
        "debug": _nobb_debug_paths(server),
    })

@app.get("/api/noblackbox/job")
@requires_login()
def api_noblackbox_job():
    sid = request.args.get("server_id", "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    # Remote proxy
    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/noblackbox/job", {"server_id": sid}, timeout=15)
        return jsonify(resp)

    return jsonify(_nobb_job_get(sid))


@app.get("/api/noblackbox/config")
@requires_login()
def api_noblackbox_get_config():
    sid = request.args.get("server_id", "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/noblackbox/config", {"server_id": sid}, timeout=25)
        return jsonify(resp)

    cfg_text = _nobb_load_cfg(server)
    return jsonify({"success": True, "config_text": cfg_text, "config": _nobb_cfg_to_dict(cfg_text)})

@app.post("/api/noblackbox/config")
@requires_login("admin")
def api_noblackbox_set_config():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/noblackbox/config_set", {"server_id": sid, "values": data.get("values") or {}}, timeout=35)
        return jsonify(resp)

    values = data.get("values") or {}
    cfg_text = _nobb_load_cfg(server)
    # Only set the keys provided
    for k, v in values.items():
        key = str(k).strip()
        if not key:
            continue
        if key == "OutputPath":
            v = _nobb_normalize_path(str(v))
        # Booleans are lower-case true/false
        if isinstance(v, bool):
            v = "true" if v else "false"
        cfg_text = _nobb_set_kv(cfg_text, key, str(v))
    _nobb_save_cfg(server, cfg_text)
    try:
        _nobb_settings_merge(sid, values)
    except Exception:
        pass
    return jsonify({"success": True})

@app.post("/api/noblackbox/install")
@requires_login("admin")
def api_noblackbox_install():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    zip_url = str(data.get("zip_url") or "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/noblackbox/install", {"server_id": sid, "zip_url": zip_url}, timeout=60)
        return jsonify(resp)

    # Start a background job so the UI can show progress
    _nobb_job_init(sid)
    _nobb_job_add(sid, "Starting NOBlackBox install...")

    def _runner():
        try:
            result = _nobb_install_local(server)
            for line in (result.get("output") or []):
                _nobb_job_add(sid, str(line))
            if result.get("success"):
                _nobb_job_add(sid, "✅ Install complete.")
                _nobb_job_finish(sid, True, None)
            else:
                _nobb_job_add(sid, f"NOBlackBox install failed: {result.get('error')}")
                _nobb_job_finish(sid, False, str(result.get("error") or "install failed"))
        except Exception as e:
            _nobb_job_add(sid, f"NOBlackBox install failed: {e}")
            _nobb_job_finish(sid, False, str(e))

    threading.Thread(target=_runner, daemon=True).start()
    return jsonify({"success": True, "started": True})

@app.post("/api/noblackbox/uninstall")
@requires_login("admin")
def api_noblackbox_uninstall():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/noblackbox/uninstall", {"server_id": sid}, timeout=30)
        return jsonify(resp)

    return jsonify(_nobb_uninstall_local(server))

@app.post("/api/noblackbox/pick-folder")
@requires_login("admin")
def api_noblackbox_pick_folder():
    # Local-only convenience: opens a native folder picker on the machine running the panel.
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        path = filedialog.askdirectory(title="Select NOBlackBox Recording Folder")
        root.destroy()
        if not path:
            return jsonify({"success": False, "error": "No folder selected"}), 400
        return jsonify({"success": True, "path": _nobb_normalize_path(path)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ----- Cluster member endpoints (NOBlackBox) -----
@app.post("/api/cluster/noblackbox/status")
@requires_cluster_member_request
def api_cluster_noblackbox_status():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    plugin_dir, cfg_path = _nobb_get_paths(server)
    return jsonify({"success": True, "installed": _nobb_is_installed(server), "plugin_dir": str(plugin_dir), "cfg_path": str(cfg_path)})

@app.post("/api/cluster/noblackbox/job")
@requires_cluster_member_request
def api_cluster_noblackbox_job():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    return jsonify(_nobb_job_get(sid))


@app.post("/api/cluster/noblackbox/config")
@requires_cluster_member_request
def api_cluster_noblackbox_config():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    cfg_text = _nobb_load_cfg(server)
    return jsonify({"success": True, "config_text": cfg_text, "config": _nobb_cfg_to_dict(cfg_text)})

@app.post("/api/cluster/noblackbox/config_set")
@requires_cluster_member_request
def api_cluster_noblackbox_config_set():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    values = data.get("values") or {}
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    cfg_text = _nobb_load_cfg(server)
    for k, v in values.items():
        key = str(k).strip()
        if not key:
            continue
        if key == "OutputPath":
            v = _nobb_normalize_path(str(v))
        if isinstance(v, bool):
            v = "true" if v else "false"
        cfg_text = _nobb_set_kv(cfg_text, key, str(v))
    _nobb_save_cfg(server, cfg_text)
    return jsonify({"success": True})

@app.post("/api/cluster/noblackbox/install")
@requires_cluster_member_request
def api_cluster_noblackbox_install():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    zip_url = str(data.get("zip_url") or "").strip()
    server = _find_server_by_id(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    _nobb_job_init(sid)
    _nobb_job_add(sid, "Starting NOBlackBox install...")

    def _runner():
        try:
            result = _nobb_install_local(server)
            for line in (result.get("output") or []):
                _nobb_job_add(sid, str(line))
            if result.get("success"):
                _nobb_job_add(sid, "✅ Install complete.")
                _nobb_job_finish(sid, True, None)
            else:
                _nobb_job_add(sid, f"NOBlackBox install failed: {result.get('error')}")
                _nobb_job_finish(sid, False, str(result.get("error") or "install failed"))
        except Exception as e:
            _nobb_job_add(sid, f"NOBlackBox install failed: {e}")
            _nobb_job_finish(sid, False, str(e))

    threading.Thread(target=_runner, daemon=True).start()
    return jsonify({"success": True, "started": True})

@app.post("/api/cluster/noblackbox/uninstall")
@requires_cluster_member_request
def api_cluster_noblackbox_uninstall():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    server = _find_server_by_id(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    return jsonify(_nobb_uninstall_local(server))


# ----- Server Instances API (Server Management tab) -----
@app.get("/api/servers")
@requires_login()
def api_list_servers():
    servers = _build_servers_view()
    _cache_servers_view(servers)
    return jsonify({"success": True, "servers": servers})


def _build_servers_view() -> list[dict]:
    """Build the unified server list used for pills.

    Local servers are always included. If this node is the coordinator, it will
    also include member-local servers via signed cluster calls.
    """
    out_map: dict[str, dict] = {}
    this_nid = _this_node_id() if cluster_state.is_enabled() else ""

    for s in load_servers():
        server_dir = _server_install_dir_for(s)
        sid = str(s.get("id") or "")
        if not sid:
            continue
        out_map[sid] = {
            "id": sid,
            "name": s.get("name"),
            "install_dir": s.get("install_dir"),
            "remote_commands_port": s.get("remote_commands_port"),
            "running": _is_server_running(server_dir),
            "node_id": str(s.get("node_id") or this_nid or ""),
            "location": "local",
        }

    if cluster_state.is_enabled() and cluster_state.is_coordinator():
        try:
            for mem in list(cluster_state.state.get("members", [])):
                nid = str(mem.get("node_id") or "")
                resp = _cluster_signed_post_to_member(mem, "/api/cluster/servers/list_local", {}, timeout=10)
                if not isinstance(resp, dict) or not resp.get("success"):
                    continue
                for srv in resp.get("servers", []) or []:
                    sid = str(srv.get("id") or "")
                    if not sid:
                        continue
                    srv["node_id"] = str(srv.get("node_id") or nid)
                    srv["location"] = "remote"
                    out_map[sid] = srv
        except Exception:
            pass

    return list(out_map.values())


def _find_server_in_unified_view(server_id: str) -> Optional[dict]:
    try:
        sid = str(server_id or "").strip()
        if not sid:
            return None
        # 1) cached last-known mapping (helps when a member is slow/unreachable)
        cached = _SERVERS_VIEW_CACHE.get(sid)
        if isinstance(cached, dict):
            return cached

        # 2) rebuild and refresh cache
        view = _build_servers_view() or []
        _cache_servers_view(view)
        for s in view:
            if str(s.get("id") or "") == sid:
                return s
    except Exception:
        return None
    return None


def _proxy_server_control_if_remote(server_id: str, action: str, extra: Optional[dict] = None) -> Optional[tuple[dict, int]]:
    """If server_id belongs to a remote node and this node is the coordinator,
    proxy the control action to the owning member.

    Returns (payload,status) if proxied, otherwise None.
    """
    try:
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return None
        srv = _find_server_in_unified_view(server_id)
        if not srv:
            return None
        # A server is considered remote if either:
        # - the unified view marks it as remote, OR
        # - it has a node_id that differs from this node's id (covers cases where a remote server
        #   accidentally exists in local servers.json but still belongs to a member node).
        this_nid = _this_node_id() if cluster_state.is_enabled() else ""
        nid = str(srv.get("node_id") or "").strip()
        is_remote = (str(srv.get("location")) == "remote")
        if nid and this_nid and nid != this_nid:
            is_remote = True
        if not is_remote:
            return None
        if not nid:
            return None
        member = None
        for m in list(cluster_state.state.get("members", [])):
            if str(m.get("node_id") or "") == nid:
                member = m
                break
        if not member:
            return ({"success": False, "error": f"Remote member for node_id {nid} not found"}, 502)
        payload = {"server_id": str(server_id), "action": str(action)}
        if extra:
            payload.update(extra)
        resp = _cluster_signed_post_to_member(member, "/api/cluster/servers/control", payload, timeout=60)
        if isinstance(resp, dict) and resp.get("success") is True:
            return (resp, 200)
        # Preserve member error if present
        err = None
        if isinstance(resp, dict):
            err = resp.get("error") or resp.get("message")
        return ({"success": False, "error": err or "Remote control failed"}, 502)
    except Exception as e:
        return ({"success": False, "error": f"Remote proxy error: {e}"}, 502)



def _proxy_server_op_if_remote(server_id: str, op: str, payload: Optional[dict] = None, timeout: int = 30) -> Optional[tuple[dict, int]]:
    """Proxy non-control server operations to the owning member when the
    selected server lives on a remote node.

    Returns (response_payload, http_status) if proxied, otherwise None.
    """
    try:
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return None
        srv = _find_server_in_unified_view(server_id)
        if not srv:
            return None
        # A server is considered remote if either:
        # - the unified view marks it as remote, OR
        # - it has a node_id that differs from this node's id (covers cases where a remote server
        #   accidentally exists in local servers.json but still belongs to a member node).
        this_nid = _this_node_id() if cluster_state.is_enabled() else ""
        nid = str(srv.get("node_id") or "").strip()
        is_remote = (str(srv.get("location")) == "remote")
        if nid and this_nid and nid != this_nid:
            is_remote = True
        if not is_remote:
            return None
        if not nid:
            return None
        member = _find_member_by_node_id(nid)
        if not member:
            return ({"success": False, "error": f"Remote member for node_id {nid} not found"}, 502)
        body: dict = {"server_id": str(server_id)}
        if payload:
            body.update(payload)
        resp = _cluster_signed_post_to_member(member, op, body, timeout=timeout)
        if isinstance(resp, dict):
            code = 200 if resp.get("success") else 502
            return (resp, code)
        return ({"success": False, "error": "Bad response from member"}, 502)
    except Exception as e:
        return ({"success": False, "error": f"Remote proxy error: {e}"}, 502)



@app.post("/api/servers")

@requires_login("admin")
def api_create_server():
    data = request.get_json(force=True, silent=True) or {}

    # Cluster-aware deployment: coordinator can choose the node that will host the server install.
    target_node_id = str(data.get("target_node_id") or "").strip()
    if cluster_state.is_enabled() and cluster_state.is_coordinator() and target_node_id and target_node_id != _this_node_id():
        member = _find_member_by_node_id(target_node_id)
        if not member:
            return jsonify({"success": False, "error": "Target node not found in cluster members."}), 400
        payload = dict(data)
        payload.pop("target_node_id", None)
        # Deployment can take a long time (SteamCMD download/verify, file copy, etc.)
        # Use a long timeout so the coordinator doesn't return a 502 while the remote node is still working.
        resp = _cluster_signed_post_to_member(member, "/api/cluster/servers/deploy", payload, timeout=1800)
        if not isinstance(resp, dict):
            return jsonify({"success": False, "error": "Bad response from target node."}), 502
        # If remote deploy succeeded, return an updated unified view so the coordinator UI
        # can immediately render pills without needing a follow-up refresh.
        if isinstance(resp, dict) and resp.get("success"):
            resp["servers"] = _build_servers_view()
            return jsonify(resp), 200

        # Remote deploy failed. Our HTTP helper returns errors like "HTTP 400: ..." when the
        # member returns a client error. Surface that as a 400 instead of a generic 502.
        err = ""
        try:
            err = str((resp or {}).get("error") or "")
        except Exception:
            err = ""
        m = re.match(r"^HTTP\s+(\d{3})\b", err.strip())
        if m:
            code = int(m.group(1))
            if 400 <= code < 500:
                return jsonify(resp), 400
        return jsonify(resp), 502

    payload, status = _create_server_local_from_payload(data)
    if isinstance(payload, dict) and payload.get("success"):
        payload["servers"] = _build_servers_view()
    return jsonify(payload), status


def _delete_server_local(server_id: str, delete_files: bool) -> tuple[dict, int]:
    """Delete a server from THIS node's servers.json and optionally remove its install dir.
    Local-only helper used by both normal UI route and cluster member route.
    """
    servers = load_servers()
    target = None
    kept = []
    for s in servers:
        if str(s.get("id") or "") == str(server_id):
            target = s
        else:
            kept.append(s)
    if not target:
        return {"success": False, "error": "Server not found"}, 404

    save_servers(kept)

    # Best-effort: remove panel-owned firewall rules for this server
    try:
        _fw_remove_server_rules(server_id)
    except Exception:
        pass

    # Remove any Ports tab entries tied to this server so stale ports don't remain
    try:
        ports = load_ports() or []
        t_port = target.get("remote_commands_port")
        t_name = (target.get("name") or "").strip().lower()
        new_ports = []
        for p in ports:
            try:
                if str(p.get("server_id") or "") == str(server_id):
                    continue
                if t_port is not None and int(p.get("port")) == int(t_port) and (p.get("name") or "").strip().lower() == t_name:
                    continue
            except Exception:
                pass
            new_ports.append(p)
        save_ports(new_ports)
    except Exception:
        pass

    if delete_files:
        # Stop this server first (best-effort) to avoid locked files.
        try:
            d = target.get("install_dir")
            if d:
                tmp_out = []
                _stop_server_processes_for_install_dir(d, tmp_out)
        except Exception:
            pass
        try:
            d = target.get("install_dir")
            if d and os.path.isdir(d):
                shutil.rmtree(d, ignore_errors=True)
        except Exception:
            pass

    return {"success": True, "removed": target}, 200


@app.delete("/api/servers/<server_id>")
@requires_login("admin")
def api_delete_server(server_id: str):
    data = request.get_json(silent=True) or {}
    delete_files = bool(data.get("delete_files"))

    # Cluster-aware delete: if this server lives on a remote member, proxy the delete there.
    proxy = _proxy_server_op_if_remote(server_id, "/api/cluster/servers/delete", {"delete_files": delete_files}, timeout=90)
    if proxy is not None:
        resp, code = proxy
        if isinstance(resp, dict) and resp.get("success"):
            resp["servers"] = _build_servers_view()
        return jsonify(resp), code

    payload, code = _delete_server_local(server_id, delete_files)
    if isinstance(payload, dict) and payload.get("success"):
        payload["servers"] = _build_servers_view()
    return jsonify(payload), code



# ----- DedicatedServerConfig.json editor -----

def _dedicated_config_get_local(sid: str) -> dict:
    """Local-only helper for DedicatedServerConfig.json.

    Must not perform cluster proxying and must not depend on a browser session.
    Cluster member endpoints call this directly.
    """
    p = _config_path(sid)
    if not p.exists():
        return {"success": True, "exists": False, "path": str(p), "config": None}
    data = _read_json_file(p)
    return {"success": True, "exists": True, "path": str(p), "config": data}


def _dedicated_config_save_local(sid: str, cfg) -> dict:
    """Local-only helper for writing DedicatedServerConfig.json."""
    p = _config_path(sid)
    if not isinstance(cfg, dict):
        return {"success": False, "error": "config must be a JSON object"}
    _write_json_file(p, cfg)
    return {"success": True, "path": str(p)}
@app.get("/api/dedicated-config")
@requires_login("admin")
def api_get_dedicated_config():
    try:
        sid = _get_request_server_id()
        proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/get_dedicated_config", {})
        if proxy is not None:
            resp, code = proxy
            return jsonify(resp), code
        return jsonify(_dedicated_config_get_local(sid))
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/dedicated-config")
@requires_login("admin")
def save_dedicated_config():
    data = request.get_json(force=True, silent=True) or {}
    try:
        sid = data.get("server_id") or _get_request_server_id()
        proxy = _proxy_server_op_if_remote(str(sid), "/api/cluster/servers/save_dedicated_config", {"config": data.get("config")})
        if proxy is not None:
            resp, code = proxy
            return jsonify(resp), code
        res = _dedicated_config_save_local(str(sid), data.get("config"))
        if not res.get("success"):
            return jsonify(res), 400
        return jsonify(res)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@app.get("/api/startup-settings")
@requires_login("admin")
def get_startup_settings():
    try:
        sid = _get_request_server_id()
        proxy = _proxy_server_op_if_remote(str(sid), "/api/cluster/servers/get_startup_settings", None)
        if proxy is not None:
            resp, code = proxy
            return jsonify(resp), code
        server = get_server_by_id(sid)
        bat_path = _bat_path(sid)
        if not bat_path.exists():
            return jsonify({"success": False, "error": f"BAT not found: {bat_path}"}), 404
        settings = _parse_bat_settings(bat_path.read_text(encoding="utf-8", errors="ignore"))
        # Also expose MaxPlayers from DedicatedServerConfig.json (for Server Settings UI)
        try:
            cfg_path = _config_path(sid)
            if cfg_path.exists():
                cfg = _read_json_file(cfg_path) or {}
                if isinstance(cfg, dict) and "MaxPlayers" in cfg:
                    settings["max_players"] = cfg.get("MaxPlayers")
        except Exception:
            pass
        # prefer server's stored remote port if present
        if server.get("remote_commands_port"):
            settings["remote_commands_port"] = server.get("remote_commands_port")
        return jsonify({"success": True, "bat_path": str(bat_path), "settings": settings, "server": server})
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.post("/api/startup-settings")
@requires_login("admin")
def api_set_startup_settings():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        sid = payload.get("server_id") or _get_request_server_id()
        proxy = _proxy_server_op_if_remote(str(sid), "/api/cluster/servers/set_startup_settings", {"server_id": str(sid), "settings": payload.get("settings") or {}})
        if proxy is not None:
            resp, code = proxy
            return jsonify(resp), code
        server = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

    settings = payload.get("settings") or {}

    if not isinstance(settings, dict):
        return jsonify({"success": False, "error": "settings must be an object"}), 400

    bp = _bat_path(sid)
    old_text = bp.read_text(encoding="utf-8", errors="ignore")
    new_text = old_text

    restart_required = False

    # Read previous values from BAT (best-effort)
    parsed_old = _parse_bat_settings(old_text)
    bat_old_port = parsed_old.get("remote_commands_port")

    # Read what the UI says the "current managed port" is
    ui_old_port = None
    try:
        ui_old_port = int(settings.get("old_port")) if settings.get("old_port") else None
    except Exception:
        ui_old_port = None

    # ---------- FPS ----------
    if "fps" in settings and settings["fps"] is not None:
        fps = int(settings["fps"])
        new_text, changed = _set_bat_fps(new_text, fps)
        restart_required = restart_required or changed

    # ---------- Max Players (DedicatedServerConfig.json) ----------
    if "max_players" in settings and settings["max_players"] is not None:
        try:
            mp = int(settings["max_players"])
            cfg_path = _config_path(sid)
            cfg = _read_json_file(cfg_path) if cfg_path.exists() else {}
            if not isinstance(cfg, dict):
                cfg = {}
            cfg["MaxPlayers"] = mp
            _write_json_file(cfg_path, cfg)
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to write MaxPlayers: {e}"}), 500

    # ---------- Remote command port ----------
    if "remote_commands_port" in settings and settings["remote_commands_port"] is not None:
        new_port = int(settings["remote_commands_port"])
        new_text, changed, bat_detected_old = _set_bat_remote_port(new_text, new_port)
        restart_required = restart_required or changed

        # Determine which port to sync FROM (priority: UI → BAT → parsed)
        ref_old = (
            ui_old_port
            if ui_old_port is not None
            else bat_detected_old
            if bat_detected_old is not None
            else bat_old_port
        )

        if ref_old is not None and ref_old != new_port:
            _sync_ports_tab_for_server(str(server.get("id") or sid), str(server.get("name") or f"Server {new_port}"), ref_old, new_port)

        # Persist the new remote port for this server instance
        try:
            if server.get("id"):
                servers = load_servers()
                for s in servers:
                    if s.get("id") == server.get("id"):
                        s["remote_commands_port"] = new_port
                save_servers(servers)
        except Exception:
            pass

    # ---------- Write BAT if changed ----------
    if new_text != old_text:
        bp.write_text(new_text, encoding="utf-8")

    return jsonify({
        "success": True,
        "bat_path": str(bp),
        "restart_required": restart_required
    })


# =============================
# MOTD (Message of the Day)
# =============================

@app.get("/api/server-motd")
@requires_login("admin")
def api_get_server_motd():
    """Returns stored MOTD settings for the selected server."""
    try:
        sid = request.args.get("server_id") or _get_request_server_id()
        server = get_server_by_id(sid)
        motd = {
            "text": server.get("motd_text") or "",
            "repeat_minutes": server.get("motd_repeat_minutes") if server.get("motd_repeat_minutes") is not None else 0,
        }
        return jsonify({"success": True, "motd": motd})
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/server-motd")
@requires_login("admin")
def api_set_server_motd():
    """Stores MOTD settings (text + optional repeat interval) for the selected server."""
    data = request.get_json(silent=True) or {}
    try:
        sid = data.get("server_id") or _get_request_server_id()
        text = (data.get("text") or "").strip()
        repeat = data.get("repeat_minutes")
        try:
            repeat = int(repeat) if repeat is not None and str(repeat).strip() != "" else 0
        except Exception:
            return jsonify({"success": False, "error": "repeat_minutes must be a number"}), 400
        if repeat < 0:
            return jsonify({"success": False, "error": "repeat_minutes must be 0 or greater"}), 400

        servers = load_servers()
        if not servers:
            raise NoServersConfigured("No servers configured. Create one in the Server Deployment tab first.")
        updated = False
        for s in servers:
            if s.get("id") == sid:
                s["motd_text"] = text
                s["motd_repeat_minutes"] = repeat
                updated = True
                break
        if not updated:
            # fallback to first
            servers[0]["motd_text"] = text
            servers[0]["motd_repeat_minutes"] = repeat
        save_servers(servers)
        return jsonify({"success": True})
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----- Local update server (stop -> steamcmd -> restart via BAT) -----
@app.post("/local/update-server")
@requires_login("admin")
def local_update_server():
    output: list[str] = []
    payload = request.get_json(silent=True) or {}
    sid = payload.get("server_id") or _get_request_server_id()
    try:
        server = get_server_by_id(sid)
        # If this server record belongs to a different node, proxy the update to the owning member
        if cluster_state.is_enabled() and cluster_state.is_coordinator():
            this_nid = _this_node_id()
            nid = str(server.get("node_id") or "").strip()
            if nid and this_nid and nid != this_nid:
                proxied = _proxy_server_control_if_remote(str(sid), "update")
                if proxied:
                    payload, status = proxied
                    return jsonify(payload), status

    except NoServersConfigured as e:
        # If there are no local servers but the selected server_id belongs to a remote node,
        # proxy the request to the owning member (coordinator only).
        proxied = _proxy_server_control_if_remote(str(sid), "update")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": str(e)}), 400
    install_dir = server.get("install_dir") or None

    def stop_server_processes():
        found = False
        for proc in psutil.process_iter(["name"]):
            try:
                if proc.info["name"] == SERVER_EXE_NAME:
                    found = True
                    output.append(f"Stopping {SERVER_EXE_NAME} (PID {proc.pid})...")
                    proc.terminate()
                    try:
                        proc.wait(timeout=12)
                        output.append(f"PID {proc.pid} stopped.")
                    except psutil.TimeoutExpired:
                        proc.kill()
                        output.append(f"PID {proc.pid} force-killed.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not found:
            output.append("No running NuclearOptionServer processes found.")

    stop_server_processes()

    steamcmd = find_steamcmd()
    if not steamcmd:
        output.append("SteamCMD not found. Downloading SteamCMD...")
        steamcmd = ensure_steamcmd(str(TOOLS_DIR / "steamcmd"))
        output.append(f"SteamCMD installed to: {steamcmd}")
    else:
        output.append(f"Using SteamCMD: {steamcmd}")

    output.append(f"Updating app {config.STEAM_APP_ID} (validate) via SteamCMD...")
    args = [
        steamcmd,
        *( ["+force_install_dir", install_dir] if install_dir else [] ),
        "+login", config.STEAM_LOGIN,
        "+app_update", str(config.STEAM_APP_ID), "validate",
        "+quit",
    ]

    r = subprocess.run(args, capture_output=True, text=True, timeout=3600)
    if r.stdout:
        output.append(r.stdout)
    if r.stderr:
        output.append("STDERR:")
        output.append(r.stderr)
    if r.returncode != 0:
        return jsonify({"success": False, "output": output, "error": f"SteamCMD exit code {r.returncode}"}), 500

    if getattr(config, "AUTO_RESTART_AFTER_UPDATE", True):
        try:
            server_dir = _server_dir(sid)
        except NoServersConfigured as e:
            return jsonify({"success": False, "output": output, "error": str(e)}), 400
        # Restart using the same hidden-window launcher used by the normal Start button.
        _start_server_from_bat(server_dir, output)

    return jsonify({"success": True, "output": output})

# ----- Local start/stop/restart (per selected server) -----
def _stop_server_processes_for_install_dir(install_dir: str, output: list[str]) -> bool:
    """Stop NuclearOptionServer.exe processes that live under install_dir."""
    stopped_any = False
    base = os.path.abspath(install_dir)
    for proc in psutil.process_iter(["name", "exe"]):
        try:
            if proc.info.get("name") != SERVER_EXE_NAME:
                continue
            exe = proc.info.get("exe") or ""
            if not exe:
                continue
            if not os.path.abspath(exe).startswith(base):
                continue
            stopped_any = True
            output.append(f"Stopping {SERVER_EXE_NAME} (PID {proc.pid})...")
            proc.terminate()
            try:
                proc.wait(timeout=12)
                output.append(f"PID {proc.pid} stopped.")
            except psutil.TimeoutExpired:
                proc.kill()
                output.append(f"PID {proc.pid} force-killed.")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception as e:
            output.append(f"Error stopping PID {getattr(proc, 'pid', '?')}: {e}")
    return stopped_any

def _start_server_from_bat(server_dir: str, output: list[str]) -> None:
    bat = find_start_bat(server_dir)
    if not bat:
        # common fallback
        fallback = Path(server_dir) / "RunServer.bat"
        bat = str(fallback) if fallback.is_file() else None
    if not bat:
        raise RuntimeError("Could not locate a server start .bat file in the install directory.")

    output.append(f"Starting server using: {bat}")

    if os.name == "nt":
        # Use cmd.exe to run batch, detached + no visible console window
        creationflags = 0
        try:
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                creationflags |= subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
                creationflags |= subprocess.CREATE_NEW_PROCESS_GROUP
        except Exception:
            creationflags = 0
        subprocess.Popen(
            ["cmd.exe", "/c", bat],
            cwd=server_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
        )
    else:
        subprocess.Popen(
            ["bash", "-lc", f'"{bat}"'],
            cwd=server_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
        )
    output.append("Start command issued.")


# =============================
# MOTD runtime broadcaster
# =============================

_MOTD_STATE_LOCK = threading.Lock()
_MOTD_STATE: dict[str, dict] = {}

def _server_motd_config(server: dict) -> tuple[str, int]:
    text = (server.get("motd_text") or "").strip()
    try:
        repeat = int(server.get("motd_repeat_minutes") or 0)
    except Exception:
        repeat = 0
    if repeat < 0:
        repeat = 0
    return text, repeat

def _send_motd_now(server: dict) -> bool:
    """Send the configured MOTD to this server once (best-effort)."""
    text, _repeat = _server_motd_config(server)
    if not text:
        return False
    try:
        port = int(server.get("remote_commands_port") or 0)
        if port <= 0:
            return False
        c = create_remote_commander(port)
        code, _body = server_commands.send_chat_message(c, text)
        return str(code) == "Success"
    except Exception:
        return False

def _motd_tick_once():
    """One scheduler tick: detect server start transitions and send repeats."""
    try:
        servers = load_servers()
    except Exception:
        return

    now = time.time()
    for s in servers or []:
        sid = str(s.get("id") or "").strip()
        if not sid:
            continue
        text, repeat = _server_motd_config(s)
        if not text:
            # no MOTD configured, keep state but don't act
            continue

        server_dir = _server_install_dir_for(s)
        running = _is_server_running(server_dir)

        with _MOTD_STATE_LOCK:
            st = _MOTD_STATE.setdefault(sid, {"last_running": False, "last_sent": 0.0})
            last_running = bool(st.get("last_running"))
            last_sent = float(st.get("last_sent") or 0.0)

        # Transition: stopped -> running
        if running and not last_running:
            sent_ok = _send_motd_now(s)
            if sent_ok:
                with _MOTD_STATE_LOCK:
                    st = _MOTD_STATE.setdefault(sid, {"last_running": True, "last_sent": 0.0})
                    st["last_sent"] = now
                    st["last_running"] = True
            else:
                with _MOTD_STATE_LOCK:
                    st = _MOTD_STATE.setdefault(sid, {"last_running": True, "last_sent": 0.0})
                    st["last_running"] = True

        # Repeat while running
        if running and repeat > 0:
            due = (now - last_sent) >= (repeat * 60)
            if due:
                sent_ok = _send_motd_now(s)
                if sent_ok:
                    with _MOTD_STATE_LOCK:
                        st = _MOTD_STATE.setdefault(sid, {"last_running": True, "last_sent": 0.0})
                        st["last_sent"] = now
                        st["last_running"] = True

        # Update last_running when stopped
        if not running and last_running:
            with _MOTD_STATE_LOCK:
                st = _MOTD_STATE.setdefault(sid, {"last_running": False, "last_sent": 0.0})
                st["last_running"] = False

def _motd_scheduler_loop():
    while True:
        try:
            _motd_tick_once()
        except Exception:
            pass
        time.sleep(5)

@app.post("/local/start-server")
@requires_login()
def local_start_server():
    output: list[str] = []
    payload = request.get_json(silent=True) or {}
    sid = payload.get("server_id") or _get_request_server_id()
    try:
        server = get_server_by_id(sid)
        # If this server record belongs to a different node, proxy instead of using local filesystem
        if cluster_state.is_enabled() and cluster_state.is_coordinator():
            this_nid = _this_node_id()
            nid = str(server.get("node_id") or "").strip()
            if nid and this_nid and nid != this_nid:
                proxied = _proxy_server_control_if_remote(str(sid), "start")
                if proxied:
                    payload, status = proxied
                    return jsonify(payload), status

    except NoServersConfigured as e:
        proxied = _proxy_server_control_if_remote(str(sid), "start")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": str(e)}), 400
    except KeyError:
        proxied = _proxy_server_control_if_remote(str(sid), "start")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": "Unknown server_id"}), 404

    server_dir = _server_install_dir_for(server)
    if not server_dir:
        return jsonify({"success": False, "output": output, "error": "Server install_dir not set and could not be auto-detected."}), 400

    if _is_server_running(server_dir):
        output.append("Server is already running.")
        return jsonify({"success": True, "output": output, "running": True})

    try:
        _start_server_from_bat(server_dir, output)
        time.sleep(0.6)
        running = _is_server_running(server_dir)
        if running:
            # If MOTD is configured, send once immediately and prime the scheduler state.
            sent = _send_motd_now(server)
            with _MOTD_STATE_LOCK:
                st = _MOTD_STATE.setdefault(str(server.get("id") or sid), {"last_running": True, "last_sent": 0.0})
                st["last_running"] = True
                if sent:
                    st["last_sent"] = time.time()
        return jsonify({"success": True, "output": output, "running": running})
    except Exception as e:
        return jsonify({"success": False, "output": output, "error": str(e)}), 500

@app.post("/local/stop-server")
@requires_login()
def local_stop_server():
    output: list[str] = []
    payload = request.get_json(silent=True) or {}
    sid = payload.get("server_id") or _get_request_server_id()
    try:
        server = get_server_by_id(sid)
        # If this server record belongs to a different node, proxy instead of using local filesystem
        if cluster_state.is_enabled() and cluster_state.is_coordinator():
            this_nid = _this_node_id()
            nid = str(server.get("node_id") or "").strip()
            if nid and this_nid and nid != this_nid:
                proxied = _proxy_server_control_if_remote(str(sid), "stop")
                if proxied:
                    payload, status = proxied
                    return jsonify(payload), status

    except NoServersConfigured as e:
        proxied = _proxy_server_control_if_remote(str(sid), "stop")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": str(e)}), 400
    except KeyError:
        proxied = _proxy_server_control_if_remote(str(sid), "stop")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": "Unknown server_id"}), 404

    server_dir = _server_install_dir_for(server)
    if not server_dir:
        return jsonify({"success": False, "output": output, "error": "Server install_dir not set and could not be auto-detected."}), 400

    stopped = _stop_server_processes_for_install_dir(server_dir, output)
    if not stopped:
        output.append("No matching server process found for this install_dir.")
    time.sleep(0.4)
    return jsonify({"success": True, "output": output, "running": _is_server_running(server_dir)})

@app.post("/local/restart-server")
@requires_login()
def local_restart_server():
    output: list[str] = []
    payload = request.get_json(silent=True) or {}
    sid = payload.get("server_id") or _get_request_server_id()
    try:
        server = get_server_by_id(sid)
        # If this server record belongs to a different node, proxy instead of using local filesystem
        if cluster_state.is_enabled() and cluster_state.is_coordinator():
            this_nid = _this_node_id()
            nid = str(server.get("node_id") or "").strip()
            if nid and this_nid and nid != this_nid:
                proxied = _proxy_server_control_if_remote(str(sid), "restart")
                if proxied:
                    payload, status = proxied
                    return jsonify(payload), status

    except NoServersConfigured as e:
        proxied = _proxy_server_control_if_remote(str(sid), "restart")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": str(e)}), 400
    except KeyError:
        proxied = _proxy_server_control_if_remote(str(sid), "restart")
        if proxied:
            payload, status = proxied
            return jsonify(payload), status
        return jsonify({"success": False, "output": output, "error": "Unknown server_id"}), 404

    server_dir = _server_install_dir_for(server)
    if not server_dir:
        return jsonify({"success": False, "output": output, "error": "Server install_dir not set and could not be auto-detected."}), 400

    _stop_server_processes_for_install_dir(server_dir, output)
    time.sleep(0.6)
    try:
        _start_server_from_bat(server_dir, output)
        time.sleep(0.6)
        running = _is_server_running(server_dir)
        if running:
            sent = _send_motd_now(server)
            with _MOTD_STATE_LOCK:
                st = _MOTD_STATE.setdefault(str(server.get("id") or sid), {"last_running": True, "last_sent": 0.0})
                st["last_running"] = True
                if sent:
                    st["last_sent"] = time.time()
        return jsonify({"success": True, "output": output, "running": running})
    except Exception as e:
        return jsonify({"success": False, "output": output, "error": str(e)}), 500




# ----- Remote commands -----
@app.post("/command/send-chat-message")
@requires_login()
def send_chat_message():
    data = request.get_json(force=True, silent=True) or {}
    msg = (data.get("message") or "").strip()
    if not msg:
        return jsonify({"success": False, "error": "Message required"}), 400

    # If this server is hosted on a remote cluster member, proxy the command to that member.
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(
        sid,
        "/api/cluster/servers/command",
        {"cmd": "send-chat-message", "args": {"message": msg}},
    )
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.send_chat_message(c, msg)
    return ok(code, body)

@app.post("/command/reload-config")
@requires_login("admin")
def reload_config():
    data = request.get_json(force=True, silent=True) or {}
    path = (data.get("path") or "").strip() or None
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "reload-config", "args": {"path": path}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.reload_config(c, path)
    return ok(code, body)

@app.post("/command/get-mission-time")
@requires_login()
def get_mission_time():
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "get-mission-time", "args": {}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.get_mission_time(c)
    return ok(code, body)

@app.post("/command/get-mission")
@requires_login()
def get_mission():
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "get-mission", "args": {}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.get_mission(c)
    return ok(code, body)

@app.post("/command/get-player-list")
@requires_login()
def get_player_list():
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "get-player-list", "args": {}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.get_player_list(c)
    return ok(code, body)

@app.post("/command/set-time-remaining")
@requires_login()
def set_time_remaining():
    data = request.get_json(force=True, silent=True) or {}
    if "time" not in data:
        return jsonify({"success": False, "error": "time required"}), 400
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "set-time-remaining", "args": {"time": float(data.get("time") or 0)}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.set_time_remaining(c, float(data["time"]))
    return ok(code, body)

@app.post("/command/set-next-mission")
@requires_login()
def set_next_mission():
    data = request.get_json(force=True, silent=True) or {}
    for k in ("group", "name", "max_time"):
        if k not in data:
            return jsonify({"success": False, "error": f"{k} required"}), 400
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "set-next-mission", "args": {"group": data.get("group"), "name": data.get("name"), "max_time": data.get("max_time")}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.set_next_mission(c, data["group"], data["name"], float(data["max_time"]))
    return ok(code, body)

@app.post("/command/kick-player")
@requires_login()
def kick_player():
    data = request.get_json(force=True, silent=True) or {}
    if "steam_id" not in data:
        return jsonify({"success": False, "error": "steam_id required"}), 400
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "kick-player", "args": {"steam_id": data.get("steam_id")}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.kick_player(c, data["steam_id"])
    return ok(code, body)

@app.post("/command/unkick-player")
@requires_login()
def unkick_player():
    data = request.get_json(force=True, silent=True) or {}
    if "steam_id" not in data:
        return jsonify({"success": False, "error": "steam_id required"}), 400
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "unkick-player", "args": {"steam_id": data.get("steam_id")}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.unkick_player(c, data["steam_id"])
    return ok(code, body)

@app.post("/command/clear-kicked-players")
@requires_login()
def clear_kicked_players():
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "clear-kicked-players", "args": {}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.clear_kicked_players(c)
    return ok(code, body)

@app.post("/command/banlist-reload")
@requires_login()
def banlist_reload():
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "banlist-reload", "args": {}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.banlist_reload(c)
    return ok(code, body)

@app.post("/command/banlist-add")
@requires_login()
def banlist_add():
    data = request.get_json(force=True, silent=True) or {}
    if "steam_id" not in data:
        return jsonify({"success": False, "error": "steam_id required"}), 400
    reason = (data.get("reason") or "").strip() or None
    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.banlist_add(c, data["steam_id"], reason)
    return ok(code, body)

@app.post("/command/banlist-remove")
@requires_login()
def banlist_remove():
    data = request.get_json(force=True, silent=True) or {}
    if "steam_id" not in data:
        return jsonify({"success": False, "error": "steam_id required"}), 400
    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.banlist_remove(c, data["steam_id"])
    return ok(code, body)

@app.post("/command/banlist-clear")
@requires_login()
def banlist_clear():
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "")
    proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/command", {"cmd": "banlist-clear", "args": {}})
    if proxy:
        payload, status = proxy
        return jsonify(payload), status

    c, e = get_commander_from_json(data)
    if e: return e
    code, body = server_commands.banlist_clear(c)
    return ok(code, body)





# =============================
# Missions (BuiltIn + User)
# =============================

def _list_user_missions() -> list[str]:
    """Return user mission names available under the panel's missions folder.

    Supports both layouts:
      1) missions/<Name>.json
      2) missions/<Name>/<Name>.json  (and ignores meta.json)
    The dropdown uses the mission *Name* (stem/folder name), not the file path.
    """
    names: list[str] = []
    seen: set[str] = set()
    try:
        # Layout 1: missions/*.json
        for p in sorted(MISSIONS_DIR.glob("*.json")):
            if p.name.lower() == "meta.json":
                continue
            n = p.stem
            if n and n not in seen:
                seen.add(n); names.append(n)

        # Layout 2: missions/*/*.json (common community pack layout showing in your screenshot)
        for d in sorted(MISSIONS_DIR.iterdir()):
            if not d.is_dir():
                continue
            # Prefer <folder>/<folder>.json if present, else any .json except meta.json
            preferred = d / f"{d.name}.json"
            candidate = None
            if preferred.is_file():
                candidate = preferred
            else:
                for p in sorted(d.glob("*.json")):
                    if p.name.lower() == "meta.json":
                        continue
                    candidate = p
                    break
            if candidate:
                n = d.name
                if n and n not in seen:
                    seen.add(n); names.append(n)
    except Exception:
        pass
    return names

@app.get("/api/missions")
@requires_login()
def api_list_missions():
    group = (request.args.get("group") or "BuiltIn").strip()
    if group.lower() == "user":
        return jsonify({"success": True, "group": "User", "missions": _list_user_missions(), "mission_dir": str(MISSIONS_DIR)})
    # default built-in
    return jsonify({"success": True, "group": "BuiltIn", "missions": BUILTIN_MISSIONS, "mission_dir": str(MISSIONS_DIR)})

@app.get("/api/mission-settings")
@requires_login()
def api_get_mission_settings():
    """Backward-compatible single-mission API (maps to slot 1)."""
    try:
        sid = _get_request_server_id()

        # If this is a cluster-remote server, reuse the mission-slots proxy and map slot1 -> legacy fields
        proxy = _proxy_server_op_if_remote(str(sid), "/api/cluster/servers/get_mission_slots", {})
        if proxy:
            payload, code = proxy
            if code != 200 or not isinstance(payload, dict) or not payload.get("success"):
                return jsonify(payload), code
            slot1 = payload.get("slot1") or {}
            group = slot1.get("group") or "BuiltIn"
            name = slot1.get("name") or None
            return jsonify({"success": True, "server_id": sid, "mission_group": group, "mission_name": name, "mission_dir": str(MISSIONS_DIR)})

        server = get_server_by_id(sid)
        group = server.get("mission1_group") or server.get("mission_group") or "BuiltIn"
        name = server.get("mission1_name") or server.get("mission_name") or None
        return jsonify({"success": True, "server_id": sid, "mission_group": group, "mission_name": name, "mission_dir": str(MISSIONS_DIR)})

    except KeyError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400


def _normalize_mission_group(g: str) -> str:
    g = (g or "BuiltIn").strip().lower()
    return "User" if g == "user" else "BuiltIn"


def _validate_mission_choice(group: str, name: str) -> tuple[bool, str]:
    """Return (ok, error). Empty name is allowed and means 'None'."""
    group = _normalize_mission_group(group)
    name = (name or "").strip()
    if not name:
        return True, ""
    if group == "BuiltIn":
        if name not in BUILTIN_MISSIONS:
            return False, "Unknown built-in mission name"
        return True, ""
    # User
    if name not in _list_user_missions():
        return False, "User mission file not found in missions folder"
    return True, ""


def _apply_mission_slots_to_config(cfg: dict, slot1: dict | None, slot2: dict | None) -> dict:
    """Write MissionDirectory + MissionRotation with up to 2 entries."""
    if not isinstance(cfg, dict):
        cfg = {}
    cfg["MissionDirectory"] = str(MISSIONS_DIR)

    def _slot_to_entry(slot: dict) -> dict | None:
        if not isinstance(slot, dict):
            return None
        group = _normalize_mission_group(slot.get("group") or "BuiltIn")
        name = (slot.get("name") or "").strip()
        if not name:
            return None
        return {"Key": {"Group": group, "Name": name}, "MaxTime": float(slot.get("max_time") or 7200.0)}

    rot: list[dict] = []
    e1 = _slot_to_entry(slot1 or {})
    e2 = _slot_to_entry(slot2 or {})
    if e1: rot.append(e1)
    if e2: rot.append(e2)
    cfg["MissionRotation"] = rot
    return cfg


def _infer_slots_from_config(cfg: dict) -> tuple[dict, dict]:
    """Infer slot1/slot2 from DedicatedServerConfig.json MissionRotation."""
    slot1 = {"group": "BuiltIn", "name": "", "max_time": 7200.0}
    slot2 = {"group": "BuiltIn", "name": "", "max_time": 7200.0}
    rot = cfg.get("MissionRotation") if isinstance(cfg, dict) else None
    if isinstance(rot, list):
        def pull(i):
            try:
                e = rot[i]
                key = e.get("Key") if isinstance(e, dict) else None
                if not isinstance(key, dict):
                    return None
                return {
                    "group": _normalize_mission_group(key.get("Group") or "BuiltIn"),
                    "name": (key.get("Name") or "").strip(),
                    "max_time": float(e.get("MaxTime") or 7200.0)
                }
            except Exception:
                return None
        s1 = pull(0)
        s2 = pull(1)
        if s1: slot1 = s1
        if s2: slot2 = s2
    return slot1, slot2


@app.get("/api/mission-slots")
@requires_login()
def api_get_mission_slots():
    sid = _get_request_server_id()
    # Proxy to remote member if this is a cluster-remote server
    proxy = _proxy_server_op_if_remote(str(sid), "/api/cluster/servers/get_mission_slots", {})
    if proxy:
        payload, code = proxy
        return jsonify(payload), code

    try:
        server = _find_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400

    if not server:
        return jsonify({"success": False, "error": f"Unknown server_id: {sid}"}), 404

    slot1 = {
        "group": server.get("mission1_group") or server.get("mission_group") or "BuiltIn",
        "name": server.get("mission1_name") or server.get("mission_name") or "",
        "max_time": float(server.get("mission1_max_time") or server.get("mission_max_time") or 0) or None,
    }
    slot2 = {
        "group": server.get("mission2_group") or "BuiltIn",
        "name": server.get("mission2_name") or "",
        "max_time": float(server.get("mission2_max_time") or 0) or None,
    }
    return jsonify({"success": True, "slot1": slot1, "slot2": slot2})

@app.post("/api/mission-slots")
@requires_login("admin")
def api_set_mission_slots():
    sid = _get_request_server_id()
    data = request.get_json(force=True, silent=True) or {}

    proxy = _proxy_server_op_if_remote(str(sid), "/api/cluster/servers/set_mission_slots", {"data": data})
    if proxy:
        payload, code = proxy
        return jsonify(payload), code

    try:
        get_server_by_id(sid)  # ensure exists
    except KeyError:
        return jsonify({"success": False, "error": f"Unknown server_id: {sid}"}), 404
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400

    try:
        slot1 = data.get("slot1") or {}
        slot2 = data.get("slot2") or {}

        # Persist slot selections to servers.json for UI/preview
        updates = {
            "mission1_group": slot1.get("group") or "BuiltIn",
            "mission1_name": slot1.get("name") or "",
            "mission1_max_time": slot1.get("max_time"),
            "mission2_group": slot2.get("group") or "BuiltIn",
            "mission2_name": slot2.get("name") or "",
            "mission2_max_time": slot2.get("max_time"),
        }
        _update_server_fields(sid, updates)

        # ALSO persist into DedicatedServerConfig.json so the dedicated server actually uses the selection
        p = _config_path(sid)
        cfg = _read_json_file(p) if p.exists() else {}
        if not isinstance(cfg, dict):
            cfg = {}

        cfg = _apply_mission_slots_to_config(cfg, slot1, slot2)
        _write_json_file(p, cfg)

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/mission-settings")
@requires_login("admin")
def api_set_mission_settings():
    """Backward-compatible single-mission save (maps to mission slot 1)."""
    payload = request.get_json(force=True, silent=True) or {}
    try:
        sid = payload.get("server_id") or _get_request_server_id()
        get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400

    group = (payload.get("mission_group") or "BuiltIn").strip()
    name = (payload.get("mission_name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "mission_name is required"}), 400

    ok, err = _validate_mission_choice(group, name)
    if not ok:
        return jsonify({"success": False, "error": err}), 400

    # Keep slot2 as-is (infer from config if needed)
    try:
        p = _config_path(sid)
        cfg = _read_json_file(p) if p.exists() else {}
        s1, s2 = _infer_slots_from_config(cfg if isinstance(cfg, dict) else {})
    except Exception:
        s2 = {"group": "BuiltIn", "name": "", "max_time": 7200.0}

    slot1 = {"group": group, "name": name, "max_time": 7200.0}
    slot2 = s2

    # Reuse the multi-slot persistence logic
    servers = load_servers()
    for s in servers:
        if s.get("id") == sid:
            s["mission1_group"] = _normalize_mission_group(slot1.get("group"))
            s["mission1_name"] = (slot1.get("name") or "").strip()
            s["mission1_max_time"] = float(slot1.get("max_time") or 7200.0)
            s["mission2_group"] = _normalize_mission_group(slot2.get("group"))
            s["mission2_name"] = (slot2.get("name") or "").strip()
            s["mission2_max_time"] = float(slot2.get("max_time") or 7200.0)
            s["mission_directory"] = str(MISSIONS_DIR)
    save_servers(servers)

    try:
        p = _config_path(sid)
        cfg = _read_json_file(p) if p.exists() else {}
        if not isinstance(cfg, dict):
            cfg = {}
        cfg = _apply_mission_slots_to_config(cfg, slot1, slot2)
        _write_json_file(p, cfg)
    except Exception as e:
        return jsonify({"success": True, "warning": f"Saved mission, but failed to write DedicatedServerConfig.json: {e}"}), 200

    return jsonify({"success": True})

# =============================
# Password (DedicatedServerConfig.json)
# =============================

@app.post("/api/server-password")
@requires_login("admin")
def api_set_server_password():
    payload = request.get_json(force=True, silent=True) or {}
    try:
        sid = payload.get("server_id") or _get_request_server_id()
        proxy = _proxy_server_op_if_remote(sid, "/api/cluster/servers/set_password", payload)
        if proxy is not None:
            resp, code = proxy
            return jsonify(resp), code
        _ = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    pw = payload.get("password")
    if pw is None:
        return jsonify({"success": False, "error": "password is required (can be empty string)"}), 400
    if not isinstance(pw, str):
        return jsonify({"success": False, "error": "password must be a string"}), 400

    try:
        p = _config_path(sid)
        cfg = _read_json_file(p) if p.exists() else {}
        if not isinstance(cfg, dict):
            cfg = {}
        cfg["Password"] = pw
        cfg.setdefault("MissionDirectory", str(MISSIONS_DIR))
        _write_json_file(p, cfg)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================
# Entry point
# =============================


# -----------------------------
# Steam Workshop cache sync
# -----------------------------
def _find_steam_libraryfolders_vdf_candidates() -> list[Path]:
    candidates: list[Path] = []
    # Common Steam locations
    if os.name == "nt":
        pf86 = os.environ.get("PROGRAMFILES(X86)")
        pf = os.environ.get("PROGRAMFILES")
        for base in [pf86, pf]:
            if base:
                candidates.append(Path(base) / "Steam" / "steamapps" / "libraryfolders.vdf")
        # Also try to read Steam install path from registry
        try:
            import winreg  # type: ignore
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for key_path in (r"Software\Valve\Steam", r"SOFTWARE\WOW6432Node\Valve\Steam"):
                    try:
                        with winreg.OpenKey(hive, key_path) as k:
                            steam_path, _ = winreg.QueryValueEx(k, "SteamPath")
                            if steam_path:
                                candidates.append(Path(steam_path) / "steamapps" / "libraryfolders.vdf")
                    except Exception:
                        pass
        except Exception:
            pass
    else:
        home = Path.home()
        candidates += [
            home / ".steam" / "steam" / "steamapps" / "libraryfolders.vdf",
            home / ".local" / "share" / "Steam" / "steamapps" / "libraryfolders.vdf",
        ]
    # Add panel dir quick check
    candidates.append(BASE_DIR / "steamapps" / "libraryfolders.vdf")
    # Deduplicate while preserving order
    seen=set()
    out=[]
    for c in candidates:
        p=c.resolve() if c.exists() else c
        if str(p) in seen: 
            continue
        seen.add(str(p))
        out.append(c)
    return out


def _parse_libraryfolders_vdf(vdf_path: Path) -> list[Path]:
    """
    Very small parser: pulls all lines like  "path"  "D:\\SteamLibrary"
    Supports both old and new libraryfolders.vdf formats.
    """
    try:
        data = vdf_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    paths: list[Path] = []
    for m in re.finditer(r'\"path\"\s*\"([^\"]+)\"', data, flags=re.IGNORECASE):
        raw = m.group(1).replace("\\\\", "\\")
        if raw:
            paths.append(Path(raw))
    # In some older formats, numeric keys directly map to paths:  "1" "D:\\SteamLibrary"
    for m in re.finditer(r'\"(\d+)\"\s*\"([A-Za-z]:\\\\[^\"]+)\"', data):
        raw = m.group(2).replace("\\\\", "\\")
        paths.append(Path(raw))
    # Always include the folder containing the VDF as a library root too
    # ...\Steam\steamapps\libraryfolders.vdf -> ...\Steam
    try:
        steam_root = vdf_path.parent.parent
        paths.insert(0, steam_root)
    except Exception:
        pass
    # Dedup
    seen=set()
    out=[]
    for p in paths:
        p = Path(str(p))
        if str(p).lower() in seen:
            continue
        seen.add(str(p).lower())
        out.append(p)
    return out


def _get_steam_library_paths() -> list[Path]:
    # First try known candidates
    for cand in _find_steam_libraryfolders_vdf_candidates():
        if cand.exists():
            libs = _parse_libraryfolders_vdf(cand)
            if libs:
                return libs
    # Fallback: bounded search in common roots for libraryfolders.vdf
    roots: list[Path] = []
    if os.name == "nt":
        roots = [Path(os.environ.get("SYSTEMDRIVE", "C:")) / "\\", Path.home()]
    else:
        roots = [Path.home()]
    for r in roots:
        try:
            for p in r.rglob("libraryfolders.vdf"):
                if "steamapps" in str(p).lower():
                    libs = _parse_libraryfolders_vdf(p)
                    if libs:
                        return libs
        except Exception:
            continue
    return []



def _sync_workshop_cache_into_panel_missions(appid: int = 2168680) -> dict:
    """
    Sync missions from the local Steam client's workshop cache into panel missions folder.

    Workshop item folders are numeric IDs. We:
      - Skip "skin/cosmetic" items (identified by catalog_1.json or catalog_workshop.json).
      - Treat each mission json file (excluding meta.json / workshop.json / catalog_*.json) as a mission entry.
      - Create: missions/<MissionName>/<MissionName>.json
      - Copy meta.json alongside if present (optional).
    """
    missions_root = (BASE_DIR / "missions")
    missions_root.mkdir(parents=True, exist_ok=True)

    libs = _get_steam_library_paths()
    workshop_roots: list[Path] = []
    for lib in libs:
        workshop = lib / "steamapps" / "workshop" / "content" / str(appid)
        if workshop.exists():
            workshop_roots.append(workshop)

    def _sanitize_folder_name(name: str) -> str:
        # Windows-safe folder names
        name = str(name).strip().strip(".")
        name = re.sub(r'[<>:"/\\|?*]', "_", name)
        name = re.sub(r"\s+", " ", name).strip()
        return name[:120] if len(name) > 120 else name

    copied: list[str] = []
    skipped: list[str] = []
    total_missions = 0

    for wroot in workshop_roots:
        try:
            for item_dir in wroot.iterdir():
                if not item_dir.is_dir():
                    continue

                # Skip obvious non-mission workshop items (skins etc.)
                # Many skin items include a catalog_1.json (or catalog_workshop.json) at top-level.
                has_catalog = any((item_dir / fn).exists() for fn in ("catalog_1.json", "catalog_workshop.json"))
                if not has_catalog:
                    # Some items may nest the catalog file one level deep
                    for p in item_dir.glob("**/catalog_1.json"):
                        has_catalog = True
                        break
                    if not has_catalog:
                        for p in item_dir.glob("**/catalog_workshop.json"):
                            has_catalog = True
                            break
                if has_catalog:
                    skipped.append(item_dir.name)
                    continue

                # Candidate mission jsons (usually at root; allow recursive but exclude known non-mission json files)
                candidates: list[Path] = []
                for p in item_dir.rglob("*.json"):
                    if not p.is_file():
                        continue
                    low = p.name.lower()
                    if low in ("meta.json", "workshop.json", "catalog_1.json", "catalog_workshop.json"):
                        continue
                    if low.startswith("catalog_"):
                        continue
                    candidates.append(p)

                if not candidates:
                    skipped.append(item_dir.name)
                    continue

                # Copy each mission into its own folder named after the mission file stem
                meta_src = item_dir / "meta.json"
                for mission_json in candidates:
                    mission_name = _sanitize_folder_name(mission_json.stem)
                    if not mission_name:
                        continue
                    dest_dir = missions_root / mission_name
                    dest_dir.mkdir(parents=True, exist_ok=True)

                    dest_json = dest_dir / f"{mission_name}.json"
                    shutil.copy2(mission_json, dest_json)

                    # Optional: copy meta.json for reference (doesn't affect server)
                    if meta_src.exists():
                        try:
                            shutil.copy2(meta_src, dest_dir / "meta.json")
                        except Exception:
                            pass

                    total_missions += 1
                    copied.append(mission_name)
        except Exception:
            continue

    # De-duplicate copied list for reporting
    copied_unique = []
    seen = set()
    for name in copied:
        if name not in seen:
            copied_unique.append(name)
            seen.add(name)

    return {
        "synced_count": len(copied_unique),
        "missions_copied": total_missions,
        "copied": copied_unique[:200],
        "skipped": skipped[:200],
        "workshop_roots": [str(p) for p in workshop_roots],
    }


@app.post("/local/sync-workshop-missions")
@requires_login("admin")
def local_sync_workshop_missions():
    """
    Sync Nuclear Option workshop missions from the local Steam client cache into the panel missions folder.
    Optionally updates a selected server's DedicatedServerConfig.json MissionDirectory to point to the panel missions folder.
    """
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "").strip()

    try:
        result = _sync_workshop_cache_into_panel_missions(appid=2168680)

        # If a server_id was provided, point that server's config to panel missions dir
        if sid:
            p = _config_path(sid)
            cfg = _read_json_file(p) if p.exists() else {}
            if not isinstance(cfg, dict):
                cfg = {}
            cfg["MissionDirectory"] = str(MISSIONS_DIR)
            _write_json_file(p, cfg)

        return jsonify({"success": True, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500





@app.post("/api/sync-workshop-missions")
@requires_login("admin")
def api_sync_workshop_missions():
    """Sync Workshop missions across ALL servers (local + remote).

    This runs the workshop sync once per node (local + each remote member that owns servers)
    and then updates every server's DedicatedServerConfig.json MissionDirectory to point to the
    panel missions folder on that node.

    Notes:
    - Backwards compatible: if the UI still passes server_id, it is ignored.
    """
    _ = request.get_json(force=True, silent=True) or {}

    try:
        servers = load_servers()
        if not servers:
            return jsonify({"success": False, "error": "No servers configured."}), 400

        output: list[str] = []

        # ---- Local node: sync once, then update all local servers ----
        local_sids = [s.get("id") for s in servers if s.get("location") != "remote" and s.get("id")]
        if local_sids:
            result = _sync_workshop_cache_into_panel_missions(appid=2168680)
            output.extend(result.get("output") or [])

            for sid in local_sids:
                try:
                    p = _config_path(sid)
                    cfg = _read_json_file(p) if p.exists() else {}
                    if not isinstance(cfg, dict):
                        cfg = {}
                    cfg["MissionDirectory"] = str(MISSIONS_DIR)
                    _write_json_file(p, cfg)
                except Exception as e:
                    output.append(f"Failed to update MissionDirectory for {sid}: {e}")

        # ---- Remote nodes: proxy once per owning node_id ----
        remote_by_node: dict[str, str] = {}
        for s in servers:
            if s.get("location") == "remote" and s.get("node_id") and s.get("id"):
                # Use first server on that node as a proxy anchor.
                remote_by_node.setdefault(str(s["node_id"]), str(s["id"]))

        for node_id, any_sid in remote_by_node.items():
            proxied = _proxy_server_op_if_remote(any_sid, "/api/cluster/servers/sync_workshop_missions", {"server_id": "__all__"}, timeout_sec=1800)
            if proxied:
                payload, code = proxied
                if code != 200 or not payload.get("success"):
                    output.append(f"Remote node {node_id} sync failed: {payload.get('error') or 'Unknown error'}")
                else:
                    output.extend(payload.get("output") or [])
            else:
                output.append(f"Remote node {node_id} sync skipped: unable to proxy")

        return jsonify({"success": True, "output": output})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500




# =============================
# Panel Users / Moderation
# =============================

@app.get("/api/panel-users")
@requires_login(role="admin")
def api_panel_users_get():
    _ensure_user_store()
    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    users_out = []
    for u in users_data:
        users_out.append({
            "username": u.get("username"),
            "role": u.get("role", "mod"),
            "created_at": u.get("created_at"),
            "must_change_password": bool(u.get("must_change_password")),
        })
    attempts = _load_json_file(LOGIN_AUDIT_FILE, {"attempts": []}).get("attempts", [])[-100:]
    blocked = _blocked_ips().get("blocked", [])
    return jsonify({
        "success": True,
        "users": users_out,
        "attempts": attempts,
        "blocked": blocked,
        "is_local": _is_localhost(),
        "your_ip": _client_ip(),
    })

@app.post("/api/panel-users")
@requires_login(role="admin")
def api_panel_users_create():
    # Cluster mode: non-coordinator nodes forward user edits to the coordinator
    if cluster_state.is_enabled() and not cluster_state.is_coordinator():
        c_url = cluster_state.coordinator_url()
        if not c_url:
            return jsonify({"success": False, "error": "Cluster coordinator not available."}), 503
        payload = request.get_json(silent=True) or {}
        body_bytes = json.dumps({"action": "create", "payload": payload}).encode("utf-8")
        headers = cluster_state.make_signed_headers("POST", "/api/cluster/users/apply", body_bytes)
        try:
            return jsonify(http_post_json(f"{c_url}/api/cluster/users/apply", {"action": "create", "payload": payload}, headers=headers, timeout=8))
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to reach coordinator: {e}"}), 502
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "mod").strip()
    if role not in ("admin", "mod"):
        role = "mod"
    if len(username) < 3 or len(password) < 6:
        return jsonify({"success": False, "error": "Username must be 3+ chars and password 6+ chars."}), 400
    if _get_user(username):
        return jsonify({"success": False, "error": "User already exists."}), 400
    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    users_data.append({
        "username": username,
        "password_hash": generate_password_hash(password),
        "role": role,
        "created_at": _iso_now(),
        "must_change_password": False,
    })
    _set_users(users_data)
    _append_audit("user_created", {"username": username, "role": role})
    return jsonify({"success": True})

@app.post("/api/panel-users/reset-password")
@requires_login(role="admin")
def api_panel_users_reset_password():
    if cluster_state.is_enabled() and not cluster_state.is_coordinator():
        c_url = cluster_state.coordinator_url()
        if not c_url:
            return jsonify({"success": False, "error": "Cluster coordinator not available."}), 503
        payload = request.get_json(silent=True) or {}
        body_bytes = json.dumps({"action": "reset_password", "payload": payload}).encode("utf-8")
        headers = cluster_state.make_signed_headers("POST", "/api/cluster/users/apply", body_bytes)
        try:
            return jsonify(http_post_json(f"{c_url}/api/cluster/users/apply", {"action": "reset_password", "payload": payload}, headers=headers, timeout=8))
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to reach coordinator: {e}"}), 502
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    new_password = data.get("password") or ""
    if len(new_password) < 6:
        return jsonify({"success": False, "error": "Password must be 6+ chars."}), 400
    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    found = False
    for u in users_data:
        if u.get("username","").lower() == username.lower():
            u["password_hash"] = generate_password_hash(new_password)
            u["must_change_password"] = False
            found = True
            break
    if not found:
        return jsonify({"success": False, "error": "User not found."}), 404
    _set_users(users_data)
    _append_audit("user_password_reset", {"username": username})
    return jsonify({"success": True})

@app.delete("/api/panel-users/<username>")
@requires_login(role="admin")
def api_panel_users_delete(username: str):
    username = (username or "").strip()
    if cluster_state.is_enabled() and not cluster_state.is_coordinator():
        c_url = cluster_state.coordinator_url()
        if not c_url:
            return jsonify({"success": False, "error": "Cluster coordinator not available."}), 503
        payload = {"username": username}
        body_bytes = json.dumps({"action": "delete", "payload": payload}).encode("utf-8")
        headers = cluster_state.make_signed_headers("POST", "/api/cluster/users/apply", body_bytes)
        try:
            return jsonify(http_post_json(f"{c_url}/api/cluster/users/apply", {"action": "delete", "payload": payload}, headers=headers, timeout=8))
        except Exception as e:
            return jsonify({"success": False, "error": f"Failed to reach coordinator: {e}"}), 502
    if username.lower() == (session.get("username","").lower()):
        return jsonify({"success": False, "error": "You cannot delete your own account."}), 400
    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    new_users = [u for u in users_data if u.get("username","").lower() != username.lower()]
    if len(new_users) == len(users_data):
        return jsonify({"success": False, "error": "User not found."}), 404
    _set_users(new_users)
    _append_audit("user_deleted", {"username": username})
    return jsonify({"success": True})

@app.post("/api/panel-users/unblock")
@requires_login(role="admin")
def api_panel_users_unblock():
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"success": False, "error": "Missing IP"}), 400
    _unblock_ip(ip)
    return jsonify({"success": True})


# =============================
# Cluster API (MVP)
# =============================

@app.get("/api/cluster/state")
@requires_login(role="admin")
def api_cluster_state():
    view = cluster_state.public_view()
    # Show join secret only to local admins, and only if this node is the coordinator.
    if view.get("enabled") and view.get("is_coordinator"):
        view["secret"] = str(cluster_state.state.get("secret") or "")
    return jsonify({"success": True, "cluster": view})



@app.post("/api/cluster/servers/list_local")
def api_cluster_servers_list_local():
    """Coordinator -> member: list servers that exist on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    this_nid = _this_node_id()
    out = []
    for s in load_servers():
        server_dir = _server_install_dir_for(s)
        out.append({
            "id": s.get("id"),
            "name": s.get("name"),
            "install_dir": s.get("install_dir"),
            "remote_commands_port": s.get("remote_commands_port"),
            "game_port": s.get("game_port"),
            "query_port": s.get("query_port"),
            "running": _is_server_running(server_dir),
            "node_id": str(s.get("node_id") or this_nid or ""),
            "location": "local",
        })
    return jsonify({"success": True, "servers": out})




# --- Cluster: server config helpers (coordinator -> member) ---
@app.post("/api/cluster/servers/get_startup_settings")
def api_cluster_get_startup_settings():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        server = get_server_by_id(sid)
        bat_path = _bat_path(sid)
        if not bat_path.exists():
            return jsonify({"success": False, "error": f"BAT not found: {bat_path}"}), 404
        settings = _parse_bat_settings(bat_path.read_text(encoding="utf-8", errors="ignore"))
        # Also expose MaxPlayers from DedicatedServerConfig.json (for Server Settings UI)
        try:
            cfg_path = _config_path(sid)
            if cfg_path.exists():
                cfg = _read_json_file(cfg_path) or {}
                if isinstance(cfg, dict) and "MaxPlayers" in cfg:
                    settings["max_players"] = cfg.get("MaxPlayers")
        except Exception:
            pass
        if server.get("remote_commands_port"):
            settings["remote_commands_port"] = server.get("remote_commands_port")
        return jsonify({"success": True, "bat_path": str(bat_path), "settings": settings, "server": server})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/set_startup_settings")
def api_cluster_set_startup_settings():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    settings = data.get("settings") or {}
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400

    try:
        # Reuse same logic as normal endpoint by calling the internal helper functions it uses.
        server = get_server_by_id(sid)
        bat_path = _bat_path(sid)
        if not bat_path.exists():
            return jsonify({"success": False, "error": f"BAT not found: {bat_path}"}), 404

        # Apply updates using the same helpers the UI endpoint uses
        old_text = bat_path.read_text(encoding="utf-8", errors="ignore")
        new_text = old_text
        restart_required = False

        # FPS
        if "fps" in settings and settings["fps"] is not None:
            new_text, changed = _set_bat_fps(new_text, int(settings["fps"]))
            restart_required = restart_required or changed

        # Max Players (DedicatedServerConfig.json)
        if "max_players" in settings and settings["max_players"] is not None:
            try:
                mp = int(settings["max_players"])
                cfg_path = _config_path(sid)
                cfg = _read_json_file(cfg_path) if cfg_path.exists() else {}
                if not isinstance(cfg, dict):
                    cfg = {}
                cfg["MaxPlayers"] = mp
                _write_json_file(cfg_path, cfg)
            except Exception as e:
                return jsonify({"success": False, "error": f"Failed to write MaxPlayers: {e}"}), 500

        # Remote Commands Port
        if "remote_commands_port" in settings and settings["remote_commands_port"] is not None:
            new_port = int(settings["remote_commands_port"])
            new_text, changed, bat_detected_old = _set_bat_remote_port(new_text, new_port)
            restart_required = restart_required or changed

            # Sync ports tab when port changes
            try:
                ui_old_port = int(server.get("remote_commands_port")) if server.get("remote_commands_port") else None
            except Exception:
                ui_old_port = None
            try:
                parsed_old = _parse_bat_settings(old_text).get("remote_commands_port")
            except Exception:
                parsed_old = None
            ref_old = ui_old_port if ui_old_port is not None else (bat_detected_old if bat_detected_old is not None else parsed_old)
            if ref_old is not None and ref_old != new_port:
                _sync_ports_tab_for_server(str(server.get("id") or sid), str(server.get("name") or f"Server {new_port}"), ref_old, new_port)

            # Persist in servers.json
            try:
                servers = load_servers()
                for s in servers:
                    if s.get("id") == server.get("id"):
                        s["remote_commands_port"] = new_port
                save_servers(servers)
            except Exception:
                pass

        if new_text != old_text:
            bat_path.write_text(new_text, encoding="utf-8")

        return jsonify({"success": True, "bat_path": str(bat_path), "restart_required": restart_required})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/get_dedicated_config")
def api_cluster_get_dedicated_config():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        return jsonify(_dedicated_config_get_local(sid))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/save_dedicated_config")
def api_cluster_save_dedicated_config():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    cfg = data.get("config")
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        return jsonify(_dedicated_config_save_local(sid, cfg))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/get_server_motd")
def api_cluster_get_server_motd():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        server = get_server_by_id(sid)
        motd = {
            "text": server.get("motd_text") or "",
            "repeat_minutes": server.get("motd_repeat_minutes") if server.get("motd_repeat_minutes") is not None else 0,
        }
        return jsonify({"success": True, "motd": motd})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/set_server_motd")
def api_cluster_set_server_motd():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    motd = data.get("motd") or {}
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        updates = {
            "motd_text": motd.get("text") or "",
            "motd_repeat_minutes": int(motd.get("repeat_minutes") or 0),
        }
        _update_server_fields(sid, updates)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500




@app.post("/api/cluster/servers/get_server_password")
def api_cluster_get_server_password():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        server = get_server_by_id(sid)
        return jsonify({"success": True, "password": server.get("password") or ""})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/set_server_password")
def api_cluster_set_server_password():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    password = data.get("password") or ""
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        _update_server_fields(sid, {"password": password})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.post("/api/cluster/servers/get_mission_slots")
def api_cluster_get_mission_slots():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        server = get_server_by_id(sid)
        slot1 = {
            "group": server.get("mission1_group") or server.get("mission_group") or "BuiltIn",
            "name": server.get("mission1_name") or server.get("mission_name") or "",
            "max_time": float(server.get("mission1_max_time") or server.get("mission_max_time") or 0) or None,
        }
        slot2 = {
            "group": server.get("mission2_group") or "BuiltIn",
            "name": server.get("mission2_name") or "",
            "max_time": float(server.get("mission2_max_time") or 0) or None,
        }
        return jsonify({"success": True, "slot1": slot1, "slot2": slot2})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/set_mission_slots")
def api_cluster_set_mission_slots():
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    inner = data.get("data") or {}
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    try:
        slot1 = inner.get("slot1") or {}
        slot2 = inner.get("slot2") or {}
        updates = {
            "mission1_group": slot1.get("group") or "BuiltIn",
            "mission1_name": slot1.get("name") or "",
            "mission1_max_time": slot1.get("max_time"),
            "mission2_group": slot2.get("group") or "BuiltIn",
            "mission2_name": slot2.get("name") or "",
            "mission2_max_time": slot2.get("max_time"),
        }
        _update_server_fields(sid, updates)
        # Also persist into DedicatedServerConfig.json for the server on THIS node.
        # The coordinator UI expects mission slots to be written to the actual
        # server config file, not just servers.json.
        try:
            p = _config_path(sid)
            cfg = _read_json_file(p) if p.exists() else {}
            if not isinstance(cfg, dict):
                cfg = {}
            slot1_norm = {
                "group": _normalize_mission_group(slot1.get("group")),
                "name": (slot1.get("name") or "").strip(),
                "max_time": float(slot1.get("max_time") or 0) or None,
            }
            slot2_norm = {
                "group": _normalize_mission_group(slot2.get("group")),
                "name": (slot2.get("name") or "").strip(),
                "max_time": float(slot2.get("max_time") or 0) or None,
            }
            cfg = _apply_mission_slots_to_config(cfg, slot1_norm, slot2_norm)
            _write_json_file(p, cfg)
        except Exception as e:
            # Keep the request "success" but return a warning so the coordinator can show it.
            return jsonify({"success": True, "warning": f"Saved slots but failed to write DedicatedServerConfig.json: {e}"})

        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.post("/api/cluster/servers/command")
def api_cluster_servers_command():
    """Coordinator -> member: run a remote-command against the game server on THIS node (uses 127.0.0.1)."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(force=True, silent=True) or {}
    sid = data.get("server_id")
    cmd = data.get("cmd")
    args = data.get("args") or {}
    if not sid or not cmd:
        return jsonify({"success": False, "error": "server_id and cmd required"}), 400

    try:
        server = get_server_by_id(sid)
        port = int(server.get("remote_commands_port") or 0)
        if not port:
            return jsonify({"success": False, "error": "Server has no Remote Commands Port configured"}), 400

        commander = create_remote_commander(port)
        # Dispatch to server_commands helpers
        if cmd == "send-chat-message":
            res = server_commands.send_chat_message(commander, args.get("message",""))
        elif cmd == "reload-config":
            res = server_commands.reload_config(commander, args.get("path") or "")
        elif cmd == "get-mission-time":
            res = server_commands.get_mission_time(commander)
        elif cmd == "get-mission":
            res = server_commands.get_mission(commander)
        elif cmd == "get-player-list":
            res = server_commands.get_player_list(commander)
        elif cmd == "set-time-remaining":
            res = server_commands.set_time_remaining(commander, int(args.get("time") or 0))
        elif cmd == "set-next-mission":
            res = server_commands.set_next_mission(
                commander,
                args.get("group",""),
                args.get("name",""),
                int(args.get("max_time") or 0),
            )
        elif cmd == "kick-player":
            res = server_commands.kick_player(commander, args.get("steam_id",""))
        elif cmd == "unkick-player":
            res = server_commands.unkick_player(commander, args.get("steam_id",""))
        elif cmd == "clear-kicked-players":
            res = server_commands.clear_kicked_players(commander)
        elif cmd == "banlist-reload":
            res = server_commands.banlist_reload(commander)
        elif cmd == "banlist-clear":
            res = server_commands.banlist_clear(commander)
        elif cmd == "banlist-add":
            res = server_commands.ban_player(commander, args.get("steam_id",""), args.get("reason",""))
        elif cmd == "banlist-remove":
            res = server_commands.unban_player(commander, args.get("steam_id",""))
        else:
            return jsonify({"success": False, "error": f"Unknown cmd: {cmd}"}), 400

        # Normalize output to match the local /command/* response shape.
        # Local endpoints return: {success:true, status_code:"Success", response:{...}}
        # The coordinator UI relies on that shape (e.g., for player pills).
        status_code = None
        body = None
        try:
            if isinstance(res, (list, tuple)) and len(res) == 2:
                status_code, body = res[0], res[1]
            else:
                status_code, body = "Success", res
        except Exception:
            status_code, body = "Success", res

        return jsonify({
            "success": True,
            "status_code": status_code,
            "response": body,
            # Backwards-compatible field for any callers that used the old shape.
            "result": [status_code, body],
        })
    except KeyError as e:
        return jsonify({"success": False, "error": str(e)}), 404
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.post("/api/cluster/servers/sync_workshop_missions")
def api_cluster_servers_sync_workshop_missions():
    """Coordinator -> member: sync workshop missions on THIS node.

    Accepts optional JSON body: {"server_id": "<id>"} to update that server's DedicatedServerConfig.json MissionDirectory
    to point at this node's panel missions folder.
    """
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "").strip()

    try:
        result = _sync_workshop_cache_into_panel_missions(appid=2168680)

        # If sid is omitted (or "__all__"), update MissionDirectory for ALL servers on this node.
        # This makes the workshop sync button apply everywhere, not just one server.
        if (not sid) or (sid.lower() == "__all__"):
            servers = load_servers()
            for s in servers:
                try:
                    p = _config_path(s.get("id"))
                    cfg = _read_json_file(p) if p.exists() else {}
                    if not isinstance(cfg, dict):
                        cfg = {}
                    cfg["MissionDirectory"] = str(MISSIONS_DIR)
                    _write_json_file(p, cfg)
                except Exception:
                    # Don't fail the whole sync if one config is missing/bad
                    pass
        else:
            p = _config_path(sid)
            cfg = _read_json_file(p) if p.exists() else {}
            if not isinstance(cfg, dict):
                cfg = {}
            cfg["MissionDirectory"] = str(MISSIONS_DIR)
            _write_json_file(p, cfg)

        return jsonify({"success": True, **result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500





@app.post("/api/cluster/servers/update_ports")
def api_cluster_servers_update_ports():
    """Coordinator -> member: update Game/Query ports for a server that lives on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400
    gp = data.get("game_port")
    qp = data.get("query_port")
    # Values are already validated on the coordinator; accept ints or None.
    if gp is not None and not isinstance(gp, int):
        return jsonify({"success": False, "error": "Invalid game_port"}), 400
    if qp is not None and not isinstance(qp, int):
        return jsonify({"success": False, "error": "Invalid query_port"}), 400

    ok2, err = _update_server_game_query_ports_local(sid, gp, qp)
    if not ok2:
        return jsonify({"success": False, "error": err or "Failed to update ports"}), 500

    # Return the updated row
    s = get_server_by_id(sid)
    return jsonify({
        "success": True,
        "server": {
            "id": s.get("id"),
            "name": s.get("name"),
            "game_port": s.get("game_port"),
            "query_port": s.get("query_port"),
            "node_id": str(s.get("node_id") or _this_node_id() or ""),
            "location": "local",
        }
    })


@app.post("/api/cluster/servers/control")
def api_cluster_servers_control():
    """Coordinator -> member: start/stop/restart a server on THIS node.

    This is used to make the main panel actions cluster-aware while keeping the
    browser UI calling the existing /local/* endpoints.
    """
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    action = str(data.get("action") or "").strip().lower()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400
    if action not in {"start", "stop", "restart"}:
        return jsonify({"success": False, "error": "Invalid action"}), 400

    output: list[str] = []
    try:
        server = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "output": output, "error": str(e)}), 400
    except KeyError:
        return jsonify({"success": False, "output": output, "error": "Unknown server_id"}), 404

    server_dir = _server_install_dir_for(server)
    if not server_dir:
        return jsonify({"success": False, "output": output, "error": "Server install_dir not set and could not be auto-detected."}), 400

    try:
        if action == "start":
            if _is_server_running(server_dir):
                output.append("Server is already running.")
                return jsonify({"success": True, "output": output, "running": True})
            _start_server_from_bat(server_dir, output)
            time.sleep(0.6)
            running = _is_server_running(server_dir)
            return jsonify({"success": True, "output": output, "running": running})

        if action == "stop":
            stopped = _stop_server_processes_for_install_dir(server_dir, output)
            if not stopped:
                output.append("No matching server process found for this install_dir.")
            time.sleep(0.4)
            return jsonify({"success": True, "output": output, "running": _is_server_running(server_dir)})

        # restart
        _stop_server_processes_for_install_dir(server_dir, output)
        time.sleep(0.6)
        _start_server_from_bat(server_dir, output)
        time.sleep(0.6)
        running = _is_server_running(server_dir)
        return jsonify({"success": True, "output": output, "running": running})
    except Exception as e:
        return jsonify({"success": False, "output": output, "error": str(e)}), 500


def _create_server_local_from_payload(data: dict) -> tuple[dict, int]:
    """Shared implementation for local create + cluster remote deploy."""
    name = str(data.get("name") or "").strip()
    if not name:
        return {"success": False, "error": "Server name is required"}, 400

    remote_port = int(data.get("remote_commands_port") or 7779)
    if remote_port < 1 or remote_port > 65535:
        return {"success": False, "error": "Remote Commands port out of range"}, 400

    def _to_int(v):
        try:
            if v is None or v == "":
                return None
            return int(v)
        except Exception:
            return None

    game_port = _to_int(data.get("game_port"))
    query_port = _to_int(data.get("query_port"))

    existing = load_servers() or []
    used_ports: dict[int, list[tuple[str, str]]] = {}
    for s in existing:
        sname = str(s.get("name") or s.get("id") or "server").strip()
        for field in ("remote_commands_port", "game_port", "query_port"):
            try:
                p = s.get(field)
                if p is None or p == "":
                    continue
                p = int(p)
                used_ports.setdefault(p, []).append((sname, field))
            except Exception:
                continue

    new_ports: list[tuple[str, int]] = []
    if isinstance(remote_port, int):
        new_ports.append(("remote_commands_port", remote_port))
    if isinstance(game_port, int):
        new_ports.append(("game_port", game_port))
    if isinstance(query_port, int):
        new_ports.append(("query_port", query_port))

    dup_within = []
    for i in range(len(new_ports)):
        for j in range(i + 1, len(new_ports)):
            if int(new_ports[i][1]) == int(new_ports[j][1]):
                dup_within.append((new_ports[i][0], new_ports[j][0], int(new_ports[i][1])))

    if dup_within:
        a, b, p = dup_within[0]
        return {"success": False, "error": f"Port conflict: {p} is used for both {a} and {b} in the new server. Choose unique ports."}, 400

    conflicts = []
    for field, p in new_ports:
        p = int(p)
        if p in used_ports:
            refs = used_ports[p][:3]
            ref_str = ", ".join([f"{n} ({f})" for n, f in refs])
            extra = ""
            if len(used_ports[p]) > 3:
                extra = f" (+{len(used_ports[p]) - 3} more)"
            conflicts.append(f"{field}={p} conflicts with {ref_str}{extra}")

    if conflicts:
        return {"success": False, "error": "Port conflict: one or more ports are already in use by an existing server. " + " | ".join(conflicts)}, 400

    sid = str(uuid.uuid4())

    install_dir = str(data.get("install_dir") or "").strip() or str(SERVERS_DIR / re.sub(r"[^a-zA-Z0-9 _\-]", "", name).strip() or "server")
    install_dir = os.path.abspath(install_dir)
    os.makedirs(install_dir, exist_ok=True)

    steamcmd = find_steamcmd() or ensure_steamcmd(str(TOOLS_DIR / "steamcmd"))

    cmd = [
        steamcmd,
        "+force_install_dir", install_dir,
        "+login", "anonymous",
        "+app_update", str(getattr(config, "STEAM_APP_ID", 3930080)),
        "validate",
        "+quit",
    ]

    def _run_steamcmd_once(args: list[str]):
        return subprocess.run(args, capture_output=True, text=True, shell=False)

    try:
        _run_steamcmd_once([steamcmd, "+quit"])
    except Exception:
        pass

    last_proc = None
    for attempt in range(2):
        try:
            last_proc = _run_steamcmd_once(cmd)
        except Exception as e:
            return {"success": False, "error": f"SteamCMD failed: {e}"}, 500

        if last_proc.returncode == 0:
            break
        time.sleep(1)
        try:
            _run_steamcmd_once([steamcmd, "+quit"])
        except Exception:
            pass

    if last_proc is None or last_proc.returncode != 0:
        return {
            "success": False,
            "error": "SteamCMD returned non-zero exit code",
            "stdout": getattr(last_proc, "stdout", ""),
            "stderr": getattr(last_proc, "stderr", ""),
            "returncode": getattr(last_proc, "returncode", None),
        }, 500

    bat = _server_bat_for(install_dir)
    if not bat:
        bat = os.path.join(install_dir, "RunServer.bat")
        Path(bat).write_text(f"@echo off\n\"%~dp0{SERVER_EXE_NAME}\" -ServerRemoteCommands {remote_port}\n", encoding="utf-8")

    try:
        _write_start_bat_settings(bat, fps=None, remote_port=remote_port)
    except Exception:
        pass

    # Pre-create Windows Firewall program/port rules BEFORE first boot to avoid the Windows Security prompt.
    try:
        _fw_sync_server_rules({
            "id": sid,
            "install_dir": install_dir,
            "remote_commands_port": remote_port,
            "game_port": game_port,
            "query_port": query_port,
        })
    except Exception:
        pass

    boot_output = []
    try:
        first_boot_seconds = int(data.get("first_boot_seconds") or 10)
    except Exception:
        first_boot_seconds = 10

    try:
        _run_bat_hidden_for_seconds(bat, install_dir, first_boot_seconds, boot_output)
    except Exception as e:
        boot_output.append(f"First boot failed: {e}")

    cfg_guess = Path(install_dir) / "DedicatedServerConfig.json"
    _wait_for_file(cfg_guess, timeout_sec=30)

    cfg_path = _server_config_path_for(install_dir)
    if cfg_path:
        try:
            cfg = _read_json_file(cfg_path) or {}
            if isinstance(name, str) and name.strip():
                cfg["ServerName"] = name.strip()
            if isinstance(game_port, int):
                if isinstance(cfg.get("Port"), dict):
                    cfg["Port"]["IsOverride"] = True
                    cfg["Port"]["Value"] = int(game_port)
            if isinstance(query_port, int):
                if isinstance(cfg.get("QueryPort"), dict):
                    cfg["QueryPort"]["IsOverride"] = True
                    cfg["QueryPort"]["Value"] = int(query_port)
            _write_json_file(cfg_path, cfg)
        except Exception:
            pass

    servers = load_servers() or []
    entry = {
        "id": sid,
        "name": name,
        "install_dir": install_dir,
        "remote_commands_port": remote_port,
        "game_port": game_port,
        "query_port": query_port,
        "mission_directory": str(MISSIONS_DIR),
        "mission_group": "BuiltIn",
        "mission_name": (BUILTIN_MISSIONS[0] if BUILTIN_MISSIONS else None),
    }
    if cluster_state.is_enabled():
        entry["node_id"] = _this_node_id()

    servers.append(entry)
    save_servers(servers)

    # Best-effort: manage Windows Firewall rules for this server's ports (panel-owned rules only)
    try:
        _fw_sync_server_rules(entry)
    except Exception:
        pass

    try:
        ports = load_ports()
        if all(int(p["port"]) != int(remote_port) for p in ports):
            ports.append({"port": int(remote_port), "name": name, "server_id": str(entry.get("id"))})
            save_ports(ports)
    except Exception:
        pass

    return {"success": True, "server": entry, "stdout": getattr(last_proc, "stdout", ""), "boot_output": "\n".join(boot_output)}, 200



@app.post("/api/cluster/servers/get_startup_settings", endpoint="api_cluster_servers_get_startup_settings_route")
def api_cluster_servers_get_startup_settings():
    """Coordinator -> member: fetch startup settings for a server on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400

    try:
        _ = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError:
        return jsonify({"success": False, "error": "Unknown server_id"}), 404

    # NOTE: the normal startup-settings route is implemented as get_startup_settings()
    # and expects server_id in query args. This cluster RPC passes server_id in JSON.
    # So we replicate the handler logic here.
    server = get_server_by_id(sid)
    bat_path = _bat_path(sid)

    settings = {
        "server_id": sid,
        "server_name": server.get("name", sid),
        "remote_command_port": server.get("remote_command_port", 7777),
        "game_port": server.get("game_port", 7777),
        "query_port": server.get("query_port", 27015),
        "rcon_port": server.get("rcon_port", 7778),
        "fps": server.get("fps", 60),
    }

    if bat_path.exists():
        try:
            bat_text = bat_path.read_text(encoding="utf-8", errors="ignore")
            bat_settings = _parse_bat_settings(bat_text)
            settings.update(bat_settings)
        except Exception:
            # Don't fail the request if the batch file is unreadable.
            pass

    return jsonify({"success": True, "settings": settings, "bat_path": str(bat_path)})


# NOTE: deprecated duplicate route removed (kept signed version below)
def _deprecated_cluster_servers_get_dedicated_config():
    # Member-side: return DedicatedServerConfig.json for the given server_id.
    data = request.get_json(silent=True) or {}
    sid = data.get("server_id")
    if not sid:
        return jsonify({"ok": False, "error": "Missing server_id"}), 400
    try:
        p = _config_path(sid)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Unknown server_id: {sid}"}), 404
    if not Path(p).exists():
        return jsonify({"ok": True, "data": {}}), 200
    try:
        return jsonify({"ok": True, "data": json.loads(Path(p).read_text(encoding="utf-8"))}), 200
    except Exception as e:
        return jsonify({"ok": False, "error": f"Failed to read config: {e}"}), 500

@app.post("/api/cluster/servers/set_startup_settings", endpoint="api_cluster_servers_set_startup_settings_route")
def api_cluster_servers_set_startup_settings():
    """Coordinator -> member: set startup settings for a server on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400

    try:
        _ = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError:
        return jsonify({"success": False, "error": "Unknown server_id"}), 404

    # Reuse the normal handler; it reads server_id & settings from the payload.
    return api_set_startup_settings()





@app.post("/api/cluster/servers/get_dedicated_config", endpoint="api_cluster_servers_get_dedicated_config_route")
def api_cluster_servers_get_dedicated_config():
    """Coordinator -> member: fetch DedicatedServerConfig.json for a server on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400

    try:
        _ = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError:
        return jsonify({"success": False, "error": "Unknown server_id"}), 404

    # Do not call the normal /api/dedicated-config handler here because it is
    # wrapped with requires_login() and would redirect to /login for cluster
    # traffic. Return a pure JSON payload.
    return jsonify(_dedicated_config_get_local(sid))


@app.post("/api/cluster/servers/save_dedicated_config", endpoint="api_cluster_servers_save_dedicated_config_route")
def api_cluster_servers_save_dedicated_config():
    """Coordinator -> member: save DedicatedServerConfig.json for a server on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400

    try:
        _ = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError:
        return jsonify({"success": False, "error": "Unknown server_id"}), 404

    # Do not call the normal /api/dedicated-config POST handler here because it is
    # wrapped with requires_login() and may redirect to /login for cluster traffic.
    res = _dedicated_config_save_local(sid, data.get("config"))
    if not res.get("success"):
        return jsonify(res), 400
    return jsonify(res)


@app.post("/api/cluster/servers/set_password", endpoint="api_cluster_servers_set_password_route")
def api_cluster_servers_set_password():
    """Coordinator -> member: set server password for a server on THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400

    try:
        _ = get_server_by_id(sid)
    except NoServersConfigured as e:
        return jsonify({"success": False, "error": str(e)}), 400
    except KeyError:
        return jsonify({"success": False, "error": "Unknown server_id"}), 404

    # Perform the password write locally. Do NOT call the normal /api/server-password
    # handler because it is wrapped with requires_login() and may redirect to /login
    # (HTML), which breaks the coordinator proxy.
    pw = data.get("password")
    if pw is None:
        return jsonify({"success": False, "error": "password is required (can be empty string)"}), 400
    if not isinstance(pw, str):
        return jsonify({"success": False, "error": "password must be a string"}), 400

    try:
        p = _config_path(sid)
        cfg = _read_json_file(p) if p.exists() else {}
        if not isinstance(cfg, dict):
            cfg = {}
        cfg["Password"] = pw
        cfg.setdefault("MissionDirectory", str(MISSIONS_DIR))
        _write_json_file(p, cfg)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@app.post("/api/cluster/servers/deploy")
def api_cluster_servers_deploy():
    """Coordinator -> member: deploy a server ON THIS node."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    payload, status = _create_server_local_from_payload(data)
    return jsonify(payload), status


@app.post("/api/cluster/servers/delete")
def api_cluster_servers_delete():
    """Coordinator -> member: delete a server ON THIS node (and optionally its files)."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request(request.method, request.path, body_bytes, dict(request.headers))
    if not ok:
        return jsonify({"success": False, "error": msg}), 401
    data = request.get_json(force=True, silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "server_id required"}), 400
    delete_files = bool(data.get("delete_files"))
    payload, code = _delete_server_local(sid, delete_files)
    return jsonify(payload), code


@app.get("/api/cluster/discovery")
@requires_login(role="admin")
def api_cluster_discovery():
    # Best-effort: ensure this node can receive discovery broadcasts on the LAN
    try:
        _fw_ensure_cluster_discovery_rules(int(config.FLASK_PORT), int(DISCOVERY_PORT))
    except Exception:
        pass
    return jsonify({"success": True, "clusters": _cluster_discovery.get_discovered()})


@app.post("/api/cluster/discovery/probe")
@requires_login(role="admin")
def api_cluster_discovery_probe():
    """Ask coordinators on the LAN to respond immediately.

    This improves discovery reliability on networks/hosts that drop periodic
    broadcast packets.
    """
    # Best-effort: ensure this node can receive discovery broadcasts on the LAN
    try:
        _fw_ensure_cluster_discovery_rules(int(config.FLASK_PORT), int(DISCOVERY_PORT))
    except Exception:
        pass
    try:
        _cluster_discovery.send_probe()
    except Exception:
        pass
    return jsonify({"success": True})


def _cluster_pending_requests() -> list[dict]:
    return list(cluster_state.state.get("pending_join_requests", []) or [])


def _cluster_set_pending_requests(reqs: list[dict]) -> None:
    cluster_state.state["pending_join_requests"] = reqs
    # Persist using ClusterState's save helper
    try:
        cluster_state._save()  # type: ignore[attr-defined]
    except Exception:
        # Fallback: direct write
        try:
            CLUSTER_FILE.write_text(json.dumps(cluster_state.state, indent=2), encoding="utf-8")
        except Exception:
            pass


JOIN_VERIFY_WINDOW_SEC = 300


@app.post("/api/cluster/join/request")
@requires_login(role="admin")
def api_cluster_join_request():
    """Member -> coordinator: request to join (no secret required).

    The coordinator must approve within JOIN_VERIFY_WINDOW_SEC.
    """
    if cluster_state.is_enabled():
        role = "coordinator" if cluster_state.is_coordinator() else "member"
        return jsonify({"success": False, "error": f"This node is already in a cluster as {role}. Leave/Disband (or Break) before requesting another join."}), 400

    data = request.get_json(silent=True) or {}
    coord_ip = str(data.get("coordinator_ip") or "").strip()
    coord_port = int(data.get("coordinator_port") or 0)
    if not coord_ip or not coord_port:
        return jsonify({"success": False, "error": "Missing coordinator IP/port."}), 400

    # Send our node info to coordinator; coordinator will use request.remote_addr if needed.
    node = dict(cluster_state.state.get("this_node", {}) or {})
    node.setdefault("ip", best_effort_local_ip())
    # Use configured panel port (defaults to 5000)
    try:
        node.setdefault("http_port", int(getattr(config, "FLASK_PORT", 5000)))
    except Exception:
        node.setdefault("http_port", 5000)
    node.setdefault("node_name", socket.gethostname())
    payload = {"node": node}
    try:
        resp = http_post_json(f"http://{coord_ip}:{int(coord_port)}/api/cluster/join/requests", payload, timeout=8)
    except Exception as e:
        return jsonify({"success": False, "error": f"Request failed: {e}"}), 502
    if not resp.get("success"):
        return jsonify(resp), 400

    # Record that we initiated a join request so only an approval matching this
    # request_id can finalize the join on this node.
    try:
        req_obj = resp.get("request") or {}
        rid = str(req_obj.get("request_id") or "").strip()
        if rid:
            cluster_state.state["pending_join_confirm"] = {
                "request_id": rid,
                "requested_at": int(time.time()),
                "coordinator_ip": coord_ip,
                "coordinator_port": int(coord_port),
            }
            try:
                cluster_state._save()  # type: ignore[attr-defined]
            except Exception:
                try:
                    CLUSTER_FILE.write_text(json.dumps(cluster_state.state, indent=2), encoding="utf-8")
                except Exception:
                    pass
    except Exception:
        pass

    return jsonify({"success": True, "request": resp.get("request")})


@app.get("/api/cluster/join/requests")
@requires_login(role="admin")
def api_cluster_join_requests_list():
    """Coordinator UI: list pending join requests."""
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return jsonify({"success": False, "error": "Only the coordinator can view join requests."}), 403
    now = int(time.time())
    reqs = []
    for r in _cluster_pending_requests():
        try:
            ts = int(r.get("ts") or 0)
        except Exception:
            ts = 0
        if ts and (now - ts) <= JOIN_VERIFY_WINDOW_SEC:
            reqs.append(r)
    # prune expired
    _cluster_set_pending_requests(reqs)
    return jsonify({"success": True, "requests": reqs})


@app.post("/api/cluster/join/requests")
def api_cluster_join_requests_receive():
    """Member -> coordinator: enqueue a join request."""
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return jsonify({"success": False, "error": "This node is not a coordinator."}), 400
    data = request.get_json(silent=True) or {}
    node = dict(data.get("node") or {})
    # Use observed IP for reliability
    observed_ip = request.remote_addr or node.get("ip")
    if observed_ip:
        node["ip"] = observed_ip
    if not node.get("http_port"):
        node["http_port"] = 5000
    rid = str(uuid.uuid4())
    ts = int(time.time())
    req = {
        "request_id": rid,
        "ts": ts,
        "node": node,
    }
    reqs = _cluster_pending_requests()
    # remove any existing request from same node_id
    nid = str((node.get("node_id") or "")).strip()
    if nid:
        reqs = [r for r in reqs if str((r.get("node") or {}).get("node_id") or "") != nid]
    reqs.insert(0, req)
    _cluster_set_pending_requests(reqs)
    return jsonify({"success": True, "request": req})


@app.post("/api/cluster/join/approve")
@requires_login(role="admin")
def api_cluster_join_approve():
    """Coordinator: approve a pending join request and push confirmation to member."""
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return jsonify({"success": False, "error": "Only the coordinator can approve joins."}), 403
    data = request.get_json(silent=True) or {}
    rid = str(data.get("request_id") or "").strip()
    if not rid:
        return jsonify({"success": False, "error": "Missing request_id"}), 400
    now = int(time.time())
    reqs = _cluster_pending_requests()
    match = None
    for r in reqs:
        if str(r.get("request_id") or "") == rid:
            match = r
            break
    if not match:
        return jsonify({"success": False, "error": "Request not found (it may have expired)."}), 404
    ts = int(match.get("ts") or 0)
    if not ts or (now - ts) > JOIN_VERIFY_WINDOW_SEC:
        reqs = [r for r in reqs if str(r.get("request_id") or "") != rid]
        _cluster_set_pending_requests(reqs)
        return jsonify({"success": False, "error": "Request expired. Ask the member to refresh and request again."}), 400

    node = dict(match.get("node") or {})
    ip = str(node.get("ip") or "").strip()
    port = int(node.get("http_port") or 0)
    if not ip or not port:
        return jsonify({"success": False, "error": "Member node IP/port missing."}), 400

    # Build cluster view + coordinator info + users for sync
    cluster_view = cluster_state.public_view()
    coordinator = cluster_state.state.get("coordinator") or {}
    users_list = list(_get_users() or [])
    secret = str(cluster_state.state.get("secret") or "")
    confirm_payload = {
        "request_id": rid,
        "issued_at": now,
        "expires_in": JOIN_VERIFY_WINDOW_SEC,
        "secret": secret,
        "cluster": cluster_view,
        "coordinator": coordinator,
        "users": users_list,
    }

    try:
        resp = http_post_json(f"http://{ip}:{int(port)}/api/cluster/join/confirm", confirm_payload, timeout=10)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to reach member: {e}"}), 502
    if not resp.get("success"):
        return jsonify({"success": False, "error": resp.get("error") or "Member rejected join"}), 400

    # Add as a member now that they've confirmed
    try:
        cluster_state.add_or_update_member(node)
    except Exception:
        pass

    # Remove request from pending list
    reqs = [r for r in reqs if str(r.get("request_id") or "") != rid]
    _cluster_set_pending_requests(reqs)

    return jsonify({"success": True})


@app.post("/api/cluster/join/confirm")
def api_cluster_join_confirm():
    """Coordinator -> member: finalize join, valid for JOIN_VERIFY_WINDOW_SEC."""
    if cluster_state.is_enabled():
        role = "coordinator" if cluster_state.is_coordinator() else "member"
        return jsonify({"success": False, "error": f"Already in a cluster as {role}."}), 400
    data = request.get_json(silent=True) or {}

    # Safety: only accept confirmations for a request that THIS node initiated.
    pending = dict(cluster_state.state.get("pending_join_confirm") or {})
    expected_rid = str(pending.get("request_id") or "").strip()
    incoming_rid = str(data.get("request_id") or "").strip()
    if not expected_rid or not incoming_rid or incoming_rid != expected_rid:
        return jsonify({"success": False, "error": "No matching pending join request on this node. Please request again."}), 400

    # Extra safety: only accept from the coordinator IP we requested.
    expected_coord_ip = str(pending.get("coordinator_ip") or "").strip()
    if expected_coord_ip and request.remote_addr and str(request.remote_addr).strip() != expected_coord_ip:
        return jsonify({"success": False, "error": "Join confirmation source mismatch."}), 403

    issued_at = int(data.get("issued_at") or 0)
    expires_in = int(data.get("expires_in") or JOIN_VERIFY_WINDOW_SEC)
    if not issued_at or (int(time.time()) - issued_at) > min(expires_in, JOIN_VERIFY_WINDOW_SEC):
        return jsonify({"success": False, "error": "Join confirmation expired. Please request again."}), 400
    secret = str(data.get("secret") or "").strip()
    cluster_view = data.get("cluster") or {}
    coordinator = data.get("coordinator") or {}
    users_list = data.get("users") or []
    if not secret or not (cluster_view.get("cluster_id") and coordinator.get("ip") and coordinator.get("http_port")):
        return jsonify({"success": False, "error": "Invalid confirmation payload."}), 400
    cluster_state.apply_joined_state(cluster_view=cluster_view, secret=secret, coordinator=coordinator)

    # Clear pending join marker
    try:
        cluster_state.state.pop("pending_join_confirm", None)
        try:
            cluster_state._save()  # type: ignore[attr-defined]
        except Exception:
            try:
                CLUSTER_FILE.write_text(json.dumps(cluster_state.state, indent=2), encoding="utf-8")
            except Exception:
                pass
    except Exception:
        pass
    try:
        _set_users(users_list)
    except Exception:
        pass
    return jsonify({"success": True})


@app.post("/api/cluster/create")
@requires_login(role="admin")
def api_cluster_create():
    # Do not allow creating a new cluster if this node is already in one (coordinator or member).
    if cluster_state.is_enabled():
        role = "coordinator" if cluster_state.is_coordinator() else "member"
        return jsonify({
            "success": False,
            "error": f"This node is already in a cluster as {role}. Use Leave/Disband (or Break) before creating a new cluster."
        }), 400

    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip() or "Cluster"
    broadcast = bool(data.get("broadcast"))
    view = cluster_state.create_cluster(name=name, broadcast=broadcast)
    # Best-effort: open firewall for LAN discovery + join traffic (panel-owned rules only)
    try:
        if broadcast:
            _fw_ensure_cluster_discovery_rules(int(config.FLASK_PORT), int(DISCOVERY_PORT))
    except Exception:
        pass
    return jsonify({"success": True, "cluster": view})
@app.post("/api/cluster/join")
@requires_login(role="admin")
def api_cluster_join():
    # Do not allow joining if already in a cluster.
    if cluster_state.is_enabled():
        role = "coordinator" if cluster_state.is_coordinator() else "member"
        return jsonify({"success": False, "error": f"This node is already in a cluster as {role}. Leave/Disband (or Break) before joining another cluster."}), 400

    data = request.get_json(silent=True) or {}
    coord_ip = (data.get("coordinator_ip") or "").strip()
    coord_port = int(data.get("coordinator_port") or 0)
    secret = (data.get("secret") or "").strip()
    if not coord_ip or not coord_port or not secret:
        return jsonify({"success": False, "error": "Missing coordinator IP/port or secret."}), 400

    # Block self-join (same node / same panel address)
    try:
        mine = cluster_state.state.get("this_node", {}) or {}
        if coord_ip == str(mine.get("ip") or "") and int(mine.get("http_port") or 0) == int(coord_port):
            return jsonify({"success": False, "error": "Cannot join your own cluster (same machine)."}), 400
    except Exception:
        pass

    try:
        resp = cluster_state.join_via_coordinator(coord_ip, coord_port, secret)
    except Exception as e:
        return jsonify({"success": False, "error": f"Join failed: {e}"}), 502
    if not resp.get("success"):
        return jsonify(resp), 400
    cluster_view = resp.get("cluster") or {}
    coordinator = resp.get("coordinator") or {"ip": coord_ip, "http_port": coord_port}
    users_list = resp.get("users") or []
    # Persist joined state + sync users from coordinator
    cluster_state.apply_joined_state(cluster_view=cluster_view, secret=secret, coordinator=coordinator)
    try:
        _set_users(users_list)
    except Exception:
        pass
    return jsonify({"success": True, "cluster": cluster_state.public_view()})
@app.post("/api/cluster/break")
@requires_login(role="admin")
def api_cluster_break():
    # Local-only failsafe: do not contact coordinator
    cluster_state.break_from_cluster()
    return jsonify({"success": True, "cluster": cluster_state.public_view()})



@app.post("/api/cluster/leave")
@requires_login(role="admin")
def api_cluster_leave():
    """Clean leave for members: ask coordinator to remove us, then clear local state."""
    if not cluster_state.is_enabled():
        return jsonify({"success": False, "error": "This node is not in a cluster."}), 400
    if cluster_state.is_coordinator():
        return jsonify({"success": False, "error": "This node is the cluster coordinator. Use Disband cluster (clean) or Break from cluster."}), 400

    coordinator_url = cluster_state.coordinator_url()
    if not coordinator_url:
        return jsonify({"success": False, "error": "Coordinator URL is unknown. Use Break from cluster."}), 400

    payload = {"node_id": str(cluster_state.state.get("this_node", {}).get("node_id") or "")}
    body_bytes = json.dumps(payload).encode("utf-8")
    headers = cluster_state.make_signed_headers("POST", "/api/cluster/members/remove", body_bytes)
    try:
        resp = http_post_json(f"{coordinator_url}/api/cluster/members/remove", payload, headers=headers, timeout=8)
    except Exception as e:
        return jsonify({"success": False, "error": f"Coordinator unreachable: {e}. Use Break from cluster if needed."}), 502

    if not resp.get("success"):
        return jsonify({"success": False, "error": resp.get("error") or "Coordinator refused leave."}), 400

    cluster_state.break_from_cluster()
    return jsonify({"success": True, "cluster": cluster_state.public_view()})


@app.post("/api/cluster/disband")
@requires_login(role="admin")
def api_cluster_disband():
    """Coordinator clean disband: instruct all members to leave, then clear local state."""
    if not cluster_state.is_enabled():
        return jsonify({"success": False, "error": "No active cluster to disband."}), 400
    if not cluster_state.is_coordinator():
        return jsonify({"success": False, "error": "Only the cluster coordinator can disband the cluster."}), 403

    members = list(cluster_state.state.get("members", []))
    failures = []
    for m in members:
        ip = m.get("ip")
        port = m.get("http_port")
        if not ip or not port:
            continue
        url = f"http://{ip}:{int(port)}/api/cluster/force_leave"
        payload = {"reason": "disbanded"}
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = cluster_state.make_signed_headers("POST", "/api/cluster/force_leave", body_bytes)
        try:
            http_post_json(url, payload, headers=headers, timeout=6)
        except Exception as e:
            failures.append(f"{ip}:{port} ({e})")

    cluster_state.break_from_cluster()
    return jsonify({"success": True, "cluster": cluster_state.public_view(), "failures": failures})


@app.post("/api/cluster/force_leave")
def api_cluster_force_leave():
    """Member receives coordinator instruction to leave (signed)."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request("POST", "/api/cluster/force_leave", body_bytes, request.headers)
    if not ok:
        return jsonify({"success": False, "error": msg}), 403

    # Coordinator should never force-leave itself.
    if cluster_state.is_coordinator():
        return jsonify({"success": False, "error": "Coordinator cannot be forced to leave."}), 400

    cluster_state.break_from_cluster()
    return jsonify({"success": True})


@app.post("/api/cluster/members/remove")
def api_cluster_members_remove():
    """Coordinator removes a member (signed request from member)."""
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return jsonify({"success": False, "error": "Not cluster coordinator."}), 403

    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request("POST", "/api/cluster/members/remove", body_bytes, request.headers)
    if not ok:
        return jsonify({"success": False, "error": msg}), 403

    data = request.get_json(silent=True) or {}
    node_id = (data.get("node_id") or "").strip()
    if not node_id:
        return jsonify({"success": False, "error": "Missing node_id"}), 400

    try:
        cluster_state.remove_member(node_id)
    except Exception:
        # fallback if method missing
        members = [m for m in cluster_state.state.get("members", []) if m.get("node_id") != node_id]
        cluster_state.state["members"] = members
        cluster_state._save()  # type: ignore

    return jsonify({"success": True, "cluster": cluster_state.public_view()})
@app.post("/api/cluster/join-request", endpoint="api_cluster_join_request_dash")
def api_cluster_join_request_dash():
    """Coordinator receives join request (NOT signed; uses join secret)."""
    if not cluster_state.is_enabled() or not cluster_state.is_coordinator():
        return jsonify({"success": False, "error": "Not a cluster coordinator."}), 400
    data = request.get_json(silent=True) or {}
    secret = (data.get("secret") or "").strip()
    if secret != str(cluster_state.state.get("secret") or ""):
        return jsonify({"success": False, "error": "Bad join secret."}), 403
    node = data.get("node") or {}
    if not node.get("node_id"):
        return jsonify({"success": False, "error": "Missing node_id."}), 400
    # Prevent a coordinator from joining itself (self-join)
    if str(node.get("node_id")) == str(cluster_state.state.get("coordinator_node_id") or ""):
        return jsonify({"success": False, "error": "Cannot join your own cluster (same node)."}), 400

    # Add to member list
    cluster_state.add_or_update_member({
        "node_id": node.get("node_id"),
        "node_name": node.get("node_name"),
        "ip": node.get("ip"),
        "http_port": node.get("http_port"),
    })
    # Return cluster view + current users for initial sync
    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    return jsonify({
        "success": True,
        "cluster": cluster_state.public_view(),
        "coordinator": cluster_state.state.get("coordinator"),
        "users": users_data,
    })


def _cluster_push_users_to_members() -> None:
    """Coordinator pushes full users list to all members."""
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return
    users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
    members = cluster_state.state.get("members", [])
    for m in members:
        ip = m.get("ip")
        port = m.get("http_port")
        if not ip or not port:
            continue
        url = f"http://{ip}:{int(port)}/api/cluster/sync/users"
        payload = {"users": users_data}
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = cluster_state.make_signed_headers("POST", "/api/cluster/sync/users", body_bytes)
        try:
            http_post_json(url, payload, headers=headers, timeout=6)
        except Exception:
            continue


@app.post("/api/cluster/sync/users")
def api_cluster_sync_users():
    """Members receive updated users list (signed)."""
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request("POST", "/api/cluster/sync/users", body_bytes, request.headers)
    if not ok:
        return jsonify({"success": False, "error": msg}), 403
    data = request.get_json(silent=True) or {}
    users_list = data.get("users") or []
    _set_users(users_list)
    return jsonify({"success": True})


@app.post("/api/cluster/users/apply")
def api_cluster_users_apply():
    """Members -> coordinator user change requests (signed)."""
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return jsonify({"success": False, "error": "Not coordinator"}), 400
    body_bytes = request.get_data() or b""
    ok, msg = cluster_state.verify_signed_request("POST", "/api/cluster/users/apply", body_bytes, request.headers)
    if not ok:
        return jsonify({"success": False, "error": msg}), 403
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    payload = data.get("payload") or {}

    # Apply change locally using same validations
    if action == "create":
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        role = (payload.get("role") or "mod").strip()
        if role not in ("admin", "mod"):
            role = "mod"
        if len(username) < 3 or len(password) < 6:
            return jsonify({"success": False, "error": "Username must be 3+ chars and password 6+ chars."}), 400
        if _get_user(username):
            return jsonify({"success": False, "error": "User already exists."}), 400
        users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
        users_data.append({
            "username": username,
            "password_hash": generate_password_hash(password),
            "role": role,
            "created_at": _iso_now(),
            "must_change_password": False,
        })
        _set_users(users_data)
        _append_audit("user_created", {"username": username, "role": role})
        _cluster_push_users_to_members()
        return jsonify({"success": True})

    if action == "reset_password":
        username = (payload.get("username") or "").strip()
        new_password = payload.get("password") or ""
        if len(new_password) < 6:
            return jsonify({"success": False, "error": "Password must be 6+ chars."}), 400
        users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
        found = False
        for u in users_data:
            if u.get("username", "").lower() == username.lower():
                u["password_hash"] = generate_password_hash(new_password)
                u["must_change_password"] = False
                found = True
                break
        if not found:
            return jsonify({"success": False, "error": "User not found."}), 404
        _set_users(users_data)
        _append_audit("user_password_reset", {"username": username})
        _cluster_push_users_to_members()
        return jsonify({"success": True})

    if action == "delete":
        username = (payload.get("username") or "").strip()
        if username.lower() == (session.get("username", "").lower()):
            # Note: session here is coordinator's session (likely empty for signed calls); still keep safe
            pass
        users_data = _load_json_file(USERS_FILE, {"users": []}).get("users", [])
        new_users = [u for u in users_data if u.get("username", "").lower() != username.lower()]
        if len(new_users) == len(users_data):
            return jsonify({"success": False, "error": "User not found."}), 404
        _set_users(new_users)
        _append_audit("user_deleted", {"username": username})
        _cluster_push_users_to_members()
        return jsonify({"success": True})

    return jsonify({"success": False, "error": "Unknown action"}), 400

# Localhost-only audit log viewing/clearing
@app.get("/api/audit-logs")
@requires_login(role="admin")
def api_audit_logs_get():
    if not _is_localhost():
        return jsonify({"success": False, "error": "Localhost only."}), 403
    if not AUDIT_LOG_FILE.exists():
        return jsonify({"success": True, "logs": []})
    lines = AUDIT_LOG_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()
    logs = []
    for line in lines[-500:]:
        try:
            logs.append(json.loads(line))
        except Exception:
            continue
    return jsonify({"success": True, "logs": logs})

@app.delete("/api/audit-logs")
@requires_login(role="admin")
def api_audit_logs_clear():
    if not _is_localhost():
        return jsonify({"success": False, "error": "Localhost only."}), 403
    AUDIT_LOG_FILE.write_text("", encoding="utf-8")
    _append_audit("audit_logs_cleared", {})
    return jsonify({"success": True})




# =============================
# Discord Bot API
# =============================
@app.get("/api/discord/status")
@requires_login(role="admin")
def api_discord_status():
    return jsonify({"success": True, "status": discord_manager.status()})

@app.get("/api/discord/config")
@requires_login(role="admin")
def api_discord_config_get():
    # Never return token to browser
    return jsonify({"success": True, "config": discord_manager.config.to_public_dict()})

@app.post("/api/discord/config")
@requires_login(role="admin")
def api_discord_config_set():
    data = request.get_json(force=True, silent=True) or {}
    cfg = discord_manager.config

    # token: only overwrite when provided (non-empty)
    token = str(data.get("token", "") or "").strip()
    if token:
        cfg.token = token

    cfg.enabled = bool(data.get("enabled", cfg.enabled))

    # role IDs can come as list or comma-separated string
    roles = data.get("allowed_role_ids", [])
    role_ids = []
    if isinstance(roles, str):
        parts = [p.strip() for p in roles.split(",")]
        for p in parts:
            if p.isdigit():
                role_ids.append(int(p))
    elif isinstance(roles, list):
        for r in roles:
            try:
                s = str(r).strip()
                if s.isdigit():
                    role_ids.append(int(s))
            except Exception:
                continue
    cfg.allowed_role_ids = role_ids

    guild_id = str(data.get("guild_id", "") or "").strip()
    cfg.guild_id = int(guild_id) if guild_id.isdigit() else None

    channel_id = str(data.get("channel_id", "") or "").strip()
    cfg.channel_id = int(channel_id) if channel_id.isdigit() else None

    prefix = str(data.get("command_prefix", "") or "").strip()
    cfg.command_prefix = prefix or "!"

    panel_base_url = str(data.get("panel_base_url", "") or "").strip() or cfg.panel_base_url
    cfg.panel_base_url = panel_base_url

    # keep internal secret stable (loaded earlier)
    cfg.internal_secret = DISCORD_INTERNAL_SECRET

    discord_manager.save_config(cfg)
    return jsonify({"success": True, "config": cfg.to_public_dict()})

@app.post("/api/discord/start")
@requires_login(role="admin")
def api_discord_start():
    payload, status = discord_manager.start()
    return jsonify(payload), status

@app.post("/api/discord/stop")
@requires_login(role="admin")
def api_discord_stop():
    payload, status = discord_manager.stop()
    return jsonify(payload), status



@app.get("/api/branding")
@requires_login()
def api_get_branding():
    b = _load_branding()
    logo_url = "/static/branding/logo.png" if b.get("has_logo") else None
    return jsonify({
        "success": True,
        "branding": {
            "accent": b.get("accent"),
            "accent2": b.get("accent2"),
            "logo_url": logo_url,
            "logo_size": {"w": 42, "h": 42},
        }
    })

@app.post("/api/branding")
@requires_login("admin")
def api_set_branding():
    payload = request.get_json(force=True, silent=True) or {}
    accent = payload.get("accent")
    accent2 = payload.get("accent2")
    updates = {}
    if accent is not None:
        if not _is_hex_color(str(accent)):
            return jsonify({"success": False, "error": "Invalid accent color."}), 400
        updates["accent"] = _normalize_hex(str(accent))
    if accent2 is not None:
        if not _is_hex_color(str(accent2)):
            return jsonify({"success": False, "error": "Invalid accent2 color."}), 400
        updates["accent2"] = _normalize_hex(str(accent2))
    if updates:
        _save_branding(updates)
    return jsonify({"success": True})

@app.post("/api/branding/logo")
@requires_login("admin")
def api_upload_brand_logo():
    if "file" not in request.files:
        return jsonify({"success": False, "error": "Missing file."}), 400
    f = request.files["file"]
    if not f or not getattr(f, "filename", ""):
        return jsonify({"success": False, "error": "No file selected."}), 400

    data = f.read()
    if not data:
        return jsonify({"success": False, "error": "Empty file."}), 400

    try:
        _fit_logo_square_bytes(data, BRANDING_LOGO_PATH, size=42)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to process image: {e}"}), 400

    return jsonify({"success": True, "logo_url": "/static/branding/logo.png"})

@app.post("/api/branding/logo/reset")
@requires_login("admin")
def api_reset_brand_logo():
    try:
        BRANDING_LOGO_PATH.unlink(missing_ok=True)
    except Exception:
        pass
    return jsonify({"success": True})


def _gallery_cache_root() -> Path:
    """Where to store fetched remote recordings on THIS node."""
    # Prefer the first local server's NOBlackBox OutputPath (same place the user stores local footage).
    try:
        for s in load_servers():
            if str(s.get("location") or "").lower() != "remote":
                out_dir = _gallery_get_output_path_for_server(s)
                if out_dir:
                    out_dir.mkdir(parents=True, exist_ok=True)
                    return out_dir
    except Exception:
        pass
    # Fallback inside panel folder
    p = BASE_DIR / "recordings"
    p.mkdir(parents=True, exist_ok=True)
    return p

def _gallery_cache_path_for_remote(server_name: str, filename: str) -> Path:
    safe_server = re.sub(r"[^a-zA-Z0-9._\- ]+", "_", server_name or "remote")
    root = _gallery_cache_root() / safe_server
    root.mkdir(parents=True, exist_ok=True)
    return root / filename

# ----- Gallery (NOBlackBox recordings) -----
def _gallery_get_output_path_for_server(server: dict) -> Path | None:
    try:
        cfg_text = _nobb_load_cfg(server)
        cfg = _nobb_cfg_to_dict(cfg_text)
        outp = str(cfg.get("OutputPath") or "").strip()
        if not outp:
            return None
        outp = _nobb_normalize_path(outp)
        return Path(outp)
    except Exception:
        return None

def _gallery_list_files(out_dir: Path) -> list[dict]:
    if not out_dir or not out_dir.exists() or not out_dir.is_dir():
        return []
    items = []
    for p in out_dir.iterdir():
        try:
            if not p.is_file():
                continue
            st = p.stat()
            items.append({
                "name": p.name,
                "path": str(p),
                "size": int(st.st_size),
                "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
                "mtime_ts": float(st.st_mtime),
            })
        except Exception:
            continue
    items.sort(key=lambda x: x.get("mtime_ts", 0), reverse=True)
    for it in items:
        it.pop("mtime_ts", None)
    return items

@app.get("/api/gallery/list")
@requires_login()
def api_gallery_list():
    sid = request.args.get("server_id", "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    # Remote server: proxy to member node
    if str(server.get("location") or "").lower() == "remote":
        if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
            return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400
        nid = str(server.get("node_id") or "").strip()
        mem = _find_member_by_node_id(nid) if nid else None
        if not mem:
            return jsonify({"success": False, "error": "Remote server owner not found."}), 400
        resp = _cluster_signed_post_to_member(mem, "/api/cluster/gallery/list", {"server_id": sid}, timeout=25)
        return jsonify(resp)

    out_dir = _gallery_get_output_path_for_server(server)
    if not out_dir:
        return jsonify({"success": False, "error": "NOBlackBox OutputPath is not set for this server."}), 400

    files = _gallery_list_files(out_dir)
    return jsonify({"success": True, "output_path": str(out_dir), "files": files})

@app.post("/api/gallery/open")
@requires_login("admin")
def api_gallery_open():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    name = str(data.get("name") or "").strip()
    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    if not name or "/" in name or "\\" in name or "\\" in name or ".." in name:
        return jsonify({"success": False, "error": "Invalid file name."}), 400    # Remote server: open the cached local copy (fetch first if needed)
    if str(server.get("location") or "").lower() == "remote":
        server_name = str(server.get("name") or server.get("server_name") or server.get("id") or "remote")
        cache_path = _gallery_cache_path_for_remote(server_name, name)
        if not cache_path.exists():
            return jsonify({"success": False, "error": "Recording not downloaded yet. Click 'View in program' again after Fetch completes (or press Refresh)."}), 400
        fpath = cache_path
    else:
        out_dir = _gallery_get_output_path_for_server(server)
        if not out_dir:
            return jsonify({"success": False, "error": "NOBlackBox OutputPath is not set for this server."}), 400
        fpath = (out_dir / name)
        if not fpath.exists() or not fpath.is_file():
            return jsonify({"success": False, "error": "File not found."}), 404


    try:
        # Open in the default associated program (Tacview if associated with .acmi)
        if os.name == "nt":
            os.startfile(str(fpath))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(fpath)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(fpath)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to open: {e}"}), 500



@app.post("/api/gallery/fetch")
@requires_login("admin")
def api_gallery_fetch():
    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    name = str(data.get("name") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400
    if not name or "/" in name or ".." in name:
        return jsonify({"success": False, "error": "Invalid file name."}), 400

    server = _find_server_in_unified_view(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    # Local server: nothing to fetch
    if str(server.get("location") or "").lower() != "remote":
        return jsonify({"success": True, "local": True})

    # Must be coordinator to fetch from a member
    if not (cluster_state.is_enabled() and cluster_state.is_coordinator()):
        return jsonify({"success": False, "error": "This node is not the cluster coordinator."}), 400

    nid = str(server.get("node_id") or "").strip()
    mem = _find_member_by_node_id(nid) if nid else None
    if not mem:
        return jsonify({"success": False, "error": "Remote server owner not found."}), 400

    resp = _cluster_signed_post_to_member(mem, "/api/cluster/gallery/fetch", {"server_id": sid, "name": name}, timeout=120)
    if not isinstance(resp, dict) or not resp.get("success"):
        return jsonify(resp if isinstance(resp, dict) else {"success": False, "error": "Fetch failed"}), 400

    b64 = resp.get("data_b64") or ""
    try:
        raw = base64.b64decode(b64.encode("utf-8"), validate=False)
    except Exception:
        return jsonify({"success": False, "error": "Failed to decode file data."}), 500

    server_name = str(server.get("name") or server.get("server_name") or server.get("id") or "remote")
    cache_path = _gallery_cache_path_for_remote(server_name, name)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "wb") as f:
            f.write(raw)
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to write cached file: {e}"}), 500

    return jsonify({"success": True, "local_path": str(cache_path)})

# ---- Cluster member endpoints for Gallery ----
@app.post("/api/cluster/gallery/list")
def api_cluster_gallery_list():
    if not cluster_state.is_enabled():
        return jsonify({"success": False, "error": "Cluster not enabled."}), 400
    if not _cluster_require_signed_request():
        return jsonify({"success": False, "error": "Unauthorized."}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    server = _find_server_by_id(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    out_dir = _gallery_get_output_path_for_server(server)
    if not out_dir:
        return jsonify({"success": False, "error": "NOBlackBox OutputPath is not set for this server."}), 400
    files = _gallery_list_files(out_dir)
    return jsonify({"success": True, "output_path": str(out_dir), "files": files})

@app.post("/api/cluster/gallery/open")
def api_cluster_gallery_open():
    if not cluster_state.is_enabled():
        return jsonify({"success": False, "error": "Cluster not enabled."}), 400
    if not _cluster_require_signed_request():
        return jsonify({"success": False, "error": "Unauthorized."}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    name = str(data.get("name") or "").strip()
    server = _find_server_by_id(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404
    if not name or "/" in name or ".." in name:
        return jsonify({"success": False, "error": "Invalid file name."}), 400

    out_dir = _gallery_get_output_path_for_server(server)
    if not out_dir:
        return jsonify({"success": False, "error": "NOBlackBox OutputPath is not set for this server."}), 400
    fpath = (out_dir / name)
    if not fpath.exists() or not fpath.is_file():
        return jsonify({"success": False, "error": "File not found."}), 404

    try:
        if os.name == "nt":
            os.startfile(str(fpath))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(fpath)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.Popen(["xdg-open", str(fpath)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to open: {e}"}), 500




@app.post("/api/cluster/gallery/fetch")
def api_cluster_gallery_fetch():
    if not cluster_state.is_enabled():
        return jsonify({"success": False, "error": "Cluster not enabled."}), 400
    if not _cluster_require_signed_request():
        return jsonify({"success": False, "error": "Unauthorized."}), 401

    data = request.get_json(silent=True) or {}
    sid = str(data.get("server_id") or "").strip()
    name = str(data.get("name") or "").strip()
    if not sid:
        return jsonify({"success": False, "error": "Missing server_id"}), 400
    if not name or "/" in name or ".." in name:
        return jsonify({"success": False, "error": "Invalid file name."}), 400

    server = _find_server_by_id(sid)
    if not server:
        return jsonify({"success": False, "error": "Server not found"}), 404

    out_dir = _gallery_get_output_path_for_server(server)
    if not out_dir:
        return jsonify({"success": False, "error": "NOBlackBox OutputPath is not set for this server."}), 400
    fpath = (out_dir / name)
    if not fpath.exists() or not fpath.is_file():
        return jsonify({"success": False, "error": "File not found."}), 404

    try:
        raw = fpath.read_bytes()
        b64 = base64.b64encode(raw).decode("utf-8")
        st = fpath.stat()
        return jsonify({
            "success": True,
            "name": fpath.name,
            "size": int(st.st_size),
            "mtime": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
            "data_b64": b64
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Failed to read file: {e}"}), 500


if __name__ == "__main__":
    # Background MOTD broadcaster (daemon)
    try:
        t = threading.Thread(target=_motd_scheduler_loop, daemon=True)
        t.start()
    except Exception:
        pass

    app.run(host=config.FLASK_HOST, port=int(config.FLASK_PORT))