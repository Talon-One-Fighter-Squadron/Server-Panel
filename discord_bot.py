
"""
Discord bot integration for the Nuclear Option Server Panel.

Design goals:
- Bot runs *inside* the panel process (threaded), so users only paste a token.
- Bot commands call back into the panel's existing HTTP API using a localhost-only internal header.
- Access is restricted to configured Discord role IDs (and/or administrators).

Notes for users:
- If using prefix commands (!...), the bot requires the "Message Content Intent" enabled in the Discord Dev Portal.
- Invite the bot with the proper permissions (Send Messages, Read Message History, Use Slash Commands if enabled later).
"""

from __future__ import annotations

import json
import threading
import time
import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import urllib.request
import urllib.error

# Optional dependency: requests (used if installed). Fallback to urllib if missing.
try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None  # type: ignore

# ----------------------------
# Logging
# ----------------------------

_LOG_FORMAT = "[discord-bot] %(asctime)s %(levelname)s %(message)s"
logging.basicConfig(level=logging.INFO, format=_LOG_FORMAT)
log = logging.getLogger("server_panel.discord_bot")


def _tail_file(path: Path, max_lines: int = 200) -> str:
    """Return the last N lines from a text file (best effort)."""
    try:
        if not path.exists():
            return ""
        data = path.read_text(encoding="utf-8", errors="replace")
        lines = data.splitlines()[-max_lines:]
        return "\n".join(lines)
    except Exception:
        return ""

CONFIG_FILENAME = "discord_config.json"


def _is_localhost_host(host: str) -> bool:
    host = (host or "").lower().strip()
    return host.startswith("http://127.0.0.1") or host.startswith("http://localhost") or host.startswith("https://127.0.0.1") or host.startswith("https://localhost")


@dataclass
class DiscordConfig:
    enabled: bool = False
    token: str = ""
    allowed_role_ids: List[int] = None  # type: ignore
    guild_id: Optional[int] = None
    channel_id: Optional[int] = None
    command_prefix: str = "!"
    panel_base_url: str = "http://127.0.0.1:5000"
    internal_secret: str = ""

    def to_public_dict(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "has_token": bool(self.token),
            "allowed_role_ids": self.allowed_role_ids or [],
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "command_prefix": self.command_prefix or "!",
            "panel_base_url": self.panel_base_url,
        }

    def to_disk_dict(self) -> Dict[str, Any]:
        return {
            "enabled": bool(self.enabled),
            "token": self.token,
            "allowed_role_ids": self.allowed_role_ids or [],
            "guild_id": self.guild_id,
            "channel_id": self.channel_id,
            "command_prefix": self.command_prefix or "!",
            "panel_base_url": self.panel_base_url,
            "internal_secret": self.internal_secret,
        }


class DiscordBotManager:
    """
    Starts/stops a discord.py bot in a background thread.
    """

    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.cfg_path = self.data_dir / CONFIG_FILENAME
        self.log_path = self.data_dir / "discord_bot.log"
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._status: str = "stopped"
        self._last_error: str = ""
        self._client = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None

        self.config = self.load_config()

        # Ensure bot logs are written to disk for debugging "interaction failed" issues.
        try:
            # Avoid duplicating handlers if module reloads.
            if not any(getattr(h, "baseFilename", "") == str(self.log_path) for h in log.handlers):
                fh = logging.FileHandler(self.log_path, encoding="utf-8")
                fh.setLevel(logging.INFO)
                fh.setFormatter(logging.Formatter(_LOG_FORMAT))
                log.addHandler(fh)
        except Exception:
            pass

    def load_config(self) -> DiscordConfig:
        cfg = DiscordConfig(allowed_role_ids=[])
        if self.cfg_path.exists():
            try:
                data = json.loads(self.cfg_path.read_text(encoding="utf-8"))
                cfg.enabled = bool(data.get("enabled", False))
                cfg.token = str(data.get("token", "") or "")
                cfg.allowed_role_ids = [int(x) for x in (data.get("allowed_role_ids") or []) if str(x).strip().isdigit()]
                cfg.guild_id = int(data["guild_id"]) if str(data.get("guild_id", "")).strip().isdigit() else None
                cfg.channel_id = int(data["channel_id"]) if str(data.get("channel_id", "")).strip().isdigit() else None
                cfg.command_prefix = str(data.get("command_prefix", "!") or "!")
                cfg.panel_base_url = str(data.get("panel_base_url", "http://127.0.0.1:5000") or "http://127.0.0.1:5000").strip()
                cfg.internal_secret = str(data.get("internal_secret", "") or "")
            except Exception:
                # keep defaults, but don't crash panel
                cfg = DiscordConfig(allowed_role_ids=[])
        if not cfg.internal_secret:
            import secrets
            cfg.internal_secret = secrets.token_urlsafe(32)
            try:
                self.save_config(cfg)
            except Exception:
                pass
        return cfg

    def save_config(self, cfg: DiscordConfig) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cfg_path.write_text(json.dumps(cfg.to_disk_dict(), indent=2), encoding="utf-8")
        self.config = cfg

    def status(self) -> Dict[str, Any]:
        with self._lock:
            running = self._thread is not None and self._thread.is_alive()
            return {
                "running": running,
                "status": self._status,
                "last_error": self._last_error,
                "log_tail": _tail_file(self.log_path, max_lines=200),
                "config": self.config.to_public_dict(),
            }

    def start(self) -> Tuple[Dict[str, Any], int]:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return {"ok": True, "message": "Discord bot is already running."}, 200

            if not self.config.token:
                return {"ok": False, "message": "Bot token is not set."}, 400

            if not _is_localhost_host(self.config.panel_base_url):
                return {"ok": False, "message": "For safety, panel_base_url must be localhost (127.0.0.1 or localhost)."}, 400

            self._stop_flag.clear()
            self._last_error = ""
            self._status = "starting"

            t = threading.Thread(target=self._run_thread, name="DiscordBotThread", daemon=True)
            self._thread = t
            t.start()
            return {"ok": True, "message": "Discord bot starting..."}, 200

    def stop(self) -> Tuple[Dict[str, Any], int]:
        with self._lock:
            if not (self._thread and self._thread.is_alive()):
                self._status = "stopped"
                return {"ok": True, "message": "Discord bot is not running."}, 200
            self._status = "stopping"
            self._stop_flag.set()

            # ask the client to close
            try:
                if self._loop and self._client:
                    asyncio.run_coroutine_threadsafe(self._client.close(), self._loop)
            except Exception:
                pass

            return {"ok": True, "message": "Stopping Discord bot..."}, 200

    # ----------------------------
    # Internal helpers
    # ----------------------------



    def _panel_api(self, method: str, path: str, payload: Optional[dict] = None, params: Optional[dict] = None, timeout_sec: int = 8) -> dict:
        # Call back into the panel API (localhost) using the internal secret header.
        url = (self.config.panel_base_url or "").rstrip("/") + path
        # internal_secret is stored on the persisted config; older builds mistakenly
        # referenced a missing attribute on the manager instance.
        headers = {"X-Discord-Internal": getattr(self.config, "internal_secret", "")}

        # Log request details (never log the Discord bot token)
        safe_payload = None
        if isinstance(payload, dict):
            safe_payload = dict(payload)
            if "token" in safe_payload:
                safe_payload["token"] = "***"
        log.info("panel_api %s %s params=%s payload=%s", method.upper(), url, params, safe_payload)

        try:
            if requests is None:
                # Fallback to urllib (no extra deps)
                from urllib.parse import urlencode
                import urllib.request
                import urllib.error
                import json as _json

                full_url = url
                if params:
                    qs = urlencode(params, doseq=True)
                    full_url = full_url + ("&" if "?" in full_url else "?") + qs

                data_bytes = None
                if payload is not None:
                    data_bytes = _json.dumps(payload).encode("utf-8")
                    headers.setdefault("Content-Type", "application/json")

                req = urllib.request.Request(
                    full_url,
                    data=data_bytes,
                    headers=headers,
                    method=method.upper(),
                )
                with urllib.request.urlopen(req, timeout=int(timeout_sec)) as r:
                    status = getattr(r, "status", 200)
                    body = r.read()
                class _Resp:
                    def __init__(self, status, body):
                        self.status_code = int(status) if status is not None else 0
                        self._body = body or b""

                    @property
                    def ok(self):
                        return 200 <= int(self.status_code) < 400

                    def json(self):
                        return _json.loads(self.text or "{}")

                    @property
                    def text(self):
                        try:
                            return self._body.decode("utf-8", errors="replace")
                        except Exception:
                            return ""
                resp = _Resp(status, body)
            else:
                resp = requests.request(
                    method.upper(),
                    url,
                    headers=headers,
                    params=params,
                    json=payload if payload is not None else None,
                    timeout=int(timeout_sec),
                )
        except Exception as e:
            log.exception("panel_api request failed")
            return {"ok": False, "status": 0, "error": f"Failed to reach panel: {e}"}

        try:
            data = resp.json()
        except Exception:
            data = None

        # Log response
        try:
            preview = (resp.text or "").strip()
            if len(preview) > 400:
                preview = preview[:400] + "..."
        except Exception:
            preview = "<unavailable>"
        log.info("panel_api response status=%s ok=%s preview=%s", resp.status_code, resp.ok, preview)

        if isinstance(data, dict):
            if "ok" not in data:
                data["ok"] = resp.ok
            if "status" not in data:
                data["status"] = resp.status_code
            return data

        body = (resp.text or "").strip() or f"HTTP {resp.status_code}"
        return {"ok": resp.ok, "status": resp.status_code, "error": body}


    async def _panel_api_async(self, method: str, path: str, payload: Optional[dict] = None, params: Optional[dict] = None, timeout_sec: int = 8):
        """Async wrapper for _panel_api to avoid blocking the Discord event loop."""
        return await asyncio.to_thread(
            self._panel_api,
            method,
            path,
            payload,
            params,
            timeout_sec,
        )

    def _author_allowed(self, member) -> bool:
        # allow admins always; otherwise require one of allowed_role_ids
        try:
            if getattr(member.guild_permissions, "administrator", False):
                return True
            allowed = set(self.config.allowed_role_ids or [])
            if not allowed:
                return False
            roles = getattr(member, "roles", []) or []
            for r in roles:
                rid = getattr(r, "id", None)
                if rid in allowed:
                    return True
            return False
        except Exception:
            return False

    def _pick_server_id(self, servers: List[Dict[str, Any]], token: str) -> Optional[str]:
        token = (token or "").strip().lower()
        if not token:
            return None
        # exact id
        for s in servers:
            if str(s.get("id","")).lower() == token:
                return str(s["id"])
        # exact name
        for s in servers:
            if str(s.get("name","")).strip().lower() == token:
                return str(s["id"])
        # startswith name
        for s in servers:
            name = str(s.get("name","")).strip().lower()
            if name and name.startswith(token):
                return str(s["id"])
        return None

    def _help_text(self) -> str:
        p = self.config.command_prefix or "!"
        return (
            f"**Panel bot commands**\n"
            f"`{p}servers` — list servers\n"
            f"`{p}status <server>` — server status\n"
            f"`{p}start <server>` — start server\n"
            f"`{p}stop <server>` — stop server\n"
            f"`{p}update <server>` — update server via SteamCMD\n"
            f"`{p}cmd <server> <command...>` — send remote command\n"
        )

    def _run_thread(self) -> None:
        try:
            import discord  # type: ignore
            from discord import app_commands  # type: ignore
        except Exception as e:
            with self._lock:
                self._status = "error"
                self._last_error = f"discord.py not installed: {e}"
            return



        intents = discord.Intents.default()
        # Slash commands do NOT require Message Content Intent.
        intents.message_content = False
        intents.guilds = True
        # Do NOT request privileged intents we don't need.
        intents.members = False
        intents.presences = False

        cfg = self.config
        guild_obj = discord.Object(id=cfg.guild_id) if cfg.guild_id else None

        class PanelClient(discord.Client):
            def __init__(self, manager: "DiscordBotManager"):
                super().__init__(intents=intents)
                self.manager = manager
                self.tree = app_commands.CommandTree(self)

            async def setup_hook(self):
                # Guild sync (fast). If guild_id is not set, fall back to global sync.
                try:
                    if guild_obj is not None:
                        # If this bot was previously synced globally, users may see duplicate commands
                        # (one global + one guild). Clear global commands and sync an empty set to
                        # remove the old global registrations.
                        try:
                            self.tree.clear_commands(guild=None)
                            await self.tree.sync()
                        except Exception:
                            pass
                        await self.tree.sync(guild=guild_obj)
                        log.info("Slash commands synced to guild_id=%s", cfg.guild_id)
                    else:
                        await self.tree.sync()
                        log.warning("guild_id not set; slash commands synced globally (can take time to appear).")
                except Exception:
                    log.exception("Failed to sync slash commands")

        client = PanelClient(self)

        @client.event
        async def on_error(event, *args, **kwargs):
            # Catch-any logging for unexpected errors in event handlers.
            log.exception("Discord on_error event=%s args=%s kwargs=%s", event, args, kwargs)

        self._client = client

        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)

        def _interaction_allowed(interaction: discord.Interaction) -> tuple[bool, str]:
            # Guild restriction
            if cfg.guild_id and getattr(getattr(interaction, "guild", None), "id", None) != cfg.guild_id:
                return False, "This command can only be used in the configured guild."
            # Channel restriction
            if cfg.channel_id and getattr(getattr(interaction, "channel", None), "id", None) != cfg.channel_id:
                return False, "This command can only be used in the configured channel."
            # Role restriction
            member = getattr(interaction, "user", None)
            if getattr(interaction, "guild", None) and not self._author_allowed(member):
                return False, "You are not allowed to use panel commands."
            return True, ""

        def _servers_list() -> list[dict]:
            resp = self._panel_api("GET", "/api/servers")
            if isinstance(resp, dict) and isinstance(resp.get("servers"), list):
                return resp["servers"]
            if isinstance(resp, dict) and isinstance(resp.get("data"), list):
                return resp["data"]
            if isinstance(resp, list):
                return resp
            return []

        def _resolve_server_id_by_name(name: str) -> Optional[str]:
            token = (name or "").strip().lower()
            servers = _servers_list()
            # exact name match
            for s in servers:
                if str(s.get("name","")).strip().lower() == token:
                    return str(s.get("id"))
            # allow id
            for s in servers:
                if str(s.get("id","")).strip().lower() == token:
                    return str(s.get("id"))
            # startswith fallback
            for s in servers:
                if str(s.get("name","")).strip().lower().startswith(token):
                    return str(s.get("id"))
            return None

        def _get_cluster_nodes() -> list[dict]:
            """Return a list of available nodes for deployment.

            Each item: {"node_id": str, "label": str}
            Always includes a local sentinel ("__local__").
            """
            nodes: list[dict] = [{"node_id": "__local__", "label": "This node (local)"}]
            try:
                st = self._panel_api("GET", "/api/cluster/state")
                if isinstance(st, dict) and st.get("success"):
                    cluster = st.get("cluster") or st.get("state") or {}
                    # Members (remote nodes)
                    for m in list(cluster.get("members") or []):
                        mid = str(m.get("node_id") or "").strip()
                        if not mid:
                            continue
                        mname = str(m.get("node_name") or m.get("name") or m.get("ip") or mid).strip()
                        label = f"{mname} (remote)"
                        # Avoid duplicates
                        if any(x.get("node_id") == mid for x in nodes):
                            continue
                        nodes.append({"node_id": mid, "label": label})
            except Exception:
                pass
            return nodes

        async def _node_autocomplete(interaction: discord.Interaction, current: str):
            cur = (current or "").lower().strip()
            items = _get_cluster_nodes()
            out: list[app_commands.Choice[str]] = []
            for n in items:
                label = n["label"]
                nid = n["node_id"]
                if cur and (cur not in label.lower() and cur not in nid.lower()):
                    continue
                # Use node_id as the actual value so deploy can pass it straight through.
                out.append(app_commands.Choice(name=label, value=nid))
                if len(out) >= 25:
                    break
            return out

        async def _server_name_autocomplete(interaction: discord.Interaction, current: str):
            try:
                servers = _servers_list()
                cur = (current or "").strip().lower()
                choices = []
                for s in servers:
                    nm = str(s.get("name","")).strip()
                    if not nm:
                        continue
                    if not cur or cur in nm.lower():
                        choices.append(app_commands.Choice(name=nm, value=nm))
                    if len(choices) >= 25:
                        break
                return choices
            except Exception:
                return []

        async def _footage_recording_autocomplete(interaction: discord.Interaction, current: str):
            """Populate the /footage recording choices (newest -> oldest).
            Values are numeric strings: 1=newest, 2=second-newest, etc.
            """
            try:
                # If the interaction isn't allowed, don't leak filenames
                ok, _why = _interaction_allowed(interaction)
                if not ok:
                    return []

                # The selected server name comes from the 'server' option
                server_name = ""
                try:
                    server_name = str(getattr(interaction.namespace, "server", "") or "")
                except Exception:
                    server_name = ""

                if not server_name:
                    return []

                sid = _resolve_server_id_by_name(server_name)
                if not sid:
                    return []

                lst = await self._panel_api_async("GET", f"/api/gallery/list?server_id={sid}", timeout_sec=30)
                if not isinstance(lst, dict) or not lst.get("success"):
                    return []

                files = list(lst.get("files") or [])
                if not files:
                    return []

                cur = (current or "").strip().lower()
                choices = []
                # Discord autocomplete max = 25
                for i, it in enumerate(files[:200], start=1):  # cap scan
                    nm = str(it.get("name") or "").strip()
                    if not nm:
                        continue
                    label = f"{i}. {nm}"
                    if (not cur) or (cur in nm.lower()) or (cur in str(i)):
                        # value as index so the command's existing numeric handling works
                        choices.append(app_commands.Choice(name=label[:100], value=str(i)))
                    if len(choices) >= 25:
                        break
                return choices
            except Exception:
                return []

        async def _send_ephemeral(interaction: discord.Interaction, text: str):
            try:
                if interaction.response.is_done():
                    await interaction.followup.send(text, ephemeral=True)
                else:
                    await interaction.response.send_message(text, ephemeral=True)
            except Exception:
                pass

        def _format_players(payload: dict) -> str:
            # Panel's remote commander typically returns:
            # { "response": { "Players": [ {Name/SteamId...}, ... ] }, "status_code": "Success" }
            resp = payload.get("response") if isinstance(payload, dict) else None
            players = None
            if isinstance(resp, dict):
                players = resp.get("Players") or resp.get("players")
            if players is None and isinstance(payload, dict):
                players = payload.get("Players") or payload.get("players")
            if not isinstance(players, list):
                players = []
            if not players:
                return "No players connected."
            out = []
            for p in players:
                name = ""
                steam = ""
                if isinstance(p, dict):
                    # Common key variants:
                    # - Game/remote-command JSON: displayName, steamId, faction
                    # - Older/alt: Name/SteamId
                    name = str(
                        p.get("displayName")
                        or p.get("DisplayName")
                        or p.get("Name")
                        or p.get("name")
                        or p.get("PlayerName")
                        or p.get("player_name")
                        or ""
                    ).strip()
                    steam = str(
                        p.get("steamId")
                        or p.get("SteamId")
                        or p.get("steam_id")
                        or p.get("SteamID")
                        or p.get("id")
                        or ""
                    ).strip()
                else:
                    # string fallback
                    s = str(p).strip()
                    name = s
                if not name and steam:
                    name = "unknown"
                if steam:
                    out.append(f"{name} - {steam}")
                else:
                    out.append(name)
            return "\n".join(out[:50])

        @client.event
        async def on_ready():
            with self._lock:
                self._status = "running"
                self._last_error = ""
            print(f"[discord] Logged in as {client.user} (id={client.user.id})")

        # ----------------------------
        # Slash commands
        # ----------------------------

        @client.tree.command(name="help", description="Show bot commands", guild=guild_obj)
        async def help_cmd(interaction: discord.Interaction):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            await _send_ephemeral(
                interaction,
                "**Server Panel slash commands**\n"
                "/servers\n"
                "/start /stop /restart /update\n"
                "/deploy /delete\n"
                "/say /password /motd\n"
                "/players\n"
                "/footage\n"
                "/kick /ban /unban /banreload /clearkicked",
            )

        @client.tree.command(name="servers", description="List servers", guild=guild_obj)
        async def servers_cmd(interaction: discord.Interaction):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            servers = _servers_list()
            if not servers:
                await _send_ephemeral(interaction, "No servers found.")
                return
            lines = []
            for s in servers[:25]:
                loc = s.get("location") or ("remote" if s.get("node_id") else "local")
                status = s.get("status") or "unknown"
                lines.append(f"- **{s.get('name','(unnamed)')}** — `{status}` — {str(loc).upper()}")
            await _send_ephemeral(interaction, "\n".join(lines))

        @client.tree.command(name="start", description="Start a server", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def start_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/local/start-server", {"server_id": sid})
            msg = r.get("message") or r.get("error") or "OK"
            await _send_ephemeral(interaction, f"✅ Start `{server}`: {msg}" if r.get("ok") else f"❌ Start `{server}` failed: {msg}")

        @client.tree.command(name="stop", description="Stop a server", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def stop_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/local/stop-server", {"server_id": sid})
            msg = r.get("message") or r.get("error") or "OK"
            await _send_ephemeral(interaction, f"✅ Stop `{server}`: {msg}" if r.get("ok") else f"❌ Stop `{server}` failed: {msg}")

        @client.tree.command(name="restart", description="Restart a server", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def restart_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/local/restart-server", {"server_id": sid})
            msg = r.get("message") or r.get("error") or "OK"
            await _send_ephemeral(interaction, f"✅ Restart `{server}`: {msg}" if r.get("ok") else f"❌ Restart `{server}` failed: {msg}")

        @client.tree.command(name="update", description="Update a server via SteamCMD", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def update_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            await interaction.response.defer(ephemeral=True, thinking=True)
            # SteamCMD validate can take a while, especially first run or on slow disks.
            r = await self._panel_api_async("POST", "/local/update-server", {"server_id": sid}, timeout_sec=1800)
            msg = r.get("message") or r.get("error") or "OK"
            await interaction.followup.send(f"✅ Update `{server}`: {msg}" if r.get("ok") else f"❌ Update `{server}` failed: {msg}", ephemeral=True)

        @client.tree.command(name="deploy", description="Deploy (create) a new server", guild=guild_obj)
        @app_commands.autocomplete(node=_node_autocomplete)
        async def deploy_cmd(
            interaction: discord.Interaction,
            name: str,
            remote_port: int = 7779,
            game_port: Optional[int] = None,
            query_port: Optional[int] = None,
            node: Optional[str] = None,
        ):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return

            # Basic validation: prevent duplicate ports (common cause of remote deploy failing)
            try:
                rp = int(remote_port)
                gp = int(game_port) if game_port is not None else None
                qp = int(query_port) if query_port is not None else None
            except Exception:
                await _send_ephemeral(interaction, "❌ Invalid port value. Ports must be integers.")
                return

            ports = [("remote_port", rp)]
            if gp is not None:
                ports.append(("game_port", gp))
            if qp is not None:
                ports.append(("query_port", qp))

            bad = [(k, v) for (k, v) in ports if v < 1 or v > 65535]
            if bad:
                await _send_ephemeral(interaction, f"❌ Invalid port(s): {', '.join(f'{k}={v}' for k,v in bad)}")
                return

            seen = {}
            dups = []
            for k, v in ports:
                if v in seen:
                    dups.append((seen[v], k, v))
                else:
                    seen[v] = k
            if dups:
                a, b, v = dups[0]
                await _send_ephemeral(interaction, f"❌ Ports must be unique. `{a}` and `{b}` are both set to `{v}`.")
                return

            await interaction.response.defer(ephemeral=True, thinking=True)
            payload: dict = {"name": name, "remote_commands_port": remote_port}
            if game_port is not None:
                payload["game_port"] = int(game_port)
            if query_port is not None:
                payload["query_port"] = int(query_port)
            # If a target node was selected (cluster deploy), send it through.
            # The panel API already supports target_node_id when coordinator.
            if node and str(node).strip() not in ('__local__','local'):
                payload["target_node_id"] = str(node).strip()
            # Deploy/download/install can take a while.
            r = await self._panel_api_async("POST", "/api/servers", payload, timeout_sec=1800)
            if r.get("success") or r.get("ok"):
                await interaction.followup.send(f"✅ Deployed server `{name}`.", ephemeral=True)
            else:
                await interaction.followup.send(f"❌ Deploy failed: {r.get('error') or r}", ephemeral=True)

        @client.tree.command(name="delete", description="Delete a server", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def delete_cmd(interaction: discord.Interaction, server: str, delete_files: bool = False):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            await interaction.response.defer(ephemeral=True, thinking=True)
            # Deleting (especially remote) can take longer than the default HTTP timeout.
            # If the panel completes the delete but the request times out, the bot would
            # incorrectly report a failure.
            r = await self._panel_api_async(
                "DELETE",
                f"/api/servers/{sid}",
                payload={"delete_files": bool(delete_files)},
                timeout_sec=120,
            )
            if r.get("success") or r.get("ok"):
                await interaction.followup.send(f"✅ Deleted `{server}`.", ephemeral=True)
            else:
                await interaction.followup.send(f"❌ Delete failed: {r.get('error') or r}", ephemeral=True)

        @client.tree.command(name="say", description="Send a chat message to players", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def say_cmd(interaction: discord.Interaction, server: str, message: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/command/send-chat-message", {"server_id": sid, "message": message})
            await _send_ephemeral(interaction, "✅ Sent." if r.get("ok") else f"❌ Failed: {r.get('error') or r}")


        @client.tree.command(name="footage", description="Upload a NOBlackBox recording to this channel", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete, recording=_footage_recording_autocomplete)
        async def footage_cmd(interaction: discord.Interaction, server: str, recording: str = ""):
            """Upload a NOBlackBox recording.

            Usage:
              /footage server:<name> recording:<optional # or filename>
            - If recording is omitted: uploads the newest recording.
            - If recording is a number: 1 = newest, 2 = second-newest, etc.
            - Otherwise: treated as a filename (or substring match).
            """
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return

            await interaction.response.defer(ephemeral=True, thinking=True)

            # List recordings (newest -> oldest)
            lst = await self._panel_api_async("GET", f"/api/gallery/list?server_id={sid}", timeout_sec=60)
            if not isinstance(lst, dict) or not lst.get("success"):
                await interaction.followup.send(f"❌ Gallery list failed: {lst.get('error') if isinstance(lst, dict) else lst}", ephemeral=True)
                return
            files = list(lst.get("files") or [])
            if not files:
                await interaction.followup.send("No recordings found for that server.", ephemeral=True)
                return

            # Pick a recording
            pick = None
            rec_arg = (recording or "").strip()
            if rec_arg:
                # number => index
                if rec_arg.isdigit():
                    idx = int(rec_arg)
                    if idx < 1 or idx > len(files):
                        await interaction.followup.send(f"❌ Invalid recording number. Choose 1-{len(files)}.", ephemeral=True)
                        return
                    pick = files[idx - 1]
                else:
                    # exact/substring match
                    low = rec_arg.lower()
                    for it in files:
                        nm = str(it.get("name") or "")
                        if nm.lower() == low:
                            pick = it
                            break
                    if pick is None:
                        for it in files:
                            nm = str(it.get("name") or "")
                            if low in nm.lower():
                                pick = it
                                break
                    if pick is None:
                        await interaction.followup.send("❌ Recording not found. Use a number (1=newest) or the filename.", ephemeral=True)
                        return
            else:
                pick = files[0]  # newest

            name = str(pick.get("name") or "")
            if not name:
                await interaction.followup.send("❌ Could not determine recording filename.", ephemeral=True)
                return

            # For remote servers, fetch caches the file locally on the coordinator. For local servers, we can use output_path/name directly.
            local_path = ""
            fetch = await self._panel_api_async("POST", "/api/gallery/fetch", {"server_id": sid, "name": name}, timeout_sec=180)
            if isinstance(fetch, dict) and fetch.get("success") and fetch.get("local_path"):
                local_path = str(fetch.get("local_path") or "")
            else:
                out_path = str(lst.get("output_path") or "")
                if out_path:
                    local_path = str(Path(out_path) / name)

            fpath = Path(local_path) if local_path else None
            if not fpath or not fpath.exists() or not fpath.is_file():
                await interaction.followup.send("❌ Recording file is not accessible on the panel host.", ephemeral=True)
                return

            size = 0
            try:
                size = int(fpath.stat().st_size)
            except Exception:
                size = 0

            # Discord upload limits vary; keep a conservative default unless configured elsewhere.
            max_bytes = 8 * 1024 * 1024  # 8MB
            if size and size > max_bytes:
                await interaction.followup.send(f"❌ File is too large to upload (size={size/1024/1024:.1f}MB). Discord default limit is ~8MB.", ephemeral=True)
                return

            # Post the file into the channel where the command was run.
            try:
                file_obj = discord.File(str(fpath), filename=fpath.name)
                await interaction.channel.send(content=f"📼 **{server}** — `{fpath.name}`", file=file_obj)
            except Exception as e:
                await interaction.followup.send(f"❌ Upload failed: {e}", ephemeral=True)
                return

            # Send a short confirmation + a list (newest->oldest) for reference.
            preview = []
            for i, it in enumerate(files[:10], start=1):
                nm = str(it.get("name") or "")
                mt = str(it.get("mtime") or "")
                preview.append(f"{i}. `{nm}` ({mt})")
            extra = "\n".join(preview)
            msg = f"✅ Uploaded `{name}`.\n\n**Latest recordings (newest → oldest):**\n{extra}"
            if len(files) > 10:
                msg += f"\n… and {len(files)-10} more."
            await interaction.followup.send(msg, ephemeral=True)

        @client.tree.command(name="password", description="Set/clear the server password", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def password_cmd(interaction: discord.Interaction, server: str, password: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/api/server-password", {"server_id": sid, "password": password})
            await _send_ephemeral(interaction, "✅ Password updated." if r.get("success") or r.get("ok") else f"❌ Failed: {r.get('error') or r}")

        @client.tree.command(name="motd", description="Set MOTD text and repeat interval (minutes)", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def motd_cmd(interaction: discord.Interaction, server: str, text: str, repeat_minutes: int = 0):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/api/server-motd", {"server_id": sid, "text": text, "repeat_minutes": int(repeat_minutes)})
            await _send_ephemeral(interaction, "✅ MOTD updated." if r.get("success") or r.get("ok") else f"❌ Failed: {r.get('error') or r}")

        @client.tree.command(name="players", description="List currently connected players", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def players_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            # Player list can occasionally take >3 seconds if the server is busy.
            # Defer so the interaction doesn't fail.
            await interaction.response.defer(ephemeral=True, thinking=True)
            r = await self._panel_api_async("POST", "/command/get-player-list", {"server_id": sid})
            if not r.get("ok"):
                await interaction.followup.send(f"❌ Failed: {r.get('error') or r}", ephemeral=True)
                return
            await interaction.followup.send(_format_players(r), ephemeral=True)

        @client.tree.command(name="kick", description="Kick a player by steam_id", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def kick_cmd(interaction: discord.Interaction, server: str, steam_id: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/command/kick-player", {"server_id": sid, "steam_id": steam_id})
            await _send_ephemeral(interaction, "✅ Kicked." if r.get("ok") else f"❌ Failed: {r.get('error') or r}")

        @client.tree.command(name="ban", description="Ban a player by steam_id", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def ban_cmd(interaction: discord.Interaction, server: str, steam_id: str, reason: str = ""):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            payload = {"server_id": sid, "steam_id": steam_id}
            if reason:
                payload["reason"] = reason
            r = await self._panel_api_async("POST", "/command/banlist-add", payload)
            await _send_ephemeral(interaction, "✅ Banned." if r.get("ok") else f"❌ Failed: {r.get('error') or r}")

        @client.tree.command(name="unban", description="Unban a player by steam_id", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def unban_cmd(interaction: discord.Interaction, server: str, steam_id: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/command/banlist-remove", {"server_id": sid, "steam_id": steam_id})
            await _send_ephemeral(interaction, "✅ Unbanned." if r.get("ok") else f"❌ Failed: {r.get('error') or r}")

        @client.tree.command(name="banreload", description="Reload ban list from disk", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def banreload_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/command/banlist-reload", {"server_id": sid})
            await _send_ephemeral(interaction, "✅ Banlist reloaded." if r.get("ok") else f"❌ Failed: {r.get('error') or r}")

        @client.tree.command(name="clearkicked", description="Clear kicked players list (allow rejoin)", guild=guild_obj)
        @app_commands.autocomplete(server=_server_name_autocomplete)
        async def clearkicked_cmd(interaction: discord.Interaction, server: str):
            ok, why = _interaction_allowed(interaction)
            if not ok:
                await _send_ephemeral(interaction, f"❌ {why}")
                return
            sid = _resolve_server_id_by_name(server)
            if not sid:
                await _send_ephemeral(interaction, f"Server not found: `{server}`")
                return
            r = await self._panel_api_async("POST", "/command/clear-kicked-players", {"server_id": sid})
            await _send_ephemeral(interaction, "✅ Cleared kicked list." if r.get("ok") else f"❌ Failed: {r.get('error') or r}")
        async def _stop_watcher():
            while not self._stop_flag.is_set():
                await asyncio.sleep(0.5)
            try:
                await client.close()
            except Exception:
                pass

        try:
            loop.create_task(_stop_watcher())
            loop.run_until_complete(client.start(self.config.token))
        except Exception as e:
            with self._lock:
                self._status = "error"
                self._last_error = str(e)
            try:
                loop.run_until_complete(client.close())
            except Exception:
                pass
        finally:
            with self._lock:
                if self._status != "error":
                    self._status = "stopped"
            try:
                loop.stop()
                loop.close()
            except Exception:
                pass
            self._client = None
            self._loop = None