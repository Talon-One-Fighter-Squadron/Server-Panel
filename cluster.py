"""LAN cluster support (MVP) for the Nuclear Option Server Panel.

Coordinator (creator) is authoritative.

Features:
- UDP discovery (optional) so nodes can see clusters on the LAN.
- HMAC signed node-to-node requests using a shared secret.
- Local-only "Break from cluster" failsafe.

Only uses the Python standard library.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import threading
import time
import uuid
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


DISCOVERY_PORT = 47037
# Faster LAN discovery without noticeable overhead.
DISCOVERY_INTERVAL_SEC = 0.6
DISCOVERY_TTL_SEC = 3.0
SIGNATURE_SKEW_SEC = 45


def _now() -> float:
    return time.time()


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def generate_secret() -> str:
    return _b64url(os.urandom(32))


def sign(secret: str, ts: str, method: str, path: str, body_bytes: bytes) -> str:
    key = secret.encode("utf-8")
    msg = (ts + "\n" + method.upper() + "\n" + path + "\n").encode("utf-8") + body_bytes
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def verify(secret: str, ts: str, method: str, path: str, body_bytes: bytes, signature: str) -> bool:
    expected = sign(secret, ts, method, path, body_bytes)
    return hmac.compare_digest(expected, signature)


def http_post_json(url: str, payload: dict, headers: Optional[dict] = None, timeout: int = 8) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            ctype = ""
            try:
                ctype = str(resp.headers.get("Content-Type") or "")
            except Exception:
                ctype = ""

            data = resp.read().decode("utf-8", errors="replace")
            if not data:
                return {"success": False, "error": f"Empty response (HTTP {status})"}
            try:
                return json.loads(data)
            except Exception:
                snippet = data.strip().replace("\r", "")
                if len(snippet) > 240:
                    snippet = snippet[:240] + "..."
                # Common root cause: the remote node is running a different panel build,
                # so the /api/cluster/... endpoint is missing and a generic HTML page is returned.
                hint = ""
                low = (snippet or "").lower()
                if status == 200 and ("<html" in low or "<!doctype" in low or "text/html" in (ctype or "").lower()):
                    hint = "Remote node likely has a different panel version (cluster API missing). Update the remote node to the same panel build."
                # Put the useful info into `error` because the UI often only shows the error string.
                err = f"Non-JSON response (HTTP {status})"
                if hint:
                    err += f" — {hint}"
                if snippet:
                    err += f"\n\nResponse preview:\n{snippet}"
                return {"success": False, "error": err, "detail": snippet, "content_type": ctype}
    except urllib.error.HTTPError as e:
        try:
            body_txt = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_txt = ""
        snippet = body_txt.strip().replace("\r", "")
        if len(snippet) > 240:
            snippet = snippet[:240] + "..."
        msg = f"HTTP {getattr(e, 'code', 'error')}"
        if snippet:
            msg += f": {snippet}"
        return {"success": False, "error": msg}
    except Exception as e:
        return {"success": False, "error": str(e)}


def http_get_json(url: str, headers: Optional[dict] = None, timeout: int = 6) -> dict:
    req = urllib.request.Request(url, method="GET")
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8")
        return json.loads(data) if data else {}


@dataclass
class DiscoveredCluster:
    cluster_id: str
    cluster_name: str
    coordinator_ip: str
    coordinator_port: int
    last_seen: float


class ClusterDiscovery:
    """UDP broadcast discovery listener + (optional) broadcaster."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: Dict[str, DiscoveredCluster] = {}
        self._stop = threading.Event()
        self._listen_thread: Optional[threading.Thread] = None
        self._broadcast_thread: Optional[threading.Thread] = None
        self._broadcast_enabled = False
        self._broadcast_payload: Optional[dict] = None


    def _broadcast_targets(self) -> list[tuple[str, int]]:
        """Return a list of broadcast targets for discovery packets.

        Windows (especially with VPN/virtual adapters) can be unreliable with only
        '<broadcast>'. We try a few common targets to improve LAN discovery.
        """
        targets: list[tuple[str, int]] = []
        # Standard broadcast
        targets.append(("<broadcast>", DISCOVERY_PORT))
        # Global broadcast
        targets.append(("255.255.255.255", DISCOVERY_PORT))
        # Best-effort /24 subnet broadcast based on the primary local IP.
        try:
            ip = best_effort_local_ip()
            parts = ip.split(".")
            if len(parts) == 4 and parts[0] != "127":
                subnet_bcast = ".".join(parts[:3] + ["255"])
                targets.append((subnet_bcast, DISCOVERY_PORT))
        except Exception:
            pass

        # De-duplicate while preserving order
        dedup: list[tuple[str, int]] = []
        seen = set()
        for t in targets:
            if t not in seen:
                seen.add(t)
                dedup.append(t)
        return dedup
    def start(self) -> None:
        if self._listen_thread and self._listen_thread.is_alive():
            return
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._listen_thread.start()
        self._broadcast_thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self._broadcast_thread.start()

    def stop(self) -> None:
        self._stop.set()

    def set_broadcast(self, enabled: bool, payload: Optional[dict]) -> None:
        with self._lock:
            self._broadcast_enabled = enabled
            self._broadcast_payload = payload

    def get_discovered(self) -> List[dict]:
        now = _now()
        with self._lock:
            dead = [k for k, v in self._seen.items() if now - v.last_seen > DISCOVERY_TTL_SEC]
            for k in dead:
                self._seen.pop(k, None)
            out = [{
                "cluster_id": v.cluster_id,
                "cluster_name": v.cluster_name,
                "coordinator_ip": v.coordinator_ip,
                "coordinator_port": v.coordinator_port,
                "last_seen": v.last_seen,
            } for v in self._seen.values()]
        out.sort(key=lambda x: x.get("last_seen", 0), reverse=True)
        return out

    def send_probe(self) -> None:
        """Broadcast a discovery probe to solicit coordinator responses."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            payload = {"type": "nuclear-option-panel-discover"}
            data = json.dumps(payload).encode("utf-8")
            for host, port in self._broadcast_targets():
                sock.sendto(data, (host, port))
        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _listen_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", DISCOVERY_PORT))
            sock.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    data, addr = sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    payload = json.loads(data.decode("utf-8"))
                except Exception:
                    continue

                # Active probe: members broadcast a probe and coordinators reply.
                # This improves reliability on networks where periodic broadcasts
                # are dropped by host firewalls.
                if payload.get("type") == "nuclear-option-panel-discover":
                    with self._lock:
                        enabled = self._broadcast_enabled
                        bpayload = self._broadcast_payload
                    if enabled and bpayload:
                        try:
                            sock.sendto(json.dumps(bpayload).encode("utf-8"), (addr[0], DISCOVERY_PORT))
                        except Exception:
                            pass
                    continue

                if payload.get("type") != "nuclear-option-panel-cluster":
                    continue
                cid = payload.get("cluster_id")
                cname = payload.get("cluster_name")
                cport = payload.get("coordinator_port")
                if not cid or not cname or not cport:
                    continue
                ip = payload.get("coordinator_ip") or addr[0]
                with self._lock:
                    self._seen[str(cid)] = DiscoveredCluster(
                        cluster_id=str(cid),
                        cluster_name=str(cname),
                        coordinator_ip=str(ip),
                        coordinator_port=int(cport),
                        last_seen=_now(),
                    )
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def _broadcast_loop(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            while not self._stop.is_set():
                time.sleep(DISCOVERY_INTERVAL_SEC)
                with self._lock:
                    enabled = self._broadcast_enabled
                    payload = self._broadcast_payload
                if not enabled or not payload:
                    continue
                try:
                    data = json.dumps(payload).encode("utf-8")
                    for host, port in self._broadcast_targets():
                        sock.sendto(data, (host, port))
                except Exception:
                    continue
        finally:
            try:
                sock.close()
            except Exception:
                pass


class ClusterState:
    def __init__(self, path: Path, discovery: ClusterDiscovery) -> None:
        self.path = path
        self.discovery = discovery
        self._lock = threading.Lock()
        self.state: dict = self._load()
        self._apply_broadcast_config()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                return {"enabled": False}
        return {"enabled": False}

    def _save(self) -> None:
        self.path.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        self._apply_broadcast_config()

    def _apply_broadcast_config(self) -> None:
        enabled = bool(self.state.get("enabled")) and bool(self.state.get("broadcast")) and self.is_coordinator()
        payload = None
        if enabled:
            payload = {
                "type": "nuclear-option-panel-cluster",
                "cluster_id": self.state.get("cluster_id"),
                "cluster_name": self.state.get("cluster_name"),
                "coordinator_ip": self.state.get("this_node", {}).get("ip"),
                "coordinator_port": self.state.get("this_node", {}).get("http_port"),
            }
        self.discovery.set_broadcast(enabled, payload)

    def is_enabled(self) -> bool:
        return bool(self.state.get("enabled"))

    def is_coordinator(self) -> bool:
        if not self.is_enabled():
            return False
        return self.state.get("this_node", {}).get("node_id") == self.state.get("coordinator_node_id")

    def ensure_node_identity(self, node_name: str, ip: str, http_port: int) -> None:
        with self._lock:
            st = dict(self.state)
            tn = dict(st.get("this_node") or {})
            if not tn.get("node_id"):
                tn["node_id"] = str(uuid.uuid4())
            tn["node_name"] = node_name
            tn["ip"] = ip
            tn["http_port"] = int(http_port)
            st["this_node"] = tn
            self.state = st
            self._save()

    def public_view(self) -> dict:
        st = self.state
        return {
            "enabled": bool(st.get("enabled")),
            "cluster_id": st.get("cluster_id"),
            "cluster_name": st.get("cluster_name"),
            "broadcast": bool(st.get("broadcast")),
            "is_coordinator": self.is_coordinator(),
            "this_node": st.get("this_node", {}),
            "coordinator": st.get("coordinator"),
            "members": st.get("members", []),
        }

    def create_cluster(self, name: str, broadcast: bool) -> dict:
        with self._lock:
            st = dict(self.state)
            tn = dict(st.get("this_node") or {})
            st["enabled"] = True
            st["cluster_id"] = str(uuid.uuid4())
            st["cluster_name"] = name
            st["broadcast"] = bool(broadcast)
            st["secret"] = generate_secret()
            st["coordinator_node_id"] = tn.get("node_id")
            st["coordinator"] = {
                "node_id": tn.get("node_id"),
                "node_name": tn.get("node_name"),
                "ip": tn.get("ip"),
                "http_port": tn.get("http_port"),
            }
            st["members"] = []
            self.state = st
            self._save()
            return self.public_view() | {"secret": st.get("secret")}

    def break_from_cluster(self) -> None:
        with self._lock:
            this_node = self.state.get("this_node", {})
            self.state = {"enabled": False, "this_node": this_node}
            self._save()

    def make_signed_headers(self, method: str, path: str, body_bytes: bytes) -> dict:
        secret = str(self.state.get("secret") or "")
        ts = str(int(_now()))
        sig = sign(secret, ts, method, path, body_bytes)
        return {
            "X-Cluster-Id": str(self.state.get("cluster_id") or ""),
            "X-Node-Id": str(self.state.get("this_node", {}).get("node_id") or ""),
            "X-Timestamp": ts,
            "X-Signature": sig,
        }

    def verify_signed_request(self, method: str, path: str, body_bytes: bytes, headers: dict) -> tuple[bool, str]:
        if not self.is_enabled():
            return False, "Cluster not enabled"
        cid = headers.get("X-Cluster-Id", "")
        if cid != str(self.state.get("cluster_id")):
            return False, "Wrong cluster"
        ts = headers.get("X-Timestamp", "")
        sig = headers.get("X-Signature", "")
        if not ts or not sig:
            return False, "Missing signature"
        try:
            ts_i = int(ts)
        except Exception:
            return False, "Bad timestamp"
        if abs(int(_now()) - ts_i) > SIGNATURE_SKEW_SEC:
            return False, "Signature expired"
        secret = str(self.state.get("secret") or "")
        if not verify(secret, ts, method, path, body_bytes, sig):
            return False, "Bad signature"
        return True, "ok"

    def coordinator_url(self) -> Optional[str]:
        if not self.is_enabled():
            return None
        c = self.state.get("coordinator") or {}
        ip = c.get("ip")
        port = c.get("http_port")
        if not ip or not port:
            return None
        return f"http://{ip}:{int(port)}"

    def add_or_update_member(self, node: dict) -> None:
        with self._lock:
            members = list(self.state.get("members", []))
            nid = node.get("node_id")
            if not nid:
                return
            found = False
            for m in members:
                if m.get("node_id") == nid:
                    m.update(node)
                    m["last_seen"] = int(_now())
                    found = True
                    break
            if not found:
                nn = dict(node)
                nn["last_seen"] = int(_now())
                members.append(nn)
            self.state["members"] = members
            self._save()

    def remove_member(self, node_id: str) -> None:
        """Coordinator removes a member by node_id."""
        if not node_id:
            return
        with self._lock:
            members = list(self.state.get("members", []))
            members = [m for m in members if m.get("node_id") != node_id]
            self.state["members"] = members
            self._save()

    def apply_joined_state(self, cluster_view: dict, secret: str, coordinator: dict) -> None:
        with self._lock:
            this_node = self.state.get("this_node", {})
            self.state = {
                "enabled": True,
                "cluster_id": cluster_view.get("cluster_id"),
                "cluster_name": cluster_view.get("cluster_name"),
                "broadcast": False,
                "secret": secret,
                "coordinator_node_id": (cluster_view.get("coordinator") or {}).get("node_id"),
                "coordinator": coordinator,
                "this_node": this_node,
                "members": cluster_view.get("members", []),
            }
            self._save()

    def join_via_coordinator(self, coordinator_ip: str, coordinator_port: int, secret: str) -> dict:
        url = f"http://{coordinator_ip}:{int(coordinator_port)}/api/cluster/join-request"
        body = {"secret": secret, "node": self.state.get("this_node", {})}
        return http_post_json(url, body, timeout=8)


def best_effort_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass
