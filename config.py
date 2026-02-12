# =============================
# Flask web panel settings
# =============================
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000

# =============================
# HTTP Basic Authentication
# =============================
USERNAME = "admin"      # CHANGE
PASSWORD = "changeme"   # CHANGE

# =============================
# SteamCMD / Updates
# =============================
# Nuclear Option Dedicated Server AppID
STEAM_APP_ID = 3930080
STEAM_LOGIN = "anonymous"

AUTO_RESTART_AFTER_UPDATE = True

# =============================
# Ports tab storage
# =============================
PORTS_FILE = "ports.json"
DEFAULT_SERVER_PORTS = [{"port": 7779, "name": "Default Server"}]

# Optional hard fallback used only if ports.json is missing/corrupt
SERVER_PORTS = [7779]
