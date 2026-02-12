# Nuclear Option Server Control Panel (Modern UI)

This is a Python/Flask re-skin of the original control panel you uploaded.
It keeps the same command endpoints and TCP protocol (RemoteCommander), but
updates the UI to a modern dark theme with rounded edges (inspired by your image).

## Install
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configure
Edit `config.py`:
- `SERVER_PORTS`: list of dedicated server remote command ports on localhost
- `USERNAME` / `PASSWORD`: Basic Auth credentials (CHANGE DEFAULT)
- optional `SSL_CERT_PATH` / `SSL_KEY_PATH` to run HTTPS directly

## Run
```bash
python app.py
```

Then open: `http://<host>:5000/`

If you host publicly, run behind a reverse proxy (Nginx/Caddy) with HTTPS.


## Start (Windows / Administrator)

If you want the panel to automatically create/modify Windows Firewall rules (cluster discovery + server ports), start it elevated:

- Run `Start-Panel.bat` (prompts for UAC)
- Or run `Start-Panel.ps1` (prompts for UAC)

Starting `app.py` by double-clicking typically runs non-elevated and cannot manage firewall rules.
