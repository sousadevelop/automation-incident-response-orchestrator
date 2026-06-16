"""
Notion IR — Webhook receiver for Grafana alerts.
Implements idempotency via Fingerprint lookup before creating cards.
"""

from http.server import BaseHTTPRequestHandler
import json
import os
import urllib.request
import urllib.error

NOTION_TOKEN = os.environ["NOTION_TOKEN"]
NOTION_DB_ID = os.environ["NOTION_DB_ID"]  # 4d5281f79dda49e9881c0029fea5127d

HEADERS = {
    "Authorization": f"Bearer {NOTION_TOKEN}",
    "Content-Type": "application/json",
    "Notion-Version": "2022-06-28",
}

SEVERITY_MAP = {
    "critical": "Crítica",
    "warning":  "Média",
    "info":     "Baixa",
    "ok":       "Baixa",
}

STATUS_DEFAULT = "Triagem / Investigação"


def _notion_request(method: str, path: str, body: dict | None = None) -> dict:
    url = f"https://api.notion.com/v1{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=HEADERS, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def fingerprint_exists(fingerprint: str) -> bool:
    """Query Notion DB for existing card with same fingerprint."""
    payload = {
        "filter": {
            "property": "Fingerprint",
            "rich_text": {"equals": fingerprint},
        }
    }
    result = _notion_request("POST", f"/databases/{NOTION_DB_ID}/query", payload)
    return len(result.get("results", [])) > 0


def build_fingerprint(alert: dict) -> str:
    """
    Build fingerprint from Grafana alert fields.
    Format: <env>/<domain>/<alertname>-<YYYY-MM-DD>
    Falls back to alert fingerprint if provided by Grafana.
    """
    if fp := alert.get("fingerprint"):
        return fp

    labels = alert.get("labels", {})
    env      = labels.get("env", labels.get("cluster", "unknown"))
    domain   = labels.get("job", labels.get("namespace", "unknown"))
    name     = labels.get("alertname", "alert").lower().replace(" ", "-")
    date_str = (alert.get("startsAt", "")[:10]) or "unknown-date"
    return f"{env}/{domain}/{name}-{date_str}"


def create_notion_card(alert: dict) -> dict:
    labels   = alert.get("labels", {})
    anns     = alert.get("annotations", {})

    title    = anns.get("summary") or labels.get("alertname", "Alerta sem título")
    severity = SEVERITY_MAP.get(alert.get("status", "").lower(),
               SEVERITY_MAP.get(labels.get("severity", "").lower(), "Baixa"))
    fp       = build_fingerprint(alert)

    payload = {
        "parent": {"database_id": NOTION_DB_ID},
        "properties": {
            "Name":        {"title": [{"text": {"content": title}}]},
            "Status":      {"select": {"name": STATUS_DEFAULT}},
            "Severity":    {"select": {"name": severity}},
            "Fingerprint": {"rich_text": [{"text": {"content": fp}}]},
        },
    }
    return _notion_request("POST", "/pages", payload)


class handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence default stdout logs
        pass

    def _respond(self, status: int, body: dict):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def do_GET(self):
        self._respond(200, {"status": "ok", "service": "notion-ir"})

    def do_POST(self):
        try:
            length  = int(self.headers.get("Content-Length", 0))
            raw     = self.rfile.read(length)
            payload = json.loads(raw)
        except Exception as e:
            self._respond(400, {"error": f"Invalid JSON: {e}"})
            return

        alerts = payload.get("alerts", [payload])  # support both Grafana batch and single
        created, skipped, errors = [], [], []

        for alert in alerts:
            fp = build_fingerprint(alert)
            try:
                if fingerprint_exists(fp):
                    skipped.append(fp)
                    continue
                page = create_notion_card(alert)
                created.append({"fingerprint": fp, "notion_page": page.get("id")})
            except urllib.error.HTTPError as e:
                errors.append({"fingerprint": fp, "error": e.read().decode()})
            except Exception as e:
                errors.append({"fingerprint": fp, "error": str(e)})

        self._respond(200, {
            "created": created,
            "skipped_idempotent": skipped,
            "errors":  errors,
        })
