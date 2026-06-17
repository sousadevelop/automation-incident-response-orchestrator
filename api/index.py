from http.server import BaseHTTPRequestHandler
import json
import os
import urllib.request
import urllib.error

NOTION_TOKEN = os.environ.get("NOTION_TOKEN", "")
NOTION_DB_ID = os.environ.get("NOTION_DB_ID", "")

SEVERITY_MAP = {
    "critical": "Crítica",
    "warning":  "Média",
    "info":     "Baixa",
    "ok":       "Baixa",
}
STATUS_DEFAULT = "Triagem / Investigação"


def _notion(method, path, body=None):
    headers = {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28",
    }
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        f"https://api.notion.com/v1{path}", data=data, headers=headers, method=method
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def fingerprint_exists(fp):
    res = _notion("POST", f"/databases/{NOTION_DB_ID}/query",
                  {"filter": {"property": "Fingerprint", "rich_text": {"equals": fp}}})
    return len(res.get("results", [])) > 0


def build_fp(alert):
    if fp := alert.get("fingerprint"):
        return fp
    labels = alert.get("labels", {})
    env    = labels.get("env", labels.get("cluster", "unknown"))
    domain = labels.get("job", labels.get("namespace", "unknown"))
    name   = labels.get("alertname", "alert").lower().replace(" ", "-")
    date   = (alert.get("startsAt", "")[:10]) or "unknown"
    return f"{env}/{domain}/{name}-{date}"


def create_card(alert):
    labels = alert.get("labels", {})
    anns   = alert.get("annotations", {})
    title  = anns.get("summary") or labels.get("alertname", "Alerta")
    sev    = SEVERITY_MAP.get(alert.get("status", "").lower(),
             SEVERITY_MAP.get(labels.get("severity", "").lower(), "Baixa"))
    fp     = build_fp(alert)
    return _notion("POST", "/pages", {
        "parent": {"database_id": NOTION_DB_ID},
        "properties": {
            "Name":        {"title": [{"text": {"content": title}}]},
            "Status":      {"select": {"name": STATUS_DEFAULT}},
            "Severity":    {"select": {"name": sev}},
            "Fingerprint": {"rich_text": [{"text": {"content": fp}}]},
        },
    })


class handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, status, body):
        out = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(out))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        self._send(200, {"status": "ok", "service": "notion-ir"})

    def do_POST(self):
        if not NOTION_TOKEN or not NOTION_DB_ID:
            self._send(500, {"error": "missing env vars"})
            return
        try:
            length  = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length))
        except Exception as e:
            self._send(400, {"error": f"bad json: {e}"}); return

        alerts  = payload.get("alerts", [payload])
        created, skipped, errors = [], [], []
        for alert in alerts:
            fp = build_fp(alert)
            try:
                if fingerprint_exists(fp):
                    skipped.append(fp)
                else:
                    page = create_card(alert)
                    created.append({"fingerprint": fp, "notion_page": page.get("id")})
            except urllib.error.HTTPError as e:
                errors.append({"fingerprint": fp, "error": e.read().decode()})
            except Exception as e:
                errors.append({"fingerprint": fp, "error": str(e)})

        self._send(200, {"created": created, "skipped_idempotent": skipped, "errors": errors})