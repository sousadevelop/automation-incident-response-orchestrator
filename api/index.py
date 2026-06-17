"""
Notion IR — Webhook receiver for Grafana alerts.
Vercel Python Serverless Function (handler signature).
Implements idempotency via Fingerprint lookup before creating cards.
"""

import json
import os
import urllib.request
import urllib.error

NOTION_TOKEN = os.environ.get("NOTION_TOKEN", "")
NOTION_DB_ID = os.environ.get("NOTION_DB_ID", "")  # 4d5281f79dda49e9881c0029fea5127d

SEVERITY_MAP = {
    "critical": "Crítica",
    "warning":  "Média",
    "info":     "Baixa",
    "ok":       "Baixa",
}

STATUS_DEFAULT = "Triagem / Investigação"


def _notion_request(method: str, path: str, body: dict | None = None) -> dict:
    headers = {
        "Authorization": f"Bearer {NOTION_TOKEN}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28",
    }
    url = f"https://api.notion.com/v1{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def fingerprint_exists(fingerprint: str) -> bool:
    payload = {
        "filter": {
            "property": "Fingerprint",
            "rich_text": {"equals": fingerprint},
        }
    }
    result = _notion_request("POST", f"/databases/{NOTION_DB_ID}/query", payload)
    return len(result.get("results", [])) > 0


def build_fingerprint(alert: dict) -> str:
    if fp := alert.get("fingerprint"):
        return fp
    labels   = alert.get("labels", {})
    env      = labels.get("env", labels.get("cluster", "unknown"))
    domain   = labels.get("job", labels.get("namespace", "unknown"))
    name     = labels.get("alertname", "alert").lower().replace(" ", "-")
    date_str = (alert.get("startsAt", "")[:10]) or "unknown-date"
    return f"{env}/{domain}/{name}-{date_str}"


def create_notion_card(alert: dict) -> dict:
    labels   = alert.get("labels", {})
    anns     = alert.get("annotations", {})
    title    = anns.get("summary") or labels.get("alertname", "Alerta sem título")
    severity = SEVERITY_MAP.get(
        alert.get("status", "").lower(),
        SEVERITY_MAP.get(labels.get("severity", "").lower(), "Baixa")
    )
    fp = build_fingerprint(alert)
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


# ── Vercel serverless handler ──────────────────────────────────────────────────

def handler(request, response):
    """Vercel Python serverless function entry point."""

    if request.method == "GET":
        response.status_code = 200
        return json.dumps({"status": "ok", "service": "notion-ir"})

    if request.method != "POST":
        response.status_code = 405
        return json.dumps({"error": "Method not allowed"})

    try:
        body = request.body
        if isinstance(body, (bytes, bytearray)):
            body = body.decode()
        payload = json.loads(body)
    except Exception as e:
        response.status_code = 400
        return json.dumps({"error": f"Invalid JSON: {e}"})

    if not NOTION_TOKEN or not NOTION_DB_ID:
        response.status_code = 500
        return json.dumps({"error": "Missing NOTION_TOKEN or NOTION_DB_ID env vars"})

    alerts = payload.get("alerts", [payload])
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

    response.status_code = 200
    return json.dumps({
        "created": created,
        "skipped_idempotent": skipped,
        "errors": errors,
    })