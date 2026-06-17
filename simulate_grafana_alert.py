"""
Notion IR — QA: simula payload Grafana de alerta crítico de CPU.
Usage:
    python simulate_grafana_alert.py https://automation-incident-response-orches.vercel.app/
    python simulate_grafana_alert.py https://notion-ir.vercel.app
"""

import json
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Payload ────────────────────────────────────────────────────────────────────

def build_payload(run: int = 1) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return {
        "receiver": "notion-ir-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "critical",
                "labels": {
                    "alertname": "HighCPUUsage",
                    "severity": "critical",
                    "env": "prod-sa-east-1",
                    "job": "node-exporter",
                    "instance": "10.0.1.42:9100",
                    "namespace": "production",
                },
                "annotations": {
                    "summary": f"CPU usage acima de 95% em prod-sa-east-1 (run #{run})",
                    "description": "Node 10.0.1.42 com CPU > 95% por mais de 5 minutos.",
                    "runbook_url": "https://wiki.internal/runbooks/high-cpu",
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": f"prod-sa-east-1/node-exporter/highcpuusage-{date}",
            }
        ],
        "groupLabels": {"alertname": "HighCPUUsage"},
        "commonLabels": {"severity": "critical", "env": "prod-sa-east-1"},
        "commonAnnotations": {},
        "externalURL": "https://grafana.internal",
        "version": "4",
        "groupKey": "{}:{alertname='HighCPUUsage'}",
    }


# ── HTTP ───────────────────────────────────────────────────────────────────────

def post(url: str, payload: dict) -> tuple[int, dict]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, {"error": e.read().decode()}
    except Exception as e:
        return 0, {"error": str(e)}


# ── Tests ──────────────────────────────────────────────────────────────────────

def run_tests(base_url: str):
    webhook = base_url.rstrip("/")
    results = []

    # ── Test 1: health check ──────────────────────────────────────────────────
    print("\n[1/3] GET / — health check")
    req = urllib.request.Request(webhook, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            body = json.loads(r.read())
        ok = r.status == 200 and body.get("status") == "ok"
        print(f"     {'✅ PASS' if ok else '❌ FAIL'} — HTTP {r.status} {body}")
        results.append(ok)
    except Exception as e:
        print(f"     ❌ FAIL — {e}")
        results.append(False)

    # ── Test 2: first alert (should CREATE card) ──────────────────────────────
    print("\n[2/3] POST /  — alerta crítico CPU (deve criar card no Notion)")
    payload = build_payload(run=1)
    fp = payload["alerts"][0]["fingerprint"]
    print(f"     fingerprint: {fp}")
    status, body = post(webhook, payload)
    created = body.get("created", [])
    ok = status == 200 and len(created) == 1
    print(f"     {'✅ PASS' if ok else '❌ FAIL'} — HTTP {status}")
    print(f"     response: {json.dumps(body, indent=6, ensure_ascii=False)}")
    results.append(ok)

    # ── Test 3: same fingerprint (should SKIP — idempotency) ─────────────────
    print("\n[3/3] POST /  — mesmo fingerprint (deve retornar skipped_idempotent)")
    status2, body2 = post(webhook, payload)
    skipped = body2.get("skipped_idempotent", [])
    ok2 = status2 == 200 and len(skipped) == 1 and len(body2.get("created", [])) == 0
    print(f"     {'✅ PASS' if ok2 else '❌ FAIL'} — HTTP {status2}")
    print(f"     response: {json.dumps(body2, indent=6, ensure_ascii=False)}")
    results.append(ok2)

    # ── Summary ───────────────────────────────────────────────────────────────
    passed = sum(results)
    total  = len(results)
    print(f"\n{'='*50}")
    print(f"  Resultado: {passed}/{total} testes passaram")
    print(f"  Status: {'✅ ALL PASS' if passed == total else '❌ FAILURES DETECTED'}")
    print(f"{'='*50}\n")
    return passed == total


# ── Entry ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python simulate_grafana_alert.py https://automation-incident-response-orches.vercel.app/")
        print("Ex:  python simulate_grafana_alert.py https://notion-ir.vercel.app")
        sys.exit(1)

    url = sys.argv[1]
    print(f"Alvo: {url}")
    success = run_tests(url)
    sys.exit(0 if success else 1)