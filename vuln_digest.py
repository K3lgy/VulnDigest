#!/usr/bin/env python3
"""Veille quotidienne des vulnérabilités -> Discord + Telegram.

Sources :
  - NVD (CVE publiées sur la période, filtrées par score CVSS)
  - CISA KEV (vulnérabilités activement exploitées, ajoutées récemment)

Configuration par variables d'environnement (voir .env.example).
Utilisation :
  python vuln_digest.py            # envoie la synthèse
  python vuln_digest.py --dry-run  # affiche la synthèse sans l'envoyer
"""
import argparse
import html
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

LOOKBACK_HOURS = int(os.getenv("LOOKBACK_HOURS", "24"))
MIN_CVSS = float(os.getenv("MIN_CVSS", "7.0"))
MAX_NVD_ITEMS = int(os.getenv("MAX_NVD_ITEMS", "25"))
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

DISCORD_LIMIT = 1900
TELEGRAM_LIMIT = 3900


def http_json(url, data=None, headers=None, retries=3):
    headers = {"User-Agent": "vuln-digest/1.0", **(headers or {})}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=body, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code in (429, 503) and attempt < retries - 1:
                time.sleep(10 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            if attempt < retries - 1:
                time.sleep(5)
                continue
            raise


def fetch_nvd(start, end):
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "resultsPerPage": 2000,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    data = http_json(NVD_URL + "?" + urllib.parse.urlencode(params), headers=headers)
    items = []
    for entry in data.get("vulnerabilities", []):
        cve = entry["cve"]
        status = cve.get("vulnStatus", "")
        if status in ("Rejected",):
            continue
        score, severity = None, "N/A"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                m = metrics[key][0]
                cvss = m["cvssData"]
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or m.get("baseSeverity", "N/A")
                break
        desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
        items.append({
            "id": cve["id"],
            "score": score,
            "severity": severity,
            "description": " ".join(desc.split()),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
        })
    total = len(items)
    unscored = sum(1 for i in items if i["score"] is None)
    kept = [i for i in items if i["score"] is not None and i["score"] >= MIN_CVSS]
    kept.sort(key=lambda i: i["score"], reverse=True)
    return kept, total, unscored


def fetch_kev(since):
    data = http_json(KEV_URL)
    out = []
    for v in data.get("vulnerabilities", []):
        added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        if added >= since.replace(hour=0, minute=0, second=0, microsecond=0):
            out.append({
                "id": v["cveID"],
                "vendor": v.get("vendorProject", ""),
                "product": v.get("product", ""),
                "name": v.get("vulnerabilityName", ""),
                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known",
                "due": v.get("dueDate", ""),
                "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
            })
    return out


def truncate(text, n):
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def sev_icon(sev):
    return {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")


def build_blocks(kev, nvd, total, unscored, start, end, fmt):
    """Retourne une liste de blocs de texte (fmt = 'discord' ou 'telegram')."""
    esc = html.escape if fmt == "telegram" else (lambda s: s)
    b = (lambda s: f"<b>{s}</b>") if fmt == "telegram" else (lambda s: f"**{s}**")
    link = (lambda t, u: f'<a href="{u}">{t}</a>') if fmt == "telegram" else (lambda t, u: f"[{t}]({u})")

    blocks = [
        f"🛡️ {b('Veille vulnérabilités')} — {end.strftime('%d/%m/%Y')}\n"
        f"Période : dernières {LOOKBACK_HOURS} h · {total} CVE publiées · "
        f"{len(nvd)} avec CVSS ≥ {MIN_CVSS:g} · {len(kev)} ajout(s) CISA KEV"
        + (f" · {unscored} sans score" if unscored else "")
    ]

    if kev:
        blocks.append(b("🚨 Activement exploitées (CISA KEV)"))
        for v in kev:
            ransom = " · 💀 ransomware" if v["ransomware"] else ""
            blocks.append(
                f"• {link(esc(v['id']), v['url'])} — {esc(v['vendor'])} {esc(v['product'])}\n"
                f"  {esc(truncate(v['name'], 150))}{ransom}\n"
                f"  Correctif exigé avant : {esc(v['due'])}"
            )
    else:
        blocks.append("🚨 Aucun nouvel ajout au catalogue CISA KEV.")

    if nvd:
        shown = nvd[:MAX_NVD_ITEMS]
        blocks.append(b(f"📋 Nouvelles CVE les plus sévères ({len(shown)}/{len(nvd)})"))
        for v in shown:
            blocks.append(
                f"{sev_icon(v['severity'])} {link(esc(v['id']), v['url'])} — "
                f"{b(str(v['score']))} {esc(v['severity'])}\n"
                f"  {esc(truncate(v['description'], 220))}"
            )
        if len(nvd) > len(shown):
            blocks.append(f"… et {len(nvd) - len(shown)} autre(s) CVE au-dessus du seuil.")
    else:
        blocks.append(f"📋 Aucune nouvelle CVE avec CVSS ≥ {MIN_CVSS:g} sur la période.")
    return blocks


def chunk(blocks, limit):
    messages, current = [], ""
    for blk in blocks:
        blk = truncate(blk, limit)
        if current and len(current) + len(blk) + 2 > limit:
            messages.append(current)
            current = blk
        else:
            current = f"{current}\n\n{blk}" if current else blk
    if current:
        messages.append(current)
    return messages


def send_discord(messages):
    for m in messages:
        http_json(DISCORD_WEBHOOK_URL, data={"content": m, "flags": 4})  # 4 = pas d'aperçu de liens
        time.sleep(1)


def send_telegram(messages):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    for m in messages:
        http_json(url, data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": m,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        })
        time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="affiche sans envoyer")
    args = ap.parse_args()

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=LOOKBACK_HOURS)

    errors = []
    try:
        nvd, total, unscored = fetch_nvd(start, end)
    except Exception as e:
        nvd, total, unscored = [], 0, 0
        errors.append(f"NVD indisponible : {e}")
    try:
        kev = fetch_kev(start)
    except Exception as e:
        kev = []
        errors.append(f"CISA KEV indisponible : {e}")

    for label, fmt, limit in (("Discord", "discord", DISCORD_LIMIT), ("Telegram", "telegram", TELEGRAM_LIMIT)):
        blocks = build_blocks(kev, nvd, total, unscored, start, end, fmt)
        for err in errors:
            blocks.append(f"⚠️ {html.escape(err) if fmt == 'telegram' else err}")
        messages = chunk(blocks, limit)

        if args.dry_run:
            print(f"===== {label} ({len(messages)} message(s)) =====")
            print("\n\n--- coupure ---\n\n".join(messages))
            continue

        try:
            if fmt == "discord":
                if not DISCORD_WEBHOOK_URL:
                    print("Discord ignoré : DISCORD_WEBHOOK_URL absent", file=sys.stderr)
                    continue
                send_discord(messages)
            else:
                if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
                    print("Telegram ignoré : TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID absent", file=sys.stderr)
                    continue
                send_telegram(messages)
            print(f"{label} : {len(messages)} message(s) envoyé(s)")
        except Exception as e:
            print(f"Erreur d'envoi {label} : {e}", file=sys.stderr)
            sys.exit(1)

    if errors and len(errors) == 2:
        sys.exit(1)


if __name__ == "__main__":
    main()
