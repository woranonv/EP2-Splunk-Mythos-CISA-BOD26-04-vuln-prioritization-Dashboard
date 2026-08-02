#!/usr/bin/env python3
"""Fetch CISA Vulnrichment SSVC values for observed CVEs and send them to
Splunk Cloud via HEC (index=threat_intel, sourcetype=cisa:ssvc).

Usage:
    export HEC_URL="https://http-inputs-<stack>.splunkcloud.com:443/services/collector/event"
    export HEC_TOKEN="<token>"
    python3 fetch_ssvc.py

Falls back to writing cisa_vulnrichment_lookup.csv if HEC vars are not set.
"""
import csv, json, os, ssl, sys, time, urllib.request

try:  # use certifi CA bundle if available (fixes macOS CERTIFICATE_VERIFY_FAILED)
    import certifi
    _CTX = ssl.create_default_context(cafile=certifi.where())
except ImportError:
    _CTX = ssl.create_default_context()

CVES = [
    # Windows Server
    "CVE-2025-59287", "CVE-2025-29824", "CVE-2025-53770", "CVE-2025-49704",
    "CVE-2025-33053", "CVE-2025-26633", "CVE-2025-24071", "CVE-2025-21333",
    "CVE-2025-59230", "CVE-2025-24990", "CVE-2025-53786", "CVE-2025-55315",
    # Linux / app servers
    "CVE-2025-32433", "CVE-2025-32463", "CVE-2025-24813", "CVE-2025-31324",
    "CVE-2025-61882", "CVE-2025-29927", "CVE-2025-55182",
]
BASE = "https://raw.githubusercontent.com/cisagov/vulnrichment/develop"
HEC_URL = os.environ.get("HEC_URL", "")
HEC_TOKEN = os.environ.get("HEC_TOKEN", "")
HEC_INDEX = os.environ.get("HEC_INDEX", "vuln_intel")


def ssvc_from(record):
    out = {}
    for adp in (record.get("containers", {}).get("adp") or []):
        if "CISA" not in (adp.get("providerMetadata", {}).get("shortName") or "").upper():
            continue
        for m in adp.get("metrics", []) or []:
            o = m.get("other") or {}
            if o.get("type") == "ssvc":
                content = o.get("content", {})
                for opt in content.get("options", []):
                    for k, v in opt.items():
                        out[k.strip().lower().replace(" ", "_")] = str(v).lower()
                out["ssvc_version"] = content.get("version", "")
    return out


def fetch_cve(cve):
    year, num = cve.split("-")[1], cve.split("-")[2]
    url = f"{BASE}/{year}/{num[:-3]}xxx/{cve}.json"
    with urllib.request.urlopen(url, timeout=30, context=_CTX) as r:
        rec = json.load(r)
    s = ssvc_from(rec)
    return {
        "cve": cve,
        "exploitation": s.get("exploitation", ""),
        "automatable": s.get("automatable", ""),
        "technical_impact": s.get("technical_impact", ""),
        "cisa_date_updated": (rec.get("cveMetadata") or {}).get("dateUpdated", ""),
        "source": "cisa_vulnrichment",
    }


def send_hec(rows):
    now = time.time()
    payload = "\n".join(json.dumps({
        "time": now,
        "event": r,
        "sourcetype": "cisa:ssvc",
        "index": HEC_INDEX,
        "source": "fetch_ssvc.py",
    }) for r in rows)
    req = urllib.request.Request(
        HEC_URL, data=payload.encode(),
        headers={"Authorization": f"Splunk {HEC_TOKEN}",
                 "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30, context=_CTX) as resp:
        body = json.loads(resp.read())
    if body.get("code") != 0:
        sys.exit(f"[!] HEC rejected the batch: {body}")
    print(f"[+] Sent {len(rows)} events to HEC (index={HEC_INDEX}, sourcetype=cisa:ssvc)")


def write_csv(rows):
    with open("cisa_vulnrichment_lookup.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cve", "exploitation", "automatable", "technical_impact"])
        w.writeheader()
        w.writerows([{k: r[k] for k in ("cve", "exploitation", "automatable", "technical_impact")} for r in rows])
    print(f"[+] Wrote cisa_vulnrichment_lookup.csv ({len(rows)} rows) — upload manually to Splunk.")


def main():
    rows = []
    for cve in CVES:
        try:
            r = fetch_cve(cve)
            rows.append(r)
            print(f"[+] {cve}: exploitation={r['exploitation'] or '?'} "
                  f"automatable={r['automatable'] or '?'} "
                  f"technical_impact={r['technical_impact'] or '?'}")
        except Exception as e:
            rows.append({"cve": cve, "exploitation": "", "automatable": "",
                         "technical_impact": "", "cisa_date_updated": "",
                         "source": "cisa_vulnrichment"})
            print(f"[!] {cve}: {e}  (blank — CVSS-vector fallback applies in SPL)")

    if HEC_URL and HEC_TOKEN:
        send_hec(rows)
        print("[*] Next: the scheduled search in Splunk materializes the lookup.")
    else:
        print("[*] HEC_URL/HEC_TOKEN not set — falling back to CSV output.")
        write_csv(rows)


if __name__ == "__main__":
    main()
