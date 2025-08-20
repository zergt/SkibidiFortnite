import os, json, urllib.parse, urllib.request, datetime, logging
from azure.storage.blob import BlobServiceClient

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
WINDOW_HOURS = 24  # "new CVEs" window

def fetch_new(api_key=None, hours=WINDOW_HOURS):
    now = datetime.datetime.utcnow()
    start = (now - datetime.timedelta(hours=hours)).isoformat(timespec="seconds") + "Z"
    params = {"pubStartDate": start, "resultsPerPage": "2000"}
    url = f"{BASE}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    if api_key:
        req.add_header("apiKey", api_key)  # optional
    with urllib.request.urlopen(req) as r:
        return json.load(r)

def main(mytimer) -> None:
    logging.info("NVD sync start")
    data = fetch_new(api_key=os.environ.get("NVD_API_KEY"))
    items = data.get("vulnerabilities", [])

    compact = []
    for it in items:
        cve = it.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue

        # prefer English description
        desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang")=="en"), "")
        # get a score if present
        score = None
        metrics = cve.get("metrics", {})
        for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            m = metrics.get(k)
            if m:
                score = m[0]["cvssData"].get("baseScore")
                break

        compact.append({
            "cve": cve_id,
            "published": cve.get("published"),
            "score": score,
            "descriptions": [desc] if desc else []
        })

    conn = os.environ["STORAGE_CONN"]
    container = os.environ.get("SNAPSHOT_CONTAINER", "snapshots")
    bsc = BlobServiceClient.from_connection_string(conn)
    bsc.get_blob_client(container=container, blob="new.json").upload_blob(
        json.dumps(compact, separators=(",",":")).encode("utf-8"),
        overwrite=True
    )
    logging.info(f"NVD sync done: {len(compact)} items")
