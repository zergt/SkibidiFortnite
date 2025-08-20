import os, json, urllib.request, logging
from azure.storage.blob import BlobServiceClient

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def main(mytimer) -> None:
    logging.info("KEV sync start")
    with urllib.request.urlopen(KEV_URL) as r:
        data = json.load(r)
    vulns = data.get("vulnerabilities", [])
    out = []
    for v in vulns:
        cve = v.get("cveID")
        if not cve:
            continue
        out.append({
            "cve": cve,
            "dateAdded": v.get("dateAdded"),
            "descriptions": [v.get("shortDescription","")],
        })

    conn = os.environ["STORAGE_CONN"]
    container = os.environ.get("SNAPSHOT_CONTAINER","snapshots")
    bsc = BlobServiceClient.from_connection_string(conn)
    bsc.get_blob_client(container=container, blob="manipulated.json").upload_blob(
        json.dumps(out, separators=(",",":")).encode("utf-8"),
        overwrite=True
    )
    logging.info(f"KEV sync done: {len(out)} items")
