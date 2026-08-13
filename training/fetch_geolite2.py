"""Download the GeoLite2 City + ASN databases into the Tauri resource dir.

GraphHunter already ships the reader (the `maxminddb` crate, compiled in
behind the `geoip` feature). All that is missing are the two `.mmdb`
files; drop them in place and `graph_summary` flips to
`geoip:true, asn:true`.

Credentials come from the environment, never the command line, so the
license key does not land in shell history:

    setx MAXMIND_ACCOUNT_ID  1234567
    setx MAXMIND_LICENSE_KEY xxxxxxxxxxxx
    # open a NEW terminal, then:
    python training/fetch_geolite2.py

Get both at https://www.maxmind.com/en/accounts/current/license-key
(free account: https://www.maxmind.com/en/geolite2/signup).

MaxMind has moved these downloads to HTTP basic auth with the account id;
the older `?license_key=` permalink still answers for many accounts, so
this tries basic auth first and falls back.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

DEST = Path(__file__).resolve().parent.parent / "apps/tauri/src-tauri/resources/geoip"
EDITIONS = ["GeoLite2-City", "GeoLite2-ASN"]

BASIC_URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
LEGACY_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id={edition}&license_key={key}&suffix=tar.gz"
)


def fetch(edition: str, account_id: str | None, key: str) -> bytes:
    """Returns the .tar.gz bytes for one edition."""
    attempts: list[tuple[str, urllib.request.Request]] = []

    if account_id:
        req = urllib.request.Request(BASIC_URL.format(edition=edition))
        import base64

        token = base64.b64encode(f"{account_id}:{key}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
        attempts.append(("basic auth", req))

    attempts.append(
        ("license_key permalink", urllib.request.Request(LEGACY_URL.format(edition=edition, key=key)))
    )

    last: Exception | None = None
    for label, req in attempts:
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                print(f"  {edition}: {label} OK")
                return r.read()
        except urllib.error.HTTPError as e:
            print(f"  {edition}: {label} failed ({e.code} {e.reason})")
            last = e
        except Exception as e:  # network, TLS, ...
            print(f"  {edition}: {label} failed ({type(e).__name__}: {e})")
            last = e
    raise SystemExit(f"could not download {edition}: {last}")


def extract_mmdb(blob: bytes, edition: str, dest: Path) -> Path:
    """Pulls the single .mmdb out of the dated folder inside the archive."""
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        member = next((m for m in tar.getmembers() if m.name.endswith(".mmdb")), None)
        if member is None:
            raise SystemExit(f"{edition}: archive contained no .mmdb")
        src = tar.extractfile(member)
        if src is None:
            raise SystemExit(f"{edition}: could not read {member.name}")
        out = dest / f"{edition}.mmdb"
        out.write_bytes(src.read())
        return out


def main() -> int:
    key = os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    account_id = os.environ.get("MAXMIND_ACCOUNT_ID", "").strip() or None
    if not key:
        print(__doc__)
        print("ERROR: MAXMIND_LICENSE_KEY is not set.")
        return 1

    DEST.mkdir(parents=True, exist_ok=True)
    print(f"destination: {DEST}")
    for edition in EDITIONS:
        blob = fetch(edition, account_id, key)
        out = extract_mmdb(blob, edition, DEST)
        print(f"  wrote {out.name}: {out.stat().st_size:,} bytes")

    print(
        "\nDone. Restart GraphHunter and check graph_summary — capabilities "
        "should now report geoip:true, asn:true."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
