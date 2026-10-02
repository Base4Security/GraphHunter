# GeoIP databases (GeoLite2)

Drop `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` in this directory before
building the installer. Everything in `resources/geoip/*` is bundled next to
the executable and picked up automatically at startup — see
`GraphHunterApi::bootstrap_geoip`.

Without them, country/ASN enrichment is disabled: `graph_summary` reports
`geoip:false, asn:false`, `enrich_ip` fails, and any analysis that depends on
geography or hosting-provider attribution silently cannot run. A real hunt
(AD-CAP, 2026-08-12) lost its entire intel-driven dimension to exactly this.

## Where the loader looks, in order

1. `GRAPHHUNTER_GEOIP_DIR` — explicit override, wins over everything
2. `<exe_dir>/resources/geoip` — this directory, once bundled
3. `<data_dir>/GraphHunter/geoip` — user drop-in, no rebuild needed

First directory containing at least one readable `.mmdb` wins. Either file may
be missing: with only the ASN database you get ASN/org but no country/city, and
vice versa.

## Obtaining the files

GeoLite2 requires a free MaxMind account and a license key (mandatory since
December 2019):

1. Create an account at <https://www.maxmind.com/en/geolite2/signup>
2. Generate a license key in *My Account → Manage License Keys*
3. Download the **GeoLite2 City** and **GeoLite2 ASN** databases in `.mmdb`
   format (the `tar.gz` bundles contain the `.mmdb` inside a dated folder)
4. Copy the two `.mmdb` files here

## Before redistributing

These files are **not** committed to the repository — `.gitignore` excludes
them, deliberately. They are ~70 MB of third-party data under the GeoLite2 End
User License Agreement, which places conditions on redistribution, including
keeping copies current as new releases ship. MaxMind publishes updates weekly,
so a database frozen inside an installer goes stale quickly and its accuracy
degrades.

Confirm the current EULA terms before shipping an installer that includes them,
and prefer the user drop-in path (option 3 above) for public builds.

## The network fallback, and why it is off

`GRAPHHUNTER_GEOIP_HTTP=1` enables an ip-api.com fallback that needs no local
database. It is opt-in and should stay that way for investigative work: the
free tier is **plaintext HTTP**, so every lookup discloses the IP being
investigated to a third party in the clear. During an incident that leaks case
data and can tip off an adversary watching their own infrastructure. Offline
databases have neither problem — which is also what keeps GraphHunter usable
air-gapped.
