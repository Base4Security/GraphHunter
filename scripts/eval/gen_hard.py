"""The three-source scenario with the traps a real network has, plus the
truth to score against. Writes sysmon.jsonl, firewall.csv, idp.csv and
truth.json to <dir>. Usage: gen_hard.py <dir> [n_sysmon]

gen_synthetic_sysmon.py + gen_multisource.py plant one needle in noise that
never overlaps it, so any pattern that finds the needle "works". Here the
same intrusion (WS-042 -> SRV-07 -> c2.badactor.example) sits among:

  - a partner office (203.0.113.7): accounts sign in from it and internal
    hosts browse its portal, so the cross-source pattern has benign matches
    and the intrusion must win on ranking, not on being the only result;
  - inbound connections (RDP into servers from the VPN pool): Sysmon logs
    them with Initiated=false and the *client* as SourceIp, so a rule that
    reads SourceIp as the host's own address invents addresses;
  - address reuse: 10.20.206.10 belongs to WS-150 until 12:00 and to SRV-07
    after, and some workstations renew DHCP leases mid-day, so a host-to-
    address join that ignores time blames the wrong machine;
  - the first stage runs in powershell.exe, an image every host runs.

Everything is deterministic (seeded, no hash()) and synthetic: documentation
address ranges and example domains only.
"""
import csv, datetime, json, random, sys, zlib

out_dir = sys.argv[1]
n_events = int(sys.argv[2]) if len(sys.argv) > 2 else 60000
random.seed(23)
BS = chr(92)
HOSTS = [f"WS-{i:03d}" for i in range(1, 201)] + [f"SRV-{i:02d}" for i in range(1, 21)]
WS, SRV = HOSTS[:200], HOSTS[200:]
USERS = [f"user{i:03d}" for i in range(1, 181)]
SYS32 = f"C:{BS}Windows{BS}System32{BS}"
APPS = {
    "chrome": f"C:{BS}Program Files{BS}Google{BS}Chrome{BS}Application{BS}chrome.exe",
    "outlook": f"C:{BS}Program Files{BS}Microsoft Office{BS}Office16{BS}OUTLOOK.EXE",
    "teams": f"C:{BS}Program Files{BS}Teams{BS}teams.exe",
    "explorer": f"C:{BS}Windows{BS}explorer.exe",
    "svchost": SYS32 + "svchost.exe",
    "services": SYS32 + "services.exe",
    "powershell": SYS32 + f"WindowsPowerShell{BS}v1.0{BS}powershell.exe",
    "cmd": SYS32 + "cmd.exe",
    "net": SYS32 + "net.exe",
}
DOMAINS = [f"app{i}.example.com" for i in range(400)] + [f"cdn{i}.example.net" for i in range(100)]
PARTNER_IP, PARTNER_DOMAIN = "203.0.113.7", "portal.partner.example"
C2_IP, C2_DOMAIN = "203.0.113.42", "c2.badactor.example"
CB_IP, CB_DOMAIN = "203.0.113.88", "callback.badactor.example"
T0 = datetime.datetime(2024, 6, 15)
SPAN, NOON = 24 * 3600, 12 * 3600


def ts(sec):
    return (T0 + datetime.timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S.000")


def iso(sec):
    return (T0 + datetime.timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def base_ip(host):
    i = HOSTS.index(host)
    return f"10.{20 + i // 250}.{i % 250}.10"


# Mid-day DHCP renewals: (host -> (renewal second, new address)).
RENEW = {h: (random.randint(8 * 3600, 18 * 3600), f"10.21.{n}.{random.randint(20, 240)}")
         for n, h in enumerate(random.sample([h for h in WS if h != "WS-150" and h != "WS-042"], 20))}


def ip_at(host, sec):
    """The address `host` holds at `sec`. 10.20.206.10 is SRV-07's from noon
    on and WS-150's before; SRV-07 sat on 10.20.249.10 until then."""
    if host == "WS-150":
        return "10.20.206.10" if sec < NOON else "10.20.149.10"
    if host == "SRV-07" and sec < NOON:
        return "10.20.249.10"
    if host in RENEW and sec >= RENEW[host][0]:
        return RENEW[host][1]
    return base_ip(host)


def dst_ip(domain):
    return f"198.51.100.{zlib.crc32(domain.encode()) % 250 + 1}"


def vpn_ip(user):
    return f"192.0.2.{int(user[4:]) % 200 + 20}"


sysmon, fw, idp = [], [], []
_seq = [0]
_lived = {}


def inst(host, image):
    _seq[0] += 1
    return {"host": host, "image": image, "pid": random.randint(1000, 60000),
            "guid": "{%08x-0000-4000-8000-%012x}" % (HOSTS.index(host), _seq[0])}


def lived(host, image):
    if (host, image) not in _lived:
        _lived[(host, image)] = inst(host, image)
    return _lived[(host, image)]


def own(p):
    return {"Image": p["image"], "ProcessGuid": p["guid"], "ProcessId": p["pid"], "Computer": p["host"]}


def proc(sec, host, user, image, parent, cmd=None):
    if isinstance(parent, str):
        parent = lived(host, parent)
    p = inst(host, image)
    sysmon.append((sec, {"EventID": 1, "UtcTime": ts(sec), **own(p), "User": user,
                         "CommandLine": cmd or image.split(BS)[-1], "ParentImage": parent["image"],
                         "ParentProcessGuid": parent["guid"], "ParentProcessId": parent["pid"]}))
    return p


def dns(sec, p, name, result):
    sysmon.append((sec, {"EventID": 22, "UtcTime": ts(sec), **own(p), "QueryName": name,
                         "QueryResults": result, "QueryType": "A"}))


def conn(sec, p, dip, dport, dhost=None, nbytes=None):
    """Outbound connection, seen by Sysmon and, when it leaves the network,
    by the perimeter firewall too."""
    sip = ip_at(p["host"], sec)
    e = {"EventID": 3, "UtcTime": ts(sec), **own(p), "Initiated": "true", "SourceIp": sip,
         "SourcePort": str(random.randint(49152, 65535)), "DestinationIp": dip,
         "DestinationPort": str(dport), "Protocol": "tcp"}
    if dhost:
        e["DestinationHostname"] = dhost
    sysmon.append((sec, e))
    if not dip.startswith("10."):
        fw.append((sec, [iso(sec), sip, dip, dport, "tcp", "allow", nbytes or random.randint(800, 90000)]))


def inbound(sec, host, client, dport):
    """An accepted connection: Sysmon puts the remote client in SourceIp."""
    p = lived(host, APPS["svchost"])
    sysmon.append((sec, {"EventID": 3, "UtcTime": ts(sec), **own(p), "Initiated": "false",
                         "SourceIp": client, "SourcePort": str(random.randint(49152, 65535)),
                         "DestinationIp": ip_at(host, sec), "DestinationPort": str(dport),
                         "Protocol": "tcp"}))


def fwrite(sec, p, path):
    sysmon.append((sec, {"EventID": 11, "UtcTime": ts(sec), **own(p), "TargetFilename": path}))


def signin(sec, user, ip, app="vpn"):
    idp.append((sec, [iso(sec), f"{user}@corp.example", ip, "success", app]))


# ── Benign activity ────────────────────────────────────────────────────
partner_staff = USERS[150:165]
while len(sysmon) < n_events:
    sec = random.randint(0, SPAN - 600)
    host, user = random.choice(HOSTS), random.choice(USERS)
    acct = f"CORP{BS}{user}"
    r = random.random()
    if r < 0.40:
        app = random.choice(["chrome", "outlook", "teams"])
        p = proc(sec, host, acct, APPS[app], APPS["explorer"])
        for k in range(random.randint(1, 4)):
            d = random.choice(DOMAINS)
            dns(sec + 5 + k, p, d, dst_ip(d))
            conn(sec + 6 + k, p, dst_ip(d), 443)
    elif r < 0.45:
        # The partner portal: routine, from many hosts.
        p = proc(sec, host, acct, APPS["chrome"], APPS["explorer"])
        dns(sec + 4, p, PARTNER_DOMAIN, PARTNER_IP)
        conn(sec + 5, p, PARTNER_IP, 443, PARTNER_DOMAIN)
    elif r < 0.70:
        p = proc(sec, host, f"NT AUTHORITY{BS}SYSTEM", APPS["svchost"], APPS["services"])
        d = random.choice(DOMAINS[:40])
        dns(sec + 3, p, d, dst_ip(d))
        conn(sec + 4, p, dst_ip(d), 443)
    elif r < 0.85:
        p = proc(sec, host, acct, APPS["powershell"], APPS["explorer"], "powershell.exe -File inventory.ps1")
        proc(sec + 2, host, acct, APPS["cmd"], p, "cmd.exe /c ipconfig")
        d = random.choice(DOMAINS[:60])
        dns(sec + 4, p, d, dst_ip(d))
        fwrite(sec + 5, p, f"C:{BS}Temp{BS}inv-{random.randint(1, 500)}.log")
    elif r < 0.93:
        srv = random.choice(SRV)
        p = proc(sec, host, acct, APPS["net"], APPS["cmd"], f"net use {BS}{BS}{srv}{BS}share")
        conn(sec + 1, p, ip_at(srv, sec + 1), 445, srv)
    else:
        # Remote desktop into a server from a VPN client.
        inbound(sec, random.choice(SRV), vpn_ip(user), 3389)

# Plain perimeter traffic with no endpoint counterpart (unmanaged devices,
# hosts without Sysmon), so the firewall is not a strict subset.
for _ in range(n_events // 6):
    sec = random.randint(0, SPAN - 1)
    fw.append((sec, [iso(sec), f"10.30.{random.randint(0, 40)}.{random.randint(2, 250)}",
                     dst_ip(random.choice(DOMAINS)), 443, "tcp", "allow", random.randint(800, 90000)]))

for _ in range(n_events // 8):
    sec, user = random.randint(0, SPAN - 1), random.choice(USERS)
    signin(sec, user, PARTNER_IP if user in partner_staff and random.random() < 0.6 else vpn_ip(user))
for sec in (3 * 3600, 9 * 3600, 20 * 3600):
    signin(sec, "svc-backup", "192.0.2.10", "backup-console")

# ── Planted intrusion ──────────────────────────────────────────────────
V, DC = "WS-042", "SRV-07"
U, ADM = f"CORP{BS}user042", f"CORP{BS}svc-backup"
s = 14 * 3600
dl = f"C:{BS}Users{BS}user042{BS}Downloads{BS}"
tmp = f"C:{BS}Windows{BS}Temp{BS}"
outlook = proc(s - 1800, V, U, APPS["outlook"], APPS["explorer"])
ps = proc(s, V, U, APPS["powershell"], outlook, "powershell.exe -ep bypass -nop -w hidden -enc SQBFAFgA")
proc(s + 120, V, U, APPS["cmd"], ps, "cmd.exe /c whoami /all && net user /domain")
cred = proc(s + 480, V, U, dl + "credtool.exe", ps, "credtool.exe sekurlsa::logonpasswords")
fwrite(s + 540, cred, f"C:{BS}Users{BS}user042{BS}AppData{BS}Local{BS}Temp{BS}creds-dump.txt")
psexec = proc(s + 720, V, ADM, dl + "PsExec64.exe", ps, f"PsExec64.exe {BS}{BS}{DC} -u svc-backup cmd.exe")
conn(s + 780, psexec, ip_at(DC, s + 780), 445, DC)
psexesvc = inst(DC, f"C:{BS}Windows{BS}PSEXESVC.exe")
dropper = proc(s + 900, DC, ADM, tmp + "dropper.exe", psexesvc, "dropper.exe --install --silent")
beacon = proc(s + 1080, DC, ADM, tmp + "beacon.exe", dropper, "beacon.exe -interval 30")
dns(s + 1200, beacon, C2_DOMAIN, C2_IP)
dns(s + 1620, ps, CB_DOMAIN, CB_IP)
conn(s + 1650, ps, CB_IP, 443, CB_DOMAIN, 52_000)
fwrite(s + 1800, beacon, tmp + "exfil-staging.zip")
conn(s + 1920, beacon, C2_IP, 443, C2_DOMAIN, 480_000_000)
signin(s - 600, "svc-backup", C2_IP)

# ── Write ──────────────────────────────────────────────────────────────
for rows in (sysmon, fw, idp):
    rows.sort(key=lambda r: r[0])
with open(f"{out_dir}/sysmon.jsonl", "w", encoding="utf-8") as f:
    for _, e in sysmon:
        f.write(json.dumps(e) + "\n")
with open(f"{out_dir}/firewall.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_out"])
    w.writerows(r for _, r in fw)
with open(f"{out_dir}/idp.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "username", "source_ip", "result", "application"])
    w.writerows(r for _, r in idp)

truth = {
    # Every entity of the intrusion. An id matches when it contains one of
    # these (case-insensitive): process ids carry host, guid and image.
    "intrusion": [
        ps["guid"], cred["guid"], psexec["guid"], psexesvc["guid"], dropper["guid"], beacon["guid"],
        "creds-dump.txt", "exfil-staging.zip", C2_DOMAIN, CB_DOMAIN, C2_IP, CB_IP,
    ],
    # The cross-source question: an account that signed in from an address
    # an internal host also talks to; who, from where, which host, which
    # domain and which process.
    "answer": {"user": "svc-backup@corp.example", "ip": C2_IP, "host": "srv-07",
               "host_ip": "10.20.206.10", "domain": C2_DOMAIN, "process_guid": beacon["guid"]},
    # Benign matches of the same pattern: the partner office.
    "decoy_ip": PARTNER_IP,
    # 10.20.206.10 before noon was WS-150; the exfiltration was at 14:32.
    "reused_ip": {"ip": "10.20.206.10", "wrong_host": "ws-150", "event_time": iso(s + 1920)},
    # No host ever holds a VPN-pool address: those are RDP clients.
    "never_host_address_prefix": "192.0.2.",
}
with open(f"{out_dir}/truth.json", "w", encoding="utf-8") as f:
    json.dump(truth, f, indent=2)
print(f"sysmon {len(sysmon)}, firewall {len(fw)}, idp {len(idp)} rows; truth.json -> {out_dir}")
