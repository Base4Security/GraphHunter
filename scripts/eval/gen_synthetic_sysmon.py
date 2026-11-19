"""Synthetic Sysmon-like JSONL: benign noise on many hosts plus one planted
intrusion. All values are made up (documentation IP ranges, example domains)."""
import json, random, sys, datetime

n_events = int(sys.argv[1])
out = sys.argv[2]
random.seed(7)
BS = chr(92)
HOSTS = [f"WS-{i:03d}" for i in range(1, 201)] + [f"SRV-{i:02d}" for i in range(1, 21)]
USERS = [f"CORP{BS}user{i:03d}" for i in range(1, 181)]
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
T0 = datetime.datetime(2024, 6, 15, 0, 0, 0)
SPAN = 24 * 3600


def ts(sec):
    return (T0 + datetime.timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S.000")


def ip_of(host):
    i = HOSTS.index(host)
    return f"10.{20 + i // 250}.{i % 250}.10"


def dst_ip(domain):
    h = abs(hash(domain)) % 250 + 1
    return f"198.51.100.{h}"


events = []



_seq = [0]
_lived = {}


def inst(host, image):
    """A new process instance: what Sysmon identifies with ProcessGuid."""
    _seq[0] += 1
    return {"host": host, "image": image, "guid": "{%08x-0000-4000-8000-%012x}" % (HOSTS.index(host), _seq[0]),
            "pid": random.randint(1000, 60000)}


def lived(host, image):
    """Long-running process (explorer, services): one instance per host."""
    key = (host, image)
    if key not in _lived:
        _lived[key] = inst(host, image)
    return _lived[key]


def own(p):
    return {"Image": p["image"], "ProcessGuid": p["guid"], "ProcessId": p["pid"], "Computer": p["host"]}


def proc(sec, host, user, image, parent, cmd=None):
    """Process create. `parent` is an instance, or an image name for a
    long-lived parent on the same host. Returns the new instance."""
    if isinstance(parent, str):
        parent = lived(host, parent)
    p = inst(host, image)
    events.append((sec, {"EventID": 1, "UtcTime": ts(sec), **own(p), "User": user,
                         "CommandLine": cmd or image.split(BS)[-1], "ParentImage": parent["image"],
                         "ParentProcessGuid": parent["guid"], "ParentProcessId": parent["pid"]}))
    return p


def dns(sec, p, name, result):
    events.append((sec, {"EventID": 22, "UtcTime": ts(sec), **own(p), "QueryName": name,
                         "QueryResults": result, "QueryType": "A"}))


def conn(sec, p, dip, dport, dhost=None):
    e = {"EventID": 3, "UtcTime": ts(sec), **own(p), "SourceIp": ip_of(p["host"]),
         "SourcePort": str(random.randint(49152, 65535)), "DestinationIp": dip, "DestinationPort": str(dport),
         "Protocol": "tcp"}
    if dhost:
        e["DestinationHostname"] = dhost
    events.append((sec, e))


def fwrite(sec, p, path):
    events.append((sec, {"EventID": 11, "UtcTime": ts(sec), **own(p), "TargetFilename": path}))


# Benign noise. Includes admins legitimately running powershell/cmd/net, and
# Outlook/Chrome doing DNS, so the planted chain is not trivially unique.
# Users are not tied to hosts: any host sees many users, which is the hard
# case for attribution (shared servers, jump hosts).
while len(events) < n_events:
    sec = random.randint(0, SPAN - 600)
    host = random.choice(HOSTS)
    user = random.choice(USERS)
    r = random.random()
    if r < 0.45:
        app = random.choice(["chrome", "outlook", "teams"])
        p = proc(sec, host, user, APPS[app], APPS["explorer"])
        for k in range(random.randint(1, 4)):
            d = random.choice(DOMAINS)
            dns(sec + 5 + k, p, d, dst_ip(d))
            conn(sec + 6 + k, p, dst_ip(d), 443)
    elif r < 0.75:
        p = proc(sec, host, f"NT AUTHORITY{BS}SYSTEM", APPS["svchost"], APPS["services"])
        d = random.choice(DOMAINS[:40])
        dns(sec + 3, p, d, dst_ip(d))
        conn(sec + 4, p, dst_ip(d), 443)
    elif r < 0.90:
        p = proc(sec, host, user, APPS["powershell"], APPS["explorer"], "powershell.exe -File inventory.ps1")
        proc(sec + 2, host, user, APPS["cmd"], p, "cmd.exe /c ipconfig")
        d = random.choice(DOMAINS[:60])
        dns(sec + 4, p, d, dst_ip(d))
        fwrite(sec + 5, p, f"C:{BS}Temp{BS}inv-{random.randint(1, 500)}.log")
    else:
        srv = random.choice(HOSTS[200:])
        p = proc(sec, host, user, APPS["net"], APPS["cmd"], f"net use {BS}{BS}{srv}{BS}share")
        conn(sec + 1, p, ip_of(srv), 445, srv)

# Planted intrusion: WS-042 (phish) -> SRV-07 (lateral) -> C2.
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
conn(s + 780, psexec, ip_of(DC), 445, DC)
# On the target the parent is the PsExec service, a different process.
dropper = proc(s + 900, DC, ADM, tmp + "dropper.exe", f"C:{BS}Windows{BS}PSEXESVC.exe", "dropper.exe --install --silent")
beacon = proc(s + 1080, DC, ADM, tmp + "beacon.exe", dropper, "beacon.exe -interval 30")
dns(s + 1200, beacon, "c2.badactor.example", "203.0.113.42")
dns(s + 1620, ps, "callback.badactor.example", "203.0.113.88")
fwrite(s + 1800, beacon, tmp + "exfil-staging.zip")
conn(s + 1920, beacon, "203.0.113.42", 443, "c2.badactor.example")

events.sort(key=lambda x: x[0])
with open(out, "w", encoding="utf-8") as f:
    for _, e in events:
        f.write(json.dumps(e) + "\n")
print(len(events), "events ->", out)
