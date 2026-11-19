"""Two extra sources that see the same planted intrusion as
gen_synthetic_sysmon.py, with their own field names and identity formats:

  firewall.csv  - perimeter flows by IP only (no hostnames, no users)
  idp.csv       - identity-provider sign-ins, users as user@domain

The point is to test stitching: the C2 address 203.0.113.42 is a DNS answer
and a connection target in Sysmon, a destination in the firewall, and the
origin of a sign-in in the IdP. All values are synthetic.

Truth:
  - SRV-07 (10.20.206.10) sends ~480 MB to 203.0.113.42:443 at 14:32 (firewall)
  - svc-backup signs in from 203.0.113.42 at 13:50 (IdP); every other
    sign-in of that account comes from 192.0.2.10
"""
import csv, datetime, random, sys

out_dir = sys.argv[1]
n_fw = int(sys.argv[2]) if len(sys.argv) > 2 else 40000
n_idp = int(sys.argv[3]) if len(sys.argv) > 3 else 8000
random.seed(11)
T0 = datetime.datetime(2024, 6, 15, 0, 0, 0)


def iso(sec):
    return (T0 + datetime.timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def host_ip(i):  # same scheme as gen_synthetic_sysmon.ip_of
    return f"10.{20 + i // 250}.{i % 250}.10"


rows = []
for _ in range(n_fw):
    sec = random.randint(0, 86399)
    rows.append((sec, [iso(sec), host_ip(random.randrange(220)), f"198.51.100.{random.randint(1, 250)}",
                       443, "tcp", "allow", random.randint(800, 90000)]))
s = 14 * 3600
rows.append((s + 1920, [iso(s + 1920), host_ip(206), "203.0.113.42", 443, "tcp", "allow", 480_000_000]))
rows.append((s + 1650, [iso(s + 1650), host_ip(41), "203.0.113.88", 443, "tcp", "allow", 52_000]))
rows.sort(key=lambda r: r[0])
with open(f"{out_dir}/firewall.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "action", "bytes_out"])
    w.writerows(r for _, r in rows)

rows = []
for _ in range(n_idp):
    sec = random.randint(0, 86399)
    u = random.randint(1, 180)
    rows.append((sec, [iso(sec), f"user{u:03d}@corp.example", f"192.0.2.{u % 200 + 20}", "success", "vpn"]))
for sec in (3 * 3600, 9 * 3600, 20 * 3600):
    rows.append((sec, [iso(sec), "svc-backup@corp.example", "192.0.2.10", "success", "backup-console"]))
rows.append((s - 600, [iso(s - 600), "svc-backup@corp.example", "203.0.113.42", "success", "vpn"]))
rows.sort(key=lambda r: r[0])
with open(f"{out_dir}/idp.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "username", "source_ip", "result", "application"])
    w.writerows(r for _, r in rows)
print("firewall.csv", n_fw + 2, "rows; idp.csv", n_idp + 4, "rows ->", out_dir)
