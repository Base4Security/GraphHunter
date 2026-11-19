"""DuckDB answer to the gen_hard.py question, scored against truth.json.
Usage: duckdb_hard.py <dir>   (pip install duckdb)

Same question as score_hard.py: an account that signed in from an address an
internal host also talks to, and which host, domain and process. The host is
found from the address it held *at the time of the flow* (an ASOF join on
Sysmon's own outbound connections), which is what address reuse demands."""
import duckdb, json, sys, time

d = sys.argv[1]
truth = json.load(open(f"{d}/truth.json", encoding="utf-8"))
con = duckdb.connect()
# The firewall's `...Z` stamps load as TIMESTAMPTZ, Sysmon's UtcTime as a
# zone-less TIMESTAMP. Comparing them goes through the session time zone,
# so on a machine not set to UTC the ASOF join silently looks up the
# address holder hours off, and blames the wrong host.
con.execute("set TimeZone = 'UTC'")
t = time.time()
con.execute(f"create table ev as select * from read_json_auto('{d}/sysmon.jsonl')")
con.execute(f"create table fw as select * from read_csv_auto('{d}/firewall.csv')")
con.execute(f"create table idp as select * from read_csv_auto('{d}/idp.csv')")
print(f"load {time.time() - t:.2f}s")

t = time.time()
rows = con.execute("""
with lease as (   -- who held which address, observed from the host itself
    select SourceIp as ip, lower(Computer) as host, UtcTime as seen
    from ev where EventID = 3 and Initiated = 'true'
),
flows as (
    select f.src_ip, f.dst_ip, f.timestamp::timestamp as ts, f.bytes_out, l.host
    from fw f asof left join lease l on l.ip = f.src_ip and l.seen <= f.timestamp::timestamp
),
dns as (
    select QueryName as domain, QueryResults as ip, lower(Computer) as host, ProcessGuid, Image
    from ev where EventID = 22
)
select i.username, i.source_ip, f.src_ip, f.host, f.bytes_out, d.domain, d.Image, d.ProcessGuid
from idp i
join flows f on f.dst_ip = i.source_ip
join dns d on d.ip = i.source_ip and d.host = f.host
group by all
order by f.bytes_out desc
""").fetchall()
print(f"query {time.time() - t:.2f}s, {len(rows)} rows")

a = truth["answer"]
hit = [r for r in rows if r[0] == a["user"] and r[1] == a["ip"] and r[3] == a["host"]
       and r[5] == a["domain"] and r[7] == a["process_guid"]]
blamed = sorted({r[3] for r in rows if r[1] == a["ip"] and r[3] != a["host"]})
print(f"{'ok  ' if hit else 'FAIL'} contains the answer")
print(f"{'ok  ' if not blamed else 'FAIL'} C2 traffic not blamed on another host {blamed or ''}")
rank = next((i + 1 for i, r in enumerate(rows) if r in hit), None)
print(f"rank answer position by bytes out: {rank} of {len(rows)}")
for r in rows[:3]:
    print("  ", r)
