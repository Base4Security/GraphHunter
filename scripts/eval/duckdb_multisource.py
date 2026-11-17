"""DuckDB baseline for the multi-source question: an address an account
signed in from (idp.csv) that an internal host also talks to (firewall.csv,
Sysmon), and what resolved to it. Usage: duckdb_multisource.py <dir> <sysmon.jsonl>"""
import duckdb, sys, time

d, sysmon = sys.argv[1], sys.argv[2]
con = duckdb.connect()
t = time.time()
con.execute("create table ev as select * from read_json_auto(?)", [sysmon])
con.execute(f"create table fw as select * from read_csv_auto('{d}/firewall.csv')")
con.execute(f"create table idp as select * from read_csv_auto('{d}/idp.csv')")
print("load secs", round(time.time() - t, 2))

t = time.time()
rows = con.execute("""
with internal_talkers as (
    select dst_ip as ip, src_ip as talker, 'firewall' as source from fw
    union all
    select DestinationIp, Computer, 'sysmon' from ev where EventID = 3
),
resolved as (
    select QueryName as name, trim(unnest(string_split(QueryResults, ';'))) as ip
    from ev where EventID = 22
)
select i.username, i.source_ip,
       list(distinct t.talker || ' (' || t.source || ')') as talkers,
       (select list(distinct name) from resolved r where r.ip = i.source_ip) as resolved_from
from idp i join internal_talkers t on t.ip = i.source_ip
group by all
""").fetchall()
print(f"query {time.time()-t:.2f}s, {len(rows)} rows")
for r in rows:
    print("  ", r)
