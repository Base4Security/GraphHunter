import duckdb, sys, time

con = duckdb.connect()
t = time.time()
con.execute("create table ev as select * from read_json_auto(?)", [sys.argv[1]])
con.execute("create macro base(p) as list_last(string_split(p, chr(92)))")
print("load secs", round(time.time() - t, 2), con.execute("select count(*) from ev").fetchone())


def run(title, q):
    t = time.time()
    rows = con.execute(q).fetchall()
    print(f"-- {title} ({time.time()-t:.2f}s, {len(rows)} rows)")
    for r in rows[:12]:
        print("  ", r)


# 1. Same question as the hunt: who ran a process, spawned from an Office app, that then did DNS?
run("office child doing DNS", """
select p.Computer, p."User", base(p.ParentImage) parent, base(p.Image) child, list(distinct d.QueryName) dns
from ev p join ev d on d.EventID=22 and d.Computer=p.Computer and d.Image=p.Image
                   and d.UtcTime between p.UtcTime and p.UtcTime + interval 1 hour
where p.EventID=1 and regexp_matches(p.ParentImage,'(?i)(outlook|winword|excel).exe$')
  and not regexp_matches(p.Image,'(?i)(outlook|winword|excel).exe$')
group by all""")

# 2. Rarity, the generic first move: images seen on very few hosts.
run("rare images", """
select base(Image) img, count(distinct Computer) hosts, count(*) n
from ev group by all having hosts <= 2 order by n""")

# 3. Process tree from the seed, host-scoped, following PsExec across hosts.
run("tree from office child", """
with recursive tree as (
  select Computer, Image, UtcTime, "User", CommandLine, 0 d from ev
  where EventID=1 and regexp_matches(ParentImage,'(?i)outlook.exe$') and regexp_matches(Image,'(?i)powershell')
  union all
  select c.Computer, c.Image, c.UtcTime, c."User", c.CommandLine, t.d+1
  from ev c join tree t on c.EventID=1 and c.ParentImage=t.Image
       and c.UtcTime between t.UtcTime and t.UtcTime + interval 2 hour
       and (c.Computer=t.Computer or regexp_matches(t.Image,'(?i)psexec')) and t.d<5
)
select distinct strftime(UtcTime,'%H:%M') ts, Computer, "User", d, CommandLine from tree order by ts""")
