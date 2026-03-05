# Real-World Security Datasets

The included demo files (`apt_attack_simulation.json`, `sentinel_attack_simulation.json`, `generic_csv_logs.csv`) are small synthetic datasets for quick testing.

For large-scale testing with real attack telemetry, download from these public sources:

## OTRF / Mordor Datasets (JSON NDJSON)

Pre-recorded Windows Sysmon + Security events from adversary simulations. Works with **Auto-detect** or **Generic JSON** format.

```bash
# Download and combine multiple attack datasets (~28K events, ~132MB)
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_backupkeys_dcerpc_smb_lsarpc.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip

# Extract all
unzip "*.zip"

# Combine into single NDJSON file
cat *.json > mordor_combined_attacks.json
```

### Additional OTRF datasets

```bash
# Mimikatz SAM access (12K events)
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access.zip

# LSASS dump via Task Manager (5K events)
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip

# PowerView LDAP enumeration (9K events)
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_powerview_ldap_ntsecuritydescriptor.zip

# PSRemoting stager (2.7K events)
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager.zip
```

## Mega Dataset (~2.8GB, ~963K events)

One-liner to download all datasets above and combine them into a single file for stress testing:

```bash
cd demo_data

# 1. Download all archives
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_backupkeys_dcerpc_smb_lsarpc.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/defense_evasion/host/empire_powerview_ldap_ntsecuritydescriptor.zip
curl -LO https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager.zip
curl -L -o apt29_day1.zip https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip
curl -L -o apt29_day2.zip https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day2/apt29_evals_day2_manual.zip

# 2. Extract all
unzip -o "*.zip"
# APT29 zips extract into subdirs
unzip -o apt29_day1.zip -d .
unzip -o apt29_day2.zip -d .

# 3. Combine into single NDJSON file
cat *.json > mega_dataset_1gb.json

# 4. Clean up archives
rm -f *.zip

echo "Done! mega_dataset_1gb.json ready (~2.8GB, ~963K events)"
```

Load in Graph Hunter with **Auto-detect** format. Ingestion takes ~20 seconds.

---

## Splunk attack_data (XML, needs conversion)

Sysmon logs in XML format from MITRE ATT&CK technique simulations. Requires conversion to JSON.

```bash
# Clop ransomware - full infection chain (47K events, 76MB XML)
curl -LO https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log

# Cobalt Strike process injection (7.6K events)
curl -LO https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon_dllhost.log

# Credential dumping T1003 (8K events)
curl -LO https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log
```

Convert XML to JSON with Node.js:

```javascript
// xml_to_json.js - Convert Splunk Sysmon XML to NDJSON
const fs = require('fs');
const lines = fs.readFileSync(process.argv[2], 'utf8').split('\n').filter(l => l.trim());
const results = [];
for (const line of lines) {
  const obj = {};
  const eid = line.match(/<EventID>(\d+)<\/EventID>/);
  if (eid) obj.EventID = parseInt(eid[1]);
  const comp = line.match(/<Computer>([^<]+)<\/Computer>/);
  if (comp) obj.Hostname = comp[1];
  const time = line.match(/SystemTime='([^']+)'/);
  if (time) obj.TimeCreated = time[1];
  const dataRe = /<Data Name='([^']+)'>([^<]*)<\/Data>/g;
  let m;
  while ((m = dataRe.exec(line)) !== null) obj[m[1]] = m[2];
  if (Object.keys(obj).length > 2) results.push(JSON.stringify(obj));
}
fs.writeFileSync(process.argv[3], results.join('\n') + '\n');
console.log(`Converted ${results.length} events`);
```

```bash
node xml_to_json.js windows-sysmon.log clop_converted.json
```

## Testing tips

- **Auto-detect** handles both OTRF JSON and converted Splunk JSON
- Start with Explorer Mode and search for known IOCs: `mimikatz`, `lsass.exe`, `psexec`, `pgustavo`
- For hunts, use specific patterns to avoid combinatorial explosion on large datasets
