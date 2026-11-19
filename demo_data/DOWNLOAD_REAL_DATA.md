# Real-world corpus for the pruning ablation

The EJS paper's ablation ("Mordor Combined") runs on five OTRF
Security-Datasets captures concatenated into one NDJSON file. The file is
132 MB, so it is not committed (`.gitignore` excludes it); this page
rebuilds it byte for byte.

## Build it

```bash
cd demo_data
B=https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows
curl -LO $B/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip
curl -LO $B/execution/host/empire_launcher_vbs.zip
curl -LO $B/credential_access/host/empire_mimikatz_backupkeys_dcerpc_smb_lsarpc.zip
curl -LO $B/credential_access/host/empire_mimikatz_logonpasswords.zip
curl -LO $B/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip

for z in empire_*.zip; do unzip -o "$z"; done

# The order matters for the hash below: alphabetical by dataset name.
cat empire_dcsync_dcerpc_drsuapi_DsGetNCChanges_*.json \
    empire_launcher_vbs_*.json \
    empire_mimikatz_backupkeys_dcerpc_smb_lsarpc_*.json \
    empire_mimikatz_logonpasswords_*.json \
    empire_psexec_dcerpc_tcp_svcctl_*.json > mordor_combined_attacks.json
rm -f empire_*.zip empire_*.json
```

## Check it

| | Value |
|---|---|
| Events (lines) | 28,793 |
| Size | 138,038,083 bytes |
| SHA-256 | `3499200527f0d355805d9bde7b66a8df4482402d4b3d46ec8dfd9ffbae93cc43` |

The archives as downloaded on 2026-11-18:

| Archive | SHA-256 |
|---|---|
| `empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip` | `fe1fcc96c0ff0cbae8fd4ffaadf85f51e28475441774f6fda3d963d4e2962800` |
| `empire_launcher_vbs.zip` | `812da270cf8cda6f1948fb6275410f15dc1794d0bd6b623c9c25b2518285019c` |
| `empire_mimikatz_backupkeys_dcerpc_smb_lsarpc.zip` | `63ee26d89071b9026a2381c31cd9d5842435e3859e1c0d84825cdbb01475e4d8` |
| `empire_mimikatz_logonpasswords.zip` | `bb4c057b62d781be5426e011872ba1a15070c07afbb24848a14458f4b22b06fb` |
| `empire_psexec_dcerpc_tcp_svcctl.zip` | `8f40e7fc86bbbf31ebd50b3ba537cf0f4378392ae3e74de84bee00aeb0de1fa5` |

If OTRF republishes a capture the hash will change, and so will the graph.

## Run the ablation

```bash
cargo build --release --manifest-path apps/cli/Cargo.toml
apps/cli/target/release/graph_hunter_cli bench --ablation --runs 31 \
    --mordor demo_data/mordor_combined_attacks.json
```

It prints one CSV row per dataset and hypothesis length: graph size,
matches, nodes visited with and without pruning, median times, the
complete engine's time, and the share each pruning rule rejects. The
naive baseline only runs on graphs up to `--naive-max-relations` edges
(default 1,000); on this corpus it did not finish even L = 2 after 20
minutes (2026-11-18, Ryzen 5 PRO 5650U), which the paper reports as a bound
rather than a ratio. To see that for yourself:

```bash
timeout 1800 apps/cli/target/release/graph_hunter_cli bench --ablation \
    --runs 1 --lengths 2 --naive-max-relations 1000000 \
    --mordor demo_data/mordor_combined_attacks.json
```

Load the file through the binaries, not through `cargo test`: the
engine's test build enables `serde_json/preserve_order`, which changes
the field order the generic parser sees and with it the graph (970
vertices in the binaries, 980 under `cargo test`).
