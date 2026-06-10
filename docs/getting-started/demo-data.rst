************************
Demo data
************************

.. contents:: Table of Contents

Graph Hunter includes small synthetic datasets for quick testing. For large-scale testing with real attack telemetry, you can use public datasets and link them from here.

Included demo data
==================

Located in the ``demo_data/`` directory:

.. list-table::
   :header-rows: 1
   :widths: 30 12 58

   * - File
     - Format
     - Scenario
   * - ``apt_attack_simulation.json``
     - Sysmon
     - APT kill chain: spearphishing, discovery, Mimikatz, PsExec, C2, exfiltration
   * - ``sentinel_attack_simulation.json``
     - Sentinel
     - Cloud-to-on-prem: brute-force DC, Azure AD abuse, lateral movement, beacon, exfiltration
   * - ``generic_csv_logs.csv``
     - CSV
     - Firewall/proxy logs: normal traffic plus C2, SMB lateral, exfiltration attempts

Quick try
=========

1. Start the app: ``npm run tauri dev`` (from ``app/``).
2. Create or select a session.
3. Choose **Auto-detect**, then **Select Log File** and pick one of the files above.
4. In **Hunt Mode**, try e.g.:

   * ``User →[Execute]→ Process →[Write]→ File`` (malware drop)
   * ``User →[Auth]→ Host`` (lateral auth)
   * ``Host →[Connect]→ IP`` (C2)
   * ``Process →[Spawn]→ Process`` (parent-child chains)
   * Or pick a pattern from the **ATT&CK catalog**.
5. Switch to **Explorer Mode** to search IOCs and expand neighborhoods; use **Events**, **Heatmap**, and **Timeline** for context.

Real-world datasets
===================

For larger tests with real attack telemetry, see **DOWNLOAD_REAL_DATA.md** in the ``demo_data/`` folder (in the repository). It includes:

* **OTRF / Mordor** — Pre-recorded Windows Sysmon + Security events (JSON/NDJSON); download and combine scripts.
* **Splunk attack_data** — XML logs; conversion steps to JSON/NDJSON for use with Graph Hunter.

Load those files with **Auto-detect** (or the appropriate format) after conversion where needed.
