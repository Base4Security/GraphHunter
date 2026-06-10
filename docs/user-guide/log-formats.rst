************************
Supported log formats
************************

.. contents:: Table of Contents

Graph Hunter supports multiple log formats. Use **Auto-detect** to let the engine choose the parser from content heuristics, or select a format manually.

Auto-detect (recommended)
=========================

The engine identifies the format as follows:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Content heuristic
     - Parser used
   * - JSON with ``EventID`` and ``UtcTime`` (or similar)
     - Sysmon
   * - JSON with Sentinel ``Type`` field
     - Microsoft Sentinel
   * - Other JSON
     - Generic (field normalization)
   * - Non-JSON (e.g. CSV)
     - CSV (then Generic)

Sysmon (Windows Event Log)
==========================

Parses Sysmon JSON (array or NDJSON). Supported event IDs and triples:

.. list-table::
   :header-rows: 1
   :widths: 10 22 68

   * - Event ID
     - Description
     - Triples
   * - 1
     - Process Create
     - ``User -[Execute]-> Process``, ``Parent -[Spawn]-> Child``
   * - 3
     - Network Connection
     - ``Host -[Connect]-> IP``
   * - 11
     - File Create
     - ``Process -[Write]-> File``
   * - 22
     - DNS Query
     - ``Process -[DNS]-> Domain``

Microsoft Sentinel (Azure)
===========================

Parses Sentinel-style JSON (e.g. exported from Log Analytics). Records are classified by the ``Type`` field when present.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Table / source
     - Triples
   * - SecurityEvent (4624/4625)
     - ``User -[Auth]-> Host``
   * - SecurityEvent (4688)
     - ``User -[Execute]-> Process``, ``Parent -[Spawn]-> Child``
   * - SecurityEvent (4663)
     - ``Process -[Read]-> File``
   * - SigninLogs
     - ``User -[Auth]-> IP``
   * - DeviceProcessEvents
     - ``User -[Execute]-> Process``, ``Parent -[Spawn]-> Child``
   * - DeviceNetworkEvents
     - ``Host -[Connect]-> IP``
   * - DeviceFileEvents
     - ``Process -[Write/Read]-> File``
   * - CommonSecurityLog
     - ``IP -[Connect]-> IP``

Generic JSON
=============

Format-agnostic parser:

* **Normalization:** Maps 80+ field name variants (case-insensitive) to canonical names (e.g. ``source_user``, ``SourceUserName`` → user).
* **Inference:** Builds triples from normalized fields using rules (e.g. ``source_user`` + ``source_process`` → ``User →[Execute]→ Process``).
* **Configurable:** You can define or adjust field → entity type mapping and preview before ingest.

Example inferred triples:

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Condition (fields present)
     - Triple
   * - source_user + source_process
     - ``User -[Execute]-> Process``
   * - parent_process + source_process
     - ``Process -[Spawn]-> Process``
   * - source_host + target_ip
     - ``Host -[Connect]-> IP``
   * - source_ip + target_ip
     - ``IP -[Connect]-> IP``
   * - source_process + target_file
     - ``Process -[Write]-> File``
   * - source_process + target_domain
     - ``Process -[DNS]-> Domain``
   * - source_process + target_url
     - ``Process -[Connect]-> URL``
   * - source_process + target_registry
     - ``Process -[Modify]-> Registry``

Works with any JSON log schema; no per-format config required for basic use.

CSV
====

* Parses CSV files with headers.
* Each row is converted to a JSON object and then processed by the **Generic** parser.
* Handles quoted fields and embedded commas.
* Choose **CSV** when the input is CSV; for JSON, use Auto-detect or Generic.

Entity and relation types
==========================

Across all parsers, the model uses:

**Entity types:** IP, Host, User, Process, File, Domain, Registry, URL, Service (plus wildcard ``*`` in hypotheses).

**Relation types:** Auth, Connect, Execute, Read, Write, DNS, Modify, Spawn, Delete (plus wildcard ``*`` in hypotheses).
