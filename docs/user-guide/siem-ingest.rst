************************
SIEM query-based ingest
************************

Graph Hunter can ingest log data directly from **Azure Sentinel** (Log Analytics) and **Elasticsearch** by running queries against their APIs. Data is fetched in batches; you can run a new query after each task (e.g. after each hunt) to pull more data, using the returned pagination state.

Ingest source options
====================

- **From file** — Upload or select a local file (Sysmon, Sentinel export, generic JSON, CSV). No SIEM connection.
- **Azure Sentinel** — Connect using the same data as env vars: **Azure Tenant ID**, **Client ID**, **Client Secret**, and **Workspace ID**. You can enter them in the UI (per session) or set env vars. The app uses a default query (SecurityEvent, last 24h) to fetch data.
- **Elasticsearch** — Run a search query against an index. Requires cluster URL and (optionally) API key or basic auth.

Environment variables (no secrets in repo)
==========================================

Azure Sentinel (Log Analytics)
------------------------------

Set these in the environment where the Graph Hunter CLI or gateway runs (e.g. shell, systemd, or gateway server):

- **AZURE_TENANT_ID** — Azure AD tenant ID (GUID).
- **AZURE_CLIENT_ID** — App registration (client) ID.
- **AZURE_CLIENT_SECRET** — Client secret for the app registration.

The app registration must have permission to run Log Analytics queries (e.g. **Log Analytics Reader** on the workspace or subscription).

Elasticsearch
-------------

Use one of:

- **ELASTIC_URL** — Cluster URL (e.g. ``https://localhost:9200``).
- **ELASTIC_API_KEY** — API key for authentication (sent as ``ApiKey <key>``).

Or:

- **ELASTIC_USER** and **ELASTIC_PASSWORD** — Basic authentication.

How to run one query and ingest
===============================

Web app (with gateway)
----------------------

1. Open the **Datasets** panel and expand **Data Ingestion**.
2. Set **Ingest source** to **Azure Sentinel** or **Elasticsearch**.
3. **Sentinel:** Enter **Azure Tenant ID**, **Azure Client ID**, **Azure Client Secret** (same as the env vars), and **Workspace ID** (Log Analytics workspace GUID). Click **Connect and ingest**. Data is fetched with a default query (SecurityEvent, last 24h); no tables or time range to configure.
4. **Elastic:** Enter Cluster URL, Index (or ``_all``), Query (JSON), and Size, then click **Run query and ingest**.
5. Progress is shown; when the job completes, the graph is updated.

CLI (gateway-driven)
--------------------

The gateway sends an ``ingest_query`` command to the Rust CLI with params. To trigger from the API:

.. code-block:: bash

   curl -X POST http://localhost:3001/api/ingest/query \
     -H "Content-Type: application/json" \
     -d '{
       "session_id": "<session-id>",
       "source": "sentinel",
       "workspace_id": "<workspace-guid>",
       "query": "SecurityEvent | where TimeGenerated > ago(1d) | take 1000"
     }'

For Elasticsearch:

.. code-block:: bash

   curl -X POST http://localhost:3001/api/ingest/query \
     -H "Content-Type: application/json" \
     -d '{
       "session_id": "<session-id>",
       "source": "elastic",
       "url": "https://localhost:9200",
       "index": "logs-*",
       "query": "{\"match_all\": {}}",
       "size": 1000
     }'

Poll ``GET /api/jobs/:id`` for status; when ``status === "completed"``, ``result`` includes ``new_entities``, ``new_relations``, and optionally ``pagination`` for the next run.

Running a new query after each task (pagination)
================================================

- **Sentinel:** The API returns at most a limited number of rows per request. To fetch more, run the same (or updated) KQL with a time filter. The job result can include ``pagination.next_query_start`` (the latest ``TimeGenerated`` in the batch). Use that value as the start of the next time window (e.g. ``| where TimeGenerated > datetime(<next_query_start>)``) and run the job again.
- **Elasticsearch:** The job result can include ``pagination.next_search_after`` (cursor from the last hit). Send that as ``search_after`` in the next ``POST /api/ingest/query`` body to get the next page.

Desktop (Tauri) app
------------------

SIEM query-based ingest in the desktop app is available when using the **web build with the gateway**. When running the native Tauri desktop app without the gateway, use **From file** and export logs from your SIEM to a file, then ingest that file.
