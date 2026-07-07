************************
Installation
************************

.. contents:: Table of Contents

You need Rust, Node.js, and the Tauri v2 prerequisites. No extra services or accounts are required.

Prerequisites
=============

1. **Rust** (2024 edition) — https://rustup.rs/
2. **Node.js** (v18 or later) — https://nodejs.org/
3. **Tauri v2 build tools** — see `Tauri prerequisites <https://v2.tauri.app/start/prerequisites/>`_ for your OS (e.g. Visual Studio Build Tools on Windows, Xcode CLI on macOS, build-essential on Linux).

Steps
=====

1. Clone the repository
-----------------------

.. code-block:: bash

   git clone https://github.com/Base4Security/GraphHunter
   cd GraphHunter

2. Install and run in development
----------------------------------

.. code-block:: bash

   cd app
   npm install
   npm run tauri dev

The first run may take a few minutes while dependencies compile.

3. Verify
---------

* The app window should open.
* Create a session (or use the default).
* Load ``demo_data/apt_attack_simulation.json`` with **Auto-detect**.
* In **Hunt Mode**, add a step (e.g. ``User -[Auth]-> Host``) and click **Run**.
* If you see paths and the graph updates, the installation is correct.

Run tests
=========

From the repository root:

.. code-block:: bash

   cd graph_hunter_core
   cargo test

Type-check frontend (optional)
==============================

.. code-block:: bash

   cd app
   npx tsc --noEmit

Build for production
====================

.. code-block:: bash

   cd app
   npm run tauri build

Installers and binaries are produced in ``app/src-tauri/target/release/`` (and platform-specific subfolders).

Troubleshooting
===============

* **Tauri build fails:** Ensure all `Tauri prerequisites <https://v2.tauri.app/start/prerequisites/>`_ for your OS are installed (e.g. WebView2 on Windows, webkit2gtk on Linux).
* **``npm install`` errors:** Use Node.js v18+ and try ``npm ci`` or remove ``node_modules`` and run ``npm install`` again.
* **Rust errors:** Run ``rustup update`` and ensure you are on the 2024 edition in ``graph_hunter_core/Cargo.toml``.
