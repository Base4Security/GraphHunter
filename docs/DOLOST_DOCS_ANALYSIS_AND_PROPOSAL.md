

## 3. Proposals to improve Graph Hunter docs (DOLOST-inspired)


### 3.2 Uncomment and add screenshots in Usage

**Current:** `docs/getting-started/usage.rst` has `.. .. image:: ../images/screenshot-main.png` commented out.

**Proposal:**

- Add (or reuse) a main-window screenshot after “Quick run” (e.g. session loaded, one hunt run).
- Add one screenshot per main workflow if possible:
  - Data panel + “Select Log File” / Auto-detect.
  - Hunt Mode with hypothesis + Run + results.
  - Explorer with search and expanded node.
- Use consistent naming, e.g. `screenshot-ingestingdata.png`, `screenshot-hunt-results.png`, `screenshot-exploringnodes.png`, and reference them in RST with `:alt:` and optional `:width:`.

**Impact:** Reduces “what should I see?” uncertainty and aligns with DOLOST-style “show, then explain.”

---

### 3.3 “First hunt” mini-tutorial

**Idea:** A short, linear “First hunt in 5 minutes” section (in Getting started or as a dedicated page).

**Content:**

1. Start app → create session.
2. Load `demo_data/apt_attack_simulation.json` with Auto-detect.
3. Open Hunt Mode → enter or select one hypothesis (e.g. `User -[Auth]-> Host -[Execute]-> Process`).
4. Run → interpret path count and graph.
5. Optional: open one path in Explorer, search an IOC, add a note.

**Format:** Numbered steps + one or two screenshots (e.g. “after load”, “after run”). Link to **Usage**, **Hypothesis & catalog**, and **Demo data** for details.

**Impact:** Mirrors the “quick path to value” that a schematic + quickstart give in DOLOST.

**Implemented:** See :doc:`getting-started/first-hunt` (added as **First hunt (5 minutes)** in the Getting started section).

---

