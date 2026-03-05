import { useState, useEffect, useCallback } from "react";
import { invoke } from "../lib/tauri";
import { Plus, Trash2, Crosshair, X, BookOpen, Code, Sparkles } from "lucide-react";
import type {
  HypothesisStep,
  Hypothesis,
  HuntResults,
  LogEntry,
  DslResult,
  CatalogEntry,
  AiConfig,
} from "../types";
import { ENTITY_TYPES_WITH_WILDCARD, RELATION_TYPES_WITH_WILDCARD } from "../types";

interface HypothesisBuilderProps {
  onHuntResults: (results: HuntResults) => void;
  onLog: (entry: LogEntry) => void;
}

const DEFAULT_STEP: HypothesisStep = {
  origin_type: "IP",
  relation_type: "Connect",
  dest_type: "Host",
};

function now(): string {
  return new Date().toLocaleTimeString("en-US", { hour12: false });
}

/** Convert steps array to DSL string */
function stepsToDsl(steps: HypothesisStep[]): string {
  if (steps.length === 0) return "";
  let s = steps[0].origin_type;
  for (const step of steps) {
    s += ` -[${step.relation_type}]-> ${step.dest_type}`;
  }
  return s;
}

export default function HypothesisBuilder({
  onHuntResults,
  onLog,
}: HypothesisBuilderProps) {
  const [steps, setSteps] = useState<HypothesisStep[]>([{ ...DEFAULT_STEP }]);
  const [kSimplicity, setKSimplicity] = useState(1);
  const [hunting, setHunting] = useState(false);
  const [results, setResults] = useState<HuntResults | null>(null);

  // DSL input mode
  const [dslMode, setDslMode] = useState(false);
  const [dslText, setDslText] = useState("");
  const [dslError, setDslError] = useState<string | null>(null);

  // Catalog
  const [catalogOpen, setCatalogOpen] = useState(false);
  const [catalog, setCatalog] = useState<CatalogEntry[]>([]);

  // AI propose hypothesis dialog
  const [aiDialogOpen, setAiDialogOpen] = useState(false);
  const [aiSituation, setAiSituation] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiResult, setAiResult] = useState<DslResult | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiKeyConfigured, setAiKeyConfigured] = useState<boolean | null>(null);
  const [aiKeyInput, setAiKeyInput] = useState("");
  const [aiKeySaving, setAiKeySaving] = useState(false);

  // Load catalog on first open
  useEffect(() => {
    if (!catalogOpen || catalog.length > 0) return;
    invoke<CatalogEntry[]>("cmd_get_catalog")
      .then(setCatalog)
      .catch(() => {});
  }, [catalogOpen, catalog.length]);

  // Sync: steps -> DSL text (when chain UI changes)
  const syncStepsToDsl = useCallback((newSteps: HypothesisStep[]) => {
    setDslText(stepsToDsl(newSteps));
    setDslError(null);
  }, []);

  function addStep() {
    const lastStep = steps[steps.length - 1];
    const newSteps = [
      ...steps,
      {
        origin_type: lastStep ? lastStep.dest_type : "IP",
        relation_type: "Connect" as const,
        dest_type: "Host" as const,
      },
    ];
    setSteps(newSteps);
    syncStepsToDsl(newSteps);
  }

  function removeStep(idx: number) {
    if (steps.length <= 1) return;
    const newSteps = steps.filter((_, i) => i !== idx);
    setSteps(newSteps);
    syncStepsToDsl(newSteps);
  }

  function updateStep(idx: number, field: keyof HypothesisStep, value: string) {
    const updated = [...steps];
    updated[idx] = { ...updated[idx], [field]: value };
    setSteps(updated);
    syncStepsToDsl(updated);
  }

  // DSL parse: text -> steps
  async function parseDsl() {
    if (!dslText.trim()) {
      setDslError("Enter a hypothesis chain");
      return;
    }
    try {
      const result = await invoke<DslResult>("cmd_parse_dsl", {
        input: dslText,
        name: null,
      });
      setSteps(result.hypothesis.steps);
      setKSimplicity(result.hypothesis.k_simplicity ?? 1);
      setDslError(null);
      onLog({ time: now(), message: "DSL parsed successfully", level: "info" });
    } catch (e) {
      setDslError(String(e));
    }
  }

  // AI propose hypothesis
  async function aiProposeHypothesis() {
    if (!aiSituation.trim()) {
      setAiError("Describe the situation or scenario first.");
      return;
    }
    setAiLoading(true);
    setAiError(null);
    setAiResult(null);
    try {
      const result = await invoke<DslResult>("cmd_ai_propose_hypothesis", { situation: aiSituation.trim() });
      setAiResult(result);
      onLog({ time: now(), message: "AI proposed hypothesis", level: "info" });
    } catch (e) {
      setAiError(String(e));
      onLog({ time: now(), message: `AI propose error: ${e}`, level: "error" });
    } finally {
      setAiLoading(false);
    }
  }

  function useAiResultInBuilder() {
    if (!aiResult) return;
    setSteps(aiResult.hypothesis.steps);
    setKSimplicity(aiResult.hypothesis.k_simplicity ?? 1);
    setDslText(aiResult.formatted);
    setDslError(null);
    setResults(null);
    setAiDialogOpen(false);
    setAiResult(null);
    setAiSituation("");
    onLog({ time: now(), message: "AI hypothesis loaded into builder. Run Hunt when ready.", level: "info" });
  }

  // Load catalog entry
  async function loadCatalogEntry(entry: CatalogEntry) {
    try {
      const result = await invoke<DslResult>("cmd_load_catalog_hypothesis", {
        catalogId: entry.id,
      });
      setSteps(result.hypothesis.steps);
      setKSimplicity(result.hypothesis.k_simplicity ?? 1);
      setDslText(result.formatted);
      setDslError(null);
      setResults(null);
      setCatalogOpen(false);
      onLog({ time: now(), message: `Loaded ATT&CK: ${entry.mitre_id} — ${entry.name}`, level: "info" });
    } catch (e) {
      onLog({ time: now(), message: `Catalog load error: ${e}`, level: "error" });
    }
  }

  async function runHunt() {
    setHunting(true);
    setResults(null);
    onLog({ time: now(), message: "Running hunt...", level: "info" });

    // If in DSL mode, parse first
    if (dslMode && dslText.trim()) {
      try {
        const result = await invoke<DslResult>("cmd_parse_dsl", {
          input: dslText,
          name: null,
        });
        setSteps(result.hypothesis.steps);
        setKSimplicity(result.hypothesis.k_simplicity ?? 1);
        setDslError(null);
      } catch (e) {
        setDslError(String(e));
        setHunting(false);
        return;
      }
    }

    const hypothesis: Hypothesis = {
      name: "Hunt",
      steps,
      k_simplicity: kSimplicity,
    };

    try {
      const res = await invoke<HuntResults>("cmd_run_hunt", {
        hypothesisJson: JSON.stringify(hypothesis),
        timeWindow: null,
      });

      setResults(res);
      onHuntResults(res);

      if (res.path_count > 0) {
        const cappedNote = res.truncated ? " (capped at 10,000)" : "";
        onLog({
          time: now(),
          message: `FOUND ${res.path_count} attack path(s)!${cappedNote}`,
          level: "success",
        });
      } else {
        onLog({ time: now(), message: "No matching paths found", level: "info" });
      }
    } catch (e) {
      onLog({ time: now(), message: `Hunt error: ${e}`, level: "error" });
    } finally {
      setHunting(false);
    }
  }

  return (
    <div className="hypothesis-content">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h2>
          <Crosshair size={14} style={{ marginRight: 6, verticalAlign: "middle" }} />
          Hypothesis Builder
        </h2>
        <div style={{ display: "flex", gap: 4 }}>
          <button
            className={`btn btn-sm ${dslMode ? "btn-primary" : ""}`}
            onClick={() => {
              setDslMode(!dslMode);
              if (!dslMode) syncStepsToDsl(steps);
            }}
            title="Toggle DSL text input"
          >
            <Code size={12} /> DSL
          </button>
          <button
            className="btn btn-sm"
            onClick={() => {
              setAiDialogOpen(true);
              setAiError(null);
              setAiResult(null);
              // Check if AI key is configured
              invoke<AiConfig>("cmd_ai_check_config")
                .then((config) => setAiKeyConfigured(config.api_key_set))
                .catch(() => setAiKeyConfigured(false));
            }}
            title="AI: propose hypothesis from situation"
          >
            <Sparkles size={12} /> Ask for hypothesis
          </button>
          <button
            className={`btn btn-sm ${catalogOpen ? "btn-primary" : ""}`}
            onClick={() => setCatalogOpen(!catalogOpen)}
            title="ATT&CK Catalog"
          >
            <BookOpen size={12} /> ATT&CK
          </button>
          <label title="k-Simplicity: max times a vertex can appear in a path (1 = simple path)" style={{ display: "flex", alignItems: "center", gap: 3, fontSize: 11, color: "var(--text-secondary)" }}>
            k=
            <input
              type="number"
              min={1}
              max={10}
              value={kSimplicity}
              onChange={(e) => setKSimplicity(Math.max(1, parseInt(e.target.value) || 1))}
              style={{
                width: 36,
                padding: "2px 4px",
                fontSize: 11,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderRadius: 3,
                color: kSimplicity > 1 ? "var(--accent)" : "var(--text-primary)",
                fontWeight: kSimplicity > 1 ? "bold" : "normal",
              }}
            />
          </label>
        </div>
      </div>

      {/* AI Propose Hypothesis Dialog */}
      {aiDialogOpen && (
        <div
          className="modal-overlay"
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => !aiLoading && setAiDialogOpen(false)}
        >
          <div
            className="modal-content"
            style={{
              background: "var(--bg-primary)",
              border: "1px solid var(--border)",
              borderRadius: 8,
              padding: 16,
              maxWidth: 480,
              width: "90%",
              maxHeight: "80vh",
              overflow: "auto",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <h3 style={{ margin: 0, fontSize: 14, display: "flex", alignItems: "center", gap: 6 }}>
                <Sparkles size={16} /> AI Propose Hypothesis
              </h3>
              <button className="btn btn-sm" onClick={() => !aiLoading && setAiDialogOpen(false)}>
                <X size={14} />
              </button>
            </div>
            {aiKeyConfigured === false && (
              <div style={{
                padding: 10,
                marginBottom: 10,
                background: "var(--bg-tertiary)",
                border: "1px solid var(--warning, orange)",
                borderRadius: 6,
                fontSize: 11,
              }}>
                <div style={{ marginBottom: 6, color: "var(--warning, orange)", fontWeight: "bold" }}>
                  No API key configured
                </div>
                <div style={{ marginBottom: 6, color: "var(--text-secondary)" }}>
                  Enter your OpenAI-compatible API key to use AI features.
                </div>
                <div style={{ display: "flex", gap: 4 }}>
                  <input
                    type="password"
                    value={aiKeyInput}
                    onChange={(e) => setAiKeyInput(e.target.value)}
                    placeholder="sk-..."
                    style={{
                      flex: 1,
                      padding: "4px 8px",
                      fontSize: 11,
                      background: "var(--bg-secondary)",
                      border: "1px solid var(--border)",
                      borderRadius: 4,
                      color: "var(--text-primary)",
                    }}
                  />
                  <button
                    className="btn btn-sm btn-primary"
                    disabled={aiKeySaving || !aiKeyInput.trim()}
                    onClick={async () => {
                      setAiKeySaving(true);
                      try {
                        await invoke("cmd_ai_set_key", { key: aiKeyInput.trim() });
                        setAiKeyConfigured(true);
                        setAiKeyInput("");
                        onLog({ time: now(), message: "AI API key saved", level: "success" });
                      } catch (e) {
                        setAiError(`Failed to save key: ${e}`);
                      } finally {
                        setAiKeySaving(false);
                      }
                    }}
                  >
                    {aiKeySaving ? "Saving..." : "Save"}
                  </button>
                </div>
              </div>
            )}
            <p style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 8 }}>
              Describe a situation or scenario that could trigger malicious action. The AI will propose a hypothesis chain you can run manually.
            </p>
            <textarea
              value={aiSituation}
              onChange={(e) => { setAiSituation(e.target.value); setAiError(null); }}
              placeholder="e.g. Lateral movement after credential theft, or process injection from a signed binary"
              rows={3}
              style={{
                width: "100%",
                resize: "vertical",
                fontFamily: "inherit",
                fontSize: 12,
                padding: 8,
                background: "var(--bg-secondary)",
                border: "1px solid var(--border)",
                borderRadius: 4,
                color: "var(--text-primary)",
                marginBottom: 8,
                boxSizing: "border-box",
              }}
            />
            <button
              className="btn btn-primary"
              onClick={aiProposeHypothesis}
              disabled={aiLoading}
              style={{ marginBottom: 12 }}
            >
              {aiLoading ? "Proposing..." : "Propose hypothesis"}
            </button>
            {aiError && (
              <div style={{ color: "var(--danger)", fontSize: 11, marginBottom: 8 }}>{aiError}</div>
            )}
            {aiResult && (
              <div style={{ marginTop: 8, padding: 8, background: "var(--bg-secondary)", borderRadius: 4 }}>
                <div style={{ fontSize: 11, color: "var(--text-secondary)", marginBottom: 4 }}>Proposed hypothesis</div>
                <code style={{ fontSize: 12, wordBreak: "break-all", display: "block", marginBottom: 8 }}>
                  {aiResult.formatted}
                </code>
                <button className="btn btn-sm btn-primary" onClick={useAiResultInBuilder}>
                  Use in builder
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ATT&CK Catalog Panel */}
      {catalogOpen && (
        <div style={{
          border: "1px solid var(--border)",
          borderRadius: 6,
          padding: 10,
          marginBottom: 8,
          flex: "1 1 0",
          minHeight: 80,
          overflowY: "auto",
          background: "var(--bg-secondary)",
        }}>
          <div style={{ fontSize: 12, fontWeight: "bold", color: "var(--text-secondary)", marginBottom: 6 }}>
            MITRE ATT&CK Hypothesis Catalog
          </div>
          {catalog.map((entry) => (
            <div
              key={entry.id}
              onClick={() => loadCatalogEntry(entry)}
              style={{
                padding: "6px 8px",
                cursor: "pointer",
                borderRadius: 4,
                marginBottom: 2,
                fontSize: 12,
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ color: "var(--accent)", fontWeight: "bold", minWidth: 85 }}>
                  {entry.mitre_id}
                </span>
                <span style={{ color: "var(--text-primary)", fontWeight: 500 }}>{entry.name}</span>
                {entry.k_simplicity > 1 && (
                  <span style={{ color: "var(--warning, orange)", fontSize: 9, fontWeight: "bold", padding: "1px 5px", border: "1px solid var(--warning, orange)", borderRadius: 3 }}>
                    k={entry.k_simplicity}
                  </span>
                )}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: 10, fontFamily: "monospace", marginTop: 2, paddingLeft: 85 + 8 }}>
                {entry.dsl_pattern}
              </div>
            </div>
          ))}
          {catalog.length === 0 && (
            <div style={{ color: "var(--text-muted)", fontSize: 11, padding: 4 }}>Loading catalog...</div>
          )}
        </div>
      )}

      {/* DSL Text Input */}
      {dslMode && (
        <div style={{ marginBottom: 6 }}>
          <div style={{ display: "flex", gap: 4, alignItems: "center" }}>
            <input
              type="text"
              value={dslText}
              onChange={(e) => {
                setDslText(e.target.value);
                setDslError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") parseDsl();
              }}
              placeholder="User -[Auth]-> Host -[Execute]-> Process"
              style={{
                flex: 1,
                fontFamily: "monospace",
                fontSize: 12,
                padding: "4px 8px",
                background: "var(--bg-secondary)",
                border: dslError ? "1px solid var(--danger)" : "1px solid var(--border)",
                borderRadius: 4,
                color: "var(--text-primary)",
              }}
            />
            <button className="btn btn-sm" onClick={parseDsl}>
              Parse
            </button>
          </div>
          {dslError && (
            <div style={{ color: "var(--danger)", fontSize: 10, marginTop: 2 }}>{dslError}</div>
          )}
          <div style={{ color: "var(--text-muted)", fontSize: 9, marginTop: 2 }}>
            Syntax: EntityType -[RelationType]-&gt; EntityType ... Use * for wildcard.
          </div>
        </div>
      )}

      {/* Steps Chain */}
      <div className="hypothesis-chain">
        {steps.map((step, idx) => (
          <div key={idx} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            {idx > 0 && <span className="step-arrow">&rarr;</span>}
            <div className="step-group">
              <select
                value={step.origin_type}
                onChange={(e) => updateStep(idx, "origin_type", e.target.value)}
              >
                {ENTITY_TYPES_WITH_WILDCARD.map((t) => (
                  <option key={t} value={t}>{t === "*" ? "* (Any)" : t}</option>
                ))}
              </select>

              <span style={{ color: "var(--accent)", fontSize: 11 }}>&mdash;[</span>

              <select
                value={step.relation_type}
                onChange={(e) => updateStep(idx, "relation_type", e.target.value)}
              >
                {RELATION_TYPES_WITH_WILDCARD.map((t) => (
                  <option key={t} value={t}>{t === "*" ? "* (Any)" : t}</option>
                ))}
              </select>

              <span style={{ color: "var(--accent)", fontSize: 11 }}>]&rarr;</span>

              <select
                value={step.dest_type}
                onChange={(e) => updateStep(idx, "dest_type", e.target.value)}
              >
                {ENTITY_TYPES_WITH_WILDCARD.map((t) => (
                  <option key={t} value={t}>{t === "*" ? "* (Any)" : t}</option>
                ))}
              </select>

              {steps.length > 1 && (
                <span className="step-remove" onClick={() => removeStep(idx)} title="Remove step">
                  <X size={12} />
                </span>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Actions */}
      <div className="hypothesis-actions">
        <button className="btn" onClick={addStep}>
          <Plus size={14} /> Add Step
        </button>
        <button className="btn btn-primary" onClick={runHunt} disabled={hunting}>
          <Crosshair size={14} />
          {hunting ? "Hunting..." : "Run Hunt"}
        </button>
        {results && (
          <button className="btn btn-danger btn-sm" onClick={() => setResults(null)}>
            <Trash2 size={12} /> Clear
          </button>
        )}
        {results && (
          <span
            style={{
              color: results.path_count > 0 ? "var(--danger)" : "var(--text-muted)",
              fontWeight: "bold",
              fontSize: 13,
            }}
          >
            {results.path_count > 0
              ? `${results.path_count} path(s) found${results.truncated ? " (capped at 10,000)" : ""}`
              : "No matches"}
          </span>
        )}
      </div>
    </div>
  );
}
