import React, { useState } from "react";
import { BookOpen, Info, ChevronRight, X } from "lucide-react";

type HelpTab = "how-to-use" | "about";

interface HelpPanelProps {
  onClose: () => void;
}

const HelpPanel: React.FC<HelpPanelProps> = ({ onClose }) => {
  const [tab, setTab] = useState<HelpTab>("how-to-use");

  return (
    <div className="help-panel" role="dialog" aria-label="Guide" aria-modal="true">
      <div className="help-panel-header">
        <h2 className="help-panel-title">Guide</h2>
        <button
          type="button"
          className="help-panel-close"
          onClick={onClose}
          aria-label="Close guide"
        >
          <X size={18} />
        </button>
      </div>
      <div className="help-panel-tabs">
        <button
          type="button"
          className={`help-panel-tab ${tab === "how-to-use" ? "active" : ""}`}
          onClick={() => setTab("how-to-use")}
          aria-pressed={tab === "how-to-use"}
        >
          <BookOpen size={16} />
          <span>How to use</span>
          <ChevronRight size={14} className="help-panel-tab-chevron" />
        </button>
        <button
          type="button"
          className={`help-panel-tab ${tab === "about" ? "active" : ""}`}
          onClick={() => setTab("about")}
          aria-pressed={tab === "about"}
        >
          <Info size={16} />
          <span>About the tool</span>
          <ChevronRight size={14} className="help-panel-tab-chevron" />
        </button>
      </div>
      <div className="help-panel-content">
        {tab === "how-to-use" && (
          <div className="help-panel-body">
            <h3>How to use Graph Hunter</h3>
            <ol className="help-steps">
              <li>
                <strong>Create or load a session</strong> — Use the session selector. Each session is a workspace with its own graph and notes.
              </li>
              <li>
                <strong>Ingest data</strong> — Open the <em>Datasets</em> panel and load security logs (Sysmon, Sentinel, JSON, CSV). The engine auto-detects format and builds a knowledge graph.
              </li>
              <li>
                <strong>Hunt</strong> — In Hunt mode, define a hypothesis as a chain of steps (e.g. <code>User →[Auth]→ Host →[Execute]→ Process</code>). The engine finds all paths matching the pattern with causal order.
              </li>
              <li>
                <strong>Explore</strong> — Search IOCs, expand node neighborhoods, inspect metadata and anomaly scores. Use Events, Heatmap, and Timeline views to pivot.
              </li>
            </ol>
            <p className="help-note">
              Use the top toolbar for Datasets, Activity log, Metrics, Path Nodes, Notes, and AI Analysis once a session is open.
            </p>
          </div>
        )}
        {tab === "about" && (
          <div className="help-panel-body">
            <h3>About Graph Hunter</h3>
            <p>
              Graph Hunter is a <strong>graph-based threat hunting engine</strong> that turns security telemetry (Sysmon, Microsoft Sentinel, JSON, CSV) into a single <strong>knowledge graph</strong>.
            </p>
            <p>
              Analysts define <strong>hypotheses</strong> as chains of entity and relation types. The engine finds all paths that match the pattern while enforcing <strong>causal monotonicity</strong>: each step occurs at or after the previous one in time.
            </p>
            <p>
              Results are explored via an interactive graph canvas, IOC search, timeline and heatmap views, and optional MITRE ATT&CK–aligned hypothesis templates. The engine includes <strong>anomaly scoring</strong> (Entity Rarity, Edge Rarity, Neighborhood Concentration, Temporal Novelty, and optional GNN Threat) to prioritize suspicious paths.
            </p>
          </div>
        )}
      </div>
      <div className="help-panel-footer">
        <span className="help-panel-authors">From BASE4 Security, Lucas Sotomayor & Diego Staino</span>
      </div>
    </div>
  );
};

export default HelpPanel;
