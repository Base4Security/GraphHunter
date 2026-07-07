import React from "react";
import { FolderPlus } from "lucide-react";
import SessionSelector from "./SessionSelector";
import type { SessionInfo, LogEntry } from "../types";

interface WelcomePageProps {
  currentSession: SessionInfo | null;
  sessions: SessionInfo[];
  onSessionChange: (session: SessionInfo | null) => void;
  onSessionsListChange: (list: SessionInfo[]) => void;
  onError: (message: string) => void;
  onLog?: (entry: LogEntry) => void;
}

const WelcomePage: React.FC<WelcomePageProps> = ({
  currentSession,
  sessions,
  onSessionChange,
  onSessionsListChange,
  onError,
  onLog,
}) => {
  return (
    <div className="welcome-page">
      <main className="welcome-main" role="main">
        <div className="welcome-hero">
          <h1 className="welcome-hero-title">Graph Hunter</h1>
          <p className="welcome-hero-subtitle">
            Hypothesis-driven threat hunting on temporal knowledge graphs
          </p>
        </div>
        <div className="welcome-session-block">
          <h2 className="welcome-session-heading">
            <FolderPlus size={22} />
            Select a session
          </h2>
          <p className="welcome-session-desc">
            Create a new session or load an existing one to start ingesting data and hunting.
          </p>
          <div className="welcome-session-selector-wrap">
            <SessionSelector
              currentSession={currentSession}
              sessions={sessions}
              onSessionChange={onSessionChange}
              onSessionsListChange={onSessionsListChange}
              onError={onError}
              onLog={onLog}
            />
          </div>
        </div>
      </main>
    </div>
  );
};

export default WelcomePage;
