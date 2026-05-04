import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { invoke } from "../../lib/tauri";
import SessionSelector from "../SessionSelector";
import type { SessionInfo } from "../../types";

const mockedInvoke = vi.mocked(invoke);

const mockSessions: SessionInfo[] = [
  { id: "s1", name: "Incident Alpha", created_at: 1700000000 },
  { id: "s2", name: "Incident Beta", created_at: 1700100000 },
];

describe("SessionSelector", () => {
  const onSessionChange = vi.fn();
  const onSessionsListChange = vi.fn();
  const onError = vi.fn();
  const onLog = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    // The component calls cmd_list_sessions on mount
    mockedInvoke.mockResolvedValue([]);
  });

  it("renders without crash", async () => {
    render(
      <SessionSelector
        currentSession={null}
        sessions={[]}
        onSessionChange={onSessionChange}
        onSessionsListChange={onSessionsListChange}
        onError={onError}
        onLog={onLog}
      />
    );

    await waitFor(() => {
      expect(screen.getByText("Session:")).toBeInTheDocument();
    });
  });

  it("displays session list when provided", async () => {
    render(
      <SessionSelector
        currentSession={null}
        sessions={mockSessions}
        onSessionChange={onSessionChange}
        onSessionsListChange={onSessionsListChange}
        onError={onError}
        onLog={onLog}
      />
    );

    await waitFor(() => {
      const select = screen.getByRole("combobox");
      expect(select).toBeInTheDocument();
    });

    // Session names appear as <option> elements
    expect(screen.getByText("Incident Alpha")).toBeInTheDocument();
    expect(screen.getByText("Incident Beta")).toBeInTheDocument();
  });

  it("shows the '+ New session' option in the dropdown", async () => {
    render(
      <SessionSelector
        currentSession={null}
        sessions={mockSessions}
        onSessionChange={onSessionChange}
        onSessionsListChange={onSessionsListChange}
        onError={onError}
        onLog={onLog}
      />
    );

    await waitFor(() => {
      expect(screen.getByText("+ New session")).toBeInTheDocument();
    });
  });

  it("opens new session dialog when new session button is clicked", async () => {
    const user = userEvent.setup();

    render(
      <SessionSelector
        currentSession={null}
        sessions={[]}
        onSessionChange={onSessionChange}
        onSessionsListChange={onSessionsListChange}
        onError={onError}
        onLog={onLog}
      />
    );

    await waitFor(() => {
      expect(screen.getByLabelText("New session")).toBeInTheDocument();
    });

    await user.click(screen.getByLabelText("New session"));

    await waitFor(() => {
      expect(screen.getByText("Create session")).toBeInTheDocument();
    });
  });

  it("shows save and delete buttons when a session is selected", async () => {
    const currentSession: SessionInfo = {
      id: "s1",
      name: "Incident Alpha",
      created_at: 1700000000,
    };

    render(
      <SessionSelector
        currentSession={currentSession}
        sessions={mockSessions}
        onSessionChange={onSessionChange}
        onSessionsListChange={onSessionsListChange}
        onError={onError}
        onLog={onLog}
      />
    );

    await waitFor(() => {
      expect(screen.getByLabelText("Save session")).toBeInTheDocument();
      expect(screen.getByLabelText("Delete session")).toBeInTheDocument();
    });
  });
});
