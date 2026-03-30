import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import NotesPanel from "../NotesPanel";
import type { Note } from "../../types";

const mockNotes: Note[] = [
  {
    id: "n1",
    content: "Suspicious lateral movement from host-A to host-B",
    node_id: null,
    created_at: 1700000000,
  },
  {
    id: "n2",
    content: "This user account was created recently and has admin privileges",
    node_id: "user-123",
    created_at: 1700100000,
  },
];

describe("NotesPanel", () => {
  const onNotesChange = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders without crash with empty notes", () => {
    render(
      <NotesPanel
        notes={[]}
        selectedNodeId={null}
        onNotesChange={onNotesChange}
      />
    );

    expect(
      screen.getByText(/No notes yet/i)
    ).toBeInTheDocument();
  });

  it("displays notes when provided", () => {
    render(
      <NotesPanel
        notes={mockNotes}
        selectedNodeId={null}
        onNotesChange={onNotesChange}
      />
    );

    expect(
      screen.getByText(/Suspicious lateral movement/i)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/This user account was created recently/i)
    ).toBeInTheDocument();
  });

  it("shows the 'New note' button", () => {
    render(
      <NotesPanel
        notes={[]}
        selectedNodeId={null}
        onNotesChange={onNotesChange}
      />
    );

    expect(screen.getByText("New note")).toBeInTheDocument();
  });

  it("opens the note creation editor when 'New note' is clicked", async () => {
    const user = userEvent.setup();

    render(
      <NotesPanel
        notes={[]}
        selectedNodeId={null}
        onNotesChange={onNotesChange}
      />
    );

    await user.click(screen.getByText("New note"));

    expect(screen.getByPlaceholderText("Note content\u2026")).toBeInTheDocument();
    expect(screen.getByText("Save")).toBeInTheDocument();
    expect(screen.getByText("Cancel")).toBeInTheDocument();
  });

  it("shows delete buttons for each note", () => {
    render(
      <NotesPanel
        notes={mockNotes}
        selectedNodeId={null}
        onNotesChange={onNotesChange}
      />
    );

    const deleteButtons = screen.getAllByLabelText("Delete note");
    expect(deleteButtons).toHaveLength(mockNotes.length);
  });

  it("shows expand buttons for each note", () => {
    render(
      <NotesPanel
        notes={mockNotes}
        selectedNodeId={null}
        onNotesChange={onNotesChange}
      />
    );

    const expandButtons = screen.getAllByLabelText("View note full screen");
    expect(expandButtons).toHaveLength(mockNotes.length);
  });
});
