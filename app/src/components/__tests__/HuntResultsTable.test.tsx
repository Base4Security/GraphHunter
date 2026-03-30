import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { invoke } from "../../lib/tauri";
import HuntResultsTable from "../HuntResultsTable";
import type { PaginatedHuntResults } from "../../types";

const mockedInvoke = vi.mocked(invoke);

function emptyPage(): PaginatedHuntResults {
  return {
    total_paths: 0,
    filtered_paths: 0,
    page: 0,
    page_size: 50,
    paths: [],
  };
}

function pageWithResults(count: number): PaginatedHuntResults {
  return {
    total_paths: count,
    filtered_paths: count,
    page: 0,
    page_size: 50,
    paths: Array.from({ length: Math.min(count, 50) }, (_, i) => ({
      path: [`node-${i}-a`, `node-${i}-b`],
      max_score: 10 + i,
      total_score: 20 + i,
      time_start: 1700000000 + i * 60,
      time_end: 1700000060 + i * 60,
      chain_summary: `User-${i} -> Host-${i}`,
    })),
  };
}

describe("HuntResultsTable", () => {
  const onViewPath = vi.fn();
  const onLog = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders without crash with empty results", async () => {
    mockedInvoke.mockResolvedValueOnce(emptyPage());

    render(
      <HuntResultsTable totalPaths={0} onViewPath={onViewPath} onLog={onLog} />
    );

    await waitFor(() => {
      expect(screen.getByText("No results")).toBeInTheDocument();
    });
  });

  it("renders rows when given hunt result paths", async () => {
    mockedInvoke.mockResolvedValueOnce(pageWithResults(3));

    render(
      <HuntResultsTable totalPaths={3} onViewPath={onViewPath} onLog={onLog} />
    );

    await waitFor(() => {
      expect(screen.getByText("User-0 -> Host-0")).toBeInTheDocument();
      expect(screen.getByText("User-1 -> Host-1")).toBeInTheDocument();
      expect(screen.getByText("User-2 -> Host-2")).toBeInTheDocument();
    });
  });

  it("shows pagination controls", async () => {
    mockedInvoke.mockResolvedValueOnce(pageWithResults(3));

    render(
      <HuntResultsTable totalPaths={3} onViewPath={onViewPath} onLog={onLog} />
    );

    await waitFor(() => {
      expect(screen.getByText("Prev")).toBeInTheDocument();
      expect(screen.getByText("Next")).toBeInTheDocument();
    });

    // On single page, both buttons should be disabled
    const prevBtn = screen.getByText("Prev");
    const nextBtn = screen.getByText("Next");
    expect(prevBtn).toBeDisabled();
    expect(nextBtn).toBeDisabled();
  });

  it("shows filter and top anomalies buttons", async () => {
    mockedInvoke.mockResolvedValueOnce(emptyPage());

    render(
      <HuntResultsTable totalPaths={0} onViewPath={onViewPath} onLog={onLog} />
    );

    await waitFor(() => {
      expect(screen.getByText("Filter")).toBeInTheDocument();
      expect(screen.getByText("Top Anomalies")).toBeInTheDocument();
    });
  });

  it("displays total path count in header", async () => {
    mockedInvoke.mockResolvedValueOnce(pageWithResults(5));

    render(
      <HuntResultsTable totalPaths={5} onViewPath={onViewPath} onLog={onLog} />
    );

    await waitFor(() => {
      expect(screen.getByText(/Hunt Results:.*5.*paths/)).toBeInTheDocument();
    });
  });
});
