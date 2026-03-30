import "@testing-library/jest-dom";
import { vi } from "vitest";

// Mock the lib/tauri module so components can call invoke() without Tauri runtime
vi.mock("../lib/tauri", () => ({
  invoke: vi.fn().mockRejectedValue(new Error("invoke not mocked for this call")),
}));

// Mock the lib/runtime module so isTauri() returns false in tests
vi.mock("../lib/runtime", () => ({
  isTauri: vi.fn().mockReturnValue(false),
}));
