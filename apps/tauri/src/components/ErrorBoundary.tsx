import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  /** Optional label shown in the fallback UI (e.g. "Graph Canvas"). */
  section?: string;
}

interface State {
  error: Error | null;
}

/**
 * Catches render errors in its subtree and shows a recovery UI instead
 * of crashing the entire app.  Wrap around major sections (graph canvas,
 * bottom panel, side panels) so a bug in one area doesn't take out the
 * rest of the workspace.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error(`[ErrorBoundary${this.props.section ? `: ${this.props.section}` : ""}]`, error, info.componentStack);
  }

  private handleReset = () => {
    this.setState({ error: null });
  };

  render() {
    if (this.state.error) {
      return (
        <div
          style={{
            padding: 24,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            gap: 12,
            height: "100%",
            color: "var(--text-secondary)",
            fontSize: 13,
          }}
        >
          <p style={{ color: "var(--danger)", fontWeight: 600 }}>
            {this.props.section
              ? `Something went wrong in ${this.props.section}.`
              : "Something went wrong."}
          </p>
          <pre
            style={{
              fontSize: 11,
              maxWidth: "100%",
              overflow: "auto",
              background: "var(--bg-secondary)",
              padding: 8,
              borderRadius: 4,
              maxHeight: 120,
            }}
          >
            {this.state.error.message}
          </pre>
          <button
            type="button"
            className="btn btn-primary"
            onClick={this.handleReset}
            style={{ fontSize: 12 }}
          >
            Try again
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
