import { useLogState } from "../context/LogContext";
import ActivityLogLeftPanel from "./ActivityLogLeftPanel";

/**
 * Thin wrapper around `ActivityLogLeftPanel` that reads the log entries
 * from `LogContext` directly instead of receiving them as a prop.
 *
 * Why: the log is updated on nearly every user action, and when it lived
 * in the main app state the whole `AppInner` tree re-rendered on every
 * push. Extracting the log into its own context and this container means
 * only this component (and its descendants) re-render when a new entry
 * arrives. See `context/LogContext.tsx` for the underlying split.
 */
interface Props {
  onClose: () => void;
}

export default function ActivityLogContainer({ onClose }: Props) {
  const log = useLogState();
  return <ActivityLogLeftPanel log={log} onClose={onClose} />;
}
