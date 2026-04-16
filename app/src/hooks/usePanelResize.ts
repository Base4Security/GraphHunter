import { useCallback } from "react";
import { useUIState, useAppDispatch } from "../context/AppStateContext";

export function usePanelResize() {
  const dispatch = useAppDispatch();
  const { bottomPanelHeight } = useUIState();

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const startY = e.clientY;
    const startHeight = bottomPanelHeight;
    const onMove = (e2: MouseEvent) => {
      const delta = startY - e2.clientY;
      dispatch({ type: "SET_BOTTOM_PANEL_HEIGHT", payload: Math.min(600, Math.max(120, startHeight + delta)) });
    };
    const onUp = () => {
      document.removeEventListener("mousemove", onMove);
      document.removeEventListener("mouseup", onUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.body.style.cursor = "ns-resize";
    document.body.style.userSelect = "none";
    document.addEventListener("mousemove", onMove);
    document.addEventListener("mouseup", onUp);
  }, [bottomPanelHeight, dispatch]);

  return { bottomPanelHeight, handleResizeStart };
}
