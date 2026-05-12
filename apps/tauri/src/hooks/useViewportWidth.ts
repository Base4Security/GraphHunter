import { useEffect, useState } from "react";

const DEBOUNCE_MS = 100;

/**
 * Tracks the viewport width via `ResizeObserver` on `document.body`
 * plus a fallback `resize` listener. Debounced so React's render
 * loop doesn't see every intermediate tick during a continuous drag.
 *
 * Returns the current width in CSS pixels, or `Number.POSITIVE_INFINITY`
 * during the very brief window before the first observation lands —
 * that default is intentional: consumers use the value in
 * `width < threshold` comparisons, so "infinity" maps to "treat as
 * wide enough" which avoids a flash-of-compact-toolbar on initial
 * mount.
 *
 * Lifetime: the observer + listener are torn down on unmount. The
 * debounce timer is cleared too so the hook leaves no lingering
 * callbacks after the consumer unmounts.
 */
export function useViewportWidth(): number {
  const [width, setWidth] = useState<number>(() =>
    typeof window === "undefined" ? Number.POSITIVE_INFINITY : window.innerWidth,
  );

  useEffect(() => {
    if (typeof window === "undefined") return;
    let timeout: ReturnType<typeof setTimeout> | null = null;
    const tick = () => {
      timeout = null;
      setWidth(window.innerWidth);
    };
    const onResize = () => {
      if (timeout !== null) clearTimeout(timeout);
      timeout = setTimeout(tick, DEBOUNCE_MS);
    };
    const ro = new ResizeObserver(onResize);
    ro.observe(document.body);
    window.addEventListener("resize", onResize);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", onResize);
      if (timeout !== null) clearTimeout(timeout);
    };
  }, []);

  return width;
}

/**
 * Threshold below which the top toolbar switches to compact (icon-
 * only) mode. The full toolbar renders 8–11 buttons + up to 3
 * status badges (~1160 px at the maximum set); below 1100 px the
 * row begins to overflow even before badges appear, so that's the
 * point at which collapsing button labels buys back a full line of
 * vertical real-estate.
 */
export const TOOLBAR_COMPACT_THRESHOLD_PX = 1100;
