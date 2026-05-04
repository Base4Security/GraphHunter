import { createContext, useContext, useCallback, useState, useEffect, useRef } from "react";
import type { ReactNode } from "react";

export interface Notification {
  id: string;
  message: string;
  type: "error" | "warning" | "info" | "success";
  timestamp: number;
}

interface NotificationContextValue {
  notifications: Notification[];
  addNotification: (n: Omit<Notification, "id" | "timestamp">) => void;
  dismissNotification: (id: string) => void;
}

const NotificationContext = createContext<NotificationContextValue | null>(null);

let nextId = 0;

export function NotificationProvider({ children }: { children: ReactNode }) {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const timersRef = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  const dismissNotification = useCallback((id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
    const timer = timersRef.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timersRef.current.delete(id);
    }
  }, []);

  const addNotification = useCallback(
    (n: Omit<Notification, "id" | "timestamp">) => {
      const id = `notif-${++nextId}`;
      const notification: Notification = {
        ...n,
        id,
        timestamp: Date.now(),
      };
      setNotifications((prev) => [...prev, notification]);

      // Auto-dismiss after 5 seconds
      const timer = setTimeout(() => {
        setNotifications((prev) => prev.filter((x) => x.id !== id));
        timersRef.current.delete(id);
      }, 5000);
      timersRef.current.set(id, timer);
    },
    []
  );

  // Clean up timers on unmount
  useEffect(() => {
    return () => {
      for (const timer of timersRef.current.values()) {
        clearTimeout(timer);
      }
    };
  }, []);

  return (
    <NotificationContext.Provider
      value={{ notifications, addNotification, dismissNotification }}
    >
      {children}
      <NotificationContainer
        notifications={notifications}
        onDismiss={dismissNotification}
      />
    </NotificationContext.Provider>
  );
}

export function useNotifications(): NotificationContextValue {
  const ctx = useContext(NotificationContext);
  if (!ctx) {
    throw new Error("useNotifications must be used within NotificationProvider");
  }
  return ctx;
}

// ── Toast container component ──

const typeStyles: Record<Notification["type"], { bg: string; border: string; icon: string }> = {
  error: { bg: "#2d1b1b", border: "#ff6b6b", icon: "\u2716" },
  warning: { bg: "#2d2a1b", border: "#f9ca24", icon: "\u26A0" },
  info: { bg: "#1b2230", border: "#45b7d1", icon: "\u2139" },
  success: { bg: "#1b2d1e", border: "#4ecdc4", icon: "\u2714" },
};

function NotificationContainer({
  notifications,
  onDismiss,
}: {
  notifications: Notification[];
  onDismiss: (id: string) => void;
}) {
  if (notifications.length === 0) return null;

  return (
    <div
      style={{
        position: "fixed",
        bottom: 16,
        right: 16,
        zIndex: 9999,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        maxWidth: 380,
        pointerEvents: "none",
      }}
    >
      {notifications.map((n) => {
        const style = typeStyles[n.type];
        return (
          <div
            key={n.id}
            style={{
              pointerEvents: "auto",
              background: style.bg,
              border: `1px solid ${style.border}`,
              borderRadius: 6,
              padding: "10px 14px",
              display: "flex",
              alignItems: "flex-start",
              gap: 10,
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
              animation: "toast-slide-in 0.25s ease-out",
            }}
          >
            <span
              style={{
                fontSize: 14,
                lineHeight: "18px",
                flexShrink: 0,
                color: style.border,
              }}
            >
              {style.icon}
            </span>
            <span
              style={{
                fontSize: 12,
                color: "#e0e0e0",
                flex: 1,
                lineHeight: "18px",
                wordBreak: "break-word",
              }}
            >
              {n.message}
            </span>
            <button
              type="button"
              onClick={() => onDismiss(n.id)}
              style={{
                background: "none",
                border: "none",
                color: "#888",
                cursor: "pointer",
                fontSize: 14,
                padding: 0,
                lineHeight: "18px",
                flexShrink: 0,
              }}
              title="Dismiss"
              aria-label="Dismiss notification"
            >
              {"\u2715"}
            </button>
          </div>
        );
      })}
    </div>
  );
}
