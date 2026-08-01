import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import ThreatAlertToastStack from "@/components/alerts/ThreatAlertToastStack";
import { buildWebSocketUrl } from "@/config/env";
import { useAuth } from "@/hooks/useAuth";
import type { ThreatAlertMessage, ThreatAlertSocketMessage, ThreatAlertSocketStatus } from "@/types/threatAlertSocket";
import { getAccessToken } from "@/utils";

const MAX_VISIBLE_ALERTS = 5;
const RECONNECT_BASE_MS = 2000;
const RECONNECT_MAX_MS = 30000;
const PING_INTERVAL_MS = 30000;

interface ThreatAlertSocketContextValue {
  status: ThreatAlertSocketStatus;
  alerts: ThreatAlertMessage[];
  dismissAlert: (alertId: string) => void;
  subscribeToAlerts: (listener: (alert: ThreatAlertMessage) => void) => () => void;
}

const ThreatAlertSocketContext = createContext<ThreatAlertSocketContextValue | undefined>(undefined);

function parseSocketMessage(rawMessage: string): ThreatAlertSocketMessage | null {
  try {
    return JSON.parse(rawMessage) as ThreatAlertSocketMessage;
  } catch {
    return null;
  }
}

export function ThreatAlertSocketProvider({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  const [status, setStatus] = useState<ThreatAlertSocketStatus>("idle");
  const [alerts, setAlerts] = useState<ThreatAlertMessage[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);
  const pingTimerRef = useRef<number | null>(null);
  const listenersRef = useRef<Set<(alert: ThreatAlertMessage) => void>>(new Set());

  const dismissAlert = useCallback((alertId: string) => {
    setAlerts((currentAlerts) => currentAlerts.filter((alert) => alert.alert_id !== alertId));
  }, []);

  const subscribeToAlerts = useCallback((listener: (alert: ThreatAlertMessage) => void) => {
    listenersRef.current.add(listener);
    return () => {
      listenersRef.current.delete(listener);
    };
  }, []);

  const notifyListeners = useCallback((alert: ThreatAlertMessage) => {
    listenersRef.current.forEach((listener) => listener(alert));
  }, []);

  const pushAlert = useCallback(
    (alert: ThreatAlertMessage) => {
      setAlerts((currentAlerts) => {
        const withoutDuplicate = currentAlerts.filter((item) => item.alert_id !== alert.alert_id);
        return [alert, ...withoutDuplicate].slice(0, MAX_VISIBLE_ALERTS);
      });
      notifyListeners(alert);
    },
    [notifyListeners],
  );

  const clearTimers = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }

    if (pingTimerRef.current !== null) {
      window.clearInterval(pingTimerRef.current);
      pingTimerRef.current = null;
    }
  }, []);

  const disconnect = useCallback(() => {
    clearTimers();

    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
  }, [clearTimers]);

  const connect = useCallback(() => {
    const token = getAccessToken();
    if (!isAuthenticated || !token) {
      setStatus("idle");
      disconnect();
      return;
    }

    disconnect();
    setStatus("connecting");

    const socket = new WebSocket(buildWebSocketUrl(token));
    socketRef.current = socket;

    socket.onopen = () => {
      reconnectAttemptRef.current = 0;
      setStatus("connected");

      pingTimerRef.current = window.setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send("ping");
        }
      }, PING_INTERVAL_MS);
    };

    socket.onmessage = (event) => {
      const message = parseSocketMessage(String(event.data));
      if (!message) {
        return;
      }

      if (message.type === "threat_alert" && message.data.alert_id) {
        pushAlert(message.data);
      }
    };

    socket.onerror = () => {
      setStatus("error");
    };

    socket.onclose = () => {
      clearTimers();
      socketRef.current = null;

      if (!isAuthenticated) {
        setStatus("idle");
        return;
      }

      setStatus("disconnected");
      const delay = Math.min(
        RECONNECT_BASE_MS * 2 ** reconnectAttemptRef.current,
        RECONNECT_MAX_MS,
      );
      reconnectAttemptRef.current += 1;

      reconnectTimerRef.current = window.setTimeout(() => {
        connect();
      }, delay);
    };
  }, [clearTimers, disconnect, isAuthenticated, pushAlert]);

  useEffect(() => {
    if (!isAuthenticated) {
      disconnect();
      setStatus("idle");
      setAlerts([]);
      return;
    }

    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect, isAuthenticated]);

  const value = useMemo(
    () => ({
      status,
      alerts,
      dismissAlert,
      subscribeToAlerts,
    }),
    [status, alerts, dismissAlert, subscribeToAlerts],
  );

  return (
    <ThreatAlertSocketContext.Provider value={value}>
      {children}
      <ThreatAlertToastStack alerts={alerts} onDismiss={dismissAlert} status={status} />
    </ThreatAlertSocketContext.Provider>
  );
}

export function useThreatAlertSocket() {
  const context = useContext(ThreatAlertSocketContext);

  if (!context) {
    throw new Error("useThreatAlertSocket must be used within a ThreatAlertSocketProvider");
  }

  return context;
}
