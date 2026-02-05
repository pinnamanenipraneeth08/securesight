/**
 * WebSocket Hook for Real-Time Updates
 */

import { useEffect, useRef, useCallback, useState } from 'react';
import { useAuthStore } from '../stores/authStore';

type WebSocketChannel = 'alerts' | 'events' | 'logs' | 'dashboard';

interface WebSocketMessage {
  type: string;
  timestamp: string;
  data?: any;
  message?: string;
  channel?: string;
}

interface UseWebSocketOptions {
  channel: WebSocketChannel;
  onMessage?: (message: WebSocketMessage) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: Event) => void;
  autoReconnect?: boolean;
  reconnectInterval?: number;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  lastMessage: WebSocketMessage | null;
  send: (data: string) => void;
  disconnect: () => void;
  reconnect: () => void;
}

const WS_BASE_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/api/v1';

export function useWebSocket(options: UseWebSocketOptions): UseWebSocketReturn {
  const {
    channel,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
    autoReconnect = true,
    reconnectInterval = 5000,
  } = options;

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pingIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null);
  const { token } = useAuthStore();

  // Use refs for callbacks to avoid dependency changes causing reconnects
  const onMessageRef = useRef(onMessage);
  const onConnectRef = useRef(onConnect);
  const onDisconnectRef = useRef(onDisconnect);
  const onErrorRef = useRef(onError);
  
  // Update refs when callbacks change
  useEffect(() => {
    onMessageRef.current = onMessage;
    onConnectRef.current = onConnect;
    onDisconnectRef.current = onDisconnect;
    onErrorRef.current = onError;
  }, [onMessage, onConnect, onDisconnect, onError]);

  const connect = useCallback(() => {
    // Clear any existing connection
    if (wsRef.current) {
      wsRef.current.close();
    }

    // Build WebSocket URL with token
    const wsUrl = `${WS_BASE_URL}/ws/${channel}${token ? `?token=${token}` : ''}`;
    
    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log(`WebSocket connected to ${channel}`);
        setIsConnected(true);
        onConnectRef.current?.();

        // Start ping interval to keep connection alive
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
          }
        }, 30000);
      };

      ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);
          setLastMessage(message);
          onMessageRef.current?.(message);
        } catch (e) {
          console.warn('Failed to parse WebSocket message:', event.data);
        }
      };

      ws.onerror = (error) => {
        console.error(`WebSocket error on ${channel}:`, error);
        onErrorRef.current?.(error);
      };

      ws.onclose = (event) => {
        console.log(`WebSocket disconnected from ${channel}:`, event.code, event.reason);
        setIsConnected(false);
        onDisconnectRef.current?.();

        // Clear ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }

        // Auto-reconnect if enabled and not a normal close
        if (autoReconnect && event.code !== 1000) {
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log(`Attempting to reconnect to ${channel}...`);
            connect();
          }, reconnectInterval);
        }
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
    }
  }, [channel, token, autoReconnect, reconnectInterval]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnect');
      wsRef.current = null;
    }
    setIsConnected(false);
  }, []);

  const send = useCallback((data: string) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(data);
    }
  }, []);

  const reconnect = useCallback(() => {
    disconnect();
    connect();
  }, [disconnect, connect]);

  // Connect on mount, disconnect on unmount
  useEffect(() => {
    connect();
    return () => {
      disconnect();
    };
  }, [connect, disconnect]);

  return {
    isConnected,
    lastMessage,
    send,
    disconnect,
    reconnect,
  };
}

// Convenience hooks for specific channels
export function useAlertsWebSocket(onNewAlert?: (alert: any) => void) {
  return useWebSocket({
    channel: 'alerts',
    onMessage: (message) => {
      if (message.type === 'new_alert' && onNewAlert) {
        onNewAlert(message.data);
      }
    },
  });
}

export function useDashboardWebSocket(callbacks?: {
  onNewAlert?: (alert: any) => void;
  onStatsUpdate?: (stats: any) => void;
}) {
  return useWebSocket({
    channel: 'dashboard',
    onMessage: (message) => {
      if (message.type === 'new_alert' && callbacks?.onNewAlert) {
        callbacks.onNewAlert(message.data);
      }
      if (message.type === 'stats_update' && callbacks?.onStatsUpdate) {
        callbacks.onStatsUpdate(message.data);
      }
    },
  });
}

export function useLogsWebSocket(onNewLog?: (log: any) => void) {
  return useWebSocket({
    channel: 'logs',
    onMessage: (message) => {
      if (message.type === 'new_log' && onNewLog) {
        onNewLog(message.data);
      }
    },
  });
}
