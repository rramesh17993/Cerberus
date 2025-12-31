/**
 * 🔌 WebSocket Context - Manages real-time connections
 */

import React, { createContext, useContext, useEffect, useState, useRef } from 'react';

interface WebSocketContextType {
  socket: WebSocket | null;
  isConnected: boolean;
  subscribe: (channel: string, callback: (data: any) => void) => void;
  unsubscribe: (channel: string) => void;
  send: (message: any) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [socket, setSocket] = useState<WebSocket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const subscriptions = useRef<Map<string, (data: any) => void>>(new Map());

  useEffect(() => {
    // TODO: Connect to actual WebSocket endpoint
    // const ws = new WebSocket('ws://localhost:8000/ws');
    
    const mockSocket = {
      send: (data: string) => console.log('WebSocket send:', data),
      close: () => console.log('WebSocket closed'),
      addEventListener: () => {},
      removeEventListener: () => {},
    } as any;

    setSocket(mockSocket);
    setIsConnected(true);

    return () => {
      if (socket) {
        socket.close();
      }
    };
  }, []);

  const subscribe = (channel: string, callback: (data: any) => void) => {
    subscriptions.current.set(channel, callback);
  };

  const unsubscribe = (channel: string) => {
    subscriptions.current.delete(channel);
  };

  const send = (message: any) => {
    if (socket && isConnected) {
      socket.send(JSON.stringify(message));
    }
  };

  const value: WebSocketContextType = {
    socket,
    isConnected,
    subscribe,
    unsubscribe,
    send,
  };

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>;
};

export const useWebSocket = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (context === undefined) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};