import { useEffect, useState, useRef } from "react";
import { LogWebSocket } from "../../services/websocket";
import { useQueryClient } from "@tanstack/react-query";

export function useScanLogs() {
  const [logs, setLogs] = useState([]);
  const wsRef = useRef(null);
  const queryClient = useQueryClient();

  useEffect(() => {
    const wsUrl = "ws://localhost:8000/ws/logs";

    wsRef.current = new LogWebSocket(
      wsUrl,
      (data) => {
        setLogs((prev) => [...prev, data].slice(-1000));

        if (
          data.message &&
          data.message.includes("Scan finished successfully")
        ) {
          queryClient.invalidateQueries({ queryKey: ["scanStatus"] });
          queryClient.invalidateQueries({ queryKey: ["scanResults"] });
        }
      },
      (error) => {
        console.error("WS Error", error);
      }
    );

    wsRef.current.connect();

    return () => {
      wsRef.current.disconnect();
    };
  }, [queryClient]);

  const clearLogs = () => setLogs([]);

  return { logs, clearLogs };
}
