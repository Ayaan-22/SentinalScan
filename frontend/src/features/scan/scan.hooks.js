import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi } from "../../services/api";

export function useScanStatus(scanId) {
  return useQuery({
    queryKey: ["scanStatus", scanId],
    queryFn: () => scanApi.getStatus(scanId),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const scanStatus = query.state?.data?.status;
      // Poll every 1.5s if running or pending
      return scanStatus === "running" || scanStatus === "pending" ? 1500 : false;
    },
  });
}

export function useScanLogs(scanId, isScanning) {
  return useQuery({
    queryKey: ["scanLogs", scanId],
    queryFn: () => scanApi.getLogs(scanId),
    enabled: !!scanId,
    refetchInterval: isScanning ? 1500 : false,
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (config) => {
      // Build the proper payload for the backend
      const payload = {
        target_url: config.target_url,
        max_pages: config.max_pages || 50,
        workers: config.workers || 5,
        timeout: config.timeout || 15,
        verify_ssl: config.verify_ssl ?? true,
        obey_robots: config.obey_robots ?? true,
      };

      // Parse advanced options if present
      if (config.auth_token) payload.auth_token = config.auth_token;
      if (config.cookies_str) {
        const cookies = {};
        config.cookies_str.split(";").forEach((part) => {
          const [k, v] = part.split("=");
          if (k?.trim() && v?.trim()) cookies[k.trim()] = v.trim();
        });
        if (Object.keys(cookies).length > 0) payload.cookies = cookies;
      }
      if (config.headers_str) {
        const headers = {};
        config.headers_str.split(";").forEach((part) => {
          const [k, v] = part.split(":");
          if (k?.trim() && v?.trim()) headers[k.trim()] = v.trim();
        });
        if (Object.keys(headers).length > 0) payload.headers = headers;
      }
      if (config.exclude_paths_str) {
        const paths = config.exclude_paths_str
          .split(",")
          .map((p) => p.trim())
          .filter(Boolean);
        if (paths.length > 0) payload.exclude_paths = paths;
      }

      return scanApi.start(payload);
    },
    onSuccess: () => {
      // Invalidate any stale scan queries
      queryClient.invalidateQueries({ queryKey: ["scanStatus"] });
    },
  });
}

export function useStopScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scanApi.stop,
    onSuccess: (data, scanId) => {
      queryClient.invalidateQueries({ queryKey: ["scanStatus", scanId] });
      queryClient.invalidateQueries({ queryKey: ["scanResults", scanId] });
    },
  });
}

export function useScanResults(scanId, isScanning) {
  return useQuery({
    queryKey: ["scanResults", scanId],
    queryFn: () => scanApi.getResults(scanId),
    enabled: !!scanId && !isScanning,
    // Refetch once when scan completes
    staleTime: 5000,
  });
}
