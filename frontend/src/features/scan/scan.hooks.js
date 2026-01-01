import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { scanApi } from "../../services/api";

export function useScanStatus() {
  return useQuery({
    queryKey: ["scanStatus"],
    queryFn: scanApi.getStatus,
    refetchInterval: (query) => {
      // Poll every 1s if scanning, else 5s or stop
      return query.state.data?.is_scanning ? 1000 : 5000;
    },
    refetchIntervalInBackground: true,
  });
}

export function useStartScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scanApi.start,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scanStatus"] });
      // We might also want to reset results or logs here
    },
  });
}

export function useStopScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scanApi.stop,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scanStatus"] });
    },
  });
}

export function useScanResults() {
  const { data: status } = useScanStatus();
  return useQuery({
    queryKey: ["scanResults"],
    queryFn: scanApi.getResults,
    enabled: !status?.is_scanning, // Fetch only when not scanning? Or allows manual fetch.
    options: {
      // We only really need to fetch when status changes to !is_scanning
      // But react-query handles caching well.
    },
  });
}
