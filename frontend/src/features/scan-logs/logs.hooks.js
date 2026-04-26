import { useScanLogs as useScanLogsQuery } from "../scan/scan.hooks";

export function useScanLogs(scanId, isScanning) {
  const { data: logs = [] } = useScanLogsQuery(scanId, isScanning);
  return { logs };
}
