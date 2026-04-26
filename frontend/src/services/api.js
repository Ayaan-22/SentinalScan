import axios from "axios";

// Look for VITE_API_URL first, fallback to locahost is discouraged but kept for safety
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";
const API_KEY = import.meta.env.VITE_API_KEY || "dev_api_key_12345";

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": API_KEY,
  },
});

export const scanApi = {
  start: async (config) => {
    // Backend expects POST /scan/ (trailing slash optional in FastAPI but good practice)
    // Returns { scan_id, status, target_url, ... }
    const { data } = await api.post("/scan/", config);
    return data;
  },

  stop: async (scanId) => {
    if (!scanId) throw new Error("Scan ID required to stop scan");
    const { data } = await api.post(`/scan/${scanId}/stop`);
    return data;
  },

  getStatus: async (scanId) => {
    if (!scanId) throw new Error("Scan ID required to get status");
    const { data } = await api.get(`/scan/${scanId}`);
    return data;
  },

  getResults: async (scanId) => {
    if (!scanId) throw new Error("Scan ID required to get results");
    const { data } = await api.get(`/scan/${scanId}/results`);
    return data;
  },

  getLogs: async (scanId) => {
    if (!scanId) return [];
    const { data } = await api.get(`/scan/${scanId}/logs`);
    return data;
  },
};
