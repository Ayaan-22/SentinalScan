import axios from "axios";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000/api/v1";
export const WS_BASE = import.meta.env.VITE_WS_URL || "ws://localhost:8000";
const SESSION_KEY = "sentinalscan.apiKey";

function getApiRoot() {
  return API_BASE.replace(/\/api\/v1\/?$/, "");
}

export function getApiKey() {
  return sessionStorage.getItem(SESSION_KEY) || import.meta.env.VITE_API_KEY || "";
}

export function setApiKey(apiKey) {
  const trimmed = apiKey.trim();
  if (trimmed) {
    sessionStorage.setItem(SESSION_KEY, trimmed);
  } else {
    sessionStorage.removeItem(SESSION_KEY);
  }
}

export function hasApiKey() {
  return Boolean(getApiKey());
}

export function getFriendlyApiError(error) {
  const detail = error?.response?.data?.detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg || item.message).filter(Boolean).join("; ");
  }
  if (typeof detail === "string") return detail;
  if (error?.response?.status === 401) return "Missing API key. Enter the key configured on the backend.";
  if (error?.response?.status === 403) return "Invalid API key. Check that it matches SENTINAL_API_KEY.";
  return error?.message || "Request failed";
}

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => {
  const apiKey = getApiKey();
  if (apiKey) {
    config.headers["X-API-Key"] = apiKey;
  }
  return config;
});

export const scanApi = {
  health: async () => {
    const { data } = await axios.get(`${getApiRoot()}/health`, { timeout: 2500 });
    return data;
  },

  start: async (config) => {
    // Backend expects POST /scan/ (trailing slash optional in FastAPI but good practice)
    // Returns { scan_id, status, target_url, ... }
    const { data } = await api.post("/scan/", config);
    return data;
  },
  
  list: async () => {
    const { data } = await api.get("/scan/");
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
