import axios from "axios";

const API_BASE = "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    "Content-Type": "application/json",
  },
});

export const scanApi = {
  start: async (config) => {
    const { data } = await api.post("/scan/start", config);
    return data;
  },
  stop: async () => {
    const { data } = await api.post("/scan/stop");
    return data;
  },
  getStatus: async () => {
    const { data } = await api.get("/scan/status");
    return data;
  },
  getResults: async () => {
    const { data } = await api.get("/scan/results");
    return data;
  },
};
