import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 10000,
});

export const socApi = {
  // Alerts
  getAlerts: async (params = {}) => {
    const response = await api.get('/alerts', { params });
    return response.data;
  },

  getAlertById: async (id) => {
    const response = await api.get(`/alerts/${id}`);
    return response.data;
  },

  getAlertReport: async (id) => {
    const response = await api.get(`/alerts/${id}/report`);
    return response.data;
  },

  ingestAlert: async (alertData) => {
    const response = await api.post('/alerts', alertData);
    return response.data;
  },

  simulateAlert: async () => {
    const response = await api.post('/alerts/simulate/inject');
    return response.data;
  },

  // Analyst Mitigation Actions
  takeAction: async (id, actionData) => {
    const response = await api.post(`/alerts/${id}/action`, actionData);
    return response.data;
  },

  // Operations Metrics
  getMetrics: async () => {
    const response = await api.get('/metrics');
    return response.data;
  },
};

export default api;
