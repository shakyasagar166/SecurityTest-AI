import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const client = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  // Security Dashboard & Pipeline
  getDashboardStats: async () => {
    const res = await client.get('/api/security/dashboard-stats');
    return res.data;
  },

  triggerScan: async (payload) => {
    const res = await client.post('/api/security/scan', payload);
    return res.data;
  },

  // Scans & Targets
  getScans: async () => {
    const res = await client.get('/api/scans');
    return res.data;
  },

  getScan: async (scanId) => {
    const res = await client.get(`/api/scans/${scanId}`);
    return res.data;
  },

  getScanLogs: async (scanId) => {
    const res = await client.get(`/api/scans/${scanId}/logs`);
    return res.data;
  },

  getTargets: async () => {
    const res = await client.get('/api/scans/targets/list');
    return res.data;
  },

  createTarget: async (targetData) => {
    const res = await client.post('/api/scans/targets/create', targetData);
    return res.data;
  },

  // Vulnerabilities & Remediations
  getVulnerabilities: async (params = {}) => {
    const res = await client.get('/api/vulnerabilities', { params });
    return res.data;
  },

  getVulnerability: async (vulnId) => {
    const res = await client.get(`/api/vulnerabilities/${vulnId}`);
    return res.data;
  },

  updateVulnerabilityStatus: async (vulnId, status) => {
    const res = await client.patch(`/api/vulnerabilities/${vulnId}/status?status=${status}`);
    return res.data;
  },

  getRemediation: async (vulnId) => {
    const res = await client.get(`/api/vulnerabilities/${vulnId}/remediation`);
    return res.data;
  },

  // Reports
  getReports: async () => {
    const res = await client.get('/api/reports');
    return res.data;
  },

  getReport: async (reportId) => {
    const res = await client.get(`/api/reports/${reportId}`);
    return res.data;
  },

  downloadReportUrl: (reportId) => {
    return `${API_BASE}/api/reports/${reportId}/download`;
  }
};
