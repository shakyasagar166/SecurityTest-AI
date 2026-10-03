import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [selectedLogs, setSelectedLogs] = useState(null);
  const [selectedScanId, setSelectedScanId] = useState(null);

  const loadScans = async () => {
    try {
      const data = await api.getScans();
      setScans(data);
    } catch (err) {
      console.error('Error loading scans:', err);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleViewLogs = async (scanId) => {
    setSelectedScanId(scanId);
    try {
      const res = await api.getScanLogs(scanId);
      setSelectedLogs(res.logs || []);
    } catch (err) {
      setSelectedLogs(['Failed to load logs for this scan.']);
    }
  };

  const getRiskColor = (risk) => {
    switch (risk) {
      case 'CRITICAL':
        return 'text-rose-400 bg-rose-950/40 border-rose-800';
      case 'HIGH':
        return 'text-orange-400 bg-orange-950/40 border-orange-800';
      case 'MEDIUM':
        return 'text-amber-400 bg-amber-950/40 border-amber-800';
      default:
        return 'text-emerald-400 bg-emerald-950/40 border-emerald-800';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-cyan-400">📋</span> Security Audit Runs & History
          </h2>
          <p className="text-xs text-slate-400">
            Historical audit logs, posture scores, and multi-agent execution traces
          </p>
        </div>
        <button
          onClick={loadScans}
          className="px-3 py-1.5 bg-[#111827] hover:bg-[#1a2333] border border-[#1f293d] text-slate-300 rounded-lg text-xs font-semibold"
        >
          🔄 Refresh
        </button>
      </div>

      <div className="bg-[#111827] border border-[#1f293d] rounded-xl overflow-hidden shadow-lg">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-[#0a0f1d] text-slate-400 uppercase tracking-wider text-[11px] border-b border-[#1f293d]">
              <tr>
                <th className="px-4 py-3">Scan ID</th>
                <th className="px-4 py-3">Target Name</th>
                <th className="px-4 py-3">Profile</th>
                <th className="px-4 py-3">Score & Risk</th>
                <th className="px-4 py-3">Findings</th>
                <th className="px-4 py-3">Duration</th>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3 text-right">Logs</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1f293d]">
              {scans.length === 0 ? (
                <tr>
                  <td colSpan="8" className="text-center py-8 text-slate-500">
                    No scans registered yet.
                  </td>
                </tr>
              ) : (
                scans.map((s) => (
                  <tr key={s.id} className="hover:bg-[#1a2333]/50 transition-colors">
                    <td className="px-4 py-3.5 font-mono text-cyan-400 font-semibold whitespace-nowrap">
                      {s.id}
                    </td>
                    <td className="px-4 py-3.5 text-white font-medium">
                      {s.target_name}
                    </td>
                    <td className="px-4 py-3.5 uppercase font-mono text-[11px] text-slate-400">
                      {s.scan_type}
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap">
                      <span className="font-mono text-white font-bold mr-2">{s.security_score}/100</span>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getRiskColor(s.risk_level)}`}>
                        {s.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-3.5 whitespace-nowrap text-slate-300">
                      <span className="text-rose-400 font-bold">{s.critical_count}C</span> /{' '}
                      <span className="text-orange-400 font-bold">{s.high_count}H</span> /{' '}
                      <span className="text-amber-400 font-bold">{s.medium_count}M</span>
                    </td>
                    <td className="px-4 py-3.5 font-mono text-slate-400">
                      {s.duration_seconds}s
                    </td>
                    <td className="px-4 py-3.5 text-slate-400 whitespace-nowrap">
                      {new Date(s.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3.5 text-right whitespace-nowrap">
                      <button
                        onClick={() => handleViewLogs(s.id)}
                        className="px-2.5 py-1 bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 rounded text-xs transition-all"
                      >
                        Trace Logs
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Log Modal */}
      {selectedLogs && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-[#111827] border border-[#1f293d] rounded-2xl w-full max-w-2xl max-h-[80vh] flex flex-col shadow-2xl overflow-hidden font-mono">
            <div className="p-4 border-b border-[#1f293d] flex items-center justify-between">
              <span className="text-xs font-bold text-cyan-400">
                Execution Logs: {selectedScanId}
              </span>
              <button
                onClick={() => setSelectedLogs(null)}
                className="text-slate-400 hover:text-white"
              >
                ✕
              </button>
            </div>
            <div className="p-4 overflow-y-auto space-y-1 text-xs text-slate-300 bg-[#060a14] flex-1">
              {selectedLogs.length === 0 ? (
                <div className="text-slate-600">No logs captured for this scan.</div>
              ) : (
                selectedLogs.map((l, i) => (
                  <div key={i} className="leading-relaxed">
                    <span className="text-slate-600 mr-2">&gt;</span>
                    {l}
                  </div>
                ))
              )}
            </div>
            <div className="p-3 border-t border-[#1f293d] bg-[#0a0f1d] flex justify-end">
              <button
                onClick={() => setSelectedLogs(null)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
