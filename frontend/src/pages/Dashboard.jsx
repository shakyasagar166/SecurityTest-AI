import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import SecurityScoreWidget from '../components/SecurityScoreWidget';
import TargetInput from '../components/TargetInput';
import ScanConsole from '../components/ScanConsole';
import VulnerabilityCard from '../components/VulnerabilityCard';
import RemediationModal from '../components/RemediationModal';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [recentVulns, setRecentVulns] = useState([]);
  const [logs, setLogs] = useState([]);
  const [isScanning, setIsScanning] = useState(false);
  const [activeModalVuln, setActiveModalVuln] = useState(null);
  const [modalPatches, setModalPatches] = useState([]);

  const loadData = async () => {
    try {
      const statsData = await api.getDashboardStats();
      setStats(statsData);

      const vulnsData = await api.getVulnerabilities({ severity: 'CRITICAL' });
      const highVulns = await api.getVulnerabilities({ severity: 'HIGH' });
      setRecentVulns([...vulnsData, ...highVulns].slice(0, 6));
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleStartScan = async (payload) => {
    setIsScanning(true);
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] Dispatching multi-agent security audit...`]);

    try {
      const res = await api.triggerScan(payload);
      if (res.logs) {
        setLogs(res.logs);
      }
      await loadData();
    } catch (err) {
      setLogs((prev) => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] Audit error: ${err.response?.data?.detail || err.message}`,
      ]);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectRemediate = async (vuln) => {
    setActiveModalVuln(vuln);
    try {
      const patches = await api.getRemediation(vuln.id);
      setModalPatches(patches);
    } catch (err) {
      console.error('Error fetching patches:', err);
    }
  };

  const handleUpdateStatus = async (vulnId, newStatus) => {
    try {
      await api.updateVulnerabilityStatus(vulnId, newStatus);
      await loadData();
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Posture & Score Overview */}
      <SecurityScoreWidget stats={stats} />

      {/* Target Input Scan Trigger */}
      <TargetInput onStartScan={handleStartScan} isScanning={isScanning} />

      {/* Live Agent Console */}
      <ScanConsole logs={logs} isScanning={isScanning} />

      {/* High-Risk Findings Section */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="text-rose-500">🚨</span> High-Priority Security Findings
            </h2>
            <p className="text-xs text-slate-400">
              Critical and high vulnerabilities demanding immediate remediation
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">
            Showing {recentVulns.length} severe issues
          </span>
        </div>

        {recentVulns.length === 0 ? (
          <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-8 text-center text-slate-400 text-xs">
            No critical or high vulnerabilities detected. Your target has clean security posture!
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {recentVulns.map((vuln) => (
              <VulnerabilityCard
                key={vuln.id}
                vuln={vuln}
                onSelectRemediate={handleSelectRemediate}
                onUpdateStatus={handleUpdateStatus}
              />
            ))}
          </div>
        )}
      </div>

      {/* Remediation Patch Modal */}
      {activeModalVuln && (
        <RemediationModal
          vuln={activeModalVuln}
          patches={modalPatches}
          onClose={() => setActiveModalVuln(null)}
          onApplyPatch={(vulnId) => handleUpdateStatus(vulnId, 'patched')}
        />
      )}
    </div>
  );
}
