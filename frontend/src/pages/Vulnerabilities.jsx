import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import VulnerabilityTable from '../components/VulnerabilityTable';
import RemediationModal from '../components/RemediationModal';

export default function Vulnerabilities() {
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [activeModalVuln, setActiveModalVuln] = useState(null);
  const [modalPatches, setModalPatches] = useState([]);

  const loadVulnerabilities = async () => {
    try {
      const data = await api.getVulnerabilities();
      setVulnerabilities(data);
    } catch (err) {
      console.error('Error loading vulnerabilities:', err);
    }
  };

  useEffect(() => {
    loadVulnerabilities();
  }, []);

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
      await loadVulnerabilities();
    } catch (err) {
      console.error('Failed to update status:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-cyan-400">🛡️</span> Vulnerability Management & Triage Matrix
          </h2>
          <p className="text-xs text-slate-400">
            Validated vulnerabilities mapped to OWASP Top 10 and Common Weakness Enumeration (CWE)
          </p>
        </div>
        <button
          onClick={loadVulnerabilities}
          className="px-3 py-1.5 bg-[#111827] hover:bg-[#1a2333] border border-[#1f293d] text-slate-300 rounded-lg text-xs font-semibold"
        >
          🔄 Refresh
        </button>
      </div>

      {/* Vulnerability Table Component */}
      <VulnerabilityTable
        vulnerabilities={vulnerabilities}
        onSelectRemediate={handleSelectRemediate}
        onUpdateStatus={handleUpdateStatus}
      />

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
