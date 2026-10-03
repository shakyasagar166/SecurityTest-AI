import React, { useState } from 'react';

export default function TargetInput({ onStartScan, isScanning }) {
  const [targetLocation, setTargetLocation] = useState('target_samples/vulnerable_app.py');
  const [targetUrl, setTargetUrl] = useState('http://localhost:5000');
  const [scanType, setScanType] = useState('full');
  const [generatePatches, setGeneratePatches] = useState(true);

  const handleSubmit = (e) => {
    e.preventDefault();
    onStartScan({
      target_location: targetLocation,
      target_url: targetUrl,
      scan_type: scanType,
      generate_patches: generatePatches,
    });
  };

  return (
    <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-6 shadow-xl relative overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 via-indigo-500 to-emerald-500"></div>

      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <span className="text-cyan-400">⚡</span> Launch Multi-Agent Security Audit
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Dispatch ReconAgent, SASTAgent, DASTAgent, ExploitValidator & RemediationAgent
          </p>
        </div>
        <span className="px-3 py-1 rounded-full text-xs font-semibold bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
          Autonomous Graph v1.0
        </span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Source Code Path or Repository Target
            </label>
            <input
              type="text"
              value={targetLocation}
              onChange={(e) => setTargetLocation(e.target.value)}
              placeholder="e.g. target_samples/vulnerable_app.py"
              className="w-full bg-[#0a0f1d] border border-[#1f293d] rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Live Web Endpoint / Service URL
            </label>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="e.g. http://localhost:5000"
              className="w-full bg-[#0a0f1d] border border-[#1f293d] rounded-lg px-3 py-2 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Audit Scope Profile
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              className="w-full bg-[#0a0f1d] border border-[#1f293d] rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="full">Full Audit (Recon + SAST + DAST + Patches)</option>
              <option value="sast_only">SAST Only (Source Code & Dependencies)</option>
              <option value="dast_only">DAST Only (Live Endpoints & Headers)</option>
              <option value="recon_only">Recon Only (Ports, Services & Headers)</option>
            </select>
          </div>

          <div className="flex items-center gap-3 pt-6">
            <input
              type="checkbox"
              id="patchesCheck"
              checked={generatePatches}
              onChange={(e) => setGeneratePatches(e.target.checked)}
              className="w-4 h-4 rounded bg-[#0a0f1d] border-[#1f293d] text-cyan-500 focus:ring-0 cursor-pointer"
            />
            <label htmlFor="patchesCheck" className="text-xs font-medium text-slate-300 cursor-pointer">
              Auto-Synthesize Unified Diff Patches
            </label>
          </div>

          <div className="flex items-end justify-end">
            <button
              type="submit"
              disabled={isScanning}
              className={`w-full md:w-auto px-6 py-2 rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition-all ${
                isScanning
                  ? 'bg-slate-700 text-slate-400 cursor-not-allowed'
                  : 'bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white shadow-lg shadow-cyan-900/30'
              }`}
            >
              {isScanning ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-cyan-400" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                  <span>Executing Pipeline...</span>
                </>
              ) : (
                <>
                  <span>🚀</span>
                  <span>Start Security Audit</span>
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
