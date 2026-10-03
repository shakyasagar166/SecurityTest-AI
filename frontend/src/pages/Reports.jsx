import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

export default function Reports() {
  const [reports, setReports] = useState([]);
  const [selectedReport, setSelectedReport] = useState(null);

  const loadReports = async () => {
    try {
      const data = await api.getReports();
      setReports(data);
      if (data.length > 0 && !selectedReport) {
        setSelectedReport(data[0]);
      }
    } catch (err) {
      console.error('Error loading reports:', err);
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const getRiskBadge = (risk) => {
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
            <span className="text-cyan-400">📄</span> Security Audit Reports
          </h2>
          <p className="text-xs text-slate-400">
            Executive summaries and technical vulnerability disclosures
          </p>
        </div>
        <button
          onClick={loadReports}
          className="px-3 py-1.5 bg-[#111827] hover:bg-[#1a2333] border border-[#1f293d] text-slate-300 rounded-lg text-xs font-semibold"
        >
          🔄 Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Reports Navigation Sidebar */}
        <div className="space-y-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Available Reports ({reports.length})
          </span>
          <div className="space-y-2">
            {reports.length === 0 ? (
              <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-4 text-center text-xs text-slate-500">
                No audit reports generated yet.
              </div>
            ) : (
              reports.map((r) => (
                <div
                  key={r.id}
                  onClick={() => setSelectedReport(r)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    selectedReport?.id === r.id
                      ? 'bg-[#1a2333] border-cyan-500 shadow-md shadow-cyan-950/30'
                      : 'bg-[#111827] border-[#1f293d] hover:border-slate-600'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="font-mono text-cyan-400 text-xs font-bold">
                      {r.report_code}
                    </span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getRiskBadge(r.risk_level)}`}>
                      {r.risk_level}
                    </span>
                  </div>
                  <h4 className="text-xs font-semibold text-white truncate">
                    {r.title}
                  </h4>
                  <span className="text-[11px] text-slate-500 block mt-1">
                    {new Date(r.created_at).toLocaleDateString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Selected Report Viewer */}
        <div className="lg:col-span-2">
          {selectedReport ? (
            <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-[#1f293d]">
                <div>
                  <span className="text-xs font-mono text-cyan-400 font-semibold">
                    {selectedReport.report_code}
                  </span>
                  <h3 className="text-lg font-bold text-white mt-0.5">
                    {selectedReport.title}
                  </h3>
                </div>
                <a
                  href={api.downloadReportUrl(selectedReport.id)}
                  download={`${selectedReport.report_code}.md`}
                  className="px-3 py-1.5 bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow"
                >
                  <span>⬇️</span>
                  <span>Download Report (.md)</span>
                </a>
              </div>

              {/* Executive Summary Callout */}
              <div className="bg-[#0a0f1d] border border-[#1f293d] rounded-lg p-4">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Executive Briefing
                </span>
                <p className="text-xs text-slate-300 leading-relaxed">
                  {selectedReport.executive_summary}
                </p>
              </div>

              {/* Raw Markdown / Technical Details Display */}
              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
                  Technical Audit Transcript
                </span>
                <div className="bg-[#060a14] border border-[#1f293d] rounded-xl p-4 max-h-[500px] overflow-y-auto text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed">
                  {selectedReport.markdown_content}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-12 text-center text-slate-500 text-xs">
              Select an audit report from the left sidebar to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
