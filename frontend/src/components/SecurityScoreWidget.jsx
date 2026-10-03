import React from 'react';

export default function SecurityScoreWidget({ stats }) {
  const score = stats?.average_security_score ?? 100;
  const posture = stats?.overall_posture ?? 'SECURE';

  const getScoreColor = (val) => {
    if (val >= 85) return 'text-emerald-400 border-emerald-500/40 bg-emerald-950/20';
    if (val >= 70) return 'text-amber-400 border-amber-500/40 bg-amber-950/20';
    if (val >= 40) return 'text-orange-400 border-orange-500/40 bg-orange-950/20';
    return 'text-rose-500 border-rose-500/40 bg-rose-950/20';
  };

  const getPostureBadge = (pos) => {
    if (pos.includes('CRITICAL')) return 'bg-rose-500/20 text-rose-400 border-rose-500/40';
    if (pos.includes('HIGH')) return 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    if (pos.includes('MODERATE')) return 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    return 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
      {/* Score Card */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 flex items-center gap-4">
        <div className={`w-16 h-16 rounded-full border-4 flex items-center justify-center font-bold text-2xl font-mono ${getScoreColor(score)}`}>
          {score}
        </div>
        <div>
          <div className="text-xs uppercase font-medium tracking-wider text-slate-400">Security Score</div>
          <span className={`inline-block mt-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${getPostureBadge(posture)}`}>
            {posture}
          </span>
        </div>
      </div>

      {/* Critical & High */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 flex flex-col justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-400">High Risk Vectors</span>
        <div className="flex items-baseline gap-4 mt-2">
          <div>
            <span className="text-3xl font-extrabold text-rose-500 font-mono">
              {stats?.critical_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-rose-400/80 block">Critical</span>
          </div>
          <div className="border-l border-[#1f293d] pl-4">
            <span className="text-3xl font-extrabold text-orange-400 font-mono">
              {stats?.high_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-orange-400/80 block">High</span>
          </div>
        </div>
      </div>

      {/* Medium & Low */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 flex flex-col justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-400">Moderate / Low</span>
        <div className="flex items-baseline gap-4 mt-2">
          <div>
            <span className="text-3xl font-extrabold text-amber-400 font-mono">
              {stats?.medium_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-amber-400/80 block">Medium</span>
          </div>
          <div className="border-l border-[#1f293d] pl-4">
            <span className="text-3xl font-extrabold text-blue-400 font-mono">
              {stats?.low_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-blue-400/80 block">Low/Info</span>
          </div>
        </div>
      </div>

      {/* Audit Pipeline Stats */}
      <div className="bg-[#111827] border border-[#1f293d] rounded-xl p-5 flex flex-col justify-between">
        <span className="text-xs uppercase tracking-wider text-slate-400">Audits & Fixes</span>
        <div className="flex items-baseline gap-4 mt-2">
          <div>
            <span className="text-3xl font-extrabold text-cyan-400 font-mono">
              {stats?.total_scans ?? 0}
            </span>
            <span className="text-xs text-cyan-400/80 block">Total Audits</span>
          </div>
          <div className="border-l border-[#1f293d] pl-4">
            <span className="text-3xl font-extrabold text-emerald-400 font-mono">
              {stats?.remediated_vulnerabilities ?? 0}
            </span>
            <span className="text-xs text-emerald-400/80 block">Patched</span>
          </div>
        </div>
      </div>
    </div>
  );
}
