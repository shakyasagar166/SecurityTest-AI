import React, { useState } from 'react';

export default function RemediationModal({ vuln, patches, onClose, onApplyPatch }) {
  const [copied, setCopied] = useState(false);
  const patch = patches && patches.length > 0 ? patches[0] : null;

  const handleCopy = () => {
    if (patch?.unified_diff) {
      navigator.clipboard.writeText(patch.unified_diff);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const renderDiffLine = (line, idx) => {
    if (line.startsWith('+')) {
      return (
        <div key={idx} className="bg-emerald-950/40 text-emerald-300 px-2 py-0.5 font-mono">
          {line}
        </div>
      );
    }
    if (line.startsWith('-')) {
      return (
        <div key={idx} className="bg-rose-950/40 text-rose-300 px-2 py-0.5 font-mono">
          {line}
        </div>
      );
    }
    if (line.startsWith('@@')) {
      return (
        <div key={idx} className="text-cyan-400 font-semibold px-2 py-0.5 font-mono">
          {line}
        </div>
      );
    }
    return (
      <div key={idx} className="text-slate-400 px-2 py-0.5 font-mono">
        {line}
      </div>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#111827] border border-[#1f293d] rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="p-6 border-b border-[#1f293d] flex items-center justify-between">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
                RemediationAgent Synthesized
              </span>
              <span className="text-xs font-mono text-slate-400">
                {vuln.cwe_id}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white">
              {vuln.title}
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white text-xl font-bold w-8 h-8 flex items-center justify-center rounded-lg hover:bg-slate-800"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5 flex-1">
          {patch ? (
            <>
              <div>
                <h4 className="text-sm font-semibold text-white mb-1">
                  Fix Strategy: {patch.title}
                </h4>
                <p className="text-xs text-slate-300">
                  {patch.explanation}
                </p>
              </div>

              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-semibold text-slate-300">Unified Diff Code Patch:</span>
                  <button
                    onClick={handleCopy}
                    className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
                  >
                    {copied ? '✓ Copied to Clipboard!' : '📋 Copy Diff'}
                  </button>
                </div>
                <div className="bg-[#060a14] border border-[#1f293d] rounded-xl p-3 text-xs overflow-x-auto">
                  {patch.unified_diff.split('\n').map((line, idx) => renderDiffLine(line, idx))}
                </div>
              </div>

              {patch.manual_steps && (
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 mb-2">
                    Implementation Directives:
                  </h4>
                  <div className="bg-[#0a0f1d] border border-[#1f293d] rounded-xl p-3 text-xs text-slate-300 whitespace-pre-line font-mono">
                    {patch.manual_steps}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="text-center py-8 text-slate-400">
              No patch currently generated for this finding.
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-[#1f293d] bg-[#0a0f1d] flex items-center justify-between">
          <span className="text-xs text-slate-400">
            Target: <code className="text-cyan-300">{vuln.affected_component}</code>
          </span>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
            >
              Close
            </button>
            <button
              onClick={() => {
                onApplyPatch(vuln.id);
                onClose();
              }}
              className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-lg text-xs font-semibold shadow"
            >
              Mark Vulnerability as Remediated
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
