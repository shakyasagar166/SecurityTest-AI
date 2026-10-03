import React, { useEffect, useRef } from 'react';

export default function ScanConsole({ logs, isScanning }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-[#0a0f1d] border border-[#1f293d] rounded-xl overflow-hidden shadow-xl font-mono">
      <div className="bg-[#111827] px-4 py-2.5 border-b border-[#1f293d] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-2.5 h-2.5 rounded-full bg-rose-500"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-amber-500"></div>
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500"></div>
          <span className="text-xs font-semibold text-slate-300 ml-2">
            SecurityAgent Execution Console
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isScanning && (
            <span className="flex items-center gap-1.5 text-[11px] text-cyan-400">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              Live Pipeline Active
            </span>
          )}
          <span className="text-[11px] text-slate-500">
            {logs.length} events logged
          </span>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="p-4 h-64 overflow-y-auto space-y-1 text-xs text-slate-300"
      >
        {logs.length === 0 ? (
          <div className="text-slate-600 italic">
            Console idle. Launch an audit to observe multi-agent orchestration events...
          </div>
        ) : (
          logs.map((log, index) => {
            let color = 'text-slate-300';
            if (log.includes('CRITICAL') || log.includes('error')) color = 'text-rose-400 font-bold';
            else if (log.includes('HIGH') || log.includes('vulnerabilities')) color = 'text-amber-400';
            else if (log.includes('completed') || log.includes('score')) color = 'text-emerald-400 font-bold';
            else if (log.includes('Triggering') || log.includes('Agent')) color = 'text-cyan-300';

            return (
              <div key={index} className={`leading-relaxed ${color}`}>
                <span className="text-slate-600 select-none mr-2">&gt;</span>
                {log}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
