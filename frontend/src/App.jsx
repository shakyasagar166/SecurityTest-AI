import React, { useState } from 'react';
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import Vulnerabilities from './pages/Vulnerabilities';
import Reports from './pages/Reports';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div className="min-h-screen bg-[#060a14] text-slate-100 flex flex-col font-sans">
      {/* Top Navbar */}
      <header className="border-b border-[#1f293d] bg-[#0a0f1d]/90 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 via-indigo-600 to-rose-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 text-xl font-bold">
              🛡️
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-base tracking-wide bg-gradient-to-r from-cyan-400 via-indigo-300 to-emerald-400 bg-clip-text text-transparent">
                  SecurityTest-AI
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800">
                  Autonomous SecOps
                </span>
              </div>
              <span className="text-[11px] text-slate-400 block -mt-0.5">
                Multi-Agent Vulnerability Discovery & Auto-Remediation
              </span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="flex items-center gap-1 bg-[#111827] p-1 rounded-xl border border-[#1f293d]">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'dashboard'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2333]'
              }`}
            >
              📊 Dashboard
            </button>
            <button
              onClick={() => setActiveTab('scans')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'scans'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2333]'
              }`}
            >
              📋 Scans & History
            </button>
            <button
              onClick={() => setActiveTab('vulnerabilities')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'vulnerabilities'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2333]'
              }`}
            >
              🛡️ Vulnerabilities
            </button>
            <button
              onClick={() => setActiveTab('reports')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                activeTab === 'reports'
                  ? 'bg-cyan-600 text-white shadow-md shadow-cyan-900/40'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a2333]'
              }`}
            >
              📄 Reports
            </button>
          </nav>
        </div>
      </header>

      {/* Main Page Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'dashboard' && <Dashboard />}
        {activeTab === 'scans' && <Scans />}
        {activeTab === 'vulnerabilities' && <Vulnerabilities />}
        {activeTab === 'reports' && <Reports />}
      </main>

      {/* Footer */}
      <footer className="border-t border-[#1f293d] bg-[#0a0f1d] py-4 text-center text-xs text-slate-500">
        <p>SecurityTest-AI © 2026. Autonomous Cybersecurity Orchestration with LangGraph, Groq LLaMA-3.3-70B & OWASP Matrix.</p>
      </footer>
    </div>
  );
}
