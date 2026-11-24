import React, { useState, useEffect } from 'react';
import { ShieldAlert, Radio, Activity, RefreshCw, Zap, Plus, Cloud, Sun, Moon } from 'lucide-react';
import { socWebSocket } from '../services/websocket';

export default function Navbar({
  onSimulateAlert,
  onOpenIngestModal,
  onRefresh,
  threatStatus,
  isRefreshing,
  theme,
  onToggleTheme
}) {
  const [wsConnected, setWsConnected] = useState(false);

  useEffect(() => {
    socWebSocket.connect();
    const unsubscribe = socWebSocket.subscribeStatus((status) => {
      setWsConnected(status);
    });
    return () => unsubscribe();
  }, []);

  return (
    <header className="sticky top-0 z-40 w-full border-b border-slate-200 dark:border-slate-800 bg-white/90 dark:bg-[#0B0F19]/90 backdrop-blur-md transition-colors duration-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        
        {/* Left: Branding */}
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-blue-600/10 dark:bg-blue-600/20 border border-blue-500/20 dark:border-blue-500/30 text-blue-600 dark:text-blue-400">
            <ShieldAlert className="w-6 h-6 animate-pulse-subtle" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight bg-gradient-to-r from-blue-600 via-indigo-500 to-cyan-500 dark:from-blue-400 dark:via-indigo-300 dark:to-cyan-400 bg-clip-text text-transparent">
                AegisSOC
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-blue-100 dark:bg-blue-900/60 border border-blue-200 dark:border-blue-700/50 text-blue-700 dark:text-blue-300 font-semibold">
                Tier-1 SOC
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-mono hidden sm:block">
              First Response Alert Enrichment & Containment
            </p>
          </div>
        </div>

        {/* Center: Realtime Telemetry Status */}
        <div className="hidden lg:flex items-center space-x-3 text-xs font-mono">
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-100 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800">
            <span className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-emerald-500 animate-ping' : 'bg-rose-500'}`} />
            <span className="text-slate-700 dark:text-slate-300 font-medium">
              {wsConnected ? 'LIVE FEED (WS)' : 'CONNECTING...'}
            </span>
          </div>

          {/* External Feeds Pill */}
          <div className="flex items-center space-x-2 px-2.5 py-1 rounded-full bg-slate-100 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 text-slate-500 dark:text-slate-400">
            <span className="text-[11px] text-slate-400 dark:text-slate-500 uppercase">Feeds:</span>
            <span className="flex items-center space-x-1 text-slate-700 dark:text-slate-300" title="VirusTotal API v3">
              <Activity className="w-3 h-3 text-emerald-500 dark:text-emerald-400" />
              <span>VT v3</span>
            </span>
            <span className="text-slate-300 dark:text-slate-700">•</span>
            <span className="flex items-center space-x-1 text-slate-700 dark:text-slate-300" title="AbuseIPDB v2">
              <Cloud className="w-3 h-3 text-blue-500 dark:text-blue-400" />
              <span>AbuseIPDB</span>
            </span>
            <span className="text-slate-300 dark:text-slate-700">•</span>
            <span className="flex items-center space-x-1 text-slate-700 dark:text-slate-300" title="Shodan Host Recon">
              <Radio className="w-3 h-3 text-amber-500 dark:text-amber-400" />
              <span>Shodan</span>
            </span>
          </div>
        </div>

        {/* Right: Quick Actions + Theme Switcher */}
        <div className="flex items-center space-x-2 sm:space-x-3">
          
          {/* Light / Dark Mode Toggle Button */}
          <button
            id="theme-toggle-btn"
            onClick={onToggleTheme}
            className="flex items-center space-x-1 p-2 rounded-lg bg-slate-100 hover:bg-slate-200 border border-slate-200 dark:bg-slate-800/80 dark:hover:bg-slate-700/80 dark:border-slate-700 text-slate-700 dark:text-slate-200 transition-all"
            title={theme === 'dark' ? "Switch to White (Light) Theme" : "Switch to Black (Dark) Theme"}
          >
            {theme === 'dark' ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-slate-700" />
            )}
            <span className="text-xs font-mono font-medium hidden md:inline ml-1">
              {theme === 'dark' ? 'Black' : 'White'}
            </span>
          </button>

          <button
            id="refresh-btn"
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-100 hover:bg-slate-200 border border-slate-200 dark:bg-slate-800/80 dark:hover:bg-slate-700/80 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-all disabled:opacity-50"
            title="Refresh Alert Queue"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-blue-500 dark:text-blue-400' : ''}`} />
          </button>

          <button
            id="simulate-alert-btn"
            onClick={onSimulateAlert}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 text-amber-600 dark:text-amber-300 hover:text-amber-700 dark:hover:text-amber-200 text-xs font-medium transition-all"
            title="Inject simulated security alert to demonstrate live enrichment"
          >
            <Zap className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Simulate Attack</span>
          </button>

          <button
            id="ingest-alert-btn"
            onClick={onOpenIngestModal}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium shadow-md shadow-blue-600/20 transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Ingest Alert</span>
          </button>
        </div>

      </div>
    </header>
  );
}
