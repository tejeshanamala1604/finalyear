import React from 'react';
import { AlertOctagon, Flame, Clock, Layers, ShieldBan } from 'lucide-react';

export default function MetricsOverview({ metrics, isLoading }) {
  if (isLoading && !metrics) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
        {[...Array(5)].map((_, i) => (
          <div key={i} className="h-28 rounded-xl bg-slate-200 dark:bg-slate-900/60 border border-slate-300 dark:border-slate-800 animate-pulse" />
        ))}
      </div>
    );
  }

  const m = metrics || {
    total_alerts: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    active_isolations: 0,
    avg_response_time_minutes: 4.2
  };

  const cards = [
    {
      title: "Total Ingested Alerts",
      value: m.total_alerts,
      icon: Layers,
      color: "blue",
      subtext: `${m.new_count || 0} requiring triage`,
      glowClass: "border-blue-500/20 bg-blue-50 dark:bg-blue-500/5 text-blue-600 dark:text-blue-400"
    },
    {
      title: "Critical Threats",
      value: m.critical_count,
      icon: AlertOctagon,
      color: "red",
      subtext: "Immediate escalation tier",
      glowClass: "border-rose-500/30 bg-rose-50 dark:bg-rose-500/10 text-rose-600 dark:text-rose-400 soc-glow-red"
    },
    {
      title: "High Severity",
      value: m.high_count,
      icon: Flame,
      color: "orange",
      subtext: "Elevated risk telemetry",
      glowClass: "border-orange-500/30 bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400"
    },
    {
      title: "Avg Triage Latency",
      value: `${m.avg_response_time_minutes}m`,
      icon: Clock,
      color: "emerald",
      subtext: "Target SLA: < 15 min",
      glowClass: "border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/5 text-emerald-600 dark:text-emerald-400"
    },
    {
      title: "Active Host Isolations",
      value: m.active_isolations,
      icon: ShieldBan,
      color: "purple",
      subtext: "EDR quarantine active",
      glowClass: "border-purple-500/30 bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400"
    }
  ];

  return (
    <div className="space-y-4 mb-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {cards.map((card, idx) => {
          const Icon = card.icon;
          return (
            <div
              key={idx}
              className={`p-4 rounded-xl border backdrop-blur-md transition-all hover:translate-y-[-2px] shadow-sm ${card.glowClass}`}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium uppercase tracking-wider text-slate-500 dark:text-slate-400">
                  {card.title}
                </span>
                <Icon className="w-5 h-5 opacity-80" />
              </div>
              <div className="mt-2 flex items-baseline space-x-2">
                <span className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white font-mono">
                  {card.value}
                </span>
              </div>
              <p className="mt-1 text-[11px] text-slate-500 dark:text-slate-400 font-mono truncate">
                {card.subtext}
              </p>
            </div>
          );
        })}
      </div>

      {/* Severity distribution bar */}
      {m.total_alerts > 0 && (
        <div className="p-3 rounded-lg bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 shadow-sm">
          <div className="flex items-center space-x-2">
            <span className="text-slate-600 dark:text-slate-400 font-mono font-medium">Threat Breakdown:</span>
            <div className="flex items-center space-x-3 text-xs font-mono">
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                <span className="text-rose-600 dark:text-rose-400 font-semibold">{m.critical_count} Critical</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-orange-500" />
                <span className="text-orange-600 dark:text-orange-400 font-semibold">{m.high_count} High</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-yellow-500" />
                <span className="text-yellow-600 dark:text-yellow-400 font-semibold">{m.medium_count} Med</span>
              </span>
              <span className="flex items-center space-x-1">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span className="text-emerald-600 dark:text-emerald-400 font-semibold">{m.low_count} Low</span>
              </span>
            </div>
          </div>

          {/* Mini progress bar */}
          <div className="w-full sm:w-64 h-2 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden flex">
            <div
              style={{ width: `${(m.critical_count / m.total_alerts) * 100}%` }}
              className="bg-rose-500 h-full"
              title="Critical"
            />
            <div
              style={{ width: `${(m.high_count / m.total_alerts) * 100}%` }}
              className="bg-orange-500 h-full"
              title="High"
            />
            <div
              style={{ width: `${(m.medium_count / m.total_alerts) * 100}%` }}
              className="bg-yellow-500 h-full"
              title="Medium"
            />
            <div
              style={{ width: `${(m.low_count / m.total_alerts) * 100}%` }}
              className="bg-emerald-500 h-full"
              title="Low"
            />
          </div>
        </div>
      )}
    </div>
  );
}
