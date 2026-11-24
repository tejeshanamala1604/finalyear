import React from 'react';
import { Search, ChevronRight, ShieldAlert, Monitor, User, Globe } from 'lucide-react';

export default function AlertTable({
  alerts,
  totalAlerts,
  isLoading,
  selectedAlertId,
  onSelectAlert,
  searchQuery,
  onSearchChange,
  severityFilter,
  onSeverityChange,
  statusFilter,
  onStatusChange,
  page,
  onPageChange
}) {
  const getSeverityBadge = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30 soc-glow-red';
      case 'high':
        return 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30 soc-glow-orange';
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/30';
      case 'low':
        return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700';
    }
  };

  const getStatusBadge = (status) => {
    switch (status?.toLowerCase()) {
      case 'new':
        return 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30';
      case 'triaged':
        return 'bg-cyan-500/10 text-cyan-600 dark:text-cyan-400 border-cyan-500/30';
      case 'in progress':
        return 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30';
      case 'mitigated':
        return 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30';
      case 'dismissed':
        return 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 border-slate-300 dark:border-slate-700';
      default:
        return 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-300 dark:border-slate-700';
    }
  };

  const getScoreBadge = (score) => {
    if (score >= 80) return 'text-rose-600 dark:text-rose-400 bg-rose-100 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800/60 soc-glow-red';
    if (score >= 60) return 'text-orange-600 dark:text-orange-400 bg-orange-100 dark:bg-orange-950/40 border-orange-300 dark:border-orange-800/60';
    if (score >= 35) return 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-950/40 border-yellow-300 dark:border-yellow-800/60';
    return 'text-emerald-600 dark:text-emerald-400 bg-emerald-100 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800/60';
  };

  const formatTimestamp = (isoString) => {
    if (!isoString) return 'Just now';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/60 backdrop-blur-md overflow-hidden shadow-sm dark:shadow-xl transition-colors duration-200">
      
      {/* Control Bar: Filters & Search */}
      <div className="p-4 border-b border-slate-200 dark:border-slate-800/80 flex flex-col md:flex-row gap-4 items-center justify-between">
        
        {/* Search Input */}
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400 dark:text-slate-400" />
          <input
            id="alert-search-input"
            type="text"
            placeholder="Search by title, IP, host, or user..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-50 dark:bg-slate-950/70 border border-slate-200 dark:border-slate-800 rounded-lg text-xs text-slate-900 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-blue-500 transition-all font-mono"
          />
        </div>

        {/* Severity & Status Filters */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          {/* Severity Pills */}
          <div className="flex items-center space-x-1 p-1 bg-slate-100 dark:bg-slate-950/60 rounded-lg border border-slate-200 dark:border-slate-800 text-xs">
            {['All', 'Critical', 'High', 'Medium', 'Low'].map((sev) => {
              const active = (sev === 'All' && !severityFilter) || severityFilter?.toLowerCase() === sev.toLowerCase();
              return (
                <button
                  key={sev}
                  onClick={() => onSeverityChange(sev === 'All' ? '' : sev)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-all ${
                    active
                      ? 'bg-blue-600 text-white font-semibold shadow'
                      : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              );
            })}
          </div>

          {/* Status Dropdown */}
          <select
            id="status-filter-select"
            value={statusFilter}
            onChange={(e) => onStatusChange(e.target.value)}
            className="bg-slate-100 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800 text-slate-700 dark:text-slate-300 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-blue-500 font-mono"
          >
            <option value="">All Statuses</option>
            <option value="New">New</option>
            <option value="Triaged">Triaged</option>
            <option value="In Progress">In Progress</option>
            <option value="Mitigated">Mitigated</option>
            <option value="Dismissed">Dismissed</option>
          </select>
        </div>

      </div>

      {/* Table Body */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/40 text-slate-500 dark:text-slate-400 uppercase tracking-wider font-mono">
              <th className="py-3 px-4 w-20 text-center">Risk Score</th>
              <th className="py-3 px-4">Alert Dossier</th>
              <th className="py-3 px-4 w-28">Severity</th>
              <th className="py-3 px-4 w-28">Status</th>
              <th className="py-3 px-4">Affected Entities</th>
              <th className="py-3 px-4 w-28">Logged At</th>
              <th className="py-3 px-4 w-24 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60">
            {isLoading ? (
              [...Array(6)].map((_, i) => (
                <tr key={i} className="animate-pulse">
                  <td colSpan={7} className="py-4 px-4 bg-slate-100 dark:bg-slate-900/30 h-14" />
                </tr>
              ))
            ) : alerts.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-12 text-center text-slate-500 dark:text-slate-400">
                  <ShieldAlert className="w-8 h-8 mx-auto mb-2 text-slate-400 dark:text-slate-600 opacity-60" />
                  <p className="font-medium text-slate-700 dark:text-slate-300">No security alerts matching current filters.</p>
                  <p className="text-xs text-slate-500 mt-1">Adjust search parameters or inject a simulated attack.</p>
                </td>
              </tr>
            ) : (
              alerts.map((alert) => {
                const isSelected = selectedAlertId === alert.id;
                return (
                  <tr
                    key={alert.id}
                    id={`alert-row-${alert.id}`}
                    onClick={() => onSelectAlert(alert.id)}
                    className={`cursor-pointer transition-all hover:bg-slate-50 dark:hover:bg-slate-800/50 ${
                      isSelected ? 'bg-blue-50 dark:bg-blue-900/20 border-l-2 border-blue-500' : ''
                    }`}
                  >
                    {/* Dynamic Risk Score */}
                    <td className="py-3 px-4 text-center">
                      <div
                        className={`inline-flex items-center justify-center font-mono font-bold text-xs px-2.5 py-1 rounded-md border ${getScoreBadge(
                          alert.dynamic_risk_score
                        )}`}
                      >
                        {alert.dynamic_risk_score}
                      </div>
                    </td>

                    {/* Alert Title & Source */}
                    <td className="py-3 px-4 max-w-sm">
                      <div className="font-semibold text-slate-900 dark:text-slate-100 truncate hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
                        {alert.title}
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 mt-1">
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                          {alert.source}
                        </span>
                        {alert.mitre_technique_id && (
                          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-800 font-semibold" title={alert.mitre_tactic}>
                            MITRE {alert.mitre_technique_id}
                          </span>
                        )}
                        {alert.file_hash && (
                          <span className="text-[10px] text-slate-500 font-mono truncate max-w-[120px]" title={alert.file_hash}>
                            hash:{alert.file_hash.substring(0, 8)}...
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block font-mono text-[11px] font-semibold px-2 py-0.5 rounded-full border ${getSeverityBadge(
                          alert.current_severity || alert.raw_severity
                        )}`}
                      >
                        {alert.current_severity || alert.raw_severity}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block font-mono text-[11px] px-2 py-0.5 rounded-full border ${getStatusBadge(
                          alert.status
                        )}`}
                      >
                        {alert.status}
                      </span>
                    </td>

                    {/* Affected Entities (Host / User / IP) */}
                    <td className="py-3 px-4">
                      <div className="flex flex-col space-y-1 text-[11px] font-mono">
                        {alert.affected_host && (
                          <div className="flex items-center space-x-1 text-slate-700 dark:text-slate-300">
                            <Monitor className="w-3 h-3 text-slate-400 dark:text-slate-500 flex-shrink-0" />
                            <span className="truncate">{alert.affected_host}</span>
                          </div>
                        )}
                        {alert.affected_user && (
                          <div className="flex items-center space-x-1 text-slate-500 dark:text-slate-400">
                            <User className="w-3 h-3 text-slate-400 dark:text-slate-500 flex-shrink-0" />
                            <span className="truncate">{alert.affected_user}</span>
                          </div>
                        )}
                        {(alert.dest_ip || alert.src_ip) && (
                          <div className="flex items-center space-x-1 text-slate-500 dark:text-slate-400">
                            <Globe className="w-3 h-3 text-slate-400 dark:text-slate-500 flex-shrink-0" />
                            <span className="truncate">
                              {alert.src_ip} &rarr; {alert.dest_ip || 'N/A'}
                            </span>
                          </div>
                        )}
                      </div>
                    </td>

                    {/* Timestamp */}
                    <td className="py-3 px-4 text-slate-500 dark:text-slate-400 font-mono text-[11px]">
                      {formatTimestamp(alert.created_at)}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert.id);
                        }}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-blue-600/10 hover:bg-blue-600/20 dark:bg-blue-600/20 dark:hover:bg-blue-600/40 border border-blue-500/30 text-blue-600 dark:text-blue-300 text-xs font-medium transition-all"
                      >
                        <span>Investigate</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>

                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      <div className="p-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-mono text-slate-500 dark:text-slate-400">
        <div>
          Showing {alerts.length} of {totalAlerts} alerts
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => onPageChange(Math.max(1, page - 1))}
            disabled={page === 1}
            className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Previous
          </button>
          <span className="px-2 py-1 text-slate-700 dark:text-slate-200 font-semibold">Page {page}</span>
          <button
            onClick={() => onPageChange(page + 1)}
            disabled={alerts.length < 10}
            className="px-2.5 py-1 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next
          </button>
        </div>
      </div>

    </div>
  );
}
