import React, { useState } from 'react';
import {
  X, ShieldCheck, ShieldBan, Lock, Globe,
  Server, User, Cpu, Radio, Activity, CheckCircle,
  Terminal, AlertOctagon, Check, Download, Target, ExternalLink
} from 'lucide-react';
import { socApi } from '../services/api';

export default function AlertDetailModal({
  alert,
  onClose,
  onTakeAction,
  isActionLoading
}) {
  const [analystNote, setAnalystNote] = useState('');
  const [lastActionSuccess, setLastActionSuccess] = useState(null);
  const [isDownloading, setIsDownloading] = useState(false);

  if (!alert) return null;

  const enrichment = alert.enrichment_data || {};
  const asset = enrichment.internal_asset || {};
  const user = enrichment.internal_user || {};
  const threat = enrichment.threat_intelligence || {};
  const vt = threat.virustotal || {};
  const vtFile = threat.virustotal_file || {};
  const abuse = threat.abuseipdb || {};
  const shodan = threat.shodan || {};
  const score = alert.dynamic_risk_score || 0;

  const handleDownloadReport = async () => {
    setIsDownloading(true);
    try {
      const reportData = await socApi.getAlertReport(alert.id);
      const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `NIST_SP800-61_Incident_Report_Alert_${alert.id}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setLastActionSuccess(`Forensic Incident Report Downloaded (ID: INC-SOC-${alert.id})`);
      setTimeout(() => setLastActionSuccess(null), 4000);
    } catch (err) {
      console.error('Failed to download report:', err);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleActionClick = async (actionName) => {
    try {
      const res = await onTakeAction(alert.id, actionName, 'Analyst Alex', analystNote);
      setLastActionSuccess(`Executed: ${actionName}`);
      setTimeout(() => setLastActionSuccess(null), 4000);
      setAnalystNote('');
    } catch (err) {
      console.error(err);
    }
  };

  const getScoreColor = (sc) => {
    if (sc >= 80) return { text: 'text-rose-600 dark:text-rose-500', bg: 'bg-rose-500', ring: 'stroke-rose-600 dark:stroke-rose-500', label: 'CRITICAL THREAT' };
    if (sc >= 60) return { text: 'text-orange-600 dark:text-orange-500', bg: 'bg-orange-500', ring: 'stroke-orange-600 dark:stroke-orange-500', label: 'HIGH RISK' };
    if (sc >= 35) return { text: 'text-yellow-600 dark:text-yellow-500', bg: 'bg-yellow-500', ring: 'stroke-yellow-600 dark:stroke-yellow-500', label: 'ELEVATED' };
    return { text: 'text-emerald-600 dark:text-emerald-500', bg: 'bg-emerald-500', ring: 'stroke-emerald-600 dark:stroke-emerald-500', label: 'LOW RISK' };
  };

  const scoreTheme = getScoreColor(score);

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 dark:bg-black/80 backdrop-blur-sm flex items-center justify-center p-3 sm:p-6 transition-colors duration-200">
      
      {/* Modal Dialog */}
      <div className="relative w-full max-w-5xl rounded-2xl border border-slate-200 dark:border-slate-700/80 bg-white dark:bg-[#0E1526] text-slate-900 dark:text-slate-100 shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Top Header */}
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 flex items-start justify-between">
          <div className="flex items-start space-x-4">
            
            {/* Dynamic Score Ring Gauge */}
            <div className="relative flex-shrink-0 w-16 h-16 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="stroke-slate-200 dark:stroke-slate-800"
                  strokeWidth="3.5"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className={`${scoreTheme.ring} transition-all duration-1000 ease-out`}
                  strokeDasharray={`${score}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-lg font-bold font-mono ${scoreTheme.text}`}>{score}</span>
              </div>
            </div>

            <div>
              <div className="flex items-center space-x-2">
                <span className={`text-[10px] font-mono uppercase font-bold px-2 py-0.5 rounded-full border ${
                  score >= 80 ? 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30 soc-glow-red' :
                  score >= 60 ? 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30' :
                  'bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 border-yellow-500/30'
                }`}>
                  {scoreTheme.label} ({score}/100)
                </span>
                <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">ID: #{alert.id}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 font-mono">
                  {alert.source}
                </span>
                {alert.mitre_technique_id && (
                  <a
                    href={`https://attack.mitre.org/techniques/${alert.mitre_technique_id.split('.')[0]}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center space-x-1 text-[11px] font-mono font-semibold px-2 py-0.5 rounded bg-indigo-100 dark:bg-indigo-950/60 border border-indigo-300 dark:border-indigo-800 text-indigo-800 dark:text-indigo-300 hover:underline"
                    title="View Official MITRE ATT&CK Matrix Technique"
                  >
                    <Target className="w-3 h-3 text-indigo-600 dark:text-indigo-400" />
                    <span>MITRE: {alert.mitre_technique_id} ({alert.mitre_tactic || 'Technique'})</span>
                    <ExternalLink className="w-2.5 h-2.5 opacity-70" />
                  </a>
                )}
              </div>
              <h2 className="text-lg font-bold text-slate-900 dark:text-white mt-1 leading-snug">
                {alert.title}
              </h2>
              <p className="text-xs text-slate-600 dark:text-slate-400 mt-1 max-w-2xl">
                {alert.description}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action success alert banner */}
        {lastActionSuccess && (
          <div className="bg-emerald-500/10 dark:bg-emerald-500/20 border-b border-emerald-500/30 px-4 py-2 flex items-center space-x-2 text-xs text-emerald-700 dark:text-emerald-300 font-mono">
            <CheckCircle className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
            <span>{lastActionSuccess}</span>
          </div>
        )}

        {/* Modal Scrollable Content: 2-Column Split View */}
        <div className="overflow-y-auto p-5 space-y-6">
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* COLUMN 1: Internal Enterprise Context */}
            <div className="space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono uppercase tracking-wider text-blue-600 dark:text-blue-400 font-semibold">
                <Server className="w-4 h-4" />
                <span>Internal Enterprise Context (CMDB & IAM)</span>
              </div>

              {/* Host & Asset Details Card */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2">
                    <Cpu className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                    <span className="text-sm font-semibold text-slate-900 dark:text-slate-200">
                      {asset.hostname || alert.affected_host || 'Unknown Host'}
                    </span>
                  </div>
                  {asset.is_isolated ? (
                    <span className="flex items-center space-x-1 text-[11px] font-mono px-2 py-0.5 rounded bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-400 border border-rose-300 dark:border-rose-700 soc-glow-red">
                      <ShieldBan className="w-3 h-3" />
                      <span>ISOLATED BY EDR</span>
                    </span>
                  ) : (
                    <span className="flex items-center space-x-1 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">
                      <ShieldCheck className="w-3 h-3" />
                      <span>ONLINE / CONNECTED</span>
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-y-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Criticality Tier:</span>
                    <span className={`font-semibold ${asset.criticality_tier?.includes('Tier 0') ? 'text-rose-600 dark:text-rose-400' : 'text-slate-700 dark:text-slate-300'}`}>
                      {asset.criticality_tier || 'Tier 2 - Operational'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Environment:</span>
                    <span className="text-slate-700 dark:text-slate-300">{asset.environment || 'Production'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Operating System:</span>
                    <span className="text-slate-700 dark:text-slate-300">{asset.os || 'Windows 11 / Linux'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Internal IP / MAC:</span>
                    <span className="text-slate-700 dark:text-slate-300 truncate block">
                      {asset.ip_address || alert.src_ip || 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Asset Owner:</span>
                    <span className="text-slate-700 dark:text-slate-300">{asset.owner || 'IT Security'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Network Zone:</span>
                    <span className="text-slate-700 dark:text-slate-300">{asset.network_zone || 'Corporate LAN'}</span>
                  </div>
                </div>
              </div>

              {/* IAM User Profile Card */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2">
                    <User className="w-4 h-4 text-slate-500 dark:text-slate-400" />
                    <span className="text-sm font-semibold text-slate-900 dark:text-slate-200">
                      {user.full_name || alert.affected_user || 'Service Account'}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700">
                    {user.department || 'Corporate'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-y-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Privilege Tier:</span>
                    <span className={`font-semibold ${user.privilege_level?.includes('Admin') ? 'text-amber-600 dark:text-amber-400' : 'text-slate-700 dark:text-slate-300'}`}>
                      {user.privilege_level || 'Standard User'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Account Status:</span>
                    <span className={`font-semibold ${user.account_status === 'Credentials_Revoked' ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
                      {user.account_status || 'Active'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">MFA Enforcement:</span>
                    <span className={user.mfa_enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-rose-600 dark:text-rose-400 font-bold'}>
                      {user.mfa_enabled ? 'Enforced (FIDO2/TOTP)' : 'DISABLED (High Risk)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block">Corporate Email:</span>
                    <span className="text-slate-700 dark:text-slate-300 truncate block">{user.email || `${alert.affected_user || 'user'}@corp.local`}</span>
                  </div>
                </div>
              </div>

            </div>

            {/* COLUMN 2: External Threat Intelligence */}
            <div className="space-y-4">
              <div className="flex items-center space-x-2 text-xs font-mono uppercase tracking-wider text-cyan-600 dark:text-cyan-400 font-semibold">
                <Globe className="w-4 h-4" />
                <span>External Threat Intelligence (VT / AbuseIPDB / Shodan)</span>
              </div>

              {/* VirusTotal Telemetry */}
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 space-y-3">
                <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800/80 pb-2">
                  <div className="flex items-center space-x-2">
                    <Activity className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
                    <span className="text-sm font-semibold text-slate-900 dark:text-slate-200">VirusTotal v3 Reputation</span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-400 dark:text-slate-500">
                    {vt.is_mock ? 'Mock Fallback Engine' : 'Live API Query'}
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block">Malicious Verdict:</span>
                    <span className="text-rose-600 dark:text-rose-400 font-bold text-sm">
                      {vt.malicious_count || vtFile.malicious_count || 0} / 72 Security Engines
                    </span>
                  </div>
                  <div className="text-right">
                    <span className="text-slate-500 block">Threat Classification:</span>
                    <span className="text-amber-600 dark:text-amber-400 font-semibold">
                      {vtFile.popular_threat_name || (vt.malicious_count > 0 ? 'Adversary C2 Infrastructure' : 'Benign / Clean')}
                    </span>
                  </div>
                </div>

                {/* Detecting engines pills */}
                {(vt.top_detecting_engines || vtFile.top_detecting_engines) && (
                  <div className="pt-1">
                    <span className="text-[10px] text-slate-500 font-mono block mb-1">Detecting AV Engines:</span>
                    <div className="flex flex-wrap gap-1">
                      {(vt.top_detecting_engines || vtFile.top_detecting_engines).map((eng, idx) => (
                        <span key={idx} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-100 dark:bg-rose-950/60 border border-rose-300 dark:border-rose-900 text-rose-700 dark:text-rose-300">
                          {eng}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* AbuseIPDB & Shodan Telemetry */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                
                {/* AbuseIPDB Card */}
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200">
                    <Radio className="w-3.5 h-3.5 text-blue-500 dark:text-blue-400" />
                    <span>AbuseIPDB Score</span>
                  </div>
                  <div className="text-2xl font-bold font-mono text-rose-600 dark:text-rose-400">
                    {abuse.abuse_confidence_score || 0}%
                  </div>
                  <div className="text-[11px] font-mono text-slate-600 dark:text-slate-400 space-y-1">
                    <p>Total Reports: <span className="text-slate-900 dark:text-slate-200 font-semibold">{abuse.total_reports || 0}</span></p>
                    <p className="truncate">ISP: <span className="text-slate-900 dark:text-slate-200">{abuse.isp || 'N/A'}</span></p>
                    <p>Country: <span className="text-slate-900 dark:text-slate-200">{abuse.country_code || 'N/A'}</span></p>
                  </div>
                </div>

                {/* Shodan Card */}
                <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 space-y-2">
                  <div className="flex items-center space-x-1.5 text-xs font-semibold text-slate-800 dark:text-slate-200">
                    <Server className="w-3.5 h-3.5 text-amber-500 dark:text-amber-400" />
                    <span>Shodan Recon</span>
                  </div>
                  <div className="text-xs font-mono text-slate-600 dark:text-slate-400 space-y-1.5">
                    <div>
                      <span className="text-slate-500 block text-[10px]">Open Ports:</span>
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {(shodan.open_ports || [80, 443]).map((p) => (
                          <span key={p} className="text-[10px] px-1 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-slate-800 dark:text-slate-200 border border-slate-300 dark:border-slate-700 font-mono">
                            {p}
                          </span>
                        ))}
                      </div>
                    </div>
                    {shodan.vulns && shodan.vulns.length > 0 && (
                      <div className="pt-1">
                        <span className="text-rose-600 dark:text-rose-400 block text-[10px] font-bold">Known CVEs:</span>
                        <span className="text-rose-700 dark:text-rose-300 text-[10px]">{shodan.vulns.join(', ')}</span>
                      </div>
                    )}
                  </div>
                </div>

              </div>

            </div>

          </div>

          {/* SECTION: Recommended SOC Playbook Actions */}
          <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/70 border border-slate-200 dark:border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-mono uppercase tracking-wider text-amber-600 dark:text-amber-400 font-semibold">
                <Terminal className="w-4 h-4" />
                <span>Prescriptive SOC Playbook Mitigations</span>
              </div>
              <span className="text-xs text-slate-500 font-mono">Execute 1-Click First Response Actions</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2">
              
              {/* Containment: Isolate Host */}
              <button
                id="modal-isolate-host-btn"
                onClick={() => handleActionClick(asset.is_isolated ? 'Unisolate Host' : 'Isolate Host')}
                disabled={isActionLoading || !alert.affected_host}
                className={`p-3 rounded-lg border text-left transition-all ${
                  asset.is_isolated
                    ? 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-300 dark:border-emerald-800 hover:bg-emerald-100 dark:hover:bg-emerald-900/50 text-emerald-800 dark:text-emerald-200'
                    : 'bg-rose-50 dark:bg-rose-950/40 border-rose-300 dark:border-rose-800 hover:bg-rose-100 dark:hover:bg-rose-900/50 text-rose-800 dark:text-rose-200 soc-glow-red'
                } disabled:opacity-40`}
              >
                <div className="flex items-center justify-between mb-1">
                  <ShieldBan className="w-4 h-4" />
                  <span className="text-[10px] uppercase font-mono px-1 rounded bg-black/10 dark:bg-black/40">Containment</span>
                </div>
                <div className="text-xs font-bold font-mono">
                  {asset.is_isolated ? 'Restore Host Network' : 'Isolate Endpoint Host'}
                </div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 line-clamp-1">
                  {asset.hostname || alert.affected_host} via EDR Lock
                </p>
              </button>

              {/* Perimeter: Block Threat IP */}
              <button
                id="modal-block-ip-btn"
                onClick={() => handleActionClick('Block IP')}
                disabled={isActionLoading || (!alert.dest_ip && !alert.src_ip)}
                className="p-3 rounded-lg bg-orange-50 dark:bg-orange-950/40 border border-orange-300 dark:border-orange-800 hover:bg-orange-100 dark:hover:bg-orange-900/50 text-orange-800 dark:text-orange-200 text-left transition-all disabled:opacity-40"
              >
                <div className="flex items-center justify-between mb-1">
                  <AlertOctagon className="w-4 h-4" />
                  <span className="text-[10px] uppercase font-mono px-1 rounded bg-black/10 dark:bg-black/40">Perimeter</span>
                </div>
                <div className="text-xs font-bold font-mono">Block Attacker IP</div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 line-clamp-1">
                  Push {alert.dest_ip || alert.src_ip} to Edge WAF
                </p>
              </button>

              {/* Identity: Reset Credentials */}
              <button
                id="modal-reset-cred-btn"
                onClick={() => handleActionClick('Reset Credentials')}
                disabled={isActionLoading || !alert.affected_user}
                className="p-3 rounded-lg bg-indigo-50 dark:bg-indigo-950/40 border border-indigo-300 dark:border-indigo-800 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 text-indigo-800 dark:text-indigo-200 text-left transition-all disabled:opacity-40"
              >
                <div className="flex items-center justify-between mb-1">
                  <Lock className="w-4 h-4" />
                  <span className="text-[10px] uppercase font-mono px-1 rounded bg-black/10 dark:bg-black/40">IAM Identity</span>
                </div>
                <div className="text-xs font-bold font-mono">Revoke Sessions & MFA</div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 line-clamp-1">
                  Force credential rotation for {alert.affected_user}
                </p>
              </button>

              {/* Triage / Dismiss */}
              <button
                id="modal-dismiss-btn"
                onClick={() => handleActionClick('Dismiss')}
                disabled={isActionLoading}
                className="p-3 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-700 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-left transition-all disabled:opacity-40"
              >
                <div className="flex items-center justify-between mb-1">
                  <Check className="w-4 h-4" />
                  <span className="text-[10px] uppercase font-mono px-1 rounded bg-black/10 dark:bg-black/40">Resolution</span>
                </div>
                <div className="text-xs font-bold font-mono">Dismiss as Benign</div>
                <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-1 line-clamp-1">
                  Mark closed with FP metadata
                </p>
              </button>

            </div>
          </div>

          {/* SECTION: Analyst Audit Log Timeline */}
          {alert.audit_log && alert.audit_log.length > 0 && (
            <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-800/80 space-y-2">
              <span className="text-xs font-mono uppercase text-slate-500 dark:text-slate-400 font-semibold block">
                SOC Audit Trail & Incident Timeline
              </span>
              <div className="space-y-1.5 font-mono text-xs max-h-36 overflow-y-auto">
                {alert.audit_log.map((log, idx) => (
                  <div key={idx} className="flex items-start space-x-2 text-slate-600 dark:text-slate-400 py-1 border-b border-slate-200 dark:border-slate-800/40 last:border-0">
                    <span className="text-slate-400 dark:text-slate-600 font-mono text-[10px]">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span className="text-blue-600 dark:text-blue-400 font-semibold">[{log.analyst}]:</span>
                    <span className="text-slate-800 dark:text-slate-200">{log.action}</span>
                    {log.note && <span className="text-slate-500">— {log.note}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>

        {/* Modal Bottom Footer */}
        <div className="p-4 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center space-x-2">
            <span className="text-slate-500">Alert Status:</span>
            <span className="font-semibold text-slate-800 dark:text-slate-200">{alert.status}</span>
          </div>

          <div className="flex items-center space-x-2">
            <button
              id="download-forensic-report-btn"
              onClick={handleDownloadReport}
              disabled={isDownloading}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-50 dark:bg-blue-900/30 hover:bg-blue-100 dark:hover:bg-blue-900/50 border border-blue-300 dark:border-blue-700/60 text-blue-700 dark:text-blue-300 font-semibold transition-all disabled:opacity-50"
              title="Export complete NIST SP 800-61 / ISO 27035 incident report"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{isDownloading ? 'Generating...' : 'Export NIST 800-61 Report'}</span>
            </button>

            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 font-medium transition-colors"
            >
              Close Dossier
            </button>
          </div>
        </div>

      </div>
    </div>
  );
}
