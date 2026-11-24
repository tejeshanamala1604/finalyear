import React, { useState } from 'react';
import { X, Send, Terminal } from 'lucide-react';

export default function IngestAlertModal({ isOpen, onClose, onIngest, isLoading }) {
  const [formData, setFormData] = useState({
    title: 'Suspicious PowerShell C2 Beaconing to Hostile Foreign IP',
    description: 'Process powershell.exe spawned hidden child process initiating outbound beaconing to known malicious C2 controller.',
    source: 'CrowdStrike Falcon',
    raw_severity: 'High',
    src_ip: '10.0.10.45',
    dest_ip: '185.220.101.5',
    dest_port: 443,
    file_hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
    domain: 'cdn-sysupdate-auth.com',
    affected_user: 'j.smith',
    affected_host: 'WKST-FIN-04'
  });

  if (!isOpen) return null;

  const presets = [
    {
      name: 'Cobalt Strike C2 (Finance Workstation)',
      data: {
        title: 'Suspicious Cobalt Strike C2 Beaconing via Rundll32',
        description: 'Periodic HTTPS jitter beaconing detected to bulletproof hosting IP.',
        source: 'CrowdStrike Falcon',
        raw_severity: 'Critical',
        src_ip: '10.0.10.45',
        dest_ip: '185.220.101.5',
        dest_port: 443,
        file_hash: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
        domain: 'cdn-sysupdate-auth.com',
        affected_user: 'j.smith',
        affected_host: 'WKST-FIN-04'
      }
    },
    {
      name: 'Mimikatz LSASS Dump (Domain Controller)',
      data: {
        title: 'LSASS Memory Dumping Attempt Detected (Mimikatz)',
        description: 'Unauthorized access to lsass process memory on core identity tier.',
        source: 'Wazuh EDR',
        raw_severity: 'Critical',
        src_ip: '10.0.1.10',
        dest_ip: '194.26.29.112',
        dest_port: 4444,
        file_hash: 'cca92080a2489c92257973c714d68d0ee5df2d72f22b7c4d57c79e6ff2e4313f',
        affected_user: 'alex.ross',
        affected_host: 'DC-CORP-01'
      }
    },
    {
      name: 'Data Exfiltration (K8s Cluster Node)',
      data: {
        title: 'Mass Data Exfiltration over Encrypted DNS Tunnel',
        description: 'Unusually high rate of anomalous DNS TXT requests to foreign nameserver.',
        source: 'AWS GuardDuty',
        raw_severity: 'High',
        src_ip: '10.0.3.15',
        dest_ip: '193.106.191.24',
        dest_port: 53,
        domain: 'evil-exfil-sink.net',
        affected_user: 'marcus.chen',
        affected_host: 'K8S-APP-NODE-03'
      }
    }
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    onIngest(formData);
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black/60 dark:bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 transition-colors duration-200">
      <div className="relative w-full max-w-2xl rounded-2xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#0E1526] shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/80 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="w-5 h-5 text-blue-600 dark:text-blue-400" />
            <h3 className="font-bold text-slate-900 dark:text-slate-100 text-sm">
              Webhook Ingestion Endpoint Simulator
            </h3>
          </div>
          <button onClick={onClose} className="p-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Quick Presets */}
        <div className="p-4 bg-slate-50 dark:bg-slate-950/40 border-b border-slate-200 dark:border-slate-800/80">
          <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400 block mb-2">
            Load Threat Scenario Preset:
          </span>
          <div className="flex flex-wrap gap-2">
            {presets.map((preset, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => setFormData({ ...preset.data })}
                className="text-xs font-mono px-2.5 py-1 rounded bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 transition-colors"
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        {/* Ingest Form */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          <div>
            <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Alert Title</label>
            <input
              type="text"
              required
              value={formData.title}
              onChange={(e) => setFormData({ ...formData, title: e.target.value })}
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div>
            <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Description / Log Context</label>
            <textarea
              rows={2}
              required
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">EDR / Sensor Source</label>
              <input
                type="text"
                value={formData.source}
                onChange={(e) => setFormData({ ...formData, source: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Raw Severity</label>
              <select
                value={formData.raw_severity}
                onChange={(e) => setFormData({ ...formData, raw_severity: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Source IP (Internal Host)</label>
              <input
                type="text"
                value={formData.src_ip}
                onChange={(e) => setFormData({ ...formData, src_ip: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Destination IP (Adversary IOC)</label>
              <input
                type="text"
                value={formData.dest_ip}
                onChange={(e) => setFormData({ ...formData, dest_ip: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Affected Hostname</label>
              <input
                type="text"
                value={formData.affected_host}
                onChange={(e) => setFormData({ ...formData, affected_host: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
            <div>
              <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Affected Username (IAM)</label>
              <input
                type="text"
                value={formData.affected_user}
                onChange={(e) => setFormData({ ...formData, affected_user: e.target.value })}
                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-mono text-slate-600 dark:text-slate-400 block mb-1">Payload SHA256 File Hash (Optional)</label>
            <input
              type="text"
              value={formData.file_hash}
              onChange={(e) => setFormData({ ...formData, file_hash: e.target.value })}
              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs text-slate-900 dark:text-white focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div className="pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-end space-x-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium shadow-md shadow-blue-600/30 disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isLoading ? 'Ingesting & Enriching...' : 'Dispatch Webhook Alert'}</span>
            </button>
          </div>
        </form>

      </div>
    </div>
  );
}
