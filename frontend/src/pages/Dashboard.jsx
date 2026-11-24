import React, { useState, useEffect, useCallback } from 'react';
import Navbar from '../components/Navbar';
import MetricsOverview from '../components/MetricsOverview';
import AlertTable from '../components/AlertTable';
import AlertDetailModal from '../components/AlertDetailModal';
import IngestAlertModal from '../components/IngestAlertModal';
import AnalyticsView from '../components/AnalyticsView';
import { socApi } from '../services/api';
import { socWebSocket } from '../services/websocket';
import { ShieldAlert, CheckCircle2, LayoutList, BarChart3 } from 'lucide-react';

export default function Dashboard() {
  const [alerts, setAlerts] = useState([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [metrics, setMetrics] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [isDetailLoading, setIsDetailLoading] = useState(false);
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [isIngestModalOpen, setIsIngestModalOpen] = useState(false);
  const [isIngesting, setIsIngesting] = useState(false);
  const [notification, setNotification] = useState(null);
  const [activeTab, setActiveTab] = useState('feed'); // 'feed' | 'analytics'

  // Theme State: Default to 'dark' (Black theme) as requested
  const [theme, setTheme] = useState(() => localStorage.getItem('soc_theme') || 'dark');

  useEffect(() => {
    if (theme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('soc_theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [page, setPage] = useState(1);

  const showNotification = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 5000);
  };

  // Fetch Alerts
  const loadAlerts = useCallback(async () => {
    try {
      const data = await socApi.getAlerts({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        search: searchQuery || undefined,
        page,
        limit: 10
      });
      setAlerts(data.alerts);
      setTotalAlerts(data.total);
    } catch (err) {
      console.error('Failed to load alerts:', err);
    }
  }, [severityFilter, statusFilter, searchQuery, page]);

  // Fetch Metrics
  const loadMetrics = useCallback(async () => {
    try {
      const data = await socApi.getMetrics();
      setMetrics(data);
    } catch (err) {
      console.error('Failed to load metrics:', err);
    }
  }, []);

  // Combined Refresh
  const handleRefresh = async () => {
    setIsRefreshing(true);
    await Promise.all([loadAlerts(), loadMetrics()]);
    setIsRefreshing(false);
  };

  // Initial Load
  useEffect(() => {
    const init = async () => {
      setIsLoading(true);
      await Promise.all([loadAlerts(), loadMetrics()]);
      setIsLoading(false);
    };
    init();
  }, [loadAlerts, loadMetrics]);

  // WebSocket Live Listener
  useEffect(() => {
    const unsubscribe = socWebSocket.subscribe((msg) => {
      const { event, data } = msg;

      if (event === 'alert_created') {
        showNotification(`New Ingested Alert: ${data.title}`, 'alert');
        loadAlerts();
        loadMetrics();
      } else if (event === 'alert_enriched') {
        loadAlerts();
        loadMetrics();
        // If current modal is viewing this alert, update it
        setSelectedAlert((prev) => {
          if (prev && prev.id === data.id) {
            return {
              ...prev,
              dynamic_risk_score: data.dynamic_risk_score,
              current_severity: data.current_severity,
              status: data.status,
              enrichment_data: data.enrichment_data
            };
          }
          return prev;
        });
      } else if (event === 'action_taken') {
        showNotification(`Mitigation Executed: ${data.action} on Alert #${data.alert_id}`, 'success');
        loadAlerts();
        loadMetrics();
      }
    });

    return () => unsubscribe();
  }, [loadAlerts, loadMetrics]);

  // Open Alert Detail Dossier
  const handleSelectAlert = async (alertId) => {
    setIsDetailLoading(true);
    try {
      const detail = await socApi.getAlertById(alertId);
      setSelectedAlert(detail);
    } catch (err) {
      console.error('Failed to load alert detail:', err);
    } finally {
      setIsDetailLoading(false);
    }
  };

  // Take Mitigation Action
  const handleTakeAction = async (alertId, action, analyst, note) => {
    setIsActionLoading(true);
    try {
      const res = await socApi.takeAction(alertId, { action, analyst, note });
      // Update local modal data
      const updated = await socApi.getAlertById(alertId);
      setSelectedAlert(updated);
      loadAlerts();
      loadMetrics();
      return res;
    } catch (err) {
      console.error('Failed to take action:', err);
      throw err;
    } finally {
      setIsActionLoading(false);
    }
  };

  // Trigger Random Ingest Simulation
  const handleSimulateAlert = async () => {
    try {
      const newAlert = await socApi.simulateAlert();
      showNotification(`Simulated Attack Injected: ${newAlert.title}`, 'alert');
      loadAlerts();
      loadMetrics();
    } catch (err) {
      console.error('Simulation failed:', err);
    }
  };

  // Handle Manual Ingest
  const handleIngestSubmit = async (formData) => {
    setIsIngesting(true);
    try {
      const created = await socApi.ingestAlert(formData);
      setIsIngestModalOpen(false);
      showNotification(`Alert Ingested & Enriched: ${created.title}`, 'success');
      loadAlerts();
      loadMetrics();
      handleSelectAlert(created.id);
    } catch (err) {
      console.error('Ingest failed:', err);
    } finally {
      setIsIngesting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#0B0F19] text-slate-900 dark:text-slate-100 flex flex-col transition-colors duration-200">
      
      {/* Top Navbar with Theme Switcher */}
      <Navbar
        onSimulateAlert={handleSimulateAlert}
        onOpenIngestModal={() => setIsIngestModalOpen(true)}
        onRefresh={handleRefresh}
        isRefreshing={isRefreshing}
        threatStatus={metrics?.threat_feed_status}
        theme={theme}
        onToggleTheme={toggleTheme}
      />

      {/* Realtime Notification Toast */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 animate-bounce">
          <div className="flex items-center space-x-2 px-4 py-3 rounded-xl border border-blue-500/40 bg-white/95 dark:bg-slate-900/90 text-slate-900 dark:text-white text-xs font-mono shadow-2xl backdrop-blur-md">
            {notification.type === 'alert' ? (
              <ShieldAlert className="w-4 h-4 text-rose-500" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
            )}
            <span>{notification.msg}</span>
          </div>
        </div>
      )}

      {/* Main SOC Cockpit Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        
        {/* Executive Metrics Overview */}
        <MetricsOverview metrics={metrics} isLoading={isLoading} />

        {/* View Switcher Tabs */}
        <div className="flex items-center space-x-2 border-b border-slate-200 dark:border-slate-800 pb-2">
          <button
            id="tab-live-feed-btn"
            onClick={() => setActiveTab('feed')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'feed'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800/60'
            }`}
          >
            <LayoutList className="w-3.5 h-3.5" />
            <span>Live Incident Stream ({totalAlerts})</span>
          </button>

          <button
            id="tab-analytics-btn"
            onClick={() => setActiveTab('analytics')}
            className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all ${
              activeTab === 'analytics'
                ? 'bg-blue-600 text-white shadow-sm'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white bg-slate-100 dark:bg-slate-800/60'
            }`}
          >
            <BarChart3 className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK & Evaluation Benchmarks</span>
          </button>
        </div>

        {/* Tab Content: Live Feed or Analytics View */}
        {activeTab === 'feed' ? (
          <AlertTable
            alerts={alerts}
            totalAlerts={totalAlerts}
            isLoading={isLoading}
            selectedAlertId={selectedAlert?.id}
            onSelectAlert={handleSelectAlert}
            searchQuery={searchQuery}
            onSearchChange={setSearchQuery}
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            statusFilter={statusFilter}
            onStatusChange={setStatusFilter}
            page={page}
            onPageChange={setPage}
          />
        ) : (
          <AnalyticsView metrics={metrics} />
        )}

      </main>

      {/* Detailed Enrichment Modal */}
      {selectedAlert && (
        <AlertDetailModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onTakeAction={handleTakeAction}
          isActionLoading={isActionLoading}
        />
      )}

      {/* Ingest Modal */}
      <IngestAlertModal
        isOpen={isIngestModalOpen}
        onClose={() => setIsIngestModalOpen(false)}
        onIngest={handleIngestSubmit}
        isLoading={isIngesting}
      />

    </div>
  );
}
