import { useState, useEffect, useRef, useCallback } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell, ReferenceLine } from 'recharts';
import { AlertCircle, ShieldAlert, CheckCircle2, Play, Square, RefreshCcw, Activity, Clock, FileWarning, FileCheck2, Loader2, ShieldCheck, ChevronRight, Radio, Terminal } from 'lucide-react';
import { format } from 'date-fns';

const API_URL = 'http://127.0.0.1:8000';
const WS_URL = 'ws://127.0.0.1:8000/ws/incidents';
const API_TOKEN = import.meta.env.VITE_AGENT_TOKEN;
// Reserved connection state retained for the existing incident stream integration.
void WS_URL;
if (!API_TOKEN) throw new Error("Missing VITE_AGENT_TOKEN");

type ActionStatus = 'pending' | 'delivered' | 'complete' | 'failed';
type ActionType = 'terminate' | 'resume' | 'restore';
interface Action { id: string; type: ActionType; status: ActionStatus; }
interface IncidentEvent { id: string; timestamp: string; score: number; signal_contributions?: Record<string, number>; }
interface Reason { reason: string; }
interface Incident {
  id: string; pid: number | null; process_name: string; cmdline: string[]; create_time: number;
  status: string; max_score: number; start_time: string; contained_after_ms: number | null;
  affected_count: number; restored_count: number; events?: IncidentEvent[]; reasons?: Reason[]; actions?: Action[];
}

function StatusPill({ status }: { status: string }) {
  const config: Record<string, { cls: string; icon: React.ReactNode }> = {
    Alert: { cls: 'status-neutral', icon: <AlertCircle /> },
    'Suspend-Pending': { cls: 'status-pending', icon: <Loader2 /> },
    Suspended: { cls: 'status-danger', icon: <ShieldAlert /> },
    'Terminate-Pending': { cls: 'status-pending', icon: <Loader2 /> },
    Terminated: { cls: 'status-danger', icon: <Square /> },
    Restored: { cls: 'status-ok', icon: <CheckCircle2 /> },
    Resumed: { cls: 'status-neutral', icon: <Play /> },
    Failed: { cls: 'status-danger', icon: <AlertCircle /> },
  };
  const item = config[status] ?? { cls: 'status-neutral', icon: <AlertCircle /> };
  return <span className={`status-pill ${item.cls}`}>{item.icon}<span>{status}</span></span>;
}

function ScoreGauge({ score }: { score: number }) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  return <div className="score-gauge" aria-label={`Threat score ${score.toFixed(0)} of 100`}>
    <svg viewBox="0 0 128 128" role="img" aria-hidden="true">
      <circle className="gauge-track" cx="64" cy="64" r={radius} />
      <circle className="gauge-value" cx="64" cy="64" r={radius} strokeDasharray={circumference} strokeDashoffset={circumference * (1 - Math.min(score, 100) / 100)} />
      {[40, 70, 90].map((n) => <line key={n} className={`gauge-marker marker-${n}`} x1="64" y1="5" x2="64" y2="12" transform={`rotate(${n * 3.6} 64 64)`} />)}
    </svg>
    <div className="gauge-label"><strong>{score.toFixed(0)}</strong><span>RISK SCORE</span></div>
  </div>;
}

export default function App() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isMock, setIsMock] = useState(false);
  const [backendStatus, setBackendStatus] = useState<'connected' | 'disconnected' | 'polling'>('disconnected');
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [confirmTerminate, setConfirmTerminate] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectDelayRef = useRef(1000);
  const reconnectTimerRef = useRef<number | null>(null);
  const pollTimerRef = useRef<number | null>(null);
  void wsRef;
  void reconnectDelayRef;
  void reconnectTimerRef;
  const isMockRef = useRef(isMock);
  const selectedIdRef = useRef(selectedId);
  useEffect(() => { isMockRef.current = isMock; }, [isMock]);
  useEffect(() => { selectedIdRef.current = selectedId; }, [selectedId]);

  const fetchIncidents = useCallback(async () => {
    if (isMockRef.current) return;
    try {
      const res = await fetch(`${API_URL}/api/incidents`, { headers: { 'x-agent-token': API_TOKEN } });
      if (res.ok) {
        const data = await res.json();
        setIncidents(prev => {
          const newIncidents = data.map((newInc: any) => { const existing = prev.find(p => p.id === newInc.id); return existing ? { ...existing, ...newInc } : newInc; });
          return JSON.stringify(prev) === JSON.stringify(newIncidents) ? prev : newIncidents;
        });
      }
    } catch { /* backend may be down */ }
  }, []);

  const fetchIncidentDetails = useCallback(async (id: string) => {
    if (isMockRef.current) return;
    try {
      const res = await fetch(`${API_URL}/api/incidents/${id}`, { headers: { 'x-agent-token': API_TOKEN } });
      if (res.ok) {
        const data = await res.json();
        setIncidents(prev => { const newIncidents = prev.map(inc => inc.id === id ? { ...inc, ...data } : inc); return JSON.stringify(prev) === JSON.stringify(newIncidents) ? prev : newIncidents; });
      }
    } catch { /* silently handle */ }
  }, []);

  useEffect(() => {
    if (isMock) {
      if (pollTimerRef.current) { clearInterval(pollTimerRef.current); pollTimerRef.current = null; }
      setBackendStatus('connected');
      setIncidents([{
        id: 'mock-1', pid: 1234, process_name: 'malware.exe', cmdline: ['malware.exe', '--encrypt'], create_time: Date.now() / 1000,
        status: 'Suspended', max_score: 85, start_time: new Date().toISOString(), contained_after_ms: 1250, affected_count: 42, restored_count: 0,
        events: Array.from({ length: 10 }).map((_, i) => ({ id: `ev-${i}`, timestamp: new Date(Date.now() - (10 - i) * 5000).toISOString(), score: Math.min(100, i * 10 + Math.random() * 5), signal_contributions: { rename: 15, entropy: 10, ransomware_combo: 25 } })),
        reasons: [{ reason: 'rename + extension change + high entropy together, typical of ransomware' }], actions: []
      }]);
      return;
    }
    const doPoll = async () => {
      try { await fetchIncidents(); setBackendStatus('connected'); if (selectedIdRef.current) await fetchIncidentDetails(selectedIdRef.current); }
      catch { setBackendStatus('disconnected'); }
    };
    doPoll();
    const interval = incidents.length > 0 ? 1000 : 3000;
    pollTimerRef.current = window.setInterval(doPoll, interval);
    return () => { if (pollTimerRef.current) { clearInterval(pollTimerRef.current); pollTimerRef.current = null; } };
  }, [isMock, fetchIncidents, fetchIncidentDetails, incidents.length]);

  const triggerAction = async (id: string, type: ActionType) => {
    if (isMock) return;
    setActionLoading(`${id}-${type}`);
    try {
      const res = await fetch(`${API_URL}/api/incidents/${id}/actions`, { method: 'POST', headers: { 'x-agent-token': API_TOKEN, 'Content-Type': 'application/json' }, body: JSON.stringify({ type }) });
      if (res.status === 409) { /* already exists, refresh */ }
      await fetchIncidentDetails(id);
    } catch { /* silently handle */ }
    finally { setActionLoading(null); setConfirmTerminate(false); }
  };

  const totalIncidents = incidents.length;
  const ttdValues = incidents.filter(i => i.contained_after_ms != null && i.contained_after_ms > 0);
  const ttdAvg = ttdValues.length > 0 ? ttdValues.reduce((acc, inc) => acc + (inc.contained_after_ms ?? 0), 0) / ttdValues.length : 0;
  const totalFilesAffected = incidents.reduce((acc, inc) => acc + Math.max(inc.affected_count ?? 0, inc.restored_count ?? 0), 0);
  const totalRestored = incidents.reduce((acc, inc) => acc + inc.restored_count, 0);
  const selected = incidents.find(i => i.id === selectedId);
  const canResume = selected?.status === 'Suspended';
  const canTerminate = selected?.status === 'Suspended' || selected?.status === 'Resumed';
  const canRestore = selected?.status === 'Terminated' && (selected?.restored_count ?? 0) === 0;
  const hasPendingAction = (type: ActionType) => selected?.actions?.some(a => a.type === type && (a.status === 'pending' || a.status === 'delivered')) ?? false;
  const activeThreat = incidents.some(i => i.status === 'Suspended' || i.status === 'Terminated' || i.status === 'Failed');
  const restoredPercent = selected && Math.max(selected.affected_count ?? 0, selected.restored_count ?? 0) > 0 ? Math.min(100, selected.restored_count / Math.max(selected.affected_count ?? 0, selected.restored_count ?? 0) * 100) : 0;
  const events = selected?.events?.slice().reverse() ?? [];
  const signals = selected?.events?.[0]?.signal_contributions ? Object.entries(selected.events[0].signal_contributions).filter(([k, v]) => k !== 'total' && v > 0).map(([name, value]) => ({ name: name.replaceAll('_', ' '), value })) : [];

  return <main className={`app-shell ${activeThreat ? 'has-threat' : ''}`}>
    <div className="top-rule" />
    <header className="masthead enter">
      <a className="brand" href="#top" aria-label="ThreatShield AI home"><span className="brand-mark"><ShieldAlert size={22} /></span><span><b>THREATSHIELD <em>AI</em></b><small>ENDPOINT DEFENSE / INCIDENT ROOM</small></span></a>
      <div className="header-right">
        <label className="mock-toggle"><input type="checkbox" checked={isMock} onChange={e => setIsMock(e.target.checked)} /><span className="toggle-track" /><span>Demo feed</span></label>
        <div className="connection"><span className={`connection-dot ${backendStatus}`} /><span>{backendStatus === 'connected' ? `LIVE · ${incidents.length > 0 ? '1' : '3'}s SYNC` : backendStatus === 'polling' ? 'SYNCING' : 'OFFLINE'}</span></div>
      </div>
    </header>

    <section className="intro-row enter" style={{ animationDelay: '.06s' }}>
      <div><div className="eyebrow"><Radio size={13} /> PROTECTION OVERVIEW <span className="eyebrow-line" /></div><h1>Threats, <span>contained.</span></h1><p>Every second counts. See the signal, the response, and what came back.</p></div>
      <div className="today-stamp"><span>OPERATOR CONSOLE</span><strong>{format(new Date(), 'dd MMM yyyy')}</strong></div>
    </section>

    <section className="overview-grid enter" style={{ animationDelay: '.12s' }}>
      <article className="containment-card">
        <div className="metric-top"><span className="eyebrow">MEAN TIME TO CONTAIN</span><span className="metric-icon"><Clock size={17} /></span></div>
        <div className="hero-metric">{ttdAvg > 0 ? <>{(ttdAvg / 1000).toFixed(1)}<small>s</small></> : <>—<small> s</small></>}</div>
        <div className="metric-foot"><span className="metric-pip" /> ALERT <ChevronRight size={13} /> CONTAINED <span className="metric-divider" /> <b>{ttdValues.length} CASE{ttdValues.length === 1 ? '' : 'S'}</b></div>
      </article>
      <article className="support-stat"><span>INCIDENTS OBSERVED</span><strong>{totalIncidents.toString().padStart(2, '0')}</strong><div className="stat-foot"><Activity size={14} /> Across this session</div></article>
      <article className="support-stat"><span>FILES AT RISK</span><strong>{totalFilesAffected.toString().padStart(2, '0')}</strong><div className="stat-foot"><FileWarning size={14} /> Identified in incidents</div></article>
      <article className="support-stat recovered-stat"><span>FILES RECOVERED</span><strong>{totalRestored.toString().padStart(2, '0')}</strong><div className="stat-foot"><FileCheck2 size={14} /> Returned to safety</div></article>
    </section>

    <section className="workspace enter" style={{ animationDelay: '.18s' }}>
      <div className="case-column panel">
        <div className="section-heading"><div><span className="eyebrow">CASE REGISTER</span><h2>Incidents <sup>{totalIncidents}</sup></h2></div><span className="heading-side">NEWEST FIRST <span className="mini-live" /></span></div>
        {incidents.length === 0 ? <div className="empty-state"><div className="empty-seal"><ShieldCheck size={28} /><span /></div><div className="eyebrow">ALL CLEAR</div><h3>Your endpoints are quiet.</h3><p>No ransomware behavior has been detected. We’re watching file activity in real time.</p><div className="watching"><span className="connection-dot connected" /> MONITORING ACTIVE</div></div> : <div className="case-list" role="list">
          {incidents.map((inc, index) => <button type="button" role="listitem" key={inc.id} onClick={() => { setSelectedId(inc.id); setConfirmTerminate(false); fetchIncidentDetails(inc.id); }} className={`case-row ${selectedId === inc.id ? 'selected' : ''} ${['Suspended', 'Terminated', 'Failed'].includes(inc.status) ? 'row-danger' : ''}`} style={{ animationDelay: `${index * 50}ms` }}>
            <span className="case-time">{format(new Date(inc.start_time), 'HH:mm:ss')}<small>{format(new Date(inc.start_time), 'dd MMM')}</small></span>
            <span className="case-main"><strong>{inc.process_name}</strong><small>PID {inc.pid ?? 'N/A'} <span>·</span> {inc.cmdline?.[1] ?? 'process activity'}</small></span>
            <span className="case-score"><b>{inc.max_score.toFixed(0)}</b><small>RISK</small></span>
            <StatusPill status={inc.status} />
          </button>)}
        </div>}
        <div className="list-footer"><span><span className="legend-dot danger" /> Elevated</span><span><span className="legend-dot neutral" /> Monitored</span><span><span className="legend-dot ok" /> Recovered</span></div>
      </div>

      <div className={`detail-column panel ${selected && ['Suspended', 'Terminated', 'Failed'].includes(selected.status) ? 'detail-threat' : ''}`}>
        {!selected ? <div className="detail-placeholder"><div className="placeholder-mark"><Activity size={22} /></div><span className="eyebrow">INCIDENT DOSSIER</span><h3>Select a case to inspect.</h3><p>Detection signals, containment timeline, and recovery actions will appear here.</p></div> : <>
          <div className="detail-header"><div><span className="eyebrow">INCIDENT DOSSIER <span className="dossier-id">/ {selected.id.slice(0, 8).toUpperCase()}</span></span><h2>{selected.process_name}</h2><span className="process-meta">PID {selected.pid ?? 'N/A'} <span>·</span> {format(new Date(selected.start_time), 'dd MMM yyyy, HH:mm:ss')}</span></div><StatusPill status={selected.status} /></div>
          {selected.cmdline?.length > 0 && <div className="command-line"><Terminal size={13} /><code>{selected.cmdline.join(' ')}</code></div>}

          <div className="incident-summary">
            <ScoreGauge score={selected.max_score} />
            <div className="tier-legend"><span className="eyebrow">RESPONSE THRESHOLDS</span><div><i className="tier-line alert-tier" /><b>40</b><span>Alert</span></div><div><i className="tier-line suspend-tier" /><b>70</b><span>Suspend</span></div><div><i className="tier-line terminate-tier" /><b>90</b><span>Terminate</span></div></div>
            <div className="mini-result"><span className="eyebrow">CONTAINED IN</span><strong>{selected.contained_after_ms != null && selected.contained_after_ms > 0 ? (selected.contained_after_ms / 1000).toFixed(2) : '—'}<small>{selected.contained_after_ms != null && selected.contained_after_ms > 0 ? 's' : ''}</small></strong><span>FROM FIRST ALERT</span></div>
          </div>

          <section className="timeline-section"><div className="section-label"><span className="eyebrow">RESPONSE TIMELINE</span><span>{selected.contained_after_ms != null && selected.contained_after_ms > 0 ? `${(selected.contained_after_ms / 1000).toFixed(2)}s TO CONTAIN` : 'LIVE OBSERVATION'}</span></div>
            <div className="timeline-track"><div className="timeline-progress" /><div className="timeline-step"><i className="step-dot detected" /><b>DETECTED</b><small>{selected.events?.[0] ? format(new Date(selected.events[0].timestamp), 'HH:mm:ss') : format(new Date(selected.start_time), 'HH:mm:ss')}</small></div><div className="timeline-step"><i className={`step-dot ${selected.max_score >= 40 ? 'reached' : ''}`} /><b>ALERT</b><small>Score ≥ 40</small></div><div className="timeline-step"><i className={`step-dot ${selected.max_score >= 70 ? 'reached' : ''}`} /><b>CONTAINED</b><small>{selected.status.includes('Pending') ? 'Awaiting action' : selected.status}</small></div><div className="timeline-step"><i className={`step-dot ${selected.restored_count > 0 ? 'recovered' : ''}`} /><b>RECOVERED</b><small>{selected.restored_count > 0 ? 'Files returned' : 'Awaiting restore'}</small></div></div>
          </section>

          <section className="recovery-band"><div className="recovery-copy"><div><span className="eyebrow">BLAST RADIUS / RECOVERY</span><strong>{selected.restored_count}<small> / {Math.max(selected.affected_count ?? 0, selected.restored_count ?? 0)} files</small></strong></div><span className="recovery-percent">{restoredPercent.toFixed(0)}% RESTORED</span></div><div className="recovery-track"><span style={{ width: `${restoredPercent}%` }} /></div></section>

          {selected.reasons?.length ? <section className="signals-section"><span className="eyebrow">WHY IT WAS FLAGGED</span>{selected.reasons.map((reason) => <div className="signal-note" key={reason.reason}><AlertCircle size={16} /><p>{reason.reason}<small>MITRE ATT&CK · T1486 DATA ENCRYPTED FOR IMPACT</small></p></div>)}</section> : null}

          {events.length > 0 && <section className="chart-section"><div className="section-label"><span className="eyebrow">BEHAVIORAL SCORE</span><span>0—100 / RECENT SIGNALS</span></div><div className="chart-box"><ResponsiveContainer width="100%" height="100%"><LineChart data={events} margin={{ top: 14, right: 8, bottom: 0, left: -24 }}><defs><linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#e5202e" stopOpacity={0.15} /><stop offset="100%" stopColor="#e5202e" stopOpacity={0} /></linearGradient></defs><XAxis dataKey="timestamp" tickFormatter={t => format(new Date(t), 'HH:mm:ss')} tick={{ fill: '#8b8b95', fontSize: 10, fontFamily: 'IBM Plex Mono' }} axisLine={false} tickLine={false} /><YAxis domain={[0, 100]} ticks={[0, 40, 70, 90, 100]} tick={{ fill: '#8b8b95', fontSize: 9 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: '#fff', border: '1px solid #e4e4e7', borderRadius: 10, color: '#0f0f12', fontSize: 12, boxShadow: '0 8px 28px rgba(15,15,18,.08)' }} labelFormatter={v => format(new Date(String(v)), 'HH:mm:ss')} formatter={v => [`${v} / 100`, 'Risk score']} /><ReferenceLine y={40} stroke="#a1a1aa" strokeDasharray="3 4" /><ReferenceLine y={70} stroke="#e5202e" strokeOpacity={.45} strokeDasharray="3 4" /><ReferenceLine y={90} stroke="#e5202e" strokeDasharray="3 4" /><Line type="monotone" dataKey="score" stroke="#e5202e" strokeWidth={2.5} dot={false} activeDot={{ r: 4, fill: '#e5202e', stroke: '#fff', strokeWidth: 2 }} isAnimationActive /></LineChart></ResponsiveContainer><div className="chart-thresholds"><span>40 ALERT</span><span>70 SUSPEND</span><span>90 TERMINATE</span></div></div></section>}

          {signals.length > 0 && <section className="chart-section signal-chart"><div className="section-label"><span className="eyebrow">SIGNAL CONTRIBUTIONS</span><span>WEIGHTED EVIDENCE</span></div><div className="chart-box"><ResponsiveContainer width="100%" height="100%"><BarChart data={signals} layout="vertical" margin={{ top: 2, right: 24, bottom: 0, left: 4 }}><XAxis type="number" hide domain={[0, 'dataMax + 10']} /><YAxis dataKey="name" type="category" width={110} tick={{ fill: '#62626c', fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip cursor={{ fill: '#f7f7f8' }} contentStyle={{ background: '#fff', border: '1px solid #e4e4e7', borderRadius: 9, fontSize: 12 }} formatter={v => [`${v} pts`, 'Contribution']} /><Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={10} isAnimationActive><Cell fill="#e5202e" />{signals.slice(1).map(item => <Cell key={item.name} fill="#777781" />)}</Bar></BarChart></ResponsiveContainer></div></section>}

          <section className="actions-section"><div className="section-label"><span className="eyebrow">OPERATOR CONTROLS</span><span>ACTIONS ARE AUDITED</span></div><div className="action-buttons">
            <button type="button" onClick={() => triggerAction(selected.id, 'resume')} disabled={!canResume || hasPendingAction('resume') || actionLoading !== null} className="action-button resume-button">{actionLoading === `${selected.id}-resume` || hasPendingAction('resume') ? <Loader2 className="spin" size={15} /> : <Play size={15} />} {hasPendingAction('resume') ? 'PENDING' : 'RESUME'}</button>
            <button type="button" onClick={() => confirmTerminate ? triggerAction(selected.id, 'terminate') : setConfirmTerminate(true)} disabled={!canTerminate || hasPendingAction('terminate') || actionLoading !== null} className={`action-button terminate-button ${confirmTerminate ? 'confirming' : ''}`}>{actionLoading === `${selected.id}-terminate` || hasPendingAction('terminate') ? <Loader2 className="spin" size={15} /> : <Square size={14} />} {hasPendingAction('terminate') ? 'PENDING' : confirmTerminate ? 'CONFIRM TERMINATE' : 'TERMINATE'}</button>
            <button type="button" onClick={() => triggerAction(selected.id, 'restore')} disabled={!canRestore || hasPendingAction('restore') || actionLoading !== null} className="action-button restore-button">{actionLoading === `${selected.id}-restore` || hasPendingAction('restore') ? <Loader2 className="spin" size={15} /> : <RefreshCcw size={15} />} {hasPendingAction('restore') ? 'PENDING' : 'RESTORE FILES'}</button>
          </div>{confirmTerminate && <div className="confirm-note" role="status">Terminate this process? Select “Confirm terminate” again to send the audited action.<button type="button" onClick={() => setConfirmTerminate(false)}>Cancel</button></div>}
          {selected.actions?.length ? <div className="action-history">{selected.actions.map(action => <div className="history-row" key={action.id}><span>{action.type} requested</span><span className={action.status === 'complete' ? 'history-ok' : action.status === 'failed' ? 'history-failed' : 'history-pending'}>{action.status === 'complete' && <CheckCircle2 size={13} />}{(action.status === 'pending' || action.status === 'delivered') && <Loader2 className="spin" size={13} />}{action.status}</span></div>)}</div> : null}</section>
        </>}
      </div>
    </section>
    <footer className="page-footer"><span>THREATSHIELD AI <span>·</span> ENDPOINT RANSOMWARE DEFENSE</span><span>DETECT <i /> CONTAIN <i /> RESTORE</span></footer>
  </main>;
}
