import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import HostTerminal from './components/HostTerminal.jsx';
import Sidebar from './components/Sidebar.jsx';
import Login from './pages/Login.jsx';
import { AuthProvider, useAuth } from './auth.jsx';
import { apiFetch, ApiError } from './api.js';
import {
  ShieldAlert, Server, Database, Activity, Lock, Unlock, CheckCircle2,
  Bell, BellOff, ZoomIn, ZoomOut, Network as NetworkIcon, Loader2,
  Trash2, CheckCheck, X, RotateCcw, LayoutGrid,
  Sun, Moon, Search, ExternalLink, Copy, Check, RefreshCw, ChevronDown, ChevronUp,
  Terminal, Eraser, Maximize2, LogOut, KeyRound,
} from 'lucide-react';

const DEFAULT_BACKEND_URL = 'http://localhost:8001';
const SOLANA_RPC_URL = 'http://localhost:8899';
const MAX_NOTIFICATIONS = 100;
const LIVE_MAX_LIMIT = 5000;
const SEARCH_FETCH_LIMIT = 5000;
const LOG_PAGE_SIZE = 20;

// Claves de persistencia local (solo en el navegador del usuario)
const STORAGE_KEYS = {
  settings: 'sdn-dash:settings',
  notifications: 'sdn-dash:notifications',
  seen: 'sdn-dash:seen-alerts',
  positions: 'sdn-dash:node-positions',
  theme: 'sdn-dash:theme',
};

// --- Configuración por defecto del dashboard ---

const DEFAULT_SETTINGS = {
  backendUrl: DEFAULT_BACKEND_URL,
  pollInterval: 2000,      // ms entre consultas al backend
  attackWindow: 15,        // s en los que un evento se considera "activo" en el mapa
  timelineSize: 8,         // eventos en la línea de tiempo
  logSize: 20,             // eventos iniciales en el registro en vivo
  widgets: {
    threat: true,
    services: true,
    topology: true,
    timeline: true,
    blockchain: true,
    aiPanel: true,
    eventLog: true,
    kpis: false,
    attackTypes: false,
    severity: false,
    topAttackers: false,
    ports: false,
  },
  notifications: {
    enabled: true,
    toasts: true,
    sound: false,
  },
  topology: {
    lockNodes: false,
  },
};

const BASE_WIDGETS = [
  { key: 'threat', label: 'Contexto de amenaza crítica', desc: 'Detalle de la última alerta recibida.' },
  { key: 'services', label: 'Estado de servicios', desc: 'MongoDB y Solana.' },
  { key: 'topology', label: 'Topología', desc: 'Mapa de nodos de SDN_Net.' },
  { key: 'timeline', label: 'Línea de tiempo de integridad', desc: 'Secuencia de eventos recientes.' },
  { key: 'blockchain', label: 'Último hash blockchain', desc: 'Firma de la última transacción en Solana.' },
  { key: 'aiPanel', label: 'Panel de IA', desc: 'Distribución % por tipo de ataque y totales.' },
  { key: 'eventLog', label: 'Registro de eventos en vivo', desc: 'Lista de alertas en tiempo real.' },
];

const EXTRA_WIDGETS = [
  { key: 'kpis', label: 'Indicadores clave (KPIs)', desc: 'Franja superior con totales, bloqueos, confianza media y atacantes únicos.' },
  { key: 'attackTypes', label: 'Distribución por tipo de ataque', desc: 'Barras con el número de alertas por tipo de ataque.' },
  { key: 'severity', label: 'Distribución de severidad', desc: 'Gráfico circular por nivel de severidad según la confianza de la IA.' },
  { key: 'topAttackers', label: 'Top IPs atacantes', desc: 'Direcciones de origen con más alertas.' },
  { key: 'ports', label: 'Puertos más atacados', desc: 'Puertos de destino más frecuentes en las alertas.' },
];

// IPs reales de la SDN levantada por VNX (datacenter_sdn.xml). Se muestran fijas
// en la topología para que no cambien con cada ataque; en un IP_Spoofing el
// atacante falsea su IP (p. ej. 8.8.8.8) y esa IP falsa aparece en el detalle
// del evento, pero el nodo del mapa sigue representando al host físico real.
const TOPOLOGY = {
  attacker: { ip: '192.168.1.50' },
  server1: { ip: '192.168.1.10' },
  server2: { ip: '192.168.1.11' },
};

const DEFAULT_NODE_POSITIONS = {
  attacker: { x: 12, y: 64 },
  switchNode: { x: 47, y: 40 },
  server1: { x: 86, y: 22 },
  server2: { x: 86, y: 70 },
};

const EMPTY_FILTERS = {
  id: '',
  type: '',
  dateFrom: '',
  dateTo: '',
  timeFrom: '',
  timeTo: '',
  attacker: '',
  victim: '',
  port: '',
  action: 'all',
  severity: 'all',
  minConfidence: 0,
};

// --- Persistencia local ---

function loadJSON(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function saveJSON(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // almacenamiento lleno o no disponible: se ignora
  }
}

function loadSettings() {
  const s = loadJSON(STORAGE_KEYS.settings, {}) || {};
  const widgets = { ...DEFAULT_SETTINGS.widgets, ...(s.widgets || {}) };
  delete widgets.architecture; // panel retirado del dashboard
  return {
    ...DEFAULT_SETTINGS,
    ...s,
    widgets,
    notifications: { ...DEFAULT_SETTINGS.notifications, ...(s.notifications || {}) },
    topology: { ...DEFAULT_SETTINGS.topology, ...(s.topology || {}) },
  };
}

function loadPositions() {
  const stored = loadJSON(STORAGE_KEYS.positions, {}) || {};
  const result = { ...DEFAULT_NODE_POSITIONS };
  for (const id of Object.keys(DEFAULT_NODE_POSITIONS)) {
    const p = stored[id];
    if (p && Number.isFinite(p.x) && Number.isFinite(p.y)) result[id] = { x: p.x, y: p.y };
  }
  return result;
}

function loadTheme() {
  const t = loadJSON(STORAGE_KEYS.theme, 'dark');
  return t === 'light' ? 'light' : 'dark';
}

// --- Helpers de dominio ---

function getSeverity(confidence) {
  if (confidence === undefined || confidence === null) {
    return { label: 'N/D', text: 'text-gray-400', border: 'border-gray-700', bg: 'bg-gray-800' };
  }
  if (confidence >= 90) return { label: 'CRÍTICA', text: 'text-red-400', border: 'border-red-700', bg: 'bg-red-900/30' };
  if (confidence >= 75) return { label: 'ALTA', text: 'text-orange-400', border: 'border-orange-700', bg: 'bg-orange-900/30' };
  if (confidence >= 50) return { label: 'MEDIA', text: 'text-yellow-400', border: 'border-yellow-700', bg: 'bg-yellow-900/30' };
  return { label: 'BAJA', text: 'text-blue-400', border: 'border-blue-700', bg: 'bg-blue-900/30' };
}

function isBlockAction(actionTaken) {
  const a = (actionTaken || '').toLowerCase();
  return a.includes('drop') || a.includes('block') || a.includes('deny');
}

function shortId(id) {
  if (!id) return '—';
  const s = String(id);
  return s.length > 8 ? s.slice(-8) : s;
}

// El backend guarda las fechas en UTC. Si el string ISO no trae 'Z' ni offset
// (+HH:MM / -HH:MM), el navegador lo interpretaría como hora LOCAL, corriendo
// el timestamp varias horas — suficiente para que un evento pasado parezca
// estar "en el futuro" y la topología nunca vuelva a reposo. Forzamos UTC
// aquí como red de seguridad, incluso si el backend ya se corrigió.
function parseTimestamp(ts) {
  if (!ts) return new Date(NaN);
  const hasTz = /Z$|[+-]\d{2}:\d{2}$/.test(ts);
  return new Date(hasTz ? ts : `${ts}Z`);
}

function formatDateTime(ts) {
  const d = parseTimestamp(ts);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

const pad2 = (n) => String(n).padStart(2, '0');

// Fecha local en formato YYYY-MM-DD (mismo formato que <input type="date">)
function localDateKey(d) {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

function timeToMinutes(hhmm) {
  const [h, m] = hhmm.split(':').map(Number);
  return h * 60 + m;
}

function timeAgo(ms, now) {
  if (!Number.isFinite(ms)) return '';
  const s = Math.max(0, Math.floor((now - ms) / 1000));
  if (s < 60) return `hace ${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `hace ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `hace ${h} h`;
  return new Date(ms).toLocaleDateString();
}

function countBy(items, keyFn, limit = 6) {
  const map = new Map();
  for (const it of items) {
    const k = keyFn(it);
    if (k === undefined || k === null || k === '') continue;
    const key = String(k);
    map.set(key, (map.get(key) || 0) + 1);
  }
  return [...map.entries()]
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}

const clamp = (v, min, max) => Math.min(max, Math.max(min, v));

function matchesFilters(a, f) {
  if (f.id) {
    const q = f.id.trim().toLowerCase();
    const haystack = `${a._id || ''} ${a.blockchain_signature || ''}`.toLowerCase();
    if (!haystack.includes(q)) return false;
  }
  if (f.type && a.attack_type !== f.type) return false;

  if (f.dateFrom || f.dateTo || f.timeFrom || f.timeTo) {
    const d = parseTimestamp(a.timestamp);
    if (Number.isNaN(d.getTime())) return false;
    const key = localDateKey(d);
    if (f.dateFrom && key < f.dateFrom) return false;
    if (f.dateTo && key > f.dateTo) return false;

    const mins = d.getHours() * 60 + d.getMinutes();
    const tf = f.timeFrom ? timeToMinutes(f.timeFrom) : null;
    const tt = f.timeTo ? timeToMinutes(f.timeTo) : null;
    if (tf !== null && tt !== null && tf > tt) {
      // franja horaria que cruza la medianoche (p. ej. 22:00 → 02:00)
      if (!(mins >= tf || mins <= tt)) return false;
    } else {
      if (tf !== null && mins < tf) return false;
      if (tt !== null && mins > tt) return false;
    }
  }

  if (f.attacker && !(a.attacker_ip || '').includes(f.attacker.trim())) return false;
  if (f.victim && !(a.victim_ip || '').includes(f.victim.trim())) return false;
  if (String(f.port).trim() !== '' && String(a.victim_port) !== String(f.port).trim()) return false;
  if (f.action === 'blocked' && !isBlockAction(a.action_taken)) return false;
  if (f.action === 'allowed' && isBlockAction(a.action_taken)) return false;
  if (f.severity !== 'all' && getSeverity(a.confidence).label !== f.severity) return false;
  if ((Number(a.confidence) || 0) < f.minConfidence) return false;
  return true;
}

function countActiveFilters(f) {
  return Object.keys(EMPTY_FILTERS).filter((k) => f[k] !== EMPTY_FILTERS[k] && String(f[k]).trim() !== '').length;
}

function solanaExplorerUrl(signature) {
  return `https://explorer.solana.com/tx/${signature}?cluster=custom&customUrl=${encodeURIComponent(SOLANA_RPC_URL)}`;
}

function playAlertSound() {
  try {
    const Ctx = window.AudioContext || window.webkitAudioContext;
    if (!Ctx) return;
    const ctx = new Ctx();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'square';
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.0001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.12, ctx.currentTime + 0.01);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);
    osc.connect(gain).connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.3);
    osc.onended = () => ctx.close();
  } catch {
    // el navegador puede bloquear audio sin interacción previa del usuario
  }
}

function alertToNotification(a) {
  return {
    id: a._id,
    attack_type: a.attack_type,
    confidence: a.confidence,
    attacker_ip: a.attacker_ip,
    victim_ip: a.victim_ip,
    victim_port: a.victim_port,
    action_taken: a.action_taken,
    timestamp: a.timestamp,
    receivedAt: Date.now(),
    read: false,
  };
}

// --- Componentes genéricos ---

function Panel({ title, subtitle, children, className = '' }) {
  return (
    <div className={`bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg ${className}`}>
      <div className="flex items-center justify-between mb-3 gap-2">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">{title}</h2>
        {subtitle && <span className="text-[10px] text-gray-600 font-mono shrink-0">{subtitle}</span>}
      </div>
      {children}
    </div>
  );
}

function Toggle({ checked, onChange, label, desc }) {
  return (
    <label className="flex items-start justify-between gap-4 py-2.5 cursor-pointer">
      <span className="min-w-0">
        <span className="block text-sm text-gray-200">{label}</span>
        {desc && <span className="block text-[11px] text-gray-500 mt-0.5 leading-snug">{desc}</span>}
      </span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`relative shrink-0 mt-0.5 w-9 h-5 rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${checked ? 'bg-blue-600' : 'bg-gray-600'}`}
      >
        <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white transition-transform ${checked ? 'translate-x-4' : ''}`} />
      </button>
    </label>
  );
}

function RangeSetting({ label, desc, value, min, max, step = 1, unit = '', onChange }) {
  return (
    <div className="py-2.5">
      <div className="flex items-center justify-between">
        <span className="text-sm text-gray-200">{label}</span>
        <span className="text-xs font-mono text-blue-300">{value}{unit}</span>
      </div>
      {desc && <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{desc}</p>}
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full mt-2 accent-blue-500"
      />
    </div>
  );
}

function SectionTitle({ children }) {
  return <h3 className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mt-5 mb-1 first:mt-0">{children}</h3>;
}

// Estado real de un servicio (MongoDB / Solana) según /api/health:
// 'on' | 'off' | 'unknown'. Si el backend no está conectado o el endpoint no
// existe todavía, se muestra neutro en vez de un ONLINE falso.
function serviceState(ok, connected) {
  if (!connected) return 'unknown';
  if (ok === undefined || ok === null) return 'on';
  return ok ? 'on' : 'off';
}

// Anillo de salud: fracción de servicios en línea (gráfico real del panel).
function HealthRing({ states, isLight }) {
  const total = states.length;
  const known = states.filter((s) => s !== 'unknown');
  const on = states.filter((s) => s === 'on').length;
  const track = isLight ? '#e5e7eb' : '#111827';
  const centerFill = isLight ? '#64748b' : '#9ca3af';

  if (known.length === 0) {
    return (
      <svg viewBox="0 0 42 42" className="w-32 h-32 shrink-0">
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke={track} strokeWidth="5" />
        <text x="21" y="21" textAnchor="middle" dominantBaseline="central" fill={centerFill} fontSize="9" fontFamily="monospace">—</text>
      </svg>
    );
  }

  const onPct = (on / total) * 100;
  const offPct = ((known.length - on) / total) * 100;
  return (
    <svg viewBox="0 0 42 42" className="w-32 h-32 shrink-0 -rotate-90">
      <circle cx="21" cy="21" r="15.915" fill="transparent" stroke={track} strokeWidth="5" />
      {offPct > 0 && (
        <circle
          cx="21" cy="21" r="15.915" fill="transparent" stroke="#ef4444" strokeWidth="5"
          strokeDasharray={`${offPct} ${100 - offPct}`} strokeDashoffset={-onPct}
        />
      )}
      {onPct > 0 && (
        <circle
          cx="21" cy="21" r="15.915" fill="transparent" stroke="#22c55e" strokeWidth="5"
          strokeDasharray={`${onPct} ${100 - onPct}`} strokeDashoffset={0}
        />
      )}
      <text x="21" y="21" textAnchor="middle" dominantBaseline="central" fill={isLight ? '#1e293b' : '#e5e7eb'} fontSize="8" fontFamily="monospace" transform="rotate(90 21 21)">
        {on}/{total}
      </text>
    </svg>
  );
}

function ServicePill({ state }) {
  const style = state === 'on'
    ? 'border-green-700 bg-green-900/30 text-green-400'
    : state === 'off'
      ? 'border-red-700 bg-red-900/30 text-red-400'
      : 'border-gray-700 bg-gray-900/50 text-gray-500';
  const dot = state === 'on' ? 'bg-green-500' : state === 'off' ? 'bg-red-500' : 'bg-gray-600';
  const label = state === 'on' ? 'ONLINE' : state === 'off' ? 'OFFLINE' : '—';
  return (
    <span className={`flex items-center gap-1.5 text-xs font-bold font-mono px-2.5 py-1 rounded-full border ${style}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${dot}`} />{label}
    </span>
  );
}

function Modal({ onClose, children, className = '', z = 'z-[60]', label }) {
  return (
    <div className={`fixed inset-0 ${z} flex items-center justify-center p-4`} role="dialog" aria-modal="true" aria-label={label}>
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm backdrop-in" onClick={onClose} />
      <div className={`modal-in relative bg-gray-800 border border-gray-700 rounded-xl shadow-2xl w-full flex flex-col max-h-[90vh] ${className}`}>
        {children}
      </div>
    </div>
  );
}

function CopyButton({ text, label = 'Copiar' }) {
  const [done, setDone] = useState(false);
  const copy = async (e) => {
    e.stopPropagation();
    try {
      await navigator.clipboard.writeText(text);
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } catch {
      // portapapeles no disponible
    }
  };
  return (
    <button
      onClick={copy}
      className="shrink-0 p-1 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-700"
      title={label}
      aria-label={label}
    >
      {done ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
    </button>
  );
}

function Field({ label, value, mono = true, copy, className = '', valueClass = 'text-gray-200' }) {
  return (
    <div className={`min-w-0 ${className}`}>
      <p className="text-[11px] text-gray-500">{label}</p>
      <div className="flex items-start gap-1">
        <p className={`text-sm break-all ${mono ? 'font-mono' : ''} ${valueClass}`}>{value ?? '—'}</p>
        {copy && value && <CopyButton text={String(value)} />}
      </div>
    </div>
  );
}

// --- Gráfico: mezcla de ataques en vivo (% por tipo, se actualiza con cada evento) ---

const MIX_PALETTE = ['#f87171', '#fb923c', '#facc15', '#60a5fa', '#c084fc', '#22d3ee', '#4ade80', '#f472b6'];

function mixColor(label) {
  let h = 0;
  for (let i = 0; i < label.length; i++) h = (h * 31 + label.charCodeAt(i)) >>> 0;
  return MIX_PALETTE[h % MIX_PALETTE.length];
}

function AttackMixBars({ data }) {
  const total = data.reduce((s, d) => s + d.value, 0);

  if (!total) {
    return <div className="text-xs text-gray-500 font-mono py-6 text-center">Sin ataques registrados todavía.</div>;
  }

  return (
    <div>
      {/* Franja 100% apilada: foto instantánea de la mezcla */}
      <div className="flex h-2.5 rounded overflow-hidden bg-gray-900 mb-3" title="Mezcla total">
        {data.map((d) => (
          <div
            key={d.label}
            className="h-full transition-all duration-500"
            style={{ width: `${(d.value / total) * 100}%`, backgroundColor: mixColor(d.label) }}
            title={`${d.label}: ${((d.value / total) * 100).toFixed(1)}%`}
          />
        ))}
      </div>
      <div className="space-y-2.5">
        {data.map((d) => {
          const pct = (d.value / total) * 100;
          return (
            <div key={d.label}>
              <div className="flex justify-between text-[11px] font-mono mb-1 gap-2">
                <span className="flex items-center gap-1.5 text-gray-300 truncate">
                  <span className="w-2 h-2 rounded-sm shrink-0" style={{ backgroundColor: mixColor(d.label) }} />
                  <span className="truncate">{d.label}</span>
                </span>
                <span className="text-gray-400 shrink-0">{pct.toFixed(1)}% · {d.value}</span>
              </div>
              <div className="h-1.5 bg-gray-900 rounded overflow-hidden">
                <div
                  className="h-full rounded transition-all duration-500"
                  style={{ width: `${pct}%`, backgroundColor: mixColor(d.label) }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// --- Gráficos adicionales (activables desde Configuración) ---

function HBarChart({ data, color, emptyText }) {
  if (!data.length) {
    return <div className="text-xs text-gray-500 font-mono py-6 text-center">{emptyText}</div>;
  }
  const max = Math.max(...data.map((d) => d.value));
  return (
    <div className="space-y-2.5">
      {data.map((d) => (
        <div key={d.label}>
          <div className="flex justify-between text-[11px] font-mono mb-1">
            <span className="text-gray-300 truncate pr-2">{d.label}</span>
            <span className="text-gray-400">{d.value}</span>
          </div>
          <div className="h-1.5 bg-gray-900 rounded overflow-hidden">
            <div className="h-full rounded transition-all duration-500" style={{ width: `${(d.value / max) * 100}%`, backgroundColor: color }} />
          </div>
        </div>
      ))}
    </div>
  );
}

const SEVERITY_BUCKETS = [
  { label: 'CRÍTICA', color: '#f87171' },
  { label: 'ALTA', color: '#fb923c' },
  { label: 'MEDIA', color: '#facc15' },
  { label: 'BAJA', color: '#60a5fa' },
];

function SeverityDonut({ alerts, isLight }) {
  const counts = SEVERITY_BUCKETS.map((b) => ({
    ...b,
    value: alerts.filter((a) => getSeverity(a.confidence).label === b.label).length,
  }));
  const total = counts.reduce((s, c) => s + c.value, 0);

  if (total === 0) {
    return <div className="text-xs text-gray-500 font-mono py-6 text-center">Sin datos de severidad.</div>;
  }

  let offset = 0;
  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 42 42" className="w-28 h-28 shrink-0 -rotate-90">
        <circle cx="21" cy="21" r="15.915" fill="transparent" stroke={isLight ? '#e5e7eb' : '#111827'} strokeWidth="5" />
        {counts.filter((c) => c.value > 0).map((c) => {
          const pct = (c.value / total) * 100;
          const el = (
            <circle
              key={c.label}
              cx="21" cy="21" r="15.915"
              fill="transparent"
              stroke={c.color}
              strokeWidth="5"
              strokeDasharray={`${pct} ${100 - pct}`}
              strokeDashoffset={-offset}
            />
          );
          offset += pct;
          return el;
        })}
        <text x="21" y="21" textAnchor="middle" dominantBaseline="central" fill={isLight ? '#1e293b' : '#e5e7eb'} fontSize="8" fontFamily="monospace" transform="rotate(90 21 21)">
          {total}
        </text>
      </svg>
      <div className="space-y-1.5 text-[11px] font-mono flex-1">
        {counts.map((c) => (
          <div key={c.label} className="flex items-center justify-between gap-2">
            <span className="flex items-center gap-2 text-gray-300">
              <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: c.color }} />
              {c.label}
            </span>
            <span className="text-gray-400">{c.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function KpiStrip({ stats, totalAlerts, totalBlocked }) {
  const items = [
    { label: 'Alertas totales', value: totalAlerts, color: 'text-gray-100' },
    { label: 'Flujos bloqueados', value: `${totalBlocked}`, extra: totalAlerts ? `${Math.round((totalBlocked / totalAlerts) * 100)}%` : '0%', color: 'text-red-400' },
    { label: 'Confianza media IA', value: `${stats.avgConfidence.toFixed(1)}%`, color: 'text-green-400' },
    { label: 'Atacantes únicos', value: stats.uniqueAttackers, color: 'text-orange-400' },
    { label: 'Ataque más frecuente', value: stats.topType || '—', color: 'text-blue-300', small: true },
  ];
  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-4">
      {items.map((it) => (
        <div key={it.label} className="bg-gray-800 p-3 rounded-lg border border-gray-700 shadow-lg">
          <p className="text-[11px] text-gray-500">{it.label}</p>
          <p className={`font-mono font-bold mt-1 truncate ${it.small ? 'text-base' : 'text-2xl'} ${it.color}`}>
            {it.value}
            {it.extra && <span className="text-xs text-gray-500 font-normal ml-2">{it.extra}</span>}
          </p>
        </div>
      ))}
    </div>
  );
}

// --- Mapa de red interactivo (nodos arrastrables) ---

function NetworkMap({ latestAlert, isActive, blocked, targetLabel, zoom, positions, onMoveNode, locked, isLight, onHostClick, onSwitchClick }) {
  const containerRef = useRef(null);
  const dragRef = useRef(null); // { id, dx, dy, startX, startY, moved }
  const [draggingId, setDraggingId] = useState(null);

  const P = positions;
  const server1Active = isActive && targetLabel === 'server1';
  const server2Active = isActive && targetLabel === 'server2';
  const idleLink = isLight ? '#cbd5e1' : '#4b5563';
  const idleBranch = isLight ? '#cbd5e1' : '#374151';

  // Convierte la posición del puntero a % del contenedor. getBoundingClientRect ya
  // incluye el scale() del zoom, así que el cálculo es correcto a cualquier nivel de zoom.
  const toPercent = (e) => {
    const rect = containerRef.current.getBoundingClientRect();
    return {
      x: ((e.clientX - rect.left) / rect.width) * 100,
      y: ((e.clientY - rect.top) / rect.height) * 100,
    };
  };

  const handlePointerDown = (id) => (e) => {
    if (e.button !== 0) return;
    // Guardamos el punto inicial para distinguir click (abrir consola) de drag (mover)
    dragRef.current = { id, dx: 0, dy: 0, startX: e.clientX, startY: e.clientY, moved: false };
    if (!locked) {
      e.preventDefault();
      const p = toPercent(e);
      // Guardamos el desfase para que el nodo no "salte" al centro del cursor
      dragRef.current.dx = p.x - P[id].x;
      dragRef.current.dy = p.y - P[id].y;
      e.currentTarget.setPointerCapture(e.pointerId);
      setDraggingId(id);
    }
  };

  const handlePointerMove = (e) => {
    const d = dragRef.current;
    if (!d) return;
    // Si se movió más de 6px ya es un arrastre, no un click
    if (Math.hypot(e.clientX - d.startX, e.clientY - d.startY) > 6) d.moved = true;
    if (locked) return;
    if (draggingId === null) return;
    const p = toPercent(e);
    onMoveNode(d.id, { x: clamp(p.x - d.dx, 4, 96), y: clamp(p.y - d.dy, 7, 84) });
  };

  const handlePointerUp = (id) => (e) => {
    const d = dragRef.current;
    if (d && !d.moved) {
      if (onHostClick && (id === 'attacker' || id === 'server1' || id === 'server2')) {
        // Click sin arrastre sobre un host: abrir la miniconsola de ese host
        onHostClick(id);
      } else if (id === 'switchNode' && onSwitchClick) {
        // Click sin arrastre sobre el OVS: ofrecer limpieza del switch
        onSwitchClick();
      }
    }
    if (!dragRef.current) return;
    dragRef.current = null;
    setDraggingId(null);
    if (e.currentTarget.hasPointerCapture?.(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  };

  const nodeProps = (id) => {
    const clickable = id === 'attacker' || id === 'server1' || id === 'server2';
    const isSwitch = id === 'switchNode';
    const title = clickable
      ? 'Click para abrir consola · Arrastra para mover'
      : isSwitch
        ? 'Click para limpiar el switch (clean-switch) · Arrastra para mover'
        : (locked ? undefined : 'Arrastra para mover');
    return {
      className: `absolute select-none ${locked ? '' : draggingId === id ? 'cursor-grabbing z-30' : 'cursor-grab z-10 hover:z-20'} ${clickable ? 'cursor-pointer' : ''}`,
      style: {
        left: `${P[id].x}%`,
        top: `${P[id].y}%`,
        transform: 'translate(-50%, -50%)',
        touchAction: locked ? 'auto' : 'none',
      },
      onPointerDown: handlePointerDown(id),
      onPointerMove: handlePointerMove,
      onPointerUp: handlePointerUp(id),
      onPointerCancel: handlePointerUp(id),
      title,
    };
  };

  const dragRing = (id) => (draggingId === id ? 'ring-2 ring-blue-400/70 ring-offset-2 ring-offset-gray-800' : '');

  // Etiqueta posicionada bajo el icono: así el centro del nodo coincide con el icono
  // y las líneas de enlace llegan exactamente a él.
  const labelClass = 'absolute left-1/2 top-full mt-1.5 -translate-x-1/2 flex flex-col items-center whitespace-nowrap pointer-events-none';

  return (
    <div
      ref={containerRef}
      className="relative w-full h-full transition-transform duration-150"
      style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
    >
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="absolute inset-0 w-full h-full pointer-events-none">
        <line
          x1={P.attacker.x} y1={P.attacker.y}
          x2={P.switchNode.x} y2={P.switchNode.y}
          stroke={blocked ? '#ef4444' : isActive ? '#22c55e' : idleLink} strokeWidth="0.6"
          className={isActive ? 'flow-line-active' : ''}
        />
        <line
          x1={P.switchNode.x} y1={P.switchNode.y}
          x2={P.server1.x} y2={P.server1.y}
          stroke={server1Active ? '#ef4444' : idleBranch} strokeWidth="0.5"
          className={server1Active ? 'flow-line-active' : ''}
        />
        <line
          x1={P.switchNode.x} y1={P.switchNode.y}
          x2={P.server2.x} y2={P.server2.y}
          stroke={server2Active ? '#ef4444' : idleBranch} strokeWidth="0.5"
          className={server2Active ? 'flow-line-active' : ''}
        />
      </svg>

      {/* Attacker */}
      <div {...nodeProps('attacker')}>
        <div className={`relative rounded-lg bg-gray-800 ${dragRing('attacker')}`}>
          <div className={`w-14 h-14 rounded-lg flex items-center justify-center border-2 transition-colors hover:border-green-400 ${blocked ? 'bg-red-900/60 border-red-500' : 'bg-green-900/30 border-green-700'}`}>
            <ShieldAlert size={24} className={blocked ? 'text-red-400' : 'text-green-400'} />
          </div>
          <div className="absolute -bottom-2 -right-2 w-6 h-6 rounded-full bg-gray-900 border border-gray-600 flex items-center justify-center" title="Abrir consola">
            <Terminal size={11} className="text-green-400" />
          </div>
        </div>
        <div className={labelClass}>
          <span className="text-xs text-gray-300 font-mono">Attacker</span>
          <span className="text-[10px] text-gray-500 font-mono">{TOPOLOGY.attacker.ip}</span>
        </div>
      </div>

      {/* Switch / OVS */}
      <div {...nodeProps('switchNode')}>
        <div className="relative">
          <div className={`w-16 h-16 rounded-lg flex items-center justify-center border-2 bg-gray-800 ${blocked ? 'border-red-500' : 'border-blue-600'} ${dragRing('switchNode')}`}>
            <NetworkIcon size={26} className={blocked ? 'text-red-400' : 'text-blue-400'} />
          </div>
          {blocked ? (
            <div className="absolute -top-2.5 -right-2.5 w-7 h-7 rounded-full bg-red-600 border-2 border-gray-900 flex items-center justify-center pulse-ring">
              <Lock size={13} className="text-white" />
            </div>
          ) : (
            <div className="absolute -top-2.5 -right-2.5 w-6 h-6 rounded-full bg-green-600 border-2 border-gray-900 flex items-center justify-center">
              <CheckCircle2 size={12} className="text-white" />
            </div>
          )}
        </div>
        <div className={labelClass}>
          <span className="text-xs text-gray-300 font-mono text-center leading-tight">SDN_Net<br />(Open vSwitch)</span>
        </div>
      </div>

      {/* server1 */}
      <div {...nodeProps('server1')}>
        <div className={`relative rounded-lg bg-gray-800 ${dragRing('server1')}`}>
          <div className={`w-12 h-12 rounded-lg flex items-center justify-center border-2 transition-colors hover:border-green-400 ${server1Active ? 'bg-red-900/40 border-red-500' : 'bg-gray-800 border-green-700'}`}>
            <Server size={19} className={server1Active ? 'text-red-400' : 'text-green-400'} />
          </div>
          <div className="absolute -bottom-2 -right-2 w-6 h-6 rounded-full bg-gray-900 border border-gray-600 flex items-center justify-center" title="Abrir consola">
            <Terminal size={11} className="text-green-400" />
          </div>
        </div>
        <div className={labelClass}>
          <span className="text-xs text-gray-300 font-mono">server1</span>
          <span className="text-[10px] text-gray-500 font-mono">{TOPOLOGY.server1.ip}</span>
        </div>
      </div>

      {/* server2 */}
      <div {...nodeProps('server2')}>
        <div className={`relative rounded-lg bg-gray-800 ${dragRing('server2')}`}>
          <div className={`w-12 h-12 rounded-lg flex items-center justify-center border-2 transition-colors hover:border-green-400 ${server2Active ? 'bg-red-900/40 border-red-500' : 'bg-gray-800 border-green-700'}`}>
            <Server size={19} className={server2Active ? 'text-red-400' : 'text-green-400'} />
          </div>
          <div className="absolute -bottom-2 -right-2 w-6 h-6 rounded-full bg-gray-900 border border-gray-600 flex items-center justify-center" title="Abrir consola">
            <Terminal size={11} className="text-green-400" />
          </div>
        </div>
        <div className={labelClass}>
          <span className="text-xs text-gray-300 font-mono">server2</span>
          <span className="text-[10px] text-gray-500 font-mono">{TOPOLOGY.server2.ip}</span>
        </div>
      </div>

      {/* Tooltip de flujo activo: sigue el punto medio del enlace attacker ↔ switch */}
      {isActive && latestAlert && (
        <div
          className="absolute z-20 bg-gray-900/95 border border-gray-700 rounded px-2 py-1 text-[10px] font-mono text-gray-300 whitespace-nowrap shadow-lg pointer-events-none"
          style={{
            left: `${(P.attacker.x + P.switchNode.x) / 2}%`,
            top: `${(P.attacker.y + P.switchNode.y) / 2}%`,
            transform: 'translate(-50%, -150%)',
          }}
        >
          <div>Puerto: {latestAlert.victim_port}</div>
          <div>ID: {shortId(latestAlert._id)}</div>
        </div>
      )}

      {/* Estado inferior */}
      <div className="absolute bottom-1 left-1/2 -translate-x-1/2 text-[11px] font-mono text-center px-2 pointer-events-none">
        {blocked ? (
          <span className="text-green-400">Estado: Mitigación quirúrgica activa mediante reglas DROP en OVS.</span>
        ) : isActive && latestAlert ? (
          <span className="text-yellow-400">Estado: Tráfico permitido — sin regla de bloqueo activa.</span>
        ) : (
          <span className="text-gray-500">Estado: Red en reposo. Sin amenazas activas en este momento.</span>
        )}
      </div>
    </div>
  );
}

// --- Línea de tiempo de integridad de activos ---

function AssetTimeline({ alerts, limit }) {
  const items = [...alerts].slice(0, limit).reverse();

  if (items.length === 0) {
    return <div className="text-xs text-gray-500 font-mono py-6 text-center">Sin eventos registrados todavía.</div>;
  }

  return (
    <div className="flex items-start gap-0 overflow-x-auto pb-1">
      {items.map((a, i) => {
        const blocked = isBlockAction(a.action_taken);
        return (
          <div key={a._id || i} className="flex flex-col items-center min-w-[92px] relative px-1">
            {i !== 0 && <div className="absolute top-3 right-1/2 w-[92px] h-px bg-gray-700" />}
            <div className={`relative z-10 w-6 h-6 rounded-full flex items-center justify-center border-2 border-gray-900 ${blocked ? 'bg-red-600' : 'bg-yellow-500'}`}>
              {blocked ? <Lock size={11} className="text-white" /> : <CheckCircle2 size={11} className="text-gray-900" />}
            </div>
            <span className="text-[9px] text-gray-500 font-mono mt-1.5">{parseTimestamp(a.timestamp).toLocaleTimeString()}</span>
            <span className="text-[9px] text-gray-400 font-mono truncate max-w-[88px]">{a.attack_type}</span>
          </div>
        );
      })}
    </div>
  );
}

// --- Registro de un evento (reutilizado en el registro en vivo y en el buscador) ---

function EventRow({ alert, onClick }) {
  const isBlocked = isBlockAction(alert.action_taken);
  return (
    <button
      type="button"
      onClick={() => onClick(alert)}
      className={`w-full text-left border-l-2 pl-2 p-1.5 rounded bg-gray-900/40 hover:bg-gray-700/40 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 transition-colors ${isBlocked ? 'border-red-500' : 'border-yellow-500'}`}
      title="Ver detalle del ataque"
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-gray-500 text-[10px]">{formatDateTime(alert.timestamp)}</p>
        <span className="text-[9px] text-gray-600">#{shortId(alert._id)}</span>
      </div>
      <p className={`font-bold ${isBlocked ? 'text-red-400' : 'text-yellow-400'}`}>
        {alert.attack_type} (Conf: {Number(alert.confidence ?? 0).toFixed(1)}%)
      </p>
      <p className="text-gray-300 text-[11px]">Src: {alert.attacker_ip} → Dst: {alert.victim_ip}:{alert.victim_port}</p>
      <p className="text-green-400 text-[10px]">Acción: {alert.action_taken}</p>
    </button>
  );
}

// --- Detalle inline de la amenaza del panel (MongoDB + Solana, compacto) ---
// Misma información que el modal, pero viviendo dentro del panel: cuando el
// panel se estira, aquí se ve más contenido en vez de letras separadas.

function ThreatDetail({ alert, api, related }) {
  const [chain, setChain] = useState({ status: 'idle' });
  const [tries, setTries] = useState(0);
  const [showJson, setShowJson] = useState(false);
  const signature = alert.blockchain_signature;
  const chainStatus = alert.blockchain_status; // pending | confirmed | unconfirmed | error | undefined

  const load = useCallback(async () => {
    if (!signature) return;
    setChain({ status: 'loading' });
    try {
      const body = await api(`/api/blockchain/tx/${encodeURIComponent(signature)}`);
      setChain({ status: 'ok', data: body });
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setChain({ status: 'notyet', error: e.message });
        return;
      }
      setChain({ status: 'error', error: e.message || 'Error desconocido' });
    }
  }, [api, signature]);

  useEffect(() => {
    setTries(0);
    if (signature) load();
    else setChain({ status: 'idle' });
  }, [signature, load]);

  // Reintentos cortos mientras la tx se sella (máx. 3; el modal reintenta más)
  useEffect(() => {
    if (chain.status !== 'notyet' || tries >= 3) return;
    const t = setTimeout(() => {
      setTries((n) => n + 1);
      load();
    }, 2500);
    return () => clearTimeout(t);
  }, [chain.status, tries, load]);

  const tx = chain.data;

  return (
    <div className="mt-3 pt-3 border-t border-gray-700 space-y-3">
      <section>
        <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Registro en MongoDB</p>
        <div className="grid grid-cols-1 gap-1.5 bg-gray-900/50 border border-gray-700 rounded-lg p-2.5 text-xs">
          <div className="flex items-start gap-1 min-w-0">
            <span className="text-gray-500 shrink-0">ID:</span>
            <span className="font-mono text-gray-300 break-all">{alert._id}</span>
            <CopyButton text={String(alert._id)} label="Copiar ID" />
          </div>
          <div className="flex justify-between gap-2">
            <span className="text-gray-500">Fecha (local):</span>
            <span className="font-mono text-gray-300 text-right">{formatDateTime(alert.timestamp)}</span>
          </div>
          <div className="flex justify-between gap-2">
            <span className="text-gray-500">Puerto destino:</span>
            <span className="font-mono text-gray-300">{alert.victim_port}</span>
          </div>
        </div>
      </section>

      <section>
        <div className="flex items-center justify-between mb-1.5 gap-2">
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Registro en Solana</p>
          {signature && (
            <a
              href={solanaExplorerUrl(signature)}
              target="_blank"
              rel="noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="flex items-center gap-1 text-[10px] text-blue-400 hover:text-blue-300 shrink-0"
            >
              Explorer <ExternalLink size={10} />
            </a>
          )}
        </div>
        <div className="bg-gray-900/50 border border-gray-700 rounded-lg p-2.5 text-xs space-y-1.5">
          {!signature ? (
            <p className="text-gray-500 font-mono text-[11px]">
              {chainStatus === 'error'
                ? `No se pudo registrar${alert.blockchain_error ? `: ${alert.blockchain_error}` : '.'}`
                : 'Registrando en la blockchain…'}
            </p>
          ) : (
            <>
              <div className="flex items-center gap-1.5 flex-wrap">
                {chainStatus === 'confirmed' && <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border border-green-700 bg-green-900/30 text-green-400">CONFIRMADA</span>}
                {chainStatus === 'pending' && <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border border-yellow-700 bg-yellow-900/30 text-yellow-400">PENDIENTE</span>}
                {chainStatus === 'unconfirmed' && <span className="text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border border-orange-700 bg-orange-900/30 text-orange-400">SIN CONFIRMAR</span>}
                <button
                  onClick={(e) => { e.stopPropagation(); setTries(0); load(); }}
                  className="p-0.5 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-700"
                  title="Volver a consultar"
                  aria-label="Volver a consultar Solana"
                >
                  <RefreshCw size={11} className={chain.status === 'loading' ? 'animate-spin' : ''} />
                </button>
              </div>
              <div className="flex items-start gap-1 min-w-0">
                <span className="text-gray-500 shrink-0">Firma:</span>
                <span className="font-mono text-yellow-400/90 break-all">{signature}</span>
                <CopyButton text={signature} label="Copiar firma" />
              </div>
              {chain.status === 'loading' && (
                <p className="flex items-center gap-1.5 text-gray-500 font-mono text-[11px]">
                  <Loader2 size={12} className="animate-spin" /> Consultando el ledger…
                </p>
              )}
              {chain.status === 'notyet' && (
                <p className="text-gray-500 font-mono text-[11px]">
                  Sellándose en el ledger… {tries >= 3 ? '(pulsa recargar)' : `(reintento ${tries + 1}/3)`}
                </p>
              )}
              {chain.status === 'error' && (
                <p className="text-red-400 font-mono text-[11px]">No se pudo obtener: {chain.error}</p>
              )}
              {chain.status === 'ok' && tx && (
                <>
                  <div className="flex justify-between gap-2 font-mono text-[11px]">
                    <span className="text-gray-500">Slot:</span>
                    <span className="text-gray-300">{tx.slot?.toLocaleString() ?? '—'}</span>
                  </div>
                  <div className="flex justify-between gap-2 font-mono text-[11px]">
                    <span className="text-gray-500">Estado:</span>
                    <span className={tx.status === 'confirmed' ? 'text-green-400' : 'text-red-400'}>
                      {tx.status === 'confirmed' ? 'Confirmada' : 'Fallida'}
                    </span>
                  </div>
                  <div className="flex justify-between gap-2 font-mono text-[11px]">
                    <span className="text-gray-500">Comisión:</span>
                    <span className="text-gray-300 text-right">
                      {tx.fee_lamports != null ? `${tx.fee_lamports.toLocaleString()} lamports` : '—'}
                    </span>
                  </div>
                  <div className="flex justify-between gap-2 font-mono text-[11px]">
                    <span className="text-gray-500">Fecha del bloque:</span>
                    <span className="text-gray-300 text-right">
                      {tx.block_time ? new Date(tx.block_time * 1000).toLocaleString() : '—'}
                    </span>
                  </div>
                  {tx.fee_payer && (
                    <div className="flex items-start gap-1 min-w-0 font-mono text-[11px]">
                      <span className="text-gray-500 shrink-0">Pagadora:</span>
                      <span className="text-gray-300 break-all">{tx.fee_payer}</span>
                      <CopyButton text={tx.fee_payer} label="Copiar pagadora" />
                    </div>
                  )}
                  {tx.recent_blockhash && (
                    <div className="flex items-start gap-1 min-w-0 font-mono text-[11px]">
                      <span className="text-gray-500 shrink-0">Blockhash:</span>
                      <span className="text-gray-300 break-all">{tx.recent_blockhash}</span>
                      <CopyButton text={tx.recent_blockhash} label="Copiar blockhash" />
                    </div>
                  )}
                  {tx.memo && (
                    <pre className="font-mono text-[10px] text-gray-400 whitespace-pre-wrap break-all bg-gray-900 border border-gray-700 rounded p-1.5">
                      {tx.memo}
                    </pre>
                  )}
                </>
              )}
            </>
          )}
        </div>
      </section>

      {related && (
        <section>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
            Actividad de {alert.attacker_ip} ({related.count} otro{related.count === 1 ? '' : 's'})
          </p>
          {related.count === 0 ? (
            <p className="text-[11px] text-gray-500 font-mono">Único evento de este atacante en lo cargado.</p>
          ) : (
            <div className="space-y-1">
              {related.items.map((a) => (
                <div key={a._id} className="flex justify-between gap-2 font-mono text-[11px] bg-gray-900/50 border border-gray-700 rounded px-2 py-1">
                  <span className="text-gray-300 truncate">{a.attack_type} :{a.victim_port}</span>
                  <span className="text-gray-500 shrink-0">{parseTimestamp(a.timestamp).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          )}
        </section>
      )}

      <section>
        <button
          onClick={() => setShowJson((v) => !v)}
          className="flex items-center gap-1.5 text-[11px] text-gray-400 hover:text-gray-200"
          aria-expanded={showJson}
        >
          {showJson ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
          Documento JSON completo
        </button>
        {showJson && (
          <div className="relative mt-1.5">
            <div className="absolute top-1 right-1">
              <CopyButton text={JSON.stringify(alert, null, 2)} label="Copiar JSON" />
            </div>
            <pre className="font-mono text-[10px] text-gray-300 whitespace-pre-wrap break-all bg-gray-900 border border-gray-700 rounded p-2">
              {JSON.stringify(alert, null, 2)}
            </pre>
          </div>
        )}
      </section>
    </div>
  );
}

// --- Ventana de detalle de un ataque (MongoDB + Solana) ---

function AlertDetailModal({ alert, api, onClose, onDeleted, canDelete }) {
  const [chain, setChain] = useState({ status: 'idle' });
  const [showJson, setShowJson] = useState(false);
  const [autoTries, setAutoTries] = useState(0);
  const [confirmDel, setConfirmDel] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [delError, setDelError] = useState('');
  const signature = alert.blockchain_signature;
  const chainStatus = alert.blockchain_status; // pending | confirmed | unconfirmed | error | undefined
  const sev = getSeverity(alert.confidence);
  const blocked = isBlockAction(alert.action_taken);

  const loadChain = useCallback(async () => {
    if (!signature) return;
    setChain({ status: 'loading' });
    try {
      const body = await api(`/api/blockchain/tx/${encodeURIComponent(signature)}`);
      setChain({ status: 'ok', data: body });
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        // Aún no consultable en el ledger: no es un error definitivo, reintentamos
        setChain({ status: 'notyet', error: e.message });
        return;
      }
      setChain({ status: 'error', error: e.message || 'Error desconocido' });
    }
  }, [api, signature]);

  // Al abrir (o cuando llega la firma) se consulta el ledger.
  useEffect(() => {
    setAutoTries(0);
    if (signature) loadChain();
    else setChain({ status: 'idle' });
  }, [signature, loadChain]);

  // Reintento automático mientras la tx todavía no aparece en el ledger
  // (el validador local tarda un par de segundos en sellarla). Hasta 8 intentos.
  useEffect(() => {
    if (chain.status !== 'notyet' || autoTries >= 8) return;
    const t = setTimeout(() => {
      setAutoTries((n) => n + 1);
      loadChain();
    }, 2000);
    return () => clearTimeout(t);
  }, [chain.status, autoTries, loadChain]);

  const tx = chain.data;

  // Borrado de este registro en MongoDB (no vuelve a aparecer al recargar).
  // La transacción de Solana, si ya se selló, permanece en el ledger inmutable.
  const handleDelete = async () => {
    if (!confirmDel) {
      setConfirmDel(true);
      setTimeout(() => setConfirmDel(false), 5000);
      return;
    }
    setDeleting(true);
    setDelError('');
    try {
      await api(`/api/alerts/${encodeURIComponent(alert._id)}`, { method: 'DELETE' });
      onDeleted?.(alert._id);
    } catch (e) {
      setDelError(e.message || 'No se pudo borrar');
      setDeleting(false);
      setConfirmDel(false);
    }
  };

  // Mensaje del estado de la firma (mientras el backend la confirma)
  const pendingLabel = chainStatus === 'unconfirmed'
    ? 'La firma se envió pero el validador no la confirmó a tiempo. Puede que se haya perdido si el validador se reinició.'
    : chainStatus === 'error'
    ? `El backend no pudo registrar la transacción${alert.blockchain_error ? `: ${alert.blockchain_error}` : '.'}`
    : 'Registrando en la blockchain... el backend está enviando la transacción a Solana.';

  return (
    <Modal onClose={onClose} className="max-w-3xl" label="Detalle del ataque">
      <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-4 border-b border-gray-700">
        <div className="min-w-0">
          <p className="text-[11px] text-gray-500">Detalle del ataque</p>
          <h2 className={`text-lg font-bold font-mono truncate ${blocked ? 'text-red-400' : 'text-yellow-400'}`}>{alert.attack_type}</h2>
          <div className="flex flex-wrap items-center gap-2 mt-1.5">
            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${sev.border} ${sev.bg} ${sev.text}`}>{sev.label}</span>
            <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border ${blocked ? 'border-red-700 bg-red-900/30 text-red-400' : 'border-yellow-700 bg-yellow-900/30 text-yellow-400'}`}>
              {alert.action_taken}
            </span>
            <span className="text-[11px] text-gray-500 font-mono">{formatDateTime(alert.timestamp)}</span>
          </div>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-100 p-1 rounded" aria-label="Cerrar detalle">
          <X size={18} />
        </button>
      </div>

      <div className="flex items-center justify-between gap-2 px-5 py-2 bg-gray-900/40 border-b border-gray-700">
        <p className="text-[10px] text-gray-600 font-mono">
          {canDelete ? 'Borrar quita el registro de MongoDB (no reaparece).' : 'Solo el administrador puede eliminar registros.'}
        </p>
        <div className="flex items-center gap-2">
          {delError && <span className="text-[11px] text-red-400 font-mono">{delError}</span>}
          {canDelete && (
          <button
            onClick={handleDelete}
            disabled={deleting}
            className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border transition-colors disabled:opacity-40 ${confirmDel ? 'border-red-500 bg-red-600/20 text-red-300 font-bold' : 'border-gray-700 text-gray-400 hover:text-red-300 hover:border-red-600'}`}
            title="Elimina este registro de MongoDB"
          >
            <Trash2 size={13} />
            {deleting ? 'Borrando…' : confirmDel ? '¡Confirmar borrado!' : 'Eliminar registro'}
          </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
        {/* MongoDB */}
        <section>
          <h3 className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
            <Database size={14} className="text-blue-400" /> Registro en MongoDB
          </h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 bg-gray-900/50 border border-gray-700 rounded-lg p-4">
            <Field label="ID del documento" value={alert._id} copy className="sm:col-span-2" />
            <Field label="Fecha y hora (local)" value={formatDateTime(alert.timestamp)} />
            <Field label="Timestamp (UTC, almacenado)" value={alert.timestamp} />
            <Field label="Tipo de ataque" value={alert.attack_type} />
            <Field label="Confianza IA" value={`${Number(alert.confidence ?? 0).toFixed(2)}%`} valueClass="text-green-400" />
            <Field label="IP atacante" value={alert.attacker_ip} copy />
            <Field label="IP víctima" value={alert.victim_ip} copy />
            <Field label="Puerto destino" value={alert.victim_port} />
            <Field label="Severidad" value={sev.label} valueClass={sev.text} />
          </div>
        </section>

        {/* Solana */}
        <section>
          <div className="flex items-center justify-between mb-3 gap-2">
            <h3 className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
              <Server size={14} className="text-purple-400" /> Registro en Solana (blockchain)
            </h3>
            {signature && (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => { setAutoTries(0); loadChain(); }}
                  className="p-1 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-700"
                  title="Volver a consultar"
                  aria-label="Volver a consultar Solana"
                >
                  <RefreshCw size={13} className={chain.status === 'loading' ? 'animate-spin' : ''} />
                </button>
                <a
                  href={solanaExplorerUrl(signature)}
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 px-1.5 py-1 rounded hover:bg-gray-700"
                >
                  Explorer <ExternalLink size={11} />
                </a>
              </div>
            )}
          </div>

          <div className="bg-gray-900/50 border border-gray-700 rounded-lg p-4">
            {!signature ? (
              <div className={`flex items-start gap-2 text-xs font-mono ${chainStatus === 'error' || chainStatus === 'unconfirmed' ? 'text-orange-400' : 'text-gray-500'}`}>
                {chainStatus === 'error' || chainStatus === 'unconfirmed'
                  ? <ShieldAlert size={14} className="shrink-0 mt-0.5" />
                  : <Loader2 size={14} className="animate-spin text-purple-400 shrink-0 mt-0.5" />}
                <span>{pendingLabel}</span>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  {chainStatus === 'confirmed' && <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-green-700 bg-green-900/30 text-green-400">CONFIRMADA</span>}
                  {chainStatus === 'pending' && <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-yellow-700 bg-yellow-900/30 text-yellow-400">PENDIENTE DE CONFIRMAR</span>}
                  {chainStatus === 'unconfirmed' && <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded border border-orange-700 bg-orange-900/30 text-orange-400">SIN CONFIRMAR</span>}
                </div>
                <Field label="Firma de la transacción" value={signature} copy valueClass="text-yellow-400" />
                {chain.status === 'loading' && (
                  <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
                    <Loader2 size={14} className="animate-spin" /> Consultando el ledger de Solana...
                  </div>
                )}
                {chain.status === 'notyet' && (
                  <div className="flex items-center gap-2 text-xs text-gray-500 font-mono">
                    <Loader2 size={14} className="animate-spin" /> La transacción aún se está sellando en el ledger... {autoTries >= 8 ? '(pulsa recargar para reintentar)' : `(reintento ${autoTries + 1}/8)`}
                  </div>
                )}
                {chain.status === 'error' && (
                  <p className="text-xs text-red-400 font-mono">No se pudo obtener la transacción: {chain.error}</p>
                )}
                {chain.status === 'ok' && tx && (
                  <>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
                      <Field
                        label="Estado"
                        value={tx.status === 'confirmed' ? 'Confirmada' : `Fallida ${tx.error ? JSON.stringify(tx.error) : ''}`}
                        valueClass={tx.status === 'confirmed' ? 'text-green-400' : 'text-red-400'}
                      />
                      <Field label="Slot" value={tx.slot?.toLocaleString()} />
                      <Field label="Fecha del bloque" value={tx.block_time ? new Date(tx.block_time * 1000).toLocaleString() : '—'} />
                      <Field
                        label="Comisión"
                        value={tx.fee_lamports != null ? `${tx.fee_lamports.toLocaleString()} lamports (${(tx.fee_lamports / 1e9).toFixed(6)} SOL)` : '—'}
                      />
                      <Field label="Cuenta pagadora" value={tx.fee_payer} copy />
                      <Field label="Blockhash reciente" value={tx.recent_blockhash} copy />
                    </div>
                    {tx.memo && (
                      <div>
                        <p className="text-[11px] text-gray-500 mb-1">Memo registrado on-chain</p>
                        <pre className="text-[11px] font-mono text-gray-300 whitespace-pre-wrap break-all bg-gray-900 border border-gray-700 rounded p-2">
                          {tx.memo.split(' | ').join('\n')}
                        </pre>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </section>

        {/* Documento crudo */}
        <section>
          <button
            onClick={() => setShowJson((v) => !v)}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200"
            aria-expanded={showJson}
          >
            {showJson ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            Documento JSON completo
          </button>
          {showJson && (
            <div className="relative mt-2">
              <div className="absolute top-1.5 right-1.5">
                <CopyButton text={JSON.stringify(alert, null, 2)} label="Copiar JSON" />
              </div>
              <pre className="text-[11px] font-mono text-gray-300 bg-gray-900 border border-gray-700 rounded p-3 overflow-x-auto">
                {JSON.stringify(alert, null, 2)}
              </pre>
            </div>
          )}
        </section>
      </div>
    </Modal>
  );
}

// --- Confirmación de limpieza del switch (equivale a ./ips_manager.sh clean-switch) ---

function CleanSwitchModal({ api, onClose }) {
  const [phase, setPhase] = useState('confirm'); // confirm | running | done
  const [result, setResult] = useState(null);

  const run = async () => {
    setPhase('running');
    try {
      const body = await api('/api/switch/clean', { method: 'POST' });
      setResult({
        ok: body && body.status === 'ok',
        steps: Array.isArray(body && body.steps) ? body.steps : [],
        rawError: null,
      });
    } catch (e) {
      setResult({ ok: false, steps: [], rawError: e.message || 'Sin conexión con el backend' });
    }
    setPhase('done');
  };

  return (
    <Modal onClose={onClose} className="max-w-lg" label="Limpiar switch">
      <div className="flex items-start justify-between gap-4 px-5 pt-5 pb-4 border-b border-gray-700">
        <div className="min-w-0">
          <p className="text-[11px] text-gray-500">Mantenimiento de la SDN</p>
          <h2 className="text-base font-bold text-gray-100 flex items-center gap-2">
            <Eraser size={17} className="text-blue-400" /> Limpiar switch
          </h2>
          <p className="text-[11px] text-gray-500 font-mono mt-0.5">Equivale a <span className="text-gray-300">./ips_manager.sh clean-switch</span></p>
        </div>
        <button onClick={onClose} className="text-gray-400 hover:text-gray-100 p-1 rounded" aria-label="Cerrar">
          <X size={18} />
        </button>
      </div>

      <div className="px-5 py-4">
        {phase === 'confirm' && (
          <div className="space-y-3">
            <p className="text-sm text-gray-300">Esto va a:</p>
            <ol className="text-xs font-mono text-gray-400 space-y-1.5 list-decimal list-inside">
              <li>Detener el controlador Ryu</li>
              <li>Borrar todos los flujos del switch <span className="text-gray-200">SDN_Net</span> (incluidas las reglas DROP del IPS)</li>
              <li>Reiniciar Ryu en modo monitoreo</li>
              <li>Marcar el dashboard como no bloqueado</li>
            </ol>
            <p className="text-[11px] text-yellow-400/90 leading-snug">
              Tras la limpieza el tráfico del atacante vuelve a pasar: un ataque en curso puede generar una alerta nueva.
            </p>
            <div className="flex justify-end gap-2 pt-1">
              <button onClick={onClose} className="text-xs px-4 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-100">Cancelar</button>
              <button onClick={run} className="flex items-center gap-1.5 text-xs px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold">
                <Eraser size={13} /> Confirmar limpieza
              </button>
            </div>
          </div>
        )}

        {phase === 'running' && (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-gray-300 font-mono">
            <Loader2 size={18} className="animate-spin text-blue-400" /> Limpiando switch y reiniciando Ryu…
          </div>
        )}

        {phase === 'done' && result && (
          <div className="space-y-3">
            <div className={`flex items-center gap-2 text-sm font-mono font-bold px-3 py-2 rounded border ${result.ok ? 'border-green-700 bg-green-900/30 text-green-400' : 'border-orange-700 bg-orange-900/30 text-orange-400'}`}>
              {result.ok ? <Check size={15} /> : <X size={15} />}
              {result.ok ? 'Switch limpio y Ryu monitoreando de nuevo.' : 'Limpieza parcial: revisa los pasos.'}
            </div>
            {result.rawError && <p className="text-xs text-red-400 font-mono">{result.rawError}</p>}
            {result.steps.length > 0 && (
              <div className="space-y-2">
                {result.steps.map((s, i) => (
                  <div key={i} className="bg-gray-900/50 border border-gray-700 rounded-lg px-3 py-2">
                    <p className={`flex items-center gap-1.5 text-xs font-mono font-bold ${s.ok ? 'text-green-400' : 'text-red-400'}`}>
                      {s.ok ? <Check size={13} /> : <X size={13} />} {s.name}
                    </p>
                    {s.detail && <pre className="text-[11px] font-mono text-gray-400 whitespace-pre-wrap break-all mt-1">{s.detail}</pre>}
                  </div>
                ))}
              </div>
            )}
            <div className="flex justify-end gap-2 pt-1">
              {!result.ok && (
                <button onClick={() => { setResult(null); setPhase('confirm'); }} className="text-xs px-4 py-1.5 rounded border border-gray-700 text-gray-300 hover:border-gray-500">
                  Reintentar
                </button>
              )}
              <button onClick={onClose} className="text-xs px-4 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-100">Cerrar</button>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

// --- Buscador de eventos con filtros ---

const inputClass = 'w-full bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500';

function FilterField({ label, children }) {
  return (
    <label className="block min-w-0">
      <span className="block text-[11px] text-gray-500 mb-1">{label}</span>
      {children}
    </label>
  );
}

function SearchModal({ api, filters, setFilters, onClose, onSelect, fallbackAlerts }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('loading');
  const [shown, setShown] = useState(100);
  const fallbackRef = useRef(fallbackAlerts);
  fallbackRef.current = fallbackAlerts;

  const load = useCallback(async () => {
    setStatus('loading');
    try {
      const d = await api(`/api/alerts?limit=${SEARCH_FETCH_LIMIT}`);
      setData(Array.isArray(d) ? d : []);
      setStatus('ok');
    } catch {
      setData(fallbackRef.current || []);
      setStatus('error');
    }
  }, [api]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setShown(100); }, [filters]);

  const set = (key) => (e) => setFilters((f) => ({ ...f, [key]: e.target.value }));

  const types = useMemo(
    () => [...new Set((data || []).map((a) => a.attack_type).filter(Boolean))].sort(),
    [data]
  );
  const results = useMemo(() => (data || []).filter((a) => matchesFilters(a, filters)), [data, filters]);
  const activeCount = countActiveFilters(filters);

  return (
    <Modal onClose={onClose} z="z-50" className="max-w-5xl h-[85vh]" label="Buscar eventos">
      <div className="flex items-center justify-between gap-4 px-5 pt-5 pb-4 border-b border-gray-700">
        <div>
          <h2 className="text-base font-semibold text-gray-100 flex items-center gap-2">
            <Search size={17} className="text-blue-400" /> Buscar eventos
          </h2>
          <p className="text-[11px] text-gray-500 font-mono mt-0.5">
            {status === 'loading'
              ? 'Cargando histórico...'
              : `${results.length} de ${data?.length ?? 0} eventos coinciden`}
            {status === 'error' && ' (sin conexión: buscando solo en los eventos cargados en vivo)'}
          </p>
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={load}
            className="p-1.5 rounded text-gray-400 hover:text-gray-100 hover:bg-gray-700"
            title="Recargar histórico"
            aria-label="Recargar histórico"
          >
            <RefreshCw size={15} className={status === 'loading' ? 'animate-spin' : ''} />
          </button>
          <button onClick={onClose} className="p-1.5 rounded text-gray-400 hover:text-gray-100 hover:bg-gray-700" aria-label="Cerrar buscador">
            <X size={18} />
          </button>
        </div>
      </div>

      {/* Filtros */}
      <div className="px-5 py-4 border-b border-gray-700 grid grid-cols-2 md:grid-cols-4 gap-3">
        <FilterField label="ID (Mongo o firma Solana)">
          <input className={inputClass} value={filters.id} onChange={set('id')} placeholder="p. ej. a3f91c02" />
        </FilterField>
        <FilterField label="Tipo de ataque">
          <select className={inputClass} value={filters.type} onChange={set('type')}>
            <option value="">Todos</option>
            {types.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </FilterField>
        <FilterField label="Fecha desde">
          <input type="date" className={inputClass} value={filters.dateFrom} onChange={set('dateFrom')} />
        </FilterField>
        <FilterField label="Fecha hasta">
          <input type="date" className={inputClass} value={filters.dateTo} onChange={set('dateTo')} />
        </FilterField>
        <FilterField label="Hora desde">
          <input type="time" className={inputClass} value={filters.timeFrom} onChange={set('timeFrom')} />
        </FilterField>
        <FilterField label="Hora hasta">
          <input type="time" className={inputClass} value={filters.timeTo} onChange={set('timeTo')} />
        </FilterField>
        <FilterField label="IP atacante">
          <input className={inputClass} value={filters.attacker} onChange={set('attacker')} placeholder="192.168.1." />
        </FilterField>
        <FilterField label="IP víctima">
          <input className={inputClass} value={filters.victim} onChange={set('victim')} placeholder="192.168.1." />
        </FilterField>
        <FilterField label="Puerto destino">
          <input type="number" min="0" className={inputClass} value={filters.port} onChange={set('port')} placeholder="80" />
        </FilterField>
        <FilterField label="Acción">
          <select className={inputClass} value={filters.action} onChange={set('action')}>
            <option value="all">Todas</option>
            <option value="blocked">Bloqueadas (DROP)</option>
            <option value="allowed">Permitidas</option>
          </select>
        </FilterField>
        <FilterField label="Severidad">
          <select className={inputClass} value={filters.severity} onChange={set('severity')}>
            <option value="all">Todas</option>
            {SEVERITY_BUCKETS.map((b) => <option key={b.label} value={b.label}>{b.label}</option>)}
          </select>
        </FilterField>
        <FilterField label={`Confianza mínima: ${filters.minConfidence}%`}>
          <input
            type="range" min="0" max="100" step="5"
            value={filters.minConfidence}
            onChange={(e) => setFilters((f) => ({ ...f, minConfidence: Number(e.target.value) }))}
            className="w-full accent-blue-500 mt-1.5"
          />
        </FilterField>
        <div className="col-span-2 md:col-span-4 flex items-center justify-between">
          <p className="text-[10px] text-gray-600">
            Las fechas y horas se interpretan en tu zona horaria local. Una franja como 22:00 → 02:00 cruza la medianoche.
          </p>
          <button
            onClick={() => setFilters(EMPTY_FILTERS)}
            disabled={activeCount === 0}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-100 disabled:opacity-30 disabled:pointer-events-none shrink-0"
          >
            <RotateCcw size={12} /> Limpiar filtros{activeCount ? ` (${activeCount})` : ''}
          </button>
        </div>
      </div>

      {/* Resultados */}
      <div className="flex-1 overflow-y-auto px-5 py-4 text-xs font-mono">
        {status === 'loading' && !data ? (
          <div className="h-full flex items-center justify-center gap-2 text-gray-500">
            <Loader2 size={16} className="animate-spin" /> Cargando eventos...
          </div>
        ) : results.length === 0 ? (
          <div className="h-full flex items-center justify-center text-gray-500">Ningún evento coincide con los filtros.</div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
            {results.slice(0, shown).map((a, i) => (
              <EventRow key={a._id || i} alert={a} onClick={onSelect} />
            ))}
          </div>
        )}
        {results.length > shown && (
          <div className="flex justify-center mt-3">
            <button
              onClick={() => setShown((s) => s + 100)}
              className="text-xs px-3 py-1.5 rounded border border-gray-700 text-gray-300 hover:border-gray-500"
            >
              Ver más resultados ({results.length - shown} restantes)
            </button>
          </div>
        )}
      </div>
    </Modal>
  );
}

// --- Notificaciones ---

function NotificationItem({ n, now, onRead, onRemove }) {
  const sev = getSeverity(n.confidence);
  const blocked = isBlockAction(n.action_taken);
  const ts = parseTimestamp(n.timestamp).getTime();
  return (
    <div
      onClick={() => onRead(n.id)}
      className={`group px-3 py-2.5 border-b border-gray-700/60 hover:bg-gray-700/30 cursor-default ${n.read ? '' : 'bg-gray-900/50'}`}
    >
      <div className="flex items-start gap-2">
        <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${n.read ? 'bg-gray-700' : 'bg-red-500'}`} />
        <div className="flex-1 min-w-0">
          <div className="flex justify-between gap-2">
            <p className={`text-xs font-bold font-mono truncate ${blocked ? 'text-red-400' : 'text-yellow-400'}`}>{n.attack_type}</p>
            <span className="text-[10px] text-gray-500 font-mono shrink-0">
              {timeAgo(Number.isFinite(ts) ? ts : n.receivedAt, now)}
            </span>
          </div>
          <p className="text-[11px] text-gray-300 font-mono truncate">{n.attacker_ip} → {n.victim_ip}:{n.victim_port}</p>
          <p className="text-[10px] font-mono flex flex-wrap gap-x-2">
            <span className={sev.text}>{sev.label}</span>
            <span className="text-gray-500">Conf. {Number(n.confidence ?? 0).toFixed(1)}%</span>
            <span className={blocked ? 'text-red-400' : 'text-yellow-400'}>{n.action_taken}</span>
          </p>
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); onRemove(n.id); }}
          className="opacity-0 group-hover:opacity-100 focus:opacity-100 text-gray-500 hover:text-gray-200 p-0.5 rounded"
          aria-label="Eliminar notificación"
        >
          <X size={12} />
        </button>
      </div>
    </div>
  );
}

function Toast({ toast, onDismiss }) {
  useEffect(() => {
    const t = setTimeout(() => onDismiss(toast.toastId), 6000);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [toast.toastId]);

  const blocked = isBlockAction(toast.action_taken);
  return (
    <div className={`toast-in bg-gray-800 border ${blocked ? 'border-red-700' : 'border-yellow-700'} rounded-lg shadow-2xl p-3 flex items-start gap-3`}>
      <div className={`w-8 h-8 rounded-md flex items-center justify-center shrink-0 ${blocked ? 'bg-red-900/50' : 'bg-yellow-900/40'}`}>
        <ShieldAlert size={16} className={blocked ? 'text-red-400' : 'text-yellow-400'} />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-gray-400">Nuevo ataque detectado</p>
        <p className={`text-sm font-bold font-mono truncate ${blocked ? 'text-red-400' : 'text-yellow-400'}`}>{toast.attack_type}</p>
        <p className="text-[11px] text-gray-300 font-mono truncate">{toast.attacker_ip} → {toast.victim_ip}:{toast.victim_port}</p>
      </div>
      <button onClick={() => onDismiss(toast.toastId)} className="text-gray-500 hover:text-gray-200" aria-label="Cerrar aviso">
        <X size={14} />
      </button>
    </div>
  );
}

function EventLogCard(props) {
  const {
    listHeight, selectMode, setSelectMode, setSelectedIds, setConfirmSelDel,
    selectedIds, logItems, activeFilterCount, setSearchOpen, toggleSelectId,
    selectAlert, loading, alerts, totalAlerts, logLimit, settings, setLogLimit,
    canLoadMore, loadingMore, isAdmin, confirmSelDel, deleteSelected, deleting,
    confirmWipe, setConfirmWipe, deleteAllRecords,
  } = props;
  return (
    <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex flex-col min-w-0">
      <div className="flex items-center justify-between mb-2 gap-2">
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Registro de Eventos en Vivo</h2>
        <div className="flex items-center gap-1 shrink-0">
          {isAdmin && (
          <button
            onClick={() => { setSelectMode((v) => !v); setSelectedIds(new Set()); setConfirmSelDel(false); }}
            className={`text-xs px-2 py-1 rounded border transition-colors ${selectMode ? 'bg-blue-600/20 border-blue-500 text-blue-300' : 'bg-gray-900 border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-500'}`}
            title={selectMode ? 'Salir del modo selección' : 'Seleccionar registros para borrar (admin)'}
          >
            {selectMode ? 'Cancelar' : 'Seleccionar'}
          </button>
          )}
          <button
            onClick={() => setSearchOpen(true)}
            className="relative flex items-center gap-1.5 text-xs px-2 py-1 rounded bg-gray-900 border border-gray-700 text-gray-400 hover:text-gray-200 hover:border-gray-500 shrink-0"
            title="Buscar con filtros"
          >
            <Search size={13} /> Buscar
            {activeFilterCount > 0 && (
              <span className="absolute -top-1.5 -right-1.5 min-w-[16px] h-4 px-1 rounded-full bg-blue-600 text-[10px] font-bold text-white flex items-center justify-center">
                {activeFilterCount}
              </span>
            )}
          </button>
        </div>
      </div>
      {selectMode && (
        <div className="flex items-center justify-between gap-2 mb-3 px-2 py-1.5 rounded bg-gray-900/60 border border-gray-700 text-[11px] font-mono">
          <button
            onClick={() => {
              if (selectedIds.size === logItems.length && logItems.length > 0) setSelectedIds(new Set());
              else setSelectedIds(new Set(logItems.map((a) => a._id).filter(Boolean)));
            }}
            className="text-gray-400 hover:text-gray-100"
          >
            {selectedIds.size === logItems.length && logItems.length > 0 ? 'Desmarcar visibles' : `Marcar visibles (${logItems.length})`}
          </button>
          <span className="text-gray-500">{selectedIds.size} seleccionados</span>
          <button
            onClick={() => (confirmSelDel ? deleteSelected() : setConfirmSelDel(true))}
            disabled={selectedIds.size === 0 || deleting}
            className={`flex items-center gap-1 px-2 py-1 rounded border transition-colors disabled:opacity-40 ${confirmSelDel ? 'border-red-500 bg-red-600/20 text-red-300' : 'border-gray-700 text-gray-400 hover:text-red-300 hover:border-red-600'}`}
            title="Borra de MongoDB los registros seleccionados (no volverán a aparecer)"
          >
            <Trash2 size={12} />
            {deleting ? 'Borrando…' : confirmSelDel ? `¡Confirmar borrado (${selectedIds.size})!` : 'Borrar'}
          </button>
        </div>
      )}
      {/* Lista con altura fija y scroll interno; "Ver más" añade dentro del mismo scroll */}
      <div className={`${listHeight} overflow-y-auto space-y-3 pr-1 text-xs font-mono`}>
        {loading ? (
          <p className="text-gray-500">Cargando eventos...</p>
        ) : alerts.length === 0 ? (
          <p className="text-gray-500">Sin ataques detectados. Ejecuta una prueba desde el atacante.</p>
        ) : (
          logItems.map((alert, index) => (
            selectMode ? (
              <div key={alert._id || index} className="flex items-start gap-2">
                <input
                  type="checkbox"
                  checked={alert._id ? selectedIds.has(alert._id) : false}
                  onChange={() => alert._id && toggleSelectId(alert._id)}
                  className="mt-2 w-4 h-4 shrink-0 accent-blue-500 cursor-pointer"
                  aria-label={`Seleccionar evento ${shortId(alert._id)}`}
                />
                <div className="flex-1 min-w-0">
                  <EventRow alert={alert} onClick={selectAlert} />
                </div>
              </div>
            ) : (
              <EventRow key={alert._id || index} alert={alert} onClick={selectAlert} />
            )
          ))
        )}
      </div>
      {!loading && alerts.length > 0 && (
        <div className="pt-3 mt-3 border-t border-gray-700 flex items-center justify-between gap-2">
          <span className="text-[10px] text-gray-500 font-mono">
            Mostrando {logItems.length} de {totalAlerts.toLocaleString()}
          </span>
          <div className="flex items-center gap-1">
            {isAdmin && (
            <button
              onClick={() => (confirmWipe ? deleteAllRecords() : setConfirmWipe(true))}
              disabled={deleting}
              className={`text-xs px-2 py-1 rounded transition-colors disabled:opacity-40 ${confirmWipe ? 'bg-red-600/20 text-red-300 font-bold' : 'text-gray-500 hover:text-red-300'}`}
              title="Borra TODOS los registros de MongoDB (limpieza total de pruebas)"
            >
              {deleting ? 'Borrando…' : confirmWipe ? '¡Vaciar todo!' : 'Vaciar'}
            </button>
            )}
            {logLimit > settings.logSize && (
              <button
                onClick={() => setLogLimit(settings.logSize)}
                className="text-xs px-2 py-1 rounded text-gray-400 hover:text-gray-200"
              >
                Mostrar menos
              </button>
            )}
            {canLoadMore && (
              <button
                onClick={() => setLogLimit((l) => Math.min(LIVE_MAX_LIMIT, l + LOG_PAGE_SIZE))}
                disabled={loadingMore}
                className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded border border-gray-700 text-gray-300 hover:border-gray-500 disabled:opacity-60"
              >
                {loadingMore ? <Loader2 size={12} className="animate-spin" /> : <ChevronDown size={13} />}
                Ver más
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Administración de usuarios (solo admin) ---

function UsersPage({ api }) {
  const [users, setUsers] = useState(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [form, setForm] = useState({ username: '', password: '', role: 'operator' });
  const [busy, setBusy] = useState(false);
  const [editPw, setEditPw] = useState({}); // username -> draft de nueva clave

  const load = useCallback(async () => {
    try {
      setUsers(await api('/api/users'));
      setError('');
    } catch (e) {
      setError(e.message || 'No se pudo cargar');
    }
  }, [api]);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const u = await api('/api/users');
        if (alive) {
          setUsers(u);
          setError('');
        }
      } catch (e) {
        if (alive) setError(e.message || 'No se pudo cargar');
      }
    })();
    return () => { alive = false; };
  }, [api]);

  const flash = (msg) => {
    setNotice(msg);
    setTimeout(() => setNotice(''), 4000);
  };

  const create = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/api/users', { method: 'POST', body: form });
      setForm({ username: '', password: '', role: 'operator' });
      await load();
      flash(`Usuario '${form.username.trim()}' creado.`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  const patch = async (username, body, okMsg) => {
    setError('');
    try {
      await api(`/api/users/${encodeURIComponent(username)}`, { method: 'PATCH', body });
      await load();
      if (okMsg) flash(okMsg);
    } catch (err) {
      setError(err.message);
    }
  };

  const remove = async (username) => {
    if (!window.confirm(`¿Eliminar al usuario '${username}'? Perderá el acceso de inmediato.`)) return;
    setError('');
    try {
      await api(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
      await load();
      flash(`Usuario '${username}' eliminado.`);
    } catch (err) {
      setError(err.message);
    }
  };

  const inputClass = 'bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-blue-500';

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Usuarios del sistema" subtitle="roles y acceso">
        {error && <p className="text-xs text-red-400 font-mono bg-red-900/20 border border-red-800 rounded px-2.5 py-2 mb-3">{error}</p>}
        {notice && <p className="text-xs text-green-400 font-mono bg-green-900/20 border border-green-800 rounded px-2.5 py-2 mb-3">{notice}</p>}
        {users === null ? (
          <p className="text-xs text-gray-500 font-mono">Cargando usuarios…</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[10px] text-gray-500 uppercase tracking-wider border-b border-gray-700">
                  <th className="py-2 pr-2 font-semibold">Usuario</th>
                  <th className="py-2 pr-2 font-semibold">Rol</th>
                  <th className="py-2 pr-2 font-semibold">Estado</th>
                  <th className="py-2 pr-2 font-semibold">Creado por</th>
                  <th className="py-2 font-semibold text-right">Acciones</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.username} className="border-b border-gray-700/60 last:border-0">
                    <td className="py-2 pr-2 font-mono text-gray-100">{u.username}</td>
                    <td className="py-2 pr-2">
                      <select
                        value={u.role}
                        onChange={(e) => patch(u.username, { role: e.target.value }, `Rol de '${u.username}' actualizado.`)}
                        className={`${inputClass} font-mono`}
                        aria-label={`Rol de ${u.username}`}
                      >
                        <option value="operator">operator</option>
                        <option value="admin">admin</option>
                      </select>
                    </td>
                    <td className="py-2 pr-2">
                      <button
                        onClick={() => patch(u.username, { active: !u.active }, `'${u.username}' ${u.active ? 'desactivado' : 'activado'}.`)}
                        className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded-full border ${u.active ? 'border-green-700 bg-green-900/30 text-green-400' : 'border-gray-700 bg-gray-900/50 text-gray-500'}`}
                        title="Activar / desactivar acceso"
                      >
                        {u.active ? 'ACTIVO' : 'INACTIVO'}
                      </button>
                    </td>
                    <td className="py-2 pr-2 font-mono text-gray-500">{u.created_by || '—'}</td>
                    <td className="py-2">
                      <div className="flex items-center justify-end gap-1.5">
                        <input
                          type="password"
                          placeholder="Nueva clave"
                          value={editPw[u.username] || ''}
                          onChange={(e) => setEditPw((p) => ({ ...p, [u.username]: e.target.value }))}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter' && (editPw[u.username] || '').length >= 4) {
                              patch(u.username, { password: editPw[u.username] }, `Clave de '${u.username}' actualizada.`);
                              setEditPw((p) => ({ ...p, [u.username]: '' }));
                            }
                          }}
                          className={`${inputClass} font-mono w-28`}
                          title="Escribe y pulsa Enter para cambiarle la clave (mín. 4)"
                        />
                        <button
                          onClick={() => remove(u.username)}
                          className="p-1.5 rounded text-gray-500 hover:text-red-300 hover:bg-gray-700"
                          title={`Eliminar a ${u.username}`}
                          aria-label={`Eliminar a ${u.username}`}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Crear usuario" subtitle="operator u admin">
        <form onSubmit={create} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <label className="block">
            <span className="block text-[11px] text-gray-500 mb-1">Usuario</span>
            <input className={`${inputClass} w-full font-mono`} value={form.username} onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))} placeholder="nombre" autoComplete="off" />
          </label>
          <label className="block">
            <span className="block text-[11px] text-gray-500 mb-1">Contraseña (mín. 4)</span>
            <input type="password" className={`${inputClass} w-full font-mono`} value={form.password} onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))} placeholder="••••" autoComplete="new-password" />
          </label>
          <label className="block">
            <span className="block text-[11px] text-gray-500 mb-1">Rol</span>
            <select className={`${inputClass} w-full font-mono`} value={form.role} onChange={(e) => setForm((f) => ({ ...f, role: e.target.value }))}>
              <option value="operator">operator — monitorea</option>
              <option value="admin">admin — todo</option>
            </select>
          </label>
          <button
            type="submit"
            disabled={busy || form.username.trim().length < 3 || form.password.length < 4}
            className="text-xs font-semibold px-4 py-2 rounded bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white"
          >
            {busy ? 'Creando…' : 'Crear'}
          </button>
        </form>
        <p className="text-[10px] text-gray-600 mt-3 leading-snug">
          Los operadores monitorean red y ataques (incluida la consola). Solo el admin gestiona usuarios,
          parámetros globales y borrado de registros. El backend impide dejar el sistema sin administradores.
        </p>
      </Panel>
    </div>
  );
}

// --- Página de configuración: cuenta, preferencias y parámetros globales ---

function ConfigPage(props) {
  const {
    settings, setSettings, api, isAdmin, globalConfig, onSaveGlobal, globalSaved,
    user, onResetPositions, onClearNotifications, notificationCount,
    backendUrl, onApplyBackendUrl,
  } = props;
  const [urlDraft, setUrlDraft] = useState(backendUrl);
  const [urlError, setUrlError] = useState('');
  const [pw, setPw] = useState({ current: '', next: '', repeat: '' });
  const [pwMsg, setPwMsg] = useState({ ok: '', error: '' });
  const [pwBusy, setPwBusy] = useState(false);
  const [draft, setDraft] = useState(null); // borrador de parámetros globales (admin)
  const [prevGlobal, setPrevGlobal] = useState(globalConfig);
  if (globalConfig !== prevGlobal) {
    setPrevGlobal(globalConfig);
    if (globalConfig) setDraft((d) => d || { ...globalConfig });
  }

  const setWidget = (key, value) => setSettings((p) => ({ ...p, widgets: { ...p.widgets, [key]: value } }));
  const setNotif = (key, value) => setSettings((p) => ({ ...p, notifications: { ...p.notifications, [key]: value } }));
  const setTopo = (key, value) => setSettings((p) => ({ ...p, topology: { ...p.topology, [key]: value } }));

  const applyUrl = () => {
    const v = urlDraft.trim().replace(/\/+$/, '');
    if (!/^https?:\/\/.+/.test(v)) {
      setUrlError('Debe empezar por http:// o https://');
      return;
    }
    setUrlError('');
    onApplyBackendUrl(v);
  };

  const changePw = async (e) => {
    e.preventDefault();
    setPwMsg({ ok: '', error: '' });
    if (pw.next.length < 4) {
      setPwMsg({ ok: '', error: 'La nueva debe tener al menos 4 caracteres.' });
      return;
    }
    if (pw.next !== pw.repeat) {
      setPwMsg({ ok: '', error: 'La repetición no coincide.' });
      return;
    }
    setPwBusy(true);
    try {
      await api('/api/auth/change-password', {
        method: 'POST',
        body: { current_password: pw.current, new_password: pw.next },
      });
      setPw({ current: '', next: '', repeat: '' });
      setPwMsg({ ok: 'Contraseña actualizada.', error: '' });
    } catch (err) {
      setPwMsg({ ok: '', error: err.message || 'No se pudo cambiar' });
    } finally {
      setPwBusy(false);
    }
  };

  const inputClass = 'w-full bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs text-gray-200 focus:outline-none focus:border-blue-500';
  const g = draft || {};

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Mi cuenta" subtitle={user?.username}>
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <span className="w-9 h-9 rounded-full bg-blue-600/20 border border-blue-700 flex items-center justify-center text-sm font-bold text-blue-300">
            {(user?.username || '?').slice(0, 1).toUpperCase()}
          </span>
          <div>
            <p className="text-sm font-mono text-gray-100">{user?.username}</p>
            <p className="text-[10px] font-mono text-gray-500">
              rol: <span className={isAdmin ? 'text-purple-400 font-bold' : 'text-blue-300 font-bold'}>{user?.role}</span>
              {isAdmin ? ' — acceso total' : ' — monitoreo'}
            </p>
          </div>
        </div>
        <form onSubmit={changePw} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <label className="block">
            <span className="block text-[11px] text-gray-500 mb-1">Actual</span>
            <input type="password" className={`${inputClass} font-mono`} value={pw.current} onChange={(e) => setPw((p) => ({ ...p, current: e.target.value }))} autoComplete="current-password" />
          </label>
          <label className="block">
            <span className="block text-[11px] text-gray-500 mb-1">Nueva (mín. 4)</span>
            <input type="password" className={`${inputClass} font-mono`} value={pw.next} onChange={(e) => setPw((p) => ({ ...p, next: e.target.value }))} autoComplete="new-password" />
          </label>
          <label className="block">
            <span className="block text-[11px] text-gray-500 mb-1">Repetir nueva</span>
            <input type="password" className={`${inputClass} font-mono`} value={pw.repeat} onChange={(e) => setPw((p) => ({ ...p, repeat: e.target.value }))} autoComplete="new-password" />
          </label>
          <button type="submit" disabled={pwBusy} className="text-xs font-semibold px-4 py-2 rounded bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-gray-100">
            {pwBusy ? 'Guardando…' : 'Cambiar clave'}
          </button>
        </form>
        {pwMsg.error && <p className="text-[11px] text-red-400 font-mono mt-2">{pwMsg.error}</p>}
        {pwMsg.ok && <p className="text-[11px] text-green-400 font-mono mt-2">{pwMsg.ok}</p>}
      </Panel>

      <Panel
        title="Parámetros de actualización"
        subtitle={isAdmin ? 'globales: los verán todos' : 'los define el administrador'}
      >
        {!isAdmin && (
          <p className="text-[11px] text-gray-500 mb-3 leading-snug">
            Estos valores los fija el administrador para todo el equipo. Si necesitas otros, pídelos por el canal interno.
          </p>
        )}
        <div className="py-2.5">
          <span className="text-sm text-gray-200">Intervalo de actualización</span>
          <p className="text-[11px] text-gray-500 mt-0.5">Cada cuánto se consulta el backend.</p>
          <div className="flex gap-1 mt-2">
            {[1000, 2000, 5000, 10000].map((ms) => (
              <button
                key={ms}
                disabled={!isAdmin}
                onClick={() => (isAdmin ? setDraft((d) => ({ ...(d || {}), pollInterval: ms })) : undefined)}
                className={`flex-1 text-xs font-mono py-1.5 rounded border transition-colors disabled:cursor-default ${g.pollInterval === ms ? 'bg-blue-600/20 border-blue-500 text-blue-300' : 'border-gray-700 text-gray-400 hover:border-gray-500'}`}
              >
                {ms / 1000}s
              </button>
            ))}
          </div>
        </div>
        <RangeSetting
          label="Ventana de ataque activo"
          desc="Tiempo que un evento se muestra como activo en la topología."
          value={g.attackWindow ?? settings.attackWindow} min={5} max={60} step={5} unit="s"
          onChange={(v) => isAdmin && setDraft((d) => ({ ...(d || {}), attackWindow: v }))}
        />
        <RangeSetting
          label="Eventos en la línea de tiempo"
          value={g.timelineSize ?? settings.timelineSize} min={4} max={20}
          onChange={(v) => isAdmin && setDraft((d) => ({ ...(d || {}), timelineSize: v }))}
        />
        <RangeSetting
          label="Eventos iniciales en el registro en vivo"
          desc="Con “Ver más” se cargan de 20 en 20."
          value={g.logSize ?? settings.logSize} min={5} max={50} step={5}
          onChange={(v) => isAdmin && setDraft((d) => ({ ...(d || {}), logSize: v }))}
        />
        {isAdmin && (
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-gray-700">
            <span className="text-[11px] text-gray-500">
              Al guardar, todos los usuarios verán estos valores al entrar.
              {globalSaved && <span className="text-green-400 font-mono"> ✓ guardado</span>}
            </span>
            <button
              onClick={() => draft && onSaveGlobal(draft)}
              className="text-xs font-semibold px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white"
            >
              Guardar globales
            </button>
          </div>
        )}
      </Panel>

      <Panel title="Paneles y gráficos" subtitle="visibilidad personal">
        <SectionTitle>Paneles</SectionTitle>
        {BASE_WIDGETS.map((wd) => (
          <Toggle key={wd.key} label={wd.label} desc={wd.desc} checked={settings.widgets[wd.key]} onChange={(v) => setWidget(wd.key, v)} />
        ))}
        <SectionTitle>Gráficos de análisis</SectionTitle>
        <p className="text-xs text-gray-500 mb-1">Se muestran en Eventos y análisis.</p>
        {EXTRA_WIDGETS.map((wd) => (
          <Toggle key={wd.key} label={wd.label} desc={wd.desc} checked={settings.widgets[wd.key]} onChange={(v) => setWidget(wd.key, v)} />
        ))}
        <div className="mt-2">
          <button
            onClick={() => setSettings((p) => ({
              ...p,
              widgets: { ...p.widgets, ...Object.fromEntries(BASE_WIDGETS.map((wd) => [wd.key, true])) },
            }))}
            className="text-xs text-blue-400 hover:text-blue-300"
          >
            Mostrar todos los paneles
          </button>
        </div>
      </Panel>

      <Panel title="Preferencias personales" subtitle="solo este navegador">
        <SectionTitle>Notificaciones</SectionTitle>
        <Toggle
          label="Registrar notificaciones"
          desc="Añade a la campana cada nuevo ataque detectado."
          checked={settings.notifications.enabled}
          onChange={(v) => setNotif('enabled', v)}
        />
        <Toggle
          label="Avisos emergentes"
          desc="Muestra un aviso en la esquina inferior derecha al detectar un ataque."
          checked={settings.notifications.toasts}
          onChange={(v) => setNotif('toasts', v)}
        />
        <Toggle
          label="Sonido de alerta"
          desc="Emite un pitido corto con cada nuevo ataque."
          checked={settings.notifications.sound}
          onChange={(v) => { setNotif('sound', v); if (v) playAlertSound(); }}
        />
        <button
          onClick={onClearNotifications}
          disabled={notificationCount === 0}
          className="mt-1 w-full flex items-center justify-center gap-2 text-xs py-2 rounded border border-gray-700 text-gray-300 hover:border-red-600 hover:text-red-300 disabled:opacity-40 disabled:pointer-events-none"
        >
          <Trash2 size={13} /> Limpiar notificaciones ({notificationCount})
        </button>

        <SectionTitle>Topología</SectionTitle>
        <Toggle
          label="Bloquear posición de los nodos"
          desc="Impide arrastrar los nodos por accidente durante una demostración."
          checked={settings.topology.lockNodes}
          onChange={(v) => setTopo('lockNodes', v)}
        />
        <button
          onClick={onResetPositions}
          className="mt-1 w-full flex items-center justify-center gap-2 text-xs py-2 rounded border border-gray-700 text-gray-300 hover:border-gray-500"
        >
          <RotateCcw size={13} /> Restablecer posiciones de los nodos
        </button>

        <SectionTitle>Conexión</SectionTitle>
        <div className="py-2.5">
          <label htmlFor="backend-url" className="text-sm text-gray-200">URL del backend</label>
          <div className="flex gap-2 mt-2">
            <input
              id="backend-url"
              type="text"
              value={urlDraft}
              onChange={(e) => setUrlDraft(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && applyUrl()}
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-2 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-blue-500"
            />
            <button onClick={applyUrl} className="text-xs px-3 rounded bg-blue-600 hover:bg-blue-500 text-white">Aplicar</button>
          </div>
          {urlError && <p className="text-[11px] text-red-400 mt-1">{urlError}</p>}
          <p className="text-[10px] text-gray-600 mt-1">Al aplicar se recarga la aplicación.</p>
        </div>

        <div className="mt-2 pt-3 border-t border-gray-700">
          <button
            onClick={() => { setSettings(DEFAULT_SETTINGS); setUrlDraft(DEFAULT_SETTINGS.backendUrl); setUrlError(''); }}
            className="text-xs text-gray-400 hover:text-gray-200 flex items-center gap-1.5"
          >
            <RotateCcw size={12} /> Restablecer configuración local
          </button>
        </div>
      </Panel>
    </div>
  );
}

// --- App ---


export function MainApp() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [now, setNow] = useState(Date.now());
  const [switchStatus, setSwitchStatus] = useState(null); // { blocked, updated_at, reason } | null = endpoint aún no disponible
  const [totals, setTotals] = useState(null);             // { total, blocked } | null = endpoint aún no disponible
  const [health, setHealth] = useState(null);             // { mongodb, solana } | null = endpoint aún no disponible

  const [settings, setSettings] = useState(loadSettings);
  const [nodePositions, setNodePositions] = useState(loadPositions);
  const [theme, setTheme] = useState(loadTheme);
  const isLight = theme === 'light';

  const [logLimit, setLogLimit] = useState(settings.logSize);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [filters, setFilters] = useState(EMPTY_FILTERS);

  // Panel "Contexto de Amenaza Crítica": por defecto muestra el último registro,
  // pero al hacer clic en un evento se fija a ese (sigue fijo al cerrar el detalle).
  const [pinnedId, setPinnedId] = useState(null);
  const selectAlert = useCallback((alert) => {
    setSelectedAlert(alert);
    if (alert && alert._id) setPinnedId(alert._id);
  }, []);

  // Miniconsola SDN: qué host está abierto (attacker | server1 | server2) o null = cerrada
  const [terminalHost, setTerminalHost] = useState(null);
  const terminalOpen = terminalHost !== null;
  const openTerminal = useCallback((host) => setTerminalHost(host), []);
  const closeTerminal = useCallback(() => setTerminalHost(null), []);
  // Modal de limpieza del switch (clean-switch)
  const [cleanOpen, setCleanOpen] = useState(false);
  // Navegación estilo Issabel (sin router: estado de vista)
  const [view, setView] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [userMenuOpen, setUserMenu] = useState(false);
  // Parámetros globales del admin (los ven todos; se fusionan al entrar)
  const [globalConfig, setGlobalConfig] = useState(null);
  const userMenuRef = useRef(null);

  const [notifications, setNotifications] = useState(() => {
    const stored = loadJSON(STORAGE_KEYS.notifications, []);
    return Array.isArray(stored) ? stored : [];
  });
  const [notifOpen, setNotifOpen] = useState(false);
  const [toasts, setToasts] = useState([]);
  const notifRef = useRef(null);

  // Registro de alertas ya vistas, para notificar solo las NUEVAS.
  // Si no hay registro previo, la primera carga se toma como línea base
  // (no inunda con el historial). Se guarda también el timestamp más reciente
  // procesado (newestTs): así ampliar con "Ver más" —que trae alertas viejas—
  // nunca genera notificaciones; solo lo estrictamente más nuevo notifica.
  const [seenStore] = useState(() => {
    const stored = loadJSON(STORAGE_KEYS.seen, null);
    if (stored && Array.isArray(stored.ids)) {
      return { set: new Set(stored.ids), baseline: false, newestTs: Number(stored.newestTs) || 0 };
    }
    if (Array.isArray(stored)) {
      // Formato anterior (solo IDs): se migra sin notificar lo viejo.
      return { set: new Set(stored), baseline: false, newestTs: Date.now() };
    }
    return { set: new Set(), baseline: true, newestTs: 0 };
  });

  const settingsRef = useRef(settings);
  useEffect(() => {
    settingsRef.current = settings;
    saveJSON(STORAGE_KEYS.settings, settings);
  }, [settings]);

  useEffect(() => { setLogLimit(settings.logSize); }, [settings.logSize]);

  useEffect(() => {
    saveJSON(STORAGE_KEYS.notifications, notifications);
  }, [notifications]);

  useEffect(() => {
    const t = setTimeout(() => saveJSON(STORAGE_KEYS.positions, nodePositions), 250);
    return () => clearTimeout(t);
  }, [nodePositions]);

  // Tema claro/oscuro: se aplica como clase en <html> (ver index.css)
  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('light', isLight);
    root.style.colorScheme = isLight ? 'light' : 'dark';
    saveJSON(STORAGE_KEYS.theme, theme);
  }, [theme, isLight]);

  // Borrado de registros: selección múltiple en el registro en vivo.
  // (Aquí porque usa setters declarados más arriba.)
  const [selectMode, setSelectMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState(() => new Set());
  const [confirmSelDel, setConfirmSelDel] = useState(false);
  const [confirmWipe, setConfirmWipe] = useState(false);
  const [deleting, setDeleting] = useState(false);

  // Quita registros de la vista al instante (el backend ya los borró de Mongo)
  const removeAlertsLocal = useCallback((ids) => {
    const s = new Set(ids);
    if (s.size === 0) return;
    setAlerts((prev) => prev.filter((a) => !s.has(a._id)));
    setNotifications((prev) => prev.filter((n) => !s.has(n.id)));
    setToasts((prev) => prev.filter((t) => !s.has(t.id)));
    setSelectedIds((prev) => {
      if ([...prev].every((id) => !s.has(id))) return prev;
      const next = new Set(prev);
      ids.forEach((id) => next.delete(id));
      return next;
    });
    setSelectedAlert((prev) => (prev && s.has(prev._id) ? null : prev));
  }, []);

  const toggleSelectId = useCallback((id) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleIncomingAlerts = useCallback((data) => {
    if (!Array.isArray(data) || data.length === 0) return;
    const persistSeen = () => saveJSON(
      STORAGE_KEYS.seen,
      { ids: Array.from(seenStore.set).slice(-500), newestTs: seenStore.newestTs },
    );
    const tsOf = (a) => {
      const t = parseTimestamp(a.timestamp).getTime();
      return Number.isFinite(t) ? t : 0;
    };
    const batchMax = data.reduce((m, a) => Math.max(m, tsOf(a)), 0);

    if (seenStore.baseline) {
      data.forEach((a) => a._id && seenStore.set.add(a._id));
      seenStore.newestTs = Math.max(seenStore.newestTs, batchMax);
      seenStore.baseline = false;
      persistSeen();
      return;
    }

    const unseen = data.filter((a) => a._id && !seenStore.set.has(a._id));
    // Se marca TODO lo cargado como visto (incluido lo viejo que trae "Ver más")
    // pero solo notifica lo estrictamente más nuevo que lo ya procesado.
    data.forEach((a) => a._id && seenStore.set.add(a._id));
    const fresh = unseen.filter((a) => tsOf(a) > seenStore.newestTs);
    seenStore.newestTs = Math.max(seenStore.newestTs, batchMax);
    persistSeen();
    if (fresh.length === 0) return;

    const cfg = settingsRef.current.notifications;
    if (!cfg.enabled) return;

    const newNotifs = fresh.map(alertToNotification); // el backend las devuelve de más nueva a más antigua
    setNotifications((prev) => [...newNotifs, ...prev.filter((p) => !newNotifs.some((n) => n.id === p.id))].slice(0, MAX_NOTIFICATIONS));

    if (cfg.toasts) {
      const stamp = Date.now();
      setToasts((prev) => [
        ...newNotifs.slice(0, 3).map((n, i) => ({ ...n, toastId: `${n.id}-${stamp}-${i}` })),
        ...prev,
      ].slice(0, 4));
    }
    if (cfg.sound) playAlertSound();
  }, [seenStore]);

  // Cuántos eventos se piden en cada consulta: lo que el usuario haya desplegado
  // con "Ver más" en el registro (mínimo 20 para que los gráficos tengan datos).
  const liveLimit = Math.min(LIVE_MAX_LIMIT, Math.max(20, logLimit));
  const backendBase = settings.backendUrl.replace(/\/+$/, '');

  // Sesión y rol (candidates: operator | admin)
  const { user: sessionUser, logout, isAdmin } = useAuth();

  // Llamadas autenticadas: el 401 cierra la sesión y vuelve al login.
  const api = useCallback(async (path, opts) => {
    try {
      return await apiFetch(backendBase, path, opts);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) logout();
      throw e;
    }
  }, [backendBase, logout]);

  // Parámetros globales del admin: mandan sobre los locales en esas claves.
  // (Solo tiempos y tamaños; la visibilidad de paneles sigue siendo personal.)
  const MANAGED_KEYS = useMemo(
    () => ['pollInterval', 'attackWindow', 'timelineSize', 'logSize'],
    []
  );

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const g = await apiFetch(backendBase, '/api/config');
        if (!alive || !g || typeof g !== 'object') return;
        setGlobalConfig(g);
        setSettings((prev) => {
          const next = { ...prev };
          for (const k of MANAGED_KEYS) {
            if (g[k] !== undefined) next[k] = g[k];
          }
          return next;
        });
      } catch {
        // sin globales (backend viejo o sin red): se usan los locales
      }
    })();
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [backendBase]);

  // Borrado múltiple / total (usan backendBase; se definen aquí porque lo necesitan)
  // Las confirmaciones de borrado se desarman solas a los 5s
  useEffect(() => {
    if (!confirmSelDel) return;
    const t = setTimeout(() => setConfirmSelDel(false), 5000);
    return () => clearTimeout(t);
  }, [confirmSelDel]);
  useEffect(() => {
    if (!confirmWipe) return;
    const t = setTimeout(() => setConfirmWipe(false), 5000);
    return () => clearTimeout(t);
  }, [confirmWipe]);
  const deleteSelected = useCallback(async () => {
    const ids = [...selectedIds];
    if (ids.length === 0) return;
    setDeleting(true);
    try {
      await api('/api/alerts/delete-many', { method: 'POST', body: { ids } });
      removeAlertsLocal(ids);
      setSelectMode(false);
      setSelectedIds(new Set());
    } catch (e) {
      alert(`No se pudieron borrar los registros: ${e.message}`);
    } finally {
      setDeleting(false);
      setConfirmSelDel(false);
    }
  }, [api, selectedIds, removeAlertsLocal]);

  const deleteAllRecords = useCallback(async () => {
    setDeleting(true);
    try {
      await api('/api/alerts', { method: 'DELETE' });
      setAlerts([]);
      setNotifications([]);
      setToasts([]);
      setSelectedIds(new Set());
      setSelectMode(false);
      setLogLimit(settingsRef.current.logSize);
    } catch (e) {
      alert(`No se pudo vaciar el registro: ${e.message}`);
    } finally {
      setDeleting(false);
      setConfirmWipe(false);
    }
  }, [api]);

  useEffect(() => {
    let cancelled = false;

    const fetchAlerts = async () => {
      try {
        const data = await api(`/api/alerts?limit=${liveLimit}`);
        if (cancelled || !Array.isArray(data)) return;
        setAlerts(data);
        setConnected(true);
        setLoading(false);
        handleIncomingAlerts(data);
      } catch (error) {
        if (cancelled) return;
        if (error instanceof ApiError && error.status === 401) return; // logout ya hecho
        console.error('Error conectando con el Backend:', error);
        setConnected(false);
      }
    };

    const fetchSwitchStatus = async () => {
      try {
        const data = await api('/api/switch-status');
        if (!cancelled) setSwitchStatus(data);
      } catch (error) {
        // silencioso: si falla, el fallback por tiempo sigue funcionando
      }
    };

    const fetchTotals = async () => {
      try {
        const data = await api('/api/alerts/count');
        if (!cancelled && typeof data.total === 'number') setTotals(data);
      } catch (error) {
        // silencioso
      }
    };

    const fetchHealth = async () => {
      try {
        const data = await api('/api/health');
        if (!cancelled) setHealth(data);
      } catch (error) {
        // silencioso
      }
    };

    const tick = () => {
      fetchAlerts();
      fetchSwitchStatus();
      fetchTotals();
      fetchHealth();
    };

    tick();
    const interval = setInterval(tick, settings.pollInterval);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [api, backendBase, settings.pollInterval, liveLimit, handleIncomingAlerts]);

  useEffect(() => {
    const clock = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(clock);
  }, []);

  // --- Notificaciones: acciones ---

  const unreadCount = notifications.filter((n) => !n.read).length;

  const markAllRead = useCallback(() => {
    setNotifications((prev) => (prev.some((n) => !n.read) ? prev.map((n) => ({ ...n, read: true })) : prev));
  }, []);

  const closeNotifications = useCallback(() => {
    setNotifOpen(false);
    markAllRead();
  }, [markAllRead]);

  const clearNotifications = useCallback(() => {
    setNotifications([]);
    setToasts([]);
  }, []);

  const markRead = useCallback((id) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  }, []);

  const removeNotification = useCallback((id) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id));
  }, []);

  const dismissToast = useCallback((toastId) => {
    setToasts((prev) => prev.filter((t) => t.toastId !== toastId));
  }, []);

  useEffect(() => {
    if (!notifOpen) return;
    const onDown = (e) => {
      if (notifRef.current && !notifRef.current.contains(e.target)) closeNotifications();
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [notifOpen, closeNotifications]);

  // Esc cierra primero la ventana que esté encima
  useEffect(() => {
    const onKey = (e) => {
      if (e.key !== 'Escape') return;
      if (cleanOpen) setCleanOpen(false);
      else if (selectedAlert) setSelectedAlert(null);
      else if (searchOpen) setSearchOpen(false);
      else if (notifOpen) closeNotifications();
      else if (terminalHost) setTerminalHost(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [cleanOpen, selectedAlert, searchOpen, notifOpen, closeNotifications, terminalHost]);

  // --- Topología ---

  const moveNode = useCallback((id, pos) => {
    setNodePositions((prev) => ({ ...prev, [id]: pos }));
  }, []);

  const resetPositions = useCallback(() => setNodePositions({ ...DEFAULT_NODE_POSITIONS }), []);

  // --- Datos derivados ---

  const latest = alerts[0];
  const elapsedSinceLatest = latest ? now - parseTimestamp(latest.timestamp).getTime() : Infinity;
  const isActive = latest ? elapsedSinceLatest >= 0 && elapsedSinceLatest < settings.attackWindow * 1000 : false;

  // Amenaza mostrada en el panel: el último evento clicado (fijado) si aún existe,
  // si no el último registro. La topología y el estado del switch siguen en vivo.
  const pinnedCurrent = pinnedId ? alerts.find((a) => a._id === pinnedId) || null : null;
  const threat = pinnedCurrent || latest;
  const threatSeverity = getSeverity(threat?.confidence);
  const isPinned = !!pinnedCurrent;

  // Otros eventos recientes del mismo atacante (relleno informativo del panel)
  const threatRelated = useMemo(() => {
    if (!threat?.attacker_ip) return { count: 0, items: [] };
    const same = alerts.filter((a) => a.attacker_ip === threat.attacker_ip && a._id !== threat._id);
    return { count: same.length, items: same.slice(0, 4) };
  }, [alerts, threat]);

  // Fuente de verdad: el estado real que reporta el backend (persistente, no caduca solo).
  // Si el endpoint todavía no existe en el backend desplegado, cae de vuelta a la
  // heurística por tiempo para no romper el dashboard mientras actualizas main.py.
  const blocked = switchStatus
    ? switchStatus.blocked
    : isActive && latest && isBlockAction(latest.action_taken);

  // Qué servidor está bajo ataque se decide por la IP real de la víctima frente
  // a las IPs fijas de la topología (VNX). Si la víctima no coincide con ninguna
  // (p. ej. un IP_Spoofing con victim_ip "N/A"), se marca server1 por defecto.
  const targetLabel = useMemo(() => {
    if (!latest) return null;
    if (latest.victim_ip === TOPOLOGY.server2.ip) return 'server2';
    if (latest.victim_ip === TOPOLOGY.server1.ip) return 'server1';
    return 'server1';
  }, [latest]);

  // Mezcla viva por tipo de ataque (todos los tipos, sin recorte a 6):
  // cuando aparece un tipo nuevo, nace su barra y los % se reequilibran solos.
  const attackMix = useMemo(
    () => countBy(alerts, (a) => a.attack_type || 'Desconocido', 50),
    [alerts],
  );

  const stats = useMemo(() => {
    const total = alerts.length;
    const blockedCount = alerts.filter((a) => isBlockAction(a.action_taken)).length;
    const avgConfidence = total ? alerts.reduce((s, a) => s + (Number(a.confidence) || 0), 0) / total : 0;
    const uniqueAttackers = new Set(alerts.map((a) => a.attacker_ip).filter(Boolean)).size;
    const byType = countBy(alerts, (a) => a.attack_type || 'Desconocido');
    const byAttacker = countBy(alerts, (a) => a.attacker_ip);
    const byPort = countBy(alerts, (a) => (a.victim_port ? a.victim_port : null));
    return {
      total,
      blocked: blockedCount,
      avgConfidence,
      uniqueAttackers,
      topType: byType[0]?.label,
      byType,
      byAttacker,
      byPort,
    };
  }, [alerts]);

  // Total real desde MongoDB (endpoint /api/alerts/count); si no existe, lo cargado
  const totalAlerts = Math.max(totals?.total ?? 0, alerts.length);
  const totalBlocked = totals ? Math.max(totals.blocked ?? 0, 0) : stats.blocked;

  const logItems = alerts.slice(0, logLimit);
  const canLoadMore = logItems.length < totalAlerts;
  const loadingMore = logLimit > alerts.length && alerts.length < totalAlerts;
  const activeFilterCount = countActiveFilters(filters);

  // Props compartidas de la tarjeta de registro (se usa en Panel principal y en Eventos)
  const logCardProps = {
    selectMode, setSelectMode, setSelectedIds, setConfirmSelDel, selectedIds,
    logItems, activeFilterCount, setSearchOpen, toggleSelectId, selectAlert,
    loading, alerts, totalAlerts, logLimit, settings, setLogLimit,
    canLoadMore, loadingMore, isAdmin, confirmSelDel, deleteSelected, deleting,
    confirmWipe, setConfirmWipe, deleteAllRecords,
  };

  // La ventana de detalle muestra siempre la versión más reciente del documento
  // (p. ej. cuando llega la firma de Solana mientras está abierta).
  const selectedCurrent = selectedAlert
    ? alerts.find((a) => a._id === selectedAlert._id) || selectedAlert
    : null;

  const lastBlockchainAlert = alerts.find((a) => a.blockchain_signature);

  // --- Visibilidad por página ---

  const w = settings.widgets;
  const extraCharts = ['attackTypes', 'severity', 'topAttackers', 'ports'].filter((k) => w[k]);

  const headerIconBtn = 'p-1.5 rounded transition-colors text-gray-400 hover:text-gray-100 hover:bg-gray-800';

  // Navegación Issabel: vista efectiva (usuarios es solo-admin) y etiquetas.
  const safeView = view === 'usuarios' && !isAdmin ? 'dashboard' : view;
  const VIEW_LABELS = {
    dashboard: 'Panel principal',
    eventos: 'Eventos y análisis',
    sistema: 'Servicios y blockchain',
    usuarios: 'Usuarios',
    config: 'Configuración',
  };

  // Guardar parámetros globales (admin): backend + estado local.
  const [globalSaved, setGlobalSaved] = useState(false);
  const saveGlobal = useCallback(async (draft) => {
    const body = {};
    for (const k of MANAGED_KEYS) {
      if (draft && draft[k] !== undefined) body[k] = draft[k];
    }
    const saved = await api('/api/config', { method: 'PUT', body });
    const values = (saved && saved.values) || {};
    setGlobalConfig(values);
    setSettings((prev) => ({ ...prev, ...values }));
    setGlobalSaved(true);
    setTimeout(() => setGlobalSaved(false), 3000);
  }, [api, MANAGED_KEYS]);

  // Cambiar de backend implica recargar para revalidar la sesión.
  const applyBackendUrl = useCallback((v) => {
    const s = loadSettings();
    s.backendUrl = v;
    saveJSON(STORAGE_KEYS.settings, s);
    window.location.reload();
  }, []);

  // Cerrar el menú de usuario al hacer clic fuera.
  useEffect(() => {
    if (!userMenuOpen) return;
    const onDown = (e) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) setUserMenu(false);
    };
    document.addEventListener('mousedown', onDown);
    return () => document.removeEventListener('mousedown', onDown);
  }, [userMenuOpen]);

  return (
    <div className="min-h-screen bg-gray-900 text-gray-200 font-sans flex">
      <Sidebar
        view={safeView}
        setView={setView}
        collapsed={sidebarCollapsed}
        setCollapsed={setSidebarCollapsed}
        isAdmin={isAdmin}
      />
      <div className="flex-1 min-w-0 flex flex-col min-h-screen">

      {/* Barra superior */}
      <header className="px-4 h-14 border-b border-gray-800 flex justify-between items-center gap-3 shrink-0 sticky top-0 z-40 bg-gray-900">
        <nav className="flex items-center gap-2 min-w-0" aria-label="Ubicación actual">
          <ShieldAlert size={16} className="text-red-500 shrink-0" />
          <span className="text-xs text-gray-500 font-mono hidden sm:inline">SOC</span>
          <span className="text-gray-700 hidden sm:inline">/</span>
          <span className="text-sm text-gray-100 font-semibold truncate">{VIEW_LABELS[safeView]}</span>
        </nav>
        <div className="flex items-center gap-3">
          <div className={`text-sm flex items-center gap-2 font-mono ${connected ? 'text-green-400' : 'text-red-400'}`}>
            <span className={`w-2.5 h-2.5 rounded-full animate-pulse ${connected ? 'bg-green-500' : 'bg-red-500'}`}></span>
            {connected ? 'Conectado al Backend & Orquestador' : 'Backend no disponible'}
          </div>

          {/* Modo claro / oscuro: el icono indica el modo al que se cambiará */}
          <button
            onClick={() => setTheme(isLight ? 'dark' : 'light')}
            className={headerIconBtn}
            aria-label={isLight ? 'Cambiar a modo oscuro' : 'Cambiar a modo claro'}
            title={isLight ? 'Cambiar a modo oscuro' : 'Cambiar a modo claro'}
          >
            {isLight ? <Moon size={18} /> : <Sun size={18} />}
          </button>

          {/* Campana de notificaciones */}
          <div ref={notifRef} className="relative">
            <button
              onClick={() => (notifOpen ? closeNotifications() : setNotifOpen(true))}
              className={`relative p-1.5 rounded transition-colors ${notifOpen ? 'bg-gray-800 text-gray-100' : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'}`}
              aria-label={`Notificaciones${unreadCount ? ` (${unreadCount} sin leer)` : ''}`}
              aria-expanded={notifOpen}
            >
              <Bell size={18} />
              {unreadCount > 0 && (
                <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-1 rounded-full bg-red-600 text-[10px] font-bold text-white flex items-center justify-center">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            {notifOpen && (
              <div className="pop-in absolute right-0 mt-2 w-[360px] max-w-[calc(100vw-2rem)] bg-gray-800 border border-gray-700 rounded-lg shadow-2xl z-50 overflow-hidden">
                <div className="flex items-center justify-between px-3 py-2.5 border-b border-gray-700">
                  <div>
                    <p className="text-sm font-semibold text-gray-100">Notificaciones</p>
                    <p className="text-[10px] text-gray-500 font-mono">
                      {notifications.length} en total, {unreadCount} sin leer
                    </p>
                  </div>
                  <div className="flex items-center gap-1">
                    <button
                      onClick={markAllRead}
                      disabled={unreadCount === 0}
                      className="p-1.5 rounded text-gray-400 hover:text-gray-100 hover:bg-gray-700 disabled:opacity-30 disabled:pointer-events-none"
                      title="Marcar todas como leídas"
                      aria-label="Marcar todas como leídas"
                    >
                      <CheckCheck size={15} />
                    </button>
                    <button
                      onClick={clearNotifications}
                      disabled={notifications.length === 0}
                      className="flex items-center gap-1 text-xs px-2 py-1 rounded text-gray-400 hover:text-red-300 hover:bg-gray-700 disabled:opacity-30 disabled:pointer-events-none"
                      title="Limpiar notificaciones"
                    >
                      <Trash2 size={13} /> Limpiar
                    </button>
                  </div>
                </div>
                <div className="max-h-[420px] overflow-y-auto">
                  {notifications.length === 0 ? (
                    <div className="py-10 flex flex-col items-center gap-2 text-gray-500">
                      <BellOff size={22} />
                      <p className="text-xs font-mono">Sin notificaciones.</p>
                      {!settings.notifications.enabled && (
                        <p className="text-[10px] text-gray-600">Las notificaciones están desactivadas en Configuración.</p>
                      )}
                    </div>
                  ) : (
                    notifications.map((n) => (
                      <NotificationItem key={n.id} n={n} now={now} onRead={markRead} onRemove={removeNotification} />
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Usuario y sesión */}
          <div ref={userMenuRef} className="relative">
            <button
              onClick={() => setUserMenu((v) => !v)}
              className="flex items-center gap-2 p-1 pr-1.5 rounded hover:bg-gray-800"
              aria-label="Menú de usuario"
              aria-expanded={userMenuOpen}
            >
              <span className="w-7 h-7 rounded-full bg-blue-600/20 border border-blue-700 flex items-center justify-center text-xs font-bold text-blue-300 shrink-0">
                {(sessionUser?.username || '?').slice(0, 1).toUpperCase()}
              </span>
              <span className="hidden md:block text-left">
                <span className="block text-xs text-gray-100 font-mono leading-tight">{sessionUser?.username}</span>
                <span className={`block text-[9px] font-mono leading-tight ${isAdmin ? 'text-purple-400' : 'text-blue-300'}`}>
                  {isAdmin ? 'admin' : 'operator'}
                </span>
              </span>
              <ChevronDown size={13} className="text-gray-500 shrink-0" />
            </button>
            {userMenuOpen && (
              <div className="pop-in absolute right-0 mt-2 w-48 bg-gray-800 border border-gray-700 rounded-lg shadow-2xl z-50 overflow-hidden">
                <button
                  onClick={() => { setUserMenu(false); setView('config'); }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-gray-300 hover:bg-gray-700"
                >
                  <KeyRound size={13} /> Mi cuenta
                </button>
                <button
                  onClick={() => { setUserMenu(false); logout(); }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-300 hover:bg-gray-700 border-t border-gray-700"
                >
                  <LogOut size={13} /> Cerrar sesión
                </button>
              </div>
            )}
          </div>
        </div>
      </header>

      <main className="flex-1 p-4 min-w-0">

      {safeView === 'dashboard' && (
        <>
          {w.kpis && <KpiStrip stats={stats} totalAlerts={totalAlerts} totalBlocked={totalBlocked} />}
          <div className="grid grid-cols-12 gap-4 items-stretch">
            <div className="col-span-12 xl:col-span-8 flex flex-col gap-4 min-h-0">
              {w.topology && (
                <div className="bg-gray-800 rounded-lg border border-gray-700 relative overflow-hidden shadow-lg p-4 flex-1 min-h-[440px] flex flex-col">
                  <div className="flex items-center justify-between mb-2 relative z-10 gap-2">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Topología</h2>
                    <div className="flex items-center gap-1">
                      <span className="hidden xl:inline text-[10px] text-gray-600 font-mono mr-2">
                        {settings.topology.lockNodes ? 'Nodos bloqueados · click abre consola' : 'Click en un host abre su consola · Arrastra para mover'}
                      </span>
                      <button
                        onClick={() => openTerminal('attacker')}
                        className={`w-7 h-7 rounded bg-gray-900 border flex items-center justify-center hover:text-gray-200 hover:border-gray-500 ${terminalOpen ? 'border-green-600 text-green-400' : 'border-gray-700 text-gray-400'}`}
                        aria-label="Abrir consola SDN"
                        title="Abrir consola SDN (attacker / server1 / server2)"
                      >
                        <Terminal size={13} />
                      </button>
                      <button
                        onClick={() => setCleanOpen(true)}
                        className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center text-gray-400 hover:text-gray-200 hover:border-gray-500"
                        aria-label="Limpiar switch (clean-switch)"
                        title="Limpiar switch: borra bloqueos y reinicia Ryu (equivale a ./ips_manager.sh clean-switch)"
                      >
                        <Eraser size={13} />
                      </button>
                      <button
                        onClick={() => setSettings((p) => ({ ...p, topology: { ...p.topology, lockNodes: !p.topology.lockNodes } }))}
                        className={`w-7 h-7 rounded bg-gray-900 border flex items-center justify-center hover:text-gray-200 hover:border-gray-500 ${settings.topology.lockNodes ? 'border-blue-600 text-blue-400' : 'border-gray-700 text-gray-400'}`}
                        aria-label={settings.topology.lockNodes ? 'Desbloquear nodos' : 'Bloquear nodos'}
                        title={settings.topology.lockNodes ? 'Desbloquear nodos' : 'Bloquear nodos'}
                      >
                        {settings.topology.lockNodes ? <Lock size={13} /> : <Unlock size={13} />}
                      </button>
                      <button
                        onClick={resetPositions}
                        className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center text-gray-400 hover:text-gray-200 hover:border-gray-500"
                        aria-label="Restablecer posiciones"
                        title="Restablecer posiciones"
                      >
                        <RotateCcw size={13} />
                      </button>
                      <button
                        onClick={() => setZoom((z) => Math.max(0.7, +(z - 0.1).toFixed(2)))}
                        className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center text-gray-400 hover:text-gray-200 hover:border-gray-500"
                        aria-label="Alejar"
                      >
                        <ZoomOut size={14} />
                      </button>
                      <button
                        onClick={() => setZoom((z) => Math.min(1.6, +(z + 0.1).toFixed(2)))}
                        className="w-7 h-7 rounded bg-gray-900 border border-gray-700 flex items-center justify-center text-gray-400 hover:text-gray-200 hover:border-gray-500"
                        aria-label="Acercar"
                      >
                        <ZoomIn size={14} />
                      </button>
                    </div>
                  </div>
                  <div className="relative w-full flex-1 min-h-0">
                    <div className={connected ? '' : 'blur-sm opacity-40 pointer-events-none transition-all'} style={{ width: '100%', height: '100%' }}>
                      <NetworkMap
                        latestAlert={latest}
                        isActive={isActive}
                        blocked={blocked}
                        targetLabel={targetLabel}
                        zoom={zoom}
                        positions={nodePositions}
                        onMoveNode={moveNode}
                        locked={settings.topology.lockNodes}
                        isLight={isLight}
                        onHostClick={openTerminal}
                        onSwitchClick={() => setCleanOpen(true)}
                      />
                    </div>
                    {!connected && (
                      <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 z-20">
                        <Loader2 size={28} className="text-blue-400 animate-spin" />
                        <p className="text-sm font-mono text-gray-200">Esperando conexión con el backend...</p>
                        <p className="text-xs font-mono text-gray-500">{settings.backendUrl}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
            <div className="col-span-12 xl:col-span-4 flex flex-col gap-4 min-h-0">
              {w.eventLog && <EventLogCard listHeight="h-[380px]" {...logCardProps} />}
            </div>
          </div>
          {!w.topology && !w.eventLog && !w.kpis && (
            <div className="py-24 flex flex-col items-center gap-3 text-gray-500">
              <LayoutGrid size={28} />
              <p className="text-sm font-mono">Panel principal vacío: activa paneles en Configuración.</p>
              <button onClick={() => setView('config')} className="text-xs text-blue-400 hover:text-blue-300">Abrir configuración</button>
            </div>
          )}
        </>
      )}

      {safeView === 'eventos' && (
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-12 gap-4 items-stretch">
            <div className="col-span-12 xl:col-span-5 flex flex-col gap-4 min-h-0">
              {w.threat && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex-1 flex flex-col min-h-0">
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Contexto de Amenaza Crítica</h2>
                    <div className="flex items-center gap-1 shrink-0">
                      {threat && (
                        <button
                          onClick={() => selectAlert(threat)}
                          className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border border-gray-700 text-gray-400 hover:text-gray-100 hover:border-gray-500"
                          title="Abrir detalle completo"
                        >
                          <Maximize2 size={10} />
                        </button>
                      )}
                      {isPinned && (
                        <button
                          onClick={() => setPinnedId(null)}
                          className="flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded border border-blue-700 text-blue-300 hover:border-blue-500"
                          title="Volver a mostrar el último registro"
                        >
                          <RotateCcw size={10} /> Último
                        </button>
                      )}
                    </div>
                  </div>
                  <p className="text-[10px] text-gray-600 mb-3 min-h-[12px]">
                    {isPinned
                      ? `Fijado al evento #${shortId(threat._id)} — clic en otro registro para cambiarlo.`
                      : (threat && !blocked ? 'Última alerta registrada — la infraestructura ya no está bloqueando este flujo.' : '')}
                  </p>
                  {threat ? (
                    <>
                      <div className="space-y-2.5 text-sm shrink-0">
                        <div>
                          <p className="text-xs text-gray-500">ID de Amenaza:</p>
                          <p className="font-mono text-gray-200">{shortId(threat._id)}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500">Tipo de Ataque:</p>
                          <p className="font-mono text-gray-200">{threat.attack_type}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500">Severidad:</p>
                          <p className={`font-mono font-bold ${threatSeverity.text}`}>{threatSeverity.label}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500">Confianza IA:</p>
                          <p className="font-mono font-bold text-green-400">{Number(threat.confidence ?? 0).toFixed(1)}%</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500">Origen → Destino:</p>
                          <p className="font-mono text-gray-200 text-xs">{threat.attacker_ip} → {threat.victim_ip}:{threat.victim_port}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-500">Acción Tomada:</p>
                          <p className={`font-mono font-bold ${isBlockAction(threat.action_taken) ? 'text-red-400' : 'text-yellow-400'}`}>{threat.action_taken}</p>
                        </div>
                      </div>
                      <div className="overflow-y-auto overflow-x-hidden pr-1 terminal-scroll min-h-0 max-h-[550px]">
                        <ThreatDetail key={threat._id} alert={threat} api={api} related={threatRelated} />
                      </div>
                    </>
                  ) : (
                    <p className="text-xs text-gray-500 font-mono">Sin amenazas activas.</p>
                  )}
                </div>
              )}
            </div>
            <div className="col-span-12 xl:col-span-7 flex flex-col gap-4 min-h-0">
              {w.aiPanel && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex flex-col">
                  <div className="flex items-center justify-between mb-1">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Panel de IA</h2>
                    <span className="text-[10px] text-gray-600 font-mono">
                      {attackMix.length === 0 ? 'sin datos' : `${attackMix.length} tipo${attackMix.length === 1 ? '' : 's'} · en vivo`}
                    </span>
                  </div>
                  <p className="text-xs text-gray-500 mb-2">Distribución por tipo de ataque (% del total cargado)</p>
                  <div className="flex-1 flex flex-col justify-center min-h-0">
                    <AttackMixBars data={attackMix} />
                  </div>
                  <div className="mt-3 pt-3 border-t border-gray-700 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-xs text-gray-400"><Activity size={14} className="text-green-400" /> Eventos totales registrados</span>
                      <span key={totalAlerts} className="count-bump text-lg font-bold text-green-400 font-mono">{totalAlerts.toLocaleString()}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2 text-xs text-gray-400"><Lock size={14} className="text-red-400" /> Bloqueados (DROP)</span>
                      <span className="text-sm font-bold text-red-400 font-mono">{totalBlocked.toLocaleString()}</span>
                    </div>
                    {!totals && connected && (
                      <p className="text-[10px] text-gray-600">Total parcial: actualiza main.py para obtener el recuento real de MongoDB.</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
          {w.timeline && (
            <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex flex-col">
              <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Línea de Tiempo de Integridad de Activos</h2>
              <div className="flex-1 flex flex-col justify-center min-h-0">
                <AssetTimeline alerts={alerts} limit={settings.timelineSize} />
              </div>
            </div>
          )}
          {extraCharts.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
              {w.attackTypes && (
                <Panel title="Tipos de ataque" subtitle={`últimos ${stats.total}`}>
                  <HBarChart data={stats.byType} color="#f87171" emptyText="Sin ataques registrados." />
                </Panel>
              )}
              {w.severity && (
                <Panel title="Severidad" subtitle="según confianza IA">
                  <SeverityDonut alerts={alerts} isLight={isLight} />
                </Panel>
              )}
              {w.topAttackers && (
                <Panel title="Top IPs atacantes" subtitle={`${stats.uniqueAttackers} únicas`}>
                  <HBarChart data={stats.byAttacker} color="#fb923c" emptyText="Sin IPs de origen registradas." />
                </Panel>
              )}
              {w.ports && (
                <Panel title="Puertos más atacados">
                  <HBarChart data={stats.byPort} color="#60a5fa" emptyText="Sin puertos registrados." />
                </Panel>
              )}
            </div>
          )}
          {w.eventLog && <EventLogCard listHeight="h-[520px]" {...logCardProps} />}
          {!w.threat && !w.aiPanel && !w.timeline && extraCharts.length === 0 && !w.eventLog && (
            <div className="py-24 flex flex-col items-center gap-3 text-gray-500">
              <LayoutGrid size={28} />
              <p className="text-sm font-mono">Sin paneles en esta vista: actívalos en Configuración.</p>
              <button onClick={() => setView('config')} className="text-xs text-blue-400 hover:text-blue-300">Abrir configuración</button>
            </div>
          )}
        </div>
      )}

      {safeView === 'sistema' && (
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4 items-start">
            {w.services && (
              <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex-1 flex flex-col">
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Estado de Servicios</h2>
                <div className="flex-1 flex flex-col items-center justify-center gap-4 py-3 min-h-0">
                  <HealthRing
                    states={[serviceState(health?.mongodb, connected), serviceState(health?.solana, connected)]}
                    isLight={isLight}
                  />
                  <div className="w-full space-y-3">
                    {[
                      { label: 'MongoDB', sub: 'Alertas y estado', Icon: Database, tile: 'bg-blue-900/30 border-blue-700 text-blue-400', ok: health?.mongodb },
                      { label: 'Solana', sub: 'Auditoría blockchain', Icon: Server, tile: 'bg-purple-900/30 border-purple-700 text-purple-400', ok: health?.solana },
                    ].map(({ label, sub, Icon, tile, ok }) => (
                      <div key={label} className="flex items-center gap-3">
                        <span className={`w-11 h-11 rounded-lg border flex items-center justify-center shrink-0 ${tile}`}>
                          <Icon size={20} />
                        </span>
                        <span className="flex-1 min-w-0">
                          <span className="block text-sm font-semibold text-gray-200">{label}</span>
                          <span className="block text-[10px] text-gray-500">{sub}</span>
                        </span>
                        <ServicePill state={serviceState(ok, connected)} />
                      </div>
                    ))}
                  </div>
                </div>
                {health && !health.solana && (
                  <p className="text-[10px] text-orange-400 mt-3 leading-snug">
                    Solana no responde en localhost:8899. Los ataques no se registrarán en la blockchain hasta que el validador esté activo.
                  </p>
                )}
              </div>
            )}
            <div className="flex flex-col gap-4 min-h-0">
              {w.blockchain && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex flex-col">
                  <h2 className="text-sm font-semibold text-gray-400 mb-2 uppercase tracking-wider">Último Hash Blockchain (Solana)</h2>
                  <div className="flex-1 flex flex-col justify-center min-h-0">
                  {lastBlockchainAlert ? (
                    <p className="text-xs text-yellow-400 font-mono break-all bg-gray-900 p-2 rounded border border-gray-700">
                      {lastBlockchainAlert.blockchain_signature}
                    </p>
                  ) : (
                    <p className="text-xs text-gray-500 font-mono">Esperando confirmación de transacción inmutable en bloque...</p>
                  )}
                  </div>
                </div>
              )}
              <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-2">Mantenimiento del switch</h2>
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="flex items-center gap-2 text-xs font-mono">
                    {switchStatus && switchStatus.blocked ? (
                      <span className="flex items-center gap-1.5 px-2 py-1 rounded border border-red-700 bg-red-900/30 text-red-400 font-bold">
                        <Lock size={12} /> BLOQUEANDO{switchStatus.reason ? ` · ${switchStatus.reason}` : ''}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 px-2 py-1 rounded border border-green-700 bg-green-900/30 text-green-400 font-bold">
                        <CheckCircle2 size={12} /> SIN BLOQUEOS
                      </span>
                    )}
                  </div>
                  <button
                    onClick={() => setCleanOpen(true)}
                    className="flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white"
                    title="Borra bloqueos y reinicia Ryu (equivale a ./ips_manager.sh clean-switch)"
                  >
                    <Eraser size={13} /> Limpiar switch
                  </button>
                </div>
                <p className="text-[10px] text-gray-600 mt-2 leading-snug">
                  Detiene Ryu, borra los flujos de SDN_Net (incluidas las reglas DROP) y lo reinicia en monitoreo. También desde el nodo OVS de la topología.
                </p>
              </div>
            </div>
          </div>
          {!w.services && !w.blockchain && (
            <div className="py-24 flex flex-col items-center gap-3 text-gray-500">
              <LayoutGrid size={28} />
              <p className="text-sm font-mono">Sin paneles en esta vista: actívalos en Configuración.</p>
              <button onClick={() => setView('config')} className="text-xs text-blue-400 hover:text-blue-300">Abrir configuración</button>
            </div>
          )}
        </div>
      )}

      {safeView === 'usuarios' && isAdmin && <UsersPage api={api} />}

      {safeView === 'config' && (
        <ConfigPage
          settings={settings}
          setSettings={setSettings}
          api={api}
          isAdmin={isAdmin}
          globalConfig={globalConfig}
          onSaveGlobal={saveGlobal}
          globalSaved={globalSaved}
          user={sessionUser}
          onResetPositions={resetPositions}
          onClearNotifications={clearNotifications}
          notificationCount={notifications.length}
          backendUrl={backendBase}
          onApplyBackendUrl={applyBackendUrl}
        />
      )}

      {/* Avisos emergentes */}
      {toasts.length > 0 && (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)]">
          {toasts.map((t) => (
            <Toast key={t.toastId} toast={t} onDismiss={dismissToast} />
          ))}
        </div>
      )}

      {searchOpen && (
        <SearchModal
          api={api}
          filters={filters}
          setFilters={setFilters}
          onClose={() => setSearchOpen(false)}
          onSelect={selectAlert}
          fallbackAlerts={alerts}
        />
      )}

      {selectedCurrent && (
        <AlertDetailModal
          key={selectedCurrent._id}
          alert={selectedCurrent}
          api={api}
          onClose={() => setSelectedAlert(null)}
          onDeleted={(id) => removeAlertsLocal([id])}
          canDelete={isAdmin}
        />
      )}

      {/* Miniconsola SDN: click en attacker / server1 / server2 de la topología */}
      {terminalOpen && (
        <HostTerminal
          initialHost={terminalHost}
          backendUrl={backendBase}
          onClose={closeTerminal}
        />
      )}

      {/* Limpieza del switch: click en el OVS o botón Eraser de la topología */}
      {cleanOpen && (
        <CleanSwitchModal
          api={api}
          onClose={() => setCleanOpen(false)}
        />
      )}
      </main>
    </div>
    </div>
  );
}

// --- Puerta de acceso: login o aplicación según la sesión ---

function Gate({ backendUrl, onBackendUrl }) {
  const { user, checking } = useAuth();
  if (checking) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <Loader2 size={26} className="text-blue-400 animate-spin" />
      </div>
    );
  }
  if (!user) return <Login backendUrl={backendUrl} onBackendUrl={onBackendUrl} />;
  return <MainApp />;
}

export default function App() {
  const [backendUrl, setBackendUrl] = useState(() => {
    try {
      return loadSettings().backendUrl;
    } catch {
      return 'http://localhost:8001';
    }
  });

  // Cambiar de backend implica recargar para revalidar la sesión allí.
  const applyBackendUrl = useCallback((v) => {
    try {
      const s = loadSettings();
      s.backendUrl = v;
      saveJSON(STORAGE_KEYS.settings, s);
    } catch {
      // seguimos con la recarga aunque no se pueda persistir
    }
    setBackendUrl(v);
    window.location.reload();
  }, []);

  return (
    <AuthProvider backendUrl={backendUrl}>
      <Gate backendUrl={backendUrl} onBackendUrl={applyBackendUrl} />
    </AuthProvider>
  );
}
