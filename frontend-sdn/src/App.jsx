import React, { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import {
  ShieldAlert, Server, Database, Activity, Lock, Unlock, CheckCircle2,
  Bell, BellOff, Settings, ZoomIn, ZoomOut, Network as NetworkIcon, Loader2,
  Trash2, CheckCheck, X, RotateCcw, LayoutGrid, SlidersHorizontal,
  Sun, Moon, Search, ExternalLink, Copy, Check, RefreshCw, ChevronDown, ChevronUp,
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
  trendSize: 20,           // eventos en el gráfico del Panel de IA
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
  { key: 'aiPanel', label: 'Panel de IA', desc: 'Tendencia de confianza y total de eventos.' },
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

// Estado real de un servicio (MongoDB / Solana) según /api/health.
// Si el backend no está conectado o el endpoint no existe todavía, muestra un
// estado neutro en vez de un ONLINE falso.
function ServiceStatus({ ok, connected }) {
  if (!connected) return <span className="text-gray-500 text-xs font-bold">● —</span>;
  if (ok === undefined || ok === null) return <span className="text-green-500 text-xs font-bold">● ONLINE</span>;
  return ok
    ? <span className="text-green-500 text-xs font-bold">● ONLINE</span>
    : <span className="text-red-500 text-xs font-bold">● OFFLINE</span>;
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

// --- Gráfico: tasa de detección de anomalías (construido a mano, sin dependencias nuevas) ---

function AnomalySparkline({ values }) {
  const width = 280;
  const height = 84;

  if (!values || values.length < 2) {
    return (
      <div className="h-[84px] flex items-center justify-center text-gray-600 text-xs font-mono">
        Esperando suficientes eventos...
      </div>
    );
  }

  const max = Math.max(...values, 100);
  const stepX = width / (values.length - 1);
  const points = values.map((v, i) => {
    const x = i * stepX;
    const y = height - (v / max) * (height - 8) - 4;
    return [x, y];
  });
  const linePath = 'M' + points.map(([x, y]) => `${x},${y}`).join(' L');
  const areaPath = `${linePath} L${width},${height} L0,${height} Z`;
  const last = points[points.length - 1];

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[84px]" preserveAspectRatio="none">
      <defs>
        <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill="url(#sparkFill)" stroke="none" />
      <path d={linePath} fill="none" stroke="#60a5fa" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last[0]} cy={last[1]} r="3" fill="#93c5fd" />
    </svg>
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

function NetworkMap({ latestAlert, isActive, blocked, targetLabel, zoom, positions, onMoveNode, locked, isLight }) {
  const containerRef = useRef(null);
  const dragRef = useRef(null); // { id, dx, dy }
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
    if (locked || e.button !== 0) return;
    e.preventDefault();
    const p = toPercent(e);
    // Guardamos el desfase para que el nodo no "salte" al centro del cursor
    dragRef.current = { id, dx: p.x - P[id].x, dy: p.y - P[id].y };
    e.currentTarget.setPointerCapture(e.pointerId);
    setDraggingId(id);
  };

  const handlePointerMove = (e) => {
    const d = dragRef.current;
    if (!d) return;
    const p = toPercent(e);
    onMoveNode(d.id, { x: clamp(p.x - d.dx, 4, 96), y: clamp(p.y - d.dy, 7, 84) });
  };

  const handlePointerUp = (e) => {
    if (!dragRef.current) return;
    dragRef.current = null;
    setDraggingId(null);
    if (e.currentTarget.hasPointerCapture?.(e.pointerId)) {
      e.currentTarget.releasePointerCapture(e.pointerId);
    }
  };

  const nodeProps = (id) => ({
    className: `absolute select-none ${locked ? '' : draggingId === id ? 'cursor-grabbing z-30' : 'cursor-grab z-10 hover:z-20'}`,
    style: {
      left: `${P[id].x}%`,
      top: `${P[id].y}%`,
      transform: 'translate(-50%, -50%)',
      touchAction: locked ? 'auto' : 'none',
    },
    onPointerDown: handlePointerDown(id),
    onPointerMove: handlePointerMove,
    onPointerUp: handlePointerUp,
    onPointerCancel: handlePointerUp,
    title: locked ? undefined : 'Arrastra para mover',
  });

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
        <div className={`rounded-lg bg-gray-800 ${dragRing('attacker')}`}>
          <div className={`w-14 h-14 rounded-lg flex items-center justify-center border-2 ${blocked ? 'bg-red-900/60 border-red-500' : 'bg-green-900/30 border-green-700'}`}>
            <ShieldAlert size={24} className={blocked ? 'text-red-400' : 'text-green-400'} />
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
        <div className={`rounded-lg bg-gray-800 ${dragRing('server1')}`}>
          <div className={`w-12 h-12 rounded-lg flex items-center justify-center border-2 ${server1Active ? 'bg-red-900/40 border-red-500' : 'bg-gray-800 border-green-700'}`}>
            <Server size={19} className={server1Active ? 'text-red-400' : 'text-green-400'} />
          </div>
        </div>
        <div className={labelClass}>
          <span className="text-xs text-gray-300 font-mono">server1</span>
          <span className="text-[10px] text-gray-500 font-mono">{TOPOLOGY.server1.ip}</span>
        </div>
      </div>

      {/* server2 */}
      <div {...nodeProps('server2')}>
        <div className={`rounded-lg bg-gray-800 ${dragRing('server2')}`}>
          <div className={`w-12 h-12 rounded-lg flex items-center justify-center border-2 ${server2Active ? 'bg-red-900/40 border-red-500' : 'bg-gray-800 border-green-700'}`}>
            <Server size={19} className={server2Active ? 'text-red-400' : 'text-green-400'} />
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

// --- Ventana de detalle de un ataque (MongoDB + Solana) ---

function AlertDetailModal({ alert, backendUrl, onClose }) {
  const [chain, setChain] = useState({ status: 'idle' });
  const [showJson, setShowJson] = useState(false);
  const [autoTries, setAutoTries] = useState(0);
  const signature = alert.blockchain_signature;
  const chainStatus = alert.blockchain_status; // pending | confirmed | unconfirmed | error | undefined
  const sev = getSeverity(alert.confidence);
  const blocked = isBlockAction(alert.action_taken);

  const loadChain = useCallback(async () => {
    if (!signature) return;
    setChain({ status: 'loading' });
    try {
      const r = await fetch(`${backendUrl}/api/blockchain/tx/${encodeURIComponent(signature)}`);
      const body = await r.json().catch(() => ({}));
      if (!r.ok) {
        if (r.status === 404) {
          // Aún no consultable en el ledger: no es un error definitivo, reintentamos
          setChain({ status: 'notyet', error: body.detail || 'Aún no disponible en el ledger.' });
          return;
        }
        const msg = typeof body.detail === 'string' ? body.detail : `HTTP ${r.status}`;
        throw new Error(msg);
      }
      setChain({ status: 'ok', data: body });
    } catch (e) {
      setChain({ status: 'error', error: e.message || 'Error desconocido' });
    }
  }, [backendUrl, signature]);

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

function SearchModal({ backendUrl, filters, setFilters, onClose, onSelect, fallbackAlerts }) {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('loading');
  const [shown, setShown] = useState(100);
  const fallbackRef = useRef(fallbackAlerts);
  fallbackRef.current = fallbackAlerts;

  const load = useCallback(async () => {
    setStatus('loading');
    try {
      const r = await fetch(`${backendUrl}/api/alerts?limit=${SEARCH_FETCH_LIMIT}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = await r.json();
      setData(Array.isArray(d) ? d : []);
      setStatus('ok');
    } catch {
      setData(fallbackRef.current || []);
      setStatus('error');
    }
  }, [backendUrl]);

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

// --- Panel de configuración ---

const SETTINGS_TABS = [
  { key: 'panels', label: 'Paneles' },
  { key: 'charts', label: 'Gráficos' },
  { key: 'params', label: 'Parámetros' },
  { key: 'alerts', label: 'Notificaciones' },
];

function SettingsDrawer({ settings, setSettings, onClose, onResetPositions, onClearNotifications, notificationCount }) {
  const [tab, setTab] = useState('panels');
  const [urlDraft, setUrlDraft] = useState(settings.backendUrl);
  const [urlError, setUrlError] = useState('');

  const setWidget = (key, value) => setSettings((p) => ({ ...p, widgets: { ...p.widgets, [key]: value } }));
  const setNotif = (key, value) => setSettings((p) => ({ ...p, notifications: { ...p.notifications, [key]: value } }));
  const setTopo = (key, value) => setSettings((p) => ({ ...p, topology: { ...p.topology, [key]: value } }));
  const setField = (key, value) => setSettings((p) => ({ ...p, [key]: value }));

  const applyUrl = () => {
    const v = urlDraft.trim().replace(/\/+$/, '');
    if (!/^https?:\/\/.+/.test(v)) {
      setUrlError('Debe empezar por http:// o https://');
      return;
    }
    setUrlError('');
    setField('backendUrl', v);
  };

  const visibleBase = BASE_WIDGETS.filter((w) => settings.widgets[w.key]).length;

  return (
    <div className="fixed inset-0 z-50" role="dialog" aria-modal="true" aria-label="Configuración del dashboard">
      <div className="absolute inset-0 bg-black/50 backdrop-in" onClick={onClose} />
      <aside className="drawer-in absolute right-0 top-0 h-full w-full max-w-md bg-gray-800 border-l border-gray-700 shadow-2xl flex flex-col">
        <div className="px-5 pt-5 pb-3 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-gray-100 flex items-center gap-2">
              <SlidersHorizontal size={18} className="text-blue-400" />
              Configuración
            </h2>
            <button onClick={onClose} className="text-gray-400 hover:text-gray-100 p-1 rounded" aria-label="Cerrar configuración">
              <X size={18} />
            </button>
          </div>
          <div className="flex gap-1 mt-4 bg-gray-900 p-1 rounded-md">
            {SETTINGS_TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`flex-1 text-xs py-1.5 rounded transition-colors ${tab === t.key ? 'bg-gray-700 text-gray-100' : 'text-gray-400 hover:text-gray-200'}`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-4">
          {tab === 'panels' && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs text-gray-500">{visibleBase} de {BASE_WIDGETS.length} paneles visibles</p>
                <button
                  onClick={() => setSettings((p) => ({
                    ...p,
                    widgets: { ...p.widgets, ...Object.fromEntries(BASE_WIDGETS.map((w) => [w.key, true])) },
                  }))}
                  className="text-xs text-blue-400 hover:text-blue-300"
                >
                  Mostrar todos
                </button>
              </div>
              {BASE_WIDGETS.map((w) => (
                <Toggle key={w.key} label={w.label} desc={w.desc} checked={settings.widgets[w.key]} onChange={(v) => setWidget(w.key, v)} />
              ))}
              <p className="text-[11px] text-gray-500 mt-3 leading-snug">
                Si ocultas todos los paneles de una columna, las demás se ensanchan automáticamente para aprovechar el espacio.
              </p>
            </div>
          )}

          {tab === 'charts' && (
            <div>
              <p className="text-xs text-gray-500 mb-1">
                Gráficos calculados sobre los eventos cargados en vivo en el dashboard. Los totales de los KPIs usan el recuento real de MongoDB.
              </p>
              {EXTRA_WIDGETS.map((w) => (
                <Toggle key={w.key} label={w.label} desc={w.desc} checked={settings.widgets[w.key]} onChange={(v) => setWidget(w.key, v)} />
              ))}
            </div>
          )}

          {tab === 'params' && (
            <div>
              <SectionTitle>Datos en tiempo real</SectionTitle>
              <div className="py-2.5">
                <span className="text-sm text-gray-200">Intervalo de actualización</span>
                <p className="text-[11px] text-gray-500 mt-0.5">Cada cuánto se consulta el backend.</p>
                <div className="flex gap-1 mt-2">
                  {[1000, 2000, 5000, 10000].map((ms) => (
                    <button
                      key={ms}
                      onClick={() => setField('pollInterval', ms)}
                      className={`flex-1 text-xs font-mono py-1.5 rounded border transition-colors ${settings.pollInterval === ms ? 'bg-blue-600/20 border-blue-500 text-blue-300' : 'border-gray-700 text-gray-400 hover:border-gray-500'}`}
                    >
                      {ms / 1000}s
                    </button>
                  ))}
                </div>
              </div>
              <RangeSetting
                label="Ventana de ataque activo"
                desc="Tiempo que un evento se muestra como activo en la topología."
                value={settings.attackWindow} min={5} max={60} step={5} unit="s"
                onChange={(v) => setField('attackWindow', v)}
              />
              <RangeSetting
                label="Eventos en el gráfico del Panel de IA"
                value={settings.trendSize} min={5} max={100} step={5}
                onChange={(v) => setField('trendSize', v)}
              />
              <RangeSetting
                label="Eventos en la línea de tiempo"
                value={settings.timelineSize} min={4} max={20}
                onChange={(v) => setField('timelineSize', v)}
              />
              <RangeSetting
                label="Eventos iniciales en el registro en vivo"
                desc="Con “Ver más” se cargan de 20 en 20."
                value={settings.logSize} min={5} max={50} step={5}
                onChange={(v) => setField('logSize', v)}
              />

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
              </div>
            </div>
          )}

          {tab === 'alerts' && (
            <div>
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
                className="mt-3 w-full flex items-center justify-center gap-2 text-xs py-2 rounded border border-gray-700 text-gray-300 hover:border-red-600 hover:text-red-300 disabled:opacity-40 disabled:pointer-events-none"
              >
                <Trash2 size={13} /> Limpiar notificaciones ({notificationCount})
              </button>
            </div>
          )}
        </div>

        <div className="px-5 py-3 border-t border-gray-700 flex items-center justify-between">
          <button
            onClick={() => { setSettings(DEFAULT_SETTINGS); setUrlDraft(DEFAULT_SETTINGS.backendUrl); setUrlError(''); }}
            className="text-xs text-gray-400 hover:text-gray-200 flex items-center gap-1.5"
          >
            <RotateCcw size={12} /> Restablecer configuración
          </button>
          <button onClick={onClose} className="text-xs px-4 py-1.5 rounded bg-gray-700 hover:bg-gray-600 text-gray-100">Listo</button>
        </div>
      </aside>
    </div>
  );
}

// Mapa explícito de spans (Tailwind no compila clases construidas dinámicamente)
const COL_SPAN = {
  0: 'hidden', 3: 'lg:col-span-3', 4: 'lg:col-span-4', 6: 'lg:col-span-6',
  8: 'lg:col-span-8', 9: 'lg:col-span-9', 12: 'lg:col-span-12',
};

// --- App ---


export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [now, setNow] = useState(Date.now());
  const [switchStatus, setSwitchStatus] = useState(null); // { blocked, updated_at, reason } | null = endpoint aún no disponible
  const [totals, setTotals] = useState(null);             // { total, blocked } | null = endpoint aún no disponible
  const [health, setHealth] = useState(null);             // { mongodb, solana } | null = endpoint aún no disponible

  const [settings, setSettings] = useState(loadSettings);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [nodePositions, setNodePositions] = useState(loadPositions);
  const [theme, setTheme] = useState(loadTheme);
  const isLight = theme === 'light';

  const [logLimit, setLogLimit] = useState(settings.logSize);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [filters, setFilters] = useState(EMPTY_FILTERS);

  const [notifications, setNotifications] = useState(() => {
    const stored = loadJSON(STORAGE_KEYS.notifications, []);
    return Array.isArray(stored) ? stored : [];
  });
  const [notifOpen, setNotifOpen] = useState(false);
  const [toasts, setToasts] = useState([]);
  const notifRef = useRef(null);

  // Registro de alertas ya vistas, para notificar solo las nuevas. Si no hay registro
  // previo, la primera carga se toma como línea base (no inunda con el historial).
  const [seenStore] = useState(() => {
    const stored = loadJSON(STORAGE_KEYS.seen, null);
    return { set: new Set(Array.isArray(stored) ? stored : []), baseline: !Array.isArray(stored) };
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

  const handleIncomingAlerts = useCallback((data) => {
    if (!Array.isArray(data)) return;
    const persistSeen = () => saveJSON(STORAGE_KEYS.seen, Array.from(seenStore.set).slice(-500));

    if (seenStore.baseline) {
      data.forEach((a) => a._id && seenStore.set.add(a._id));
      seenStore.baseline = false;
      persistSeen();
      return;
    }

    const fresh = data.filter((a) => a._id && !seenStore.set.has(a._id));
    if (fresh.length === 0) return;
    fresh.forEach((a) => seenStore.set.add(a._id));
    persistSeen();

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

  // Cuántos eventos se piden en cada consulta: los necesarios para el gráfico de IA
  // y para lo que el usuario haya desplegado con "Ver más" en el registro.
  const liveLimit = Math.min(LIVE_MAX_LIMIT, Math.max(20, settings.trendSize, logLimit));
  const backendBase = settings.backendUrl.replace(/\/+$/, '');

  useEffect(() => {
    let cancelled = false;

    const fetchAlerts = async () => {
      try {
        const response = await fetch(`${backendBase}/api/alerts?limit=${liveLimit}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (cancelled) return;
        setAlerts(data);
        setConnected(true);
        setLoading(false);
        handleIncomingAlerts(data);
      } catch (error) {
        if (cancelled) return;
        console.error('Error conectando con el Backend:', error);
        setConnected(false);
      }
    };

    const fetchSwitchStatus = async () => {
      try {
        const response = await fetch(`${backendBase}/api/switch-status`);
        if (!response.ok) return; // backend viejo sin este endpoint todavía: se usa el fallback
        const data = await response.json();
        if (!cancelled) setSwitchStatus(data);
      } catch (error) {
        // silencioso: si falla, el fallback por tiempo sigue funcionando
      }
    };

    const fetchTotals = async () => {
      try {
        const response = await fetch(`${backendBase}/api/alerts/count`);
        if (!response.ok) return; // backend sin el endpoint: se usa el número de eventos cargados
        const data = await response.json();
        if (!cancelled && typeof data.total === 'number') setTotals(data);
      } catch (error) {
        // silencioso
      }
    };

    const fetchHealth = async () => {
      try {
        const response = await fetch(`${backendBase}/api/health`);
        if (!response.ok) return; // backend sin el endpoint: se asume online
        const data = await response.json();
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
  }, [backendBase, settings.pollInterval, liveLimit, handleIncomingAlerts]);

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
      if (selectedAlert) setSelectedAlert(null);
      else if (searchOpen) setSearchOpen(false);
      else if (settingsOpen) setSettingsOpen(false);
      else if (notifOpen) closeNotifications();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedAlert, searchOpen, settingsOpen, notifOpen, closeNotifications]);

  // --- Topología ---

  const moveNode = useCallback((id, pos) => {
    setNodePositions((prev) => ({ ...prev, [id]: pos }));
  }, []);

  const resetPositions = useCallback(() => setNodePositions({ ...DEFAULT_NODE_POSITIONS }), []);

  // --- Datos derivados ---

  const latest = alerts[0];
  const elapsedSinceLatest = latest ? now - parseTimestamp(latest.timestamp).getTime() : Infinity;
  const isActive = latest ? elapsedSinceLatest >= 0 && elapsedSinceLatest < settings.attackWindow * 1000 : false;
  const severity = getSeverity(latest?.confidence);

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

  const confidenceTrend = useMemo(
    () => [...alerts].slice(0, settings.trendSize).reverse().map((a) => a.confidence),
    [alerts, settings.trendSize]
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

  // La ventana de detalle muestra siempre la versión más reciente del documento
  // (p. ej. cuando llega la firma de Solana mientras está abierta).
  const selectedCurrent = selectedAlert
    ? alerts.find((a) => a._id === selectedAlert._id) || selectedAlert
    : null;

  const lastBlockchainAlert = alerts.find((a) => a.blockchain_signature);

  // --- Layout dinámico según paneles visibles ---

  const w = settings.widgets;
  const leftVisible = w.threat || w.services;
  const centerVisible = w.topology || w.timeline || w.blockchain;
  const rightVisible = w.aiPanel || w.eventLog;

  // Reparto de las 12 columnas entre las 3 zonas visibles. Con las tres visibles
  // se mantiene 3/6/3 (el diseño original); si se oculta una zona entera, las
  // demás se ensanchan para ocupar su espacio y no dejar una columna vacía.
  const { leftSpan, centerSpan, rightSpan } = useMemo(() => {
    const weights = { left: leftVisible ? 1 : 0, center: centerVisible ? 2 : 0, right: rightVisible ? 1 : 0 };
    const activeCount = [leftVisible, centerVisible, rightVisible].filter(Boolean).length;
    if (activeCount === 0) return { leftSpan: 0, centerSpan: 0, rightSpan: 0 };
    if (activeCount === 1) {
      return {
        leftSpan: leftVisible ? 12 : 0,
        centerSpan: centerVisible ? 12 : 0,
        rightSpan: rightVisible ? 12 : 0,
      };
    }
    const totalW = weights.left + weights.center + weights.right;
    const spans = {
      left: Math.round((weights.left / totalW) * 12),
      center: Math.round((weights.center / totalW) * 12),
      right: Math.round((weights.right / totalW) * 12),
    };
    const visibleKeys = ['left', 'center', 'right'].filter((k) => weights[k] > 0);
    let diff = 12 - visibleKeys.reduce((s, k) => s + spans[k], 0);
    while (diff !== 0) {
      const k = diff > 0 ? 'center' : visibleKeys.reduce((a, b) => (spans[a] >= spans[b] ? a : b));
      spans[k] += diff > 0 ? 1 : -1;
      diff += diff > 0 ? -1 : 1;
    }
    return { leftSpan: spans.left, centerSpan: spans.center, rightSpan: spans.right };
  }, [leftVisible, centerVisible, rightVisible]);

  const extraCharts = ['attackTypes', 'severity', 'topAttackers', 'ports'].filter((k) => w[k]);
  const nothingVisible = !leftVisible && !centerVisible && !rightVisible && extraCharts.length === 0 && !w.kpis;

  const headerIconBtn = 'p-1.5 rounded transition-colors text-gray-400 hover:text-gray-100 hover:bg-gray-800';

  return (
    <div className="min-h-screen bg-gray-900 text-gray-200 p-4 font-sans">

      {/* Header */}
      <header className="mb-4 pb-4 border-b border-gray-700 flex justify-between items-center gap-4">
        <h1 className="text-xl font-bold text-gray-100 flex items-center gap-2">
          <ShieldAlert className="text-red-500" />
          SDN Cyberdefense Dashboard
        </h1>
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

          {/* Configuración */}
          <button
            onClick={() => { closeNotifications(); setSettingsOpen(true); }}
            className={`p-1.5 rounded transition-colors ${settingsOpen ? 'bg-gray-800 text-gray-100' : 'text-gray-400 hover:text-gray-100 hover:bg-gray-800'}`}
            aria-label="Configuración"
          >
            <Settings size={18} />
          </button>
        </div>
      </header>

      {w.kpis && <KpiStrip stats={stats} totalAlerts={totalAlerts} totalBlocked={totalBlocked} />}

      {nothingVisible && (
        <div className="py-24 flex flex-col items-center gap-3 text-gray-500">
          <LayoutGrid size={28} />
          <p className="text-sm font-mono">Todos los paneles están ocultos.</p>
          <button onClick={() => setSettingsOpen(true)} className="text-xs text-blue-400 hover:text-blue-300">Abrir configuración</button>
        </div>
      )}

      {/* Distribución en 3 columnas (izquierda / centro / derecha), como el diseño
          original. Cada columna es un flex vertical: al ocultar un panel, los de
          abajo suben sin dejar huecos. Cuando una columna entera queda vacía, las
          demás se ensanchan para ocupar su espacio (reparto de las 12 columnas). */}
      {(leftVisible || centerVisible || rightVisible) && (
        <div className="grid grid-cols-12 gap-4 items-start">

          {/* Columna Izquierda */}
          {leftVisible && (
            <div className={`col-span-12 ${COL_SPAN[leftSpan]} flex flex-col gap-4`}>

              {w.threat && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                  <h2 className="text-sm font-semibold text-gray-400 mb-1 uppercase tracking-wider">Contexto de Amenaza Crítica</h2>
                  <p className="text-[10px] text-gray-600 mb-3 min-h-[12px]">
                    {latest && !blocked ? 'Última alerta registrada — la infraestructura ya no está bloqueando este flujo.' : ''}
                  </p>
                  {latest ? (
                    <div className="space-y-3 text-sm">
                      <div>
                        <p className="text-xs text-gray-500">ID de Amenaza:</p>
                        <p className="font-mono text-gray-200">{shortId(latest._id)}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Tipo de Ataque:</p>
                        <p className="font-mono text-gray-200">{latest.attack_type}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Severidad:</p>
                        <p className={`font-mono font-bold ${severity.text}`}>{severity.label}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Confianza IA:</p>
                        <p className="font-mono font-bold text-green-400">{Number(latest.confidence ?? 0).toFixed(1)}%</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Origen → Destino:</p>
                        <p className="font-mono text-gray-200 text-xs">{latest.attacker_ip} → {latest.victim_ip}:{latest.victim_port}</p>
                      </div>
                      <div>
                        <p className="text-xs text-gray-500">Acción Tomada:</p>
                        <p className={`font-mono font-bold ${isBlockAction(latest.action_taken) ? 'text-red-400' : 'text-yellow-400'}`}>{latest.action_taken}</p>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-gray-500 font-mono">Sin amenazas activas.</p>
                  )}
                </div>
              )}

              {w.services && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                  <h2 className="text-sm font-semibold text-gray-400 mb-4 uppercase tracking-wider">Estado de Servicios</h2>
                  <div className="space-y-3 text-sm">
                    <div className="flex justify-between items-center">
                      <span className="flex items-center gap-2"><Database size={16} className="text-blue-400" /> MongoDB</span>
                      <ServiceStatus ok={health?.mongodb} connected={connected} />
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="flex items-center gap-2"><Server size={16} className="text-purple-400" /> Solana</span>
                      <ServiceStatus ok={health?.solana} connected={connected} />
                    </div>
                  </div>
                  {health && !health.solana && (
                    <p className="text-[10px] text-orange-400 mt-3 leading-snug">
                      Solana no responde en localhost:8899. Los ataques no se registrarán en la blockchain hasta que el validador esté activo.
                    </p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Columna Central */}
          {centerVisible && (
            <div className={`col-span-12 ${COL_SPAN[centerSpan]} flex flex-col gap-4`}>
              {w.topology && (
                <div className="bg-gray-800 rounded-lg border border-gray-700 relative overflow-hidden shadow-lg p-4 h-[420px]">
                  <div className="flex items-center justify-between mb-2 relative z-10 gap-2">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Topología</h2>
                    <div className="flex items-center gap-1">
                      <span className="hidden xl:inline text-[10px] text-gray-600 font-mono mr-2">
                        {settings.topology.lockNodes ? 'Nodos bloqueados' : 'Arrastra los nodos para moverlos'}
                      </span>
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
                  <div className="relative w-full h-[calc(100%-28px)]">
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

              {w.timeline && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                  <h2 className="text-sm font-semibold text-gray-400 mb-3 uppercase tracking-wider">Línea de Tiempo de Integridad de Activos</h2>
                  <AssetTimeline alerts={alerts} limit={settings.timelineSize} />
                </div>
              )}

              {w.blockchain && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                  <h2 className="text-sm font-semibold text-gray-400 mb-2 uppercase tracking-wider">Último Hash Blockchain (Solana)</h2>
                  {lastBlockchainAlert ? (
                    <p className="text-xs text-yellow-400 font-mono break-all bg-gray-900 p-2 rounded border border-gray-700">
                      {lastBlockchainAlert.blockchain_signature}
                    </p>
                  ) : (
                    <p className="text-xs text-gray-500 font-mono">Esperando confirmación de transacción inmutable en bloque...</p>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Columna Derecha */}
          {rightVisible && (
            <div className={`col-span-12 ${COL_SPAN[rightSpan]} flex flex-col gap-4`}>
              {w.aiPanel && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg">
                  <div className="flex items-center justify-between mb-1">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Panel de IA</h2>
                    <span className="text-[10px] text-gray-600 font-mono">gráfico: últimos {confidenceTrend.length || 0}</span>
                  </div>
                  <p className="text-xs text-gray-500 mb-2">Tasa de confianza de detección</p>
                  <AnomalySparkline values={confidenceTrend} />
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

              {w.eventLog && (
                <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 shadow-lg flex flex-col max-h-[640px]">
                  <div className="flex items-center justify-between mb-4 gap-2">
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Registro de Eventos en Vivo</h2>
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
                  <div className="flex-grow overflow-y-auto space-y-3 pr-1 text-xs font-mono min-h-[120px]">
                    {loading ? (
                      <p className="text-gray-500">Cargando eventos...</p>
                    ) : alerts.length === 0 ? (
                      <p className="text-gray-500">Sin ataques detectados. Ejecuta una prueba desde el atacante.</p>
                    ) : (
                      logItems.map((alert, index) => (
                        <EventRow key={alert._id || index} alert={alert} onClick={setSelectedAlert} />
                      ))
                    )}
                  </div>
                  {!loading && alerts.length > 0 && (
                    <div className="pt-3 mt-3 border-t border-gray-700 flex items-center justify-between gap-2">
                      <span className="text-[10px] text-gray-500 font-mono">
                        Mostrando {logItems.length} de {totalAlerts.toLocaleString()}
                      </span>
                      <div className="flex items-center gap-1">
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
              )}
            </div>
          )}

        </div>
      )}

      {/* Gráficos adicionales */}
      {extraCharts.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mt-4">
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

      {/* Avisos emergentes */}
      {toasts.length > 0 && (
        <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-80 max-w-[calc(100vw-2rem)]">
          {toasts.map((t) => (
            <Toast key={t.toastId} toast={t} onDismiss={dismissToast} />
          ))}
        </div>
      )}

      {settingsOpen && (
        <SettingsDrawer
          settings={settings}
          setSettings={setSettings}
          onClose={() => setSettingsOpen(false)}
          onResetPositions={resetPositions}
          onClearNotifications={clearNotifications}
          notificationCount={notifications.length}
        />
      )}

      {searchOpen && (
        <SearchModal
          backendUrl={backendBase}
          filters={filters}
          setFilters={setFilters}
          onClose={() => setSearchOpen(false)}
          onSelect={setSelectedAlert}
          fallbackAlerts={alerts}
        />
      )}

      {selectedCurrent && (
        <AlertDetailModal
          key={selectedCurrent._id}
          alert={selectedCurrent}
          backendUrl={backendBase}
          onClose={() => setSelectedAlert(null)}
        />
      )}
    </div>
  );
}
