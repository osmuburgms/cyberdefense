import { useState, useEffect, useRef, useCallback } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { X, Trash2, Loader2, Terminal as TerminalIcon, Move, RotateCw, Send } from 'lucide-react';
import { apiFetch, wsTerminalUrl } from '../api';

// Terminal REAL por WebSocket: xterm.js <--WS--> backend <--PTY--> lxc-attach.
// A diferencia del modo HTTP anterior, aquí el shell vive por conexión:
// la salida llega en streaming y Ctrl+C manda SIGINT de verdad al contenedor.

// Metadatos fijos de la topología VNX (datacenter_sdn.xml). Deben coincidir
// con ALLOWED_HOSTS del backend (main.py) y TOPOLOGY de App.jsx.
const HOSTS = {
  attacker: {
    ip: '192.168.1.50',
    quick: [
      'ip -brief addr',
      'ping -c 3 192.168.1.10',
      'cat /root/passwords.txt',
      'nmap -F 192.168.1.10',
      'hydra -l root -P /root/passwords.txt ssh://192.168.1.10 -t 4',
    ],
  },
  server1: {
    ip: '192.168.1.10',
    quick: [
      'ip -brief addr',
      'ss -tlnp',
      'ps aux | head -20',
      'ls -la /root',
      'cat /etc/os-release',
    ],
  },
  server2: {
    ip: '192.168.1.11',
    quick: [
      'ip -brief addr',
      'ss -tlnp',
      'ps aux | head -20',
      'ls -la /root',
      'cat /etc/os-release',
    ],
  },
};

const HOST_IDS = Object.keys(HOSTS);

const TERM_THEME = {
  background: '#030712',
  foreground: '#e5e7eb',
  cursor: '#4ade80',
  cursorAccent: '#030712',
  selectionBackground: 'rgba(59, 130, 246, 0.35)',
  black: '#111827',
  red: '#f87171',
  green: '#4ade80',
  yellow: '#facc15',
  blue: '#60a5fa',
  magenta: '#c084fc',
  cyan: '#22d3ee',
  white: '#e5e7eb',
  brightBlack: '#4b5563',
  brightRed: '#fca5a5',
  brightGreen: '#86efac',
  brightYellow: '#fde047',
  brightBlue: '#93c5fd',
  brightMagenta: '#d8b4fe',
  brightCyan: '#67e8f9',
  brightWhite: '#f9fafb',
};

const GEOM_KEY = 'sdn-dash:terminal-geom';
const DEFAULT_GEOM = { w: 680, h: 480 };
const MIN_W = 420;
const MIN_H = 320;

function clampGeom(g) {
  const vw = typeof window !== 'undefined' ? window.innerWidth : 1280;
  const vh = typeof window !== 'undefined' ? window.innerHeight : 800;
  const w = Math.min(Math.max(g.w || DEFAULT_GEOM.w, MIN_W), vw - 16);
  const h = Math.min(Math.max(g.h || DEFAULT_GEOM.h, MIN_H), vh - 16);
  const x = Math.min(Math.max(g.x ?? (vw - w) / 2, 0), Math.max(0, vw - 120));
  const y = Math.min(Math.max(g.y ?? (vh - h) / 2, 0), Math.max(0, vh - 60));
  return { x, y, w, h };
}

function loadGeom() {
  const center = () => {
    const vw = typeof window !== 'undefined' ? window.innerWidth : 1280;
    const vh = typeof window !== 'undefined' ? window.innerHeight : 800;
    return { x: Math.max(0, (vw - DEFAULT_GEOM.w) / 2), y: Math.max(0, (vh - DEFAULT_GEOM.h) / 2), ...DEFAULT_GEOM };
  };
  try {
    const raw = localStorage.getItem(GEOM_KEY);
    if (!raw) return center();
    return clampGeom({ ...center(), ...JSON.parse(raw) });
  } catch {
    return center();
  }
}

export default function HostTerminal({ initialHost = 'attacker', backendUrl, onClose }) {
  const safeInitial = HOSTS[initialHost] ? initialHost : 'attacker';
  const [activeHost, setActiveHost] = useState(safeInitial);
  // Si App.jsx cambia el host (click en otro nodo con la consola abierta),
  // cambiamos de pestaña sin perder las sesiones ya abiertas.
  // Patrón "ajuste de estado durante el render" (sin useEffect).
  const [prevInitial, setPrevInitial] = useState(initialHost);
  if (initialHost !== prevInitial) {
    setPrevInitial(initialHost);
    if (HOSTS[initialHost]) setActiveHost(initialHost);
  }

  const [status, setStatus] = useState({}); // host -> { running } (lxc-info)
  const [conns, setConns] = useState({});   // host -> 'connecting' | 'open' | 'closed'
  const [quick, setQuick] = useState('');

  const boxRefs = useRef({});      // host -> div contenedor de xterm
  const sessionsRef = useRef({});  // host -> { term, fit, ws, dead }
  const pendingRef = useRef({});   // host -> texto pendiente de enviar al abrir
  const backendRef = useRef(backendUrl);
  useEffect(() => { backendRef.current = backendUrl; }, [backendUrl]);

  // ---- Ventana flotante movible y redimensionable (superpuesta, z-[70]) ----
  const [geom, setGeom] = useState(loadGeom);
  const [dragging, setDragging] = useState(false);
  const [resizing, setResizing] = useState(false);
  const moveRef = useRef(null);
  const resizeRef = useRef(null);
  const headerRef = useRef(null);

  useEffect(() => {
    const t = setTimeout(() => {
      try { localStorage.setItem(GEOM_KEY, JSON.stringify(geom)); } catch { /* sin almacenamiento */ }
    }, 300);
    return () => clearTimeout(t);
  }, [geom]);

  useEffect(() => {
    const onWinResize = () => setGeom((g) => clampGeom(g));
    window.addEventListener('resize', onWinResize);
    return () => window.removeEventListener('resize', onWinResize);
  }, []);

  const centerWindow = useCallback(() => {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    setGeom((g) => ({ ...g, x: Math.max(0, (vw - g.w) / 2), y: Math.max(0, (vh - g.h) / 2) }));
  }, []);

  const onHeaderPointerDown = (e) => {
    if (e.button !== 0) return;
    if (e.target.closest('button, input, a')) return;
    e.preventDefault();
    moveRef.current = { startX: e.clientX, startY: e.clientY, origX: geom.x, origY: geom.y };
    headerRef.current?.setPointerCapture?.(e.pointerId);
    setDragging(true);
  };

  const onHeaderPointerMove = (e) => {
    const m = moveRef.current;
    if (!m) return;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const x = Math.min(Math.max(m.origX + (e.clientX - m.startX), 0), Math.max(0, vw - 120));
    const y = Math.min(Math.max(m.origY + (e.clientY - m.startY), 0), Math.max(0, vh - 50));
    setGeom((g) => ({ ...g, x, y }));
  };

  const endMove = (e) => {
    if (!moveRef.current) return;
    moveRef.current = null;
    setDragging(false);
    try { headerRef.current?.releasePointerCapture?.(e.pointerId); } catch { /* ya liberado */ }
  };

  const onResizePointerDown = (e) => {
    if (e.button !== 0) return;
    e.preventDefault();
    e.stopPropagation();
    resizeRef.current = { startX: e.clientX, startY: e.clientY, origW: geom.w, origH: geom.h };
    e.currentTarget.setPointerCapture?.(e.pointerId);
    setResizing(true);
  };

  const onResizePointerMove = (e) => {
    const r = resizeRef.current;
    if (!r) return;
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const w = Math.min(Math.max(r.origW + (e.clientX - r.startX), MIN_W), vw - geom.x - 8);
    const h = Math.min(Math.max(r.origH + (e.clientY - r.startY), MIN_H), vh - geom.y - 8);
    setGeom((g) => ({ ...g, w, h }));
  };

  const endResize = (e) => {
    if (!resizeRef.current) return;
    resizeRef.current = null;
    setResizing(false);
    try { e.currentTarget.releasePointerCapture?.(e.pointerId); } catch { /* ya liberado */ }
  };

  // ---- Sesiones xterm + WebSocket por host ----

  const setConn = useCallback((host, st) => {
    setConns((prev) => (prev[host] === st ? prev : { ...prev, [host]: st }));
  }, []);

  const pushResize = useCallback((host) => {
    const s = sessionsRef.current[host];
    if (!s || !s.term || !s.fit) return;
    if (!s.ws || s.ws.readyState !== WebSocket.OPEN) return;
    try {
      s.fit.fit();
      s.ws.send(JSON.stringify({ t: 'resize', rows: s.term.rows, cols: s.term.cols }));
    } catch { /* terminal aún sin dimensiones */ }
  }, []);

  const writeLine = useCallback((host, text) => {
    const s = sessionsRef.current[host];
    if (s?.term) s.term.writeln(text);
  }, []);

  const destroySession = useCallback((host) => {
    const s = sessionsRef.current[host];
    if (!s) return;
    s.dead = true;
    try { s.ws?.close(); } catch { /* ya cerrado */ }
    try { s.term?.dispose(); } catch { /* ya liberado */ }
    delete sessionsRef.current[host];
  }, []);

  const ensureSession = useCallback((host) => {
    if (!HOSTS[host]) return;
    const existing = sessionsRef.current[host];
    if (existing && !existing.dead) {
      if (existing.ws && (existing.ws.readyState === WebSocket.OPEN || existing.ws.readyState === WebSocket.CONNECTING)) return;
      // ws muerto pero terminal viva: reconecta sobre la misma terminal
      existing.dead = false;
    }
    const box = boxRefs.current[host];
    let s = sessionsRef.current[host];
    if (!s || !s.term) {
      if (!box) return; // contenedor aún no montado
      const term = new Terminal({
        cursorBlink: true,
        fontSize: 13,
        fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
        scrollback: 2000,
        theme: TERM_THEME,
      });
      const fit = new FitAddon();
      term.loadAddon(fit);
      term.open(box);
      term.onData((d) => {
        const cur = sessionsRef.current[host];
        if (cur?.ws && cur.ws.readyState === WebSocket.OPEN && !cur.dead) {
          cur.ws.send(JSON.stringify({ t: 'in', d }));
        }
      });
      // Ctrl+C copia si hay selección; si no, deja pasar \x03 al contenedor (= SIGINT real).
      // Ctrl+V / Shift+Ins / click derecho pegan el portapapeles.
      term.attachCustomKeyEventHandler((e) => {
        const key = e.key?.toLowerCase();
        if (e.ctrlKey && !e.altKey && !e.metaKey && (key === 'c' || key === 'v')) {
          if (key === 'c' && term.hasSelection()) {
            navigator.clipboard?.writeText(term.getSelection()).catch(() => {});
            term.clearSelection();
            return false;
          }
          if (key === 'v') {
            navigator.clipboard?.readText().then((t) => {
              const cur = sessionsRef.current[host];
              if (t && cur?.ws && cur.ws.readyState === WebSocket.OPEN && !cur.dead) {
                cur.ws.send(JSON.stringify({ t: 'in', d: t }));
              }
            }).catch(() => {});
            return false;
          }
        }
        return true;
      });
      term.attachCustomWheelEventHandler(() => true);
      s = { term, fit, ws: null, dead: false };
      sessionsRef.current[host] = s;
    }
    s.dead = false;
    setConn(host, 'connecting');
    let ws;
    try {
      ws = new WebSocket(wsTerminalUrl(backendRef.current, host));
    } catch {
      setConn(host, 'closed');
      return;
    }
    ws.binaryType = 'arraybuffer';
    s.ws = ws;

    ws.onopen = () => {
      if (s.dead) { try { ws.close(); } catch { /* noop */ } return; }
      setConn(host, 'open');
      const pend = pendingRef.current[host];
      if (pend) {
        pendingRef.current[host] = '';
        try { ws.send(JSON.stringify({ t: 'in', d: pend })); } catch { /* reintentará el usuario */ }
      }
      // Ajusta al tamaño visible (la pestaña puede haberse mostrado justo ahora)
      requestAnimationFrame(() => pushResize(host));
      setTimeout(() => pushResize(host), 120);
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        try {
          const m = JSON.parse(ev.data);
          if (m?.t === 'exit') {
            writeLine(host, `\r\n\x1b[90m[sesión terminada en ${host} (exit ${m.code ?? '?'}) — pulsa reconectar para abrir otra]\x1b[0m`);
          }
        } catch { /* texto no-JSON: se ignora */ }
        return;
      }
      try {
        s.term.write(new Uint8Array(ev.data));
      } catch { /* terminal liberada */ }
    };
    ws.onclose = () => { if (!s.dead) setConn(host, 'closed'); };
    ws.onerror = () => { if (!s.dead) setConn(host, 'closed'); };
  }, [pushResize, setConn, writeLine]);

  const reconnect = useCallback((host) => {
    destroySession(host);
    setConn(host, 'connecting');
    // Espera al siguiente tick para que el contenedor siga montado
    setTimeout(() => ensureSession(host), 30);
  }, [destroySession, ensureSession, setConn]);

  const sendQuick = useCallback((host, cmd) => {
    const s = sessionsRef.current[host];
    if (s && !s.dead && s.ws && s.ws.readyState === WebSocket.OPEN) {
      try { s.ws.send(JSON.stringify({ t: 'in', d: cmd + '\r' })); } catch { /* noop */ }
    } else {
      pendingRef.current[host] = (pendingRef.current[host] || '') + cmd + '\r';
      ensureSession(host);
    }
    // Lleva el foco a la terminal para seguir escribiendo
    try { sessionsRef.current[host]?.term?.focus(); } catch { /* noop */ }
  }, [ensureSession]);

  const clearActive = useCallback(() => {
    try { sessionsRef.current[activeHost]?.term?.clear(); } catch { /* noop */ }
  }, [activeHost]);

  // Conecta la pestaña inicial al montar; limpia todo al desmontar.
  // La conexión se difiere un tick: el estado 'connecting' se actualiza
  // desde los callbacks del WebSocket, no de forma síncrona en el efecto.
  useEffect(() => {
    let cancelled = false;
    const t = setTimeout(() => { if (!cancelled) ensureSession(safeInitial); }, 0);
    return () => {
      cancelled = true;
      clearTimeout(t);
      Object.keys(sessionsRef.current).forEach((h) => {
        const s = sessionsRef.current[h];
        if (s) {
          s.dead = true;
          try { s.ws?.close(); } catch { /* noop */ }
          try { s.term?.dispose(); } catch { /* noop */ }
        }
      });
      sessionsRef.current = {};
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Al cambiar de pestaña o de tamaño: conecta si falta y reajusta filas/columnas
  useEffect(() => {
    const t0 = setTimeout(() => ensureSession(activeHost), 0);
    const t1 = requestAnimationFrame(() => pushResize(activeHost));
    const t2 = setTimeout(() => pushResize(activeHost), 120);
    try { sessionsRef.current[activeHost]?.term?.focus(); } catch { /* noop */ }
    return () => { clearTimeout(t0); cancelAnimationFrame(t1); clearTimeout(t2); };
  }, [activeHost, ensureSession, pushResize]);

  useEffect(() => {
    const t = setTimeout(() => pushResize(activeHost), 120);
    return () => clearTimeout(t);
  }, [geom.w, geom.h, activeHost, pushResize]);

  // Punto verde/rojo por contenedor (lxc-info). Silencioso si falla.
  useEffect(() => {
    let alive = true;
    const refresh = async () => {
      const base = backendRef.current;
      if (!base) return;
      const entries = await Promise.all(
        HOST_IDS.map(async (h) => {
          try {
            return [h, await apiFetch(base, `/api/hosts/${h}/ping`)];
          } catch {
            return [h, { running: false }];
          }
        })
      );
      if (alive) setStatus(Object.fromEntries(entries));
    };
    refresh();
    const t = setInterval(refresh, 15000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const connState = conns[activeHost] || 'connecting';

  const pasteFromMenu = async () => {
    try {
      const t = await navigator.clipboard.readText();
      const s = sessionsRef.current[activeHost];
      if (t && s && !s.dead && s.ws && s.ws.readyState === WebSocket.OPEN) {
        s.ws.send(JSON.stringify({ t: 'in', d: t }));
      }
      s?.term?.focus();
    } catch { /* portapapeles no disponible */ }
  };

  return (
    <div
      className="fixed z-[70] bg-gray-950 border border-gray-700 rounded-xl shadow-2xl flex flex-col overflow-hidden modal-in"
      role="dialog"
      aria-modal="false"
      aria-label={`Consola SDN — ${activeHost}`}
      style={{ left: geom.x, top: geom.y, width: geom.w, height: geom.h }}
    >
      {/* Cabecera (arrastrable; doble click para centrar) */}
      <div
        ref={headerRef}
        onPointerDown={onHeaderPointerDown}
        onPointerMove={onHeaderPointerMove}
        onPointerUp={endMove}
        onPointerCancel={endMove}
        onDoubleClick={centerWindow}
        className={`flex items-center gap-2 px-3 py-2 bg-gray-900 border-b border-gray-700 select-none ${dragging ? 'cursor-grabbing' : 'cursor-move'}`}
        style={{ touchAction: 'none' }}
        title="Arrastra para mover · Doble click para centrar"
      >
        <Move size={13} className="text-gray-600 shrink-0" />
        <TerminalIcon size={15} className="text-green-400 shrink-0" />
        <span className="text-xs font-semibold text-gray-200 mr-1 hidden sm:inline">Consola SDN</span>
        <div className="flex items-center gap-1 flex-1 min-w-0">
          {HOST_IDS.map((h) => {
            const st = status[h];
            const dot = st === undefined ? 'bg-gray-600' : st.running ? 'bg-green-500' : 'bg-red-500';
            const cs = conns[h];
            return (
              <button
                key={h}
                onClick={() => setActiveHost(h)}
                className={`flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 rounded border transition-colors truncate ${activeHost === h ? 'bg-gray-700 border-gray-500 text-gray-100' : 'border-transparent text-gray-400 hover:text-gray-200 hover:bg-gray-800'}`}
                title={`${h} (${HOSTS[h].ip}) — ${cs === 'open' ? 'sesión abierta' : cs === 'connecting' ? 'conectando…' : 'sesión cerrada'}`}
              >
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
                {h}
              </button>
            );
          })}
        </div>
        <span className={`text-[10px] font-mono shrink-0 ${connState === 'open' ? 'text-green-400' : connState === 'connecting' ? 'text-yellow-400' : 'text-red-400'}`}>
          {connState === 'open' ? '● en vivo' : connState === 'connecting' ? '… conectando' : '○ cerrada'}
        </span>
        <button
          onClick={() => reconnect(activeHost)}
          className="p-1.5 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-800"
          title="Reconectar (nuevo shell)"
          aria-label="Reconectar"
        >
          <RotateCw size={14} />
        </button>
        <button onClick={clearActive} className="p-1.5 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-800" title="Limpiar pantalla" aria-label="Limpiar pantalla">
          <Trash2 size={14} />
        </button>
        <button onClick={onClose} className="p-1.5 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-800" title="Cerrar consola (Esc)" aria-label="Cerrar consola">
          <X size={15} />
        </button>
      </div>

      {/* Área xterm (una instancia viva por host, solo la activa visible) */}
      <div className="relative flex-1 min-h-0 bg-[#030712]">
        {HOST_IDS.map((h) => (
          <div
            key={h}
            ref={(el) => { if (el) boxRefs.current[h] = el; }}
            className="absolute inset-0 p-2"
            style={{ display: h === activeHost ? 'block' : 'none' }}
            onContextMenu={(e) => { if (h === activeHost) { e.preventDefault(); pasteFromMenu(); } }}
          />
        ))}
        {connState === 'connecting' && (
          <div className="absolute inset-0 flex items-center justify-center gap-2 text-gray-500 text-xs font-mono bg-[#030712]/80 pointer-events-none">
            <Loader2 size={14} className="animate-spin" /> Abriendo shell en {activeHost}…
          </div>
        )}
        {connState === 'closed' && (
          <div className="absolute inset-x-0 bottom-0 p-2 flex justify-center pointer-events-none">
            <button
              onClick={() => reconnect(activeHost)}
              className="pointer-events-auto flex items-center gap-1.5 text-[11px] font-mono px-3 py-1.5 rounded border border-gray-600 bg-gray-900 text-gray-200 hover:border-green-500"
            >
              <RotateCw size={12} /> Sesión cerrada — reconectar
            </button>
          </div>
        )}
      </div>

      {/* Comandos rápidos (se escriben en el shell vivo) */}
      <div className="px-3 py-1.5 border-t border-gray-800 bg-gray-900/60 flex gap-1.5 overflow-x-auto">
        {HOSTS[activeHost].quick.map((q) => (
          <button
            key={q}
            onClick={() => sendQuick(activeHost, q)}
            className="shrink-0 text-[10px] font-mono px-2 py-1 rounded border border-gray-700 text-gray-400 hover:text-gray-100 hover:border-gray-500"
            title={`Escribir en el shell: ${q}`}
          >
            {q.length > 28 ? q.slice(0, 28) + '…' : q}
          </button>
        ))}
      </div>

      {/* Entrada rápida opcional (también puedes teclear directo en la terminal) */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!quick.trim()) return;
          sendQuick(activeHost, quick.trim());
          setQuick('');
        }}
        className="flex items-center gap-2 px-3 py-2 bg-gray-900 border-t border-gray-700"
      >
        <input
          value={quick}
          onChange={(e) => setQuick(e.target.value)}
          placeholder={`Escribir y Enter para enviar a ${activeHost} (Ctrl+C interrumpe)`}
          autoComplete="off"
          spellCheck={false}
          className="flex-1 min-w-0 bg-transparent font-mono text-[12px] text-gray-100 placeholder-gray-600 focus:outline-none"
          aria-label={`Envío rápido a ${activeHost}`}
        />
        <button
          type="submit"
          disabled={!quick.trim()}
          className="p-1.5 rounded text-gray-400 hover:text-gray-100 hover:bg-gray-800 disabled:opacity-30 shrink-0"
          title="Enviar (Enter)"
          aria-label="Enviar"
        >
          <Send size={14} />
        </button>
      </form>
      <div className="px-3 py-1 bg-gray-900 border-t border-gray-800 text-[10px] font-mono text-gray-600 truncate pr-8">
        ≡ shell real en {activeHost} · {HOSTS[activeHost].ip} · streaming WS · Ctrl+C = SIGINT · click derecho = pegar
      </div>

      {/* Esquina redimensionable */}
      <div
        onPointerDown={onResizePointerDown}
        onPointerMove={onResizePointerMove}
        onPointerUp={endResize}
        onPointerCancel={endResize}
        className={`absolute bottom-0 right-0 w-5 h-5 flex items-end justify-end pr-1 pb-1 rounded-tl-md ${resizing ? 'bg-gray-700' : 'hover:bg-gray-800'} cursor-nwse-resize`}
        style={{ touchAction: 'none' }}
        title="Arrastra para redimensionar"
        aria-label="Redimensionar consola"
      >
        <svg width="10" height="10" viewBox="0 0 10 10" className="text-gray-500">
          <path d="M9 1 L1 9 M9 5 L5 9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>
    </div>
  );
}
