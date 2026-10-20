// Cliente HTTP del dashboard: JWT + manejo central de 401.

const TOKEN_KEY = 'sdn-dash:token';

let _token = '';
try {
  _token = localStorage.getItem(TOKEN_KEY) || '';
} catch {
  _token = '';
}

export function getToken() {
  return _token;
}

export function setToken(t) {
  _token = t || '';
  try {
    if (_token) localStorage.setItem(TOKEN_KEY, _token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // almacenamiento no disponible
  }
}

export class ApiError extends Error {
  constructor(status, message) {
    super(message || `HTTP ${status}`);
    this.status = status;
  }
}

// backendBase: 'http://host:8001' (sin / final). Lanza ApiError; 401 = sesión caducada.
export async function apiFetch(backendBase, path, opts = {}) {
  const { body, ...rest } = opts;
  const headers = { ...(rest.headers || {}) };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (_token) headers.Authorization = `Bearer ${_token}`;
  let r;
  try {
    r = await fetch(`${backendBase}${path}`, { ...rest, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  } catch {
    throw new ApiError(0, `Sin conexión con el backend (${backendBase})`);
  }
  if (r.status === 401) throw new ApiError(401, 'Sesión caducada: inicia sesión de nuevo');
  if (r.status === 204) return null;
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    const msg = data && typeof data.detail === 'string' ? data.detail : `HTTP ${r.status}`;
    throw new ApiError(r.status, msg);
  }
  return data;
}

// URL del WebSocket de terminal (el navegador no envía cabeceras en WS: el JWT va en ?token=)
export function wsTerminalUrl(backendBase, host) {
  const base = backendBase.replace(/^http/, 'ws').replace(/\/+$/, '');
  return `${base}/ws/terminal/${host}?token=${encodeURIComponent(_token)}`;
}
