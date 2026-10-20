"""Motor IPS en tiempo real: LightGBM + mitigación activa.

Modelo por defecto: RAM ligero (16 features, 6 clases: BENIGN, BruteForce,
DoS, PortScan, Slowloris, UDP_Flood), probado en producción. Modelo 1.2M
completo (77 features, 14 clases CIC-IDS2017) disponible vía IPS_MODEL /
IPS_ENCODER, hoy experimental (ver NOTA_MODELO_1_2M).

Capas de decisión por flujo (además del modelo):
  L2/L3 por reglas : ARP Spoofing (reply con MAC cambiada) e IP Spoofing
                     (origen fuera de 192.168.1.0/24). Respuesta inmediata.
  Heurística lenta : conexión lenta a puerto HTTP (80/443/8080) de >5 s con
                     <30 paquetes -> etiqueta Slowloris del modelo en uso.
  Modelo (1.2M)    : checkpoints en 2 / 15 / 30 / 60 paquetes. A los 2 solo se
                     acepta PortScan (fuera de puertos de servicio comunes);
                     en 15/30/60 cualquier clase no benigna con confianza >= 0.70.
  Volumétrica      : red de seguridad (>=300 pkts y >=2000 pps -> "DDoS"
                     heurístico). Cubre floods que el modelo viera como BENIGN.

Notas de extracción (aproximan CICFlowMeter/CIC-IDS2017):
  - Longitudes = longitud total IP; ventanas = ventada TCP anunciada.
  - Header length y min_seg_size_forward = cabecera IP (ihl*4), verificado
    contra CICFlowMeter real (20 B/pkt aunque el TCP lleve opciones).
  - Bulk: rachas con datos; bytes = payload, tasa = bytes/s (verificado).
  - Active/Idle con umbral de gap de 5 s (supuesto documentado de CICFlowMeter).
  - Bulk simplificado: racha de >=4 paquetes consecutivos misma dirección con
    datos. Subflow = totales (como en el dataset). min_seg_size_forward = IP
    mínima hacia adelante.
Cambio de modelo: variables de entorno IPS_MODEL / IPS_ENCODER (por defecto
los artefactos RAM ligeros y probados en producción; el 1.2M completo es
experimental: ver NOTA_MODELO_1_2M más abajo).
El vector se ordena según modelo.feature_name(), así que el mismo código
sirve a artefactos compatibles (16 o 77 features).

NOTA_MODELO_1_2M (oct-2026, validado con scripts/validar_modelo_1_2M.py):
  El extractor de 77 features se verificó campo por campo contra CICFlowMeter
  real (longitudes, bulks=payload, subflow=totales, ventanas, flags, IAT en µs).
  Aun así, el artefacto lightgbm_1_2M_final clasifica como BENIGN (~99-100%)
  TODO lo probado: vectores live, filas TRUE de CICFlowMeter, 8 formas de
  ataque (scan/sondas, Hulk hasta 12.500 pkts, SSH-patator, UDP-flood,
  SQLi, XSS, Bot-heartbeat, GoldenEye) y barridos aleatorios amplios del
  espacio (donde sí dispara otras clases: el artefacto no es constante).
  Sin los CSV de entrenamiento (ausentes del repo) no se puede recalibrar ni
  probar su exactitud. NO usar en vivo hasta validarlo con sus datos:
  mantendría ciego el IPS frente al modelo RAM actual.
"""
import pandas as pd
import math
import joblib
import requests
import lightgbm as lgb
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import warnings
from pathlib import Path

warnings.filterwarnings('ignore')

print("Cargando Motor de IA Híbrido con Mitigación Activa (IPS) y Conexión Backend...")

AI_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = Path(os.environ.get("IPS_MODEL", AI_DIR / 'models' / 'lightgbm_ram_optimizado.txt'))
ENCODER_FILE = Path(os.environ.get("IPS_ENCODER", AI_DIR / 'models' / 'label_encoder_ram_optimizado.pkl'))

if not os.path.exists(MODEL_FILE):
    print(f"❌ ERROR CRÍTICO: No se encontró el archivo del modelo en {MODEL_FILE}")
    exit(1)
if not os.path.exists(ENCODER_FILE):
    print(f"❌ ERROR CRÍTICO: No se encontró el archivo del encoder en {ENCODER_FILE}")
    exit(1)

modelo = lgb.Booster(model_file=str(MODEL_FILE))
encoder = joblib.load(ENCODER_FILE)
features_cols = modelo.feature_name()
CLASES = set(str(c) for c in encoder.classes_)
# Etiqueta de la heurística lenta según el modelo en uso (RAM: "Slowloris").
SLOW_LABEL = "DoS slowloris" if "DoS slowloris" in CLASES else "Slowloris"

print(f"   Modelo: {MODEL_FILE.name} | {len(features_cols)} features | "
      f"{len(CLASES)} clases | árboles: {modelo.num_trees()}")

# --- Política de decisión (agnóstica al artefacto: solo usa BENIGN/PortScan) ---
UMBRAL_CONFIANZA = 0.70          # igual que infer_lightgbm.py --threshold
CHECKPOINTS_MODELO = (15, 30, 60)
PUERTOS_SCAN_EXCLUIDOS = {21, 22, 80, 443, 53}  # no alertar tráfico legítimo
PUERTOS_HTTP_HEURISTICA = (80, 8080)  # solo HTTP plano: en 443 los heartbeats
                                     # largos dan falsos positivos (validado)
VOL_MIN_PKTS = 300               # red volumétrica: flood que el modelo viera BENIGN
VOL_MIN_PPS = 2000.0
IDLE_GAP = 5.0                   # umbral active/idle (supuesto CICFlowMeter)
BULK_MIN_PKTS = 4                # racha mínima para contar un bulk

flujos = {}
tabla_arp = {}
RYU_API_URL = "http://localhost:8080/ips/block"
BACKEND_API_URL = "http://localhost:8001/api/alerts"


def _engine_key():
    """Clave X-API-Key del backend (entorno o fichero). Vacía = backend abierto."""
    for var in ("ENGINE_API_KEY", "IPS_API_KEY"):
        val = (os.environ.get(var) or "").strip()
        if val:
            return val
    candidatos = []
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        # El motor corre con sudo: ~ apunta a /root, la clave está en el home real
        candidatos.append(f"/home/{sudo_user}/cyberdefense/.engine_key")
    candidatos.append(os.path.expanduser("~/cyberdefense/.engine_key"))
    for ruta in candidatos:
        try:
            with open(ruta) as fh:
                val = fh.read().strip()
                if val:
                    return val
        except OSError:
            pass
    return ""


ENGINE_KEY = _engine_key()

# --- Topología real de la SDN levantada por VNX (datacenter_sdn.xml) ---
ATTACKER_IPS = {"192.168.1.50"}
SERVER_IPS = {"192.168.1.10", "192.168.1.11"}

_columnas_avisadas = set()


def orientar(ip_a, puerto_a, ip_b, puerto_b):
    """Devuelve (atacante_ip, victima_ip, puerto_victima) usando la topología."""
    if ip_a in ATTACKER_IPS:
        return ip_a, ip_b, puerto_b
    if ip_b in ATTACKER_IPS:
        return ip_b, ip_a, puerto_a
    if ip_a in SERVER_IPS and ip_b not in SERVER_IPS:
        return ip_b, ip_a, puerto_a
    if ip_b in SERVER_IPS and ip_a not in SERVER_IPS:
        return ip_a, ip_b, puerto_b
    return ip_a, ip_b, puerto_b


def notificar_ryu_bloqueo(ip_atacante):
    try:
        response = requests.post(RYU_API_URL, json={"ip": ip_atacante}, timeout=1)
        if response.status_code == 200:
            print(f"🛡️ [IPS] Mitigación exitosa: Controlador notificado para bloquear a {ip_atacante}")
    except requests.exceptions.RequestException as e:
        print(f"⚠️ [IPS] Error al notificar al controlador Ryu (¿Está encendido?): {e}")


def notificar_backend(clase, confianza, atacante, victima, puerto):
    try:
        payload = {
            "attack_type": clase,
            "confidence": float(confianza),
            "attacker_ip": atacante,
            "victim_ip": victima,
            "victim_port": int(puerto),
            "action_taken": "DROP"
        }
        headers = {"X-API-Key": ENGINE_KEY} if ENGINE_KEY else {}
        requests.post(BACKEND_API_URL, json=payload, headers=headers, timeout=2)
    except requests.exceptions.RequestException as e:
        print(f"⚠️ [BACKEND] Error al conectar con la API central: {e}")


# --- Estadística incremental O(1) por paquete (Welford: n, media, M2, min, max) ---

def _w_init():
    return [0, 0.0, 0.0, None, None]


def _w_add(w, x):
    n, mean, m2, mn, mx = w
    n += 1
    d = x - mean
    mean += d / n
    m2 += d * (x - mean)
    w[0], w[1], w[2] = n, mean, m2
    w[3] = x if mn is None or x < mn else mn
    w[4] = x if mx is None or x > mx else mx


def _w_mean(w):
    return w[1] if w[0] else 0.0


def _w_std(w):
    # Desviación poblacional (÷N), como CICFlowMeter/CIC-IDS2017.
    return math.sqrt(w[2] / w[0]) if w[0] > 0 else 0.0


def _w_var(w):
    return (w[2] / w[0]) if w[0] > 0 else 0.0


def _w_min(w):
    return w[3] if w[3] is not None else 0.0


def _w_max(w):
    return w[4] if w[4] is not None else 0.0


def nuevo_flujo(ts, size, dport, ip_src, ip_dst, sport, dst_port):
    return {
        'start_time': ts, 'last_time': ts, 'tot_pkts': 0, 'tot_bytes': 0,
        'fwd_pkts': 0, 'bwd_pkts': 0, 'fwd_bytes': 0, 'bwd_bytes': 0,
        'len_all': _w_init(), 'len_fwd': _w_init(), 'len_bwd': _w_init(),
        'iat_all': _w_init(), 'iat_fwd': _w_init(), 'iat_bwd': _w_init(),
        'first_fwd_ts': None, 'last_fwd_ts': None,
        'first_bwd_ts': None, 'last_bwd_ts': None,
        'syn': 0, 'ack': 0, 'rst': 0, 'psh': 0, 'fin': 0, 'urg': 0,
        'cwe': 0, 'ece': 0,
        'fwd_psh': 0, 'bwd_psh': 0, 'fwd_urg': 0, 'bwd_urg': 0,
        'fwd_hlen': 0, 'bwd_hlen': 0,
        'init_fwd_win': None, 'init_bwd_win': None,
        'act_data_fwd': 0, 'min_seg_fwd': None,
        'burst_start': ts, 'burst_w': _w_init(),
        'idle_w': _w_init(),
        'run_dir': 0, 'run_n': 0, 'run_pay': 0, 'run_data': 0, 'run_first': ts,
        'bulk_fwd': [0, 0, 0, 0.0], 'bulk_bwd': [0, 0, 0, 0.0],  # n, pay_bytes, pkts, ratesum(B/s)
        'dport': dport, 'src_ip': ip_src, 'dst_ip': ip_dst,
        'src_port': sport, 'dst_port': dst_port,
        'alertado': False,
    }


def _cerrar_bulk(f, direction):
    """Registra la racha abierta como bulk si califica (llamado al cambiar de dirección).
    CICFlowMeter cuenta BYTES de payload y tasa en bytes/s."""
    n = f['run_n']
    if n >= BULK_MIN_PKTS and f['run_data'] > 0:
        dur = max(f['last_time'] - f['run_first'], 1e-6)
        acc = f['bulk_fwd'] if direction > 0 else f['bulk_bwd']
        acc[0] += 1
        acc[1] += f['run_pay']
        acc[2] += n
        acc[3] += f['run_pay'] / dur


def registrar_paquete(f, ts, size, ip_hlen, hacia_adelante, flags, win, payload_len):
    """Actualiza el estado del flujo con un paquete. O(1), sin listas por paquete."""
    primero = (f['tot_pkts'] == 0)
    direccion = 1 if hacia_adelante else -1

    _w_add(f['len_all'], size)
    if hacia_adelante:
        _w_add(f['len_fwd'], size)
    else:
        _w_add(f['len_bwd'], size)

    if not primero:
        gap = ts - f['last_time']
        _w_add(f['iat_all'], gap)
        # active/idle: un gap > IDLE_GAP cierra el burst y abre periodo idle
        if gap > IDLE_GAP:
            _w_add(f['burst_w'], f['last_time'] - f['burst_start'])
            _w_add(f['idle_w'], gap)
            f['burst_start'] = ts
        if hacia_adelante and f['fwd_pkts'] > 0:
            _w_add(f['iat_fwd'], ts - f['last_fwd_ts'])
        if not hacia_adelante and f['bwd_pkts'] > 0:
            _w_add(f['iat_bwd'], ts - f['last_bwd_ts'])

    # rachas para bulk (al cambiar de dirección se cierra la anterior)
    if f['run_dir'] != 0 and f['run_dir'] != direccion:
        _cerrar_bulk(f, f['run_dir'])
        f['run_n'], f['run_pay'], f['run_data'] = 0, 0, 0
        f['run_first'] = ts
    if f['run_dir'] != direccion:
        f['run_dir'] = direccion
        f['run_first'] = ts
    f['run_n'] += 1
    f['run_pay'] += payload_len
    if payload_len > 0:
        f['run_data'] += 1

    if hacia_adelante:
        f['fwd_pkts'] += 1
        f['fwd_bytes'] += size
        # Header length CIC = cabecera IP (verificado contra CICFlowMeter: 20B/pkt
        # aunque el TCP lleve opciones). min_seg_size_forward = IP header mínimo.
        f['fwd_hlen'] += ip_hlen
        if f['min_seg_fwd'] is None or ip_hlen < f['min_seg_fwd']:
            f['min_seg_fwd'] = ip_hlen
        if f['first_fwd_ts'] is None:
            f['first_fwd_ts'] = ts
            f['init_fwd_win'] = win
        f['last_fwd_ts'] = ts
        if payload_len > 0:
            f['act_data_fwd'] += 1
        if flags:
            if 'P' in flags:
                f['psh'] += 1
                f['fwd_psh'] += 1
            if 'U' in flags:
                f['urg'] += 1
                f['fwd_urg'] += 1
    else:
        f['bwd_pkts'] += 1
        f['bwd_bytes'] += size
        f['bwd_hlen'] += ip_hlen
        if f['first_bwd_ts'] is None:
            f['first_bwd_ts'] = ts
            f['init_bwd_win'] = win
        f['last_bwd_ts'] = ts
        if flags:
            if 'P' in flags:
                f['psh'] += 1
                f['bwd_psh'] += 1
            if 'U' in flags:
                f['urg'] += 1
                f['bwd_urg'] += 1

    if flags:
        if 'S' in flags:
            f['syn'] += 1
        if 'A' in flags:
            f['ack'] += 1
        if 'R' in flags:
            f['rst'] += 1
        if 'F' in flags:
            f['fin'] += 1
        if 'C' in flags:
            f['cwe'] += 1
        if 'E' in flags:
            f['ece'] += 1

    f['last_time'] = ts
    f['tot_pkts'] += 1
    f['tot_bytes'] += size


def _bulk_stats(f, hacia_adelante, ahora):
    """(n, avg_bytes, avg_pkts, avg_rate) incluyendo la racha abierta si califica.
    Bytes = payload y tasa = bytes/s (verificado contra CICFlowMeter)."""
    acc = list(f['bulk_fwd'] if hacia_adelante else f['bulk_bwd'])
    if f['run_dir'] == (1 if hacia_adelante else -1) and f['run_n'] >= BULK_MIN_PKTS and f['run_data'] > 0:
        dur = max(ahora - f['run_first'], 1e-6)
        acc[0] += 1
        acc[1] += f['run_pay']
        acc[2] += f['run_n']
        acc[3] += f['run_pay'] / dur
    if acc[0] == 0:
        return 0, 0.0, 0.0, 0.0
    return acc[0], acc[1] / acc[0], acc[2] / acc[0], acc[3] / acc[0]


def _burst_stats(f):
    """(mean, std, max, min) de actividad incluyendo el burst abierto."""
    abierto = max(f['last_time'] - f['burst_start'], 0.0)
    w = list(f['burst_w'])
    n, mean, m2, mn, mx = w[0] + 1, 0.0, 0.0, None, None
    # combina bursts cerrados (media/M2) con el abierto como una muestra más
    # (aproximación paralela de varianza combinada)
    if w[0] > 0:
        tot = w[1] * w[0] + abierto
        mean = tot / n
        # varianza combinada (paralela) usando M2 de cerrados + muestra abierta
        m2 = w[2] + (abierto - w[1]) * (abierto - mean)
        mn = w[3] if w[3] is not None and w[3] < abierto else abierto
        mx = w[4] if w[4] is not None and w[4] > abierto else abierto
    else:
        mean, mn, mx = abierto, abierto, abierto
    std = math.sqrt(m2 / (n - 1)) if n > 1 else 0.0
    return mean, std, mx, mn


def extraer_vector(f):
    """Vector de features CIC-IDS2017 con los nombres exactos del modelo."""
    dur_s = f['last_time'] - f['start_time']
    if dur_s <= 0:
        dur_s = 1e-6
    tot = f['tot_pkts']
    fwd, bwd = f['fwd_pkts'], f['bwd_pkts']

    fwd_iat_tot = (f['last_fwd_ts'] - f['first_fwd_ts']) if fwd > 1 else 0.0
    bwd_iat_tot = (f['last_bwd_ts'] - f['first_bwd_ts']) if bwd > 1 else 0.0
    b_fwd_n, b_fwd_by, b_fwd_pk, b_fwd_ra = _bulk_stats(f, True, f['last_time'])
    b_bwd_n, b_bwd_by, b_bwd_pk, b_bwd_ra = _bulk_stats(f, False, f['last_time'])
    a_mean, a_std, a_max, a_min = _burst_stats(f)

    v = {
        'Destination_Port': float(f['dport']),
        'Flow_Duration': dur_s * 1e6,
        'Total_Fwd_Packets': float(fwd),
        'Total_Backward_Packets': float(bwd),
        'Total_Length_of_Fwd_Packets': float(f['fwd_bytes']),
        'Total_Length_of_Bwd_Packets': float(f['bwd_bytes']),
        'Fwd_Packet_Length_Max': _w_max(f['len_fwd']),
        'Fwd_Packet_Length_Min': _w_min(f['len_fwd']),
        'Fwd_Packet_Length_Mean': _w_mean(f['len_fwd']),
        'Fwd_Packet_Length_Std': _w_std(f['len_fwd']),
        'Bwd_Packet_Length_Max': _w_max(f['len_bwd']),
        'Bwd_Packet_Length_Min': _w_min(f['len_bwd']),
        'Bwd_Packet_Length_Mean': _w_mean(f['len_bwd']),
        'Bwd_Packet_Length_Std': _w_std(f['len_bwd']),
        'Flow_Bytes/s': f['tot_bytes'] / dur_s,
        'Flow_Packets/s': tot / dur_s,
        'Flow_IAT_Mean': _w_mean(f['iat_all']) * 1e6,
        'Flow_IAT_Std': _w_std(f['iat_all']) * 1e6,
        'Flow_IAT_Max': _w_max(f['iat_all']) * 1e6,
        'Flow_IAT_Min': _w_min(f['iat_all']) * 1e6,
        'Fwd_IAT_Total': fwd_iat_tot * 1e6,
        'Fwd_IAT_Mean': _w_mean(f['iat_fwd']) * 1e6,
        'Fwd_IAT_Std': _w_std(f['iat_fwd']) * 1e6,
        'Fwd_IAT_Max': _w_max(f['iat_fwd']) * 1e6,
        'Fwd_IAT_Min': _w_min(f['iat_fwd']) * 1e6,
        'Bwd_IAT_Total': bwd_iat_tot * 1e6,
        'Bwd_IAT_Mean': _w_mean(f['iat_bwd']) * 1e6,
        'Bwd_IAT_Std': _w_std(f['iat_bwd']) * 1e6,
        'Bwd_IAT_Max': _w_max(f['iat_bwd']) * 1e6,
        'Bwd_IAT_Min': _w_min(f['iat_bwd']) * 1e6,
        'Fwd_PSH_Flags': float(f['fwd_psh']),
        'Bwd_PSH_Flags': float(f['bwd_psh']),
        'Fwd_URG_Flags': float(f['fwd_urg']),
        'Bwd_URG_Flags': float(f['bwd_urg']),
        'Fwd_Header_Length': float(f['fwd_hlen']),
        'Bwd_Header_Length': float(f['bwd_hlen']),
        'Fwd_Packets/s': fwd / dur_s,
        'Bwd_Packets/s': bwd / dur_s,
        'Min_Packet_Length': _w_min(f['len_all']),
        'Max_Packet_Length': _w_max(f['len_all']),
        'Packet_Length_Mean': _w_mean(f['len_all']),
        'Packet_Length_Std': _w_std(f['len_all']),
        'Packet_Length_Variance': _w_var(f['len_all']),
        'FIN_Flag_Count': float(f['fin']),
        'SYN_Flag_Count': float(f['syn']),
        'RST_Flag_Count': float(f['rst']),
        'PSH_Flag_Count': float(f['psh']),
        'ACK_Flag_Count': float(f['ack']),
        'URG_Flag_Count': float(f['urg']),
        'CWE_Flag_Count': float(f['cwe']),
        'ECE_Flag_Count': float(f['ece']),
        'Down/Up_Ratio': (bwd / fwd) if fwd > 0 else 0.0,
        'Average_Packet_Size': (f['tot_bytes'] / tot) if tot > 0 else 0.0,
        'Avg_Fwd_Segment_Size': (f['fwd_bytes'] / fwd) if fwd > 0 else 0.0,
        'Avg_Bwd_Segment_Size': (f['bwd_bytes'] / bwd) if bwd > 0 else 0.0,
        'Fwd_Avg_Bytes/Bulk': b_fwd_by,
        'Fwd_Avg_Packets/Bulk': b_fwd_pk,
        'Fwd_Avg_Bulk_Rate': b_fwd_ra,
        'Bwd_Avg_Bytes/Bulk': b_bwd_by,
        'Bwd_Avg_Packets/Bulk': b_bwd_pk,
        'Bwd_Avg_Bulk_Rate': b_bwd_ra,
        'Subflow_Fwd_Packets': float(fwd),
        'Subflow_Fwd_Bytes': float(f['fwd_bytes']),
        'Subflow_Bwd_Packets': float(bwd),
        'Subflow_Bwd_Bytes': float(f['bwd_bytes']),
        'Init_Win_bytes_forward': float(f['init_fwd_win'] or 0),
        'Init_Win_bytes_backward': float(f['init_bwd_win'] or 0),
        'act_data_pkt_fwd': float(f['act_data_fwd']),
        'min_seg_size_forward': float(f['min_seg_fwd'] or 0),
        'Active_Mean': a_mean * 1e6,
        'Active_Std': a_std * 1e6,
        'Active_Max': a_max * 1e6,
        'Active_Min': a_min * 1e6,
        'Idle_Mean': _w_mean(f['idle_w']) * 1e6,
        'Idle_Std': _w_std(f['idle_w']) * 1e6,
        'Idle_Max': _w_max(f['idle_w']) * 1e6,
        'Idle_Min': _w_min(f['idle_w']) * 1e6,
    }
    return v


def vector_dataframe(f):
    """DataFrame con las columnas exactas y en el orden del modelo."""
    vec = extraer_vector(f)
    for c in features_cols:
        if c not in vec:
            vec[c] = 0.0
            if c not in _columnas_avisadas:
                _columnas_avisadas.add(c)
                print(f"⚠️ [IA] Feature del modelo sin extractor: {c} (se rellena con 0)")
    df = pd.DataFrame([vec])[features_cols]
    return df.fillna(0.0).replace([float('inf'), float('-inf')], 0.0)


def predecir(f):
    """Devuelve (clase, confianza_0_100). Ante error, BENIGN 0 (no alertar)."""
    try:
        df = vector_dataframe(f)
        preds = modelo.predict(df)[0]
        idx_max = int(preds.argmax())
        clase = str(encoder.inverse_transform([idx_max])[0])
        return clase, float(preds[idx_max] * 100.0)
    except Exception as e:
        print(f"⚠️ [IA] Error al predecir: {e}")
        return "BENIGN", 0.0


def decidir_por_modelo(clase, confianza, tot_pkts, puerto):
    """Política pura y testeable: etiqueta a alertar o None."""
    if clase == "BENIGN" or confianza < UMBRAL_CONFIANZA * 100.0:
        return None
    if tot_pkts == 2:
        if clase == "PortScan" and puerto not in PUERTOS_SCAN_EXCLUIDOS:
            return clase
        return None
    if tot_pkts in CHECKPOINTS_MODELO:
        return clase
    return None


def decidir_volumetrico(f):
    """Red volumétrica heurística: flood que el modelo viera como BENIGN."""
    dur = f['last_time'] - f['start_time']
    if dur <= 0:
        return None
    if f['tot_pkts'] >= VOL_MIN_PKTS and (f['tot_pkts'] / dur) >= VOL_MIN_PPS:
        return ("DDoS", 90.0)
    return None


def alertar_flujo(f, clase, confianza):
    atacante, victima, puerto = orientar(f['src_ip'], f['src_port'], f['dst_ip'], f['dst_port'])
    print(f"🚨 [ATAQUE CONFIRMADO] {clase} ({confianza:.1f}%) | Atacante: {atacante} -> {victima}:{puerto}")
    notificar_ryu_bloqueo(atacante)
    notificar_backend(clase, confianza, atacante, victima, puerto)
    f['alertado'] = True


def procesar_paquete(pkt):
    if ARP in pkt and pkt[ARP].op == 2:
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        if ip in tabla_arp and tabla_arp[ip] != mac:
            print(f"🚨 [ALERTA CRÍTICA L2] ¡ARP Spoofing! IP {ip} cambió de MAC")
            notificar_ryu_bloqueo(ip)
            notificar_backend("ARP_Spoofing", 99.9, ip, "N/A", 0)
        else:
            tabla_arp[ip] = mac
        return

    if IP not in pkt:
        return
    if TCP not in pkt and UDP not in pkt:
        return

    ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
    if ip_src.startswith("127.") or ip_dst.startswith("224.") or ip_dst == "255.255.255.255":
        return

    if not ip_src.startswith("192.168.1."):
        print(f"🚨 [ALERTA CRÍTICA L3] ¡IP Spoofing detectado! IP externa/falsa: {ip_src}")
        notificar_ryu_bloqueo(ip_src)
        notificar_backend("IP_Spoofing", 99.9, ip_src, ip_dst, 0)
        return

    size, ts = len(pkt[IP]), float(pkt.time)
    try:
        ip_hlen = int(pkt[IP].ihl or 5) * 4
    except Exception:
        ip_hlen = 20
    is_tcp = TCP in pkt
    if is_tcp:
        dport, sport = pkt[TCP].dport, pkt[TCP].sport
        flags = pkt[TCP].flags
        win = int(pkt[TCP].window)
        payload_len = len(pkt[TCP].payload)
    else:
        dport, sport = pkt[UDP].dport, pkt[UDP].sport
        flags, win = None, None
        payload_len = len(pkt[UDP].payload)

    flow_id = tuple(sorted([f"{ip_src}:{sport}", f"{ip_dst}:{dport}"]))

    if flow_id in flujos and (ts - flujos[flow_id]['last_time'] > 25.0):
        del flujos[flow_id]

    if flow_id not in flujos:
        flujos[flow_id] = nuevo_flujo(ts, size, dport, ip_src, ip_dst, sport, dport)

    f = flujos[flow_id]
    hacia_adelante = (ip_src == f['src_ip'])
    registrar_paquete(f, ts, size, ip_hlen, hacia_adelante, flags, win, payload_len)

    if f['alertado']:
        return

    # Heurística lenta: conexión HTTP gota a gota (Slowloris / Slowhttptest)
    duracion_flujo = ts - f['start_time']
    if f['dport'] in PUERTOS_HTTP_HEURISTICA and duracion_flujo > 5.0 and f['tot_pkts'] < 30:
        alertar_flujo(f, SLOW_LABEL, 99.9)
        return

    # Modelo 1.2M en checkpoints de paquetes
    if f['tot_pkts'] in (2,) + CHECKPOINTS_MODELO:
        clase, confianza = predecir(f)
        etiqueta = decidir_por_modelo(clase, confianza, f['tot_pkts'], f['dport'])
        if etiqueta is not None:
            alertar_flujo(f, etiqueta, confianza)
            return

    # Red volumétrica para floods sostenidos
    if f['tot_pkts'] >= VOL_MIN_PKTS and f['tot_pkts'] % 100 == 0:
        fb = decidir_volumetrico(f)
        if fb is not None:
            alertar_flujo(f, fb[0], fb[1])
            return


if __name__ == "__main__":
    print("🛡️ IPS SDN Activo Iniciado... Monitoreando, bloqueando y registrando.")
    sniff(iface="server1-e1", prn=procesar_paquete, store=False)
