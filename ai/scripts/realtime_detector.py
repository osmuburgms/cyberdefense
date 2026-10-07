import pandas as pd
import math
import joblib
import requests
import lightgbm as lgb
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import warnings
warnings.filterwarnings('ignore')

print("Cargando Motor de IA Híbrido con Mitigación Activa (IPS) y Conexión Backend...")
modelo = lgb.Booster(model_file='/home/nfazu/cyberdefense/ai/models/lightgbm_ram_optimizado.txt')
encoder = joblib.load('/home/nfazu/cyberdefense/ai/models/label_encoder_ram_optimizado.pkl')
features_cols = modelo.feature_name()

flujos = {}
tabla_arp = {}
RYU_API_URL = "http://localhost:8080/ips/block"
BACKEND_API_URL = "http://localhost:8001/api/alerts"

# --- Topología real de la SDN levantada por VNX (datacenter_sdn.xml) ---
# Fijar quién es atacante y quién víctima evita que la orientación del flujo
# dependa del orden alfabético de "ip:puerto" (que hacía que en un DoS el
# servidor apareciera como origen). El atacante conocido siempre se reporta
# como origen; los servidores, siempre como víctima.
ATTACKER_IPS = {"192.168.1.50"}
SERVER_IPS = {"192.168.1.10", "192.168.1.11"}

def orientar(ip_a, puerto_a, ip_b, puerto_b):
    """Devuelve (atacante_ip, victima_ip, puerto_victima) usando la topología.
    puerto_a/puerto_b son los puertos asociados a ip_a/ip_b respectivamente."""
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
    except Exception as e:
        print(f"⚠️ [IPS] Error al notificar al controlador Ryu: {e}")

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
        requests.post(BACKEND_API_URL, json=payload, timeout=2)
    except Exception as e:
        print(f"⚠️ [BACKEND] Error al conectar con la API central: {e}")

def mapear_variables(f):
    vector = {col: 0.0 for col in features_cols}
    duracion_micro = (f['last_time'] - f['start_time']) * 1e6
    if duracion_micro <= 0: duracion_micro = 1.0 
    
    pkts_s = f['tot_pkts'] / (duracion_micro / 1e6)
    byts_s = f['tot_bytes'] / (duracion_micro / 1e6)
    
    if len(f['iats']) > 0:
        iat_mean = sum(f['iats']) / len(f['iats'])
        iat_max = max(f['iats'])
        iat_min = min(f['iats'])
        iat_std = math.sqrt(sum((x - iat_mean)**2 for x in f['iats']) / len(f['iats']))
    else:
        iat_mean = iat_max = iat_min = iat_std = 1.0
        
    for c in features_cols:
        col_limpia = c.replace(" ", "").lower()
        if 'destinationport' in col_limpia: vector[c] = f['dport']
        elif 'flowduration' in col_limpia: vector[c] = duracion_micro
        elif 'totalfwdpackets' in col_limpia: vector[c] = f['fwd_pkts']
        elif 'totalbackwardpackets' in col_limpia: vector[c] = f['bwd_pkts']
        elif 'fwdpackets/s' in col_limpia: vector[c] = f['fwd_pkts'] / (duracion_micro / 1e6)
        elif 'flowbytes/s' in col_limpia: vector[c] = byts_s
        elif 'flowpackets/s' in col_limpia: vector[c] = pkts_s
        elif 'flowiatmean' in col_limpia: vector[c] = iat_mean
        elif 'flowiatstd' in col_limpia: vector[c] = iat_std
        elif 'flowiatmax' in col_limpia: vector[c] = iat_max
        elif 'flowiatmin' in col_limpia: vector[c] = iat_min
        elif 'forward' in col_limpia and 'win' in col_limpia: vector[c] = f['fwd_win']
        elif 'backward' in col_limpia and 'win' in col_limpia: vector[c] = f['bwd_win']
        elif 'syn' in col_limpia: vector[c] = f['syn']
        elif 'ack' in col_limpia: vector[c] = f['ack']
        elif 'rst' in col_limpia: vector[c] = f['rst']
            
    return pd.DataFrame([vector])[features_cols]

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
        
    if IP not in pkt: return
    if TCP not in pkt and UDP not in pkt: return
    
    ip_src, ip_dst = pkt[IP].src, pkt[IP].dst
    if ip_src.startswith("127.") or ip_dst.startswith("224.") or ip_dst == "255.255.255.255": return
    
    if not ip_src.startswith("192.168.1."):
        print(f"🚨 [ALERTA CRÍTICA L3] ¡IP Spoofing detectado! IP externa/falsa: {ip_src}")
        notificar_ryu_bloqueo(ip_src)
        notificar_backend("IP_Spoofing", 99.9, ip_src, ip_dst, 0)
        return
        
    size, ts = len(pkt[IP]), float(pkt.time)
    is_tcp = TCP in pkt
    dport = pkt[TCP].dport if is_tcp else pkt[UDP].dport
    sport = pkt[TCP].sport if is_tcp else pkt[UDP].sport
    
    flow_id = tuple(sorted([f"{ip_src}:{sport}", f"{ip_dst}:{dport}"]))
    
    if flow_id in flujos and (ts - flujos[flow_id]['last_time'] > 25.0):
        del flujos[flow_id]
    
    if flow_id not in flujos:
        flujos[flow_id] = {
            'start_time': ts, 'last_time': ts, 'tot_pkts': 0, 'tot_bytes': 0,
            'fwd_pkts': 0, 'bwd_pkts': 0, 'iats': [], 'syn': 0, 'ack': 0, 'rst': 0, 
            'dport': dport, 'src_ip': ip_src, 'dst_ip': ip_dst,
            'src_port': sport, 'dst_port': dport, 'fwd_win': 0, 'bwd_win': 0,
            'alertado': False
        }
        
    f = flujos[flow_id]
    if f['tot_pkts'] > 0: f['iats'].append((ts - f['last_time']) * 1e6)
    f['last_time'] = ts
    f['tot_pkts'] += 1
    f['tot_bytes'] += size
    
    if ip_src == f['src_ip']:
        f['fwd_pkts'] += 1
        if is_tcp: f['fwd_win'] = pkt[TCP].window
    else:
        f['bwd_pkts'] += 1
        if is_tcp: f['bwd_win'] = pkt[TCP].window
            
    if is_tcp:
        flags = pkt[TCP].flags
        if 'S' in flags: f['syn'] += 1
        if 'A' in flags: f['ack'] += 1
        if 'R' in flags: f['rst'] += 1
            
    duracion_flujo = ts - f['start_time']
    if not f['alertado'] and f['dport'] == 80 and duracion_flujo > 5.0 and f['tot_pkts'] < 30:
        atacante, victima, puerto = orientar(f['src_ip'], f['src_port'], f['dst_ip'], f['dst_port'])
        print(f"🚨 [ATAQUE CONFIRMADO] Slowloris | Atacante: {atacante} -> {victima}:{puerto}")
        notificar_ryu_bloqueo(atacante)
        notificar_backend("Slowloris", 99.9, atacante, victima, puerto)
        f['alertado'] = True
        return

    if not f['alertado'] and f['tot_pkts'] in [2, 15, 50]:
        duracion = f['last_time'] - f['start_time']
        if duracion <= 0: duracion = 0.000001
        pps = f['tot_pkts'] / duracion

        df = mapear_variables(f)
        preds = modelo.predict(df)[0]
        idx_max = preds.argmax()
        clase = encoder.inverse_transform([idx_max])[0]
        confianza = preds[idx_max] * 100
        
        atacante, victima, puerto = orientar(f['src_ip'], f['src_port'], f['dst_ip'], f['dst_port'])

        if f['tot_pkts'] == 50:
            nombre_ataque = "UDP_Flood" if UDP in pkt else "DoS"
            print(f"🚨 [ATAQUE CONFIRMADO] {nombre_ataque} ({confianza:.1f}%) | Atacante: {atacante} -> {victima}:{puerto}")
            notificar_ryu_bloqueo(atacante)
            notificar_backend(nombre_ataque, confianza, atacante, victima, puerto)
            f['alertado'] = True
        elif f['tot_pkts'] == 15 and pps < 2000 and clase in ["BruteForce", "Slowloris"]:
            print(f"🚨 [ATAQUE CONFIRMADO] {clase} ({confianza:.1f}%) | Atacante: {atacante} -> {victima}:{puerto}")
            notificar_ryu_bloqueo(atacante)
            notificar_backend(clase, confianza, atacante, victima, puerto)
            f['alertado'] = True
        elif f['tot_pkts'] == 2 and clase == "PortScan":
            if puerto not in [21, 22, 80, 443, 53]:
                print(f"🚨 [ATAQUE CONFIRMADO] PortScan ({confianza:.1f}%) | Atacante: {atacante} -> {victima}:{puerto}")
                notificar_ryu_bloqueo(atacante)
                notificar_backend("PortScan", confianza, atacante, victima, puerto)
                f['alertado'] = True

print("🛡️ IPS SDN Activo Iniciado... Monitoreando, bloqueando y registrando en Blockchain.")
sniff(iface="server1-e1", prn=procesar_paquete, store=False)
