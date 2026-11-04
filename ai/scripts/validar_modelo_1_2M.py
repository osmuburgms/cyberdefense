"""Validación del detector con el modelo configurado (sin red ni VNX).

Uso:
  cd ~/cyberdefense/ai && source iaenv/bin/activate
  python3 scripts/validar_modelo_1_2M.py                      # modelo RAM (defecto)
  IPS_MODEL=models/lightgbm_1_2M_final.txt \
  IPS_ENCODER=models/label_encoder_1_2M_final.pkl \
  python3 scripts/validar_modelo_1_2M.py                      # modelo 1.2M

Verifica:
  1. Cobertura total de las features del modelo (sin NaN/inf).
  2. Pipeline real (scapy -> procesar_paquete -> predecir) sobre 3 flujos
     sintéticos (informa la clase; no exige etiqueta: hay domain shift
     entre dataset y tráfico vivo y eso se calibra con el umbral).
  3. Política decidir_por_modelo / decidir_volumetrico (determinista).
  4. Extremo a extremo con predecir simulado: alerta, bloqueo Ryu y
     payload al backend con la topología correcta.
Sale con código 1 si algo falla.
"""
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import realtime_detector as rd
from scapy.all import IP, TCP, UDP, Raw

ATK, SRV = "192.168.1.50", "192.168.1.10"
fallos = []


def check(nombre, cond, detalle=""):
    print(f"  [{'OK' if cond else 'FAIL'}] {nombre}" + (f" — {detalle}" if detalle and not cond else ""))
    if not cond:
        fallos.append(nombre)


def tcp(ts, sport, dport, flags, payload=b"", win=29200):
    p = IP(src=ATK, dst=SRV) / TCP(sport=sport, dport=dport, flags=flags, window=win)
    if payload:
        p = p / Raw(load=payload)
    p.time = ts
    return p


def rta(ts, sport, dport, flags, payload=b""):
    """Respuesta del servidor (dirección inversa) para flujos bidireccionales."""
    p = IP(src=SRV, dst=ATK) / TCP(sport=sport, dport=dport, flags=flags, window=65535)
    if payload:
        p = p / Raw(load=payload)
    p.time = ts
    return p


def alimentar(pkts):
    for p in pkts:
        rd.procesar_paquete(p)


print("== 1. Cobertura de features ==")
NFEAT = len(rd.features_cols)
NONBENIGN = sorted(c for c in rd.CLASES if c != "BENIGN")[0]
print(f"   Modelo: {len(rd.CLASES)} clases | etiqueta no-benigna de prueba: {NONBENIGN}")
vec = rd.extraer_vector(rd.nuevo_flujo(0.0, 60, 80, ATK, SRV, 1111, 80))
faltan = [c for c in rd.features_cols if c not in vec]
check(f"{NFEAT}/{NFEAT} features presentes", len(rd.features_cols) >= 6 and not faltan,
      f"cols={len(rd.features_cols)} faltan={faltan}")
check("encoder con BENIGN + ataques", "BENIGN" in rd.CLASES and len(rd.CLASES) >= 2,
      str(sorted(rd.CLASES)))
df = rd.vector_dataframe(rd.nuevo_flujo(0.0, 60, 80, ATK, SRV, 1111, 80))
import pandas as pd
check(f"DataFrame 1x{NFEAT} sin NaN/inf", df.shape == (1, NFEAT) and bool((df.dtypes != object).all())
      and not df.isna().any().any()
      and not ((df == float("inf")) | (df == float("-inf"))).any().any())

print("== 2. Pipeline real sobre sintéticos (informativo) ==")
rd.notificar_ryu_bloqueo = lambda ip: None
rd.notificar_backend = lambda *a, **k: None

# PortScan: 2 SYN al puerto 3306
rd.flujos.clear(); rd.tabla_arp.clear()
alimentar([tcp(1000.0 + i * 0.002, 40000, 3306, "S") for i in range(2)])
f = list(rd.flujos.values())[0]
clase, conf = rd.predecir(f)
print(f"  scan-like -> {clase} ({conf:.1f}%)  tot={f['tot_pkts']} syn={f['syn']}")
check("vector finito en scan", all(math.isfinite(x) for x in rd.extraer_vector(f).values()))

# Hulk-like: SYN + 59 GET (PSH+ACK con payload), rápido
rd.flujos.clear()
pkts = [tcp(2000.0, 40001, 80, "S")]
pkts += [tcp(2000.05 + i * 0.001, 40001, 80, "PA", payload=b"GET /x HTTP/1.1\r\n" * 8) for i in range(59)]
alimentar(pkts)
f = list(rd.flujos.values())[0]
clase, conf = rd.predecir(f)
print(f"  hulk-like -> {clase} ({conf:.1f}%)  tot={f['tot_pkts']} psh={f['psh']}")
check("bulk fwd detectado en hulk", rd._bulk_stats(f, True, f['last_time'])[0] >= 1)

# Benigno: handshake + 4 datos + FIN/ACK ida y vuelta
rd.flujos.clear()
t, pkts = 3000.0, []
pkts.append(tcp(t, 40002, 443, "S")); pkts.append(rta(t + 0.01, 443, 40002, "SA"))
pkts.append(tcp(t + 0.02, 40002, 443, "A"))
for i in range(4):
    pkts.append(tcp(t + 0.05 + i * 0.05, 40002, 443, "PA", payload=b"datos" * 40))
    pkts.append(rta(t + 0.06 + i * 0.05, 443, 40002, "A"))
pkts.append(tcp(t + 0.5, 40002, 443, "FA")); pkts.append(rta(t + 0.51, 443, 40002, "A"))
alimentar(pkts)
f = list(rd.flujos.values())[0]
clase, conf = rd.predecir(f)
print(f"  benign-like -> {clase} ({conf:.1f}%)  tot={f['tot_pkts']} bwd={f['bwd_pkts']}")
check("win inicial fwd/bwd capturada", f['init_fwd_win'] == 29200 and f['init_bwd_win'] == 65535)

print("== 3. Política (determinista) ==")
D = rd.decidir_por_modelo
check("PortScan@2 puerto raro alerta", D("PortScan", 95.0, 2, 3306) == "PortScan")
check("PortScan@2 puerto común se suprime", D("PortScan", 95.0, 2, 443) is None)
check("otra clase@2 no alerta", D("DoS Hulk" if "DoS Hulk" in rd.CLASES else NONBENIGN, 99.0, 2, 80) is None)
check(f"{NONBENIGN}@15 alerta", D(NONBENIGN, 92.0, 15, 22) == NONBENIGN)
check("DDoS@30 alerta", D("DDoS", 88.0, 30, 80) == "DDoS")
check("BENIGN nunca alerta", D("BENIGN", 99.0, 60, 80) is None)
check("baja confianza no alerta", D(NONBENIGN, 40.0, 15, 8080) is None)
check("umbral 70.0 exacto sí alerta", D(NONBENIGN, 70.0, 15, 8080) == NONBENIGN)
check("69.9 no alerta", D(NONBENIGN, 69.9, 15, 8080) is None)
V = rd.decidir_volumetrico
check("flood 400pkts@3000pps -> DDoS",
      V({'start_time': 0.0, 'last_time': 0.133, 'tot_pkts': 400}) == ("DDoS", 90.0))
check("tráfico normal no dispara volumétrica",
      V({'start_time': 0.0, 'last_time': 10.0, 'tot_pkts': 50}) is None)

print("== 4. Extremo a extremo (predecir simulado) ==")
ryu, backend = [], []
rd.notificar_ryu_bloqueo = ryu.append
rd.notificar_backend = lambda c, cf, a, v, p: backend.append(
    {"attack_type": c, "confidence": cf, "attacker_ip": a,
     "victim_ip": v, "victim_port": p, "action_taken": "DROP"})
orig_predecir = rd.predecir
rd.predecir = lambda f: (NONBENIGN, 95.0)
try:
    rd.flujos.clear()
    alimentar([tcp(4000.0 + i * 0.01, 40003, 22, "PA", payload=b"ssh-intento" * 4) for i in range(15)])
finally:
    rd.predecir = orig_predecir
check("una sola alerta en 15 pkts", len(backend) == 1, f"alertas={len(backend)}")
if backend:
    b = backend[0]
    check("payload orientado (atk->srv:22/DROP)",
          b["attacker_ip"] == ATK and b["victim_ip"] == SRV
          and b["victim_port"] == 22 and b["action_taken"] == "DROP"
          and b["attack_type"] == NONBENIGN, str(b))
check("Ryu notificado con IP del atacante", ryu == [ATK], str(ryu))

print()
if fallos:
    print(f"❌ {len(fallos)} FALLOS: {fallos}")
    sys.exit(1)
print("✅ Validación 1.2M superada")
