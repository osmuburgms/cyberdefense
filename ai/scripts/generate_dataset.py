import pandas as pd
import numpy as np
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent / 'data'
BASE_DIR.mkdir(parents=True, exist_ok=True)
path = BASE_DIR / 'dataset_limpio.csv'

def generate_class(name, n, ports, dur_range, pkts_range, syn, ack, rst, bytes_multiplier):
    df = pd.DataFrame()
    df['Destination Port'] = np.random.choice(ports, n)
    df['Flow Duration'] = np.random.uniform(dur_range[0], dur_range[1], n)
    df['Total Fwd Packets'] = np.random.randint(pkts_range[0], pkts_range[1], n)
    df['Total Backward Packets'] = np.random.randint(pkts_range[0], pkts_range[1], n)
    df['Init_Win_bytes_forward'] = np.random.choice([29200, 65535, 8192], n)
    df['Init_Win_bytes_backward'] = np.random.choice([29200, 65535, 8192], n)
    df['SYN Flag Count'] = np.random.randint(syn[0], syn[1]+1, n)
    df['ACK Flag Count'] = np.random.randint(ack[0], ack[1]+1, n)
    df['RST Flag Count'] = np.random.randint(rst[0], rst[1]+1, n)
    
    df['Fwd Packets/s'] = df['Total Fwd Packets'] / (df['Flow Duration']/1e6)
    total_pkts = df['Total Fwd Packets'] + df['Total Backward Packets']
    df['Flow Packets/s'] = total_pkts / (df['Flow Duration']/1e6)
    df['Flow Bytes/s'] = df['Flow Packets/s'] * np.random.uniform(bytes_multiplier[0], bytes_multiplier[1], n)
    
    df['Flow IAT Mean'] = df['Flow Duration'] / total_pkts
    df['Flow IAT Max'] = df['Flow IAT Mean'] * np.random.uniform(1.1, 2.0, n)
    df['Flow IAT Min'] = df['Flow IAT Mean'] * np.random.uniform(0.1, 0.9, n)
    df['Flow IAT Std'] = df['Flow IAT Mean'] * np.random.uniform(0.1, 0.5, n)
    df['Label'] = name
    return df

print("Generando dataset extendido (BENIGN, DoS, PortScan, BruteForce, UDP_Flood, Slowloris)...")

df_benign = generate_class('BENIGN', 15000, [80, 443, 53, 22, 8080], [50000, 500000], [5, 25], [0,1], [1,5], [0,1], [100, 1500])
df_dos = generate_class('DoS', 8000, [80, 443, 8080], [1000, 20000], [5, 25], [0,2], [0,2], [0,1], [50, 100])
df_scan = generate_class('PortScan', 5000, list(range(1, 65000)), [100, 5000], [2, 6], [1,3], [0,1], [0,1], [40, 60])
df_brute = generate_class('BruteForce', 5000, [80, 21, 22], [100000, 800000], [5, 25], [0,1], [2,8], [0,0], [200, 500])

# Nuevas clases de ataques avanzados
df_udp = generate_class('UDP_Flood', 5000, [53, 123, 5000], [500, 10000], [20, 50], [0,0], [0,0], [0,0], [20, 50])
df_slow = generate_class('Slowloris', 5000, [80, 443], [2000000, 10000000], [2, 10], [0,1], [1,3], [0,0], [10, 30])

dataset = pd.concat([df_benign, df_dos, df_scan, df_brute, df_udp, df_slow], ignore_index=True)
dataset.to_csv(path, index=False)
print(f"✅ Dataset extendido guardado en: {path}")
