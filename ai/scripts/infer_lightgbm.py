"""Inferencia LightGBM 1.2M sobre flujos CIC-IDS.

Uso:
  cd ~/cyberdefense/ai && source iaenv/bin/activate
  python3 scripts/infer_lightgbm.py --csv /tmp/flujos.csv
  python3 scripts/infer_lightgbm.py --csv /tmp/flujos.csv --train datasets/train_balanceado_barajado.csv
"""
import argparse
import joblib
import lightgbm as lgb
import pandas as pd
import numpy as np
import os


# Mapeo cicflowmeter (snake_case) -> nombres entrenamiento CIC-IDS2017
CIC_MAP = {
    "dst_port": "Destination Port",
    "flow_duration": "Flow Duration",
    "tot_fwd_pkts": "Total Fwd Packets",
    "tot_bwd_pkts": "Total Backward Packets",
    "totlen_fwd_pkts": "Total Length of Fwd Packets",
    "totlen_bwd_pkts": "Total Length of Bwd Packets",
    "fwd_pkt_len_max": "Fwd Packet Length Max",
    "fwd_pkt_len_min": "Fwd Packet Length Min",
    "fwd_pkt_len_mean": "Fwd Packet Length Mean",
    "fwd_pkt_len_std": "Fwd Packet Length Std",
    "bwd_pkt_len_max": "Bwd Packet Length Max",
    "bwd_pkt_len_min": "Bwd Packet Length Min",
    "bwd_pkt_len_mean": "Bwd Packet Length Mean",
    "bwd_pkt_len_std": "Bwd Packet Length Std",
    "flow_byts_s": "Flow Bytes/s",
    "flow_pkts_s": "Flow Packets/s",
    "flow_iat_mean": "Flow IAT Mean",
    "flow_iat_std": "Flow IAT Std",
    "flow_iat_max": "Flow IAT Max",
    "flow_iat_min": "Flow IAT Min",
    "fwd_iat_tot": "Fwd IAT Total",
    "fwd_iat_mean": "Fwd IAT Mean",
    "fwd_iat_std": "Fwd IAT Std",
    "fwd_iat_max": "Fwd IAT Max",
    "fwd_iat_min": "Fwd IAT Min",
    "bwd_iat_tot": "Bwd IAT Total",
    "bwd_iat_mean": "Bwd IAT Mean",
    "bwd_iat_std": "Bwd IAT Std",
    "bwd_iat_max": "Bwd IAT Max",
    "bwd_iat_min": "Bwd IAT Min",
    "fwd_psh_flags": "Fwd PSH Flags",
    "bwd_psh_flags": "Bwd PSH Flags",
    "fwd_urg_flags": "Fwd URG Flags",
    "bwd_urg_flags": "Bwd URG Flags",
    "fwd_header_len": "Fwd Header Length",
    "bwd_header_len": "Bwd Header Length",
    "fwd_pkts_s": "Fwd Packets/s",
    "bwd_pkts_s": "Bwd Packets/s",
    "pkt_len_min": "Min Packet Length",
    "pkt_len_max": "Max Packet Length",
    "pkt_len_mean": "Packet Length Mean",
    "pkt_len_std": "Packet Length Std",
    "pkt_len_var": "Packet Length Variance",
    "fin_flag_cnt": "FIN Flag Count",
    "syn_flag_cnt": "SYN Flag Count",
    "rst_flag_cnt": "RST Flag Count",
    "psh_flag_cnt": "PSH Flag Count",
    "ack_flag_cnt": "ACK Flag Count",
    "urg_flag_cnt": "URG Flag Count",
    "cwr_flag_count": "CWE Flag Count",
    "ece_flag_cnt": "ECE Flag Count",
    "down_up_ratio": "Down/Up Ratio",
    "pkt_size_avg": "Average Packet Size",
    "fwd_seg_size_avg": "Avg Fwd Segment Size",
    "bwd_seg_size_avg": "Avg Bwd Segment Size",
    "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
    "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
    "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
    "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
    "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
    "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
    "subflow_fwd_pkts": "Subflow Fwd Packets",
    "subflow_fwd_byts": "Subflow Fwd Bytes",
    "subflow_bwd_pkts": "Subflow Bwd Packets",
    "subflow_bwd_byts": "Subflow Bwd Bytes",
    "init_fwd_win_byts": "Init_Win_bytes_forward",
    "init_bwd_win_byts": "Init_Win_bytes_backward",
    "fwd_act_data_pkts": "act_data_pkt_fwd",
    "fwd_seg_size_min": "min_seg_size_forward",
    "active_mean": "Active Mean",
    "active_std": "Active Std",
    "active_max": "Active Max",
    "active_min": "Active Min",
    "idle_mean": "Idle Mean",
    "idle_std": "Idle Std",
    "idle_max": "Idle Max",
    "idle_min": "Idle Min",
}


def load_expected_columns(train_path):
    if train_path and os.path.exists(train_path):
        cols = pd.read_csv(train_path, nrows=0).columns.tolist()
        if "Label" in cols:
            cols.remove("Label")
        return cols
    return None


def clean_df(df):
    df = df.replace([np.inf, -np.inf], np.nan)
    # CIC suele dejar NaN en Flow Bytes/s, etc. Rellenamos con 0 para demo
    # (en entrenamiento se usó limpieza similar)
    df = df.fillna(0)
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="CSV de flujos (salida de cicflowmeter)")
    ap.add_argument("--model", default="models/lightgbm_1_2M_final.txt")
    ap.add_argument("--encoder", default="models/label_encoder_1_2M_final.pkl")
    ap.add_argument("--train", default="datasets/train_balanceado_barajado.csv")
    ap.add_argument("--threshold", type=float, default=0.7)
    ap.add_argument("--out", default="")
    args = ap.parse_args()

    print(f"Cargando modelo: {args.model}")
    bst = lgb.Booster(model_file=args.model)
    enc = joblib.load(args.encoder)
    print(f"Clases: {list(enc.classes_)}")

    df = pd.read_csv(args.csv)
    # quita columnas extra típicas de cicflowmeter
    for c in ["Flow ID", "Src IP", "Src Port", "Dst IP", "Dst Port",
              "Protocol", "Timestamp", "Label"]:
        if c in df.columns and c != "Label":
            # guardamos Label real si existe para comparar
            pass
    y_true = df["Label"] if "Label" in df.columns else None
    # cicflowmeter en minúsculas? normaliza espacios
    df.columns = [c.strip() for c in df.columns]
    # renombra snake_case -> formato entrenamiento
    df = df.rename(columns=CIC_MAP)

    expected = load_expected_columns(args.train)
    if expected:
        # alinea: agrega faltantes con 0, tira sobrantes, reordena
        for c in expected:
            if c not in df.columns:
                print(f"WARN falta columna {c}, relleno con 0")
                df[c] = 0
        extra = [c for c in df.columns if c not in expected and c != "Label"]
        if extra:
            print(f"INFO columnas extra ignoradas: {extra[:5]}...")
        X = df[expected]
    else:
        X = df.drop(columns=["Label"], errors="ignore")

    X = clean_df(X)
    print(f"Flujos a predecir: {X.shape[0]} x {X.shape[1]}")

    proba = bst.predict(X)
    # Booster multiclass devuelve (n, n_clases)
    if len(proba.shape) == 1:
        proba = proba.reshape(-1, len(enc.classes_))
    idx = np.argmax(proba, axis=1)
    conf = np.max(proba, axis=1)
    pred = enc.inverse_transform(idx)
    # umbral: baja confianza -> Desconocido
    pred_final = [p if c >= args.threshold else f"{p} (baja_conf {c:.2f})"
                  for p, c in zip(pred, conf)]

    out = pd.DataFrame({"pred": pred, "pred_final": pred_final, "conf": conf})
    if y_true is not None:
        out["real"] = y_true.values
    print(out["pred"].value_counts().to_string())
    print(out.head(20).to_string())

    if args.out:
        out.to_csv(args.out, index=False)
        print(f"Guardado en {args.out}")


if __name__ == "__main__":
    main()
