"""Isolation Forest sobre mismos CSV (anomalia vs normal).
Uso: python3 scripts/infer_if.py --csv /tmp/s.csv --train datasets/train_balanceado_barajado.csv
-1 = anomalia, 1 = normal
"""
import argparse, joblib, pandas as pd, numpy as np, os
from infer_lightgbm import CIC_MAP, load_expected_columns, clean_df

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--model", default="models/isolation_forest.pkl")
    ap.add_argument("--train", default="datasets/train_balanceado_barajado.csv")
    args = ap.parse_args()
    print(f"Cargando IF: {args.model}")
    clf = joblib.load(args.model)
    df = pd.read_csv(args.csv)
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns=CIC_MAP)
    expected = load_expected_columns(args.train)
    # IF se entreno con las columnas de cicids2017_clean (78 menos duplicada).
    # Intersectamos con lo que el modelo espera:
    n_feat = getattr(clf, "n_features_in_", None)
    print(f"Modelo espera {n_feat} features, CSV aporta {len(expected)}")
    for c in expected:
        if c not in df.columns:
            df[c] = 0
    X = clean_df(df[expected])
    if n_feat and X.shape[1] != n_feat:
        # recorta/alinea por si hay desfase de 1 columna duplicada historica
        print(f"WARN ajustando {X.shape[1]} -> {n_feat}")
        X = X.iloc[:, :n_feat]
    pred = clf.predict(X)  # 1 normal, -1 anomalo
    score = clf.decision_function(X)
    out = pd.DataFrame({"if_pred": pred, "score": score})
    print(out["if_pred"].value_counts().to_string())
    print(f"Anomalias: {(pred==-1).sum()}/{len(pred)} ({(pred==-1).mean()*100:.1f}%)")
    print(out.head(10).to_string())

if __name__ == "__main__":
    main()
