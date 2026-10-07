import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import confusion_matrix

print("Cargando modelo y creando conjunto de validación (150k registros)...")
model = joblib.load("models/isolation_forest.pkl")

# Extraer muestra de validación usando una semilla diferente (99)
df_val = pd.read_csv("datasets/cicids2017_2018_limpio.csv").sample(n=150000, random_state=99)

X_val = df_val.drop(columns=["Label"], errors="ignore")

# Asegurar que no esté la columna duplicada para que coincidan las 77 features
columnas_a_borrar = ["Fwd Header Length.1", " Fwd Header Length.1"]
X_val = X_val.drop(columns=[col for col in columnas_a_borrar if col in X_val.columns], errors="ignore")

y_true = df_val["Label"].apply(lambda x: 1 if x == "BENIGN" else -1)

print("Calculando scores de anomalía (decision_function)...")
scores = model.decision_function(X_val)

# Evaluar percentiles desde el 5% hasta el 40%
percentiles = [5, 10, 15, 20, 25, 30, 35, 40]
umbrales = np.percentile(scores, percentiles)

print("\n=== EVALUACIÓN DE UMBRALES ===")
print(f"{'Percentil':<10} | {'Umbral':<10} | {'Falsos Positivos (BENIGN->IA)':<33} | {'Recall Ataques (Capturados)'}")
print("-" * 95)

for perc, umbral in zip(percentiles, umbrales):
    # Todo lo por debajo del umbral es considerado anomalía (-1)
    y_pred = np.where(scores < umbral, -1, 1)
    cm = confusion_matrix(y_true, y_pred, labels=[1, -1])
    
    fp = cm[0][1]
    tn = cm[0][0]
    fn = cm[1][0]
    tp = cm[1][1]
    
    tasa_fp = (fp / (fp + tn)) * 100 if (fp + tn) > 0 else 0
    recall = (tp / (tp + fn)) * 100 if (tp + fn) > 0 else 0
    
    print(f"{perc:>8}% | {umbral:>10.4f} | {fp:>6} ({tasa_fp:>6.2f}%) enviados a LGBM | {tp:>6} ({recall:>6.2f}%) detectados")
