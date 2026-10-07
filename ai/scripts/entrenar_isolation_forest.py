import pandas as pd
import joblib
import os
from sklearn.ensemble import IsolationForest

archivo = "datasets/cicids2017_clean.csv"
if not os.path.exists(archivo):
    archivo = "datasets/experimentos/cicids2017_clean.csv"

print(f"Cargando tráfico normal desde: {archivo}...")
df = pd.read_csv(archivo)

# Filtrar solo BENIGN y eliminar Label
df_benign = df[df["Label"] == "BENIGN"].copy()
X_benign = df_benign.drop(columns=["Label"])

# Eliminar la columna duplicada original para igualar las 78 features de LightGBM
columnas_a_borrar = ["Fwd Header Length.1", " Fwd Header Length.1"]
X_benign = X_benign.drop(columns=[col for col in columnas_a_borrar if col in X_benign.columns], errors="ignore")

# Muestreo reproducible de 300,000 registros reales
n_muestras = min(300000, len(X_benign))
X_train_if = X_benign.sample(n=n_muestras, random_state=42)

print(f"Entrenando Isolation Forest con {n_muestras} registros BENIGN puros ({X_train_if.shape[1]} features)...")
print("Usando contamination='auto' y n_jobs=1")

model = IsolationForest(
    n_estimators=100, 
    contamination="auto", 
    random_state=42, 
    n_jobs=1
)
model.fit(X_train_if)

joblib.dump(model, "models/isolation_forest.pkl")
print("\n¡Modelo guardado exitosamente en models/isolation_forest.pkl!")
