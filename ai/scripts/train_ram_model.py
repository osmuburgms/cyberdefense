import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import lightgbm as lgb
import joblib
from pathlib import Path
from sklearn.metrics import classification_report
import warnings
warnings.filterwarnings('ignore')

print("🚀 Iniciando el entrenamiento del Modelo Ligero para RAM (SDN)...")

# 1. Ruta de tu dataset (Asegúrate de que apunte a tu CSV procesado de CIC-IDS-2017)
# Cambia esta ruta si tu archivo se llama diferente o está en otra ubicación
DATASET_PATH = Path(__file__).resolve().parent.parent / 'data' / 'dataset_limpio.csv'

# 2. Las 16 variables exactas que extrae tu script realtime_detector.py
features_ram = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Fwd Packets/s', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'SYN Flag Count', 'ACK Flag Count',
    'RST Flag Count'
]

print(f"📥 Cargando dataset desde: {DATASET_PATH}")
try:
    df = pd.read_csv(DATASET_PATH)
except FileNotFoundError:
    print(f"❌ ERROR: No se encontró el dataset en {DATASET_PATH}. Por favor, verifica la ruta.")
    exit()

# Limpiar nombres de columnas (eliminar espacios en blanco al inicio/final)
df.columns = df.columns.str.strip()

# Validar que las características existan en el dataset original
columnas_existentes = [col for col in features_ram if col in df.columns]
if len(columnas_existentes) < len(features_ram):
    faltantes = set(features_ram) - set(columnas_existentes)
    print(f"⚠️ Advertencia: Faltan las siguientes columnas en el dataset: {faltantes}")
    features_ram = columnas_existentes

# Extraer X (características) e y (etiquetas)
X = df[features_ram]
y = df['Label']

print("🧹 Limpiando datos (eliminando valores nulos o infinitos)...")
X = X.replace([np.inf, -np.inf], np.nan)
X = X.fillna(0)

print("🏷️ Codificando etiquetas de ataques...")
encoder = LabelEncoder()
y_encoded = encoder.fit_transform(y)

# Guardar el nuevo encoder
joblib.dump(encoder, 'models/label_encoder_ram_optimizado.pkl')
print(f"✅ Clases detectadas: {encoder.classes_}")

# División de datos (80% entrenamiento, 20% prueba)
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)

# Parámetros optimizados para LightGBM
params = {
    'objective': 'multiclass',
    'num_class': len(encoder.classes_),
    'metric': 'multi_logloss',
    'boosting_type': 'gbdt',
    'learning_rate': 0.05,
    'num_leaves': 31,
    'max_depth': -1,
    'feature_fraction': 0.8,
    'verbose': -1
}

print("🧠 Entrenando modelo LightGBM adaptado a la topología SDN...")
train_data = lgb.Dataset(X_train, label=y_train)
test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

modelo = lgb.train(
    params,
    train_data,
    num_boost_round=300,
    valid_sets=[test_data],
    callbacks=[lgb.early_stopping(stopping_rounds=20)]
)

print("\n📊 Evaluando precisión del modelo...")
y_pred = modelo.predict(X_test)
y_pred_classes = np.argmax(y_pred, axis=1)
print(classification_report(y_test, y_pred_classes, target_names=encoder.classes_))

# Guardar el modelo adaptado
modelo.save_model('models/lightgbm_ram_optimizado.txt')
print("💾 ¡Nuevo modelo guardado exitosamente en 'models/lightgbm_ram_optimizado.txt'!")
