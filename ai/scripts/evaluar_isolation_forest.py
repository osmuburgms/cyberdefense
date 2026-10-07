import pandas as pd
import joblib
from sklearn.metrics import classification_report, confusion_matrix

print("Cargando test.csv y modelo Isolation Forest...")
test = pd.read_csv("datasets/test.csv")
model = joblib.load("models/isolation_forest.pkl")

X_test = test.drop(columns=["Label"])
y_test_raw = test["Label"]

# Mapeo estricto: 1 = Normal (Clase Negativa), -1 = Anomalía/Ataque (Clase Positiva)
y_true = y_test_raw.apply(lambda x: 1 if x == "BENIGN" else -1)

print("\nEjecutando inferencia de anomalías...")
y_pred = model.predict(X_test)

print("\n=== MATRIZ DE CONFUSIÓN ===")
# labels=[1, -1] -> [Normal (Negativo), Anomalía (Positivo)]
cm = confusion_matrix(y_true, y_pred, labels=[1, -1])
print(f"Verdaderos Negativos (BENIGN detectado como Normal)   : {cm[0][0]}")
print(f"Falsos Positivos     (BENIGN detectado como Anomalía) : {cm[0][1]}")
print(f"Falsos Negativos     (Ataque detectado como Normal)   : {cm[1][0]}")
print(f"Verdaderos Positivos (Ataque detectado como Anomalía) : {cm[1][1]}")

print("\n=== REPORTE DE CLASIFICACIÓN ===")
print("Nota: 1 = Normal (BENIGN), -1 = Anomalía (Ataque)")
print(classification_report(y_true, y_pred, digits=4))
