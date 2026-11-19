import pandas as pd
import lightgbm as lgb
import joblib
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

archivo = "datasets/train_balanceado_barajado.csv"
print(f"Cargando dataset balanceado completo: {archivo}...")
df = pd.read_csv(archivo)
test = pd.read_csv("datasets/test.csv")

X_train = df.drop(columns=["Label"])
y_train_raw = df["Label"]
X_test = test.drop(columns=["Label"])
y_test_raw = test["Label"]

encoder = LabelEncoder()
encoder.fit(pd.concat([y_train_raw, y_test_raw]))
y_train = encoder.transform(y_train_raw)
y_test = encoder.transform(y_test_raw)

print("\nEntrenando LightGBM (1.2M) con hiperparámetros regularizados...")
model = lgb.LGBMClassifier(
    objective="multiclass",
    num_class=len(encoder.classes_),
    n_estimators=300,
    learning_rate=0.05,
    max_depth=12,
    num_leaves=128,
    min_child_samples=100,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=1,
    verbosity=-1
)
model.fit(X_train, y_train)

print("\nEvaluando modelo 1.2M tuneado...")
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"\nAccuracy Final = {acc:.6f}")

print("\nClassification Report Final:")
print(classification_report(y_test, y_pred, target_names=encoder.classes_, zero_division=0))

model.booster_.save_model("models/lightgbm_1_2M_final.txt")
joblib.dump(encoder, "models/label_encoder_1_2M_final.pkl")
print("\n¡Artefactos guardados con éxito en la carpeta models/!")
