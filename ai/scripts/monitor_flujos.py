import pandas as pd
import joblib
import lightgbm as lgb
import time
import os
import warnings
warnings.filterwarnings('ignore')

print("Cargando Modelo y Diccionario de Clases...")
modelo = lgb.Booster(model_file='models/lightgbm_1_2M_final.txt')
encoder = joblib.load('models/label_encoder_1_2M_final.pkl')
features_cols = modelo.feature_name()

archivo_flujos = 'flujos_tiempo_real.csv'

def alinear_columnas(df_flujo):
    """Alinea los nombres de las columnas de CICFlowMeter con las esperadas por LightGBM"""
    # Mapeo básico: convierte a minúsculas y elimina espacios/guiones bajos
    mapeo = {c.lower().replace('_', '').replace(' ', ''): c for c in df_flujo.columns}
    vector = {col: 0.0 for col in features_cols}

    for col_esperada in features_cols:
        clave_busqueda = col_esperada.lower().replace('_', '').replace(' ', '')
        if clave_busqueda in mapeo:
            col_original = mapeo[clave_busqueda]
            # Extraer el valor. Manejar posibles valores no numéricos.
            valor = df_flujo[col_original].values[0]
            try:
                vector[col_esperada] = float(valor)
            except ValueError:
                pass # Si no se puede convertir a float, se queda en 0.0

    return pd.DataFrame([vector])[features_cols]

def analizar_ultimo_flujo():
    if not os.path.exists(archivo_flujos):
        return

    try:
        # Leer solo la última línea del CSV (el flujo más reciente)
        df_ultimo = pd.read_csv(archivo_flujos).tail(1)
        if df_ultimo.empty: return

        ip_src = df_ultimo['src_ip'].values[0]
        ip_dst = df_ultimo['dst_ip'].values[0]
        puerto = df_ultimo['dst_port'].values[0]

        # Evitar analizar tráfico interno de la máquina host
        if str(ip_src).startswith("127.") or str(ip_dst).startswith("224.") or ip_dst == "255.255.255.255":
            return

        df_features = alinear_columnas(df_ultimo)
        
        prediccion_num = modelo.predict(df_features).argmax()
        ataque_detectado = encoder.inverse_transform([prediccion_num])[0]

        # Obtener el nivel de confianza (opcional, para depuración)
        predicciones = modelo.predict(df_features)[0]
        confianza = predicciones[prediccion_num] * 100

        if ataque_detectado != "BENIGN":
            print(f"🚨 [ALERTA IA] ¡{ataque_detectado}! detectado | Atacante: {ip_src} -> Objetivo: {ip_dst}:{puerto} (Confianza: {confianza:.2f}%)")
        else:
             print(f"✅ [Normal] {ip_src} -> {ip_dst}:{puerto} | IA dice: BENIGN (Confianza: {confianza:.2f}%)")

    except Exception as e:
        pass # Ignorar errores de lectura si el archivo está siendo escrito en ese instante

print("Iniciando motor de detección en tiempo real...")
print(f"Vigilando el archivo de flujos: {archivo_flujos}")

# Monitoreo continuo (polling)
ultima_modificacion = 0
while True:
    if os.path.exists(archivo_flujos):
        modificacion_actual = os.path.getmtime(archivo_flujos)
        if modificacion_actual != ultima_modificacion:
            analizar_ultimo_flujo()
            ultima_modificacion = modificacion_actual
    time.sleep(1) # Revisar cada segundo
