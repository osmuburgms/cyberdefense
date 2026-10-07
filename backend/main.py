from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware  # <--- 1. Importar CORS
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.instruction import Instruction
from solana.transaction import Transaction
from solana.rpc.commitment import Confirmed, Finalized
from solana.rpc.types import TxOpts
import asyncio
import json
import os
from datetime import datetime, timezone

app = FastAPI(title="IPS Security Backend")

# --- 2. CONFIGURACIÓN DE CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite conexiones desde cualquier origen (ideal para desarrollo local)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIGURACIÓN MONGODB ---
MONGO_URL = "mongodb://127.0.0.1:27017/?directConnection=true"
mongo_client = AsyncIOMotorClient(MONGO_URL)
db = mongo_client.cyberdefense
alerts_collection = db.alerts
status_collection = db.system_status  # Estado persistente real del switch (no se infiere por tiempo)

# --- CONFIGURACIÓN SOLANA ---
SOLANA_URL = "http://localhost:8899"
solana_client = AsyncClient(SOLANA_URL)
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

with open(os.path.expanduser("~/.config/solana/id.json")) as f:
    secret = json.load(f)
payer = Keypair.from_bytes(bytes(secret))

class AlertModel(BaseModel):
    attack_type: str
    confidence: float
    attacker_ip: str
    victim_ip: str
    victim_port: int
    action_taken: str

def is_block_action(action_taken: str) -> bool:
    a = (action_taken or "").lower()
    return "drop" in a or "block" in a or "deny" in a

async def _confirmar_firma(signature, intentos: int = 40, espera: float = 0.75) -> bool:
    """True cuando la firma aparece confirmada/finalizada en el ledger.
    send_transaction puede volver antes de que la tx sea consultable; sin esto el
    explorer da Not Found. Tolera distintas formas de la respuesta según versión."""
    for intento in range(intentos):
        try:
            st = await solana_client.get_signature_statuses([signature])
            info = st.value[0] if st and getattr(st, "value", None) else None
            if info is not None:
                if getattr(info, "err", None) is not None:
                    print(f"⚠️ [BLOCKCHAIN] La transacción {signature} falló en el ledger: {info.err}")
                    return False
                status = getattr(info, "confirmation_status", None)
                status = str(status).lower() if status is not None else ""
                if "finalized" in status or "confirmed" in status or "processed" in status:
                    return True
                # Algunas versiones no rellenan confirmation_status pero sí slot
                if getattr(info, "slot", None):
                    return True
        except Exception as e:
            if intento == 0:
                print(f"⚠️ [BLOCKCHAIN] get_signature_statuses no disponible ({e}); usando confirm_transaction")
            # Fallback: confirm_transaction del cliente (bloquea hasta confirmar)
            try:
                await solana_client.confirm_transaction(signature, commitment=Confirmed)
                return True
            except Exception:
                pass
        await asyncio.sleep(espera)
    return False

async def registrar_en_solana(alert_data: dict):
    """Guarda un registro inmutable enriquecido del ataque en la blockchain de Solana.
    La firma se guarda EN CUANTO el validador la acepta; la confirmación se anota
    después. Así nunca se pierde una firma válida aunque la confirmación tarde."""
    signature = None
    print(f"🔗 [BLOCKCHAIN] Registrando ataque {alert_data.get('attack_type')} en Solana...")
    try:
        log_msg = f"AUDIT_IPS | Tipo: {alert_data['attack_type']} | Atacante: {alert_data['attacker_ip']} | Victima: {alert_data['victim_ip']}:{alert_data['victim_port']} | Confianza: {alert_data['confidence']:.1f}% | Accion: {alert_data['action_taken']} | Fecha: {alert_data['timestamp']}"
        memo_ix = Instruction(program_id=MEMO_PROGRAM_ID, accounts=[], data=log_msg.encode('utf-8'))

        # El validador puede tardar en aceptar conexiones (o reiniciarse). En lugar
        # de fallar a la primera con "Connection refused", reintentamos el envío
        # varias veces con espera creciente. Cada intento pide un blockhash fresco.
        ultimo_error = None
        for intento in range(1, 6):  # 5 intentos: ~1+2+3+4 = 10 s de margen
            try:
                resp = await solana_client.get_latest_blockhash()
                recent_blockhash = resp.value.blockhash

                txn = Transaction(recent_blockhash=recent_blockhash, fee_payer=payer.pubkey())
                txn.add(memo_ix)
                txn.sign(payer)

                try:
                    sig = await solana_client.send_transaction(txn, payer)
                except TypeError as te:
                    msg = str(te).lower()
                    es_error_de_firma = (
                        "positional argument" in msg
                        or ("argument" in msg and "send_transaction" in msg)
                        or "unexpected keyword" in msg
                    )
                    if not es_error_de_firma:
                        raise
                    sig = await solana_client.send_transaction(txn)

                signature = sig.value
                break  # envío correcto
            except Exception as e:
                ultimo_error = e
                nombre = type(e).__name__
                print(f"⚠️ [BLOCKCHAIN] Intento {intento}/5 falló ({nombre}). ¿Está el validador en localhost:8899? Reintentando...")
                await asyncio.sleep(intento)  # 1s, 2s, 3s, 4s

        if signature is None:
            # No se pudo enviar tras los reintentos: marcamos el estado y salimos
            raise ultimo_error if ultimo_error else RuntimeError("No se pudo enviar la transacción")

        # 1) Guardamos la firma inmediatamente con estado "pending"
        await alerts_collection.update_one(
            {"_id": alert_data["_id"]},
            {"$set": {"blockchain_signature": str(signature), "blockchain_status": "pending"}},
        )
        print(f"🔗 [BLOCKCHAIN] Transacción enviada. Firma: {signature} (confirmando...)")

        # 2) Confirmamos en segundo plano y actualizamos el estado
        confirmada = await _confirmar_firma(signature)
        nuevo_estado = "confirmed" if confirmada else "unconfirmed"
        await alerts_collection.update_one(
            {"_id": alert_data["_id"]},
            {"$set": {
                "blockchain_status": nuevo_estado,
                "blockchain_confirmed_at": datetime.now(timezone.utc).isoformat() if confirmada else None,
            }},
        )
        if confirmada:
            print(f"✅ [BLOCKCHAIN] Registro inmutable confirmado. Firma: {signature}")
        else:
            print(f"⚠️ [BLOCKCHAIN] Firma {signature} enviada pero no confirmada a tiempo (el explorer podría tardar).")
    except Exception as e:
        import traceback
        nombre = type(e).__name__
        detalle = str(e) or nombre
        if "SolanaRpcException" in nombre or "Connect" in nombre or "refused" in detalle.lower():
            detalle = "No hay conexión con el validador de Solana en localhost:8899. Comprueba que solana-test-validator esté corriendo (tail -40 ~/cyberdefense/logs/solana.log)."
        print(f"❌ [BLOCKCHAIN] Error al registrar en Solana: {detalle}")
        traceback.print_exc()
        if signature is None and alert_data.get("_id") is not None:
            await alerts_collection.update_one(
                {"_id": alert_data["_id"]},
                {"$set": {"blockchain_status": "error", "blockchain_error": detalle}},
            )

@app.post("/api/alerts")
async def receive_alert(alert: AlertModel, background_tasks: BackgroundTasks):
    alert_dict = alert.model_dump()
    alert_dict["timestamp"] = datetime.now(timezone.utc).isoformat()
    
    result = await alerts_collection.insert_one(alert_dict)
    alert_dict["_id"] = result.inserted_id
    print(f"💾 [MONGODB] Alerta guardada en base de datos local (ID: {result.inserted_id})")

    if is_block_action(alert_dict["action_taken"]):
        await status_collection.update_one(
            {"_id": "network"},
            {"$set": {"blocked": True, "updated_at": alert_dict["timestamp"], "reason": alert_dict["attack_type"]}},
            upsert=True,
        )

    background_tasks.add_task(registrar_en_solana, alert_dict)

    return {"status": "success", "message": "Alert received and processing"}

# --- 3. NUEVO ENDPOINT PARA EL FRONTEND ---
@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(20, ge=1, le=5000),
    skip: int = Query(0, ge=0),
):
    """Devuelve el historial de alertas desde MongoDB para el Dashboard.
    Sin parámetros se comporta igual que antes (últimas 20). El frontend usa
    `limit` para el botón "Ver más" y para cargar el histórico en el buscador."""
    alerts = []
    cursor = alerts_collection.find().sort("_id", -1).skip(skip).limit(limit)
    async for document in cursor:
        document["_id"] = str(document["_id"])  # Convertir ObjectId de Mongo a texto plano para JSON
        alerts.append(document)
    return alerts

@app.get("/api/alerts/count")
async def count_alerts():
    """Número total real de alertas registradas (no limitado a las últimas 20)"""
    total = await alerts_collection.count_documents({})
    blocked = await alerts_collection.count_documents(
        {"action_taken": {"$regex": "drop|block|deny", "$options": "i"}}
    )
    return {"total": total, "blocked": blocked}

@app.get("/api/health")
async def health():
    """Estado real de los servicios para el panel del dashboard."""
    mongo_ok = False
    try:
        await mongo_client.admin.command("ping")
        mongo_ok = True
    except Exception:
        mongo_ok = False

    solana_ok = False
    try:
        await solana_client.get_version()
        solana_ok = True
    except Exception:
        solana_ok = False

    return {"mongodb": mongo_ok, "solana": solana_ok}

@app.get("/api/blockchain/diag")
async def blockchain_diag():
    """Diagnóstico de Solana: envía una transacción de prueba y devuelve el error
    exacto si falla. Útil para saber por qué no se registran los ataques.
    Abre http://localhost:8001/api/blockchain/diag en el navegador."""
    import traceback
    resultado = {"payer": str(payer.pubkey())}
    try:
        v = await solana_client.get_version()
        resultado["rpc_ok"] = True
        resultado["solana_core"] = json.loads(v.to_json()).get("result", {}).get("solana-core")
    except Exception as e:
        resultado["rpc_ok"] = False
        resultado["rpc_error"] = str(e)
        return resultado

    try:
        bal = await solana_client.get_balance(payer.pubkey())
        resultado["balance_lamports"] = bal.value
        if bal.value == 0:
            resultado["aviso_balance"] = "El payer no tiene SOL. Ejecuta: solana airdrop 100 -u http://localhost:8899"
    except Exception as e:
        resultado["balance_error"] = str(e)

    try:
        memo_ix = Instruction(program_id=MEMO_PROGRAM_ID, accounts=[], data=b"DIAG_TEST")
        resp = await solana_client.get_latest_blockhash()
        txn = Transaction(recent_blockhash=resp.value.blockhash, fee_payer=payer.pubkey())
        txn.add(memo_ix)
        txn.sign(payer)
        try:
            sig = await solana_client.send_transaction(txn, payer)
        except TypeError:
            sig = await solana_client.send_transaction(txn)
        resultado["envio_ok"] = True
        resultado["firma"] = str(sig.value)
        confirmada = await _confirmar_firma(sig.value, intentos=20, espera=0.75)
        resultado["confirmada"] = confirmada
    except Exception as e:
        resultado["envio_ok"] = False
        resultado["envio_error"] = str(e)
        resultado["traceback"] = traceback.format_exc()
    return resultado

@app.get("/api/blockchain/tx/{signature}")
async def get_blockchain_tx(signature: str):
    """Consulta en Solana la transacción de auditoría asociada a una alerta"""
    try:
        sig = Signature.from_string(signature)
    except Exception:
        raise HTTPException(status_code=400, detail="Firma de transacción inválida")

    try:
        try:
            resp = await solana_client.get_transaction(
                sig, encoding="json", commitment=Finalized, max_supported_transaction_version=0
            )
        except TypeError:
            # versiones antiguas de solana-py sin max_supported_transaction_version
            resp = await solana_client.get_transaction(sig, encoding="json", commitment=Finalized)
        data = json.loads(resp.to_json()).get("result")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"No se pudo consultar Solana: {e}")

    if not data:
        # El test-validator recorta el historial anterior a su primer snapshot,
        # así que una firma vieja da Not Found aunque en su día se sellara.
        try:
            first = (await solana_client.minimum_ledger_slot()).value
        except Exception:
            first = None
        detalle = "Transacción no encontrada en el ledger local."
        if first:
            detalle += (
                f" El validador solo conserva transacciones desde el slot {first}; "
                "las anteriores se pierden al reiniciar solana-test-validator "
                "(cada './ips_manager.sh start' recrea el ledger). "
                "Genera un ataque nuevo para ver una transacción deshasheable."
            )
        raise HTTPException(status_code=404, detail=detalle)

    meta = data.get("meta") or {}
    message = (data.get("transaction") or {}).get("message") or {}
    account_keys = message.get("accountKeys") or []
    logs = meta.get("logMessages") or []

    memo = None
    for line in logs:
        if "Memo (len" in line and "): " in line:
            memo = line.split("): ", 1)[1].strip().strip('"')
            break

    return {
        "signature": signature,
        "slot": data.get("slot"),
        "block_time": data.get("blockTime"),
        "fee_lamports": meta.get("fee"),
        "status": "confirmed" if meta.get("err") is None else "failed",
        "error": meta.get("err"),
        "fee_payer": account_keys[0] if account_keys else None,
        "recent_blockhash": message.get("recentBlockhash"),
        "memo": memo,
        "logs": logs,
    }

# --- 4. ESTADO REAL DEL SWITCH (no inferido por tiempo) ---
@app.get("/api/switch-status")
async def get_switch_status():
    """Devuelve si el switch tiene actualmente una regla de bloqueo activa (estado real, persistente)"""
    doc = await status_collection.find_one({"_id": "network"})
    if not doc:
        return {"blocked": False, "updated_at": None, "reason": None}
    return {
        "blocked": doc.get("blocked", False),
        "updated_at": doc.get("updated_at"),
        "reason": doc.get("reason"),
    }

@app.post("/api/switch-status/clear")
async def clear_switch_status():
    """Llamado por ips_manager.sh cuando se ejecuta clean-switch: el bloqueo ya no existe de verdad"""
    await status_collection.update_one(
        {"_id": "network"},
        {"$set": {"blocked": False, "updated_at": datetime.now(timezone.utc).isoformat(), "reason": None}},
        upsert=True,
    )
    return {"status": "ok", "blocked": False}
