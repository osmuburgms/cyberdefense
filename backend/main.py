from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends, Request
from fastapi.middleware.cors import CORSMiddleware  # <--- 1. Importar CORS
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId
from solana.rpc.async_api import AsyncClient
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.signature import Signature
from solders.instruction import Instruction
from solana.transaction import Transaction
from solana.rpc.commitment import Confirmed, Finalized
from solana.rpc.types import TxOpts
import asyncio
import bcrypt
import fcntl
import json
import jwt as pyjwt
import os
import pty
import re
import secrets
import signal
import struct
import termios
import uuid
from datetime import datetime, timezone, timedelta

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
users_collection = db.users           # Cuentas del dashboard (hash bcrypt, nunca en claro)
config_collection = db.system_config  # Parámetros globales que verán todos (los edita el admin)

# --- CONFIGURACIÓN SOLANA ---
SOLANA_URL = "http://localhost:8899"
solana_client = AsyncClient(SOLANA_URL)
MEMO_PROGRAM_ID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

with open(os.path.expanduser("~/.config/solana/id.json")) as f:
    secret = json.load(f)
payer = Keypair.from_bytes(bytes(secret))

# ---------------------------------------------------------------------------
# AUTENTICACIÓN Y ROLES (login del dashboard)
# ---------------------------------------------------------------------------
# Roles: "operator" (monitorea: ve todo, usa consola y limpieza) y "admin"
# (además: usuarios, parámetros globales y borrado de registros).
# - Contraseñas con bcrypt (coste 12). Jamás se guardan ni devuelven en claro.
# - Sesión con JWT Bearer (12 h). Sin estado en servidor (logout = el cliente
#   descarta el token).
# - El motor de IA no hace login: usa X-API-Key compartida (IPS_API_KEY o el
#   fichero ~/cyberdefense/.engine_key que genera ips_manager.sh). Si no hay
#   clave configurada, POST /api/alerts queda abierto (modo desarrollo).
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
JWT_EXP_HOURS = 12


def _load_jwt_secret() -> str:
    env = (os.environ.get("IPS_JWT_SECRET") or "").strip()
    if env:
        return env
    path = os.path.join(BACKEND_DIR, ".jwt_secret")
    try:
        with open(path) as fh:
            val = fh.read().strip()
            if val:
                return val
    except OSError:
        pass
    val = secrets.token_urlsafe(32)
    try:
        with open(path, "w") as fh:
            fh.write(val)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return val


JWT_SECRET = _load_jwt_secret()
JWT_ALG = "HS256"
bearer_scheme = HTTPBearer(auto_error=False)


def _load_engine_key() -> str:
    env = (os.environ.get("IPS_API_KEY") or "").strip()
    if env:
        return env
    try:
        with open(os.path.expanduser("~/cyberdefense/.engine_key")) as fh:
            return fh.read().strip()
    except OSError:
        return ""


ENGINE_API_KEY = _load_engine_key()
if ENGINE_API_KEY:
    print("   [auth] Clave de motor configurada: POST /api/alerts exige JWT o X-API-Key.")
else:
    print("   [auth] Sin IPS_API_KEY: POST /api/alerts queda abierto (modo desarrollo).")


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def check_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def make_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    return pyjwt.encode(
        {"sub": username, "role": role, "iat": now, "exp": now + timedelta(hours=JWT_EXP_HOURS)},
        JWT_SECRET,
        algorithm=JWT_ALG,
    )


def public_user(doc) -> dict:
    return {
        "username": doc["_id"],
        "role": doc.get("role", "operator"),
        "active": doc.get("active", True),
        "created_at": doc.get("created_at"),
        "created_by": doc.get("created_by"),
    }


async def user_from_token(token: str):
    """Devuelve el dict público del usuario o None si el token no vale."""
    try:
        payload = pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        return None
    username = payload.get("sub")
    if not username:
        return None
    try:
        doc = await users_collection.find_one({"_id": username})
    except Exception:
        return None
    if not doc or not doc.get("active", True):
        return None
    return public_user(doc)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    if not credentials or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise HTTPException(status_code=401, detail="Falta el token de sesión (inicia sesión)")
    user = await user_from_token(credentials.credentials)
    if not user:
        raise HTTPException(status_code=401, detail="Sesión inválida o caducada (inicia sesión de nuevo)")
    return user


async def require_admin(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo el administrador puede hacer esto")
    return user


async def engine_or_user(request: Request):
    """Para llamadas máquina-a-máquina (motor IA, ips_manager.sh): acepta JWT
    de usuario o X-API-Key del motor. Si no hay clave configurada, abierto."""
    if ENGINE_API_KEY:
        key = (request.headers.get("x-api-key") or "").strip()
        if key and secrets.compare_digest(key, ENGINE_API_KEY):
            return {"type": "engine"}
    auth = (request.headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        user = await user_from_token(auth[7:])
        if user:
            return {"type": "user", "user": user}
    if ENGINE_API_KEY:
        raise HTTPException(status_code=401, detail="Se requiere sesión o clave de motor")
    return {"type": "open"}


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,32}$")
VALID_ROLES = ("operator", "admin")


def _check_username(username: str):
    if not username or not USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="Usuario inválido (3-32 caracteres: letras, números, _ . -)")


def _check_password(password: str):
    if not password or len(password) < 4:
        raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 4 caracteres")
    if len(password) > 128:
        raise HTTPException(status_code=400, detail="La contraseña es demasiado larga")


async def _ensure_not_last_admin(except_username: str | None = None):
    q = {"role": "admin", "active": True}
    if except_username:
        q["_id"] = {"$ne": except_username}
    if await users_collection.count_documents(q) == 0:
        raise HTTPException(status_code=400, detail="No puedes dejar el sistema sin administradores activos")


class LoginModel(BaseModel):
    username: str
    password: str


class UserCreateModel(BaseModel):
    username: str
    password: str
    role: str = "operator"


class UserUpdateModel(BaseModel):
    role: str | None = None
    password: str | None = None
    active: bool | None = None


class PasswordChangeModel(BaseModel):
    current_password: str
    new_password: str


# Claves gestionadas globalmente por el admin (las ven todos los usuarios).
MANAGED_CONFIG_KEYS = ("pollInterval", "attackWindow", "timelineSize", "logSize", "widgets")


def _sanitize_config(data: dict) -> dict:
    out = {}
    if not isinstance(data, dict):
        return out
    def num(key, lo, hi):
        try:
            v = int(data.get(key))
        except (TypeError, ValueError):
            return
        out[key] = max(lo, min(hi, v))
    num("pollInterval", 500, 30000)
    num("attackWindow", 5, 120)
    num("timelineSize", 4, 30)
    num("logSize", 5, 100)
    widgets = data.get("widgets")
    if isinstance(widgets, dict):
        known = ("threat", "services", "topology", "timeline", "blockchain",
                 "aiPanel", "eventLog", "kpis", "attackTypes", "severity",
                 "topAttackers", "ports")
        out["widgets"] = {k: bool(v) for k, v in widgets.items() if k in known}
    return out


@app.post("/api/auth/login")
async def login(body: LoginModel):
    doc = await users_collection.find_one({"_id": (body.username or "").strip()})
    if not doc or not doc.get("active", True) or not check_password(body.password or "", doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Usuario o contraseña incorrectos")
    user = public_user(doc)
    return {"status": "ok", "token": make_token(user["username"], user["role"]), "user": user}


@app.get("/api/auth/me")
async def auth_me(user: dict = Depends(get_current_user)):
    return user


@app.post("/api/auth/change-password")
async def change_password(body: PasswordChangeModel, user: dict = Depends(get_current_user)):
    doc = await users_collection.find_one({"_id": user["username"]})
    if not doc or not check_password(body.current_password or "", doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Tu contraseña actual no es correcta")
    _check_password(body.new_password or "")
    await users_collection.update_one({"_id": user["username"]}, {"$set": {"password_hash": hash_password(body.new_password)}})
    return {"status": "ok"}


@app.get("/api/users")
async def list_users(_admin: dict = Depends(require_admin)):
    out = []
    async for doc in users_collection.find().sort("_id", 1):
        out.append(public_user(doc))
    return out


@app.post("/api/users")
async def create_user(body: UserCreateModel, admin: dict = Depends(require_admin)):
    username = (body.username or "").strip()
    _check_username(username)
    _check_password(body.password or "")
    if body.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail="Rol inválido (operator | admin)")
    if await users_collection.find_one({"_id": username}):
        raise HTTPException(status_code=409, detail="Ese usuario ya existe")
    await users_collection.insert_one({
        "_id": username,
        "password_hash": hash_password(body.password),
        "role": body.role,
        "active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": admin["username"],
    })
    return {"status": "ok", "user": {"username": username, "role": body.role}}


@app.patch("/api/users/{username}")
async def update_user(username: str, body: UserUpdateModel, admin: dict = Depends(require_admin)):
    doc = await users_collection.find_one({"_id": username})
    if not doc:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    patch = {}
    if body.role is not None:
        if body.role not in VALID_ROLES:
            raise HTTPException(status_code=400, detail="Rol inválido (operator | admin)")
        if username == admin["username"]:
            raise HTTPException(status_code=400, detail="No puedes cambiar tu propio rol")
        patch["role"] = body.role
    if body.active is not None:
        if username == admin["username"]:
            raise HTTPException(status_code=400, detail="No puedes desactivar tu propia cuenta")
        patch["active"] = bool(body.active)
    if body.password is not None:
        _check_password(body.password)
        patch["password_hash"] = hash_password(body.password)
    if not patch:
        raise HTTPException(status_code=400, detail="Nada que actualizar")
    if patch.get("role") == "operator" or patch.get("active") is False:
        await _ensure_not_last_admin(username)
    await users_collection.update_one({"_id": username}, {"$set": patch})
    updated = await users_collection.find_one({"_id": username})
    return {"status": "ok", "user": public_user(updated)}


@app.delete("/api/users/{username}")
async def delete_user(username: str, admin: dict = Depends(require_admin)):
    if username == admin["username"]:
        raise HTTPException(status_code=400, detail="No puedes eliminar tu propia cuenta")
    if not await users_collection.find_one({"_id": username}):
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    await _ensure_not_last_admin(username)
    await users_collection.delete_one({"_id": username})
    return {"status": "ok", "deleted": username}


@app.get("/api/config")
async def get_config(_user: dict = Depends(get_current_user)):
    doc = await config_collection.find_one({"_id": "global"})
    return doc.get("values", {}) if doc else {}


@app.put("/api/config")
async def put_config(body: dict, _admin: dict = Depends(require_admin)):
    values = _sanitize_config(body or {})
    if not values:
        raise HTTPException(status_code=400, detail="Sin parámetros válidos")
    await config_collection.update_one(
        {"_id": "global"},
        {"$set": {"values": values, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )
    doc = await config_collection.find_one({"_id": "global"})
    return {"status": "ok", "values": doc.get("values", {})}

class AlertModel(BaseModel):
    attack_type: str
    confidence: float
    attacker_ip: str
    victim_ip: str
    victim_port: int
    action_taken: str


class ExecRequest(BaseModel):
    host: str
    command: str
    session_id: str | None = None


class DeleteManyModel(BaseModel):
    ids: list[str]


def _to_object_id(value) -> ObjectId | None:
    try:
        return ObjectId(str(value))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# MINICONSOLA SDN: ejecución de comandos dentro de los contenedores VNX/LXC
# ---------------------------------------------------------------------------
# Equivalente backend de lo que el usuario haría a mano en su distro:
#   sudo lxc-attach -n attacker   (o server1 / server2)
#   sudo vnx -f ~/cyberdefense/datacenter_sdn.xml -M attacker --exe-cli "<cmd>"
# El frontend envía cada línea de la miniconsola a POST /api/hosts/exec y el
# backend la ejecuta dentro del contenedor con lxc-attach, devolviendo stdout.
ALLOWED_HOSTS = {
    "attacker": {
        "ip": "192.168.1.50",
        "label": "Attacker",
        "desc": "Nodo atacante (hydra, hping3, nmap, slowhttptest)",
        "vnx": "attacker",
    },
    "server1": {
        "ip": "192.168.1.10",
        "label": "server1",
        "desc": "Servidor víctima 1 (SDN_Net)",
        "vnx": "server1",
    },
    "server2": {
        "ip": "192.168.1.11",
        "label": "server2",
        "desc": "Servidor víctima 2 (SDN_Net)",
        "vnx": "server2",
    },
}

# Sesiones lógicas para mantener el `cwd` entre comandos (lxc-attach no
# mantiene estado: cada invocación es un proceso nuevo).
TERMINAL_SESSIONS: dict[str, dict] = {}
EXEC_TIMEOUT = 30          # segundos máx. por comando (hping3/nmap pueden tardar)
EXEC_MAX_OUTPUT = 20000    # recorte para no saturar el frontend
EXEC_MAX_CMD = 8000

# Comandos que se rechazan por seguridad del laboratorio (podrían tirar el
# escenario VNX o el host). Todo lo demás se permite para no limitar la demo
# (nmap, hydra, hping3, slowhttptest, ssh, curl, ping...).
BLOCKED_CMD_PATTERNS = [
    r"\breboot\b", r"\bpoweroff\b", r"\bshutdown\b", r"\bhalt\b",
    r"\bmkfs\b", r"dd\s+.*of=/dev/",
    r":\(\)\s*\{\s*:\|\:&\s*\}\s*;",  # fork-bomb
]


def _is_blocked_command(cmd: str) -> str | None:
    for pat in BLOCKED_CMD_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE):
            return pat
    return None


def _sanitize_cwd(cwd: str) -> str:
    if not cwd or not isinstance(cwd, str):
        return "/root"
    c = cwd.strip()
    if not c.startswith("/"):
        return "/root"
    # Normaliza /tmp/../etc -> /etc pero evita escapar con null bytes etc.
    c = os.path.normpath(c).replace("\x00", "")
    if not c.startswith("/"):
        return "/root"
    if len(c) > 256:
        return "/root"
    return c or "/"


def _quote_for_single(cwd: str) -> str:
    # Escapa para meter dentro de '...' en el bash del contenedor
    return cwd.replace("'", "'\"'\"'")


async def _run_in_lxc(host: str, cwd: str, command: str):
    """Ejecuta `command` dentro del contenedor LXC `host` partiendo de `cwd`.

    Devuelve (returncode, output_combinado). Usa `sudo -n` para fallar rápido
    con un mensaje claro si falta la regla NOPASSWD, en vez de quedarse
    esperando contraseña y colgar el backend.
    """
    cwd_q = _quote_for_single(_sanitize_cwd(cwd))
    # cd al cwd de la sesión; si falla (dir borrado) caemos a /root
    wrapped = f"cd '{cwd_q}' 2>/dev/null || cd /root; {command}"
    argv = [
        "sudo", "-n",
        "timeout", str(EXEC_TIMEOUT),
        "lxc-attach", "-n", host,
        "--", "/bin/bash", "-c", wrapped,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=EXEC_TIMEOUT + 5)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return 124, f"[timeout] El comando superó los {EXEC_TIMEOUT}s y fue interrumpido."
        text = (stdout or b"").decode("utf-8", errors="replace")
        if len(text) > EXEC_MAX_OUTPUT:
            text = text[:EXEC_MAX_OUTPUT] + f"\n[... salida recortada: {len(text)} caracteres en total ...]"
        return proc.returncode if proc.returncode is not None else 0, text
    except FileNotFoundError as e:
        return 127, f"[backend] Ejecutable no encontrado: {e}. ¿Está instalado lxc-attach/timeout en el host?"
    except Exception as e:
        return 1, f"[backend] Error al ejecutar en {host}: {e}"


def _sudo_hint(output: str) -> str:
    low = output.lower()
    if "a password is required" in low or "se requiere una contrase" in low or "no tty present" in low or "sudo: -n" in low:
        return (
            "\n[ayuda] El backend no tiene permiso sudo sin contraseña para lxc-attach.\n"
            "En la máquina anfitriona (tu distro) ejecuta una vez:\n"
            "  sudo visudo -f /etc/sudoers.d/cyberdefense\n"
            "y añade (cambia jose por tu usuario):\n"
            "  jose ALL=NOPASSWD: /usr/bin/lxc-attach, /usr/bin/timeout, /usr/bin/vnx\n"
            "Luego: ./ips_manager.sh restart-backend"
        )
    if "container" in low and ("not running" in low or "not exist" in low or "no existe" in low or "stopped" in low):
        return "\n[ayuda] El contenedor no está corriendo. Levanta la red con ./ips_manager.sh start"
    return ""

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
async def receive_alert(alert: AlertModel, background_tasks: BackgroundTasks, _auth=Depends(engine_or_user)):
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
    _user: dict = Depends(get_current_user),
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
async def count_alerts(_user: dict = Depends(get_current_user)):
    """Número total real de alertas registradas (no limitado a las últimas 20)"""
    total = await alerts_collection.count_documents({})
    blocked = await alerts_collection.count_documents(
        {"action_taken": {"$regex": "drop|block|deny", "$options": "i"}}
    )
    return {"total": total, "blocked": blocked}


# ---------------------------------------------------------------------------
# BORRADO DE REGISTROS (limpieza de pruebas desde el dashboard)
# ---------------------------------------------------------------------------
# Elimina documentos de MongoDB, que es la fuente de verdad del dashboard:
# lo borrado no vuelve a aparecer ni recargando ni re-levantando el sistema.
# NOTA sobre Solana: el ledger es INMUTABLE por diseño — una transacción ya
# sellada no se puede borrar (esa es justamente la garantía de auditoría de
# la tesis). Al borrar el documento de Mongo, su firma queda huérfana: el
# dashboard deja de mostrarla y de contarla. Para vaciar TAMBIÉN la cadena
# hay que resetear el validador de pruebas (borra TODO el historial):
#   solana-test-validator --reset  (o borrar ~/cyberdefense/test-ledger)
@app.delete("/api/alerts")
async def delete_all_alerts(_admin: dict = Depends(require_admin)):
    """Borra TODOS los registros de MongoDB (limpieza total de pruebas)."""
    res = await alerts_collection.delete_many({})
    return {"status": "ok", "deleted": res.deleted_count}


@app.post("/api/alerts/delete-many")
async def delete_many_alerts(body: DeleteManyModel, _admin: dict = Depends(require_admin)):
    """Borra varios registros por lista de IDs (selección múltiple del dashboard)."""
    oids = [o for o in (_to_object_id(i) for i in (body.ids or [])) if o is not None][:1000]
    if not oids:
        raise HTTPException(status_code=400, detail="Sin IDs válidos para borrar")
    res = await alerts_collection.delete_many({"_id": {"$in": oids}})
    return {"status": "ok", "deleted": res.deleted_count}


@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: str, _admin: dict = Depends(require_admin)):
    """Borra un registro por su ID de MongoDB."""
    oid = _to_object_id(alert_id)
    if not oid:
        raise HTTPException(status_code=400, detail="ID de registro inválido")
    res = await alerts_collection.delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Registro no encontrado")
    return {"status": "ok", "deleted": 1}

@app.get("/api/health")
async def health(_user: dict = Depends(get_current_user)):
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
async def blockchain_diag(_user: dict = Depends(get_current_user)):
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
async def get_blockchain_tx(signature: str, _user: dict = Depends(get_current_user)):
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
async def get_switch_status(_user: dict = Depends(get_current_user)):
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
async def clear_switch_status(_auth=Depends(engine_or_user)):
    """Llamado por ips_manager.sh cuando se ejecuta clean-switch: el bloqueo ya no existe de verdad"""
    await status_collection.update_one(
        {"_id": "network"},
        {"$set": {"blocked": False, "updated_at": datetime.now(timezone.utc).isoformat(), "reason": None}},
        upsert=True,
    )
    return {"status": "ok", "blocked": False}


# ---------------------------------------------------------------------------
# LIMPIEZA DEL SWITCH DESDE EL DASHBOARD (equivale a ./ips_manager.sh clean-switch)
# ---------------------------------------------------------------------------
# Secuencia del script: parar Ryu, borrar flujos OVS, reiniciar Ryu y limpiar
# el flag en Mongo. Sin parámetros del usuario (comandos fijos) para que sea
# seguro exponerlo. Requiere en el anfitrión (una sola vez):
#   jose ALL=NOPASSWD: /usr/bin/pkill -f ryu-manager, /usr/bin/ovs-ofctl -O OpenFlow13 del-flows SDN_Net
# El controlador se relanza como el propio usuario (igual que el script).
async def _run_step(*argv: str, timeout: float = 20.0):
    """Ejecuta un comando y devuelve (returncode, salida recortada)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return 124, f"[timeout] Superó los {timeout:.0f}s y fue interrumpido."
        text = (out or b"").decode("utf-8", errors="replace").strip()
        return (proc.returncode if proc.returncode is not None else 1), text[:2000]
    except FileNotFoundError as e:
        return 127, f"[backend] Ejecutable no encontrado: {e}"
    except Exception as e:
        return 1, f"[backend] Error al ejecutar {' '.join(argv[:3])}: {e}"


@app.post("/api/switch/clean")
async def clean_switch(_user: dict = Depends(get_current_user)):
    """Limpia bloqueos del switch y reinicia el controlador Ryu (clean-switch)."""
    steps = []
    home = os.path.expanduser("~")
    ryu_bin = os.path.join(home, "cyberdefense", "controller", "venv", "bin", "ryu-manager")
    ryu_script = os.path.join(home, "cyberdefense", "sdn", "ryu_ips_controller.py")
    ryu_log = os.path.join(home, "cyberdefense", "logs", "ryu.log")

    # 1. Detener el controlador (pkill devuelve 1 si ya estaba parado: también vale)
    rc, out = await _run_step("sudo", "-n", "pkill", "-f", "ryu-manager")
    await asyncio.sleep(1)
    steps.append({
        "name": "Detener controlador Ryu",
        "ok": rc in (0, 1),
        "detail": out or ("Ryu detenido" if rc == 0 else "Ryu ya estaba detenido"),
    })

    # 2. Borrar todos los flujos (incluidas las reglas DROP del IPS)
    rc, out = await _run_step("sudo", "-n", "ovs-ofctl", "-O", "OpenFlow13", "del-flows", "SDN_Net")
    detail = out or "Flujos borrados"
    if rc != 0:
        detail += (
            "\n[ayuda] Si dice 'a password is required', falta la regla NOPASSWD. "
            "Añade con 'sudo visudo -f /etc/sudoers.d/cyberdefense':\n"
            "  jose ALL=NOPASSWD: /usr/bin/pkill -f ryu-manager, "
            "/usr/bin/ovs-ofctl -O OpenFlow13 del-flows SDN_Net"
        )
    steps.append({"name": "Borrar flujos del switch", "ok": rc == 0, "detail": detail})
    flows_ok = rc == 0

    # 3. Reiniciar Ryu en segundo plano (como el propio usuario, igual que el script)
    ryu_ok, ryu_detail = False, ""
    if os.path.isfile(ryu_bin) and os.path.isfile(ryu_script):
        os.makedirs(os.path.dirname(ryu_log), exist_ok=True)
        import shlex as _shlex
        cmd = (
            f"nohup {_shlex.quote(ryu_bin)} {_shlex.quote(ryu_script)} "
            f"> {_shlex.quote(ryu_log)} 2>&1 &"
        )
        rc, out = await _run_step("bash", "-c", cmd)
        await asyncio.sleep(3)
        # El patrón con [r] evita que pgrep se encuentre a sí mismo en el "bash -c" envoltorio
        rc2, out2 = await _run_step("pgrep", "-f", "ryu_ips_controlle[r]")
        ryu_ok = rc2 == 0
        ryu_detail = "Ryu reiniciado y monitoreando" if ryu_ok else (
            f"No se pudo verificar Ryu en ejecución.{(' ' + out2) if out2 else ''} "
            f"Revisa {ryu_log}"
        )
    else:
        faltan = [p for p in (ryu_bin, ryu_script) if not os.path.isfile(p)]
        ryu_detail = f"No encontrado: {', '.join(faltan)}"
    steps.append({"name": "Reiniciar controlador Ryu", "ok": ryu_ok, "detail": ryu_detail})

    # 4. El flag de Mongo solo se limpia si el switch quedó limpio de verdad
    overall = all(s["ok"] for s in steps)
    if flows_ok:
        await status_collection.update_one(
            {"_id": "network"},
            {"$set": {"blocked": False, "updated_at": datetime.now(timezone.utc).isoformat(), "reason": None}},
            upsert=True,
        )
    steps.append({
        "name": "Limpiar estado del dashboard",
        "ok": flows_ok,
        "detail": "Estado marcado como no bloqueado" if flows_ok else "Se conserva el estado: el switch no se pudo limpiar",
    })
    overall = all(s["ok"] for s in steps)

    return {"status": "ok" if overall else "partial", "blocked": False if flows_ok else None, "steps": steps}


# --- 5. MINICONSOLA SDN: hosts y ejecución remota en VNX/LXC ---
@app.get("/api/hosts")
async def list_hosts(_user: dict = Depends(get_current_user)):
    """Hosts disponibles para la miniconsola del frontend (topología VNX)."""
    return [
        {"id": hid, "ip": info["ip"], "label": info["label"], "desc": info["desc"]}
        for hid, info in ALLOWED_HOSTS.items()
    ]


@app.get("/api/hosts/{host}/ping")
async def ping_host(host: str, _user: dict = Depends(get_current_user)):
    """Comprueba si el contenedor LXC está corriendo (para el punto verde/rojo)."""
    if host not in ALLOWED_HOSTS:
        raise HTTPException(status_code=404, detail=f"Host desconocido: {host}")
    try:
        proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", "lxc-info", "-n", host, "-s",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return {"host": host, "running": False, "detail": "timeout"}
        text = (out or b"").decode("utf-8", errors="replace")
        running = "RUNNING" in text.upper()
        return {"host": host, "running": running, "detail": text.strip()[:300]}
    except Exception as e:
        return {"host": host, "running": False, "detail": str(e)[:300]}


@app.post("/api/hosts/exec")
async def exec_in_host(req: ExecRequest, _user: dict = Depends(get_current_user)):
    """Ejecuta un comando dentro del contenedor VNX/LXC indicado.

    Equivale a: sudo lxc-attach -n <host> -- bash -c "<command>"
    El frontend mantiene `session_id` por pestaña para conservar el cwd.
    """
    host = (req.host or "").strip()
    if host not in ALLOWED_HOSTS:
        raise HTTPException(status_code=404, detail=f"Host desconocido: {host}. Usa: {sorted(ALLOWED_HOSTS)}")

    command = (req.command or "").strip("\n")
    if not command.strip():
        raise HTTPException(status_code=400, detail="Comando vacío")
    if len(command) > EXEC_MAX_CMD:
        raise HTTPException(status_code=413, detail=f"Comando demasiado largo (máx {EXEC_MAX_CMD} caracteres)")

    blocked = _is_blocked_command(command)
    if blocked:
        raise HTTPException(
            status_code=403,
            detail=f"Comando bloqueado por seguridad del laboratorio (patrón: {blocked}). "
                   "Evita reboot/poweroff/shutdown/mkfs/dd sobre /dev y fork-bombs.",
        )

    # Sesión lógica (cwd persistente por pestaña del frontend)
    sid = (req.session_id or "").strip()
    sess = TERMINAL_SESSIONS.get(sid) if sid else None
    if not sess or sess.get("host") != host:
        sid = uuid.uuid4().hex[:12]
        sess = {"host": host, "cwd": "/root"}
        TERMINAL_SESSIONS[sid] = sess
        # Limpieza oportunista para no crecer sin límite
        if len(TERMINAL_SESSIONS) > 200:
            for k in list(TERMINAL_SESSIONS.keys())[:-150]:
                TERMINAL_SESSIONS.pop(k, None)
    cwd = _sanitize_cwd(sess.get("cwd", "/root"))

    stripped = command.strip()
    # `cd` se resuelve actualizando el cwd de la sesión (y verificándolo dentro
    # del contenedor para dar el error real si el directorio no existe).
    if stripped == "cd" or stripped == "cd ~" or stripped == "cd ~/":
        sess["cwd"] = "/root"
        rc, out = await _run_in_lxc(host, "/root", "pwd")
        return {"host": host, "session_id": sid, "cwd": sess["cwd"], "returncode": rc, "output": out + _sudo_hint(out)}
    if stripped == "cd ..":
        sess["cwd"] = _sanitize_cwd(os.path.dirname(cwd.rstrip("/")) or "/")
        rc, out = await _run_in_lxc(host, sess["cwd"], "pwd")
        if rc == 0:
            sess["cwd"] = _sanitize_cwd(out.strip().splitlines()[-1] if out.strip() else sess["cwd"])
        return {"host": host, "session_id": sid, "cwd": sess["cwd"], "returncode": rc, "output": out + _sudo_hint(out)}
    if stripped.startswith("cd "):
        arg = stripped[3:].strip().strip("\"'") or "/root"
        if arg == "~":
            arg = "/root"
        target = arg if arg.startswith("/") else os.path.normpath(os.path.join(cwd, arg))
        target = _sanitize_cwd(target)
        rc, out = await _run_in_lxc(host, target, "pwd")
        if rc == 0 and out.strip():
            # pwd confirma la ruta real (resuelve .. y enlaces)
            last = out.strip().splitlines()[-1].strip()
            if last.startswith("/"):
                sess["cwd"] = _sanitize_cwd(last)
            else:
                sess["cwd"] = target
            return {"host": host, "session_id": sid, "cwd": sess["cwd"], "returncode": 0, "output": ""}
        return {"host": host, "session_id": sid, "cwd": cwd, "returncode": rc, "output": (out or f"bash: cd: {arg}: No existe el fichero o el directorio\n") + _sudo_hint(out or "")}

    rc, out = await _run_in_lxc(host, cwd, command)
    return {"host": host, "session_id": sid, "cwd": cwd, "returncode": rc, "output": out + _sudo_hint(out)}


# ---------------------------------------------------------------------------
# TERMINAL REAL POR WEBSOCKET (streaming interactivo hacia los contenedores)
# ---------------------------------------------------------------------------
# A diferencia de POST /api/hosts/exec (un comando = un proceso con timeout),
# aquí se mantiene un shell vivo por conexión:
#   frontend (xterm.js) <--WS--> backend <--PTY--> sudo lxc-attach -n <host> -- /bin/bash
# La salida llega en streaming (sin esperar a que termine el comando) y
# Ctrl+C funciona de verdad: xterm envía \x03, la disciplina de línea de la
# PTY lo convierte en SIGINT al grupo de procesos del contenedor.
# Se usa pty.fork() (no subprocess) para que el hijo tenga terminal de
# control real: sin eso no hay job-control ni ISIG dentro del contenedor.

WS_MAX_ROWS = 100
WS_MAX_COLS = 300


def _pty_set_winsize(fd: int, rows: int, cols: int) -> None:
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except OSError:
        pass


@app.websocket("/ws/terminal/{host}")
async def ws_terminal(ws: WebSocket, host: str):
    if host not in ALLOWED_HOSTS:
        await ws.close(code=4404)
        return
    # El navegador no envía cabeceras en WebSocket: el JWT va en ?token=
    if not await user_from_token(ws.query_params.get("token") or ""):
        await ws.close(code=4401)
        return
    await ws.accept()
    loop = asyncio.get_running_loop()

    try:
        pid, master_fd = pty.fork()
    except OSError:
        await ws.close(code=1011)
        return

    if pid == 0:
        # --- Proceso hijo: se convierte en lxc-attach dentro del contenedor.
        # pty.fork() ya lo dejó como líder de sesión con la PTY como terminal
        # de control, así que bash tiene job-control real.
        try:
            os.execvp("sudo", ["sudo", "-n", "lxc-attach", "-n", host, "--", "/bin/bash", "-l"])
        except Exception:
            try:
                os.write(1, b"\r\n[backend] No se pudo ejecutar sudo/lxc-attach\r\n")
            except OSError:
                pass
            os._exit(127)

    # --- Proceso padre (backend): puente WS <-> PTY.
    try:
        flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    except OSError:
        pass
    _pty_set_winsize(master_fd, 24, 80)

    finished = False

    def _cleanup() -> None:
        nonlocal finished
        if finished:
            return
        finished = True
        try:
            loop.remove_reader(master_fd)
        except Exception:
            pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass

    async def _finish() -> None:
        """El shell terminó (EOF en la PTY): avisa el exit-code y cierra."""
        exit_code = None
        try:
            ret = os.waitpid(pid, os.WNOHANG)
            if ret[0] == pid:
                status = ret[1]
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exit_code = 128 + os.WTERMSIG(status)
        except ChildProcessError:
            pass
        try:
            await ws.send_text(json.dumps({"t": "exit", "code": exit_code}))
        except Exception:
            pass
        try:
            await ws.close(code=1000)
        except Exception:
            pass
        _cleanup()

    def _on_pty_output() -> None:
        try:
            data = os.read(master_fd, 65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            # EIO: el esclavo se cerró = el shell terminó.
            loop.create_task(_finish())
            return
        if data:
            loop.create_task(ws.send_bytes(data))
        else:
            loop.create_task(_finish())

    loop.add_reader(master_fd, _on_pty_output)
    try:
        while True:
            try:
                msg = await ws.receive()
            except WebSocketDisconnect:
                break
            if msg.get("type") == "websocket.disconnect":
                break
            text = msg.get("text")
            if text is not None:
                try:
                    m = json.loads(text)
                except Exception:
                    continue
                kind = m.get("t")
                if kind == "in" and isinstance(m.get("d"), str):
                    try:
                        os.write(master_fd, m["d"].encode("utf-8", errors="replace"))
                    except OSError:
                        break
                elif kind == "resize":
                    try:
                        rows = max(5, min(WS_MAX_ROWS, int(m.get("rows", 24))))
                        cols = max(20, min(WS_MAX_COLS, int(m.get("cols", 80))))
                    except (TypeError, ValueError):
                        continue
                    _pty_set_winsize(master_fd, rows, cols)
                    try:
                        os.killpg(pid, signal.SIGWINCH)
                    except (ProcessLookupError, PermissionError, OSError):
                        pass
                # {"t":"ping"} se ignora (sin keepalive necesario en red local)
            elif msg.get("bytes") is not None:
                try:
                    os.write(master_fd, msg["bytes"])
                except OSError:
                    break
    finally:
        _cleanup()
