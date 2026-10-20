#!/usr/bin/env python3
"""Alta inicial de usuarios del dashboard (operadores + admin).

- Las contraseñas se piden POR TECLADO (getpass) y solo se guarda el hash
  bcrypt en MongoDB. Nada en claro en disco, ni en el repo, ni en el historial.
- Idempotente: si el usuario ya existe, pregunta si se resetea su contraseña
  y sincroniza el rol.
- Uso:
    cd ~/cyberdefense/backend && source venv/bin/activate
    python3 crear_usuarios_iniciales.py
  Cuentas iniciales sugeridas:
    osmuburg / nfazu  -> operator  (monitorean red y ataques)
    admin             -> admin      (todo + usuarios, parámetros y borrado)
"""
import asyncio
import getpass
import sys
from datetime import datetime, timezone

try:
    import bcrypt
    from motor.motor_asyncio import AsyncIOMotorClient
except ImportError as e:
    print(f"Falta dependencia: {e} (activa el venv del backend)")
    sys.exit(1)

MONGO_URL = "mongodb://127.0.0.1:27017/?directConnection=true"
CUENTAS = [
    ("osmuburg", "operator"),
    ("nfazu", "operator"),
    ("admin", "admin"),
]


def pedir_password(username: str) -> str:
    while True:
        p1 = getpass.getpass(f"Contraseña para '{username}': ")
        if len(p1) < 4:
            print("  Mínimo 4 caracteres.")
            continue
        p2 = getpass.getpass(f"Repite la contraseña para '{username}': ")
        if p1 != p2:
            print("  No coinciden, intenta de nuevo.")
            continue
        return p1


async def main() -> int:
    try:
        client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000)
        await client.admin.command("ping")
    except Exception as e:
        print(f"No hay conexión con MongoDB en 127.0.0.1:27017 ({e}).")
        print("Levanta MongoDB primero: sudo docker start mongodb-cyberdefense")
        return 1

    users = client.cyberdefense.users
    for username, role in CUENTAS:
        doc = await users.find_one({"_id": username})
        if doc:
            print(f"- '{username}' ya existe (rol: {doc.get('role')}).")
            if input("  ¿Resetear contraseña? [s/N]: ").strip().lower() != "s":
                if doc.get("role") != role or not doc.get("active", True):
                    await users.update_one(
                        {"_id": username}, {"$set": {"role": role, "active": True}}
                    )
                    print(f"  Rol sincronizado a '{role}' y cuenta activada.")
                continue
        password = pedir_password(username)
        digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
        await users.update_one(
            {"_id": username},
            {"$set": {
                "password_hash": digest,
                "role": role,
                "active": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "created_by": "seed",
            }},
            upsert=True,
        )
        print(f"  '{username}' guardado con rol '{role}' (hash bcrypt, nada en claro).")

    print("Listo. Entra en el frontend con cualquiera de las tres cuentas.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
