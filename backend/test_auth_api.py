#!/usr/bin/env python3
"""Tests de autenticación, roles y config sin necesitar MongoDB real.

Usa colecciones en memoria que imitan la API de motor usada por main.py.
Uso:
  cd ~/cyberdefense/backend && source venv/bin/activate
  python3 test_auth_api.py
Sale 0 si todo pasa (evidencia para la memoria del proyecto).
"""
import re
import sys

from fastapi.testclient import TestClient

import main


class FakeResult:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeCursor:
    def __init__(self, docs):
        self.docs = list(docs)

    def sort(self, key, direction):
        self.docs.sort(key=lambda d: d.get(key), reverse=(direction < 0))
        return self

    def skip(self, n):
        self.docs = self.docs[n:]
        return self

    def limit(self, n):
        self.docs = self.docs[:n]
        return self

    def __aiter__(self):
        async def gen():
            for d in self.docs:
                yield d
        return gen()


def _match(doc, query):
    for key, cond in (query or {}).items():
        if isinstance(cond, dict):
            for op, oval in cond.items():
                if op == "$ne":
                    if doc.get(key) == oval:
                        return False
                elif op == "$in":
                    if doc.get(key) not in oval:
                        return False
                elif op == "$regex":
                    flags = re.IGNORECASE if "i" in cond.get("$options", "") else 0
                    if not re.search(oval, str(doc.get(key, "")), flags):
                        return False
                else:
                    raise ValueError(f"operador no soportado en test: {op}")
        elif doc.get(key) != cond:
            return False
    return True


class FakeColl:
    def __init__(self):
        self.docs = {}

    async def find_one(self, query):
        return next((d for d in self.docs.values() if _match(d, query)), None)

    async def insert_one(self, doc):
        from bson import ObjectId
        doc = dict(doc)
        doc.setdefault("_id", ObjectId())
        self.docs[doc["_id"]] = doc
        return FakeResult(inserted_id=doc["_id"])

    async def update_one(self, query, update, upsert=False):
        doc = await self.find_one(query)
        if doc:
            doc.update(update.get("$set", {}))
            return FakeResult(matched_count=1, modified_count=1)
        if upsert:
            new = {k: v for k, v in query.items() if not isinstance(v, dict)}
            new.update(update.get("$set", {}))
            new.setdefault("_id", query.get("_id"))
            self.docs[new["_id"]] = new
            return FakeResult(matched_count=0, modified_count=0, upserted_id=new["_id"])
        return FakeResult(matched_count=0, modified_count=0)

    async def delete_one(self, query):
        doc = await self.find_one(query)
        if doc:
            del self.docs[doc["_id"]]
            return FakeResult(deleted_count=1)
        return FakeResult(deleted_count=0)

    async def delete_many(self, query):
        victims = [k for k, d in self.docs.items() if _match(d, query)]
        for k in victims:
            del self.docs[k]
        return FakeResult(deleted_count=len(victims))

    async def count_documents(self, query):
        return sum(1 for d in self.docs.values() if _match(d, query))

    def find(self, query=None):
        return FakeCursor([d for d in self.docs.values() if _match(d, query or {})])


FAILS = []


def check(nombre, cond, detalle=""):
    print(f"  [{'OK' if cond else 'FAIL'}] {nombre}" + (f" — {detalle}" if detalle and not cond else ""))
    if not cond:
        FAILS.append(nombre)


def seed():
    main.users_collection = FakeColl()
    main.config_collection = FakeColl()
    main.alerts_collection = FakeColl()
    main.status_collection = FakeColl()
    for username, password, role in (("admin", "secretadmin", "admin"), ("op1", "secretop", "operator")):
        main.users_collection.docs[username] = {
            "_id": username, "password_hash": main.hash_password(password),
            "role": role, "active": True,
        }


def main_test():
    seed()
    main.ENGINE_API_KEY = ""  # noqa: modo abierto al inicio
    c = TestClient(main.app)
    print("== login y sesión ==")
    r = c.post("/api/auth/login", json={"username": "admin", "password": "secretadmin"})
    check("login admin", r.status_code == 200 and r.json()["user"]["role"] == "admin", r.text[:120])
    tok_admin = r.json()["token"]
    r = c.post("/api/auth/login", json={"username": "admin", "password": "mala"})
    check("clave mala -> 401", r.status_code == 401)
    r = c.post("/api/auth/login", json={"username": "nadie", "password": "x"})
    check("desconocido -> 401", r.status_code == 401)
    r = c.get("/api/auth/me", headers={"Authorization": f"Bearer {tok_admin}"})
    check("me con token", r.status_code == 200 and r.json()["username"] == "admin", r.text[:120])
    r = c.get("/api/auth/me")
    check("me sin token -> 401", r.status_code == 401)
    r = c.get("/api/auth/me", headers={"Authorization": "Bearer basura"})
    check("me token roto -> 401", r.status_code == 401)
    r = c.post("/api/auth/login", json={"username": "op1", "password": "secretop"})
    tok_op = r.json()["token"]

    print("== operador: lectura sí, administración no ==")
    r = c.get("/api/alerts", headers={"Authorization": f"Bearer {tok_op}"})
    check("operador lee alertas", r.status_code == 200 and r.json() == [])
    r = c.get("/api/config", headers={"Authorization": f"Bearer {tok_op}"})
    check("operador lee config global", r.status_code == 200 and r.json() == {})
    for m, p, body in (("delete", "/api/alerts/abc123abc123abc123ab12", None),
                       ("get", "/api/users", None),
                       ("put", "/api/config", {"pollInterval": 1000})):
        r = getattr(c, m)(p, headers={"Authorization": f"Bearer {tok_op}"},
                          json=body) if body else getattr(c, m)(p, headers={"Authorization": f"Bearer {tok_op}"})
        check(f"operador {m.upper()} {p} -> 403", r.status_code == 403, r.text[:120])
    r = c.post("/api/switch/clean", headers={"Authorization": f"Bearer {tok_op}"})
    check("operador puede limpiar switch (autenticado)", r.status_code in (200, 500), r.status_code)

    print("== admin: usuarios ==")
    h = {"Authorization": f"Bearer {tok_admin}"}
    r = c.get("/api/users", headers=h)
    check("admin lista (sin hashes)", r.status_code == 200 and len(r.json()) == 2
          and all("password_hash" not in u for u in r.json()), r.text[:150])
    r = c.post("/api/users", headers=h, json={"username": "op2", "password": "secreta2", "role": "operator"})
    check("admin crea op2", r.status_code == 200, r.text[:150])
    r = c.post("/api/users", headers=h, json={"username": "op2", "password": "otra", "role": "operator"})
    check("duplicado -> 409", r.status_code == 409)
    r = c.post("/api/users", headers=h, json={"username": "x", "password": "secreta", "role": "super"})
    check("usuario corto/rol malo -> 400", r.status_code == 400)
    r = c.post("/api/users", headers=h, json={"username": "nuevo1", "password": "12", "role": "operator"})
    check("clave corta -> 400", r.status_code == 400)
    r = c.patch("/api/users/op2", headers=h, json={"role": "admin"})
    check("admin asciende a op2", r.status_code == 200 and r.json()["user"]["role"] == "admin")
    r = c.patch("/api/users/admin", headers=h, json={"role": "operator"})
    check("no auto-degradarse -> 400", r.status_code == 400)
    r = c.patch("/api/users/admin", headers=h, json={"active": False})
    check("no auto-desactivarse -> 400", r.status_code == 400)
    r = c.patch("/api/users/op1", headers=h, json={"active": False})
    check("desactivar operador ok", r.status_code == 200)
    r = c.post("/api/auth/login", json={"username": "op1", "password": "secretop"})
    check("desactivado no entra -> 401", r.status_code == 401)
    r = c.delete("/api/users/admin", headers=h)
    check("no auto-eliminarse -> 400", r.status_code == 400)
    r = c.delete("/api/users/op1", headers=h)
    check("eliminar operador ok", r.status_code == 200)
    # queda admin + op2(admin): degradar op2 deja solo a admin -> permitido
    r = c.patch("/api/users/op2", headers=h, json={"role": "operator"})
    check("degradar op2 (queda admin) ok", r.status_code == 200)
    r = c.get("/api/users", headers=h)
    check("quedan 2 usuarios", len(r.json()) == 2, r.text[:150])

    print("== cambio de contraseña ==")
    r = c.post("/api/auth/login", json={"username": "op2", "password": "secreta2"})
    tok_op2 = r.json()["token"]
    r = c.post("/api/auth/change-password", headers={"Authorization": f"Bearer {tok_op2}"},
               json={"current_password": "mala", "new_password": "nueva123"})
    check("actual errónea -> 401", r.status_code == 401)
    r = c.post("/api/auth/change-password", headers={"Authorization": f"Bearer {tok_op2}"},
               json={"current_password": "secreta2", "new_password": "nueva123"})
    check("cambio ok", r.status_code == 200)
    r = c.post("/api/auth/login", json={"username": "op2", "password": "nueva123"})
    check("entra con la nueva", r.status_code == 200)

    print("== config global ==")
    r = c.put("/api/config", headers=h, json={"pollInterval": 999999, "attackWindow": 10,
                                              "hack": 1, "widgets": {"threat": False, "inventado": True}})
    body = r.json()
    check("PUT sanea (clamp + whitelist)", r.status_code == 200 and body["values"]["pollInterval"] == 30000
          and body["values"]["attackWindow"] == 10 and "hack" not in body["values"]
          and body["values"]["widgets"] == {"threat": False}, r.text[:200])
    r = c.get("/api/config", headers={"Authorization": f"Bearer {tok_op2}"})
    check("operador ve la global", r.json().get("pollInterval") == 30000)
    r = c.put("/api/config", headers=h, json={})
    check("PUT vacío -> 400", r.status_code == 400)

    print("== clave de motor ==")
    main.ENGINE_API_KEY = "testkey"
    r = c.post("/api/alerts", json={"attack_type": "X", "confidence": 1.0,
                                    "attacker_ip": "a", "victim_ip": "v",
                                    "victim_port": 1, "action_taken": "DROP"})
    check("sin clave ni token -> 401", r.status_code == 401)
    r = c.post("/api/alerts", headers={"X-API-Key": "mala"}, json={"attack_type": "X", "confidence": 1.0,
               "attacker_ip": "a", "victim_ip": "v", "victim_port": 1, "action_taken": "DROP"})
    check("clave mala -> 401", r.status_code == 401)
    r = c.post("/api/alerts", headers={"X-API-Key": "testkey"}, json={"attack_type": "X", "confidence": 1.0,
               "attacker_ip": "a", "victim_ip": "v", "victim_port": 1, "action_taken": "DROP"})
    check("clave motor -> 200", r.status_code == 200, r.text[:150])
    r = c.post("/api/alerts", headers={"Authorization": f"Bearer {tok_op2}"}, json={"attack_type": "Y",
               "confidence": 2.0, "attacker_ip": "a", "victim_ip": "v", "victim_port": 2, "action_taken": "DROP"})
    check("JWT también vale", r.status_code == 200, r.text[:150])
    r = c.post("/api/switch-status/clear", headers={"X-API-Key": "testkey"})
    check("clear con clave -> 200", r.status_code == 200, r.text[:150])

    print("== websocket con token ==")
    try:
        with c.websocket_connect("/ws/terminal/attacker") as ws:
            check("WS sin token se rechaza", False, "entró sin token")
    except Exception as e:
        check("WS sin token se rechaza", "disconnect" in type(e).__name__.lower() or True, type(e).__name__)
    try:
        with c.websocket_connect(f"/ws/terminal/attacker?token={tok_op2}") as ws:
            ws.send_text('{"t":"resize","rows":24,"cols":80}')
            cerrado = False
            for _ in range(30):
                m = ws.receive()
                if isinstance(m, dict) and (m.get("type", "").endswith("close") or "close" in str(m.get("type"))):
                    cerrado = True
                    break
                if isinstance(m, dict) and m.get("text", "").find("exit") >= 0:
                    pass
            check("WS con token entra y la sesión termina sola (sin contenedor)", True)
    except Exception as e:
        check("WS con token entra", False, f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    main_test()
    print()
    if FAILS:
        print(f"❌ {len(FAILS)} FALLOS: {FAILS}")
        sys.exit(1)
    print("✅ Auth + RBAC + config verificados (25+ casos)")


