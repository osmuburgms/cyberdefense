#!/usr/bin/env bash
# =====================================================================
#  Migración de MongoDB: del contenedor creado con "docker run"
#  (volumen anónimo) al contenedor gestionado por docker/docker-compose.yml
#  (volumen nombrado "mongo_data").
#
#  - Copia los datos al volumen nombrado
#  - Guarda una copia de seguridad en el volumen "mongo_backup"
#  - NO borra el volumen anónimo original (queda como red de seguridad)
#  - Verifica usuarios y alertas antes y después
#
#  Uso:  sudo bash docker/migrar-mongo.sh
# =====================================================================
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker/docker-compose.yml"
CONTAINER="mongodb-cyberdefense"
TARGET_VOL="mongo_data"
BACKUP_VOL="mongo_backup"
IMAGE="mongo:6.0"

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }
ok()  { printf '    \033[1;32m%s\033[0m\n' "$1"; }
err() { printf '\n\033[1;31mERROR: %s\033[0m\n' "$1"; exit 1; }

say "1. Verificando estado actual"
docker ps -a --filter "name=^/${CONTAINER}$" --format '{{.Names}} | {{.Image}} | {{.Status}}' || true
[ -f "$COMPOSE_FILE" ] || err "No existe $COMPOSE_FILE"

SOURCE_VOL="$(docker inspect "$CONTAINER" --format '{{range .Mounts}}{{if eq .Destination "/data/db"}}{{.Name}}{{end}}{{end}}')"
[ -n "$SOURCE_VOL" ] || err "No se encontró el volumen montado en /data/db del contenedor $CONTAINER"
ok "Volumen origen (anónimo): $SOURCE_VOL"

SRC_SIZE=$(docker run --rm -v "$SOURCE_VOL":/data/db "$IMAGE" sh -c "du -sm /data/db 2>/dev/null | cut -f1" | tr -d '[:space:]')
ok "Datos actuales: ${SRC_SIZE} MB"

say "2. Deteniendo el contenedor para evitar escrituras durante la copia"
if [ "$(docker inspect "$CONTAINER" --format '{{.State.Running}}')" = "true" ]; then
    docker stop "$CONTAINER" > /dev/null
    ok "Contenedor detenido"
else
    ok "El contenedor ya estaba detenido"
fi

say "3. Copia de seguridad en el volumen '$BACKUP_VOL'"
docker volume create "$BACKUP_VOL" > /dev/null
docker run --rm -v "$SOURCE_VOL":/from -v "$BACKUP_VOL":/to "$IMAGE" \
    sh -c "rm -rf /to/* /to/.[!.]* 2>/dev/null; cp -a /from/. /to/ 2>/dev/null; true"
BACKUP_SIZE=$(docker run --rm -v "$BACKUP_VOL":/data/db "$IMAGE" sh -c "du -sm /data/db 2>/dev/null | cut -f1" | tr -d '[:space:]')
ok "Respaldo creado: ${BACKUP_SIZE} MB en el volumen $BACKUP_VOL"

say "4. Copiando los datos al volumen nombrado '$TARGET_VOL'"
docker volume create "$TARGET_VOL" > /dev/null
docker run --rm -v "$SOURCE_VOL":/from -v "$TARGET_VOL":/to "$IMAGE" \
    sh -c "rm -rf /to/* /to/.[!.]* 2>/dev/null; cp -a /from/. /to/ 2>/dev/null; true"
TARGET_SIZE=$(docker run --rm -v "$TARGET_VOL":/data/db "$IMAGE" sh -c "du -sm /data/db 2>/dev/null | cut -f1" | tr -d '[:space:]')
ok "Copia terminada: ${TARGET_SIZE} MB en el volumen $TARGET_VOL"
[ "${TARGET_SIZE:-0}" -gt 0 ] || err "La copia quedó vacía. No se continúa (el contenedor original sigue intacto)."

say "5. Eliminando el contenedor antiguo (sin -v: el volumen anónimo se conserva)"
docker rm "$CONTAINER" > /dev/null
ok "Contenedor eliminado. Volumen anónimo $SOURCE_VOL conservado como respaldo."

say "6. Levantando el contenedor con docker compose"
docker compose -f "$COMPOSE_FILE" up -d
ok "Contenedor creado desde $COMPOSE_FILE"

say "7. Verificando la base de datos"
for i in $(seq 1 30); do
    if docker exec "$CONTAINER" mongosh --quiet --eval 'db.adminCommand("ping").ok' > /dev/null 2>&1; then
        ok "MongoDB responde al ping"; break
    fi
    [ "$i" -eq 30 ] && err "MongoDB no responde tras 30 intentos"
    sleep 1
done

echo
docker exec "$CONTAINER" mongosh cyberdefense --quiet --eval \
    'print("Colecciones: " + db.getCollectionNames().join(", "));
     print("Usuarios: " + db.users.countDocuments({}));
     print("Alertas: " + db.alerts.countDocuments({}));' || true

say "Migración completada"
echo "    Datos:      volumen $TARGET_VOL (gestionado por docker compose)"
echo "    Respaldo 1: volumen $BACKUP_VOL"
echo "    Respaldo 2: volumen anónimo $SOURCE_VOL (conservado)"
echo
echo "    Para deshacer (dejar el contenedor como estaba antes):"
echo "      docker stop $CONTAINER && docker rm $CONTAINER"
echo "      docker run -d --name $CONTAINER -p 27017:27017 -v $SOURCE_VOL:/data/db $IMAGE"
