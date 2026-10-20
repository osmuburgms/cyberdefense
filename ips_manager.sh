#!/bin/bash

# ==========================================
# CARGAR RUTA DE SOLANA
# ==========================================
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

LOG_DIR="$HOME/cyberdefense/logs"
mkdir -p $LOG_DIR

# Rutas correctas a los entornos y ejecutables
RYU_VENV="$HOME/cyberdefense/controller/venv"
RYU_BIN="$RYU_VENV/bin/ryu-manager"

IA_VENV="$HOME/cyberdefense/ai/iaenv"           
BACKEND_VENV="$HOME/cyberdefense/backend/venv"

# Clave compartida backend <-> motor IA (cabecera X-API-Key). Se genera una
# vez y se reutiliza; el backend y la IA también la leen del fichero.
ENGINE_KEY_FILE="$HOME/cyberdefense/.engine_key"
ensure_engine_key() {
    if [ ! -s "$ENGINE_KEY_FILE" ]; then
        if command -v openssl > /dev/null 2>&1; then
            openssl rand -hex 32 > "$ENGINE_KEY_FILE" 2>/dev/null
        else
            head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$ENGINE_KEY_FILE"
        fi
        chmod 600 "$ENGINE_KEY_FILE"
    fi
    ENGINE_API_KEY="$(cat "$ENGINE_KEY_FILE" 2>/dev/null)"
    export IPS_API_KEY="$ENGINE_API_KEY"
    export ENGINE_API_KEY
}
# Rellena el array CURL_AUTH con la cabecera de clave si existe el fichero.
# Uso: curl_auth_args; curl -s "${CURL_AUTH[@]}" -X POST http://...
curl_auth_args() {
    CURL_AUTH=()
    local key=""
    [ -s "$ENGINE_KEY_FILE" ] && key="$(cat "$ENGINE_KEY_FILE")"
    [ -n "$key" ] && CURL_AUTH=(-H "X-API-Key: $key")
}  

# LXC 6 (Ubuntu 26.04) eliminó /usr/share/lxc/config/ubuntu.common.conf, pero los
# rootfs de VNX traen un config que lo incluye -> "Failed to load config" y los
# contenedores nunca arrancan. Creamos un puente hacia el equivalente actual.
ensure_lxc_compat() {
    local compat="/usr/share/lxc/config/ubuntu.common.conf"
    if [ ! -e "$compat" ] && [ -e /usr/share/lxc/config/common.conf ]; then
        echo "lxc.include = /usr/share/lxc/config/common.conf" \
            | sudo tee "$compat" > /dev/null 2>&1
        echo "        Compat LXC6: puente ubuntu.common.conf -> common.conf creado."
    fi
}

case "$1" in
    start)
        echo "🚀 Iniciando Arquitectura de Ciberdefensa SDN..."
        
        # Asegurar directorio y permisos de logs antes de levantar servicios
        mkdir -p ~/cyberdefense/logs
        sudo chown -R $USER:$USER ~/cyberdefense/logs

        # Clave compartida backend <-> motor IA (se genera una vez)
        ensure_engine_key
        
        echo "   [1/6] Iniciando MongoDB..."
        sudo docker start mongodb-cyberdefense > /dev/null
        
        echo "   [2/6] Iniciando Solana Test Validator..."
        if solana cluster-version -u http://localhost:8899 > /dev/null 2>&1; then
            echo "        Ya hay un validador escuchando en 8899, se reutiliza."
        else
            pkill -f solana-test-validator 2>/dev/null
            sleep 2

            SV_HELP="$(solana-test-validator --help 2>&1)"
            SV_FLAGS="--ledger $HOME/cyberdefense/test-ledger"
            # ELIMINAMOS LA BANDERA --reset PARA QUE LA BLOCKCHAIN PERSISTA
            echo "$SV_HELP" | grep -q -- "--rpc-port" && SV_FLAGS="$SV_FLAGS --rpc-port 8899"
            echo "$SV_HELP" | grep -q -- "--limit-ledger-size" && SV_FLAGS="$SV_FLAGS --limit-ledger-size 100000000"

            echo "        Lanzando: solana-test-validator $SV_FLAGS"
            nohup solana-test-validator $SV_FLAGS > $LOG_DIR/solana.log 2>&1 &
        fi

        echo "        Esperando a que el validador RPC esté listo..."
        RPC_OK=0
        for i in $(seq 1 60); do
            if solana cluster-version -u http://localhost:8899 > /dev/null 2>&1; then
                RPC_OK=1
                echo "        Validador Solana listo (intento $i)."
                break
            fi
            sleep 1
        done
        if [ "$RPC_OK" != "1" ]; then
            echo "   ⚠️  El validador Solana NO respondió. Revisa el error de arranque:"
            tail -15 $LOG_DIR/solana.log | sed 's/^/        /'
        else
            solana config set --url http://localhost:8899 > /dev/null 2>&1
            BAL=$(solana balance 2>/dev/null | awk '{print $1}')
            if [ -z "$BAL" ] || [ "${BAL%%.*}" -lt 10 ] 2>/dev/null; then
                echo "        Fondeando la cuenta pagadora (airdrop 100 SOL)..."
                solana airdrop 100 -u http://localhost:8899 > /dev/null 2>&1 || true
            fi
        fi
        
        echo "   [3/6] Levantando Red SDN (VNX y Open vSwitch)..."
        ensure_lxc_compat
        sudo vnx -f ~/cyberdefense/datacenter_sdn.xml -v -t > $LOG_DIR/vnx.log 2>&1
        echo "   [3.1] Configurando herramientas en el nodo atacante (esto puede tardar unos segundos)..."
        sleep 20 
        
        sudo vnx -f ~/cyberdefense/datacenter_sdn.xml -M attacker --exe-cli "echo 'nameserver 8.8.8.8' > /etc/resolv.conf && sleep 5 && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y hydra hping3 nmap slowhttptest && echo -e 'admin\n12345\npassword\nroot\nqwerty' > /root/passwords.txt" > /dev/null 2>&1 &

        sudo ovs-vsctl set bridge SDN_Net protocols=OpenFlow13
        sudo ovs-vsctl set-controller SDN_Net tcp:127.0.0.1:6653
        sudo ovs-vsctl set-fail-mode SDN_Net secure
        sudo ovs-ofctl -O OpenFlow13 del-flows SDN_Net
        
        echo "   [4/6] Levantando Controlador Ryu..."
        nohup $RYU_BIN ~/cyberdefense/sdn/ryu_ips_controller.py > $LOG_DIR/ryu.log 2>&1 &
        
        echo "   [5/6] Levantando Backend FastAPI..."
        # NOTA: sin --ws none para no desactivar websockets; la miniconsola usa HTTP POST /api/hosts/exec
        ( cd $HOME/cyberdefense/backend && source $BACKEND_VENV/bin/activate && nohup uvicorn main:app --host 0.0.0.0 --port 8001 > $LOG_DIR/backend.log 2>&1 & )
        sleep 3
        curl_auth_args; curl -s "${CURL_AUTH[@]}" -X POST http://localhost:8001/api/switch-status/clear > /dev/null || true
        
        echo "   [6/6] Levantando Motor de IA IPS..."
        sudo nohup $IA_VENV/bin/python -u ~/cyberdefense/ai/scripts/realtime_detector.py > $LOG_DIR/ai.log 2>&1 &
        
        echo "✅ ¡Todo el sistema está en línea y operando en segundo plano!"
        ;;
        
    stop)
        echo "🛑 Iniciando apagado seguro del entorno..."
        sudo pkill -f realtime_detector.py
        sudo pkill -f uvicorn
        sudo pkill -f ryu-manager
        pkill -f solana-test-validator
        sudo docker stop mongodb-cyberdefense > /dev/null
        sudo vnx -f ~/cyberdefense/datacenter_sdn.xml -v --destroy > /dev/null 2>&1
        echo "✅ Entorno apagado correctamente."
        ;;
        
    clean-switch)
        echo "🧹 Limpiando bloqueos del switch y reiniciando Controlador..."
        sudo pkill -f ryu-manager
        sudo ovs-ofctl -O OpenFlow13 del-flows SDN_Net
        nohup $RYU_BIN ~/cyberdefense/sdn/ryu_ips_controller.py > $LOG_DIR/ryu.log 2>&1 &
        curl_auth_args; curl -s "${CURL_AUTH[@]}" -X POST http://localhost:8001/api/switch-status/clear > /dev/null || true
        echo "✅ Switch limpio y Ryu monitoreando de nuevo."
        ;;
        
    restart-ia)
        echo "🧠 Reiniciando Motor de IA..."
        sudo pkill -f realtime_detector.py
        sudo nohup $IA_VENV/bin/python -u ~/cyberdefense/ai/scripts/realtime_detector.py > $LOG_DIR/ai.log 2>&1 &
        echo "✅ IA reiniciada."
        ;;
        
    restart-backend)
        echo "💾 Reiniciando Backend..."
        sudo pkill -f uvicorn
        ( cd $HOME/cyberdefense/backend && source $BACKEND_VENV/bin/activate && nohup uvicorn main:app --host 0.0.0.0 --port 8001 > $LOG_DIR/backend.log 2>&1 & )
        echo "✅ Backend reiniciado."
        ;;
        
    logs-ia)
        tail -f $LOG_DIR/ai.log
        ;;
    logs-backend)
        tail -f $LOG_DIR/backend.log
        ;;
    logs-ryu)
        tail -f $LOG_DIR/ryu.log
        ;;
    *)
        echo "Uso: ./ips_manager.sh {start|stop|clean-switch|restart-ia|restart-backend|logs-ia|logs-backend|logs-ryu}"
        exit 1
        ;;
esac