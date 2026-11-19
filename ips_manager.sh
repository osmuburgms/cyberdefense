#!/bin/bash

# ==========================================
# CARGAR RUTA DE SOLANA
# ==========================================
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

LOG_DIR="$HOME/cyberdefense/logs"
mkdir -p $LOG_DIR
SCRIPTS_DIR="$HOME/cyberdefense/scripts"

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

# Lee el script local como root y lo transmite por stdin al contenedor. Así el
# aprovisionamiento no depende de que el archivo tenga permisos de lectura para
# el usuario que lanzó este gestor.
run_lxc_script() {
    local host="$1"
    local script_path="$2"
    sudo bash -o pipefail -c \
        'cat "$1" | lxc-attach -n "$2" -- bash -s' \
        _ "$script_path" "$host"
}

install_attacker_helper() {
    local script_path="$1"
    sudo bash -o pipefail -c \
        'cat "$1" | lxc-attach -n attacker -- bash -c "cat > /root/lab_attacks.sh && chmod 700 /root/lab_attacks.sh"' \
        _ "$script_path"
}

prepare_setup_log() {
    local log_path="$1"
    sudo install -m 600 -o "$(id -un)" -g "$(id -gn)" /dev/null "$log_path"
}

# La topología usa el bridge NAT de libvirt como salida de attacker. Puede
# mostrar NO-CARRIER mientras VNX está detenido; el flag UP indica que está
# administrativamente habilitado y VNX conectará las NIC al crear el escenario.
ensure_vnx_internet_bridge() {
    if command -v virsh >/dev/null 2>&1; then
        sudo virsh net-start default >/dev/null 2>&1 || true
    fi
    if ! ip link show dev virbr0 >/dev/null 2>&1; then
        echo "No existe virbr0 en el host; VNX no podrá dar salida a Internet a attacker." >&2
        return 1
    fi
    if ! ip -o link show dev virbr0 | awk -F'[<>]' '{n=split($2, flags, ","); for (i=1; i<=n; i++) if (flags[i] == "UP") found=1} END {exit !found}'; then
        sudo ip link set dev virbr0 up || return 1
    fi
    local bridge_addr
    bridge_addr="$(ip -4 -o addr show dev virbr0 | awk 'NR == 1 {print $4}')"
    echo "virbr0 listo (${bridge_addr:-sin IPv4}; NO-CARRIER hasta conectar los contenedores)."
}

case "$1" in
    start)
        echo "🚀 Iniciando Arquitectura de Ciberdefensa SDN..."
        SDN_SETUP_FAILED=0
        
        # Asegurar directorio y permisos de logs antes de levantar servicios
        mkdir -p ~/cyberdefense/logs
        sudo chown -R "$(id -un):$(id -gn)" "$LOG_DIR"

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
        if ! ensure_vnx_internet_bridge; then
            echo "        ⚠️ No se pudo habilitar virbr0; attacker no tendrá Internet para instalar paquetes."
            SDN_SETUP_FAILED=1
        fi
        sudo vnx -f ~/cyberdefense/scenarios/datacenter_sdn.xml -v -t > $LOG_DIR/vnx.log 2>&1
        sudo chown -R "$(id -un):$(id -gn)" "$LOG_DIR" 2>/dev/null || true
        echo "   [3.1] Configurando herramientas y script manual en attacker..."
        prepare_setup_log "$LOG_DIR/attacker-setup.log"
        if ! run_lxc_script attacker "$SCRIPTS_DIR/configure_attacker.sh" \
            > "$LOG_DIR/attacker-setup.log" 2>&1; then
            echo "        ⚠️ Falló la preparación de attacker; revisa logs/attacker-setup.log"
            sudo tail -n 25 "$LOG_DIR/attacker-setup.log" 2>/dev/null | sed 's/^/          /'
            SDN_SETUP_FAILED=1
        fi
        prepare_setup_log "$LOG_DIR/attacker-helper.log"
        if ! install_attacker_helper "$SCRIPTS_DIR/attacks_from_attacker.sh" \
            > "$LOG_DIR/attacker-helper.log" 2>&1; then
            echo "        ⚠️ No se pudo copiar /root/lab_attacks.sh; revisa logs/attacker-helper.log"
            sudo tail -n 25 "$LOG_DIR/attacker-helper.log" 2>/dev/null | sed 's/^/          /'
            SDN_SETUP_FAILED=1
        fi

        echo "   [3.2] Preparando SSH/HTTP en servidores y PCs de laboratorio..."
        VNX_TARGETS=(server1 server2 server3 server4 server5 lab1pc1 lab1pc2 lab2pc1 lab2pc2)
        for host in "${VNX_TARGETS[@]}"; do
            prepare_setup_log "$LOG_DIR/${host}-setup.log"
            if run_lxc_script "$host" "$SCRIPTS_DIR/configure_target.sh" \
                > "$LOG_DIR/${host}-setup.log" 2>&1; then
                echo "        $host listo; eth2 temporal apagada y eth1 SDN activa."
            else
                echo "        ⚠️ Falló $host; revisa logs/${host}-setup.log"
                sudo tail -n 25 "$LOG_DIR/${host}-setup.log" 2>/dev/null | sed 's/^/          /'
                SDN_SETUP_FAILED=1
            fi
        done

        sudo ovs-vsctl set bridge SDN_Net protocols=OpenFlow13
        sudo ovs-vsctl set-controller SDN_Net tcp:127.0.0.1:6653
        sudo ovs-vsctl set-fail-mode SDN_Net secure
        sudo ovs-ofctl -O OpenFlow13 del-flows SDN_Net
        
        echo "   [4/6] Levantando Controlador Ryu..."
        nohup $RYU_BIN ~/cyberdefense/controller/ryu_ips_controller.py > $LOG_DIR/ryu.log 2>&1 &
        
        echo "   [5/6] Levantando Backend FastAPI..."
        # NOTA: sin --ws none para no desactivar websockets; la miniconsola usa HTTP POST /api/hosts/exec
        ( cd $HOME/cyberdefense/backend && source $BACKEND_VENV/bin/activate && nohup uvicorn main:app --host 0.0.0.0 --port 8001 > $LOG_DIR/backend.log 2>&1 & )
        sleep 3
        curl_auth_args; curl -s "${CURL_AUTH[@]}" -X POST http://localhost:8001/api/switch-status/clear > /dev/null || true
        
        echo "   [6/6] Levantando Motor de IA IPS..."
        sudo nohup $IA_VENV/bin/python -u ~/cyberdefense/ai/scripts/realtime_detector.py > $LOG_DIR/ai.log 2>&1 &

        # Espera a que el sniffer esté activo y genera tráfico ARP legítimo en
        # las tres VLAN para inicializar su tabla antes de probar spoofing.
        for i in $(seq 1 30); do
            grep -q "IPS SDN Activo Iniciado" "$LOG_DIR/ai.log" && break
            sleep 1
        done
        sleep 1
        sudo vnx -f ~/cyberdefense/scenarios/datacenter_sdn.xml -M attacker --exe-cli "for ip in 192.168.1.10 192.168.1.11 192.168.1.12 192.168.1.13 192.168.1.14 192.168.20.11 192.168.20.12 192.168.30.11 192.168.30.12; do ping -c 1 -W 1 \$ip >/dev/null 2>&1 || true; done" > /dev/null 2>&1
        
        if [ "$SDN_SETUP_FAILED" -ne 0 ]; then
            echo "⚠️ Servicios base iniciados, pero el aprovisionamiento SDN quedó incompleto. Revisa logs/*-setup.log."
            exit 1
        fi
        echo "✅ ¡Todo el sistema está en línea y operando en segundo plano!"
        ;;
        
    stop)
        echo "🛑 Iniciando apagado seguro del entorno..."
        # Detén solo los procesos de este proyecto; evita coincidir con otros
        # servidores uvicorn/ryu que puedan estar usando el equipo.
        sudo pkill -u root -f -- "$IA_VENV/bin/python.*$HOME/cyberdefense/ai/scripts/realtime_detector.py" 2>/dev/null || true
        pkill -u "$(id -u)" -f -- 'uvicorn main:app.*--port 8001' 2>/dev/null || true
        pkill -u "$(id -u)" -f -- "$RYU_BIN.*$HOME/cyberdefense/controller/ryu_ips_controller.py" 2>/dev/null || true
        pkill -u "$(id -u)" -f -- "solana-test-validator.*--ledger $HOME/cyberdefense/test-ledger" 2>/dev/null || true
        sudo docker stop mongodb-cyberdefense > /dev/null
        sudo vnx -f ~/cyberdefense/scenarios/datacenter_sdn.xml -v --destroy > /dev/null 2>&1
        echo "✅ Entorno apagado correctamente."
        ;;
        
    clean-switch)
        echo "🧹 Limpiando bloqueos del switch y reiniciando Controlador..."
        pkill -u "$(id -u)" -f -- "$RYU_BIN.*$HOME/cyberdefense/controller/ryu_ips_controller.py" 2>/dev/null || true
        sudo ovs-ofctl -O OpenFlow13 del-flows SDN_Net
        nohup $RYU_BIN ~/cyberdefense/controller/ryu_ips_controller.py > $LOG_DIR/ryu.log 2>&1 &
        curl_auth_args; curl -s "${CURL_AUTH[@]}" -X POST http://localhost:8001/api/switch-status/clear > /dev/null || true
        echo "✅ Switch limpio y Ryu monitoreando de nuevo."
        ;;
        
    restart-ia)
        echo "🧠 Reiniciando Motor de IA..."
        sudo pkill -u root -f -- "$IA_VENV/bin/python.*$HOME/cyberdefense/ai/scripts/realtime_detector.py" 2>/dev/null || true
        sudo nohup $IA_VENV/bin/python -u ~/cyberdefense/ai/scripts/realtime_detector.py > $LOG_DIR/ai.log 2>&1 &
        echo "✅ IA reiniciada."
        ;;
        
    restart-backend)
        echo "💾 Reiniciando Backend..."
        pkill -u "$(id -u)" -f -- 'uvicorn main:app.*--port 8001' 2>/dev/null || true
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
