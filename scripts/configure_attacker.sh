#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Ejecuta este script como root dentro del contenedor attacker." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# VNX asigna if id=4 como eth4 por DHCP desde virbr0. En este escenario el
# DHCP entrega dirección y ruta de subred, pero no una ruta por defecto; el
# gateway NAT de libvirt es 192.168.122.1.
LIBVIRT_GATEWAY=192.168.122.1
EXTERNAL_IF=""
for attempt in $(seq 1 30); do
  EXTERNAL_IF="$(ip -o -4 addr show | awk '$4 ~ /^192[.]168[.]122[.]/ {print $2; exit}')"
  [[ -n "$EXTERNAL_IF" ]] && break
  sleep 2
done

if [[ -z "$EXTERNAL_IF" ]]; then
  echo "No se recibió una dirección DHCP de virbr0 en attacker." >&2
  ip -brief -4 address >&2 || true
  ip -4 route >&2 || true
  exit 1
fi

ip link set dev "$EXTERNAL_IF" up
ip route replace default via "$LIBVIRT_GATEWAY" dev "$EXTERNAL_IF" metric 100

# La imagen Ubuntu trae /etc/resolv.conf enlazado al stub 127.0.0.53. Ese
# resolved no está disponible en este contenedor, así que usa DNS directo.
if [[ -L /etc/resolv.conf ]]; then
  unlink /etc/resolv.conf
fi
cat > /etc/resolv.conf <<'EOF'
nameserver 192.168.122.1
nameserver 8.8.8.8
nameserver 1.1.1.1
options timeout:1 attempts:1
EOF

NETWORK_READY=0
for attempt in $(seq 1 20); do
  if ip -4 route get 8.8.8.8 >/dev/null 2>&1 && getent ahostsv4 archive.ubuntu.com >/dev/null 2>&1; then
    NETWORK_READY=1
    break
  fi
  sleep 2
done

if [[ "$NETWORK_READY" -ne 1 ]]; then
  echo "No hay salida a Internet en attacker por virbr0 (falló la ruta o DNS)." >&2
  echo "Interfaces IPv4:" >&2
  ip -brief -4 address >&2 || true
  echo "Rutas IPv4:" >&2
  ip -4 route >&2 || true
  echo "DNS configurado:" >&2
  cat /etc/resolv.conf >&2
  exit 1
fi

echo "Salida lista por $EXTERNAL_IF: $(ip -4 route show default | head -n 1)"
echo "DNS funcional vía 192.168.122.1."

apt-get update
apt-get install -y hydra hping3 nmap slowhttptest dsniff curl iproute2 iputils-ping

cat > /root/passwords.txt <<'EOF'
admin
12345
password
root
qwerty
EOF
chmod 600 /root/passwords.txt

cat > /root/targets-sdn.txt <<'EOF'
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
192.168.20.11
192.168.20.12
192.168.30.11
192.168.30.12
EOF
chmod 644 /root/targets-sdn.txt

# El atacante llega a cada VLAN por su interfaz dedicada; no enruta entre ellas.
sysctl -w net.ipv4.ip_forward=0 >/dev/null

for tool in hydra hping3 nmap slowhttptest arpspoof curl; do
  command -v "$tool" >/dev/null || { echo "No se instaló la herramienta requerida: $tool" >&2; exit 1; }
done

echo "Herramientas del atacante instaladas. Ataques manuales: /root/lab_attacks.sh"
