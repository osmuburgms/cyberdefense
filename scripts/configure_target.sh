#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Ejecuta este script como root dentro del contenedor objetivo." >&2
  exit 1
fi

# VNX id=2 es eth2: la interfaz DHCP temporal conectada a virbr0. eth1 es la
# interfaz SDN principal y debe permanecer activa para conservar la VLAN.
PROVISIONING_IF=eth2

disable_provisioning_nic() {
  if ip link show dev "$PROVISIONING_IF" >/dev/null 2>&1; then
    ip route del default via 192.168.122.1 dev "$PROVISIONING_IF" >/dev/null 2>&1 || true
    ip addr flush dev "$PROVISIONING_IF" >/dev/null 2>&1 || true
    ip link set dev "$PROVISIONING_IF" down >/dev/null 2>&1 || true
  fi
}
trap disable_provisioning_nic EXIT

if ip -o -4 addr show dev "$PROVISIONING_IF" | grep -q '192[.]168[.]122[.]'; then
  ip route replace default via 192.168.122.1 dev "$PROVISIONING_IF" metric 100
  if [[ -L /etc/resolv.conf ]]; then
    unlink /etc/resolv.conf
  fi
  printf 'nameserver 192.168.122.1\nnameserver 8.8.8.8\nnameserver 1.1.1.1\noptions timeout:1 attempts:1\n' > /etc/resolv.conf
fi

export DEBIAN_FRONTEND=noninteractive
if ! command -v sshd >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  apt-get update
  apt-get install -y openssh-server python3
fi

echo 'root:root' | chpasswd
mkdir -p /etc/ssh/sshd_config.d /run/sshd
cat > /etc/ssh/sshd_config.d/00-cyberdefense-lab.conf <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
EOF
ssh-keygen -A
/usr/sbin/sshd -t
if command -v pkill >/dev/null 2>&1; then
  pkill -x sshd >/dev/null 2>&1 || true
fi
/usr/sbin/sshd

mkdir -p /var/www/html
cat > /var/www/html/index.html <<'EOF'
<!doctype html><html><body><h1>CyberDefense lab target</h1></body></html>
EOF
if ! ss -ltnH 'sport = :8080' 2>/dev/null | grep -q .; then
  nohup python3 -m http.server 8080 --bind 0.0.0.0 --directory /var/www/html \
    >/var/log/cyberdefense-http.log 2>&1 </dev/null &
fi

disable_provisioning_nic
trap - EXIT
echo "SSH (22) y HTTP (8080) activos; eth2 de aprovisionamiento apagada y eth1 SDN activa."
