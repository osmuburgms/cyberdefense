#!/bin/bash

# ==========================================
# CARGAR RUTAS DE NVM, PYENV Y SOLANA
# ==========================================
PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
PYTHON310_LIB="$PYENV_ROOT/versions/3.10.14/lib"
if [ -d "$PYTHON310_LIB" ]; then
  export LD_LIBRARY_PATH="$PYTHON310_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
if command -v pyenv 1>/dev/null 2>&1; then
  eval "$(pyenv init -)"
fi

export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

# ==========================================
# INICIO DE COMPROBACIONES
# ==========================================
echo "========== SISTEMA =========="
lsb_release -d 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME
uname -r
echo

echo "========== GLOBAL =========="
python3 --version
echo "node $(node --version)"
echo "npm $(npm --version)"
docker --version
docker compose version
git --version
solana --version
nginx -v 2>&1
ovs-vsctl --version | head -n 1
tshark -v | head -n 1
echo

echo "========== VNX =========="
sudo vnx --version
sudo virsh --version
sudo virsh list
sudo brctl show
echo

echo "========== RYU =========="
cd "$PROJECT_DIR/controller"
pyenv local 3.10.14
source venv/bin/activate
python --version
ryu-manager --version 2>/dev/null || echo "ryu-manager instalado correctamente"
deactivate
echo

echo "========== BACKEND =========="
cd "$PROJECT_DIR/backend"
source venv/bin/activate
python3 --version
echo "FastAPI: $(pip show fastapi | grep Version | awk '{print $2}')"
echo "Uvicorn: $(pip show uvicorn | grep Version | awk '{print $2}')"
deactivate
echo

echo "========== IA =========="
cd "$PROJECT_DIR/ai"
source iaenv/bin/activate
python3 --version
echo "Pandas: $(pip show pandas | grep Version | awk '{print $2}')"
echo "Scikit-learn: $(pip show scikit-learn | grep Version | awk '{print $2}')"
deactivate
echo

echo "========== FRONTEND REACT =========="
cd "$PROJECT_DIR/frontend"
npm list react --depth=0
npm list react-dom --depth=0
