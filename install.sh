#!/bin/bash

set -e

PROJECT_DIR="$HOME/cyberdefense"

# =========================
# VALIDACIÓN DEL PROYECTO
# =========================
echo "========== VALIDANDO PROYECTO =========="

if [ ! -d "$PROJECT_DIR" ]; then
    echo "ERROR: No existe el directorio $PROJECT_DIR"
    echo "Clona el repositorio primero:"
    echo "git clone <repo_url> $PROJECT_DIR"
    exit 1
fi

if [ ! -f "$PROJECT_DIR/structure.sh" ]; then
    echo "ERROR: No parece ser el repositorio correcto"
    exit 1
fi

echo "Directorio del proyecto OK ✅"

echo "========== ACTUALIZANDO SISTEMA =========="
sudo apt update && sudo apt upgrade -y

# =========================
# FUNCIONES ÚTILES
# =========================
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_if_missing() {
    if ! dpkg -s "$1" >/dev/null 2>&1; then
        echo "Instalando $1..."
        sudo apt install -y "$1"
    else
        echo "$1 ya está instalado"
    fi
}

# =========================
# DEPENDENCIAS BASE
# =========================
echo "========== DEPENDENCIAS BASE =========="

BASE_PACKAGES=(
    curl wget git unzip software-properties-common
    python3 python3-pip python3-venv
    build-essential net-tools openssh-server
    libssl-dev zlib1g-dev libbz2-dev libreadline-dev
    libsqlite3-dev libffi-dev liblzma-dev libncursesw5-dev
    xz-utils tk-dev nginx
)

for pkg in "${BASE_PACKAGES[@]}"; do
    install_if_missing "$pkg"
done

# =========================
# MININET
# =========================
echo "========== MININET =========="
install_if_missing mininet
install_if_missing openvswitch-switch

sudo systemctl enable openvswitch-switch || true
sudo systemctl start openvswitch-switch || true

# =========================
# DOCKER
# =========================
echo "========== DOCKER =========="

if ! command_exists docker; then
    echo "Instalando Docker..."

    sudo install -m 0755 -d /etc/apt/keyrings

    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc

    sudo chmod a+r /etc/apt/keyrings/docker.asc

    echo \
    "Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc" | \
    sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null

    sudo apt update

    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
    echo "Docker ya está instalado"
fi

sudo systemctl enable docker || true
sudo systemctl start docker || true

# =========================
# POSTGRESQL
# =========================
echo "========== POSTGRESQL =========="
install_if_missing postgresql
install_if_missing postgresql-contrib

sudo systemctl enable postgresql || true
sudo systemctl start postgresql || true

# =========================
# CAPTURA DE TRÁFICO
# =========================
echo "========== CAPTURA =========="
install_if_missing tcpdump
install_if_missing tshark
install_if_missing wireshark

# =========================
# NODE (NVM)
# =========================
echo "========== NODE =========="

if [ ! -d "$HOME/.nvm" ]; then
    echo "Instalando NVM..."
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
fi

export NVM_DIR="$HOME/.nvm"
source "$NVM_DIR/nvm.sh"

if ! command_exists node; then
    nvm install 24
else
    echo "Node ya está instalado: $(node -v)"
fi

# =========================
# SOLANA
# =========================
echo "========== SOLANA =========="

if ! command_exists solana; then
    sudo apt-get install -y build-essential pkg-config libudev-dev llvm libclang-dev protobuf-compiler libssl-dev
    curl --proto '=https' --tlsv1.2 -sSfL https://solana-install.solana.workers.dev | bash
else
    echo "Solana ya está instalado: $(solana --version)"
fi

# =========================
# PYENV
# =========================
echo "========== PYENV =========="

if [ ! -d "$HOME/.pyenv" ]; then
    echo "Instalando pyenv..."
    curl https://pyenv.run | bash

    echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
    echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(pyenv init --path)"' >> ~/.bashrc
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
fi

export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init --path)"
eval "$(pyenv init -)"

if ! pyenv versions | grep -q "3.10.14"; then
    pyenv install 3.10.14
else
    echo "Python 3.10.14 ya instalado en pyenv"
fi

# =========================
# ESTRUCTURA
# =========================
echo "========== ESTRUCTURA =========="

DIRECTORIES=(
    backend
    ai
    controller
    frontend
    contracts
    docker
    docs
)

for dir in "${DIRECTORIES[@]}"; do
    if [ ! -d "$PROJECT_DIR/$dir" ]; then
        echo "Creando carpeta: $dir"
        mkdir -p "$PROJECT_DIR/$dir"
    else
        echo "La carpeta $dir ya existe"
    fi
done

echo "Estructura del proyecto verificada ✅"

# =========================
# RYU
# =========================
echo "========== RYU =========="
cd $PROJECT_DIR/controller

if [ ! -d "venv" ]; then
    pyenv local 3.10.14
    python -m venv venv
    source venv/bin/activate

    pip install pip==24.0 setuptools==65.5.0 wheel==0.41.2
    pip install ryu --no-build-isolation

    pip uninstall eventlet dnspython -y
    pip install eventlet==0.33.3 dnspython==2.2.1

    echo "Aplicando parche a Ryu..."

    # Detectar ruta real de site-packages (más robusto que hardcodear python3.10)
    SITE_PACKAGES=$(python -c "import site; print(site.getsitepackages()[0])")

    RYU_WSGI_PATH="$SITE_PACKAGES/ryu/app/wsgi.py"
    PATCH_FILE="$PROJECT_DIR/controller/patch/wsgi.py"

    if [ -f "$PATCH_FILE" ]; then
        echo "Parche encontrado: $PATCH_FILE"

        # Backup por si acaso (buena práctica)
        if [ -f "$RYU_WSGI_PATH" ]; then
            cp "$RYU_WSGI_PATH" "$RYU_WSGI_PATH.bak"
            rm "$RYU_WSGI_PATH"
        fi

        cp "$PATCH_FILE" "$RYU_WSGI_PATH"

        echo "Parche aplicado correctamente ✅"
    else
        echo "ERROR: No se encontró el parche en $PATCH_FILE"
        exit 1
    fi

    deactivate
else
    echo "Entorno Ryu ya existe"
fi

# =========================
# BACKEND
# =========================
echo "========== BACKEND =========="
cd $PROJECT_DIR/backend

if [ ! -d "venv" ]; then
    python3 -m venv venv
    source venv/bin/activate

    pip install --upgrade pip
    pip install fastapi uvicorn[standard]
    pip install sqlalchemy psycopg2-binary
    pip install python-multipart websockets scapy

    deactivate
else
    echo "Backend ya existe"
fi

# =========================
# AI
# =========================
echo "========== AI =========="
cd $PROJECT_DIR/ai

if [ ! -d "iaenv" ]; then
    python3 -m venv iaenv
    source iaenv/bin/activate

    pip install pandas scikit-learn numpy matplotlib

    deactivate
else
    echo "Entorno AI ya existe"
fi

# =========================
# FRONTEND
# =========================
echo "========== FRONTEND =========="
cd $PROJECT_DIR/frontend

npx create-vite@latest . --template react
npm install
npm install axios react-router-dom recharts
echo "React instalado correctamente ✅"

echo "========== INSTALACIÓN FINALIZADA =========="
