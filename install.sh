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
    xz-utils tk-dev nginx tree
)

for pkg in "${BASE_PACKAGES[@]}"; do
    install_if_missing "$pkg"
done

VNX_PACKAGES=(
    bash-completion bridge-utils expect genisoimage graphviz
    libappconfig-perl libdbi-perl liberror-perl libexception-class-perl
    libfile-homedir-perl libio-pty-perl libmath-round-perl libnetaddr-ip-perl
    libnet-ip-perl libnet-ipv6addr-perl libnet-pcap-perl libnet-telnet-perl
    libreadonly-perl libswitch-perl libsys-virt-perl libterm-readline-perl-perl
    libxml-checker-perl libxml-dom-perl libxml-libxml-perl libxml-parser-perl
    libxml-tidy-perl lxc lxc-templates openvswitch-switch picocom pv qemu-kvm
    screen tree uml-utilities virt-manager virt-viewer vlan w3m wmctrl xdotool
    xfce4-terminal xterm lsof libvirt-clients libvirt-daemon-system
)

echo "========== VNX DEPENDENCIES =========="

for pkg in "${VNX_PACKAGES[@]}"; do
    install_if_missing "$pkg"
done

# =========================
# OPEN VSWITCH (SDN)
# =========================
echo "========== OPEN VSWITCH =========="
sudo systemctl enable openvswitch-switch || true
sudo systemctl start openvswitch-switch || true

# =========================
# VNX
# =========================
echo "========== VNX =========="

if ! sudo vnx -V >/dev/null 2>&1; then
    echo "Instalando VNX..."

    mkdir -p /tmp/vnx-update
    cd /tmp/vnx-update
    rm -rf vnx-*

    wget http://vnx.dit.upm.es/vnx/vnx-latest.tgz
    tar xfvz vnx-latest.tgz
    cd vnx-*-*

    sudo ./install_vnx
else
    echo "VNX ya instalado"
fi

sudo sed -i 's|^#\?security_driver.*|security_driver = "none"|' /etc/libvirt/qemu.conf
sudo sed -i 's|^#\?user.*|user = "root"|' /etc/libvirt/qemu.conf
sudo sed -i 's|^#\?group.*|group = "root"|' /etc/libvirt/qemu.conf

sudo systemctl restart libvirtd 2>/dev/null || sudo systemctl restart libvirt-bin

if [ ! -f /etc/vnx.conf ]; then
    sudo cp /usr/share/vnx/etc/vnx.conf.sample /etc/vnx.conf
fi

sudo sed -i "s/overlayfs_workdir_option = 'no'/overlayfs_workdir_option = 'yes'/" /etc/vnx.conf
sudo sed -i "s/union_type='aufs'/union_type='overlayfs'/" /etc/vnx.conf
sudo sed -i "s/lxc_console_cmd=.*/lxc_console_cmd=lxc-attach/" /etc/vnx.conf

if [ ! -L /etc/libvirt/qemu/networks/autostart/default.xml ]; then
    sudo ln -s /etc/libvirt/qemu/networks/default.xml /etc/libvirt/qemu/networks/autostart/
fi

# =========================
# DOCKER
# =========================
echo "========== DOCKER =========="

if ! command_exists docker; then
    echo "Instalando Docker..."
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
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
# MONGODB (VIA DOCKER)
# =========================
echo "========== MONGODB =========="
if ! sudo docker ps -a | grep -q mongodb-cyberdefense; then
    echo "Descargando e iniciando contenedor de MongoDB..."
    sudo docker run -d --name mongodb-cyberdefense -p 27017:27017 -v mongo_data:/data/db mongo:latest
    sudo docker update --restart unless-stopped mongodb-cyberdefense
else
    echo "Contenedor de MongoDB ya existe. Asegurando que esté en ejecución..."
    sudo docker start mongodb-cyberdefense
fi

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

# Forzar la inclusión de la ruta por si se instaló pero no se reconoció en la sesión actual
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"

if ! command_exists solana; then
    echo "Instalando dependencias base de Solana..."
    sudo apt-get update
    sudo apt-get install -y build-essential pkg-config libudev-dev llvm libclang-dev protobuf-compiler libssl-dev
    
    echo "Instalando Solana CLI Oficial..."
    sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
    
    # Exportar inmediatamente al PATH
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
    
    # Asegurar que esté en el bashrc
    if ! grep -q "solana/install/active_release/bin" ~/.bashrc; then
        echo 'export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"' >> ~/.bashrc
    fi
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

DIRECTORIES=(backend ai controller frontend contracts docker docs scenarios)

for dir in "${DIRECTORIES[@]}"; do
    if [ ! -d "$PROJECT_DIR/$dir" ]; then
        echo "Creando carpeta: $dir"
        mkdir -p "$PROJECT_DIR/$dir"
    fi
done

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

    SITE_PACKAGES=$(python -c "import site; print(site.getsitepackages()[0])")
    RYU_WSGI_PATH="$SITE_PACKAGES/ryu/app/wsgi.py"
    PATCH_FILE="$PROJECT_DIR/controller/patch/wsgi.py"

    if [ -f "$PATCH_FILE" ]; then
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
    pip install fastapi uvicorn[standard] motor solana solders pydantic python-multipart websockets scapy

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

    pip install pandas scikit-learn numpy matplotlib lightgbm

    deactivate
else
    echo "Entorno AI ya existe"
fi

# =========================
# FRONTEND
# =========================
echo "========== FRONTEND =========="
cd $PROJECT_DIR/frontend

if [ ! -d "node_modules" ]; then
    npm install
    echo "Dependencias de React instaladas correctamente ✅"
else
    echo "El Frontend ya está inicializado."
fi

# =========================
# ACTUALIZACIONES FINALES
# =========================
echo "========== ACTUALIZACIONES Y LIMPIEZA =========="
echo "Optimizando dependencias del Frontend..."
cd $PROJECT_DIR/frontend
npm audit fix --no-fund --no-audit > /dev/null 2>&1 || true

echo "Limpiando paquetes innecesarios del sistema..."
sudo apt autoremove -y > /dev/null 2>&1

# =========================
# GUÍA POST-INSTALACIÓN (VNX)
# =========================
echo ""
echo "=================================================================="
echo "✅ INSTALACIÓN BASE FINALIZADA CORRECTAMENTE"
echo "=================================================================="
echo "⚠️  ACCIÓN REQUERIDA: INSTALACIÓN MANUAL DE ROOTFS PARA VNX"
echo "Para evitar errores en Pop!_OS 24.04 u otras distribuciones, el "
echo "sistema de archivos (RootFS) debe descargarse de forma manual."
echo ""
echo "Paso 1: Ejecuta la herramienta de descarga de VNX:"
echo "   cd /usr/share/vnx/filesystems"
echo "   sudo vnx_download_rootfs"
echo ""
echo "Paso 2: Selecciona el RootFS que necesites (ej. rootfs_lxc_ubuntu64)"
echo ""
echo "Paso 3: Crea el enlace simbólico para que tu red lo reconozca:"
echo "   sudo ln -snf /usr/share/vnx/filesystems/rootfs_lxc_ubuntu64 /usr/share/vnx/filesystems/rootfs_lxc"
echo "=================================================================="