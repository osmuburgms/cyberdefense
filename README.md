# CyberDefense Adaptive

Sistema integral de ciberdefensa basado en:

* SDN (Mininet + Ryu)
* Backend (FastAPI)
* IA (Machine Learning con Scikit-learn)
* Frontend (React + Vite)
* Blockchain (Solana + Rust)
* Captura de tráfico (TShark / Tcpdump)

---

# Requisitos

* Linux Mint 22.3 (recomendado) o Ubuntu 22.04+
* Acceso a internet
* Usuario con permisos sudo

---

# Instalación

El proyecto incluye un script que instala **todo el entorno necesario**:

```bash
chmod +x install.sh
./install.sh
```

También se incluye una guía de instalación manual dentro del repositorio, donde podrás instalar cada componente paso a paso.
```bash
software manual installation guide - cyberdefense.txt
```

Úsala si:

* Prefieres tener control total del proceso
* Quieres entender cada instalación en detalle
* El script automático presenta algún problema en tu sistema

Esta guía cubre:

* Mininet + Open vSwitch
* Ryu Controller
* Backend (FastAPI)
* IA (Scikit-learn, pandas)
* Frontend (React)
* Docker
* PostgreSQL
* Solana + Rust

---

# IMPORTANTE (Frontend React)

Durante la instalación del frontend, el script ejecutará:

```bash
npx create-vite@latest . --template react
```

### Te aparecerá una pregunta en la terminal:

```
◇  Install with npm and start now?
│  ◇ Yes / ◇ No
```

Seleccione ```Yes``` y presione ```ENTER```

---

### Luego React se ejecutará automáticamente y verás algo como:

```
Local: http://localhost:5173/
```

Abre esa dirección en tu navegador para verificar que React funciona correctamente.

---

### Para continuar con la instalación:

1. Regresa a la terminal
2. Presiona:

```bash
q + ENTER
```

Esto permitirá que el script continúe con el resto de la instalación.

---

# Estructura del proyecto

Puedes visualizar la estructura con:

```bash
./structure.sh
```

Ejemplo:

```
cyberdefense/
├── ai/
├── backend/
├── controller/
├── frontend/
```

---

# Verificar versiones instaladas

Para comprobar que todo se instaló correctamente:

```bash
./all_versions.sh
```

Esto mostrará versiones de:

* Python
* Java
* Node / npm / yarn
* Docker
* PostgreSQL
* Ryu
* FastAPI
* Scikit-learn
* React
* Mininet / OVS
* TShark

---

# Componentes del sistema

### Controller (SDN)

* Ryu Controller
* OpenFlow 1.3
* Integración con Mininet

### Backend

* FastAPI
* WebSockets
* PostgreSQL

### IA

* Pandas
* Scikit-learn
* Procesamiento de tráfico de red

### Frontend

* React + Vite
* Axios
* Recharts

---

# Notas importantes

### PostgreSQL (configuración manual)

Después de instalar, debes crear la base de datos:

Entre a la shell de PostgreSQL
```bash
sudo -u postgres psql
```
Cree la base de datos y añadir usiario administrador
```sql
CREATE DATABASE cyberdefense;
CREATE USER 'tu_usuario' WITH PASSWORD 'tu_password';
GRANT ALL PRIVILEGES ON DATABASE cyberdefense TO 'tu_usuario';
```

---

### Parche de Ryu

El script de instalación aplica automáticamente un parche necesario en:

```
controller/patch/wsgi.py
```

No necesitas hacerlo manualmente.

---

# Resultado esperado

Al finalizar la instalación tendrás:

* Mininet funcionando
* Ryu Controller operativo
* Backend listo
* IA preparada
* Frontend React corriendo
* Blockchain configurado
* Herramientas de captura instaladas

---

Proyecto desarrollado como sistema de ciberdefensa académica y experimental.

---
