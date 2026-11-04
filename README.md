# CyberDefense SDN

Plataforma de ciberseguridad para centros de datos que integra **detección de intrusiones con aprendizaje automático** y **mitigación automatizada sobre redes programables**, con visualización en tiempo real desde una interfaz web.

Desarrollado como Proyecto Integrador de la Facultad de Ingeniería en Electricidad y Computación (FIEC) — ESPOL.

---

## Arquitectura

```
        Red física / virtual (LXC + Open vSwitch + VNX)
                          │
                 ┌────────▼─────────┐
                 │  Ryu Controller   │  OpenFlow 1.3  (plano de control)
                 └────────┬─────────┘
                          │ reglas de flujo dinámicas
                 ┌────────▼─────────┐
                 │   Open vSwitch   │  (plano de datos)
                 └────────┬─────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
  ┌─────▼─────┐   ┌───────▼────────┐  ┌─────▼──────┐
  │ Percepción │   │    Análisis    │  │  Control   │
  │  (Scapy)   │──▶│   (LightGBM)   │─▶│ (mitigación)│
  └───────────┘   └───────┬────────┘  └────────────┘
                           │ eventos
                 ┌─────────▼──────────┐
                 │ Backend (FastAPI)  │──▶ MongoDB (alertas, usuarios, config)
                 │      :8001         │──▶ Solana  (registro auditable)
                 └─────────┬──────────┘
                           │  REST + WebSocket
                 ┌─────────▼──────────┐
                 │ Frontend (React)   │  :5173
                 │  dashboard web     │
                 └────────────────────┘
```

| Capa | Tecnología | Ubicación |
|------|-----------|-----------|
| Percepción | Scapy (sniffer en el borde) | `ai/scripts/realtime_detector.py` |
| Análisis | LightGBM (gradient boosting) | `ai/scripts/`, `ai/models/` |
| Control | Ryu + Open vSwitch + VNX | `controller/`, `sdn/`, `datacenter_sdn.xml` |
| Backend | FastAPI + MongoDB + Solana | `backend/main.py` |
| Presentación | React + Vite + Tailwind + xterm.js | `frontend/` |

---

## Requisitos

| Componente | Versión / nota |
|-----------|----------------|
| SO | Ubuntu 24.04 LTS o superior (probado en Ubuntu 26.04) / Linux Mint 22.3 |
| Python | 3.12+ (probado en 3.14). **Requiere recrear los venvs tras actualizar el SO** |
| Node.js | 20+ con npm |
| Docker | Para MongoDB (`mongodb-cyberdefense`) |
| LXC | 6.x (VNX 2.0b) |
| Open vSwitch | 3.x |
| VNX | 2.0b (laboratorio de redes virtuales) |
| Solana CLI | Agave / solana-test-validator |
| LaTeX | Opcional: para compilar el reporte (`latex/`) |

---

## Instalación

```bash
cd ~
git clone https://github.com/osmuburgms/cyberdefense.git
cd cyberdefense
./install.sh
```

El script instala todo el entorno. Si prefieres control paso a paso, usa la guía manual incluida:

```bash
cat "software manual installation guide - cyberdefense.txt"
```

### Entornos Python (importante)

Cada componente tiene su propio venv. Si actualizaste el sistema operativo y el Python cambió de versión, los venvs antiguos quedan inservibles (error `ModuleNotFoundError: No module named 'uvicorn'`). Recréalos con los archivos de requisitos versionados:

```bash
cd backend && rm -rf venv && python3 -m venv venv
./venv/bin/pip install -r requirements.txt

cd ../ai && rm -rf iaenv && python3 -m venv iaenv
./iaenv/bin/pip install -r requirements.txt
```

---

## Puesta en marcha

**1. Levantar todo el sistema** (Mongo, Solana, red SDN, Ryu, backend e IA):

```bash
./ips_manager.sh start
```

**2. Crear las cuentas de acceso** (solo la primera vez; el script pide las contraseñas por teclado y solo guarda hashes bcrypt):

```bash
cd backend && ./venv/bin/python crear_usuarios_iniciales.py
```

**3. Levantar el frontend** (en otra terminal, queda en primer plano):

```bash
cd frontend && npm install && npm run dev
```

Abre `http://localhost:5173` e inicia sesión.

### Comandos de `ips_manager.sh`

| Comando | Función |
|---------|---------|
| `./ips_manager.sh start` | Levanta todo el sistema |
| `./ips_manager.sh stop` | Detiene y destruye las VMs virtuales |
| `./ips_manager.sh clean-switch` | Borra los bloqueos del switch y reinicia Ryu |
| `./ips_manager.sh restart-backend` | Reinicia solo el backend |
| `./ips_manager.sh restart-ia` | Reinicia solo el motor de IA |
| `./ips_manager.sh logs-backend` | Muestra el log del backend (`Ctrl+C` para salir) |
| `./ips_manager.sh logs-ia` | Muestra el log del motor IA |
| `./ips_manager.sh logs-ryu` | Muestra el log de Ryu |

---

## Autenticación y roles

El dashboard requiere autenticación. Las cuentas viven en **MongoDB** (`cyberdefense`, colección `users`) con **hash bcrypt**; las contraseñas en claro no se guardan ni se devuelven por la API.

| Rol | Permisos |
|-----|----------|
| `operator` | Lectura de todo el sistema, consola de hosts, limpieza del switch, búsqueda y fijación de Amenazas |
| `admin` | Todo lo anterior **+** gestión de usuarios y roles, parámetros globales, borrado de registros y limpieza de la consola del switch |

Roles implementados:

- **JWT HS256** con vigencia de 12 h. Secreto en `backend/.jwt_secret` (se genera solo, permisos `600`) o variable de entorno `IPS_JWT_SECRET`.
- **Clave de motor (`X-API-Key`)**: la usan el detector de IA y los scripts de `ips_manager.sh` para hablar con el backend sin usuario. Se genera en `~/cyberdefense/.engine_key` o variable `IPS_API_KEY`.
- `POST /api/alerts` y `POST /api/switch-status/clear` aceptan JWT **o** `X-API-Key`.
- La consola WebSocket (`/ws/terminal/{host}`) recibe el token por query `?token=` porque el navegador no puede mandar cabeceras en un WebSocket.
- Gestión de usuarios y configuración global protegidas en el backend (`403`), no solo ocultas en la interfaz.

> Cambia la contraseña del administrador en el primer ingreso: *Configuración → Mi cuenta*.

---

## API principal

| Método | Ruta | Acceso |
|--------|------|--------|
| POST | `/api/auth/login` | público |
| GET | `/api/auth/me` | JWT |
| POST | `/api/auth/change-password` | JWT |
| GET / POST | `/api/users` | GET: admin · POST: admin |
| PATCH / DELETE | `/api/users/{username}` | admin |
| GET / PUT | `/api/config` | GET: todos · PUT: admin |
| GET | `/api/alerts`, `/api/alerts/count` | JWT |
| POST | `/api/alerts` | JWT o `X-API-Key` |
| DELETE | `/api/alerts`, `/api/alerts/{id}` | admin |
| GET | `/api/hosts`, `/api/hosts/{host}/ping` | JWT |
| POST | `/api/hosts/exec` | JWT |
| GET | `/api/switch-status` | JWT |
| POST | `/api/switch/clean`, `/api/switch-status/clear` | JWT o `X-API-Key` |
| GET | `/api/blockchain/diag`, `/api/blockchain/tx/{sig}` | JWT |
| GET | `/api/health` | público |
| WS | `/ws/terminal/{host}?token=<JWT>` | JWT |

---

## Frontend

`frontend/` es una SPA de React (Vite + Tailwind) con navegación por estado (sin router), para no depender de reglas de reescritura en el servidor web.

| Página | Contenido |
|--------|-----------|
| Panel principal | KPIs, topología de la red interactiva, registro de eventos |
| Eventos y análisis | Panel de amenazas, panel de IA, línea de tiempo, gráficas, registro completo |
| Servicios y blockchain | Estado de servicios, auditoría en Solana, mantenimiento del switch |
| Usuarios | Gestión de cuentas y roles (solo admin) |
| Configuración | Mi cuenta, cambio de contraseña, parámetros globales (solo admin), preferencias personales |

La consola de hosts es **xterm.js** conectado por WebSocket a una PTY real del contenedor LXC (`lxc-attach`), por lo que ejecuta comandos reales dentro del rootfs Ubuntu del host.

---

## Motor de IA

| Script | Función |
|--------|---------|
| `realtime_detector.py` | Sniffer en vivo, extrae características, clasifica con el modelo y notifica al backend |
| `train_ram_model.py` | Entrena el modelo LightGBM balanceado (modelo por defecto: `lightgbm_ram_optimizado`) |
| `entrenar_lightgbm_final.py` | Entrenamiento del modelo grande experimental (`lightgbm_1_2M_final`) |
| `validar_modelo_1_2M.py` | Verificación del modelo experimental (⚠️ clasifica todo como benigno) |
| `monitor_flujos.py` | Monitoreo y conteo de flujos |
| `generate_dataset.py` | Generación de dataset sintético |
| `infer_lightgbm.py`, `infer_if.py` | Inferencia puntual sobre capturas |

El modelo en uso se puede cambiar con las variables `IPS_MODEL` e `IPS_ENCODER`.

---

## Reporte en LaTeX

La carpeta `latex/` contiene el reporte del proyecto con la plantilla oficial de la Facultad (Arial, A4, interlineado 1.5), compilable **localmente con el mismo resultado que Overleaf** (XeLaTeX + Biber).

```bash
cd latex
make            # genera ReportePI.pdf
make clean      # borra los auxiliares
```

Desde VS Code, con la extensión *LaTeX Workshop*: `Ctrl+Alt+B` → **"latexmk (xelatex + biber)"**.

| Archivo | Contenido |
|---------|-----------|
| `title.tex` | Portada (título, autores, carrera) |
| `resumen.tex` | Resumen y Abstract con palabras clave |
| `adicionales.tex` | Dedicatoria, agradecimientos, declaración, evaluadores |
| `abreviaturas.tex` / `simbologia.tex` | Siglas y símbolos |
| `cap01.tex` | Capítulo 1 — Introducción (redactado) |
| `cap02.tex` … `cap05.tex` | Capítulos pendientes, con indicativos comentados |
| `referencias.bib` | Bibliografía (Biber, estilo APA) |

---

## Estructura del proyecto

```
cyberdefense/
├── ai/                    # Motor de IA: scripts, modelos y datasets
├── backend/               # FastAPI: auth, alertas, hosts, configuración
├── controller/            # Ryu + parche wsgi
├── frontend/             # Dashboard React (login + páginas por rol)
├── latex/                 # Reporte del PI en LaTeX
├── sdn/                   # Módulos del controlador
├── scenarios/             # Escenarios de red
├── contracts/             # Documentación contractual (carta de compromiso)
├── docker/                # MongoDB
├── datacenter_sdn.xml     # Topología VNX (attacker, server1, server2)
├── ips_manager.sh         # Orquestador del sistema
├── install.sh             # Instalador automático
├── all_versions.sh        # Verificación de versiones
└── structure.sh           # Muestra el árbol del proyecto
```

---

## Solución de problemas

| Síntoma | Causa | Solución |
|---------|-------|----------|
| `ModuleNotFoundError: No module named 'uvicorn'` (o `pandas`) | Se actualizó el SO y cambió la versión de Python; el venv quedó obsoleto | Recrear los venvs con `requirements.txt` (ver *Instalación*) |
| `Failed to load config for attacker` / la consola no conecta | LXC 6 eliminó `/usr/share/lxc/config/ubuntu.common.conf` que los rootfs de VNX aún referencian | `ips_manager.sh` crea un puente a `common.conf` automáticamente; si falla, `sudo tee /usr/share/lxc/config/ubuntu.common.conf` con la línea `lxc.include = /usr/share/lxc/config/common.conf` |
| `sudo: a password is required` al usar el backend | Falta NOPASSWD para los comandos del sistema | Añadir las reglas a `/etc/sudoers.d/cyberdefense` (revisar el bloque de sudoers en la documentación de instalación) |
| "Sin conexión con el backend" en el login | El backend no está levantado o el MongoDB no corre | `./ips_manager.sh restart-backend` y `sudo docker start mongodb-cyberdefense` |
| `lxc-info: attacker doesn't exist` | Las VMs fueron destruidas con `stop` | `./ips_manager.sh start` las recrea |
| El motor IA no registra alertas | Falta la clave compartida o el backend está caído | Verificar `~/cyberdefense/.engine_key` y `./ips_manager.sh logs-ia` |

---

## Seguridad del repositorio

Nunca se versionan secretos. Están en `.gitignore`:

```
.engine_key            # clave compartida backend <-> motor IA
backend/.jwt_secret    # secreto de firma de los JWT
backend/venv/          # entornos virtuales
ai/iaenv/
test-ledger/           # ledger de Solana de pruebas
*.csv                  # datasets
```

Las contraseñas de los usuarios nunca se escriben en el código: se solicitan de forma interactiva y solo se almacenan hashes bcrypt.

---

Proyecto de investigación aplicada en ciberseguridad y redes programables — ESPOL, FIEC.
