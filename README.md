# CyberDefense SDN

**Ciberdefensa inteligente y adaptativa para la detección de amenazas y mitigación automática en redes programables mediante IA y SDN**

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
| Control | Ryu + Open vSwitch + VNX | `controller/`, `scenarios/datacenter_sdn.xml` |
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
cat "docs/software manual installation guide - cyberdefense.txt"
```

### Entornos Python (importante)

Cada componente tiene su propio venv. Si actualizaste Python, renombraste tu usuario Linux o moviste la carpeta del proyecto, los venvs antiguos pueden conservar rutas absolutas inválidas (por ejemplo, `No such file or directory` al ejecutar `uvicorn`). El instalador detecta esos entornos, los guarda como respaldo y los recrea con las dependencias declaradas; también reconstruye el entorno especial de Ryu con Python 3.10.

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

### Topología SDN de VNX

`scenarios/datacenter_sdn.xml` levanta un switch Open vSwitch con tres VLAN de acceso:

| Segmento | VLAN | Subred | Equipos |
|----------|------|--------|---------|
| Servidores | 10 | `192.168.1.0/24` | `server1`–`server5` (`.10`–`.14`) |
| Laboratorio 1 | 20 | `192.168.20.0/24` | `lab1pc1` (`.11`), `lab1pc2` (`.12`) |
| Laboratorio 2 | 30 | `192.168.30.0/24` | `lab2pc1` (`.11`), `lab2pc2` (`.12`) |

El atacante tiene una interfaz en cada VLAN (`192.168.1.50`, `192.168.20.50` y `192.168.30.50`) y una interfaz DHCP externa en `eth4`. El gestor configura su ruta por defecto mediante el gateway NAT de libvirt (`192.168.122.1`) y un `resolv.conf` directo para que pueda instalar las herramientas. Durante `ips_manager.sh start`, los objetivos reciben temporalmente una interfaz `virbr0` en `eth2` para instalar SSH y preparar HTTP; `scripts/configure_target.sh` apaga `eth2` al terminar y conserva activa `eth1`, su puerto SDN. La consola del frontend se conecta a esos mismos contenedores LXC.

Los scripts de aprovisionamiento están en `scripts/`. El arranque configura `attacker` y los nueve objetivos, pero no ejecuta ataques. Desde la consola de `attacker`, las pruebas manuales se lanzan así:

```bash
/root/lab_attacks.sh arp servers
/root/lab_attacks.sh dos lab1
/root/lab_attacks.sh bruteforce all
```

El helper acepta `servers`, `lab1`, `lab2` o `all` como grupo.

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

### Notificaciones por correo

El backend envía alertas al correo registrado de cada cuenta **activa** con rol `operator` o `admin`. El administrador asigna las direcciones en *Usuarios*; los correos duplicados se deduplican y se puede definir un umbral mínimo de severidad.

El relay SMTP y sus credenciales se configuran localmente en `backend/.env` a partir de `backend/.env.example`. La carta de compromiso asigna al cliente la provisión del relay y de sus destinatarios autorizados. No guardes estas credenciales en MongoDB ni en el frontend. Tras completar la configuración, reinicia el backend.

Desde *Usuarios* se puede enviar una prueba a una cuenta seleccionada. La prueba usa datos sintéticos identificados como **PRUEBA SIMULADA**; no inserta una alerta, no genera tráfico y no modifica la red.

---

## API principal

| Método | Ruta | Acceso |
|--------|------|--------|
| POST | `/api/auth/login` | público |
| GET | `/api/auth/me` | JWT |
| POST | `/api/auth/change-password` | JWT |
| GET / POST | `/api/users` | GET: admin · POST: admin |
| PATCH / DELETE | `/api/users/{username}` | admin |
| GET | `/api/notifications/email/status` | admin |
| POST | `/api/notifications/email/test` | admin · cuerpo: `{"username":"..."}` |
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

## Base de datos (MongoDB en Docker)

El backend guarda alertas, usuarios y configuración en MongoDB (`base cyberdefense`, puerto `27017`).

```bash
# Crear y levantar el contenedor (primera vez, o en una PC nueva)
sudo docker compose -f docker/docker-compose.yml up -d

# Ver estado y logs
sudo docker compose -f docker/docker-compose.yml ps
sudo docker compose -f docker/docker-compose.yml logs -f

# Detener (conserva los datos)
sudo docker compose -f docker/docker-compose.yml down
```

`install.sh` usa este mismo compose automáticamente. Los datos persisten en el volumen `mongo_data`, así que el contenedor puede recrearse sin perder la información.

> **Si el contenedor ya existía creado con `docker run`**, Docker le asignó un volumen anónimo con los datos reales y el volumen `mongo_data` quedaría vacío. Antes de borrar ese contenedor, copia los datos (el procedimiento está documentado al inicio de `docker/docker-compose.yml`) o la base arrancará sin usuarios ni alertas.

---

## Estructura del proyecto

```
cyberdefense/
├── ai/                    # Motor de IA: scripts, modelos y datasets
├── backend/               # FastAPI: auth, alertas, hosts, configuración
├── controller/            # Ryu: ryu_ips_controller.py + venv del controlador
├── frontend/              # Dashboard React (login + páginas por rol)
├── latex/                 # Reporte del PI en LaTeX
├── scenarios/             # Escenarios de red (datacenter_sdn.xml, datacenter.xml)
├── contracts/             # Documentación contractual (carta de compromiso)
├── docker/                # docker-compose.yml de MongoDB
├── docs/                  # Guías y manuales (instalación, pasos IPS, VNX host)
├── scripts/               # Aprovisionamiento de attacker/objetivos y helper de laboratorio
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
| `snapshot dir account paths mismatching` | Un enlace del snapshot de Solana conserva el HOME anterior | `ips_manager.sh start` actualiza el enlace si el directorio de cuentas sigue presente; conserva `test-ledger` |
| `Failed to load config for attacker` / la consola no conecta | LXC 6 eliminó `/usr/share/lxc/config/ubuntu.common.conf` que los rootfs de VNX aún referencian | `ips_manager.sh` crea un puente a `common.conf` automáticamente; si falla, `sudo tee /usr/share/lxc/config/ubuntu.common.conf` con la línea `lxc.include = /usr/share/lxc/config/common.conf` |
| `sudo: interactive authentication is required` en la consola web | El backend usa `sudo -n`; puede faltar NOPASSWD para el usuario actual o la regla conservar el nombre anterior | En el anfitrión, edita `/etc/sudoers.d/cyberdefense` con `sudo visudo -f`, actualiza el usuario y valida con `sudo visudo -c` |
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
