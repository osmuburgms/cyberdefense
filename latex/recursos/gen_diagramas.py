#!/usr/bin/env python3
"""Diagramas del Capitulo 2 (SVG vectorial, sin filtros raster: aptos para LaTeX/PDF)."""
import os, sys
from xml.sax.saxutils import escape

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)

INK, MUTED, LINE = "#26323f", "#5b6b80", "#48566a"
GREEN_L, BLUE_L, ORANGE, RED = "#2f8f5b", "#2f6fb0", "#c9772b", "#b04a4a"
FONT = "Arial, 'Liberation Sans', Helvetica, sans-serif"

# (nombre, claro, oscuro) para degradados de cabecera
TONES = {
    "blue": ("#e6effa", "#c9dcf2"),
    "green": ("#e7f5ec", "#c6e6d2"),
    "amber": ("#fdf3df", "#f4dcaa"),
    "gray": ("#eef1f5", "#d5dbe4"),
    "rose": ("#faeaea", "#efc9c9"),
    "dark": ("#3a4a5e", "#26323f"),
}
SOLID = {"blue": "#dce8f5", "green": "#dff0e6", "amber": "#faecd2", "gray": "#e8ecf1", "rose": "#f6e0e0"}
ARROW_COLORS = [LINE, GREEN_L, BLUE_L, ORANGE, RED]


def mid(c):
    return "m" + c.strip("#")


class Svg:
    def __init__(self, w, h):
        self.w, self.h, self.p = w, h, []

    def add(self, s):
        self.p.append(s)

    # ---- primitivas
    def rect(self, x, y, w, h, fill="#ffffff", stroke=LINE, rx=8, sw=1.4, dash=None, op=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        o = f' opacity="{op}"' if op else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}{o}/>')

    def card(self, x, y, w, h, tone=None, rx=10, sw=1.4):
        """Tarjeta con sombra vectorial."""
        self.add(f'<rect x="{x+3}" y="{y+4}" width="{w}" height="{h}" rx="{rx}" fill="#1b2533" opacity="0.10"/>')
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="#ffffff" stroke="{LINE}" stroke-width="{sw}"/>')

    def header(self, x, y, w, h, tone, rx=10):
        """Banda superior con degradado y esquinas superiores redondeadas."""
        gid = f"g_{tone}"
        self.add(f'<path d="M{x},{y+h} V{y+rx} Q{x},{y} {x+rx},{y} H{x+w-rx} Q{x+w},{y} {x+w},{y+rx} V{y+h} Z" '
                 f'fill="url(#{gid})" stroke="{LINE}" stroke-width="1.4"/>')

    def text(self, x, y, s, size=14, weight="normal", anchor="start", fill=INK, style="normal"):
        self.add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" font-style="{style}" text-anchor="{anchor}" fill="{fill}">{escape(s)}</text>')

    def line(self, x1, y1, x2, y2, dash=None, arrow=True, sw=1.8, color=LINE, both=False):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        m = f' marker-end="url(#{mid(color)})"' if arrow else ""
        ms = f' marker-start="url(#{mid(color)}s)"' if both else ""
        self.add(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"{d}{m}{ms}/>')

    def path(self, d, dash=None, arrow=True, sw=1.8, color=LINE, both=False):
        ds = f' stroke-dasharray="{dash}"' if dash else ""
        m = f' marker-end="url(#{mid(color)})"' if arrow else ""
        ms = f' marker-start="url(#{mid(color)}s)"' if both else ""
        self.add(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{ds}{m}{ms}/>')

    def num(self, cx, cy, n, r=13, fill=LINE):
        self.add(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}"/>')
        self.text(cx, cy + 5, str(n), size=15, weight="bold", anchor="middle", fill="#ffffff")

    def chip(self, cx, cy, lines, color=LINE, w=None):
        """Etiqueta flotante (pastilla) con 1-2 lineas."""
        if isinstance(lines, str):
            lines = [lines]
        w = w or (max(len(l) for l in lines) * 7.6 + 20)
        h = 10 + 18 * len(lines)
        self.add(f'<rect x="{cx-w/2}" y="{cy-h/2}" width="{w}" height="{h}" rx="{h/2 if len(lines)==1 else 8}" fill="#ffffff" stroke="{color}" stroke-width="1.2"/>')
        for i, l in enumerate(lines):
            self.text(cx, cy - h / 2 + 19 + i * 18 - (0 if len(lines) > 1 else 1), l, size=14, anchor="middle", fill=color if color != LINE else INK)

    def badge(self, cx, cy, icon_name, tone="blue", r=22):
        self.add(f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{SOLID[tone]}" stroke="{LINE}" stroke-width="1.3"/>')
        icon(self, icon_name, cx, cy, k=r / 24)

    def save(self, name):
        defs = ""
        for c in ARROW_COLORS:
            defs += (f'<marker id="{mid(c)}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">'
                     f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>'
                     f'<marker id="{mid(c)}s" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
                     f'<path d="M10,0 L0,5 L10,10 z" fill="{c}"/></marker>')
        for t, (a, b) in TONES.items():
            defs += (f'<linearGradient id="g_{t}" x1="0" y1="0" x2="0" y2="1">'
                     f'<stop offset="0" stop-color="{a}"/><stop offset="1" stop-color="{b}"/></linearGradient>')
        head = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
                f'viewBox="0 0 {self.w} {self.h}" font-family="{FONT}">\n<defs>{defs}</defs>\n'
                f'<rect width="{self.w}" height="{self.h}" fill="#ffffff"/>\n')
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
            f.write(head + "\n".join(self.p) + "\n</svg>\n")


# ------------------------------------------------------------------ iconos (dibujados en el origen, ~48x48)
def icon(s, name, cx, cy, k=1.0, col=INK):
    g = []
    A = g.append
    st = f'fill="none" stroke="{col}" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"'
    if name == "server":
        A(f'<rect x="-13" y="-14" width="26" height="12" rx="2.5" {st}/><rect x="-13" y="2" width="26" height="12" rx="2.5" {st}/>')
        A(f'<circle cx="7" cy="-8" r="1.6" fill="{col}"/><circle cx="7" cy="8" r="1.6" fill="{col}"/>')
        A(f'<path d="M-9,-8 H-1 M-9,8 H-1" {st}/>')
    elif name == "db":
        A(f'<ellipse cx="0" cy="-10" rx="12" ry="4.5" {st}/>')
        A(f'<path d="M-12,-10 V10 A12,4.5 0 0 0 12,10 V-10 M-12,0 A12,4.5 0 0 0 12,0" {st}/>')
    elif name == "monitor":
        A(f'<rect x="-15" y="-12" width="30" height="21" rx="2.5" {st}/><path d="M0,9 V14 M-7,14 H7" {st}/>')
        A(f'<rect x="-9" y="-3" width="4" height="7" fill="{col}"/><rect x="-2" y="-7" width="4" height="11" fill="{col}"/><rect x="5" y="-5" width="4" height="9" fill="{col}"/>')
    elif name == "chip":
        A(f'<rect x="-10" y="-10" width="20" height="20" rx="3" {st}/>')
        A(f'<path d="M-5,-10 V-15 M0,-10 V-15 M5,-10 V-15 M-5,10 V15 M0,10 V15 M5,10 V15 M-10,-5 H-15 M-10,0 H-15 M-10,5 H-15 M10,-5 H15 M10,0 H15 M10,5 H15" {st}/>')
        A(f'<text x="0" y="4" font-size="10" font-weight="bold" text-anchor="middle" fill="{col}">IA</text>')
    elif name == "shield":
        A(f'<path d="M0,-15 L12,-10 V0 C12,8 6,13 0,16 C-6,13 -12,8 -12,0 V-10 Z" {st}/><path d="M-5,0 L-1,4 L6,-4" {st}/>')
    elif name == "chain":
        A(f'<rect x="-17" y="-6" width="11" height="12" rx="2" {st}/><rect x="-5.5" y="-6" width="11" height="12" rx="2" {st}/><rect x="6" y="-6" width="11" height="12" rx="2" {st}/>')
        A(f'<path d="M-6,0 H-5.5 M5.5,0 H6" {st}/>')
    elif name == "api":
        A(f'<text x="0" y="7" font-size="21" font-weight="bold" text-anchor="middle" fill="{col}">{{ }}</text>')
    elif name == "switch":
        A(f'<rect x="-16" y="-9" width="32" height="18" rx="3" {st}/>')
        A(f'<path d="M-9,-3 H9 M5,-6.5 L9,-3 L5,0.5 M9,3 H-9 M-5,-0.5 L-9,3 L-5,6.5" {st} transform="translate(0,0) scale(0.8)"/>')
    elif name == "laptop":
        A(f'<rect x="-12" y="-11" width="24" height="16" rx="2.5" {st}/><path d="M-16,9 H16 L13,5 H-13 Z" {st}/>')
        A(f'<text x="0" y="1.5" font-size="13" font-weight="bold" text-anchor="middle" fill="{RED}">!</text>')
    elif name == "user":
        A(f'<circle cx="0" cy="-6" r="6" {st}/><path d="M-12,13 C-12,2 12,2 12,13 Z" {st}/>')
    elif name == "mail":
        A(f'<rect x="-14" y="-9" width="28" height="18" rx="2.5" {st}/><path d="M-14,-9 L0,2 L14,-9" {st}/>')
    elif name == "traffic":
        A(f'<path d="M-14,-6 H10 M5,-11 L11,-6 L5,-1 M14,6 H-10 M-5,1 L-11,6 L-5,11" {st}/>')
    elif name == "funnel":
        A(f'<path d="M-13,-11 H13 L4,0 V11 L-4,8 V0 Z" {st}/>')
    elif name == "merge":
        A(f'<path d="M-13,-9 L-1,0 L-13,9 M-1,0 H13 M8,-5 L13,0 L8,5" {st}/>')
    elif name == "split":
        A(f'<path d="M-13,0 H-1 M-1,0 L10,-9 M-1,0 L10,9 M5,-10 H10 V-5 M5,10 H10 V5" {st}/>')
    elif name == "balance":
        A(f'<path d="M0,-12 V12 M-6,12 H6 M-13,-7 H13 M-13,-7 V0 M13,-7 V0" {st}/>')
        A(f'<path d="M-17,0 Q-13,6 -9,0 Z M9,0 Q13,6 17,0 Z" {st}/>')
    elif name == "tree":
        A(f'<circle cx="0" cy="-9" r="3.6" {st}/><circle cx="-9" cy="8" r="3.6" {st}/><circle cx="9" cy="8" r="3.6" {st}/><path d="M-2,-6 L-8,5 M2,-6 L8,5" {st}/>')
    elif name == "chart":
        A(f'<rect x="-12" y="2" width="6" height="9" fill="{col}"/><rect x="-3" y="-4" width="6" height="15" fill="{col}"/><rect x="6" y="-11" width="6" height="22" fill="{col}"/>')
    elif name == "package":
        A(f'<path d="M0,-12 L12,-6 V7 L0,13 L-12,7 V-6 Z M-12,-6 L0,0 L12,-6 M0,0 V13" {st}/>')
    s.add(f'<g transform="translate({cx},{cy}) scale({k})">{"".join(g)}</g>')



# ================================================================== 1. SECUENCIA
def fig_secuencia():
    W, H = 1275, 950
    s = Svg(W, H)
    parts = [("Tráfico de red", "switch", "gray"), ("Motor de IA", "chip", "green"), ("Ryu + OVS", "shield", "green"),
             ("Backend", "api", "blue"), ("MongoDB", "db", "blue"), ("Solana", "chain", "blue"),
             ("Servidor SMTP", "mail", "amber"), ("Dashboard", "monitor", "gray")]
    X = [95 + 155 * i for i in range(8)]
    top, bot = 20, 925
    for x, (t, ic, tone) in zip(X, parts):
        s.card(x - 72, top, 144, 88)
        s.header(x - 72, top, 144, 88, tone)
        s.badge(x, top + 28, ic, tone, r=19)
        s.text(x, top + 71, t, size=16, weight="bold", anchor="middle")
        s.line(x, top + 88, x, bot, dash="5 5", arrow=False, sw=1.3, color="#9aa8ba")
    tr, ia, ry, be, mo, so, sm, da = X

    def m(x1, x2, y, label, n, dashed=False, col=LINE):
        s.line(x1, y, x2, y, dash="6 4" if dashed else None, color=col, sw=2.2)
        s.text((x1 + x2) / 2, y - 10, label, size=15.5, anchor="middle")
        s.num(x1 - 26 if x2 > x1 else x1 + 26, y, n, fill=col)

    def note(xc, y, w, lines, tone="amber", n=None):
        h = 16 + 22 * len(lines)
        s.card(xc - w / 2, y, w, h, rx=7, sw=1.2)
        s.rect(xc - w / 2, y, w, h, fill=SOLID[tone], rx=7, sw=1.2)
        for i, l in enumerate(lines):
            s.text(xc, y + 26 + i * 22, l, size=15, anchor="middle")
        if n:
            s.num(xc - w / 2 - 18, y + h / 2, n)

    m(tr, ia, 150, "paquetes", 1, col=BLUE_L)
    note(ia, 176, 262, ["Agrupa por flujo (5-tupla)", "y extrae 78 características"], n=2)
    note(ia, 256, 262, ["LightGBM → clase + confianza", "Alerta si clase ≠ BENIGN", "y confianza ≥ umbral"], n=3)
    m(ia, ry, 385, "POST /ips/block", 4, col=GREEN_L)
    note(ry, 405, 236, ["FlowMod: DROP", "ipv4_src · prioridad 100"], tone="rose")
    m(ia, be, 505, "POST /api/alerts · X-API-Key", 5, col=ORANGE)
    m(be, mo, 561, "guardar alerta", 6)
    m(be, sm, 617, "correo a operadores (async)", 7, dashed=True)
    m(be, so, 673, "Memo AUDIT_IPS (async)", 8, dashed=True)
    m(so, be, 729, "firma", 9, dashed=True)
    m(be, mo, 785, "estado Solana", 10)
    m(da, be, 841, "GET /api/alerts (JWT)", 11, col=ORANGE)
    m(be, da, 897, "alertas en JSON", 12, dashed=True, col=ORANGE)
    s.save("fig_flujo_alerta.svg")


# ================================================================== 2. MODELO DE DATOS
def table(s, x, y, w, title, rows, tone="blue"):
    rh = 32
    h = 48 + rh * len(rows)
    s.card(x, y, w, h)
    s.header(x, y, w, 48, tone)
    s.badge(x + 28, y + 24, "db", tone, r=16)
    s.text(x + 56, y + 31, title, size=18, weight="bold")
    for i, (name, typ, pk) in enumerate(rows):
        yy = y + 48 + i * rh
        if i % 2 == 1:
            s.rect(x + 1, yy, w - 2, rh, fill="#f6f8fb", stroke="none", rx=0, sw=0)
        s.text(x + 16, yy + 22, name, size=16, weight="bold" if pk else "normal")
        s.text(x + w - 14, yy + 22, typ, size=14.5, anchor="end", fill=MUTED)
        if pk:
            bx = x + w - 14 - len(typ) * 7.4 - 44
            s.rect(bx, yy + 6, 32, 20, fill="#f6e0e0", stroke=RED, rx=4, sw=1)
            s.text(bx + 16, yy + 21, "PK", size=12.5, weight="bold", anchor="middle", fill=RED)
    return h


def fig_bd():
    s = Svg(1230, 1010)
    s.text(30, 40, "Base de datos MongoDB · cyberdefense", size=19, weight="bold", fill=MUTED)
    table(s, 30, 70, 530, "alerts", [
        ("_id", "ObjectId", True), ("attack_type", "string", False), ("confidence", "float (0–100)", False),
        ("attacker_ip", "string", False), ("victim_ip", "string", False), ("victim_port", "int", False),
        ("action_taken", "string", False), ("timestamp", "ISO-8601 UTC", False),
        ("email_notification", "objeto {status, …}", False), ("blockchain_signature", "string", False),
        ("blockchain_status", "pending | confirmed | unconfirmed", False)], "blue")
    table(s, 670, 70, 530, "users", [
        ("_id (username)", "string", True), ("password_hash", "bcrypt", False), ("role", "operator | admin", False),
        ("active", "bool", False), ("email", "string", False), ("created_at", "ISO-8601", False), ("created_by", "string", False)], "blue")
    table(s, 670, 380, 530, "email_notification_dedup", [
        ("_id", "SHA-256(huella|ventana)", True), ("expires_at", "índice TTL", False)], "amber")
    table(s, 670, 530, 530, "system_status", [
        ("_id", "\"network\"", True), ("blocked", "bool", False), ("updated_at", "ISO-8601", False), ("reason", "string", False)], "rose")
    table(s, 670, 744, 530, "system_config", [
        ("_id", "\"global\"", True), ("pollInterval", "int (ms)", False), ("attackWindow", "int", False),
        ("timelineSize", "int", False), ("logSize", "int", False), ("widgets", "objeto {bool}", False)], "gray")
    # Solana (externo)
    s.card(30, 560, 530, 150)
    s.header(30, 560, 530, 48, "green")
    s.badge(58, 584, "chain", "green", r=16)
    s.text(86, 591, "Solana (libro mayor externo)", size=18, weight="bold")
    s.text(295, 645, "Transacción Memo «AUDIT_IPS |", size=15.5, anchor="middle", fill=MUTED)
    s.text(295, 667, "tipo | atacante | víctima | confianza |", size=15.5, anchor="middle", fill=MUTED)
    s.text(295, 689, "acción | fecha»", size=15.5, anchor="middle", fill=MUTED)
    # relaciones
    s.line(560, 140, 670, 140, dash="6 4", color=ORANGE, sw=2.2)
    s.chip(615, 112, "notifica", color=ORANGE, w=92)
    s.line(560, 440, 670, 436, dash="6 4", color=ORANGE, sw=2.2)
    s.chip(615, 408, "deduplica", color=ORANGE, w=100)
    s.line(560, 455, 670, 612, dash="6 4", color=ORANGE, sw=2.2)
    s.chip(615, 548, "bloquea", color=ORANGE, w=88)
    s.line(295, 468, 295, 560, dash="6 4", color=ORANGE, sw=2.2)
    s.chip(295, 514, "audita", color=ORANGE, w=84)
    s.save("fig_modelo_bd.svg")


# ================================================================== 3. PIPELINE IA (sin despliegue)
def fig_ia():
    s = Svg(1170, 1210)
    bw, bh, x0, x1 = 520, 246, 40, 610
    ys = [30, 336, 642, 948]
    cajas = [
        ("1", "Fuentes de datos", "db", "blue", ["CIC-IDS2017 (8 archivos CSV)", "CIC-IDS2018, solo refuerzo de:", "Bot, Infiltration, XSS,", "SQL Injection"]),
        ("2", "Limpieza", "funnel", "blue", ["Elimina la clase Heartbleed", "Quita la columna duplicada", "(Fwd Header Length.1)", "Normaliza etiquetas y nombres", "NaN/Inf → 0 si duración = 0"]),
        ("3", "Integración", "merge", "blue", ["Homologa las columnas de 2018", "al esquema de 2017", "78 características", "2 966 190 flujos · 14 clases"]),
        ("4", "Partición", "split", "blue", ["Estratificada 80 % / 20 %", "random_state = 42", "Prueba: 593 238 flujos", "sin balancear (distribución real)"]),
        ("5", "Balanceo (solo entrenamiento)", "balance", "green", ["SMOTE: XSS, SQL Injection → 30 000", "Submuestreo de BENIGN → 500 000", "SMOTE: 6 clases menores → 20 000", "Entrenamiento: 1 205 562 flujos"]),
        ("6", "Entrenamiento", "tree", "green", ["LightGBM multiclase (14 clases)", "300 árboles · learning rate 0,05", "max_depth 12 · num_leaves 128", "min_child_samples 100", "subsample = colsample = 0,8"]),
        ("7", "Evaluación offline", "chart", "amber", ["Accuracy = 0,9978", "Macro: P 0,93 · R 0,94 · F1 0,93", "Clases débiles (poco soporte):", "XSS, SQL Injection,", "Web Attack Brute Force"]),
    ]
    pos = []
    for i, (n, tit, ic, tone, lines) in enumerate(cajas):
        r, c = divmod(i, 2)
        x, y = (x0 if c == 0 else x1), ys[r]
        pos.append((x, y))
        s.card(x, y, bw, bh)
        s.header(x, y, bw, 62, tone)
        s.badge(x + 36, y + 31, ic, tone, r=22)
        s.text(x + 72, y + 38, tit, size=19, weight="bold")
        s.num(x + bw - 30, y + 31, n, r=15)
        for j, l in enumerate(lines):
            s.text(x + 24, y + 104 + j * 30, l, size=17)
    # artefactos
    ax, ay = x1, ys[3]
    s.rect(ax, ay, bw, bh, fill="#f6f8fb", dash="8 5", rx=10)
    s.badge(ax + 36, ay + 31, "package", "gray", r=22)
    s.text(ax + 72, ay + 38, "Artefactos generados", size=19, weight="bold")
    s.text(ax + 24, ay + 110, "lightgbm_1_2M_final.txt", size=17, weight="bold")
    s.text(ax + 24, ay + 136, "modelo entrenado (Booster)", size=15, fill=MUTED)
    s.text(ax + 24, ay + 180, "label_encoder_1_2M_final.pkl", size=17, weight="bold")
    s.text(ax + 24, ay + 206, "codificador de las 14 clases", size=15, fill=MUTED)
    # flechas horizontales (1->2, 3->4, 5->6, 7->artefactos)
    for i in (0, 2, 4):
        (xa, ya), (xb, yb) = pos[i], pos[i + 1]
        s.line(xa + bw + 3, ya + 31, xb - 3, yb + 31, sw=2.4)
    # 7 (columna izq) -> artefactos (columna der)
    s.line(pos[6][0] + bw + 3, pos[6][1] + 31, ax - 3, ay + 31, sw=2.4, dash="6 4")
    # codos (2->3, 4->5, 6->7)
    for i in (1, 3, 5):
        (xa, ya), (xb, yb) = pos[i], pos[i + 1]
        s.path(f"M{xa + bw/2},{ya + bh + 3} V{ya + bh + 30} H{xb + bw/2} V{yb - 4}", sw=2.4)
    s.save("fig_pipeline_ia.svg")


# ================================================================== 4. TOPOLOGIA
def svc_card(s, x, y, w, h, icon_name, tone, title, sub):
    s.card(x, y, w, h, rx=9)
    s.badge(x + 38, y + h / 2, icon_name, tone, r=22)
    s.text(x + 74, y + h / 2 - 4, title, size=17, weight="bold")
    s.text(x + 74, y + h / 2 + 20, sub, size=14, fill=MUTED)


def node_card(s, x, y, w, h, icon_name, tone, title, ip, role):
    s.card(x, y, w, h)
    s.header(x, y, w, 48, tone)
    s.badge(x + 32, y + 24, icon_name, tone, r=19)
    s.text(x + 64, y + 31, title, size=18, weight="bold")
    s.text(x + 20, y + 76, ip, size=17, weight="bold")
    s.text(x + 20, y + 100, role, size=14, fill=MUTED)
    s.text(x + 20, y + 124, "eth1 SDN_Net · eth2 virbr0 (NAT)", size=13.5, fill=MUTED)


def fig_topologia():
    W, H = 1170, 1430
    s = Svg(W, H)
    # Operador
    s.card(30, 20, 180, 112)
    s.badge(120, 55, "user", "gray", r=24)
    s.text(120, 106, "Operador", size=17, weight="bold", anchor="middle")
    s.text(120, 124, "navegador", size=14, anchor="middle", fill=MUTED)
    # Host
    s.card(20, 172, 1130, 1140, rx=14, sw=2)
    s.header(20, 172, 1130, 52, "dark", rx=14)
    s.text(1130, 206, "Host de CyberDefense · Ubuntu · VNX + LXC + Open vSwitch", size=18, weight="bold", fill="#ffffff", anchor="end")
    s.badge(48, 198, "server", "gray", r=18)

    # Plano de aplicacion
    s.rect(40, 244, 1090, 220, fill="#f6f8fb", dash="7 5", rx=12, sw=1.3)
    s.text(1110, 272, "PLANO DE APLICACIÓN", size=14, weight="bold", fill=MUTED, anchor="end")
    cw, ch, cy = 232, 112, 296
    xs = [56, 324, 592, 860]
    svc_card(s, xs[0], cy, cw, ch, "monitor", "gray", "Dashboard", "React · Vite :5173")
    svc_card(s, xs[1], cy, cw, ch, "api", "blue", "Backend", "FastAPI :8001 · JWT")
    svc_card(s, xs[2], cy, cw, ch, "db", "blue", "MongoDB", "Docker :27017")
    svc_card(s, xs[3], cy, cw, ch, "chain", "blue", "Solana", "validator :8899")
    s.line(xs[0] + cw + 3, cy + ch / 2, xs[1] - 3, cy + ch / 2, both=True, sw=2.2)
    s.line(xs[1] + cw + 3, cy + ch / 2, xs[2] - 3, cy + ch / 2, sw=2.2)
    s.path(f"M{xs[1] + cw/2 + 40},{cy - 2} V{cy - 18} H{xs[3] + cw/2} V{cy - 4}", sw=2.2, dash="6 4")
    # Operador -> Dashboard
    s.line(xs[0] + cw / 2, 134, xs[0] + cw / 2, cy - 3, color=ORANGE, sw=2.4)
    s.chip(xs[0] + cw / 2, 152, "HTTP", color=ORANGE, w=70)

    # Plano de seguridad
    s.rect(40, 494, 1090, 196, fill="#f6f8fb", dash="7 5", rx=12, sw=1.3)
    s.text(1110, 522, "PLANO DE SEGURIDAD", size=14, weight="bold", fill=MUTED, anchor="end")
    svc_card(s, 56, 540, 450, 112, "chip", "green", "Motor de IA", "Scapy + LightGBM · 78 características")
    svc_card(s, 636, 540, 450, 112, "shield", "green", "Controlador Ryu", "OpenFlow 1.3 :6653 · REST :8080")
    s.line(509, 612, 633, 612, color=GREEN_L, sw=2.4)
    s.chip(571, 584, "POST /ips/block", color=GREEN_L, w=124)
    # Motor IA -> Backend (alertas)
    s.line(440, 540, 440, cy + ch + 3, color=ORANGE, sw=2.4)
    s.chip(440, 477, "alertas · REST", color=ORANGE, w=136)

    # Red virtual VNX
    s.rect(40, 720, 1090, 570, fill="#f3f7fc", dash="9 6", rx=14, sw=1.5)
    s.text(60, 748, "RED VIRTUAL VNX · PLANO DE DATOS", size=14, weight="bold", fill=MUTED)
    ox, oy, ow, oh = 56, 810, 380, 240
    s.card(ox, oy, ow, oh)
    s.header(ox, oy, ow, 52, "rose")
    s.badge(ox + 34, oy + 26, "switch", "rose", r=20)
    s.text(ox + 68, oy + 34, "Open vSwitch", size=19, weight="bold")
    s.text(ox + 22, oy + 88, "puente SDN_Net", size=17, weight="bold")
    s.text(ox + 22, oy + 114, "OpenFlow 1.3 · fail-mode secure", size=14, fill=MUTED)
    s.text(ox + 22, oy + 136, "controlador tcp:127.0.0.1:6653", size=14, fill=MUTED)
    for i in range(6):
        px = ox + 24 + i * 56
        s.rect(px, oy + oh - 52, 40, 26, fill="#dce8f5" if i < 4 else "#f3f6fa", stroke=LINE, rx=4, sw=1.2)
        s.text(px + 20, oy + oh - 33, str(i + 1), size=13.5, anchor="middle", fill=MUTED)
    s.text(ox + 24, oy + oh - 10, "puertos del switch", size=13.5, fill=MUTED)
    nx, nw, nh = 700, 400, 146
    nodes = [(790, "server", "blue", "server1", "192.168.1.10/24", "servidor de aplicación (web)"),
             (962, "server", "blue", "server2", "192.168.1.11/24", "servidor de datos (BD)"),
             (1134, "laptop", "amber", "attacker", "192.168.1.50/24", "nmap · hydra · hping3 · slowhttptest")]
    for y, ic, tone, t, ip, role in nodes:
        node_card(s, nx, y, nw, nh, ic, tone, t, ip, role)
        cyy = y + nh / 2
        s.path(f"M{ox + ow},{oy + oh/2} C560,{oy + oh/2} 590,{cyy} {nx},{cyy}", sw=3.4, color=LINE, arrow=False)
    s.chip(574, 900, "tráfico de datos", color=LINE, w=160)
    # control y captura
    s.path("M861,652 V768 H330 V808", color=GREEN_L, sw=2.8, both=True)
    s.chip(596, 768, "OpenFlow 1.3 · tcp:6653", color=GREEN_L, w=214)
    s.path("M130,808 V654", color=BLUE_L, sw=2.4, dash="7 5")
    s.chip(210, 700, ["captura", "server1-e1"], color=BLUE_L, w=118)

    # Leyenda
    ly = 1334
    s.card(20, ly, 1130, 78, rx=10)
    items = [(LINE, None, "Tráfico de datos"), (GREEN_L, None, "Control OpenFlow"),
             (BLUE_L, "7 5", "Captura de tráfico"), (ORANGE, None, "Alertas · REST · HTTP")]
    lx = 44
    for col, dash, lab in items:
        s.line(lx, ly + 28, lx + 44, ly + 28, color=col, dash=dash, sw=2.8, arrow=False)
        s.text(lx + 54, ly + 34, lab, size=15)
        lx += 54 + len(lab) * 8.4 + 28
    s.text(44, ly + 62, "Todos los nodos salen a Internet por eth2 (NAT virbr0), solo para instalar herramientas.", size=14, fill=MUTED)
    s.save("fig_topologia.svg")


for f in (fig_secuencia, fig_bd, fig_ia, fig_topologia):
    f()
print("ok", sorted(os.listdir(OUT)))
