"""Correo de alertas de seguridad y plantilla post-incidente.

La configuración SMTP se lee del entorno para no guardar credenciales en
MongoDB ni exponerlas al frontend. Las pruebas pueden inyectar SMTPSettings.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from html import escape
import os
import re
import smtplib
import ssl
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class SMTPSettings:
    host: str
    port: int
    username: str
    password: str
    sender_email: str
    sender_name: str
    use_ssl: bool
    starttls: bool
    timeout: float
    subject_prefix: str

    @property
    def missing_fields(self) -> list[str]:
        missing = []
        if not self.host:
            missing.append("SMTP_HOST")
        if not self.username:
            missing.append("SMTP_USERNAME")
        if not self.password:
            missing.append("SMTP_PASSWORD")
        if not self.sender_email:
            missing.append("SMTP_FROM_EMAIL")
        if self.use_ssl and self.starttls:
            missing.append("SMTP_USE_SSL y SMTP_STARTTLS no pueden estar activos juntos")
        return missing

    @property
    def configured(self) -> bool:
        return not self.missing_fields


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "si", "sí", "on"}


def load_smtp_settings() -> SMTPSettings:
    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        port = 587
    try:
        timeout = max(3.0, min(60.0, float(os.getenv("SMTP_TIMEOUT", "15"))))
    except ValueError:
        timeout = 15.0

    username = os.getenv("SMTP_USERNAME", "").strip()
    use_ssl = _env_bool("SMTP_USE_SSL", port == 465)
    return SMTPSettings(
        host=os.getenv("SMTP_HOST", "").strip(),
        port=port,
        username=username,
        password=os.getenv("SMTP_PASSWORD", ""),
        sender_email=os.getenv("SMTP_FROM_EMAIL", username).strip(),
        sender_name=os.getenv("SMTP_FROM_NAME", "CyberDefense AI").replace("\r", " ").replace("\n", " ").strip(),
        use_ssl=use_ssl,
        starttls=_env_bool("SMTP_STARTTLS", not use_ssl),
        timeout=timeout,
        subject_prefix=os.getenv("EMAIL_SUBJECT_PREFIX", "[CyberDefense AI]").strip(),
    )


def email_configuration_status(settings: SMTPSettings | None = None) -> dict:
    cfg = settings or load_smtp_settings()
    return {
        "configured": cfg.configured,
        "sender": cfg.sender_email if cfg.configured else None,
        "missing": cfg.missing_fields,
        "host": cfg.host or None,
        "port": cfg.port,
    }


def severity_for(confidence) -> tuple[str, str]:
    try:
        score = float(confidence)
    except (TypeError, ValueError):
        score = 0.0
    if score >= 90:
        return "CRÍTICA", "#b42332"
    if score >= 75:
        return "ALTA", "#c75b13"
    if score >= 50:
        return "MEDIA", "#a16c00"
    return "BAJA", "#087d94"


def _local_timestamp(value) -> str:
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        try:
            stamp = stamp.astimezone(ZoneInfo("America/Guayaquil"))
        except Exception:
            stamp = stamp.astimezone()
        return stamp.strftime("%d/%m/%Y %H:%M:%S %Z")
    except Exception:
        return str(value or "No disponible")


def _asset_label(ip: str) -> str:
    assets = {
        "192.168.1.50": "attacker (nodo de pruebas)",
        "192.168.20.50": "attacker (interfaz VLAN 20)",
        "192.168.30.50": "attacker (interfaz VLAN 30)",
        "192.168.1.10": "server1 (servidor de pruebas)",
        "192.168.1.11": "server2 (servidor de pruebas)",
        "192.168.1.12": "server3 (servidor de pruebas)",
        "192.168.1.13": "server4 (servidor de pruebas)",
        "192.168.1.14": "server5 (servidor de pruebas)",
        "192.168.20.11": "lab1pc1 (Laboratorio 1)",
        "192.168.20.12": "lab1pc2 (Laboratorio 1)",
        "192.168.30.11": "lab2pc1 (Laboratorio 2)",
        "192.168.30.12": "lab2pc2 (Laboratorio 2)",
    }
    return assets.get(ip, "equipo sin nombre registrado")


def _is_block_action(action: str) -> bool:
    lowered = (action or "").lower()
    return any(token in lowered for token in ("drop", "block", "deny", "bloque"))


def recommendations_for(attack_type: str) -> tuple[str, list[str], list[str]]:
    kind = re.sub(r"[^a-z0-9]+", "_", (attack_type or "").lower())
    if any(k in kind for k in ("brute", "hydra", "fuerza_bruta", "ssh")):
        impact = "Se observó tráfico de autenticación dirigido al servicio del equipo víctima. El evento no confirma por sí solo que una sesión haya sido establecida ni que el host esté comprometido."
        recommendations = [
            "Revisar los registros de autenticación y confirmar si hubo inicios de sesión exitosos desde el origen observado.",
            "Restringir SSH a las redes administrativas autorizadas; validar antes cualquier cambio de firewall.",
            "Usar llaves SSH, MFA cuando esté disponible y credenciales únicas; aplicar el procedimiento institucional de rotación si se confirma exposición.",
            "Verificar parches del servicio SSH y configurar límites de intentos conforme a la política del Centro de Datos.",
        ]
        commands = [
            "sudo journalctl -u ssh --since '15 minutes ago'",
            "sudo grep -E 'Failed password|Invalid user' /var/log/auth.log | tail -n 50",
        ]
    elif any(k in kind for k in ("ddos", "dos", "flood", "slowhttptest", "syn")):
        impact = "Se observó un volumen o patrón de solicitudes hacia el equipo víctima. El evento no mide por sí solo indisponibilidad del servicio; confirme latencia, pérdida de paquetes y uso de recursos."
        recommendations = [
            "Comparar el periodo del evento con métricas de CPU, memoria, conexiones y disponibilidad del servicio.",
            "Revisar contadores del switch y aplicar límites de tasa o filtros en el punto de control aprobado.",
            "Si el tráfico supera el laboratorio, coordinar con el proveedor de red antes de aplicar mitigaciones aguas arriba.",
        ]
        commands = [
            "sudo ovs-ofctl -O OpenFlow13 dump-ports SDN_Net",
            "sudo ovs-ofctl -O OpenFlow13 dump-flows SDN_Net",
            "ss -s",
        ]
    elif any(k in kind for k in ("scan", "nmap", "recon", "portscan", "port_scan")):
        impact = "El patrón observado es compatible con reconocimiento de servicios o puertos expuestos. El escaneo no confirma explotación ni acceso al equipo."
        recommendations = [
            "Contrastar puertos expuestos con el inventario y el uso autorizado del servidor.",
            "Cerrar o filtrar servicios innecesarios mediante un cambio revisado por el equipo responsable.",
            "Limitar la administración y los servicios de diagnóstico a segmentos de gestión autorizados.",
        ]
        commands = [
            "sudo ss -lntup",
            "sudo ovs-ofctl -O OpenFlow13 dump-flows SDN_Net",
        ]
    elif "arp" in kind:
        impact = "Se observó una anomalía asociada a resolución ARP. Verifique si existe conflicto de direcciones o una asociación IP/MAC no autorizada; el evento no confirma por sí solo interceptación de tráfico."
        recommendations = [
            "Comparar la asociación IP/MAC con el inventario y las concesiones DHCP vigentes.",
            "Revisar la segmentación de capa 2 y habilitar DHCP snooping o Dynamic ARP Inspection donde la infraestructura lo soporte.",
            "Aislar un puerto únicamente después de corroborar el equipo y seguir el procedimiento aprobado.",
        ]
        commands = [
            "ip neigh show",
            "sudo ovs-ofctl -O OpenFlow13 dump-flows SDN_Net",
        ]
    elif "spoof" in kind or "suplant" in kind:
        impact = "Se observó una discrepancia o posible suplantación de identidad de red. Verifique la dirección de origen contra el segmento y el inventario; el evento no prueba que se haya accedido a datos."
        recommendations = [
            "Validar la dirección de origen, el segmento de entrada y la asignación IP/MAC autorizada.",
            "Aplicar filtrado de ingreso o controles anti-spoofing coherentes con la política de cada segmento.",
            "Revisar las reglas OpenFlow y los registros del controlador antes de modificar flujos.",
        ]
        commands = [
            "ip neigh show",
            "sudo ovs-ofctl -O OpenFlow13 dump-flows SDN_Net",
        ]
    else:
        impact = "El detector registró un patrón clasificado como amenaza. La clase no basta para afirmar compromiso o pérdida de datos; confirme la actividad con los registros del activo y del controlador."
        recommendations = [
            "Correlacionar hora, origen y destino con los registros del host y del controlador SDN.",
            "Verificar si el servicio y el flujo estaban autorizados para ese segmento.",
            "Aplicar o mantener el bloqueo únicamente conforme a la política aprobada y documentar la revisión.",
        ]
        commands = [
            "sudo ovs-ofctl -O OpenFlow13 dump-flows SDN_Net",
            "sudo ss -lntup",
        ]
    return impact, recommendations, commands


def build_security_email(alert: dict, *, simulated: bool = False) -> tuple[str, str, str]:
    attack_type = str(alert.get("attack_type") or "Amenaza detectada")
    confidence = alert.get("confidence", 0)
    severity, severity_color = severity_for(confidence)
    attacker = str(alert.get("attacker_ip") or "No disponible")
    victim = str(alert.get("victim_ip") or "No disponible")
    port = alert.get("victim_port", "—")
    action = str(alert.get("action_taken") or "Sin acción informada")
    timestamp = _local_timestamp(alert.get("timestamp"))
    victim_asset = _asset_label(victim)
    blocked = _is_block_action(action)
    impact, recommendations, commands = recommendations_for(attack_type)

    if simulated:
        impact = "Evento sintético para verificar el canal de correo. No se generó tráfico de ataque, no se afectó un host y no se aplicó una regla de bloqueo."
        mitigation = "No aplica: esta prueba no modifica la red ni el estado del switch."
        marker = "[PRUEBA SIMULADA]"
        subject = "CyberDefense AI — verificación de notificación"
    else:
        mitigation = (
            f"El backend registró la acción {action}. La acción reportada no sustituye la verificación de los contadores del switch y del servicio afectado."
            if blocked else
            f"El backend registró la acción {action}; no consta un bloqueo automático en este evento. Revise el flujo y la política antes de intervenir."
        )
        marker = ""
        subject = f"{severity} · {attack_type} · {victim}"

    subject_prefix = load_smtp_settings().subject_prefix
    subject = " ".join(part for part in (subject_prefix, marker, subject) if part).strip()
    safe = lambda value: escape(str(value), quote=True)

    recommendations_text = "\n".join(f"  {i}. {item}" for i, item in enumerate(recommendations, 1))
    commands_text = "\n".join(f"  $ {command}" for command in commands)
    test_note = "PRUEBA SIMULADA: sin tráfico real ni cambios en la red.\n\n" if simulated else ""
    plain = (
        f"{test_note}CyberDefense AI — Notificación de seguridad\n"
        f"Severidad: {severity} | Confianza del detector: {float(confidence or 0):.1f}%\n\n"
        f"RESUMEN\nTipo: {attack_type}\nFecha y hora (Ecuador): {timestamp}\n"
        f"Origen: {attacker} ({_asset_label(attacker)})\n"
        f"Destino: {victim} ({victim_asset}), puerto {port}\nAcción reportada: {action}\n\n"
        f"AFECTACIÓN OBSERVADA\n{impact}\n\n"
        f"MITIGACIÓN\n{mitigation}\n\n"
        f"RECOMENDACIONES PARA SOPORTE\n{recommendations_text}\n\n"
        f"COMANDOS DE DIAGNÓSTICO (solo lectura)\n{commands_text}\n\n"
        "Los comandos son orientativos y deben ejecutarse en el equipo y contexto correctos. "
        "Valide cualquier cambio con el equipo de soporte y la autorización del cliente. "
        "Las recomendaciones no confirman compromiso ni sustituyen el análisis del incidente.\n"
    )

    recommendations_html = "".join(f"<li>{safe(item)}</li>" for item in recommendations)
    commands_html = "".join(
        f"<li><code>{safe(command)}</code></li>" for command in commands
    )
    test_banner = (
        '<div style="margin:0 0 20px;padding:12px 14px;border:1px solid #f2cc74;'
        'border-radius:8px;background:#fff8e5;color:#795400;font-weight:700;">'
        'PRUEBA SIMULADA · No se generó tráfico ni se modificó la red.</div>'
        if simulated else ""
    )
    html_body = f"""<!doctype html>
<html lang="es"><body style="margin:0;padding:24px;background:#eef3f8;color:#17263a;font-family:Arial,Helvetica,sans-serif;">
  <div style="max-width:720px;margin:0 auto;background:#ffffff;border:1px solid #dce5ef;border-radius:12px;overflow:hidden;">
    <div style="padding:22px 26px;background:#101a2e;color:#e8eef7;">
      <div style="font-size:11px;letter-spacing:1.5px;color:#87a1b8;text-transform:uppercase;">CyberDefense AI · ESPOL / FIEC</div>
      <h1 style="margin:10px 0 0;font-size:22px;line-height:1.3;">Notificación de seguridad</h1>
    </div>
    <div style="padding:24px 26px;">
      {test_banner}
      <div style="margin-bottom:18px;padding:14px 16px;border-left:4px solid {severity_color};background:#f7f9fc;">
        <div style="font-size:11px;color:#61738a;text-transform:uppercase;letter-spacing:1px;">{safe(marker or 'Evento detectado')}</div>
        <div style="margin-top:5px;font-size:19px;font-weight:700;color:{severity_color};">{safe(attack_type)} · {safe(severity)}</div>
        <div style="margin-top:5px;font-size:13px;color:#51647a;">Confianza del detector: {safe(f'{float(confidence or 0):.1f}%')}</div>
      </div>
      <h2 style="margin:22px 0 10px;font-size:15px;color:#14263a;">Resumen del evento</h2>
      <table role="presentation" style="width:100%;border-collapse:collapse;font-size:13px;">
        <tr><td style="padding:8px 0;color:#718197;width:155px;">Fecha (Ecuador)</td><td style="padding:8px 0;color:#17263a;">{safe(timestamp)}</td></tr>
        <tr><td style="padding:8px 0;color:#718197;">Origen</td><td style="padding:8px 0;color:#17263a;">{safe(attacker)} · {safe(_asset_label(attacker))}</td></tr>
        <tr><td style="padding:8px 0;color:#718197;">Destino / activo</td><td style="padding:8px 0;color:#17263a;">{safe(victim)} · {safe(victim_asset)} · puerto {safe(port)}</td></tr>
        <tr><td style="padding:8px 0;color:#718197;">Acción reportada</td><td style="padding:8px 0;color:#17263a;">{safe(action)}</td></tr>
      </table>
      <h2 style="margin:22px 0 8px;font-size:15px;color:#14263a;">Afectación observada</h2>
      <p style="margin:0;color:#40546b;font-size:13px;line-height:1.65;">{safe(impact)}</p>
      <h2 style="margin:22px 0 8px;font-size:15px;color:#14263a;">Mitigación</h2>
      <p style="margin:0;color:#40546b;font-size:13px;line-height:1.65;">{safe(mitigation)}</p>
      <h2 style="margin:22px 0 8px;font-size:15px;color:#14263a;">Recomendaciones para soporte</h2>
      <ol style="margin:0;padding-left:21px;color:#40546b;font-size:13px;line-height:1.7;">{recommendations_html}</ol>
      <h2 style="margin:22px 0 8px;font-size:15px;color:#14263a;">Comandos de diagnóstico · solo lectura</h2>
      <ul style="margin:0;padding:12px 18px 12px 34px;border-radius:8px;background:#101a2e;color:#e6edf6;font-size:12px;line-height:1.8;">{commands_html}</ul>
      <p style="margin:18px 0 0;padding-top:14px;border-top:1px solid #e3eaf1;color:#718197;font-size:11px;line-height:1.6;">
        Mensaje automático del prototipo. Las recomendaciones son orientativas: valide el equipo, el segmento y la autorización antes de ejecutar cambios. El evento no confirma por sí solo compromiso, exfiltración ni pérdida de datos.
      </p>
    </div>
  </div>
</body></html>"""
    return subject, plain, html_body


def send_email(settings: SMTPSettings, recipient: str, subject: str, plain: str, html_body: str) -> None:
    if not settings.configured:
        missing = ", ".join(settings.missing_fields)
        raise RuntimeError(f"SMTP no está configurado: {missing}")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((settings.sender_name or "CyberDefense AI", settings.sender_email))
    message["To"] = recipient
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain=settings.sender_email.partition("@")[2] or None)
    message.set_content(plain)
    message.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()
    if settings.use_ssl:
        with smtplib.SMTP_SSL(settings.host, settings.port, timeout=settings.timeout, context=context) as server:
            server.login(settings.username, settings.password)
            server.send_message(message)
        return

    with smtplib.SMTP(settings.host, settings.port, timeout=settings.timeout) as server:
        server.ehlo()
        if settings.starttls:
            server.starttls(context=context)
            server.ehlo()
        server.login(settings.username, settings.password)
        server.send_message(message)
