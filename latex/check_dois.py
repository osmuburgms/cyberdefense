#!/usr/bin/env python3
"""
Validador de DOIs para las referencias del Reporte del Proyecto Integrador.

Comprueba que cada DOI declarado en referencias.bib exista realmente en el
registro de Crossref y que el titulo registrado se corresponda con eltitulo
declarado en el .bib.

Uso:
    python3 check_dois.py                 # valida todo el .bib
    python3 check_dois.py 10.1145/2508859.2516684   # valida un DOI suelto
    python3 check_dois.py ryu2015onosr    # valida una clave del .bib

Codigo de salida:
    0 = todo correcto
    1 = hay DOIs invalidos o claves pedidas que no existen

Requiere: python3 (solo biblioteca estandar).
"""

import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BIB = "referencias.bib"
API = "https://api.crossref.org/works/"
UA = {"User-Agent": "cyberdefense-bibcheck/1.0 (mailto:alumno@espol.edu.ec)"}


# ---------------------------------------------------------------- utilidades
def normaliza(titulo):
    """Minusculas y solo alfanumericos, para comparar titulos tolerantes."""
    t = re.sub(r"[^a-z0-9]+", " ", titulo.lower())
    return " ".join(t.split())


def sin_doi_explicado(clave, tipo, cuerpo):
    """Explica por que una entrada va sin DOI y si deberia tener uno.

    Devuelve (estado, mensaje, doi_sugerido_o_None).
    """
    titulo = campo(cuerpo, "title")
    url = campo(cuerpo, "url")
    editorial = " ".join(
        [campo(cuerpo, "booktitle"), campo(cuerpo, "journaltitle"),
         campo(cuerpo, "institution"), campo(cuerpo, "publisher")]
    ).lower()

    # 1) editoriales conocidas que no asignan DOI (se comprueba antes que la URL)
    for marca, razon in (
        ("usenix", "sin DOI (USENIX no asigna DOI a sus proceedings)"),
        ("neural information processing systems", "sin DOI (NeurIPS no asigna DOI)"),
        ("nips", "sin DOI (NeurIPS no asigna DOI)"),
    ):
        if marca in editorial:
            return "OK", razon, None

    # 2) documentacion en linea / PDF con URL estable: el DOI no aplica
    if url or tipo in ("misc", "online", "www"):
        return "OK", "sin DOI (fuente web con URL estable, el DOI no aplica)", None

    # 3) buscar en Crossref por titulo: hay un DOI exacto que nos falte?
    try:
        for it in busca_crossref_titulo(titulo):
            real = (it.get("title") or [""])[0]
            if normaliza(real)[:70] == normaliza(titulo)[:70]:
                return "AVISO", "FALTA EL DOI: existe este registro con el mismo titulo", it["DOI"]
    except Exception:
        pass
    return "OK", "sin DOI (no hay DOI registrado para esta obra)", None


def busca_crossref_titulo(titulo):
    url = API + "?" + urllib.parse.urlencode({
        "query.title": titulo, "rows": "5",
        "select": "DOI,title,container-title,issued,page"})
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["message"]["items"]


def entradas_bib(ruta):
    """Devuelve [(clave, tipo, cuerpo)] de un archivo .bib."""
    with open(ruta, encoding="utf-8") as f:
        src = f.read()
    for m in re.finditer(r"@(\w+)\{([^,]+),(.*?)\n\}", src, re.S):
        yield m.group(2).strip(), m.group(1).lower(), m.group(3)


def campo(cuerpo, nombre):
    """Devuelve el valor de un campo del .bib, sea la ultima entrada o no.

    Admite los delimitadores { }, " " y valores con comas internas.
    """
    m = re.search(rf"(?:^|,)\s*{re.escape(nombre)}\s*=\s*", cuerpo, re.I | re.M)
    if not m:
        return ""
    i = m.end()
    if i >= len(cuerpo):
        return ""
    if cuerpo[i] == "{":
        depth = 0
        for j in range(i, len(cuerpo)):
            if cuerpo[j] == "{":
                depth += 1
            elif cuerpo[j] == "}":
                depth -= 1
                if depth == 0:
                    return " ".join(cuerpo[i + 1:j].split())
        return ""
    if cuerpo[i] == '"':
        j = cuerpo.find('"', i + 1)
        if j > 0:
            return " ".join(cuerpo[i + 1:j].split())
        return ""
    # valor sin delimitadores: hasta la coma o el fin de linea
    j = cuerpo.find(",", i)
    k = cuerpo.find("\n", i)
    fin = min(x for x in (j, k, len(cuerpo)) if x > 0)
    return " ".join(cuerpo[i:fin].split())


def consulta_crossref(doi):
    """(ok, mensaje, metadatos) para un DOI."""
    url = API + urllib.parse.quote(doi, safe="")
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=25) as r:
            return True, "registrado", json.load(r)["message"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False, "NO REGISTRADO en Crossref (404)", {}
        return False, f"error HTTP {e.code}", {}
    except Exception as e:  # red, timeout, JSON...
        return False, f"error de red: {type(e).__name__}", {}


def doi_resuelve(doi):
    """Comprueba que doi.org resuelva el DOI (red de seguridad extra)."""
    req = urllib.request.Request(
        f"https://doi.org/{doi}",
        headers={"Accept": "application/vnd.citationstyles.csl+json", **UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return True, ""
    except urllib.error.HTTPError:
        return False, "doi.org responde 'DOI Not Found'"
    except Exception as e:
        return True, f"(aviso: no se pudo confirmar en doi.org: {type(e).__name__})"


# ------------------------------------------------------------------ validacion
def valida_bib(ruta):
    problemas = 0
    print(f"{'CLAVE':<22} {'DOI':<34} ESTADO")
    print("-" * 100)
    for clave, tipo, cuerpo in entradas_bib(ruta):
        doi = campo(cuerpo, "doi")
        titulo = campo(cuerpo, "title")
        if not doi:
            estado, msg, sugerido = sin_doi_explicado(clave, tipo, cuerpo)
            if estado == "AVISO":
                problemas += 1
                print(f"{clave:<22} {'(sin DOI)':<34} !! {msg}: {sugerido}")
            else:
                print(f"{clave:<22} {'(sin DOI)':<34} OK  {msg}")
            time.sleep(0.4)
            continue
        ok, msg, meta = consulta_crossref(doi)
        if ok:
            real = (meta.get("title") or [""])[0]
            anio = (meta.get("issued", {}).get("date-parts") or [[None]])[0][0]
            coincide = (
                normaliza(titulo) == normaliza(real)
                or normaliza(titulo)[:60] in normaliza(real)
                or normaliza(real)[:60] in normaliza(titulo)
            )
            marca = "OK " if coincide else "!! "
            if not coincide:
                problemas += 1
            print(f"{clave:<22} {doi:<34} {marca}{anio} | {real[:52]}")
            if not coincide:
                print(f"{'':<22} {'':<34}    en el .bib dice: {titulo[:52]}")
        else:
            problemas += 1
            print(f"{clave:<22} {doi:<34} !! {msg}")
            res, nota = doi_resuelve(doi)
            if not res:
                print(f"{'':<22} {'':<34}    {nota} -> EL DOI NO EXISTE")
        time.sleep(0.4)
    print("-" * 100)
    print(f"Entradas con problema: {problemas}")
    return problemas


def valida_un_doi(doi):
    doi = doi.strip().rstrip("/")
    if not re.match(r"^10\.\d{4,9}/\S+$", doi):
        print(f"'{doi}' no tiene forma de DOI (debe ser 10.NNNN/...)")
        return 1
    ok, msg, meta = consulta_crossref(doi)
    if not ok:
        print(f"{doi}: {msg}")
        res, nota = doi_resuelve(doi)
        print(f"  doi.org: {'no resuelve' if not res else 'resuelve'}"
              + (f" ({nota})" if nota else ""))
        return 1
    print(f"{doi}: OK")
    print(f"  Titulo : {(meta.get('title') or [''])[0]}")
    print(f"  Autores: {', '.join((a.get('given','') + ' ' + a.get('family','')).strip() for a in meta.get('author', []))}")
    print(f"  Revista: {(meta.get('container-title') or [''])[0]}")
    print(f"  Anio   : {(meta.get('issued', {}).get('date-parts') or [[None]])[0][0]}")
    print(f"  Paginas: {meta.get('page', 'n/d')}")
    print(f"  Vol/num: {meta.get('volume', 'n/d')} / {meta.get('number', 'n/d')}")
    print(f"  ISSN   : {meta.get('ISSN', 'n/d')}")
    return 0


def url_resuelve(url):
    """(ok, nota) para una URL: comprueba que responde y a donde apunta.

    Prueba con urllib y, si falla, con curl (algunos hosts rechazan
    la pila TLS de python o las cabeceras largas).
    """
    if not url:
        return False, "no tiene URL"
    cabeceras = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) cyberdefense-bibcheck/1.0"}
    for intento in range(2):
        try:
            req = urllib.request.Request(url, headers=cabeceras)
            with urllib.request.urlopen(req, timeout=30) as r:
                return 200 <= r.status < 400, f"HTTP {r.status}"
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}"
        except Exception as e:
            ultimo = type(e).__name__
            cabeceras = {"User-Agent": "Mozilla/5.0"}
    # fallback con curl
    try:
        import subprocess
        p = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-L",
             "--max-time", "30", "-A", "Mozilla/5.0", url],
            capture_output=True, text=True, timeout=45)
        codigo = int(p.stdout.strip() or 0)
        if 200 <= codigo < 400:
            return True, f"HTTP {codigo}"
        return False, f"HTTP {codigo or ultimo}"
    except Exception:
        return False, f"no responde ({ultimo})"


def valida_urls(ruta):
    """Comprueba que todas las URL del .bib sigan vivas."""
    print()
    print("URL DEL BIBLIOGRAFIA")
    print("-" * 100)
    problemas = 0
    for clave, _tipo, cuerpo in entradas_bib(ruta):
        url = campo(cuerpo, "url")
        if not url:
            continue
        ok, nota = url_resuelve(url)
        if not ok:
            problemas += 1
        print(f"{clave:<22} {'OK ' if ok else '!! '} {nota:<22} {url[:60]}")
        time.sleep(0.3)
    print("-" * 100)
    print(f"URL con problema: {problemas}")
    return problemas


def main():
    args = sys.argv[1:]
    if not args:
        p = valida_bib(BIB)
        p += valida_urls(BIB)
        return 1 if p else 0
    for arg in args:
        print(f"=== {arg} ===")
        if "/" in arg:
            valida_un_doi(arg)
        else:
            encontrada = None
            for clave, _tipo, cuerpo in entradas_bib(BIB):
                if clave == arg:
                    encontrada = (clave, cuerpo)
                    break
            if not encontrada:
                print(f"La clave '{arg}' no existe en {BIB}")
                return 1
            clave, cuerpo = encontrada
            doi = campo(cuerpo, "doi")
            print(f"  title : {campo(cuerpo, 'title')}")
            print(f"  venue : {campo(cuerpo, 'booktitle') or campo(cuerpo, 'journaltitle') or campo(cuerpo, 'institution')}")
            print(f"  doi   : {doi or '(sin DOI)'}")
            if doi:
                valida_un_doi(doi)
    return 0


if __name__ == "__main__":
    sys.exit(main())
