#!/usr/bin/env python3
"""
Smoke test de staging para el rollback de integración IA (sacar escritura, agregar lectura ampliada).

Uso:
    export INTEGRACION_API_KEY="tu_api_key_de_integracion"
    python3 test_staging_integracion.py

O pasando la key como argumento:
    python3 test_staging_integracion.py tu_api_key_de_integracion
"""
import sys
import os
import json
import urllib.request
import urllib.error

BASE = "https://vadoca-doctracker-backend-staging.up.railway.app"

API_KEY = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("INTEGRACION_API_KEY")
if not API_KEY:
    print("Falta la API key de integración.")
    print("Usá: export INTEGRACION_API_KEY=... && python3 test_staging_integracion.py")
    print("  o: python3 test_staging_integracion.py <api_key>")
    sys.exit(1)


def llamar(metodo, path, body=None):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=metodo)
    req.add_header("Authorization", f"Bearer {API_KEY}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            cuerpo = json.loads(e.read().decode())
        except Exception:
            cuerpo = {}
        return e.code, cuerpo
    except Exception as e:
        return None, {"error_local": str(e)}


def chequear(nombre, status, esperado, detalle=""):
    ok = status == esperado
    marca = "OK " if ok else "FAIL"
    print(f"[{marca}] {nombre} -> HTTP {status} (esperado {esperado}) {detalle}")
    return ok


print(f"Probando contra: {BASE}\n")

resultados = []

# 1. Los dos endpoints de escritura ya NO deben existir (404)
s, b = llamar("POST", "/api/integracion/expedientes", {})
resultados.append(chequear("POST /api/integracion/expedientes (debe no existir)", s, 404))

s, b = llamar("POST", "/api/integracion/adjuntos", {})
resultados.append(chequear("POST /api/integracion/adjuntos (debe no existir)", s, 404))

# 2. Los 3 endpoints nuevos de lectura deben responder 200
s, b = llamar("GET", "/api/integracion/auditoria")
resultados.append(chequear("GET /api/integracion/auditoria", s, 200, f"-> {len(b.get('entradas', []))} entradas" if isinstance(b, dict) else ""))

s, b = llamar("GET", "/api/integracion/pendientes")
resultados.append(chequear("GET /api/integracion/pendientes", s, 200, f"-> {len(b.get('pendientes', []))} documentos" if isinstance(b, dict) else ""))

s, b = llamar("GET", "/api/integracion/proyectos")
resultados.append(chequear("GET /api/integracion/proyectos", s, 200, f"-> {len(b.get('proyectos', []))} proyectos" if isinstance(b, dict) else ""))

# 3. El endpoint de consulta puntual sigue funcionando (debe seguir pidiendo filtro: 400 sin filtro)
s, b = llamar("GET", "/api/seguimiento/data")
resultados.append(chequear("GET /api/seguimiento/data sin filtro (debe seguir dando 400)", s, 400))

print()
if all(resultados):
    print("Todo OK ✅ — listo para confirmar el redeploy de producción y seguir con los archivos del Custom GPT.")
else:
    print("Hay algo que no dio lo esperado ⚠️ — pegame la salida de arriba y lo reviso.")
