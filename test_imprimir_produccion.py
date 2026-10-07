#!/usr/bin/env python3
"""
Prueba en PRODUCCIÓN: lista tus presupuestos y guarda el HTML de impresión
de uno (el que elijas) para que lo abras en el navegador.

No crea ni modifica nada — es 100% lectura.

Uso:
    python3 test_imprimir_produccion.py tu_email tu_contraseña [codigo_presupuesto]

Si no pasás codigo_presupuesto, lista los primeros 15 presupuestos y te pide
que elijas uno.
"""
import sys
import json
import urllib.request
import urllib.error

BASE = "https://vadoca-doctracker-backend-production.up.railway.app"

if len(sys.argv) < 3:
    print("Uso: python3 test_imprimir_produccion.py tu_email tu_contraseña [codigo_presupuesto]")
    sys.exit(1)

EMAIL, PASSWORD = sys.argv[1], sys.argv[2]
CODIGO_FORZADO = sys.argv[3] if len(sys.argv) > 3 else None


def llamar(metodo, path, body=None, token=None, esperar_json=True):
    url = BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=metodo)
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if esperar_json else raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


print(f"Probando contra: {BASE}\n")

# 1. Login
s, b = llamar("POST", "/api/login", {"email": EMAIL, "password": PASSWORD})
if s != 200:
    print(f"No pude loguearme: HTTP {s} -> {b}")
    sys.exit(1)
token = b["token"]
print(f"[OK] Login como {b['usuario']['email']} (rol {b['usuario']['rol']})\n")

# 2. Elegir presupuesto
codigo = CODIGO_FORZADO
if not codigo:
    s, b = llamar("GET", "/api/presupuestos", token=token)
    if s != 200 or not isinstance(b, list) or not b:
        print(f"No pude listar presupuestos: HTTP {s} -> {b}")
        sys.exit(1)
    print("Presupuestos disponibles (primeros 15):")
    for p in b[:15]:
        print(f"  {p['codigo']}  -  {p.get('clienteNombre', '')}  -  estado: {p['estado']}")
    print()
    codigo = input("Pegá el código del que querés imprimir: ").strip()

# 3. Imprimir
s, html = llamar("GET", f"/api/presupuestos/{codigo}/imprimir", token=token, esperar_json=False)
if s != 200:
    print(f"No pude imprimir {codigo}: HTTP {s} -> {html}")
    sys.exit(1)

archivo = f"presupuesto_{codigo.replace('/', '-')}.html"
with open(archivo, "w", encoding="utf-8") as f:
    f.write(html)

print(f"[OK] Guardado: {archivo} ({len(html)} bytes)")
print("Abrilo con doble clic (o arrastralo al navegador) para verlo.")
