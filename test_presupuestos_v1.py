#!/usr/bin/env python3
"""
Smoke test de Presupuestos v1 (versionado + impresión) contra staging.

Uso:
    python3 test_presupuestos_v1.py tu_email tu_contraseña

Crea un presupuesto de prueba, le agrega una versión 1 con ítems mixtos (uno con
cantidad/precio, otro solo descriptivo) y un total manual, lo emite (lo que debe
bloquear la v1), crea una v2 (lo que debe reabrir a Borrador), y imprime el HTML.
No usa datos reales de un cliente — es solo para validar que el flujo no rompe nada.
"""
import sys
import json
import urllib.request
import urllib.error

BASE = "https://vadoca-doctracker-backend-staging.up.railway.app"

if len(sys.argv) < 3:
    print("Uso: python3 test_presupuestos_v1.py tu_email tu_contraseña")
    sys.exit(1)

EMAIL, PASSWORD = sys.argv[1], sys.argv[2]


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


def chequear(nombre, status, esperado, detalle=""):
    ok = status == esperado
    print(f"[{'OK ' if ok else 'FAIL'}] {nombre} -> HTTP {status} (esperado {esperado}) {detalle}")
    return ok


print(f"Probando contra: {BASE}\n")
resultados = []

# 1. Login
s, b = llamar("POST", "/api/login", {"email": EMAIL, "password": PASSWORD})
if s != 200:
    print(f"No pude loguearme: HTTP {s} -> {b}")
    sys.exit(1)
token = b["token"]
print(f"[OK ] Login como {b['usuario']['email']} (rol {b['usuario']['rol']})\n")

# 2. Crear presupuesto de prueba
s, b = llamar("POST", "/api/presupuestos", {
    "cliente": "000", "clienteNombre": "CLIENTE DE PRUEBA (borrar)",
    "descripcion": "Presupuesto de prueba — smoke test Presupuestos v1",
}, token)
resultados.append(chequear("POST /api/presupuestos (crear header)", s, 200))
if s != 200:
    sys.exit(1)
codigo = b["codigo"]
print(f"      -> código asignado: {codigo}\n")

# 3. Crear versión 1 (ítems mixtos: uno con cantidad/precio, otro solo descriptivo)
s, b = llamar("POST", f"/api/presupuestos/{codigo}/versiones", {
    "moneda": "USD",
    "items": [
        {"descripcion": "Validación de sistema — etapa 1", "cantidad": 1, "precio_unitario": 1000, "importe": 1000},
        {"descripcion": "Soporte post-entrega (incluido, sin cargo individual)"},
    ],
    "subtotal": 1000, "descuento_pct": 10, "descuento_monto": 100, "total": 900,
    "alcance": "Alcance de prueba.\n\nExclusiones: nada real, esto es un test.",
    "entregables": "Documento de prueba.",
    "cronograma": "Inmediato (test).",
    "forma_pago": "100% contra entrega (test).",
    "condiciones": "Esto es un presupuesto de prueba, no tiene validez real.",
}, token)
resultados.append(chequear("POST .../versiones (crear v1)", s, 200, f"-> numero {b.get('numero')}" if isinstance(b, dict) else ""))

# 4. Listar versiones
s, b = llamar("GET", f"/api/presupuestos/{codigo}/versiones", token=token)
resultados.append(chequear("GET .../versiones (listar)", s, 200, f"-> {len(b.get('versiones', []))} version(es)" if isinstance(b, dict) else ""))
if isinstance(b, dict) and b.get("versiones"):
    v1_bloqueada_antes = b["versiones"][0]["bloqueada"]
    resultados.append(chequear("v1 arranca sin bloquear", v1_bloqueada_antes, False))

# 5. Emitir (debe bloquear la v1)
s, b = llamar("POST", f"/api/presupuestos/{codigo}/estado", {"estado": "Enviado"}, token)
resultados.append(chequear("POST .../estado Enviado", s, 200))
s, b = llamar("GET", f"/api/presupuestos/{codigo}/versiones", token=token)
if isinstance(b, dict) and b.get("versiones"):
    resultados.append(chequear("v1 queda bloqueada tras emitir", b["versiones"][0]["bloqueada"], True))

# 6. Crear v2 (debe reabrir a Borrador)
s, b = llamar("POST", f"/api/presupuestos/{codigo}/versiones", {
    "moneda": "USD", "items": [], "total": 950,
    "condiciones": "v2 de prueba: el cliente pidió un ajuste.",
}, token)
resultados.append(chequear("POST .../versiones (crear v2)", s, 200, f"-> numero {b.get('numero')}" if isinstance(b, dict) else ""))

s, b = llamar("GET", "/api/presupuestos", token=token)
if isinstance(b, list):
    pres = next((x for x in b if x["codigo"] == codigo), None)
    if pres:
        resultados.append(chequear("Presupuesto vuelve a Borrador tras crear v2", pres["estado"], "Borrador"))

# 7. Imprimir (HTML)
s, html = llamar("GET", f"/api/presupuestos/{codigo}/imprimir", token=token, esperar_json=False)
ok_print = s == 200 and "<html" in html.lower() and codigo in html
resultados.append(chequear("GET .../imprimir (HTML)", s, 200, f"-> {len(html)} bytes, contiene código: {codigo in html}" if s == 200 else ""))

print(f"\nPresupuesto de prueba creado: {codigo} — convendría borrarlo o marcarlo bien distinto para no ensuciar tus reportes reales de Comercial.")
print()
if all(resultados):
    print("Todo OK ✅")
else:
    print("Hay algo que no dio lo esperado ⚠️ — pegame la salida de arriba.")
