/* ============================================================
   VADOCA DocTracker — Backend v2.0
   Node + Express + Postgres (Railway) + Google Drive/Sheets
   - Usuarios propios (@vadoca.com.ar o cualquier mail) con roles
   - Superusuario: alta/baja de usuarios, blanqueo de claves, con bitácora propia
   - Registro maestro en Postgres con cadena de hashes (tamper-evident)
   - Archivos en el Drive del titular (una autorización única)
   - Espejo de solo lectura en la hoja REGISTRO de Google Sheets
   ============================================================ */
'use strict';
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { google } = require('googleapis');
const { Readable } = require('stream');

/* ---------- Configuración por variables de entorno ---------- */
const {
  DATABASE_URL,
  JWT_SECRET = 'cambiar-este-secreto',
  ADMIN_EMAIL,            // superusuario inicial, ej: damian.astorino@vadoca.com.ar
  ADMIN_PASSWORD,         // clave inicial del superusuario (cambiarla al entrar)
  GOOGLE_CLIENT_ID,       // el mismo Client ID de la app OAuth
  GOOGLE_CLIENT_SECRET,   // secreto del cliente (Credenciales -> tu Client ID)
  SHEET_ID,               // planilla "VADOCA - Codigos Documentos"
  FRONTEND_ORIGIN = '*',  // ej: https://damianastorino-hue.github.io
  INTEGRACION_API_KEYS,   // clave(s) separadas del login humano, para n8n/IA. Lectura total + alta acotada en DocTracker.
                          // Coma-separadas para poder rotar sin downtime: agregás la nueva, migrás el consumidor, sacás la vieja. Vacío = integración desactivada.
  PORT = 3000,
} = process.env;
const INTEGRACION_KEYS_VALIDAS = (INTEGRACION_API_KEYS || '').split(',').map(k => k.trim()).filter(Boolean);
const esKeyIntegracionValida = (t) => t && INTEGRACION_KEYS_VALIDAS.includes(t);

const pool = new Pool({ connectionString: DATABASE_URL, ssl: DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false });
const app = express();
app.set('trust proxy', true);
app.use(cors({ origin: FRONTEND_ORIGIN === '*' ? true : FRONTEND_ORIGIN.split(','), credentials: false }));
app.use(express.json({ limit: '15mb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024, files: 30 } });
const LOGO_VADOCA = require('./assets/logo-vadoca.js'); // data: URI, para marca de agua en plantillas imprimibles

const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const ahora = () => new Date().toISOString();

/* ============================================================
   ESQUEMA DE BASE DE DATOS (se crea solo al arrancar)
   ============================================================ */
const SCHEMA = `
CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  nombre TEXT NOT NULL DEFAULT '',
  hash TEXT NOT NULL,
  rol TEXT NOT NULL DEFAULT 'editor' CHECK (rol IN ('admin','editor','lector')),
  activo BOOLEAN NOT NULL DEFAULT TRUE,
  debe_cambiar_clave BOOLEAN NOT NULL DEFAULT TRUE,
  creado TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS config (
  clave TEXT PRIMARY KEY,
  valor TEXT
);
CREATE TABLE IF NOT EXISTS documentos (
  id SERIAL PRIMARY KEY,
  codigo TEXT UNIQUE NOT NULL,
  expediente_id TEXT NOT NULL,
  fecha_alta TEXT, cliente_num TEXT, cliente_nombre TEXT,
  tipo_trabajo TEXT, linea TEXT, prot_inf TEXT, tipo_doc TEXT,
  doc_num TEXT, version TEXT, descripcion TEXT,
  codigo_interno_cliente TEXT, ref_presupuesto TEXT,
  estado TEXT NOT NULL DEFAULT 'Borrador',
  fecha_inicio TEXT, fecha_fin TEXT,
  carpeta_drive_id TEXT, carpeta_drive_url TEXT,
  historial_file_id TEXT,
  conflicto_legacy BOOLEAN DEFAULT FALSE,
  observaciones TEXT DEFAULT '',
  autor TEXT NOT NULL,
  ultimo_movimiento TIMESTAMPTZ,
  creado TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_docs_exp ON documentos(expediente_id);
CREATE TABLE IF NOT EXISTS bitacora (
  id SERIAL PRIMARY KEY,
  expediente_id TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  autor TEXT NOT NULL,
  tipo TEXT NOT NULL,
  texto TEXT NOT NULL,
  adjuntos JSONB NOT NULL DEFAULT '[]',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bit_exp ON bitacora(expediente_id);
CREATE TABLE IF NOT EXISTS procedimientos (
  id SERIAL PRIMARY KEY,
  codigo TEXT UNIQUE NOT NULL,
  codigo_base TEXT NOT NULL,
  sector TEXT NOT NULL DEFAULT '',
  titulo TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '01',
  estado TEXT NOT NULL DEFAULT 'Borrador',
  vigencia_meses INT NOT NULL DEFAULT 36,
  fecha_vigencia TEXT, fecha_vencimiento TEXT,
  carpeta_drive_id TEXT, carpeta_drive_url TEXT,
  autor TEXT NOT NULL,
  ultimo_movimiento TIMESTAMPTZ,
  creado TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_proc_base ON procedimientos(codigo_base);
CREATE TABLE IF NOT EXISTS presupuestos (
  id SERIAL PRIMARY KEY,
  codigo TEXT UNIQUE NOT NULL,
  cliente_num TEXT, cliente_nombre TEXT,
  descripcion TEXT NOT NULL,
  monto NUMERIC, moneda TEXT DEFAULT 'ARS',
  fecha_emision TEXT,
  estado TEXT NOT NULL DEFAULT 'Borrador',
  carpeta_drive_id TEXT, carpeta_drive_url TEXT,
  autor TEXT NOT NULL,
  ultimo_movimiento TIMESTAMPTZ,
  creado TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS proyectos (
  id SERIAL PRIMARY KEY,
  codigo TEXT UNIQUE NOT NULL,
  nombre TEXT NOT NULL,
  cliente_num TEXT, cliente_nombre TEXT,
  alcance TEXT DEFAULT '',
  estado TEXT NOT NULL DEFAULT 'Activo',
  carpeta_drive_id TEXT, carpeta_drive_url TEXT,
  autor TEXT NOT NULL,
  ultimo_movimiento TIMESTAMPTZ,
  creado TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Versionado de presupuestos (v1): cada edición real = una fila nueva, snapshot completo.
-- El código del header (presupuestos.codigo) nunca cambia; "v1/v2/v3" es solo este numero.
-- Sin motor de descuentos ni catálogo de precios: los totales los carga quien prepara el
-- presupuesto (igual que hoy en el Word), items es solo para mostrar el detalle.
CREATE TABLE IF NOT EXISTS presupuesto_versiones (
  id SERIAL PRIMARY KEY,
  presupuesto_codigo TEXT NOT NULL REFERENCES presupuestos(codigo) ON DELETE CASCADE,
  numero INT NOT NULL,
  moneda TEXT NOT NULL DEFAULT 'ARS',
  items JSONB NOT NULL DEFAULT '[]',   -- [{descripcion, cantidad?, precio_unitario?, importe?}, ...] todo opcional salvo descripcion
  subtotal NUMERIC,
  descuento_pct NUMERIC, descuento_monto NUMERIC,
  iva_discriminado BOOLEAN NOT NULL DEFAULT false, iva_monto NUMERIC,
  total NUMERIC NOT NULL,
  alcance TEXT DEFAULT '', entregables TEXT DEFAULT '', cronograma TEXT DEFAULT '',
  forma_pago TEXT DEFAULT '', condiciones TEXT DEFAULT '',
  bloqueada BOOLEAN NOT NULL DEFAULT false,  -- true desde que el presupuesto se emite (estado <> Borrador)
  autor TEXT NOT NULL,
  creado TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(presupuesto_codigo, numero)
);
CREATE TABLE IF NOT EXISTS proyecto_presupuestos (
  id SERIAL PRIMARY KEY,
  proyecto TEXT NOT NULL,
  presupuesto TEXT NOT NULL,
  UNIQUE(proyecto, presupuesto)
);
CREATE TABLE IF NOT EXISTS poe_relaciones (
  id SERIAL PRIMARY KEY,
  base TEXT NOT NULL,
  relacionado TEXT NOT NULL,
  UNIQUE(base, relacionado)
);
CREATE TABLE IF NOT EXISTS accesos (
  id SERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  email TEXT NOT NULL,
  evento TEXT NOT NULL,
  detalle TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS admin_log (
  id SERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  autor TEXT NOT NULL,
  accion TEXT NOT NULL,
  detalle TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
`;

async function boot() {
  await pool.query(SCHEMA);
  await pool.query("ALTER TABLE procedimientos ADD COLUMN IF NOT EXISTS sector TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE documentos ADD COLUMN IF NOT EXISTS proyecto TEXT NOT NULL DEFAULT ''");
  await pool.query("ALTER TABLE presupuestos ADD COLUMN IF NOT EXISTS facturacion TEXT NOT NULL DEFAULT 'Abierta'");
  // --- Módulo Seguimiento (FARO) ---
  await pool.query(`
    CREATE TABLE IF NOT EXISTS seg_templates (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      items JSONB NOT NULL DEFAULT '[]',
      creado TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS seg_items (
      id SERIAL PRIMARY KEY,
      proyecto TEXT NOT NULL,
      nombre TEXT NOT NULL,
      orden INT NOT NULL DEFAULT 0,
      estado TEXT NOT NULL DEFAULT 'pendiente',
      doc_codigo TEXT,
      fecha_limite TEXT,
      notas TEXT NOT NULL DEFAULT '',
      creado TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_seg_proy ON seg_items(proyecto);
    CREATE TABLE IF NOT EXISTS seg_proyectos (
      id SERIAL PRIMARY KEY,
      codigo TEXT UNIQUE,
      nombre TEXT NOT NULL,
      ambito TEXT NOT NULL DEFAULT 'personal',
      cliente TEXT NOT NULL DEFAULT '',
      estado TEXT NOT NULL DEFAULT 'Activo',
      notas TEXT NOT NULL DEFAULT '',
      creado TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS facturas (
      id SERIAL PRIMARY KEY,
      numero TEXT NOT NULL,
      cliente TEXT NOT NULL DEFAULT '',
      presupuesto TEXT NOT NULL DEFAULT '',
      fecha_emision TEXT NOT NULL,
      monto NUMERIC NOT NULL DEFAULT 0,
      moneda TEXT NOT NULL DEFAULT 'ARS',
      estado TEXT NOT NULL DEFAULT 'Emitida',
      fecha_cobro TEXT,
      notas TEXT NOT NULL DEFAULT '',
      creado TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  // --- Proyectos unificados: los proyectos FARO/FlowTracker viven en la tabla proyectos ---
  await pool.query("ALTER TABLE proyectos ADD COLUMN IF NOT EXISTS ambito TEXT NOT NULL DEFAULT 'profesional'");
  await pool.query("ALTER TABLE proyectos ADD COLUMN IF NOT EXISTS notas TEXT NOT NULL DEFAULT ''");
  const mig = await pool.query(`INSERT INTO proyectos(codigo,nombre,cliente_num,cliente_nombre,alcance,estado,autor,ultimo_movimiento,creado,ambito,notas)
    SELECT s.codigo, s.nombre, '', s.cliente, '', s.estado, 'migracion-flowtracker', now(), s.creado, s.ambito, s.notas
    FROM seg_proyectos s
    WHERE s.codigo IS NOT NULL AND NOT EXISTS (SELECT 1 FROM proyectos p WHERE p.codigo = s.codigo)
    RETURNING codigo`);
  if (mig.rowCount) console.log('Proyectos FlowTracker migrados a la tabla proyectos:', mig.rows.map(r => r.codigo).join(', '));
  const segT = await pool.query('SELECT COUNT(*)::int n FROM seg_templates');
  if (!segT.rows[0].n) {
    const pack = (extra) => ['Plan Maestro', 'RU', 'Protocolo DQ', 'Informe DQ', 'Protocolo IQ', 'Informe IQ',
      'Protocolo OQ', 'Informe OQ', 'Protocolo PQ', 'Informe PQ', ...extra, 'Informe Final'];
    const seeds = [
      ['Validación de planilla de cálculo', pack(['Protocolo IV', 'Informe IV'])],
      ['Calificación de equipo', pack([])],
      ['Calificación de software', pack([])],
      ['Presupuesto / Comercial', ['Relevamiento', 'Presupuesto', 'Seguimiento post-envío', 'Cierre (OC / aceptación)']],
      ['Proyecto libre', []]
    ];
    for (const [n, its] of seeds) await pool.query('INSERT INTO seg_templates(nombre,items) VALUES($1,$2)', [n, JSON.stringify(its)]);
    console.log('Seguimiento: templates seed cargados');
  }
  // Superusuario inicial
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {
    const r = await pool.query('SELECT 1 FROM usuarios WHERE email=$1', [ADMIN_EMAIL.toLowerCase()]);
    if (!r.rowCount) {
      await pool.query(
        'INSERT INTO usuarios(email,nombre,hash,rol,debe_cambiar_clave) VALUES($1,$2,$3,$4,TRUE)',
        [ADMIN_EMAIL.toLowerCase(), 'Superusuario', bcrypt.hashSync(ADMIN_PASSWORD, 10), 'admin']
      );
      console.log('Superusuario creado:', ADMIN_EMAIL);
    }
  }
  console.log('Base de datos lista.');
}

/* ============================================================
   CADENAS DE HASH (bitácora de expedientes y bitácora admin)
   ============================================================ */
async function ultimoHash(tabla, whereSql = '', params = []) {
  const r = await pool.query(`SELECT hash FROM ${tabla} ${whereSql} ORDER BY id DESC LIMIT 1`, params);
  return r.rowCount ? r.rows[0].hash : 'GENESIS';
}
async function agregarBitacora(expedienteId, autor, tipo, texto, adjuntos = []) {
  const prev = await ultimoHash('bitacora', 'WHERE expediente_id=$1', [expedienteId]);
  const ts = ahora();
  const h = sha(prev + '|' + ts + '|' + autor + '|' + tipo + '|' + texto + '|' + JSON.stringify(adjuntos));
  const r = await pool.query(
    'INSERT INTO bitacora(expediente_id,ts,autor,tipo,texto,adjuntos,prev_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [expedienteId, ts, autor, tipo, texto, JSON.stringify(adjuntos), prev, h]
  );
  actualizarHistorialDrive(expedienteId).catch(e => console.error('historial.json:', e.message));
  return r.rows[0];
}
async function logAdmin(autor, accion, detalle = '') {
  const prev = await ultimoHash('admin_log');
  const ts = ahora();
  const h = sha(prev + '|' + ts + '|' + autor + '|' + accion + '|' + detalle);
  await pool.query('INSERT INTO admin_log(ts,autor,accion,detalle,prev_hash,hash) VALUES($1,$2,$3,$4,$5,$6)',
    [ts, autor, accion, detalle, prev, h]);
}

/* ============================================================
   AUTENTICACIÓN Y ROLES
   ============================================================ */
function firmar(u) {
  return jwt.sign({ id: u.id, email: u.email, nombre: u.nombre, rol: u.rol }, JWT_SECRET, { expiresIn: '12h' });
}
const USUARIO_INTEGRACION = { id: 0, email: 'integracion@vadoca.local', nombre: 'Integración IA', rol: 'integracion' };

function auth(rolesPermitidos) {
  return (req, res, next) => {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    // API key de integración (n8n / IA): solo lectura (GET). Nunca reemplaza al login humano
    // ni habilita escritura acá — eso vive exclusivamente en /api/integracion/* con su propio middleware.
    if (esKeyIntegracionValida(t)) {
      if (req.method !== 'GET') return res.status(403).json({ error: 'La integración no tiene escritura en esta ruta' });
      req.user = USUARIO_INTEGRACION;
      return next();
    }
    try {
      req.user = jwt.verify(t, JWT_SECRET);
      if (rolesPermitidos && !rolesPermitidos.includes(req.user.rol))
        return res.status(403).json({ error: 'No tenés permisos para esta acción' });
      next();
    } catch (e) { res.status(401).json({ error: 'Sesión inválida o vencida' }); }
  };
}

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body || {};
  const r = await pool.query('SELECT * FROM usuarios WHERE email=$1', [(email || '').toLowerCase().trim()]);
  const u = r.rows[0];
  if (!u || !u.activo || !bcrypt.compareSync(password || '', u.hash)) {
    await pool.query('INSERT INTO accesos(email,evento,detalle) VALUES($1,$2,$3)',
      [(email || '').toLowerCase().trim() || '(vacío)', 'login_fallido', !u ? 'usuario inexistente' : (!u.activo ? 'usuario inactivo' : 'contraseña incorrecta')]).catch(() => {});
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }
  await pool.query('INSERT INTO accesos(email,evento,detalle) VALUES($1,$2,$3)', [u.email, 'login_ok', 'rol: ' + u.rol]).catch(() => {});
  res.json({ token: firmar(u), usuario: { email: u.email, nombre: u.nombre, rol: u.rol, debe_cambiar_clave: u.debe_cambiar_clave } });
});

app.post('/api/cambiar-clave', auth(), async (req, res) => {
  const { actual, nueva } = req.body || {};
  if (!nueva || nueva.length < 8) return res.status(400).json({ error: 'La clave nueva debe tener al menos 8 caracteres' });
  const r = await pool.query('SELECT * FROM usuarios WHERE id=$1', [req.user.id]);
  if (!bcrypt.compareSync(actual || '', r.rows[0].hash)) return res.status(401).json({ error: 'La clave actual no coincide' });
  await pool.query('UPDATE usuarios SET hash=$1, debe_cambiar_clave=FALSE WHERE id=$2', [bcrypt.hashSync(nueva, 10), req.user.id]);
  await logAdmin(req.user.email, 'cambio_clave_propia', '');
  res.json({ ok: true });
});

/* ---------- Gestión de usuarios (solo superusuario) ---------- */
app.get('/api/usuarios', auth(['admin']), async (_req, res) => {
  const r = await pool.query('SELECT id,email,nombre,rol,activo,debe_cambiar_clave,creado FROM usuarios ORDER BY id');
  res.json(r.rows);
});
app.post('/api/usuarios', auth(['admin']), async (req, res) => {
  const { email, nombre, rol, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Faltan email o clave inicial' });
  if (!['admin', 'editor', 'lector'].includes(rol)) return res.status(400).json({ error: 'Rol inválido' });
  try {
    await pool.query('INSERT INTO usuarios(email,nombre,hash,rol) VALUES($1,$2,$3,$4)',
      [email.toLowerCase().trim(), nombre || '', bcrypt.hashSync(password, 10), rol]);
    await logAdmin(req.user.email, 'alta_usuario', `${email} rol=${rol}`);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: 'Ese email ya existe' }); }
});
app.post('/api/usuarios/:id/blanquear', auth(['admin']), async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Falta la clave nueva' });
  const r = await pool.query('UPDATE usuarios SET hash=$1, debe_cambiar_clave=TRUE WHERE id=$2 RETURNING email',
    [bcrypt.hashSync(password, 10), req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Usuario no encontrado' });
  await logAdmin(req.user.email, 'blanqueo_clave', r.rows[0].email);
  res.json({ ok: true });
});
app.post('/api/usuarios/:id/estado', auth(['admin']), async (req, res) => {
  const { activo } = req.body || {};
  const r = await pool.query('UPDATE usuarios SET activo=$1 WHERE id=$2 RETURNING email', [!!activo, req.params.id]);
  if (!r.rowCount) return res.status(404).json({ error: 'Usuario no encontrado' });
  await logAdmin(req.user.email, activo ? 'activar_usuario' : 'desactivar_usuario', r.rows[0].email);
  res.json({ ok: true });
});
app.get('/api/admin/bitacora', auth(['admin']), async (_req, res) => {
  const r = await pool.query('SELECT * FROM admin_log ORDER BY id DESC LIMIT 500');
  res.json(r.rows);
});

/* ============================================================
   GOOGLE: autorización única del titular + clientes Drive/Sheets
   ============================================================ */
function oauthClient(req) {
  // Railway sirve siempre por https detrás de un proxy; forzamos el esquema para que
  // el redirect_uri declarado a Google coincida exactamente con el registrado.
  const base = `https://${req.get('host')}`;
  return new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, `${base}/oauth/google/callback`);
}
async function googleAuth() {
  const r = await pool.query("SELECT valor FROM config WHERE clave='google_refresh_token'");
  if (!r.rowCount) throw new Error('Drive no conectado todavía: el superusuario debe entrar a /oauth/google/start');
  const c = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
  c.setCredentials({ refresh_token: r.rows[0].valor });
  return c;
}
app.get('/oauth/google/start', (req, res) => {
  const url = oauthClient(req).generateAuthUrl({
    access_type: 'offline', prompt: 'consent',
    scope: ['https://www.googleapis.com/auth/drive.file', 'https://www.googleapis.com/auth/spreadsheets'],
  });
  res.redirect(url);
});
app.get('/oauth/google/callback', async (req, res) => {
  try {
    const { tokens } = await oauthClient(req).getToken(req.query.code);
    if (!tokens.refresh_token) return res.send('Google no devolvió refresh token. Revocá el acceso en myaccount.google.com/permissions y volvé a intentar.');
    await pool.query(`INSERT INTO config(clave,valor) VALUES('google_refresh_token',$1)
                      ON CONFLICT (clave) DO UPDATE SET valor=$1`, [tokens.refresh_token]);
    res.send('✔ Drive conectado. Ya podés cerrar esta pestaña y usar la app.');
  } catch (e) { res.status(500).send('Error conectando Drive: ' + e.message); }
});

/* ---------- Drive: carpetas, subida de archivos, historial.json ---------- */
async function driveCli() { return google.drive({ version: 'v3', auth: await googleAuth() }); }
async function sheetsCli() { return google.sheets({ version: 'v4', auth: await googleAuth() }); }

async function ensureCarpeta(drive, nombre, parentId) {
  const q = `name='${nombre.replace(/'/g, "\\'")}' and mimeType='application/vnd.google-apps.folder' and '${parentId || 'root'}' in parents and trashed=false`;
  const r = await drive.files.list({ q, fields: 'files(id)' });
  if (r.data.files.length) return r.data.files[0].id;
  const c = await drive.files.create({ requestBody: { name: nombre, mimeType: 'application/vnd.google-apps.folder', parents: parentId ? [parentId] : undefined }, fields: 'id' });
  return c.data.id;
}
const limpiar = (s) => String(s).normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/[\\/:*?"<>|#]/g, '-').trim().slice(0, 60);
const SUBCARPETAS = ['00_cliente', '01_versiones', '02_evidencias', '03_entregables'];

async function crearCarpetasExpediente(clienteNum, clienteNombre, tipoTrabajo, nombreExp) {
  const drive = await driveCli();
  let rootId = (await pool.query("SELECT valor FROM config WHERE clave='root_folder_id'")).rows[0]?.valor;
  if (!rootId) {
    rootId = await ensureCarpeta(drive, 'VADOCA_Gestion', null);
    await pool.query(`INSERT INTO config(clave,valor) VALUES('root_folder_id',$1) ON CONFLICT (clave) DO UPDATE SET valor=$1`, [rootId]);
  }
  const fCli = await ensureCarpeta(drive, `${clienteNum} - ${limpiar(clienteNombre)}`, rootId);
  const fTipo = await ensureCarpeta(drive, limpiar(tipoTrabajo), fCli);
  const fExp = await ensureCarpeta(drive, limpiar(nombreExp), fTipo);
  for (const s of SUBCARPETAS) await ensureCarpeta(drive, s, fExp);
  return fExp;
}
async function subirADrive(buffer, nombre, mime, parentId) {
  const drive = await driveCli();
  const r = await drive.files.create({
    requestBody: { name: nombre, parents: [parentId] },
    media: { mimeType: mime || 'application/octet-stream', body: Readable.from(buffer) },
    fields: 'id,name',
  });
  return r.data;
}
/* Copia legible del historial en la carpeta del expediente (la fuente de verdad es Postgres) */
async function actualizarHistorialDrive(expedienteId) {
  let doc = (await pool.query('SELECT carpeta_drive_id, historial_file_id FROM documentos WHERE expediente_id=$1 AND carpeta_drive_id IS NOT NULL LIMIT 1', [expedienteId])).rows[0];
  if (!doc) doc = (await pool.query('SELECT carpeta_drive_id, NULL as historial_file_id FROM procedimientos WHERE codigo_base=$1 AND carpeta_drive_id IS NOT NULL LIMIT 1', [expedienteId])).rows[0];
  if (!doc?.carpeta_drive_id) return;
  const entradas = (await pool.query('SELECT ts,autor,tipo,texto,adjuntos,hash FROM bitacora WHERE expediente_id=$1 ORDER BY id', [expedienteId])).rows;
  const contenido = JSON.stringify({ expediente: expedienteId, nota: 'Copia de lectura. Fuente de verdad: base de datos con cadena de integridad.', entradas }, null, 2);
  const drive = await driveCli();
  if (doc.historial_file_id) {
    await drive.files.update({ fileId: doc.historial_file_id, media: { mimeType: 'application/json', body: Readable.from(Buffer.from(contenido)) } });
  } else {
    const f = await drive.files.create({
      requestBody: { name: 'historial.json', parents: [doc.carpeta_drive_id] },
      media: { mimeType: 'application/json', body: Readable.from(Buffer.from(contenido)) }, fields: 'id',
    });
    await pool.query('UPDATE documentos SET historial_file_id=$1 WHERE expediente_id=$2', [f.data.id, expedienteId]);
    // para procedimientos no guardamos el file id: el archivo se encuentra por nombre en la carpeta
  }
}

/* ---------- Espejo de solo lectura en la hoja REGISTRO ---------- */
const COLS = ['ID','Fecha_Alta','Cliente_Num','Cliente_Nombre','Tipo_Trabajo','Linea','Prot_Inf','Tipo_Doc','Doc_Num','Version','Descripcion','Codigo_Interno_Cliente','Ref_Presupuesto','Estado','Fecha_Inicio','Fecha_Fin','Carpeta_Drive_URL','Autor','Ultimo_Movimiento','Conflicto_Legacy','Observaciones','Expediente_ID'];
let espejoTimer = null;
function programarEspejo() { clearTimeout(espejoTimer); espejoTimer = setTimeout(() => espejar().catch(e => console.error('espejo:', e.message)), 4000); }
async function espejar() {
  if (!SHEET_ID) return;
  const sheets = await sheetsCli();
  const meta = await sheets.spreadsheets.get({ spreadsheetId: SHEET_ID, fields: 'sheets.properties' });
  const titulos = meta.data.sheets.map(s => s.properties.title);
  const faltan = ['REGISTRO', 'PROCEDIMIENTOS', 'PRESUPUESTOS', 'PROYECTOS'].filter(t => !titulos.includes(t));
  if (faltan.length) await sheets.spreadsheets.batchUpdate({ spreadsheetId: SHEET_ID, requestBody: { requests: faltan.map(t => ({ addSheet: { properties: { title: t } } })) } });
  const NOTA = 'ESPEJO DE SOLO LECTURA — editar aquí NO modifica el sistema. Fuente de verdad: base de datos DocTracker.';
  async function hoja(titulo, encabezados, filas) {
    await sheets.spreadsheets.values.clear({ spreadsheetId: SHEET_ID, range: `'${titulo}'!A:Z` });
    await sheets.spreadsheets.values.update({ spreadsheetId: SHEET_ID, range: `'${titulo}'!A1`, valueInputOption: 'RAW',
      requestBody: { values: [[NOTA], encabezados, ...filas] } });
  }
  const docs = (await pool.query('SELECT * FROM documentos ORDER BY id')).rows;
  await hoja('REGISTRO', [...COLS, 'Proyecto'],
    docs.map(d => [d.codigo, d.fecha_alta, d.cliente_num, d.cliente_nombre, d.tipo_trabajo, d.linea, d.prot_inf, d.tipo_doc, d.doc_num, d.version, d.descripcion, d.codigo_interno_cliente, d.ref_presupuesto, d.estado, d.fecha_inicio, d.fecha_fin, d.carpeta_drive_url, d.autor, d.ultimo_movimiento ? new Date(d.ultimo_movimiento).toISOString() : '', d.conflicto_legacy ? 'TRUE' : '', d.observaciones, d.expediente_id, d.proyecto || '']));
  const poes = (await pool.query('SELECT * FROM procedimientos ORDER BY codigo_base, version')).rows;
  await hoja('PROCEDIMIENTOS', ['Codigo', 'Sector', 'Titulo', 'Version', 'Estado', 'Vigencia_Meses', 'Fecha_Vigencia', 'Fecha_Vencimiento', 'Autor', 'Ultimo_Movimiento', 'Carpeta_Drive'],
    poes.map(p => [p.codigo, p.sector, p.titulo, p.version, p.estado, p.vigencia_meses, p.fecha_vigencia || '', p.fecha_vencimiento || '', p.autor, p.ultimo_movimiento ? new Date(p.ultimo_movimiento).toISOString() : '', p.carpeta_drive_url || '']));
  const pres = (await pool.query('SELECT * FROM presupuestos ORDER BY codigo')).rows;
  await hoja('PRESUPUESTOS', ['Codigo', 'Cliente', 'Descripcion', 'Monto', 'Moneda', 'Fecha_Emision', 'Estado', 'Autor', 'Ultimo_Movimiento'],
    pres.map(p => [p.codigo, (p.cliente_num || '') + ' - ' + (p.cliente_nombre || ''), p.descripcion, p.monto || '', p.moneda || '', p.fecha_emision || '', p.estado, p.autor, p.ultimo_movimiento ? new Date(p.ultimo_movimiento).toISOString() : '']));
  const proys = (await pool.query("SELECT * FROM proyectos WHERE ambito <> 'personal' ORDER BY codigo")).rows;
  const vincs = (await pool.query('SELECT * FROM proyecto_presupuestos')).rows;
  await hoja('PROYECTOS', ['Codigo', 'Nombre', 'Cliente', 'Estado', 'Presupuestos', 'Alcance', 'Autor', 'Ultimo_Movimiento'],
    proys.map(p => [p.codigo, p.nombre, (p.cliente_num || '') + ' - ' + (p.cliente_nombre || ''), p.estado, vincs.filter(v => v.proyecto === p.codigo).map(v => v.presupuesto).join(', '), (p.alcance || '').slice(0, 500), p.autor, p.ultimo_movimiento ? new Date(p.ultimo_movimiento).toISOString() : '']));
}

/* ============================================================
   REGISTRO: expedientes y documentos
   ============================================================ */
const pad = (n, l) => String(n).padStart(l, '0');
const armarID = (linea, td, pi, cli, doc, ver) => `${linea}-${td}${pi ? '-' + pi : ''}-${cli}-${pad(doc, 3)}/${pad(ver, 2)}`;

app.get('/api/registro', auth(), async (_req, res) => {
  const r = await pool.query('SELECT * FROM documentos ORDER BY id');
  res.json(r.rows);
});
app.get('/api/expedientes/:id/bitacora', auth(), async (req, res) => {
  const r = await pool.query('SELECT id,ts,autor,tipo,texto,adjuntos,prev_hash,hash FROM bitacora WHERE expediente_id=$1 ORDER BY id DESC', [req.params.id]);
  res.json(r.rows);
});

/* Ingesta inteligente: ¿en qué expedientes ya aparece este código en nombres de adjuntos?
   Sirve para frenar subidas al expediente equivocado (ej: XLS083 en el expediente de XLS089). */
app.get('/api/adjuntos/donde', auth(), async (req, res) => {
  try {
    const q = String(req.query.q || '').trim();
    if (q.length < 3) return res.json([]);
    const r = await pool.query(
      `SELECT expediente_id, COUNT(*)::int n FROM bitacora
       WHERE adjuntos IS NOT NULL AND adjuntos::text ILIKE $1
       GROUP BY expediente_id ORDER BY n DESC LIMIT 20`, ['%' + q + '%']);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Anulación GxP de un adjunto: la entrada original NO se toca (cadena de hashes intacta).
   Se agrega una entrada de anulación que la referencia, se renombra el archivo en Drive
   como ANULADO_..., y el frontend bloquea el link. Reversible solo por bitácora manual. */
app.post('/api/bitacora/anular-adjunto', auth(['admin']), async (req, res) => {
  try {
    const { entrada_id, drive_id, motivo, desvio } = req.body || {};
    if (!entrada_id || !drive_id || !(motivo || '').trim())
      return res.status(400).json({ error: 'Faltan entrada, archivo o motivo (obligatorio)' });
    const ent = (await pool.query('SELECT * FROM bitacora WHERE id=$1', [entrada_id])).rows[0];
    if (!ent) return res.status(404).json({ error: 'Entrada de bitácora inexistente' });
    const adj = (ent.adjuntos || []).find(a => a.drive_id === drive_id);
    if (!adj) return res.status(404).json({ error: 'El archivo no pertenece a esa entrada' });
    const ya = await pool.query("SELECT 1 FROM bitacora WHERE tipo='anulacion' AND adjuntos @> $1::jsonb LIMIT 1",
      [JSON.stringify([{ anula: drive_id }])]);
    if (ya.rowCount) return res.status(400).json({ error: 'Ese adjunto ya está anulado' });

    const nuevoNombre = 'ANULADO_' + ahora().slice(0, 10) + '_' + adj.nombre;
    let renombrado = true;
    try {
      const drive = await driveCli();
      await drive.files.update({ fileId: drive_id, requestBody: { name: nuevoNombre }, supportsAllDrives: true });
    } catch (e) { renombrado = false; console.error('anular-adjunto rename:', e.message); }

    const fechaEnt = new Date(ent.ts).toISOString().slice(0, 10);
    const texto = `ADJUNTO ANULADO: "${adj.nombre}" (entrada #${ent.id} del ${fechaEnt}). Motivo: ${motivo.trim()}. ` +
      (desvio && String(desvio).trim() ? `Desvío asociado: ${String(desvio).trim()}. ` : 'Desvío asociado: N/A. ') +
      (renombrado ? `Archivo renombrado en Drive a "${nuevoNombre}".`
                  : 'ATENCIÓN: no se pudo renombrar el archivo en Drive; anulado solo en bitácora.');
    const entrada = await agregarBitacora(ent.expediente_id, req.user.email, 'anulacion', texto,
      [{ anula: drive_id, original: adj.nombre, nombre: renombrado ? nuevoNombre : adj.nombre, entrada: ent.id }]);
    res.json({ ok: true, entrada, renombrado });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
/* Verificación de la cadena de integridad de un expediente */
app.get('/api/expedientes/:id/verificar', auth(), async (req, res) => {
  const filas = (await pool.query('SELECT * FROM bitacora WHERE expediente_id=$1 ORDER BY id', [req.params.id])).rows;
  let prev = 'GENESIS', ok = true, rota_en = null;
  for (const f of filas) {
    const h = sha(prev + '|' + new Date(f.ts).toISOString() + '|' + f.autor + '|' + f.tipo + '|' + f.texto + '|' + JSON.stringify(f.adjuntos));
    if (h !== f.hash || f.prev_hash !== prev) { ok = false; rota_en = f.id; break; }
    prev = f.hash;
  }
  res.json({ ok, entradas: filas.length, rota_en });
});

app.post('/api/expedientes', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { ttKey, ttNombre, linea, cliente, clienteNombre, docs, desc, interno, presupuesto, proyecto } = req.body || {};
    if (!ttKey || !cliente || !desc || !Array.isArray(docs) || !docs.length) return res.status(400).json({ error: 'Faltan datos del expediente' });
    // Número siguiente con verificación en base (sin carreras)
    const r = await pool.query("SELECT COALESCE(MAX(CAST(doc_num AS INT)),0) m FROM documentos WHERE expediente_id LIKE $1", [`${ttKey}-${cliente}-%`]);
    const semilla = parseInt((await pool.query("SELECT valor FROM config WHERE clave=$1", [`semilla_${ttKey}_${cliente}`])).rows[0]?.valor || '0', 10);
    const doc = Math.max(r.rows[0].m, semilla) + 1;
    const expId = `${ttKey}-${cliente}-${pad(doc, 3)}`;
    const fExp = await crearCarpetasExpediente(cliente, clienteNombre || '', ttNombre || ttKey, `${expId} - ${desc}`);
    const url = `https://drive.google.com/drive/folders/${fExp}`;
    for (const [td, pi] of docs) {
      await pool.query(`INSERT INTO documentos(codigo,expediente_id,fecha_alta,cliente_num,cliente_nombre,tipo_trabajo,linea,prot_inf,tipo_doc,doc_num,version,descripcion,codigo_interno_cliente,ref_presupuesto,estado,fecha_inicio,carpeta_drive_id,carpeta_drive_url,autor,ultimo_movimiento,proyecto)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Borrador',$3,$15,$16,$17,now(),$18)`,
        [armarID(linea, td, pi, cliente, doc, 1), expId, ahora().slice(0, 10), cliente, clienteNombre || '', ttNombre || ttKey, linea, pi, td, pad(doc, 3), '01', desc, interno || '', presupuesto || '', fExp, url, req.user.email, proyecto || '']);
    }
    await agregarBitacora(expId, req.user.email, 'creacion', `Expediente creado. Documentos: ${docs.map(d => d[0] + '-' + d[1]).join(', ')}. Descripción: ${desc}`);
    programarEspejo();
    res.json({ ok: true, expediente: expId, carpeta: url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Corrección controlada de datos descriptivos (el código VADOCA es inmutable) */
app.post('/api/expedientes/:id/corregir', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { descripcion, interno, presupuesto, observaciones, motivo } = req.body || {};
    if (!motivo || !motivo.trim()) return res.status(400).json({ error: 'El motivo de la corrección es obligatorio' });
    const docs = (await pool.query('SELECT * FROM documentos WHERE expediente_id=$1', [req.params.id])).rows;
    if (!docs.length) return res.status(404).json({ error: 'Expediente no encontrado' });
    const antes = docs[0];
    const cambios = [];
    if (descripcion !== undefined && descripcion !== antes.descripcion) cambios.push(`Descripción: "${antes.descripcion}" → "${descripcion}"`);
    if (interno !== undefined && interno !== antes.codigo_interno_cliente) cambios.push(`Cód. interno cliente: "${antes.codigo_interno_cliente || '—'}" → "${interno || '—'}"`);
    if (presupuesto !== undefined && presupuesto !== antes.ref_presupuesto) cambios.push(`Ref. presupuesto: "${antes.ref_presupuesto || '—'}" → "${presupuesto || '—'}"`);
    if (observaciones !== undefined && observaciones !== antes.observaciones) cambios.push(`Observaciones actualizadas`);
    if (!cambios.length) return res.status(400).json({ error: 'No hay cambios para aplicar' });
    await pool.query(`UPDATE documentos SET descripcion=COALESCE($1,descripcion), codigo_interno_cliente=COALESCE($2,codigo_interno_cliente),
      ref_presupuesto=COALESCE($3,ref_presupuesto), observaciones=COALESCE($4,observaciones), ultimo_movimiento=now() WHERE expediente_id=$5`,
      [descripcion, interno, presupuesto, observaciones, req.params.id]);
    await agregarBitacora(req.params.id, req.user.email, 'correccion',
      `CORRECCIÓN DE DATOS. Motivo: ${motivo.trim()}. Cambios: ${cambios.join(' | ')}. (El código VADOCA no se modifica; para códigos mal asignados: cancelar el documento y crear el correcto.)`);
    programarEspejo();
    res.json({ ok: true, cambios });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Reasignación controlada del número de expediente (solo admin, con motivo y trazabilidad total) */
app.post('/api/expedientes/:id/reasignar', auth(['admin']), async (req, res) => {
  try {
    const { nuevoNumero, motivo } = req.body || {};
    if (!motivo || !motivo.trim()) return res.status(400).json({ error: 'El motivo es obligatorio' });
    const nuevo = String(parseInt(nuevoNumero, 10)).padStart(3, '0');
    if (isNaN(parseInt(nuevoNumero, 10))) return res.status(400).json({ error: 'Número nuevo inválido' });
    const docs = (await pool.query('SELECT * FROM documentos WHERE expediente_id=$1', [req.params.id])).rows;
    if (!docs.length) return res.status(404).json({ error: 'Expediente no encontrado' });
    const d0 = docs[0];
    const partes = req.params.id.split('-'); // TT-CLIENTE-NUM
    const tt = partes[0], cliente = partes[1], viejo = partes[2];
    if (nuevo === viejo) return res.status(400).json({ error: 'El número nuevo es igual al actual' });
    const expNuevo = `${tt}-${cliente}-${nuevo}`;
    const ocupado = await pool.query('SELECT 1 FROM documentos WHERE expediente_id=$1 LIMIT 1', [expNuevo]);
    if (ocupado.rowCount) return res.status(400).json({ error: `El número ${nuevo} ya está ocupado (${expNuevo})` });
    // Actualizar códigos de todos los documentos preservando su formato original
    const re = new RegExp(`-${cliente}-${viejo}(/)`);
    for (const d of docs) {
      const codNuevo = d.codigo.replace(re, `-${cliente}-${nuevo}$1`);
      await pool.query('UPDATE documentos SET codigo=$1, doc_num=$2, expediente_id=$3, ultimo_movimiento=now() WHERE id=$4',
        [codNuevo, nuevo, expNuevo, d.id]);
    }
    // Migrar la bitácora al código nuevo (la cadena de hashes no depende del código: la integridad se preserva)
    await pool.query('UPDATE bitacora SET expediente_id=$1 WHERE expediente_id=$2', [expNuevo, req.params.id]);
    // Renombrar la carpeta de Drive si existe
    if (d0.carpeta_drive_id) {
      try {
        const drive = await driveCli();
        await drive.files.update({ fileId: d0.carpeta_drive_id, requestBody: { name: limpiar(`${expNuevo} - ${d0.descripcion}`) } });
      } catch (e) { /* si falla el renombre, el registro queda igual correcto */ }
    }
    await agregarBitacora(expNuevo, req.user.email, 'correccion',
      `REASIGNACIÓN DE CÓDIGO DE EXPEDIENTE: ${req.params.id} → ${expNuevo}. Documentos: ${docs.map(d => d.codigo.replace(re, `-${cliente}-${nuevo}$1`)).join(', ')}. Motivo: ${motivo.trim()}.`);
    await logAdmin(req.user.email, 'reasignacion_expediente', `${req.params.id} → ${expNuevo}`);
    programarEspejo();
    res.json({ ok: true, expediente: expNuevo });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Reconstrucción de presupuestos históricos desde las referencias del registro */
app.post('/api/presupuestos/importar-desde-registro', auth(['admin']), async (req, res) => {
  try {
    const refs = (await pool.query(`SELECT ref_presupuesto rp, MIN(cliente_num) cn, MIN(cliente_nombre) cno,
        STRING_AGG(DISTINCT tipo_trabajo, ' + ') tt, COUNT(DISTINCT expediente_id) n
      FROM documentos WHERE ref_presupuesto IS NOT NULL AND ref_presupuesto <> '' AND ref_presupuesto ~ '^\\d+$'
      GROUP BY ref_presupuesto ORDER BY ref_presupuesto`)).rows;
    let creados = 0, saltados = 0;
    for (const r of refs) {
      const codigo = r.rp.padStart(4, '0');
      const existe = await pool.query('SELECT 1 FROM presupuestos WHERE codigo=$1', [codigo]);
      if (existe.rowCount) { saltados++; continue; }
      await pool.query(`INSERT INTO presupuestos(codigo,cliente_num,cliente_nombre,descripcion,estado,autor,ultimo_movimiento)
        VALUES($1,$2,$3,$4,'Aceptado',$5,now())`,
        [codigo, r.cn || '', r.cno || '', `${r.tt} — ${r.cno || ''} (histórico, ${r.n} expediente(s))`, 'reconstruccion@' + req.user.email]);
      await agregarBitacora('PRES-' + codigo, req.user.email, 'creacion',
        `Presupuesto reconstruido desde el registro histórico: referenciado por ${r.n} expediente(s) de ${r.tt}. Estado asignado: Aceptado (trabajo ejecutado).`);
      creados++;
    }
    await logAdmin(req.user.email, 'importacion_presupuestos', `${creados} reconstruidos, ${saltados} ya existían`);
    programarEspejo();
    res.json({ ok: true, creados, saltados });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Máquina de estados de documentos. Circuito: Borrador → En revisión → En ejecución →
   Enviado a cliente → Entregado. Laterales: Suspendido / Cancelado.
   Avanzar: libre. Retroceder, entrar/salir de laterales o reabrir terminales: motivo obligatorio.
   (Validable / No validable / Aprobado quedan como legacy: se pueden abandonar, no elegir.) */
const DOC_RANK = { 'Borrador': 0, 'En revisión': 1, 'Validable': 1, 'No validable': 1, 'En ejecución': 2, 'Enviado a cliente': 3, 'Aprobado': 4, 'Entregado': 5 };
const DOC_TERMINALES = ['Entregado', 'Cancelado'];
function claseTransicionDoc(viejo, nuevo) {
  if (viejo === nuevo) return { tipo: 'igual', motivo: false };
  if (DOC_TERMINALES.includes(viejo)) return { tipo: 'reapertura', motivo: true };
  if (viejo === 'Suspendido') return { tipo: 'reanudación', motivo: true };
  if (nuevo === 'Suspendido' || nuevo === 'Cancelado') return { tipo: 'lateral', motivo: true };
  const rv = DOC_RANK[viejo] ?? 2, rn = DOC_RANK[nuevo] ?? 2;
  return rn > rv ? { tipo: 'avance', motivo: false } : { tipo: 'retroceso', motivo: true };
}

app.post('/api/documentos/:codigo/estado', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { estado, motivo } = req.body || {};
    const doc = (await pool.query('SELECT estado, expediente_id FROM documentos WHERE codigo=$1', [req.params.codigo])).rows[0];
    if (!doc) return res.status(404).json({ error: 'Documento no encontrado' });
    const c = claseTransicionDoc(doc.estado, estado);
    if (c.tipo === 'igual') return res.json({ ok: true, sin_cambio: true });
    if (c.motivo && !(motivo || '').trim())
      return res.status(400).json({ error: `${doc.estado} → ${estado} es ${c.tipo}: requiere un motivo (queda en bitácora)` });
    await pool.query(`UPDATE documentos SET estado=$1, ultimo_movimiento=now(), fecha_fin=CASE WHEN $1='Entregado' THEN $2 ELSE fecha_fin END WHERE codigo=$3`,
      [estado, ahora().slice(0, 10), req.params.codigo]);
    await agregarBitacora(doc.expediente_id, req.user.email, 'estado',
      `${req.params.codigo} → estado: ${estado}` + (c.motivo ? ` [${c.tipo}] Motivo: ${motivo.trim()}` : ''));
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/expedientes/:id/notas', auth(['admin', 'editor']), upload.array('archivos', 30), async (req, res) => {
  try {
    const expId = req.params.id;
    const { texto, subcarpeta } = req.body || {};
    const docs = (await pool.query('SELECT * FROM documentos WHERE expediente_id=$1', [expId])).rows;
    if (!docs.length) return res.status(404).json({ error: 'Expediente no encontrado' });
    let base = docs[0];
    if (!base.carpeta_drive_id) { // expediente importado sin carpeta: se crea acá
      const fExp = await crearCarpetasExpediente(base.cliente_num, base.cliente_nombre, base.tipo_trabajo, `${expId} - ${base.descripcion}`);
      await pool.query('UPDATE documentos SET carpeta_drive_id=$1, carpeta_drive_url=$2 WHERE expediente_id=$3', [fExp, `https://drive.google.com/drive/folders/${fExp}`, expId]);
      base.carpeta_drive_id = fExp;
    }
    const adjuntos = [];
    if (req.files?.length) {
      const drive = await driveCli();
      const sub = SUBCARPETAS.includes(subcarpeta) ? subcarpeta : '02_evidencias';
      const subId = await ensureCarpeta(drive, sub, base.carpeta_drive_id);
      for (const f of req.files) {
        const nombre = `${ahora().slice(0, 10)}_${Buffer.from(f.originalname, 'latin1').toString('utf8')}`;
        const up = await subirADrive(f.buffer, nombre, f.mimetype, subId);
        adjuntos.push({ nombre, drive_id: up.id, subcarpeta: sub });
      }
    }
    if (!texto && !adjuntos.length) return res.status(400).json({ error: 'La nota está vacía' });
    const tipo = subcarpeta === '01_versiones' ? 'version' : adjuntos.length ? 'archivo' : 'nota';
    const entrada = await agregarBitacora(expId, req.user.email, tipo, texto || `Se subieron ${adjuntos.length} archivo(s) a ${subcarpeta}`, adjuntos);
    await pool.query('UPDATE documentos SET ultimo_movimiento=now() WHERE expediente_id=$1', [expId]);
    programarEspejo();
    res.json({ ok: true, entrada });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   INTEGRACIÓN IA (n8n / Claude / ChatGPT) — API key propia, nunca el JWT admin.
   100% LECTURA. La escritura (alta de expedientes, carga de archivos) se dio de baja:
   en la práctica no funcionaba bien vía Custom GPT Actions y el riesgo de un expediente
   mal identificado (código correcto pero expediente equivocado) no vale la pena para
   un flujo que Dami puede hacer él mismo desde la UI en segundos. Si en algún momento
   se reconsidera, la versión anterior queda en el historial de git (ver PRs #1-#5).

   Estos tres endpoints son deliberadamente agregados/acotados (nunca el dump completo
   de `documentos`) para que una consulta amplia ("qué falta entregar", "cómo viene tal
   proyecto") no requiera que quien pregunta conozca de antemano un código exacto —
   esa rigidez fue justamente la queja: "las consultas no funcionaron bien porque tienen
   que ser muy específicas". /api/seguimiento/data sigue existiendo para el lookup puntual
   por expediente/código/código de planilla.
   ============================================================ */

/* Bitácora del sistema completo (todos los expedientes), acotada por fecha — pensada para
   un audit trail semanal. Sin rango, trae los últimos 7 días. texto se devuelve completo
   (no es un dump de documentos, el volumen semanal de bitácora es manejable). */
app.get('/api/integracion/auditoria', auth(), async (req, res) => {
  try {
    const hasta = req.query.hasta ? `${req.query.hasta} 23:59:59` : ahora();
    const desdeDefault = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
    const desde = req.query.desde ? `${req.query.desde} 00:00:00` : `${desdeDefault} 00:00:00`;
    const r = await pool.query(
      `SELECT expediente_id, ts, autor, tipo, texto FROM bitacora WHERE ts BETWEEN $1 AND $2 ORDER BY ts DESC LIMIT 500`,
      [desde, hasta]);
    res.json({ desde: desde.slice(0, 10), hasta: hasta.slice(0, 10), entradas: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Documentos que NO están en un estado terminal (Entregado/Cancelado), con los días
   transcurridos desde el último movimiento — "qué falta entregar", ordenado por lo más
   estancado primero. cliente_num opcional para acotar a un cliente puntual. */
app.get('/api/integracion/pendientes', auth(), async (req, res) => {
  try {
    const vals = []; const filtros = ["estado NOT IN ('Entregado','Cancelado')"];
    if (req.query.cliente_num) { vals.push(req.query.cliente_num); filtros.push(`cliente_num=$${vals.length}`); }
    const r = await pool.query(
      `SELECT codigo, expediente_id, cliente_num, codigo_interno_cliente, estado, descripcion,
              EXTRACT(DAY FROM now() - ultimo_movimiento)::int AS dias_sin_movimiento
       FROM documentos WHERE ${filtros.join(' AND ')}
       ORDER BY ultimo_movimiento ASC NULLS FIRST LIMIT 300`, vals);
    res.json({ pendientes: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Estado de proyectos, con cuántos documentos de cada uno siguen pendientes — "cómo
   viene tal proyecto" sin tener que pedir expediente por expediente. estado=todos trae
   también los cerrados (por defecto solo los que siguen con trabajo real).

   OJO: la columna `estado` de la tabla puede quedar desincronizada de la realidad, y el
   panel web NO la usa tal cual para la etiqueta que le muestra a Dami. La regla real
   (la misma que aplica el panel) es por COMPLETITUD de documentos, no por esa columna:
   - Proyecto CON documentos vinculados ("con seguimiento"): Cerrado si no le queda
     ningún documento pendiente, Activo si le queda al menos uno — pase lo que diga la
     columna cruda.
   - Proyecto SIN ningún documento vinculado ("sin seguimiento", ej. uno recién creado
     o llevado aparte): no hay forma de calcularlo por completitud, así que ahí sí se
     usa la columna cruda tal cual.
   La columna cruda se expone aparte (estado_db) solo como referencia/diagnóstico, y
   `inconsistente` marca cuando un proyecto CON seguimiento no coincide con su columna
   cruda — para poder avisar de ese tipo de desincronización en vez de repetirla. */
app.get('/api/integracion/proyectos', auth(), async (req, res) => {
  try {
    const todos = req.query.estado === 'todos';
    const proys = (await pool.query(
      `SELECT codigo, nombre, cliente_num, cliente_nombre, estado AS estado_db, ultimo_movimiento
       FROM proyectos WHERE ambito <> 'personal' ORDER BY ultimo_movimiento DESC NULLS LAST LIMIT 200`)).rows;
    const totales = (await pool.query(
      `SELECT proyecto, COUNT(*)::int n FROM documentos WHERE proyecto <> '' GROUP BY proyecto`)).rows;
    const pend = (await pool.query(
      `SELECT proyecto, COUNT(*)::int n FROM documentos WHERE proyecto <> '' AND estado NOT IN ('Entregado','Cancelado') GROUP BY proyecto`)).rows;
    const mapaTotales = Object.fromEntries(totales.map(p => [p.proyecto, p.n]));
    const mapaPend = Object.fromEntries(pend.map(p => [p.proyecto, p.n]));
    let proyectos = proys.map(p => {
      const documentos_totales = mapaTotales[p.codigo] || 0;
      const documentos_pendientes = mapaPend[p.codigo] || 0;
      const conSeguimiento = documentos_totales > 0;
      const estado = conSeguimiento ? (documentos_pendientes > 0 ? 'Activo' : 'Cerrado') : p.estado_db;
      return { ...p, documentos_pendientes, estado,
        inconsistente: conSeguimiento && estado !== p.estado_db };
    });
    if (!todos) proyectos = proyectos.filter(p => p.estado === 'Activo');
    res.json({ proyectos });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/expedientes/:id/nueva-version', auth(['admin', 'editor']), async (req, res) => {
  try {
    const expId = req.params.id;
    const { codigos, motivo } = req.body || {}; // códigos de los documentos a reversionar
    const sel = (await pool.query('SELECT * FROM documentos WHERE expediente_id=$1 AND codigo = ANY($2)', [expId, codigos || []])).rows;
    if (!sel.length) return res.status(400).json({ error: 'Elegí al menos un documento' });
    const nuevos = [];
    for (const d of sel) {
      const nv = parseInt(d.version, 10) + 1;
      const codigo = armarID(d.linea, d.tipo_doc, d.prot_inf, d.cliente_num, parseInt(d.doc_num, 10), nv);
      await pool.query(`INSERT INTO documentos(codigo,expediente_id,fecha_alta,cliente_num,cliente_nombre,tipo_trabajo,linea,prot_inf,tipo_doc,doc_num,version,descripcion,codigo_interno_cliente,ref_presupuesto,estado,fecha_inicio,carpeta_drive_id,carpeta_drive_url,historial_file_id,autor,ultimo_movimiento)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Borrador',$3,$15,$16,$17,$18,now())`,
        [codigo, expId, ahora().slice(0, 10), d.cliente_num, d.cliente_nombre, d.tipo_trabajo, d.linea, d.prot_inf, d.tipo_doc, d.doc_num, pad(nv, 2), d.descripcion, d.codigo_interno_cliente, d.ref_presupuesto, d.carpeta_drive_id, d.carpeta_drive_url, d.historial_file_id, req.user.email]);
      nuevos.push(codigo);
    }
    await agregarBitacora(expId, req.user.email, 'version', `Nueva versión creada: ${nuevos.join(', ')}${motivo ? '. Motivo: ' + motivo : ''}`);
    programarEspejo();
    res.json({ ok: true, nuevos });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- Migración única desde la hoja REGISTRO actual ---------- */
app.post('/api/migrar', auth(['admin']), async (req, res) => {
  try {
    const ya = await pool.query('SELECT COUNT(*)::int c FROM documentos');
    if (ya.rows[0].c > 0) return res.status(400).json({ error: 'La base ya tiene documentos: la migración es solo para el arranque' });
    const sheets = await sheetsCli();
    const d = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: "'REGISTRO'!A1:W100000" });
    const filas = d.data.values || [];
    if (filas.length < 2) return res.status(400).json({ error: 'La hoja REGISTRO está vacía' });
    const head = filas[0]; const ix = (n) => head.indexOf(n);
    let n = 0;
    for (const v of filas.slice(1)) {
      const g = (c) => v[ix(c)] || '';
      if (!g('ID')) continue;
      await pool.query(`INSERT INTO documentos(codigo,expediente_id,fecha_alta,cliente_num,cliente_nombre,tipo_trabajo,linea,prot_inf,tipo_doc,doc_num,version,descripcion,codigo_interno_cliente,ref_presupuesto,estado,fecha_inicio,fecha_fin,carpeta_drive_id,carpeta_drive_url,historial_file_id,conflicto_legacy,observaciones,autor,ultimo_movimiento)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) ON CONFLICT (codigo) DO NOTHING`,
        [g('ID'), g('Expediente_ID'), g('Fecha_Alta'), g('Cliente_Num'), g('Cliente_Nombre'), g('Tipo_Trabajo'), g('Linea'), g('Prot_Inf'), g('Tipo_Doc'), g('Doc_Num'), g('Version'), g('Descripcion'), g('Codigo_Interno_Cliente'), g('Ref_Presupuesto'), g('Estado') || 'Borrador', g('Fecha_Inicio'), g('Fecha_Fin'), g('Carpeta_Drive_ID') || null, g('Carpeta_Drive_URL') || null, g('Historial_File_ID') || null, g('Conflicto_Legacy') === 'TRUE', g('Observaciones'), 'migracion@' + (req.user.email), g('Ultimo_Movimiento') ? new Date(g('Ultimo_Movimiento')) : null]);
      n++;
    }
    await logAdmin(req.user.email, 'migracion_inicial', `${n} documentos importados desde Sheets`);
    programarEspejo();
    res.json({ ok: true, importados: n });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   MÓDULO PROCEDIMIENTOS VADOCA (POEs con vigencia y versionado)
   ============================================================ */
app.get('/api/procedimientos', auth(), async (_req, res) => {
  const r = await pool.query('SELECT * FROM procedimientos ORDER BY codigo_base, version');
  res.json(r.rows);
});

app.post('/api/procedimientos', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { titulo, vigencia_meses, sector } = req.body || {};
    if (!titulo) return res.status(400).json({ error: 'Falta el título del procedimiento' });
    const sec = String(sector || 'POE').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6) || 'POE';
    // Correlativo GLOBAL: número siguiente al máximo de todos los POEs, sin importar el sector
    const m = await pool.query("SELECT COALESCE(MAX(CAST(SUBSTRING(codigo_base FROM '(\\d+)$') AS INT)),0) mx FROM procedimientos");
    const num = m.rows[0].mx + 1;
    const base = sec + '-' + String(num).padStart(3, '0');
    const codigo = base + '/01';
    const fExp = await crearCarpetasExpediente('000', 'VADOCA', 'Procedimientos', `${base} - ${titulo}`);
    const url = `https://drive.google.com/drive/folders/${fExp}`;
    await pool.query(`INSERT INTO procedimientos(codigo,codigo_base,sector,titulo,version,estado,vigencia_meses,carpeta_drive_id,carpeta_drive_url,autor,ultimo_movimiento)
      VALUES($1,$2,$3,$4,'01','Borrador',$5,$6,$7,$8,now())`,
      [codigo, base, sec, titulo, parseInt(vigencia_meses, 10) || 36, fExp, url, req.user.email]);
    await agregarBitacora(base, req.user.email, 'creacion', `Procedimiento creado: ${codigo} — ${titulo}. Vigencia: ${parseInt(vigencia_meses, 10) || 36} meses desde su entrada en vigencia.`);
    res.json({ ok: true, codigo, base, carpeta: url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Relaciones entre POEs (bidireccionales a efectos del análisis de impacto) */
app.get('/api/poe-relaciones', auth(), async (_req, res) => {
  const r = await pool.query('SELECT base, relacionado FROM poe_relaciones ORDER BY base');
  res.json(r.rows);
});
app.post('/api/poe-relaciones/:base', auth(['admin', 'editor']), async (req, res) => {
  try {
    const base = req.params.base;
    const rels = [...new Set((req.body?.relacionados || []).filter(r => r && r !== base))];
    const antes = (await pool.query('SELECT relacionado FROM poe_relaciones WHERE base=$1 ORDER BY relacionado', [base])).rows.map(r => r.relacionado);
    await pool.query('DELETE FROM poe_relaciones WHERE base=$1', [base]);
    for (const r of rels) await pool.query('INSERT INTO poe_relaciones(base,relacionado) VALUES($1,$2) ON CONFLICT DO NOTHING', [base, r]);
    if (JSON.stringify(antes) !== JSON.stringify([...rels].sort()))
      await agregarBitacora(base, req.user.email, 'relacion', `Documentos relacionados actualizados: ${rels.length ? rels.join(', ') : 'ninguno'}${antes.length ? ' (antes: ' + antes.join(', ') + ')' : ''}`);
    res.json({ ok: true, relacionados: rels });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
async function relacionadosDePoe(base) { // ambas direcciones, sin duplicados
  const r = await pool.query('SELECT relacionado x FROM poe_relaciones WHERE base=$1 UNION SELECT base x FROM poe_relaciones WHERE relacionado=$1', [base]);
  return r.rows.map(x => x.x);
}

app.post('/api/procedimientos/importar', auth(['admin']), async (req, res) => {
  try {
    const { filas } = req.body || {}; // [{sector, numero, version, titulo, fecha_vigencia, vigencia_meses}]
    if (!Array.isArray(filas) || !filas.length) return res.status(400).json({ error: 'No hay filas para importar' });
    let importados = 0, saltados = 0; const errores = [];
    for (const f of filas) {
      try {
        const sec = String(f.sector || 'POE').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 6) || 'POE';
        const num = String(parseInt(f.numero, 10)).padStart(3, '0');
        const ver = String(parseInt(f.version, 10) || 1).padStart(2, '0');
        if (!f.titulo || isNaN(parseInt(f.numero, 10))) throw new Error('faltan título o número');
        const base = sec + '-' + num, codigo = base + '/' + ver;
        const meses = parseInt(f.vigencia_meses, 10) || 36;
        let venc = null, estado = 'Borrador';
        if (f.fecha_vigencia) {
          const d = new Date(f.fecha_vigencia + 'T00:00:00');
          if (isNaN(d)) throw new Error('fecha inválida (usar AAAA-MM-DD)');
          const v = new Date(d); v.setMonth(v.getMonth() + meses);
          venc = v.toISOString().slice(0, 10); estado = 'Vigente';
        }
        const r = await pool.query(`INSERT INTO procedimientos(codigo,codigo_base,sector,titulo,version,estado,vigencia_meses,fecha_vigencia,fecha_vencimiento,autor,ultimo_movimiento)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,now()) ON CONFLICT (codigo) DO NOTHING RETURNING id`,
          [codigo, base, sec, String(f.titulo).trim().slice(0, 120), ver, estado, meses, f.fecha_vigencia || null, venc, 'importacion@' + req.user.email]);
        if (r.rowCount) {
          importados++;
          await agregarBitacora(base, req.user.email, 'creacion', `Importado del sistema documental previo: ${codigo} — ${f.titulo}.` + (venc ? ` Vigente desde ${f.fecha_vigencia}, vence ${venc}.` : ''));
        } else saltados++;
      } catch (err) { errores.push((f.sector || '?') + '-' + (f.numero || '?') + ': ' + err.message); }
    }
    await logAdmin(req.user.email, 'importacion_poes', `${importados} importados, ${saltados} ya existían, ${errores.length} con error`);
    res.json({ ok: true, importados, saltados, errores });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/procedimientos/:codigo/estado', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { estado } = req.body || {};
    const p = (await pool.query('SELECT * FROM procedimientos WHERE codigo=$1', [req.params.codigo])).rows[0];
    if (!p) return res.status(404).json({ error: 'Procedimiento no encontrado' });
    if (estado === 'Vigente') {
      const desde = new Date();
      const vence = new Date(desde); vence.setMonth(vence.getMonth() + p.vigencia_meses);
      await pool.query(`UPDATE procedimientos SET estado='Vigente', fecha_vigencia=$1, fecha_vencimiento=$2, ultimo_movimiento=now() WHERE codigo=$3`,
        [desde.toISOString().slice(0, 10), vence.toISOString().slice(0, 10), p.codigo]);
      // única versión vigente por procedimiento: las demás pasan a Obsoleto
      const obs = await pool.query(`UPDATE procedimientos SET estado='Obsoleto', ultimo_movimiento=now() WHERE codigo_base=$1 AND codigo<>$2 AND estado='Vigente' RETURNING codigo`, [p.codigo_base, p.codigo]);
      await agregarBitacora(p.codigo_base, req.user.email, 'estado', `${p.codigo} → VIGENTE desde ${desde.toISOString().slice(0, 10)}, vence ${vence.toISOString().slice(0, 10)}.` + (obs.rowCount ? ` Pasan a Obsoleto: ${obs.rows.map(r => r.codigo).join(', ')}.` : ''));
    } else {
      await pool.query('UPDATE procedimientos SET estado=$1, ultimo_movimiento=now() WHERE codigo=$2', [estado, p.codigo]);
      await agregarBitacora(p.codigo_base, req.user.email, 'estado', `${p.codigo} → estado: ${estado}`);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/procedimientos/:base/nueva-version', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { motivo, vigencia_meses } = req.body || {};
    const ult = (await pool.query('SELECT * FROM procedimientos WHERE codigo_base=$1 ORDER BY CAST(version AS INT) DESC LIMIT 1', [req.params.base])).rows[0];
    if (!ult) return res.status(404).json({ error: 'Procedimiento no encontrado' });
    const nv = String(parseInt(ult.version, 10) + 1).padStart(2, '0');
    const codigo = ult.codigo_base + '/' + nv;
    await pool.query(`INSERT INTO procedimientos(codigo,codigo_base,titulo,version,estado,vigencia_meses,carpeta_drive_id,carpeta_drive_url,autor,ultimo_movimiento)
      VALUES($1,$2,$3,$4,'Borrador',$5,$6,$7,$8,now())`,
      [codigo, ult.codigo_base, ult.titulo, nv, parseInt(vigencia_meses, 10) || ult.vigencia_meses, ult.carpeta_drive_id, ult.carpeta_drive_url, req.user.email]);
    const impactados = await relacionadosDePoe(ult.codigo_base);
    await agregarBitacora(ult.codigo_base, req.user.email, 'version', `Nueva versión ${codigo} en Borrador.${motivo ? ' Motivo: ' + motivo : ''} La versión vigente sigue siéndolo hasta aprobar y poner en vigencia la nueva.` + (impactados.length ? ` Impacto a evaluar sobre documentos relacionados: ${impactados.join(', ')}.` : ''));
    res.json({ ok: true, codigo, impactados });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/procedimientos/:base/notas', auth(['admin', 'editor']), upload.array('archivos', 30), async (req, res) => {
  try {
    const base = req.params.base;
    const { texto, subcarpeta } = req.body || {};
    let p = (await pool.query('SELECT * FROM procedimientos WHERE codigo_base=$1 LIMIT 1', [base])).rows[0];
    if (!p) return res.status(404).json({ error: 'Procedimiento no encontrado' });
    if (!p.carpeta_drive_id) { // importado sin carpeta: se crea acá, una sola vez
      const fExp = await crearCarpetasExpediente('000', 'VADOCA', 'Procedimientos', `${base} - ${p.titulo}`);
      await pool.query('UPDATE procedimientos SET carpeta_drive_id=$1, carpeta_drive_url=$2 WHERE codigo_base=$3',
        [fExp, `https://drive.google.com/drive/folders/${fExp}`, base]);
      p.carpeta_drive_id = fExp;
    }
    const adjuntos = [];
    if (req.files?.length) {
      const drive = await driveCli();
      const sub = SUBCARPETAS.includes(subcarpeta) ? subcarpeta : '01_versiones';
      const subId = await ensureCarpeta(drive, sub, p.carpeta_drive_id);
      // Nombre asignado por el sistema (integridad de nomenclatura): no importa cómo se llame el archivo original.
      const ult = (await pool.query('SELECT MAX(CAST(version AS INT)) v FROM procedimientos WHERE codigo_base=$1', [base])).rows[0].v || 1;
      const ver = String(ult).padStart(2, '0');
      let i = 0;
      for (const f of req.files) {
        i++;
        const orig = Buffer.from(f.originalname, 'latin1').toString('utf8');
        const ext = (orig.match(/\.[A-Za-z0-9]+$/) || [''])[0].toLowerCase();
        const sufijo = req.files.length > 1 ? '_' + i : '';
        let nombre;
        if (sub === '03_entregables')      nombre = `${base}_v${ver}_${ahora().slice(0, 10)}${sufijo}${ext}`;
        else if (sub === '01_versiones')   nombre = `${base}_v${ver}_borrador_${ahora().slice(0, 10)}${sufijo}${ext}`;
        else                               nombre = `${ahora().slice(0, 10)}_${orig}`; // evidencias conservan su identidad
        const up = await subirADrive(f.buffer, nombre, f.mimetype, subId);
        adjuntos.push({ nombre, original: orig, drive_id: up.id, subcarpeta: sub });
      }
    }
    if (!texto && !adjuntos.length) return res.status(400).json({ error: 'La nota está vacía' });
    const entrada = await agregarBitacora(base, req.user.email, adjuntos.length ? 'archivo' : 'nota', texto || `Se subieron ${adjuntos.length} archivo(s)`, adjuntos);
    await pool.query('UPDATE procedimientos SET ultimo_movimiento=now() WHERE codigo_base=$1', [base]);
    res.json({ ok: true, entrada });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- Recuperación de bitácoras v1 (historial.json en Drive) ---------- */
app.post('/api/importar-historiales', auth(['admin']), async (req, res) => {
  try {
    const exps = (await pool.query(`SELECT DISTINCT expediente_id, historial_file_id FROM documentos
                                    WHERE historial_file_id IS NOT NULL AND historial_file_id <> ''`)).rows;
    const drive = await driveCli();
    let importadas = 0, saltados = 0; const errores = [];
    for (const e of exps) {
      // idempotente: si el expediente ya tiene bitácora en la base, no se toca
      const ya = await pool.query('SELECT 1 FROM bitacora WHERE expediente_id=$1 LIMIT 1', [e.expediente_id]);
      if (ya.rowCount) { saltados++; continue; }
      try {
        const f = await drive.files.get({ fileId: e.historial_file_id, alt: 'media' });
        const data = typeof f.data === 'object' ? f.data : JSON.parse(f.data);
        for (const n of (data.entradas || [])) {
          const prev = await ultimoHash('bitacora', 'WHERE expediente_id=$1', [e.expediente_id]);
          const ts = n.ts || ahora();
          const autor = n.autor || 'v1';
          const tipo = n.tipo || 'nota';
          const texto = n.texto || '';
          const adjuntos = n.adjuntos || [];
          const h = sha(prev + '|' + new Date(ts).toISOString() + '|' + autor + '|' + tipo + '|' + texto + '|' + JSON.stringify(adjuntos));
          await pool.query('INSERT INTO bitacora(expediente_id,ts,autor,tipo,texto,adjuntos,prev_hash,hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
            [e.expediente_id, ts, autor, tipo, texto, JSON.stringify(adjuntos), prev, h]);
          importadas++;
        }
      } catch (err) { errores.push(e.expediente_id + ': ' + err.message); }
    }
    await logAdmin(req.user.email, 'importacion_historiales_v1', `${importadas} entradas recuperadas; ${saltados} expedientes ya tenían bitácora`);
    res.json({ ok: true, entradas: importadas, expedientes: exps.length, saltados, errores });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   MÓDULO PRESUPUESTOS (acceso exclusivo del rol admin)
   ============================================================ */
app.get('/api/presupuestos', auth(['admin']), async (_req, res) => {
  res.json((await pool.query('SELECT * FROM presupuestos ORDER BY codigo DESC')).rows);
});
app.post('/api/presupuestos', auth(['admin']), async (req, res) => {
  try {
    const { cliente, clienteNombre, descripcion, monto, moneda, fecha_emision } = req.body || {};
    if (!descripcion) return res.status(400).json({ error: 'Falta la descripción' });
    // Correlativo que continúa la serie histórica (último conocido: 0081)
    const m = await pool.query("SELECT COALESCE(MAX(CAST(codigo AS INT)), 81) mx FROM presupuestos");
    const codigo = String(m.rows[0].mx + 1).padStart(4, '0');
    await pool.query(`INSERT INTO presupuestos(codigo,cliente_num,cliente_nombre,descripcion,monto,moneda,fecha_emision,estado,autor,ultimo_movimiento)
      VALUES($1,$2,$3,$4,$5,$6,$7,'Borrador',$8,now())`,
      [codigo, cliente || '', clienteNombre || '', descripcion, monto || null, moneda || 'ARS', fecha_emision || ahora().slice(0, 10), req.user.email]);
    await agregarBitacora('PRES-' + codigo, req.user.email, 'creacion', `Presupuesto ${codigo} creado — ${descripcion}${monto ? ' (' + (moneda || 'ARS') + ' ' + monto + ')' : ''}.`);
    res.json({ ok: true, codigo });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
/* Importación masiva de presupuestos históricos (crea faltantes y completa reconstruidos) */
app.post('/api/presupuestos/importar', auth(['admin']), async (req, res) => {
  try {
    const { filas } = req.body || {};
    if (!Array.isArray(filas) || !filas.length) return res.status(400).json({ error: 'No hay filas para importar' });
    let creados = 0, actualizados = 0, saltados = 0; const errores = [];
    for (const f of filas) {
      try {
        const codigo = String(f.codigo).replace(/\D/g, '').padStart(4, '0');
        if (!codigo || !f.descripcion) throw new Error('faltan código o descripción');
        const estado = ['Borrador', 'Enviado', 'Aceptado', 'Rechazado', 'Vencido'].includes(f.estado) ? f.estado : 'Aceptado';
        const ex = (await pool.query('SELECT * FROM presupuestos WHERE codigo=$1', [codigo])).rows[0];
        if (ex && !String(ex.autor || '').startsWith('reconstruccion@')) { saltados++; continue; }
        if (ex) {
          await pool.query(`UPDATE presupuestos SET cliente_num=$1, cliente_nombre=$2, descripcion=$3, monto=$4, moneda=$5, fecha_emision=$6, estado=$7, ultimo_movimiento=now() WHERE codigo=$8`,
            [f.cliente || ex.cliente_num, f.clienteNombre || ex.cliente_nombre, f.descripcion, f.monto || null, f.moneda || 'ARS', f.fecha || ex.fecha_emision, estado, codigo]);
          await agregarBitacora('PRES-' + codigo, req.user.email, 'correccion', `Datos completados desde la planilla histórica: "${f.descripcion}"${f.monto ? ', ' + (f.moneda || 'ARS') + ' ' + f.monto : ''}, estado ${estado}.`);
          actualizados++;
        } else {
          await pool.query(`INSERT INTO presupuestos(codigo,cliente_num,cliente_nombre,descripcion,monto,moneda,fecha_emision,estado,autor,ultimo_movimiento)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,now())`,
            [codigo, f.cliente || '', f.clienteNombre || '', f.descripcion, f.monto || null, f.moneda || 'ARS', f.fecha || '', estado, 'importacion@' + req.user.email]);
          await agregarBitacora('PRES-' + codigo, req.user.email, 'creacion', `Presupuesto importado de la planilla histórica — ${f.descripcion}. Estado: ${estado}.`);
          creados++;
        }
      } catch (err) { errores.push((f.codigo || '?') + ': ' + err.message); }
    }
    await logAdmin(req.user.email, 'importacion_presupuestos_masiva', `${creados} creados, ${actualizados} completados, ${saltados} sin cambios`);
    programarEspejo();
    res.json({ ok: true, creados, actualizados, saltados, errores });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Edición de datos del presupuesto (bitácora con antes→después) */
app.post('/api/presupuestos/:codigo/corregir', auth(['admin']), async (req, res) => {
  try {
    const { cliente, clienteNombre, descripcion, monto, moneda, fecha_emision, motivo } = req.body || {};
    const p = (await pool.query('SELECT * FROM presupuestos WHERE codigo=$1', [req.params.codigo])).rows[0];
    if (!p) return res.status(404).json({ error: 'Presupuesto no encontrado' });
    const cambios = [];
    if (descripcion !== undefined && descripcion !== p.descripcion) cambios.push(`Descripción: "${p.descripcion}" → "${descripcion}"`);
    if (cliente !== undefined && cliente !== p.cliente_num) cambios.push(`Cliente: "${p.cliente_nombre || p.cliente_num || '—'}" → "${clienteNombre || cliente}"`);
    const montoNuevo = monto === '' || monto === null || monto === undefined ? null : Number(monto);
    const montoViejo = p.monto === null ? null : Number(p.monto);
    if (monto !== undefined && montoNuevo !== montoViejo) cambios.push(`Monto: ${montoViejo ?? '—'} → ${montoNuevo ?? '—'}`);
    if (moneda !== undefined && moneda !== p.moneda) cambios.push(`Moneda: ${p.moneda || '—'} → ${moneda}`);
    if (fecha_emision !== undefined && fecha_emision !== (p.fecha_emision || '')) cambios.push(`Fecha de emisión: ${p.fecha_emision || '—'} → ${fecha_emision || '—'}`);
    if (!cambios.length) return res.status(400).json({ error: 'No hay cambios para aplicar' });
    await pool.query(`UPDATE presupuestos SET cliente_num=COALESCE($1,cliente_num), cliente_nombre=COALESCE($2,cliente_nombre),
      descripcion=COALESCE($3,descripcion), monto=$4, moneda=COALESCE($5,moneda), fecha_emision=COALESCE($6,fecha_emision), ultimo_movimiento=now() WHERE codigo=$7`,
      [cliente, clienteNombre, descripcion, montoNuevo, moneda, fecha_emision, req.params.codigo]);
    await agregarBitacora('PRES-' + req.params.codigo, req.user.email, 'correccion',
      `Datos del presupuesto actualizados${motivo ? '. Motivo: ' + motivo.trim() : ''}. Cambios: ${cambios.join(' | ')}.`);
    programarEspejo();
    res.json({ ok: true, cambios });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/presupuestos/:codigo/estado', auth(['admin']), async (req, res) => {
  try {
    const { estado } = req.body || {};
    const r = await pool.query('UPDATE presupuestos SET estado=$1, ultimo_movimiento=now() WHERE codigo=$2 RETURNING codigo', [estado, req.params.codigo]);
    if (!r.rowCount) return res.status(404).json({ error: 'Presupuesto no encontrado' });
    // Al emitir (cualquier estado que no sea Borrador) la versión vigente queda bloqueada para
    // siempre — si después hace falta cambiar algo, se crea una versión nueva, esta no se toca.
    await pool.query(
      `UPDATE presupuesto_versiones SET bloqueada=$1
       WHERE presupuesto_codigo=$2 AND numero = (SELECT MAX(numero) FROM presupuesto_versiones WHERE presupuesto_codigo=$2)`,
      [estado !== 'Borrador', req.params.codigo]);
    await agregarBitacora('PRES-' + req.params.codigo, req.user.email, 'estado', `Presupuesto ${req.params.codigo} → ${estado}`);
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   VERSIONADO DE PRESUPUESTOS (v1)
   ============================================================ */

/* Lista resumida de versiones de un presupuesto (más reciente primero). */
app.get('/api/presupuestos/:codigo/versiones', auth(['admin']), async (req, res) => {
  try {
    const r = await pool.query(
      `SELECT numero, moneda, total, bloqueada, autor, creado FROM presupuesto_versiones
       WHERE presupuesto_codigo=$1 ORDER BY numero DESC`, [req.params.codigo]);
    res.json({ versiones: r.rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Detalle completo de una versión puntual (para ver histórico o armar la impresión). */
app.get('/api/presupuestos/:codigo/versiones/:numero', auth(['admin']), async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM presupuesto_versiones WHERE presupuesto_codigo=$1 AND numero=$2',
      [req.params.codigo, req.params.numero]);
    if (!r.rowCount) return res.status(404).json({ error: 'Versión no encontrada' });
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* Crea una versión nueva (snapshot completo). El código del header no cambia nunca.
   Crear una versión siempre reabre el presupuesto a 'Borrador' — es una ronda nueva de
   negociación/revisión; la versión anterior, si ya estaba emitida, queda intacta como
   historial. Sin motor de descuentos: subtotal/descuento/total se cargan tal cual, no
   se recalculan a partir de los ítems (los ítems son solo el detalle a mostrar). */
app.post('/api/presupuestos/:codigo/versiones', auth(['admin']), async (req, res) => {
  try {
    const cod = req.params.codigo;
    const p = (await pool.query('SELECT * FROM presupuestos WHERE codigo=$1', [cod])).rows[0];
    if (!p) return res.status(404).json({ error: 'Presupuesto no encontrado' });
    const { items, moneda, subtotal, descuento_pct, descuento_monto, iva_discriminado, iva_monto,
      total, alcance, entregables, cronograma, forma_pago, condiciones, motivo } = req.body || {};
    if (total === undefined || total === null || total === '') return res.status(400).json({ error: 'Falta el total' });
    let itemsArr = items;
    if (typeof itemsArr === 'string') { try { itemsArr = JSON.parse(itemsArr); } catch { itemsArr = null; } }
    if (itemsArr !== undefined && itemsArr !== null && !Array.isArray(itemsArr))
      return res.status(400).json({ error: 'items debe ser un array (puede ir vacío)' });

    const mon = moneda || p.moneda || 'ARS';
    const numero = ((await pool.query('SELECT COALESCE(MAX(numero),0) mx FROM presupuesto_versiones WHERE presupuesto_codigo=$1', [cod])).rows[0].mx) + 1;

    await pool.query(
      `INSERT INTO presupuesto_versiones(presupuesto_codigo,numero,moneda,items,subtotal,descuento_pct,descuento_monto,iva_discriminado,iva_monto,total,alcance,entregables,cronograma,forma_pago,condiciones,autor)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
      [cod, numero, mon, JSON.stringify(itemsArr || []), subtotal ?? null, descuento_pct ?? null, descuento_monto ?? null,
        !!iva_discriminado, iva_monto ?? null, total, alcance || '', entregables || '', cronograma || '', forma_pago || '', condiciones || '', req.user.email]);

    // La versión nueva reabre el presupuesto a Borrador y sincroniza monto/moneda del header
    // (de los que todavía dependen otras pantallas/reportes existentes).
    await pool.query(`UPDATE presupuestos SET estado='Borrador', monto=$1, moneda=$2, ultimo_movimiento=now() WHERE codigo=$3`, [total, mon, cod]);
    await agregarBitacora('PRES-' + cod, req.user.email, 'version',
      `Versión ${numero} creada${motivo ? ' — ' + motivo.trim() : ''} (${mon} ${total}). Presupuesto vuelve a Borrador para revisión.`);
    programarEspejo();
    res.json({ ok: true, numero });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* HTML listo para imprimir (Ctrl+P) de una versión — por defecto la más reciente.
   v1: CSS de impresión nomás; PDF server-side queda para una iteración futura. */
app.get('/api/presupuestos/:codigo/imprimir', auth(['admin']), async (req, res) => {
  try {
    const cod = req.params.codigo;
    const p = (await pool.query('SELECT * FROM presupuestos WHERE codigo=$1', [cod])).rows[0];
    if (!p) return res.status(404).json({ error: 'Presupuesto no encontrado' });
    const v = req.query.version
      ? (await pool.query('SELECT * FROM presupuesto_versiones WHERE presupuesto_codigo=$1 AND numero=$2', [cod, req.query.version])).rows[0]
      : (await pool.query('SELECT * FROM presupuesto_versiones WHERE presupuesto_codigo=$1 ORDER BY numero DESC LIMIT 1', [cod])).rows[0];
    if (!v) return res.status(404).json({ error: 'Este presupuesto todavía no tiene ninguna versión cargada' });

    const esc = (s) => String(s ?? '').replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
    const nl2p = (s) => esc(s).split(/\n{2,}/).map(par => `<p>${par.replace(/\n/g, '<br>')}</p>`).join('\n');
    const fmt = (n) => n === null || n === undefined ? '' : Number(n).toLocaleString('es-AR', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    const items = Array.isArray(v.items) ? v.items : (typeof v.items === 'string' ? JSON.parse(v.items) : []);
    const filasItems = items.map(it => `<tr>
        <td>${esc(it.descripcion)}</td>
        <td class="num">${it.cantidad ?? ''}</td>
        <td class="num">${it.precio_unitario !== undefined && it.precio_unitario !== null ? fmt(it.precio_unitario) : ''}</td>
        <td class="num">${it.importe !== undefined && it.importe !== null ? fmt(it.importe) : ''}</td>
      </tr>`).join('\n');

    res.set('Content-Type', 'text/html; charset=utf-8');
    res.send(`<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Presupuesto N°${esc(cod)}</title>
<style>
  @media print { @page { margin: 2cm; } }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { font-family: 'Calibri', Arial, sans-serif; color: #1a1a1a; max-width: 850px; margin: 0 auto; padding: 24px; line-height: 1.45; position: relative; }
  .marca-agua { position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); width: 340px; opacity: 0.07; pointer-events: none; }
  h1 { font-size: 20px; border-bottom: 2px solid #333; padding-bottom: 8px; }
  h2 { font-size: 15px; margin-top: 28px; border-bottom: 1px solid #999; padding-bottom: 4px; }
  .meta { color: #555; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 13px; text-align: center; }
  td:first-child { text-align: left; }
  th { background: #2E75B6; color: #fff; }
  tbody td { background: #DAE9F7; }
  td.num, th.num { text-align: right; }
  th.num { text-align: center; }
  .totales td { border: none; padding: 3px 8px; }
  .totales .label { text-align: right; font-weight: bold; }
  .totales .valor { text-align: right; width: 140px; }
  .totales .total td { border-top: 2px solid #333; font-size: 15px; }
  .firma { margin-top: 60px; display: flex; justify-content: space-between; }
  .firma div { width: 45%; border-top: 1px solid #333; padding-top: 6px; text-align: center; color: #555; }
  p { margin: 6px 0; }
</style>
</head><body>
  <img class="marca-agua" src="${LOGO_VADOCA}" alt="">
  <h1>Presupuesto N°${esc(cod)}</h1>
  <div class="meta">${esc(p.fecha_emision || '')} — ${esc(p.cliente_nombre || p.cliente_num || '')}<br>${esc(p.descripcion)}</div>

  ${v.alcance ? `<h2>1. Alcance del Proyecto</h2>${nl2p(v.alcance)}` : ''}
  ${v.entregables ? `<h2>2. Entregables Técnicos</h2>${nl2p(v.entregables)}` : ''}
  ${v.cronograma ? `<h2>3. Cronograma de Entregas</h2>${nl2p(v.cronograma)}` : ''}

  <h2>4. Condiciones Comerciales</h2>
  ${items.length ? `<table><thead><tr><th>Descripción</th><th class="num">Cant.</th><th class="num">P. Unit.</th><th class="num">Importe</th></tr></thead>
  <tbody>${filasItems}</tbody></table>` : ''}
  <table class="totales">
    ${v.subtotal !== null ? `<tr><td class="label">Subtotal (${esc(v.moneda)})</td><td class="valor">${fmt(v.subtotal)}</td></tr>` : ''}
    ${v.descuento_monto !== null ? `<tr><td class="label">Descuento${v.descuento_pct ? ' (' + v.descuento_pct + '%)' : ''}</td><td class="valor">-${fmt(v.descuento_monto)}</td></tr>` : ''}
    ${v.iva_discriminado && v.iva_monto !== null ? `<tr><td class="label">IVA</td><td class="valor">${fmt(v.iva_monto)}</td></tr>` : ''}
    <tr class="total"><td class="label">Total (${esc(v.moneda)})</td><td class="valor">${fmt(v.total)}</td></tr>
  </table>
  ${v.forma_pago ? `<h2>Forma de pago</h2>${nl2p(v.forma_pago)}` : ''}

  ${v.condiciones ? `<h2>5. Condiciones y Aclaraciones</h2>${nl2p(v.condiciones)}` : ''}

  <h2>6. Aceptación de la Propuesta</h2>
  <div class="firma">
    <div>Nombre y Cargo del Cliente</div>
    <div>Firma y Fecha</div>
  </div>
</body></html>`);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/presupuestos/:codigo/notas', auth(['admin']), upload.array('archivos', 30), async (req, res) => {
  try {
    const cod = req.params.codigo;
    let p = (await pool.query('SELECT * FROM presupuestos WHERE codigo=$1', [cod])).rows[0];
    if (!p) return res.status(404).json({ error: 'Presupuesto no encontrado' });
    if (!p.carpeta_drive_id) {
      const fExp = await crearCarpetasExpediente(p.cliente_num || '000', p.cliente_nombre || 'VADOCA', 'Presupuestos', `${cod} - ${p.descripcion}`);
      await pool.query('UPDATE presupuestos SET carpeta_drive_id=$1, carpeta_drive_url=$2 WHERE codigo=$3', [fExp, `https://drive.google.com/drive/folders/${fExp}`, cod]);
      p.carpeta_drive_id = fExp;
    }
    const adjuntos = [];
    if (req.files?.length) {
      const drive = await driveCli();
      const sub = SUBCARPETAS.includes(req.body?.subcarpeta) ? req.body.subcarpeta : '02_evidencias';
      const subId = await ensureCarpeta(drive, sub, p.carpeta_drive_id);
      for (const f of req.files) {
        const nombre = `${ahora().slice(0, 10)}_${Buffer.from(f.originalname, 'latin1').toString('utf8')}`;
        const up = await subirADrive(f.buffer, nombre, f.mimetype, subId);
        adjuntos.push({ nombre, drive_id: up.id, subcarpeta: sub });
      }
    }
    const texto = (req.body?.texto || '').trim();
    if (!texto && !adjuntos.length) return res.status(400).json({ error: 'La nota está vacía' });
    const entrada = await agregarBitacora('PRES-' + cod, req.user.email, adjuntos.length ? 'archivo' : 'nota', texto || `Se subieron ${adjuntos.length} archivo(s)`, adjuntos);
    await pool.query('UPDATE presupuestos SET ultimo_movimiento=now() WHERE codigo=$1', [cod]);
    res.json({ ok: true, entrada });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   MÓDULO PROYECTOS
   ============================================================ */
app.get('/api/proyectos', auth(), async (_req, res) => {
  const proys = (await pool.query("SELECT * FROM proyectos WHERE ambito <> 'personal' ORDER BY codigo")).rows;
  const vincs = (await pool.query('SELECT * FROM proyecto_presupuestos')).rows;
  res.json(proys.map(p => ({ ...p, presupuestos: vincs.filter(v => v.proyecto === p.codigo).map(v => v.presupuesto) })));
});
app.post('/api/proyectos', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { nombre, cliente, clienteNombre, alcance } = req.body || {};
    if (!nombre) return res.status(400).json({ error: 'Falta el nombre del proyecto' });
    const m = await pool.query("SELECT COALESCE(MAX(CAST(SUBSTRING(codigo FROM 'PRJ-(\\d+)') AS INT)),0) mx FROM proyectos");
    const codigo = 'PRJ-' + String(m.rows[0].mx + 1).padStart(3, '0');
    await pool.query(`INSERT INTO proyectos(codigo,nombre,cliente_num,cliente_nombre,alcance,estado,autor,ultimo_movimiento)
      VALUES($1,$2,$3,$4,$5,'Activo',$6,now())`, [codigo, nombre, cliente || '', clienteNombre || '', alcance || '', req.user.email]);
    await agregarBitacora(codigo, req.user.email, 'creacion', `Proyecto ${codigo} creado — ${nombre}.`);
    programarEspejo();
    res.json({ ok: true, codigo });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/proyectos/:codigo/actualizar', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { alcance, estado } = req.body || {};
    const p = (await pool.query('SELECT * FROM proyectos WHERE codigo=$1', [req.params.codigo])).rows[0];
    if (!p) return res.status(404).json({ error: 'Proyecto no encontrado' });
    const cambios = [];
    if (estado && estado !== p.estado) cambios.push(`estado → ${estado}`);
    if (alcance !== undefined && alcance !== p.alcance) cambios.push('alcance actualizado');
    await pool.query('UPDATE proyectos SET alcance=COALESCE($1,alcance), estado=COALESCE($2,estado), ultimo_movimiento=now() WHERE codigo=$3',
      [alcance, estado, req.params.codigo]);
    if (cambios.length) await agregarBitacora(req.params.codigo, req.user.email, 'estado', `Proyecto ${req.params.codigo}: ${cambios.join('; ')}.`);
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
/* Vinculación de presupuestos (solo admin: es quien ve el módulo de presupuestos) */
app.post('/api/proyectos/:codigo/presupuestos', auth(['admin']), async (req, res) => {
  try {
    const cod = req.params.codigo;
    const lista = [...new Set(req.body?.presupuestos || [])];
    await pool.query('DELETE FROM proyecto_presupuestos WHERE proyecto=$1', [cod]);
    for (const pr of lista) await pool.query('INSERT INTO proyecto_presupuestos(proyecto,presupuesto) VALUES($1,$2) ON CONFLICT DO NOTHING', [cod, pr]);
    await agregarBitacora(cod, req.user.email, 'relacion', `Presupuestos vinculados: ${lista.length ? lista.join(', ') : 'ninguno'}.`);
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
/* Autovinculación de expedientes por referencia de presupuesto */
app.post('/api/proyectos/:codigo/autovincular', auth(['admin', 'editor']), async (req, res) => {
  try {
    const cod = req.params.codigo;
    const pres = (await pool.query('SELECT presupuesto FROM proyecto_presupuestos WHERE proyecto=$1', [cod])).rows.map(r => r.presupuesto);
    if (!pres.length) return res.status(400).json({ error: 'El proyecto no tiene presupuestos vinculados' });
    const r = await pool.query(`UPDATE documentos SET proyecto=$1 WHERE ref_presupuesto = ANY($2) AND (proyecto IS NULL OR proyecto='') RETURNING expediente_id`, [cod, pres]);
    const exps = [...new Set(r.rows.map(x => x.expediente_id))];
    await agregarBitacora(cod, req.user.email, 'relacion', `Autovinculación por presupuesto (${pres.join(', ')}): ${exps.length} expediente(s) asociado(s).`);
    programarEspejo();
    res.json({ ok: true, expedientes: exps.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
/* Asignar/cambiar proyecto de un expediente */
app.post('/api/expedientes/:id/proyecto', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { proyecto } = req.body || {};
    const r = await pool.query("UPDATE documentos SET proyecto=$1 WHERE expediente_id=$2 RETURNING codigo", [proyecto || '', req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'Expediente no encontrado' });
    await agregarBitacora(req.params.id, req.user.email, 'relacion', proyecto ? `Expediente vinculado al proyecto ${proyecto}.` : 'Expediente desvinculado de proyecto.');
    if (proyecto) await agregarBitacora(proyecto, req.user.email, 'relacion', `Expediente ${req.params.id} vinculado al proyecto.`);
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/proyectos/:codigo/notas', auth(['admin', 'editor']), upload.array('archivos', 30), async (req, res) => {
  try {
    const cod = req.params.codigo;
    let p = (await pool.query('SELECT * FROM proyectos WHERE codigo=$1', [cod])).rows[0];
    if (!p) return res.status(404).json({ error: 'Proyecto no encontrado' });
    if (!p.carpeta_drive_id) {
      const fExp = await crearCarpetasExpediente(p.cliente_num || '000', p.cliente_nombre || 'VADOCA', 'Proyectos', `${cod} - ${p.nombre}`);
      await pool.query('UPDATE proyectos SET carpeta_drive_id=$1, carpeta_drive_url=$2 WHERE codigo=$3', [fExp, `https://drive.google.com/drive/folders/${fExp}`, cod]);
      p.carpeta_drive_id = fExp;
    }
    const adjuntos = [];
    if (req.files?.length) {
      const drive = await driveCli();
      const sub = SUBCARPETAS.includes(req.body?.subcarpeta) ? req.body.subcarpeta : '02_evidencias';
      const subId = await ensureCarpeta(drive, sub, p.carpeta_drive_id);
      for (const f of req.files) {
        const nombre = `${ahora().slice(0, 10)}_${Buffer.from(f.originalname, 'latin1').toString('utf8')}`;
        const up = await subirADrive(f.buffer, nombre, f.mimetype, subId);
        adjuntos.push({ nombre, drive_id: up.id, subcarpeta: sub });
      }
    }
    const texto = (req.body?.texto || '').trim();
    if (!texto && !adjuntos.length) return res.status(400).json({ error: 'La nota está vacía' });
    const entrada = await agregarBitacora(cod, req.user.email, adjuntos.length ? 'archivo' : 'nota', texto || `Se subieron ${adjuntos.length} archivo(s)`, adjuntos);
    await pool.query('UPDATE proyectos SET ultimo_movimiento=now() WHERE codigo=$1', [cod]);
    res.json({ ok: true, entrada });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   AUDITORÍA GLOBAL E INDICADORES
   ============================================================ */
app.get('/api/auditoria', auth(['admin']), async (req, res) => {
  try {
    const { modulo, autor, q, desde, hasta } = req.query || {};
    const params = []; let where = [];
    const filtro = (campo, val, op) => { params.push(val); return `${campo} ${op} $${params.length}`; };
    let base = `
      SELECT ts, autor, tipo, clave, texto, fuente, modulo FROM (
        SELECT b.ts, b.autor, b.tipo, b.expediente_id clave, b.texto, 'bitacora' fuente,
          CASE WHEN b.expediente_id LIKE 'PRES-%' THEN 'Presupuestos'
               WHEN b.expediente_id LIKE 'PRJ-%' THEN 'Proyectos'
               WHEN EXISTS (SELECT 1 FROM procedimientos p WHERE p.codigo_base=b.expediente_id) THEN 'Procedimientos'
               ELSE 'Expedientes' END modulo
        FROM bitacora b
        UNION ALL
        SELECT a.ts, a.autor, a.accion tipo, 'ADMINISTRACIÓN' clave, a.detalle texto, 'admin' fuente, 'Administración' modulo FROM admin_log a
        UNION ALL
        SELECT x.ts, x.email autor, x.evento tipo, 'ACCESOS' clave, x.detalle texto, 'acceso' fuente, 'Accesos' modulo FROM accesos x
      ) t`;
    if (modulo) where.push(filtro('modulo', modulo, '='));
    if (autor) where.push(filtro('autor', '%' + autor + '%', 'ILIKE'));
    if (q) { params.push('%' + q + '%'); where.push(`(texto ILIKE $${params.length} OR clave ILIKE $${params.length})`); }
    if (desde) where.push(filtro('ts', desde, '>='));
    if (hasta) where.push(filtro('ts', hasta + 'T23:59:59', '<='));
    if (where.length) base += ' WHERE ' + where.join(' AND ');
    base += ' ORDER BY ts DESC LIMIT 500';
    res.json((await pool.query(base, params)).rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/indicadores', auth(), async (req, res) => {
  try {
    const hoy = new Date(), anio = hoy.toISOString().slice(0, 4), mes = hoy.toISOString().slice(0, 7);
    const FINALES = ['Entregado', 'Cancelado'];
    const [docsMes, docsAnio, serie12, porTipo, ciclo, exps, poes, proys, docsPorProy] = await Promise.all([
      pool.query("SELECT COUNT(*) n FROM documentos WHERE fecha_alta LIKE $1", [mes + '%']),
      pool.query("SELECT COUNT(*) n FROM documentos WHERE fecha_alta LIKE $1", [anio + '%']),
      pool.query("SELECT SUBSTRING(fecha_alta,1,7) m, COUNT(*) n FROM documentos WHERE fecha_alta >= $1 GROUP BY 1 ORDER BY 1", [new Date(hoy.getFullYear(), hoy.getMonth() - 11, 1).toISOString().slice(0, 10)]),
      pool.query("SELECT tipo_doc t, COUNT(*) n FROM documentos WHERE fecha_alta LIKE $1 GROUP BY 1 ORDER BY n DESC", [anio + '%']),
      pool.query("SELECT ROUND(AVG(fecha_fin::date - fecha_alta::date),1) d, COUNT(*) n FROM documentos WHERE fecha_fin IS NOT NULL AND fecha_fin <> '' AND fecha_alta IS NOT NULL AND fecha_alta <> ''"),
      pool.query(`SELECT COUNT(DISTINCT expediente_id) FILTER (WHERE estado NOT IN ('Entregado','Cancelado')) activos,
                         COUNT(DISTINCT expediente_id) FILTER (WHERE estado NOT IN ('Entregado','Cancelado') AND ultimo_movimiento < now() - interval '7 days') estancados,
                         COUNT(DISTINCT expediente_id) total FROM documentos`),
      pool.query(`SELECT COUNT(*) FILTER (WHERE estado='Vigente') vigentes,
                         COUNT(*) FILTER (WHERE estado='Vigente' AND fecha_vencimiento <> '' AND fecha_vencimiento::date <= (now() + interval '30 days')::date) por_vencer,
                         COUNT(*) FILTER (WHERE estado='Vigente' AND fecha_vencimiento <> '' AND fecha_vencimiento::date < now()::date) vencidos,
                         COUNT(*) FILTER (WHERE estado='Borrador') borradores FROM procedimientos`),
      pool.query(`SELECT COUNT(*) total, COUNT(*) FILTER (WHERE estado='Activo') activos, COUNT(*) FILTER (WHERE estado='Cerrado') cerrados FROM proyectos`),
      pool.query(`SELECT ROUND(AVG(n),1) prom FROM (SELECT proyecto, COUNT(*) n FROM documentos WHERE proyecto <> '' GROUP BY proyecto) s`)
    ]);
    const out = {
      docs: { mes: +docsMes.rows[0].n, anio: +docsAnio.rows[0].n, serie12: serie12.rows, porTipo: porTipo.rows,
              cicloPromedioDias: ciclo.rows[0].d ? +ciclo.rows[0].d : null, cicloMuestra: +ciclo.rows[0].n },
      expedientes: exps.rows[0], poes: poes.rows[0],
      proyectos: { ...proys.rows[0], promDocsPorProyecto: docsPorProy.rows[0].prom ? +docsPorProy.rows[0].prom : null }
    };
    if (req.user.rol === 'admin') {
      const pr = await pool.query(`SELECT COUNT(*) FILTER (WHERE estado <> 'Borrador') emitidos,
        COUNT(*) FILTER (WHERE estado='Aceptado') aceptados, COUNT(*) FILTER (WHERE estado='Enviado') pipeline,
        COUNT(*) FILTER (WHERE estado='Rechazado') rechazados, COUNT(*) FILTER (WHERE estado='Vencido') vencidos FROM presupuestos`);
      const m = await pool.query(`SELECT moneda, SUM(monto) t FROM presupuestos WHERE estado='Aceptado' AND monto IS NOT NULL AND fecha_emision LIKE $1 GROUP BY moneda`, [anio + '%']);
      out.comercial = { ...pr.rows[0], montosAceptadosAnio: m.rows };
    }
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ============================================================
   MÓDULO SEGUIMIENTO (FARO) — checklist templado por proyecto
   Ítems vinculables a documentos reales: en ese caso el estado
   del documento manda (fuente única). Eventos → bitácora del
   proyecto (misma cadena de hashes).
   ============================================================ */

// Todo el estado del módulo en un solo fetch
// Filtros opcionales (expediente_id, cliente_num, codigo): acotan la respuesta a los
// documentos que matchean, y devuelven el resto de las listas vacías. Pensado para
// consumidores programáticos (integración IA) que no necesitan ni pueden manejar el
// dump completo. Con key de integración, alguno de los tres filtros es OBLIGATORIO —
// nunca se le entrega el universo completo de un solo request. El login humano (JWT)
// sigue recibiendo el dump completo cuando no manda filtros, para no tocar la UI.
app.get('/api/seguimiento/data', auth(), async (req, res) => {
  try {
    const { expediente_id, cliente_num, codigo, codigo_interno_cliente } = req.query;
    const esIntegracion = req.user.rol === 'integracion';
    if (esIntegracion && !expediente_id && !cliente_num && !codigo && !codigo_interno_cliente) {
      return res.status(400).json({ error: 'La key de integración requiere un filtro (expediente_id, cliente_num, codigo o codigo_interno_cliente) — no puede leer el listado completo.' });
    }
    const vals = [];
    const filtros = [];
    if (expediente_id) { vals.push(expediente_id); filtros.push(`expediente_id=$${vals.length}`); }
    if (cliente_num) { vals.push(cliente_num); filtros.push(`cliente_num=$${vals.length}`); }
    if (codigo) { vals.push(codigo); filtros.push(`codigo=$${vals.length}`); }
    if (codigo_interno_cliente) { vals.push(codigo_interno_cliente); filtros.push(`codigo_interno_cliente=$${vals.length}`); }
    const filtrado = filtros.length > 0;
    const whereDocs = filtrado ? 'WHERE ' + filtros.join(' AND ') : '';

    const proyectos = filtrado ? [] : (await pool.query('SELECT * FROM proyectos ORDER BY creado DESC')).rows;
    const proyectos_faro = []; // unificados en la tabla proyectos (compatibilidad con frontends viejos)
    const items = filtrado ? [] : (await pool.query(`
      SELECT s.*, d.estado AS doc_estado, d.descripcion AS doc_descripcion, d.expediente_id AS doc_expediente
      FROM seg_items s LEFT JOIN documentos d ON d.codigo = s.doc_codigo
      ORDER BY s.orden, s.id`)).rows;
    const templates = filtrado ? [] : (await pool.query('SELECT * FROM seg_templates ORDER BY id')).rows;
    const documentos = (await pool.query(
      `SELECT codigo, proyecto, expediente_id, cliente_num, codigo_interno_cliente, estado, tipo_doc, prot_inf, descripcion FROM documentos ${whereDocs} ORDER BY codigo`, vals)).rows;
    // Información comercial (montos): EXCLUSIVA de admin e integración (auditoría de solo lectura).
    // Editores y lectores reciben las listas vacías y el frontend ni muestra el módulo Comercial.
    const esAdminRol = req.user.rol === 'admin' || req.user.rol === 'integracion';
    const facturas = (filtrado || !esAdminRol)
      ? [] : (await pool.query('SELECT * FROM facturas ORDER BY fecha_emision DESC, id DESC')).rows;
    const presupuestos = (filtrado || !esAdminRol)
      ? [] : (await pool.query(
          "SELECT codigo, cliente_nombre, descripcion, monto, moneda, estado, facturacion, fecha_emision, carpeta_drive_url FROM presupuestos ORDER BY codigo DESC")).rows;
    res.json({ proyectos, proyectos_faro, items, templates, documentos, facturas, presupuestos });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Proyectos desde FlowTracker: viven en la MISMA tabla que los de DocTracker
// (serie PRJ- compartida). "ambito" distingue profesional/personal.
app.post('/api/seguimiento/proyectos', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { nombre, ambito, cliente, notas } = req.body || {};
    if (!nombre) return res.status(400).json({ error: 'Falta el nombre' });
    const amb = ['profesional', 'personal'].includes(ambito) ? ambito : 'personal';
    const m = await pool.query("SELECT COALESCE(MAX(CAST(SUBSTRING(codigo FROM 'PRJ-(\\d+)') AS INT)),0) mx FROM proyectos");
    const codigo = 'PRJ-' + String(m.rows[0].mx + 1).padStart(3, '0');
    const r = await pool.query(`INSERT INTO proyectos(codigo,nombre,cliente_num,cliente_nombre,alcance,estado,autor,ultimo_movimiento,ambito,notas)
      VALUES($1,$2,'',$3,'','Activo',$4,now(),$5,$6) RETURNING *`,
      [codigo, nombre, cliente || '', req.user.email, amb, notas || '']);
    await agregarBitacora(codigo, req.user.email, 'creacion', `Proyecto ${codigo} creado desde FlowTracker — ${nombre} (${amb}).`);
    programarEspejo();
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/seguimiento/proyectos/:codigo', auth(['admin', 'editor']), async (req, res) => {
  try {
    const b = req.body || {};
    const antes = (await pool.query('SELECT * FROM proyectos WHERE codigo=$1', [req.params.codigo])).rows[0];
    if (!antes) return res.status(404).json({ error: 'Proyecto inexistente' });
    const mapa = { nombre: 'nombre', ambito: 'ambito', cliente: 'cliente_nombre', estado: 'estado', notas: 'notas' };
    const sets = ['ultimo_movimiento=now()'], vals = [];
    for (const [campo, col] of Object.entries(mapa))
      if (b[campo] !== undefined) { vals.push(b[campo]); sets.push(`${col}=$${vals.length}`); }
    if (vals.length === 0) return res.status(400).json({ error: 'Nada que actualizar' });
    vals.push(req.params.codigo);
    const r = await pool.query(`UPDATE proyectos SET ${sets.join(',')} WHERE codigo=$${vals.length} RETURNING *`, vals);
    if (b.estado && b.estado !== antes.estado)
      await agregarBitacora(req.params.codigo, req.user.email, 'estado', `Proyecto ${req.params.codigo}: estado → ${b.estado}.`);
    programarEspejo();
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/seguimiento/proyectos/:codigo', auth(['admin', 'editor']), async (req, res) => {
  try {
    const docs = await pool.query('SELECT COUNT(*)::int n FROM documentos WHERE proyecto=$1', [req.params.codigo]);
    if (docs.rows[0].n) return res.status(400).json({ error: `El proyecto tiene ${docs.rows[0].n} documento(s) vinculados: desvinculalos o cerralo en vez de borrarlo` });
    const r = await pool.query('DELETE FROM proyectos WHERE codigo=$1 RETURNING nombre', [req.params.codigo]);
    if (!r.rowCount) return res.status(404).json({ error: 'Proyecto inexistente' });
    await pool.query('DELETE FROM seg_items WHERE proyecto=$1', [req.params.codigo]);
    await logAdmin(req.user.email, 'baja_proyecto', `${req.params.codigo} — ${r.rows[0].nombre}`);
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Aplicar un template sobre un proyecto existente
app.post('/api/seguimiento/aplicar-template', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { proyecto, template_id } = req.body || {};
    const enDT = (await pool.query('SELECT codigo FROM proyectos WHERE codigo=$1', [proyecto])).rowCount;
    const enFaro = (await pool.query('SELECT codigo FROM seg_proyectos WHERE codigo=$1', [proyecto])).rowCount;
    if (!enDT && !enFaro) return res.status(404).json({ error: 'Proyecto inexistente' });
    const t = (await pool.query('SELECT * FROM seg_templates WHERE id=$1', [template_id])).rows[0];
    if (!t) return res.status(404).json({ error: 'Template inexistente' });
    const base = (await pool.query('SELECT COALESCE(MAX(orden),-1)+1 o FROM seg_items WHERE proyecto=$1', [proyecto])).rows[0].o;
    let orden = base;
    for (const nombre of t.items)
      await pool.query('INSERT INTO seg_items(proyecto,nombre,orden) VALUES($1,$2,$3)', [proyecto, nombre, orden++]);
    await agregarBitacora(proyecto, req.user.email, 'seguimiento', `Template aplicado: ${t.nombre} (${t.items.length} ítems)`);
    res.json({ ok: true, agregados: t.items.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Crear ítem suelto
app.post('/api/seguimiento/items', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { proyecto, nombre, fecha_limite, doc_codigo } = req.body || {};
    if (!proyecto || !nombre) return res.status(400).json({ error: 'Faltan proyecto o nombre' });
    const o = (await pool.query('SELECT COALESCE(MAX(orden),-1)+1 o FROM seg_items WHERE proyecto=$1', [proyecto])).rows[0].o;
    const r = await pool.query(
      'INSERT INTO seg_items(proyecto,nombre,orden,fecha_limite,doc_codigo) VALUES($1,$2,$3,$4,$5) RETURNING *',
      [proyecto, nombre, o, fecha_limite || null, doc_codigo || null]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Editar ítem. Si está vinculado a un documento y viene "estado",
// el cambio se aplica AL DOCUMENTO (con su bitácora), no al ítem.
app.patch('/api/seguimiento/items/:id', auth(['admin', 'editor']), async (req, res) => {
  try {
    const it = (await pool.query('SELECT * FROM seg_items WHERE id=$1', [req.params.id])).rows[0];
    if (!it) return res.status(404).json({ error: 'Ítem inexistente' });
    const b = req.body || {};

    if (b.estado !== undefined && it.doc_codigo) {
      const doc = (await pool.query('SELECT estado FROM documentos WHERE codigo=$1', [it.doc_codigo])).rows[0];
      if (doc) {
        const c = claseTransicionDoc(doc.estado, b.estado);
        if (c.tipo !== 'igual') {
          if (c.motivo && !(b.motivo || '').trim())
            return res.status(400).json({ error: `${doc.estado} → ${b.estado} es ${c.tipo}: requiere un motivo (queda en bitácora)` });
          const r = await pool.query(
            `UPDATE documentos SET estado=$1, ultimo_movimiento=now(),
             fecha_fin=CASE WHEN $1='Entregado' THEN $2 ELSE fecha_fin END
             WHERE codigo=$3 RETURNING expediente_id`,
            [b.estado, ahora().slice(0, 10), it.doc_codigo]);
          if (r.rowCount)
            await agregarBitacora(r.rows[0].expediente_id, req.user.email, 'estado',
              `${it.doc_codigo} → estado: ${b.estado} (desde Seguimiento)` + (c.motivo ? ` [${c.tipo}] Motivo: ${String(b.motivo).trim()}` : ''));
        }
      }
      delete b.estado;
    }

    const campos = ['nombre', 'estado', 'fecha_limite', 'notas', 'orden', 'doc_codigo'];
    const sets = [], vals = [];
    for (const c of campos) if (b[c] !== undefined) { vals.push(b[c] === '' ? null : b[c]); sets.push(`${c}=$${vals.length}`); }
    if (sets.length) {
      vals.push(req.params.id);
      await pool.query(`UPDATE seg_items SET ${sets.join(',')} WHERE id=$${vals.length}`, vals);
      if (b.estado !== undefined && b.estado !== it.estado)
        await agregarBitacora(it.proyecto, req.user.email, 'seguimiento', `${it.nombre}: ${it.estado} → ${b.estado}`);
    }
    const out = (await pool.query(`
      SELECT s.*, d.estado AS doc_estado, d.descripcion AS doc_descripcion, d.expediente_id AS doc_expediente
      FROM seg_items s LEFT JOIN documentos d ON d.codigo = s.doc_codigo WHERE s.id=$1`, [req.params.id])).rows[0];
    res.json(out);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/seguimiento/items/:id', auth(['admin', 'editor']), async (req, res) => {
  try {
    const it = (await pool.query('DELETE FROM seg_items WHERE id=$1 RETURNING proyecto,nombre', [req.params.id])).rows[0];
    if (it) await agregarBitacora(it.proyecto, req.user.email, 'seguimiento', `Ítem eliminado: ${it.nombre}`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Nota manual sobre un ítem → bitácora del proyecto
app.post('/api/seguimiento/items/:id/nota', auth(['admin', 'editor']), async (req, res) => {
  try {
    const it = (await pool.query('SELECT * FROM seg_items WHERE id=$1', [req.params.id])).rows[0];
    if (!it) return res.status(404).json({ error: 'Ítem inexistente' });
    const texto = (req.body && req.body.texto || '').trim();
    if (!texto) return res.status(400).json({ error: 'Nota vacía' });
    const e = await agregarBitacora(it.proyecto, req.user.email, 'seguimiento', `[${it.nombre}] ${texto}`);
    res.json(e);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bitácora del proyecto (incluye entradas de seguimiento)
app.get('/api/seguimiento/proyectos/:codigo/bitacora', auth(), async (req, res) => {
  try {
    const r = await pool.query('SELECT ts,autor,tipo,texto FROM bitacora WHERE expediente_id=$1 ORDER BY id DESC LIMIT 200', [req.params.codigo]);
    res.json(r.rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ---------- Facturas ----------
app.post('/api/seguimiento/facturas', auth(['admin']), async (req, res) => {
  try {
    const { numero, cliente, presupuesto, fecha_emision, monto, moneda, notas } = req.body || {};
    if (!numero || !fecha_emision) return res.status(400).json({ error: 'Faltan número o fecha de emisión' });
    const r = await pool.query(
      `INSERT INTO facturas(numero,cliente,presupuesto,fecha_emision,monto,moneda,notas)
       VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [numero, cliente || '', presupuesto || '', fecha_emision, monto || 0, moneda || 'ARS', notas || '']);
    await agregarBitacora('__FACTURAS__', req.user.email, 'factura',
      `Factura ${numero} emitida — ${cliente || 's/cliente'} · ${moneda || 'ARS'} ${monto || 0}${presupuesto ? ' · presup. ' + presupuesto : ''}`);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/seguimiento/facturas/:id', auth(['admin']), async (req, res) => {
  try {
    const antes = (await pool.query('SELECT * FROM facturas WHERE id=$1', [req.params.id])).rows[0];
    if (!antes) return res.status(404).json({ error: 'Factura inexistente' });
    const b = req.body || {};
    const campos = ['numero', 'cliente', 'presupuesto', 'fecha_emision', 'monto', 'moneda', 'estado', 'fecha_cobro', 'notas'];
    const sets = [], vals = [];
    for (const c of campos) if (b[c] !== undefined) { vals.push(b[c] === '' && c === 'fecha_cobro' ? null : b[c]); sets.push(`${c}=$${vals.length}`); }
    if (!sets.length) return res.status(400).json({ error: 'Nada que actualizar' });
    vals.push(req.params.id);
    const r = await pool.query(`UPDATE facturas SET ${sets.join(',')} WHERE id=$${vals.length} RETURNING *`, vals);
    if (b.estado === 'Cobrada' && antes.estado !== 'Cobrada')
      await agregarBitacora('__FACTURAS__', req.user.email, 'factura',
        `Factura ${antes.numero} COBRADA (${b.fecha_cobro || 'sin fecha'}) — ${antes.cliente} · ${antes.moneda} ${antes.monto}`);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/seguimiento/facturas/:id', auth(['admin']), async (req, res) => {
  try {
    const f = (await pool.query('DELETE FROM facturas WHERE id=$1 RETURNING numero,cliente', [req.params.id])).rows[0];
    if (f) await agregarBitacora('__FACTURAS__', req.user.email, 'factura', `Factura ${f.numero} eliminada (${f.cliente})`);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Cerrar / reabrir el ciclo de facturación de un presupuesto
app.patch('/api/seguimiento/presupuestos/:codigo/facturacion', auth(['admin']), async (req, res) => {
  try {
    const estado = (req.body || {}).estado;
    if (!['Abierta', 'Cerrada'].includes(estado)) return res.status(400).json({ error: "Estado inválido (Abierta/Cerrada)" });
    const r = await pool.query('UPDATE presupuestos SET facturacion=$1 WHERE codigo=$2 RETURNING codigo,cliente_nombre', [estado, req.params.codigo]);
    if (!r.rowCount) return res.status(404).json({ error: 'Presupuesto inexistente' });
    await agregarBitacora('__FACTURAS__', req.user.email, 'factura',
      `Ciclo de facturación del presupuesto ${req.params.codigo} ${estado === 'Cerrada' ? 'CERRADO' : 'reabierto'} (${r.rows[0].cliente_nombre || ''})`);
    res.json({ ok: true, facturacion: estado });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Templates CRUD
app.post('/api/seguimiento/templates', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { nombre, items } = req.body || {};
    if (!nombre) return res.status(400).json({ error: 'Falta el nombre' });
    const r = await pool.query('INSERT INTO seg_templates(nombre,items) VALUES($1,$2) RETURNING *', [nombre, JSON.stringify(items || [])]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/seguimiento/templates/:id', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { nombre, items } = req.body || {};
    const r = await pool.query('UPDATE seg_templates SET nombre=COALESCE($1,nombre), items=COALESCE($2,items) WHERE id=$3 RETURNING *',
      [nombre || null, items ? JSON.stringify(items) : null, req.params.id]);
    res.json(r.rows[0]);
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/seguimiento/templates/:id', auth(['admin', 'editor']), async (req, res) => {
  try {
    await pool.query('DELETE FROM seg_templates WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

/* ---------- Salud y arranque ---------- */
app.get('/', (_req, res) => res.send('VADOCA DocTracker backend v2.0 — OK'));
app.get('/api/salud', async (_req, res) => {
  const db = await pool.query('SELECT COUNT(*)::int c FROM documentos').then(r => r.rows[0].c).catch(() => -1);
  const drive = await pool.query("SELECT 1 FROM config WHERE clave='google_refresh_token'").then(r => !!r.rowCount);
  res.json({ ok: true, documentos: db, drive_conectado: drive });
});

// Errores de subida de archivos (límite de cantidad, tamaño, campo mal formado) con mensaje claro
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const msgs = {
      LIMIT_FILE_COUNT: 'Demasiados archivos en una sola subida (máximo 30). Subilos en dos tandas.',
      LIMIT_FILE_SIZE: 'Un archivo supera el máximo permitido (50 MB).',
      LIMIT_UNEXPECTED_FILE: 'Campo de archivo inesperado en la subida.'
    };
    return res.status(400).json({ error: msgs[err.code] || ('Error al subir archivos: ' + err.message) });
  }
  next(err);
});

boot().then(() => app.listen(PORT, () => console.log('DocTracker backend escuchando en :' + PORT)))
  .catch(e => { console.error('Error de arranque:', e); process.exit(1); });
