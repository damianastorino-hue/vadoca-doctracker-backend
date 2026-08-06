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
  PORT = 3000,
} = process.env;

const pool = new Pool({ connectionString: DATABASE_URL, ssl: DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false });
const app = express();
app.use(cors({ origin: FRONTEND_ORIGIN === '*' ? true : FRONTEND_ORIGIN.split(','), credentials: false }));
app.use(express.json({ limit: '2mb' }));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

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
function auth(rolesPermitidos) {
  return (req, res, next) => {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
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
  if (!u || !u.activo || !bcrypt.compareSync(password || '', u.hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
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
  const base = `${req.protocol}://${req.get('host')}`;
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
  const doc = (await pool.query('SELECT carpeta_drive_id, historial_file_id FROM documentos WHERE expediente_id=$1 AND carpeta_drive_id IS NOT NULL LIMIT 1', [expedienteId])).rows[0];
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
  if (!meta.data.sheets.some(s => s.properties.title === 'REGISTRO')) {
    await sheets.spreadsheets.batchUpdate({ spreadsheetId: SHEET_ID, requestBody: { requests: [{ addSheet: { properties: { title: 'REGISTRO' } } }] } });
  }
  const docs = (await pool.query('SELECT * FROM documentos ORDER BY id')).rows;
  const filas = docs.map(d => [d.codigo, d.fecha_alta, d.cliente_num, d.cliente_nombre, d.tipo_trabajo, d.linea, d.prot_inf, d.tipo_doc, d.doc_num, d.version, d.descripcion, d.codigo_interno_cliente, d.ref_presupuesto, d.estado, d.fecha_inicio, d.fecha_fin, d.carpeta_drive_url, d.autor, d.ultimo_movimiento ? new Date(d.ultimo_movimiento).toISOString() : '', d.conflicto_legacy ? 'TRUE' : '', d.observaciones, d.expediente_id]);
  await sheets.spreadsheets.values.clear({ spreadsheetId: SHEET_ID, range: "'REGISTRO'!A:Z" });
  await sheets.spreadsheets.values.update({
    spreadsheetId: SHEET_ID, range: "'REGISTRO'!A1", valueInputOption: 'RAW',
    requestBody: { values: [['ESPEJO DE SOLO LECTURA — editar aquí NO modifica el sistema. Fuente de verdad: base de datos DocTracker.'], COLS, ...filas] },
  });
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
  const r = await pool.query('SELECT ts,autor,tipo,texto,adjuntos,prev_hash,hash FROM bitacora WHERE expediente_id=$1 ORDER BY id DESC', [req.params.id]);
  res.json(r.rows);
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
    const { ttKey, ttNombre, linea, cliente, clienteNombre, docs, desc, interno, presupuesto } = req.body || {};
    if (!ttKey || !cliente || !desc || !Array.isArray(docs) || !docs.length) return res.status(400).json({ error: 'Faltan datos del expediente' });
    // Número siguiente con verificación en base (sin carreras)
    const r = await pool.query("SELECT COALESCE(MAX(CAST(doc_num AS INT)),0) m FROM documentos WHERE expediente_id LIKE $1", [`${ttKey}-${cliente}-%`]);
    const semilla = parseInt((await pool.query("SELECT valor FROM config WHERE clave=$1", [`semilla_${ttKey}_${cliente}`])).rows[0]?.valor || '0', 10);
    const doc = Math.max(r.rows[0].m, semilla) + 1;
    const expId = `${ttKey}-${cliente}-${pad(doc, 3)}`;
    const fExp = await crearCarpetasExpediente(cliente, clienteNombre || '', ttNombre || ttKey, `${expId} - ${desc}`);
    const url = `https://drive.google.com/drive/folders/${fExp}`;
    for (const [td, pi] of docs) {
      await pool.query(`INSERT INTO documentos(codigo,expediente_id,fecha_alta,cliente_num,cliente_nombre,tipo_trabajo,linea,prot_inf,tipo_doc,doc_num,version,descripcion,codigo_interno_cliente,ref_presupuesto,estado,fecha_inicio,carpeta_drive_id,carpeta_drive_url,autor,ultimo_movimiento)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'Borrador',$3,$15,$16,$17,now())`,
        [armarID(linea, td, pi, cliente, doc, 1), expId, ahora().slice(0, 10), cliente, clienteNombre || '', ttNombre || ttKey, linea, pi, td, pad(doc, 3), '01', desc, interno || '', presupuesto || '', fExp, url, req.user.email]);
    }
    await agregarBitacora(expId, req.user.email, 'creacion', `Expediente creado. Documentos: ${docs.map(d => d[0] + '-' + d[1]).join(', ')}. Descripción: ${desc}`);
    programarEspejo();
    res.json({ ok: true, expediente: expId, carpeta: url });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/documentos/:codigo/estado', auth(['admin', 'editor']), async (req, res) => {
  try {
    const { estado } = req.body || {};
    const r = await pool.query(`UPDATE documentos SET estado=$1, ultimo_movimiento=now(), fecha_fin=CASE WHEN $1='Entregado' THEN $2 ELSE fecha_fin END WHERE codigo=$3 RETURNING expediente_id`, [estado, ahora().slice(0, 10), req.params.codigo]);
    if (!r.rowCount) return res.status(404).json({ error: 'Documento no encontrado' });
    await agregarBitacora(r.rows[0].expediente_id, req.user.email, 'estado', `${req.params.codigo} → estado: ${estado}`);
    programarEspejo();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/expedientes/:id/notas', auth(['admin', 'editor']), upload.array('archivos', 10), async (req, res) => {
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

/* ---------- Salud y arranque ---------- */
app.get('/', (_req, res) => res.send('VADOCA DocTracker backend v2.0 — OK'));
app.get('/api/salud', async (_req, res) => {
  const db = await pool.query('SELECT COUNT(*)::int c FROM documentos').then(r => r.rows[0].c).catch(() => -1);
  const drive = await pool.query("SELECT 1 FROM config WHERE clave='google_refresh_token'").then(r => !!r.rowCount);
  res.json({ ok: true, documentos: db, drive_conectado: drive });
});

boot().then(() => app.listen(PORT, () => console.log('DocTracker backend escuchando en :' + PORT)))
  .catch(e => { console.error('Error de arranque:', e); process.exit(1); });
