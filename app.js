'use strict';
/* Historias Clínicas — app de consultorio.
 * Todos los datos se guardan cifrados (AES-GCM, clave derivada de la contraseña con PBKDF2).
 * Dropbox (o el navegador, en modo prueba) solo recibe el archivo cifrado. */

const CONFIG = Object.assign({ carpetaDropbox: '/historias clínicas', minutosBloqueo: 15 }, window.HC_CONFIG || {});
const ARCHIVO_DATOS = 'historias.hc';
const ITERACIONES = 600000;

const $ = (s, raiz = document) => raiz.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const normalizar = s => String(s ?? '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const hoyISO = () => { const d = new Date(); return new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 10); };
const nuevoId = () => (crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(36) + Math.random().toString(36).slice(2));

// ---------- Preferencias del dispositivo (no son datos de pacientes) ----------
const pref = {
  get(k) { try { return localStorage.getItem('hc.' + k); } catch { return null; } },
  set(k, v) { try { v == null ? localStorage.removeItem('hc.' + k) : localStorage.setItem('hc.' + k, v); } catch { /* sin almacenamiento */ } },
};

// ---------- Cifrado ----------
const te = new TextEncoder(), td = new TextDecoder();
function aB64(buf) {
  const b = new Uint8Array(buf); let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
const deB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));

async function derivarClave(pass, salt, iter) {
  const base = await crypto.subtle.importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function cifrar(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.clave, te.encode(JSON.stringify(obj)));
  return JSON.stringify({ formato: 'historias-clinicas', v: 1, iter: S.iter, salt: aB64(S.salt), iv: aB64(iv), datos: aB64(ct) });
}
async function descifrar(texto, pass) {
  const f = JSON.parse(texto);
  const salt = deB64(f.salt);
  const clave = await derivarClave(pass, salt, f.iter);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: deB64(f.iv) }, clave, deB64(f.datos));
  return { clave, salt, iter: f.iter, db: JSON.parse(td.decode(pt)) };
}

// ---------- IndexedDB (copia local cifrada) ----------
const idb = {
  _db: null,
  abrir() {
    if (this._db) return this._db;
    this._db = new Promise((ok, mal) => {
      const r = indexedDB.open('historias-clinicas', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => ok(r.result);
      r.onerror = () => mal(r.error);
    });
    return this._db;
  },
  async get(k) {
    const db = await this.abrir();
    return new Promise((ok, mal) => { const r = db.transaction('kv').objectStore('kv').get(k); r.onsuccess = () => ok(r.result); r.onerror = () => mal(r.error); });
  },
  async set(k, v) {
    const db = await this.abrir();
    return new Promise((ok, mal) => { const t = db.transaction('kv', 'readwrite'); t.objectStore('kv').put(v, k); t.oncomplete = () => ok(); t.onerror = () => mal(t.error); });
  },
};

// ---------- Dropbox ----------
class ConflictoError extends Error {}
const DBX = {
  appKey: () => CONFIG.dropboxAppKey || pref.get('appKey') || '',
  redireccion: () => location.origin + location.pathname,
  carpeta: () => (pref.get('carpeta') || CONFIG.carpetaDropbox).replace(/\/+$/, ''),
  ruta: () => DBX.carpeta() + '/' + ARCHIVO_DATOS,
  conectado: () => !!pref.get('dbxRefresh'),

  // Las cabeceras HTTP solo admiten ASCII: Dropbox pide escapar el resto como \uXXXX.
  arg: o => JSON.stringify(o).replace(/[\u007f-￿]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')),

  async conectar() {
    const b64url = b => aB64(b).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const verificador = b64url(crypto.getRandomValues(new Uint8Array(48)));
    const desafio = b64url(await crypto.subtle.digest('SHA-256', te.encode(verificador)));
    pref.set('pkce', verificador);
    const p = new URLSearchParams({
      client_id: DBX.appKey(), response_type: 'code', code_challenge: desafio, code_challenge_method: 'S256',
      redirect_uri: DBX.redireccion(), token_access_type: 'offline',
    });
    location.href = 'https://www.dropbox.com/oauth2/authorize?' + p;
  },
  async completar(codigo) {
    const r = await fetch('https://api.dropboxapi.com/oauth2/token', {
      method: 'POST',
      body: new URLSearchParams({
        code: codigo, grant_type: 'authorization_code', code_verifier: pref.get('pkce') || '',
        client_id: DBX.appKey(), redirect_uri: DBX.redireccion(),
      }),
    });
    pref.set('pkce', null);
    if (!r.ok) throw new Error('Dropbox rechazó la autorización (' + r.status + ').');
    DBX._guardarToken(await r.json());
  },
  _guardarToken(t) {
    if (t.refresh_token) pref.set('dbxRefresh', t.refresh_token);
    DBX._token = t.access_token;
    DBX._vence = Date.now() + (t.expires_in - 60) * 1000;
  },
  async token() {
    if (DBX._token && Date.now() < DBX._vence) return DBX._token;
    const r = await fetch('https://api.dropboxapi.com/oauth2/token', {
      method: 'POST',
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: pref.get('dbxRefresh') || '', client_id: DBX.appKey() }),
    });
    if (!r.ok) {
      if (r.status === 400 || r.status === 401) pref.set('dbxRefresh', null);
      throw new Error('No se pudo renovar el acceso a Dropbox (' + r.status + '). Volvé a conectar Dropbox.');
    }
    DBX._guardarToken(await r.json());
    return DBX._token;
  },
  async descargar(ruta, binario = false) {
    const r = await fetch('https://content.dropboxapi.com/2/files/download', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + await DBX.token(), 'Dropbox-API-Arg': DBX.arg({ path: ruta }) },
    });
    if (r.status === 409) {
      const e = await r.json().catch(() => ({}));
      if (/not_found/.test(e.error_summary || '')) return null;
      throw new Error('Dropbox: ' + (e.error_summary || 'error 409'));
    }
    if (!r.ok) throw new Error('Dropbox respondió ' + r.status);
    const meta = JSON.parse(r.headers.get('Dropbox-API-Result') || '{}');
    return binario ? await r.arrayBuffer() : { texto: await r.text(), rev: meta.rev };
  },
  async borrar(ruta) {
    const r = await fetch('https://api.dropboxapi.com/2/files/delete_v2', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + await DBX.token(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ path: ruta }),
    });
    if (!r.ok && r.status !== 409) throw new Error('Dropbox respondió ' + r.status);
  },
  async subir(ruta, texto, modo) {
    const r = await fetch('https://content.dropboxapi.com/2/files/upload', {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + await DBX.token(),
        'Content-Type': 'application/octet-stream',
        'Dropbox-API-Arg': DBX.arg({ path: ruta, mode: modo, autorename: false, mute: true }),
      },
      body: texto,
    });
    if (r.status === 409) {
      const e = await r.json().catch(() => ({}));
      if (/conflict/.test(e.error_summary || '')) throw new ConflictoError('conflicto');
      throw new Error('Dropbox: ' + (e.error_summary || 'error 409'));
    }
    if (!r.ok) throw new Error('Dropbox respondió ' + r.status);
    return (await r.json()).rev;
  },
};

// ---------- Almacenamiento (Dropbox o modo prueba local) ----------
const Almacen = {
  modo: () => pref.get('modo'),
  async leer() {
    if (Almacen.modo() === 'local') return { texto: await idb.get('datos') || null };
    try {
      const r = await DBX.descargar(DBX.ruta());
      if (r) await idb.set('cache', r.texto);
      return r ? r : { texto: null };
    } catch (e) {
      const cache = await idb.get('cache');
      if (cache && !(e instanceof ConflictoError)) return { texto: cache, sinConexion: true, error: e };
      throw e;
    }
  },
  async escribir(texto) {
    if (Almacen.modo() === 'local') { await idb.set('datos', texto); return; }
    const modo = S.rev ? { '.tag': 'update', update: S.rev } : { '.tag': 'add' };
    S.rev = await DBX.subir(DBX.ruta(), texto, modo);
    await idb.set('cache', texto);
    // Copia de seguridad diaria, aparte del archivo principal (Dropbox además guarda el historial de versiones).
    const hoy = hoyISO();
    if (pref.get('ultimoBackup') !== hoy) {
      await DBX.subir(DBX.carpeta() + '/copias/historias-' + hoy + '.hc', texto, { '.tag': 'overwrite' });
      pref.set('ultimoBackup', hoy);
    }
  },
};

// ---------- Archivos adjuntos (PDF y fotos) ----------
// Cada archivo va cifrado aparte en «adjuntos/». Usan una clave propia guardada dentro de los datos
// (que a su vez están cifrados con la contraseña): así cambiar la contraseña no obliga a recifrar los archivos.
const TAM_MAXIMO = 40 * 1024 * 1024;
const CATEGORIAS_ADJUNTO = ['Epicrisis de internación', 'Estudio', 'Informe', 'Otro'];
async function claveAdjuntos() {
  if (!S.db.claveAdjuntos) S.db.claveAdjuntos = aB64(crypto.getRandomValues(new Uint8Array(32)));
  if (!S.claveAdj) S.claveAdj = await crypto.subtle.importKey('raw', deB64(S.db.claveAdjuntos), 'AES-GCM', false, ['encrypt', 'decrypt']);
  return S.claveAdj;
}
async function cifrarBytes(buf) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await claveAdjuntos(), buf);
  const salida = new Uint8Array(12 + ct.byteLength);
  salida.set(iv); salida.set(new Uint8Array(ct), 12);
  return salida;
}
async function descifrarBytes(buf) {
  const b = new Uint8Array(buf);
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.slice(0, 12) }, await claveAdjuntos(), b.slice(12));
}
const Adjuntos = {
  ruta: id => DBX.carpeta() + '/adjuntos/' + id + '.hca',
  async subir(id, bytes) {
    if (Almacen.modo() === 'local') return idb.set('adj:' + id, bytes);
    await DBX.subir(Adjuntos.ruta(id), bytes, { '.tag': 'add' });
  },
  async bajar(id) {
    const datos = Almacen.modo() === 'local' ? await idb.get('adj:' + id) : await DBX.descargar(Adjuntos.ruta(id), true);
    if (!datos) throw new Error('El archivo no está en Dropbox.');
    return descifrarBytes(datos);
  },
  async borrar(id) {
    try {
      if (Almacen.modo() === 'local') await idb.set('adj:' + id, null);
      else await DBX.borrar(Adjuntos.ruta(id));
    } catch (e) { console.error(e); } // si queda el archivo cifrado en Dropbox no molesta
  },
};
// Las fotos del celular pesan varios MB: se achican a 2400 px en JPEG (sigue siendo legible un informe escaneado).
async function prepararArchivo(f) {
  if (/^image\/(jpeg|png|webp|heic|heif)$/.test(f.type) && f.size > 600 * 1024) {
    try {
      const img = await createImageBitmap(f, { imageOrientation: 'from-image' });
      const k = Math.min(1, 2400 / Math.max(img.width, img.height));
      const c = document.createElement('canvas');
      c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      const blob = await new Promise(ok => c.toBlob(ok, 'image/jpeg', 0.85));
      if (blob && blob.size < f.size) return { bytes: await blob.arrayBuffer(), tipo: 'image/jpeg', nombre: f.name.replace(/\.[^.]+$/, '') + '.jpg' };
    } catch (e) { console.error(e); }
  }
  return { bytes: await f.arrayBuffer(), tipo: f.type || 'application/octet-stream', nombre: f.name };
}
// Sube los archivos elegidos y los agrega a la ficha. «aviso» recibe el texto de progreso.
async function adjuntarArchivos(p, archivos, datos, aviso) {
  p.adjuntos = p.adjuntos || [];
  for (let i = 0; i < archivos.length; i++) {
    const f = archivos[i];
    if (f.size > TAM_MAXIMO) throw new Error(`«${f.name}» pesa más de 40 MB.`);
    aviso(archivos.length > 1 ? `Subiendo ${i + 1} de ${archivos.length}: ${f.name}…` : `Subiendo ${f.name}…`);
    const { bytes, tipo, nombre } = await prepararArchivo(f);
    const id = nuevoId();
    await Adjuntos.subir(id, await cifrarBytes(bytes));
    p.adjuntos.push(Object.assign({ id, nombre, tipo, tam: bytes.byteLength, creado: new Date().toISOString() }, datos));
  }
}
const tamLegible = n => n > 1048576 ? (n / 1048576).toFixed(1).replace('.', ',') + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB';

// ---------- Estado ----------
const S = { clave: null, salt: null, iter: ITERACIONES, db: null, rev: null, soloLectura: false, pendiente: false, claveAdj: null };
let colaGuardado = Promise.resolve();

function estadoGuardado(texto, tipo = 'ok') {
  const el = $('#estado-guardado');
  el.textContent = texto;
  el.className = 'estado ' + (texto ? tipo : '');
}
function aviso(html) {
  const el = $('#aviso');
  el.hidden = !html;
  el.innerHTML = html || '';
}

function guardar() {
  if (S.soloLectura) { alert('Estás viendo una copia sin conexión: no se puede guardar.'); return Promise.resolve(); }
  S.db.modificado = new Date().toISOString();
  S.pendiente = true;
  estadoGuardado('Guardando…', 'guardando');
  colaGuardado = colaGuardado.then(async () => {
    try {
      await Almacen.escribir(await cifrar(S.db));
      S.pendiente = false;
      estadoGuardado('Guardado ' + new Date().toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' }));
    } catch (e) {
      console.error(e);
      if (e instanceof ConflictoError) {
        estadoGuardado('No guardado', 'error');
        aviso('Los datos se modificaron desde otro dispositivo. <b>Recargá la página</b> para ver la versión más nueva (el último cambio que hiciste acá no se guardó).');
      } else {
        estadoGuardado('Error al guardar', 'error');
        aviso('No se pudo guardar: ' + esc(e.message) + ' — revisá la conexión a internet y volvé a intentar con «Guardar de nuevo». <button class="btn chico" data-accion="reintentar">Guardar de nuevo</button>');
      }
    }
  });
  return colaGuardado;
}

// ---------- Utilidades de fechas ----------
function fechaLeg(iso) {
  if (!iso) return '';
  const [a, m, d] = iso.slice(0, 10).split('-');
  return d && m && a ? `${d}/${m}/${a}` : iso;
}
function edad(fn, ref = new Date()) {
  if (!fn) return '';
  const n = new Date(fn + 'T00:00:00');
  if (isNaN(n)) return '';
  let meses = (ref.getFullYear() - n.getFullYear()) * 12 + ref.getMonth() - n.getMonth();
  if (ref.getDate() < n.getDate()) meses--;
  if (meses < 0) return '';
  const a = Math.floor(meses / 12), m = meses % 12;
  if (a === 0) {
    const dias = Math.floor((ref - n) / 86400000);
    return meses === 0 ? dias + ' d' : meses + ' m';
  }
  return a < 18 && m ? `${a} a ${m} m` : `${a} a`;
}
// «6 a 9 m» → «6 años 9 meses»
function edadLarga(fn, ref) {
  return edad(fn, ref).replace(/(\d+) ([amd])\b/g, (_, n, u) => n + ' ' + ({ a: ['año', 'años'], m: ['mes', 'meses'], d: ['día', 'días'] }[u][n === '1' ? 0 : 1]));
}

// ---------- Presentación ----------
// Los archivos se llaman «02 Alvarez Irsolina.doc»: en pantalla se muestra solo el número.
const numeroCorto = p => (String(p.numero || '').match(/^\d+(?=\s|$)/) || [p.numero || ''])[0];
function iniciales(p) {
  const partes = [p.apellido, p.nombre].filter(Boolean).join(' ').split(/[\s,]+/).filter(w => /^\p{L}/u.test(w));
  return partes.slice(0, 2).map(w => w[0]).join('').toUpperCase() || '?';
}
const tonoDe = p => [...String(p.id)].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 7);
const avatar = (p, clase = '') => `<span class="avatar ${clase}" style="--h:${tonoDe(p)}" aria-hidden="true">${esc(iniciales(p))}</span>`;
const svg = d => `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${d}</svg>`;
const ICONO = {
  mas: svg('<path d="M12 5v14M5 12h14"/>'),
  editar: svg('<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>'),
  imprimir: svg('<path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/>'),
  atras: svg('<path d="m15 18-6-6 6-6"/>'),
  alerta: svg('<path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>'),
  buscar: svg('<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>'),
  documento: svg('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>'),
  imagen: svg('<rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="9" cy="9" r="2"/><path d="m21 15-3.1-3.1a2 2 0 0 0-2.8 0L6 21"/>'),
  compartir: svg('<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/><path d="m16 6-4-4-4 4M12 2v13"/>'),
  clip: svg('<path d="m21.4 11.1-9.2 9.2a6 6 0 0 1-8.5-8.5l9.2-9.2a4 4 0 0 1 5.7 5.7l-9.2 9.2a2 2 0 0 1-2.8-2.8l8.5-8.5"/>'),
};
const MESES = ['ene', 'feb', 'mar', 'abr', 'may', 'jun', 'jul', 'ago', 'sep', 'oct', 'nov', 'dic'];

// ---------- Modelo ----------
const CAMPOS_PACIENTE = [
  { k: 'numero', t: 'N° de historia' },
  { k: 'apellido', t: 'Apellido', req: true },
  { k: 'nombre', t: 'Nombre' },
  { k: 'fechaNac', t: 'Fecha de nacimiento', tipo: 'date' },
  { k: 'sexo', t: 'Sexo', tipo: 'select', ops: ['', 'Femenino', 'Masculino', 'Otro'] },
  { k: 'dni', t: 'DNI' },
  { k: 'obraSocial', t: 'Obra social' },
  { k: 'nroAfiliado', t: 'N° de afiliado' },
  { k: 'telefono', t: 'Teléfono', tipo: 'tel' },
  { k: 'responsable', t: 'Madre / padre / tutor' },
  { k: 'email', t: 'Email', tipo: 'email' },
  { k: 'alergias', t: 'Alergias', tipo: 'area' },
  { k: 'medicacion', t: 'Medicación actual', tipo: 'area' },
  { k: 'antPersonales', t: 'Antecedentes personales', tipo: 'area' },
  { k: 'antFamiliares', t: 'Antecedentes familiares', tipo: 'area' },
];
const TIPOS_ESTUDIO = ['ECG', 'Holter', 'PEG', 'Ecocardiograma', 'RMN cardíaca', 'AngioTC', 'Laboratorio', 'Otro'];
const CAMPOS_EVOLUCION = [
  { k: 'fecha', t: 'Fecha', tipo: 'date', req: true },
  { k: 'motivo', t: 'Motivo de consulta' },
  { k: 'peso', t: 'Peso (kg)', tipo: 'text' },
  { k: 'talla', t: 'Talla (cm)', tipo: 'text' },
  { k: 'texto', t: 'Evolución / enfermedad actual', tipo: 'area', ancho: true },
  { k: 'examen', t: 'Examen físico', tipo: 'area', ancho: true },
  { k: 'estudiosComp', t: 'Estudios complementarios', tipo: 'area', ancho: true },
  { k: 'medicacion', t: 'Medicación actual', tipo: 'area', ancho: true },
  { k: 'actualizarMed', t: 'Pasar esta medicación al «Resumen clínico» del paciente', tipo: 'casilla' },
  { k: 'diagnostico', t: 'Diagnóstico', ancho: true },
  { k: 'conducta', t: 'Conducta', tipo: 'area', ancho: true },
];
// Apartados de una evolución, en el orden en que se muestran (pantalla, PDF y resumen).
const APARTADOS_EVOLUCION = [
  ['examen', 'Examen físico'], ['estudiosComp', 'Estudios complementarios'], ['medicacion', 'Medicación actual'],
  ['diagnostico', 'Diagnóstico'], ['conducta', 'Conducta'],
];
const CAMPOS_ESTUDIO = [
  { k: 'tipo', t: 'Estudio', tipo: 'select', ops: TIPOS_ESTUDIO, req: true },
  { k: 'fecha', t: 'Fecha', tipo: 'date' },
  { k: 'detalle', t: 'Especificar (si es «Otro»)' },
  { k: 'resultado', t: 'Resultado / informe', tipo: 'area', ancho: true },
  { k: 'archivos', t: 'Adjuntar PDF o fotos del estudio', tipo: 'archivos' },
];
const CAMPOS_ADJUNTO = [
  { k: 'categoria', t: 'Tipo de documento', tipo: 'select', ops: CATEGORIAS_ADJUNTO, req: true },
  { k: 'fecha', t: 'Fecha', tipo: 'date' },
  { k: 'descripcion', t: 'Descripción', ancho: true },
];

const paciente = id => S.db.pacientes.find(p => p.id === id);
const nombreCompleto = p => [p.apellido, p.nombre].filter(Boolean).join(', ') || (p.numero ? 'Historia N° ' + p.numero : 'Sin nombre');
const ultimaFecha = p => (p.evoluciones || []).reduce((m, e) => (e.fecha > m ? e.fecha : m), p.ultimaConsultaImportada || '');

// ---------- Pantallas de ingreso ----------
function pantallaInicio(error) {
  $('#barra').hidden = true;
  const tieneKey = !!DBX.appKey();
  $('#app').innerHTML = `
  <div class="centro tarjeta">
    <img src="icono.svg" alt="" class="logo" width="56" height="56">
    <h1>Historias Clínicas</h1>
    <p class="suave">Configuración inicial de este dispositivo.</p>
    ${error ? `<p class="error-texto">${esc(error)}</p>` : ''}
    <form id="f-dropbox">
      <h2>Guardar en Dropbox</h2>
      ${tieneKey ? '' : `<label class="campo"><span>App key de Dropbox</span><input name="appKey" required autocomplete="off" spellcheck="false"></label>`}
      <label class="campo"><span>Carpeta de Dropbox</span><input name="carpeta" value="${esc(DBX.carpeta())}" required></label>
      <button class="btn primario" type="submit">Conectar con Dropbox</button>
    </form>
    <hr style="border:0;border-top:1px solid var(--borde);margin:18px 0">
    <p class="chico suave">¿Querés probarla primero con datos inventados? El modo prueba guarda todo solo en este navegador, sin copia en Dropbox.</p>
    <button class="btn" data-accion="modo-prueba">Usar en modo prueba</button>
  </div>`;
  $('#f-dropbox').addEventListener('submit', ev => {
    ev.preventDefault();
    const f = new FormData(ev.target);
    if (!tieneKey) pref.set('appKey', f.get('appKey').trim());
    let carpeta = f.get('carpeta').trim();
    if (!carpeta.startsWith('/')) carpeta = '/' + carpeta;
    pref.set('carpeta', carpeta);
    DBX.conectar();
  });
}

async function pantallaClave() {
  $('#barra').hidden = true;
  $('#app').innerHTML = `<div class="centro tarjeta"><p class="suave">Conectando…</p></div>`;
  let archivo;
  try {
    archivo = await Almacen.leer();
  } catch (e) {
    console.error(e);
    if (!DBX.conectado() && Almacen.modo() === 'dropbox') { pref.set('modo', null); return pantallaInicio(e.message); }
    $('#app').innerHTML = `<div class="centro tarjeta"><h1>No se pudo conectar</h1><p class="error-texto">${esc(e.message)}</p>
      <div class="acciones"><button class="btn primario" onclick="location.reload()">Reintentar</button></div></div>`;
    return;
  }
  const nueva = !archivo.texto;
  $('#app').innerHTML = `
  <form class="centro tarjeta" id="f-clave" autocomplete="off">
    <img src="icono.svg" alt="" class="logo" width="56" height="56">
    <h1>${nueva ? 'Crear contraseña' : 'Ingresar'}</h1>
    <p class="suave chico">${nueva
      ? 'Elegí una contraseña larga (por ejemplo, una frase). <b>Anotala en un lugar seguro:</b> sin ella no hay forma de recuperar las historias, ni siquiera desde el backup.'
      : Almacen.modo() === 'local' ? 'Modo prueba (datos solo en este navegador).' : 'Datos en Dropbox: ' + esc(DBX.ruta())}</p>
    ${archivo.sinConexion ? '<p class="error-texto">Sin conexión con Dropbox: se abrirá la última copia guardada en este dispositivo, solo para leer.</p>' : ''}
    <label class="campo"><span>Contraseña</span><input type="password" name="p1" required minlength="${nueva ? 10 : 1}" autofocus autocomplete="${nueva ? 'new-password' : 'current-password'}"></label>
    ${nueva ? '<label class="campo"><span>Repetir contraseña</span><input type="password" name="p2" required autocomplete="new-password"></label>' : ''}
    <p class="error-texto" id="err"></p>
    <button class="btn primario" type="submit">${nueva ? 'Crear' : 'Entrar'}</button>
  </form>`;
  $('#f-clave').addEventListener('submit', async ev => {
    ev.preventDefault();
    const f = new FormData(ev.target), err = $('#err'), boton = $('button[type=submit]', ev.target);
    err.textContent = '';
    const p1 = f.get('p1');
    if (nueva && p1 !== f.get('p2')) { err.textContent = 'Las contraseñas no coinciden.'; return; }
    boton.disabled = true; boton.textContent = 'Verificando…';
    try {
      if (nueva) {
        S.salt = crypto.getRandomValues(new Uint8Array(16));
        S.iter = ITERACIONES;
        S.clave = await derivarClave(p1, S.salt, S.iter);
        S.db = { version: 1, creado: new Date().toISOString(), pacientes: [] };
        S.rev = null;
        await guardar();
        if (S.pendiente) throw new Error('No se pudo crear el archivo de datos.');
      } else {
        Object.assign(S, await descifrar(archivo.texto, p1));
        S.rev = archivo.rev || null;
        S.soloLectura = !!archivo.sinConexion;
      }
    } catch (e) {
      console.error(e);
      boton.disabled = false; boton.textContent = nueva ? 'Crear' : 'Entrar';
      err.textContent = nueva ? e.message : 'Contraseña incorrecta.';
      return;
    }
    entrar();
  });
}

function entrar() {
  $('#barra').hidden = false;
  if (S.soloLectura) aviso('Sin conexión: estás viendo la última copia guardada en este dispositivo. No se pueden hacer cambios.');
  else if (Almacen.modo() === 'local') aviso('Modo prueba: los datos están solo en este navegador y <b>no tienen backup</b>. No cargues pacientes reales.');
  estadoGuardado(S.db.modificado ? 'Guardado ' + new Date(S.db.modificado).toLocaleString('es-AR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' }) : '');
  iniciarBloqueo();
  window.addEventListener('hashchange', mostrar);
  mostrar();
}

function bloquear() {
  if (S.pendiente) {
    estadoGuardado('Guardando antes de bloquear…', 'guardando');
    colaGuardado.then(() => { if (!S.pendiente || confirm('Hay cambios sin guardar. ¿Bloquear igual?')) location.replace(location.pathname); });
    return;
  }
  // Recargar borra la clave y los datos descifrados de la memoria.
  location.replace(location.pathname);
}
function iniciarBloqueo() {
  let t;
  const reiniciar = () => { clearTimeout(t); t = setTimeout(bloquear, CONFIG.minutosBloqueo * 60000); };
  ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach(e => addEventListener(e, reiniciar, { passive: true }));
  reiniciar();
}

// ---------- Navegación ----------
function mostrar() {
  if (!S.db) return;
  const h = location.hash;
  let m;
  if ((m = h.match(/^#\/p\/(.+)$/))) return vistaPaciente(decodeURIComponent(m[1]));
  if (h === '#/ajustes') return vistaAjustes();
  vistaLista();
}

// ---------- Lista de pacientes ----------
let busqueda = '', orden = pref.get('orden') || 'apellido';

function vistaLista() {
  document.title = 'Historias Clínicas';
  const ro = S.soloLectura;
  $('#app').innerHTML = `
  <div class="buscador">
    <label class="caja-busqueda">${ICONO.buscar}<input type="search" id="q" placeholder="Buscar paciente, N° o diagnóstico…" value="${esc(busqueda)}" autocomplete="off" aria-label="Buscar"></label>
    <select id="orden" aria-label="Ordenar">
      <option value="apellido">Por apellido</option>
      <option value="numero">Por N° de historia</option>
      <option value="reciente">Consulta más reciente</option>
    </select>
    ${ro ? '' : `<button class="btn primario" data-accion="nuevo-paciente" title="Paciente nuevo" aria-label="Paciente nuevo">${ICONO.mas}<span>Paciente nuevo</span></button>`}
  </div>
  <div id="resultados"></div>`;
  $('#orden').value = orden;
  let t;
  $('#q').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { busqueda = e.target.value; dibujarResultados(); }, 120); });
  $('#orden').addEventListener('change', e => { orden = e.target.value; pref.set('orden', orden); dibujarResultados(); });
  dibujarResultados();
  if (matchMedia('(min-width: 601px)').matches) $('#q').focus();
}

function textoIdentidad(p) {
  return normalizar([p.numero, p.apellido, p.nombre, p.dni, p.obraSocial, p.responsable,
    ...(p.evoluciones || []).map(e => e.diagnostico)].join(' '));
}
const textoImportado = new WeakMap(); // caché de búsqueda, no se guarda
function textoCompleto(p) {
  if (!textoImportado.has(p) && p.historiaImportada) {
    const d = new DOMParser().parseFromString(p.historiaImportada, 'text/html');
    textoImportado.set(p, normalizar(d.body.textContent));
  }
  return normalizar([p.alergias, p.medicacion, p.antPersonales, p.antFamiliares,
    ...(p.evoluciones || []).flatMap(e => [e.motivo, e.texto, e.examen, e.estudiosComp, e.medicacion, e.conducta]),
    ...(p.estudios || []).flatMap(e => [e.tipo, e.detalle, e.resultado]),
    ...(p.adjuntos || []).flatMap(a => [a.categoria, a.descripcion, a.nombre])].join(' ')) + ' ' + (textoImportado.get(p) || '');
}

function filaPaciente(p) {
  const ult = ultimaFecha(p);
  const det = [p.numero ? 'N° ' + numeroCorto(p) : '', p.fechaNac ? edadLarga(p.fechaNac) : '', p.obraSocial].filter(Boolean).join(' · ');
  return `<li><a href="#/p/${encodeURIComponent(p.id)}">
    ${avatar(p)}
    <span class="fila-info"><span class="nom">${esc(nombreCompleto(p))}</span>${det ? `<span class="det">${esc(det)}</span>` : ''}</span>
    ${ult ? `<span class="fec"><span>Últ. consulta</span>${fechaLeg(ult)}</span>` : ''}
  </a></li>`;
}

function dibujarResultados() {
  const q = normalizar(busqueda).trim();
  const palabras = q.split(/\s+/).filter(Boolean);
  const todos = S.db.pacientes;
  let directos = todos, enTexto = [];
  if (palabras.length) {
    directos = todos.filter(p => { const t = textoIdentidad(p); return palabras.every(w => t.includes(w)); });
    if (q.length >= 3) {
      const ya = new Set(directos);
      enTexto = todos.filter(p => !ya.has(p) && palabras.every(w => textoCompleto(p).includes(w)));
    }
  }
  const cmp = {
    apellido: (a, b) => nombreCompleto(a).localeCompare(nombreCompleto(b), 'es'),
    numero: (a, b) => String(a.numero || '').localeCompare(String(b.numero || ''), 'es', { numeric: true }),
    reciente: (a, b) => ultimaFecha(b).localeCompare(ultimaFecha(a)),
  }[orden];
  directos = [...directos].sort(cmp);
  enTexto.sort(cmp);
  const el = $('#resultados');
  if (!todos.length) {
    el.innerHTML = `<div class="tarjeta"><p>Todavía no hay pacientes cargados.</p>
      <p class="chico suave">Podés cargar uno con «+ Paciente nuevo» o traer las historias de Word desde <a href="#/ajustes">Ajustes → Importar Word</a>.</p></div>`;
    return;
  }
  el.innerHTML = `
    <p class="subtitulo-lista">${palabras.length ? `${directos.length} resultado${directos.length === 1 ? '' : 's'}` : `${todos.length} pacientes`}</p>
    ${directos.length ? `<ul class="lista">${directos.map(filaPaciente).join('')}</ul>` : ''}
    ${enTexto.length ? `<p class="subtitulo-lista">También aparece en el texto de ${enTexto.length} historia${enTexto.length === 1 ? '' : 's'}:</p>
      <ul class="lista">${enTexto.map(filaPaciente).join('')}</ul>` : ''}
    ${palabras.length && !directos.length && !enTexto.length ? '<p class="vacio">Sin resultados.</p>' : ''}`;
}

// ---------- Ficha del paciente ----------
const filtroEstudio = {};

function vistaPaciente(id) {
  const p = paciente(id);
  if (!p) { location.hash = '#/'; return; }
  document.title = nombreCompleto(p) + ' — Historias Clínicas';
  const ro = S.soloLectura;
  const qid = esc(id);
  const dato = (t, v) => v ? `<div><dt>${t}</dt><dd>${esc(v)}</dd></div>` : '';
  const chip = v => v ? `<span class="chip">${esc(v)}</span>` : '';
  const evol = [...(p.evoluciones || [])].sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  const filtro = filtroEstudio[id] || '';
  const todosEst = [...(p.estudios || [])].sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  const tiposPresentes = TIPOS_ESTUDIO.filter(t => todosEst.some(e => e.tipo === t));
  const est = filtro ? todosEst.filter(e => e.tipo === filtro) : todosEst;
  const botonAgregar = (accion, texto) => ro ? '' : `<button class="btn primario chico" data-accion="${accion}" data-id="${qid}">${ICONO.mas}<span>${texto}</span></button>`;
  const botonEditar = (accion, reg) => ro ? '' : `<button class="btn-icono no-imprimir" data-accion="${accion}" data-id="${qid}" data-reg="${esc(reg)}" title="Editar" aria-label="Editar">${ICONO.editar}</button>`;
  const fechaBloque = f => {
    const [a, m, d] = (f || '').split('-');
    return a ? `<div class="evol-fecha"><span class="dia">${+d}</span><span class="mes">${MESES[+m - 1] || ''}</span><span class="anio">${a}</span></div>` : '<div class="evol-fecha"></div>';
  };
  const adjuntos = [...(p.adjuntos || [])].sort((a, b) => (b.fecha || b.creado || '').localeCompare(a.fecha || a.creado || ''));
  const resumen = [['Medicación actual', p.medicacion], ['Antecedentes personales', p.antPersonales], ['Antecedentes familiares', p.antFamiliares]];

  $('#app').innerHTML = `
  <a class="volver no-imprimir" href="#/">${ICONO.atras}Pacientes</a>
  <section class="tarjeta ficha-cab">
    <div class="ficha-titulo">
      ${avatar(p, 'grande')}
      <div class="ficha-id">
        <h1>${esc(nombreCompleto(p))}</h1>
        <div class="chips">
          ${p.numero ? chip('N° ' + numeroCorto(p)) : ''}
          ${p.fechaNac ? chip(edadLarga(p.fechaNac)) + chip('Nac. ' + fechaLeg(p.fechaNac)) : ''}
          ${chip([p.obraSocial, p.nroAfiliado].filter(Boolean).join(' · '))}
        </div>
      </div>
      <div class="acciones no-imprimir">
        ${ro ? '' : `<button class="btn chico" data-accion="editar-paciente" data-id="${qid}">${ICONO.editar}<span>Editar<span class="solo-pc"> datos</span></span></button>`}
        <button class="btn chico" data-accion="resumen-pdf" data-id="${qid}">${ICONO.documento}<span>Resumen<span class="solo-pc"> PDF</span></span></button>
        <button class="btn chico solo-pc" data-accion="imprimir">${ICONO.imprimir}<span>Imprimir</span></button>
      </div>
    </div>
    ${p.sexo || p.dni || p.telefono || p.responsable || p.email ? `<dl class="datos">
      ${dato('Sexo', p.sexo)}${dato('DNI', p.dni)}${dato('Teléfono', p.telefono)}${dato('Madre / padre / tutor', p.responsable)}${dato('Email', p.email)}
    </dl>` : ''}
    ${p.alergias ? `<div class="alergia">${ICONO.alerta}<div><b>Alergias</b> ${esc(p.alergias)}</div></div>` : ''}
  </section>

  <div class="ficha-cuerpo">
    <div class="col-principal">
      <section class="tarjeta seccion-evol">
        <div class="cabecera-seccion"><h2>Evoluciones <span class="cuenta">${evol.length || ''}</span></h2>${botonAgregar('nueva-evolucion', 'Evolución')}</div>
        ${evol.length ? `<div class="linea-tiempo">${evol.map(e => `
          <article class="evol">
            ${fechaBloque(e.fecha)}
            <div class="evol-cuerpo">
              <header>
                <h3>${esc(e.motivo || 'Consulta')}</h3>
                ${e.importada ? '<span class="etiqueta" title="Consulta traída de la historia en Word">Word</span>' : ''}
                <button class="btn-icono no-imprimir" data-accion="pdf-evolucion" data-id="${qid}" data-reg="${esc(e.id)}" title="PDF para compartir" aria-label="PDF para compartir">${ICONO.compartir}</button>
                ${botonEditar('editar-evolucion', e.id)}
              </header>
              ${e.peso || e.talla ? `<p class="medidas">${esc([e.peso && e.peso + ' kg', e.talla && e.talla + ' cm'].filter(Boolean).join(' · '))}</p>` : ''}
              ${e.texto ? `<p class="pre">${esc(e.texto)}</p>` : ''}
              ${APARTADOS_EVOLUCION.some(([k]) => e[k]) ? `<dl class="evol-campos">
                ${APARTADOS_EVOLUCION.filter(([k]) => e[k]).map(([k, t]) => `<div><dt>${t}</dt><dd>${esc(e[k])}</dd></div>`).join('')}
              </dl>` : ''}
            </div>
          </article>`).join('')}</div>` : '<p class="vacio">Sin evoluciones cargadas.</p>'}
      </section>

      ${p.historiaImportada ? `
      <section class="tarjeta seccion-historia">
        <details ${p.evoluciones?.length ? '' : 'open'}>
          <summary>${ICONO.documento}<span>Historia original completa${p.importado?.archivo ? `<small>${esc(p.importado.archivo)}</small>` : ''}</span></summary>
          <div class="importada">${limpiarHTML(p.historiaImportada)}</div>
        </details>
      </section>` : ''}
    </div>

    <aside class="col-lateral">
      <section class="tarjeta seccion-resumen">
        <div class="cabecera-seccion"><h2>Resumen clínico</h2>${ro ? '' : `<button class="btn-icono no-imprimir" data-accion="editar-resumen" data-id="${qid}" title="Editar resumen clínico" aria-label="Editar resumen clínico">${ICONO.editar}</button>`}</div>
        <dl class="resumen">${resumen.map(([t, v]) => `<div><dt>${t}</dt><dd class="${v ? 'pre' : 'vacio'}">${v ? esc(v) : 'Sin datos'}</dd></div>`).join('')}</dl>
      </section>

      ${todosEst.length ? `
      <!-- Los estudios ahora se cargan dentro de cada evolución; este recuadro solo aparece si quedaron estudios cargados aparte. -->
      <section class="tarjeta seccion-estudios">
        <div class="cabecera-seccion"><h2>Estudios <span class="cuenta">${todosEst.length}</span></h2></div>
        ${tiposPresentes.length > 1 ? `<div class="filtros">
          <button data-accion="filtro-estudio" data-id="${qid}" data-tipo="" class="${filtro ? '' : 'activo'}">Todos</button>
          ${tiposPresentes.map(t => `<button data-accion="filtro-estudio" data-id="${qid}" data-tipo="${esc(t)}" class="${filtro === t ? 'activo' : ''}">${esc(t)}</button>`).join('')}
        </div>` : ''}
        ${est.length ? est.map(e => `
          <article class="estudio">
            <header><span class="etiqueta tipo" style="--h:${(TIPOS_ESTUDIO.indexOf(e.tipo) * 47 + 200) % 360}">${esc(e.tipo === 'Otro' && e.detalle ? e.detalle : e.tipo)}</span>
              <span class="suave">${fechaLeg(e.fecha)}</span>${botonEditar('editar-estudio', e.id)}</header>
            ${e.resultado ? `<p class="pre">${esc(e.resultado)}</p>` : ''}
            ${adjuntos.filter(a => a.estudioId === e.id).map(a => `<button class="adjunto-mini" data-accion="ver-adjunto" data-id="${qid}" data-reg="${esc(a.id)}">${ICONO.clip}<span>${esc(a.nombre)}</span></button>`).join('')}
          </article>`).join('') : ''}
      </section>` : ''}

      <section class="tarjeta seccion-archivos">
        <div class="cabecera-seccion"><h2>Archivos <span class="cuenta">${adjuntos.length || ''}</span></h2>${botonAgregar('adjuntar', 'Adjuntar')}</div>
        ${adjuntos.length ? `<ul class="adjuntos">${adjuntos.map(a => `
          <li>
            <button class="adjunto" data-accion="ver-adjunto" data-id="${qid}" data-reg="${esc(a.id)}">
              <span class="adjunto-icono ${a.tipo === 'application/pdf' ? 'pdf' : ''}">${a.tipo.startsWith('image/') ? ICONO.imagen : ICONO.documento}</span>
              <span class="adjunto-info"><span class="adjunto-nombre">${esc(a.descripcion || a.nombre)}</span>
                <span class="adjunto-det">${esc([a.categoria, fechaLeg(a.fecha), tamLegible(a.tam)].filter(Boolean).join(' · '))}</span></span>
            </button>
            ${botonEditar('editar-adjunto', a.id)}
          </li>`).join('')}</ul>` : '<p class="vacio">Sin archivos. Podés adjuntar epicrisis, informes o estudios en PDF o foto.</p>'}
      </section>
    </aside>
  </div>

  ${ro ? '' : `<p class="pie-ficha no-imprimir"><button class="btn chico peligro" data-accion="borrar-paciente" data-id="${qid}">Eliminar paciente</button></p>`}`;
  scrollTo(0, 0);
}

// ---------- Formularios ----------
function campoHTML(c, v) {
  if (c.tipo === 'html') return c.html;
  if (c.tipo === 'casilla') return `<label class="casilla ancho"><input type="checkbox" name="${c.k}"${v ? ' checked' : ''}><span>${c.t}</span></label>`;
  const val = esc(v ?? '');
  const req = c.req ? ' required' : '';
  let input;
  if (c.tipo === 'archivos') input = `<input name="${c.k}" type="file" multiple accept="application/pdf,image/*"${req}><small class="ayuda">PDF o fotos. En el celular podés sacar la foto en el momento.</small>`;
  else if (c.tipo === 'area') input = `<textarea name="${c.k}"${req}>${val}</textarea>`;
  else if (c.tipo === 'select') input = `<select name="${c.k}"${req}>${c.ops.map(o => `<option${o === (v ?? '') ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  else input = `<input name="${c.k}" type="${c.tipo || 'text'}" value="${val}"${req} autocomplete="off">`;
  return `<label class="campo${c.tipo === 'area' || c.tipo === 'archivos' || c.ancho ? ' ancho' : ''}"><span>${c.t}${c.req ? ' *' : ''}</span>${input}</label>`;
}

function formulario({ titulo, campos, valores = {}, onGuardar, onBorrar, textoBorrar = 'Eliminar', textoGuardar = 'Guardar', intro = '' }) {
  const dlg = $('#dlg'), form = $('#dlg-form');
  form.innerHTML = `<h2>${esc(titulo)}</h2>${intro}
    <div class="rejilla">${campos.map(c => campoHTML(c, valores[c.k])).join('')}</div>
    <p class="error-texto" id="dlg-err"></p>
    <div class="pie-dialogo">
      ${onBorrar ? `<button type="button" class="btn peligro izq" data-dlg="borrar">${esc(textoBorrar)}</button>` : ''}
      <button type="button" class="btn" data-dlg="cancelar">Cancelar</button>
      <button type="submit" class="btn primario">${esc(textoGuardar)}</button>
    </div>`;
  const cerrar = () => { dlg.close(); form.onsubmit = null; form.onclick = null; };
  form.onclick = ev => {
    const b = ev.target.closest('[data-dlg]');
    if (!b) return;
    if (b.dataset.dlg === 'cancelar') cerrar();
    if (b.dataset.dlg === 'borrar' && onBorrar() !== false) cerrar();
  };
  form.onsubmit = async ev => {
    ev.preventDefault();
    const datos = {};
    for (const c of campos.filter(c => c.tipo !== 'html')) datos[c.k] = c.tipo === 'casilla' ? form.elements[c.k].checked : c.tipo === 'archivos' ? [...form.elements[c.k].files] : (form.elements[c.k].value || '').trim();
    const err = $('#dlg-err'), botones = form.querySelectorAll('.pie-dialogo button');
    botones.forEach(b => { b.disabled = true; });
    err.classList.add('progreso-texto');
    let error;
    try { error = await onGuardar(datos, texto => { err.textContent = texto; }); }
    catch (e) { console.error(e); error = 'No se pudo subir: ' + e.message; }
    botones.forEach(b => { b.disabled = false; });
    err.classList.remove('progreso-texto');
    if (error) { err.textContent = error; return; }
    cerrar();
  };
  dlg.showModal();
  const primero = form.querySelector('input, textarea, select');
  if (primero && matchMedia('(min-width: 601px)').matches) primero.focus();
}

function editarPaciente(id) {
  const p = id ? paciente(id) : null;
  formulario({
    titulo: p ? 'Editar datos del paciente' : 'Paciente nuevo',
    campos: CAMPOS_PACIENTE,
    valores: p || { numero: siguienteNumero() },
    onGuardar(d) {
      if (d.numero && S.db.pacientes.some(o => o !== p && String(o.numero) === d.numero)) return 'Ya existe un paciente con el N° de historia ' + d.numero + '.';
      if (p) Object.assign(p, d, { modificado: new Date().toISOString() });
      else S.db.pacientes.push(Object.assign({ id: nuevoId(), creado: new Date().toISOString(), evoluciones: [], estudios: [] }, d));
      guardar();
      const destino = '#/p/' + encodeURIComponent((p || S.db.pacientes[S.db.pacientes.length - 1]).id);
      if (location.hash === destino) mostrar(); else location.hash = destino;
    },
    onBorrar: p ? () => borrarPaciente(p) : null,
    textoBorrar: 'Eliminar paciente',
  });
}
// Solo los datos clínicos del recuadro «Resumen clínico» (y las alergias), sin el resto de la ficha.
function editarResumenClinico(id) {
  const p = paciente(id);
  formulario({
    titulo: 'Resumen clínico — ' + nombreCompleto(p),
    campos: CAMPOS_PACIENTE.filter(c => ['alergias', 'medicacion', 'antPersonales', 'antFamiliares'].includes(c.k)),
    valores: p,
    onGuardar(d) {
      Object.assign(p, d, { modificado: new Date().toISOString() });
      guardar(); mostrar();
    },
  });
}
function editarAdjunto(id, adjId) {
  const p = paciente(id);
  const adj = adjId ? (p.adjuntos || []).find(a => a.id === adjId) : null;
  formulario({
    titulo: (adj ? 'Editar archivo' : 'Adjuntar PDF o fotos') + ' — ' + nombreCompleto(p),
    campos: adj ? CAMPOS_ADJUNTO : [...CAMPOS_ADJUNTO, { k: 'archivos', t: 'Archivos', tipo: 'archivos', req: true }],
    valores: adj || { categoria: CATEGORIAS_ADJUNTO[0], fecha: hoyISO() },
    async onGuardar(d, aviso) {
      if (adj) Object.assign(adj, d, { modificado: new Date().toISOString() });
      else {
        const archivos = d.archivos; delete d.archivos;
        if (!archivos.length) return 'Elegí al menos un archivo.';
        await adjuntarArchivos(p, archivos, d, aviso);
      }
      guardar(); mostrar();
    },
    onBorrar: adj ? () => {
      if (!confirm(`¿Eliminar «${adj.nombre}»? No se puede deshacer.`)) return false;
      p.adjuntos = p.adjuntos.filter(a => a !== adj);
      Adjuntos.borrar(adj.id);
      guardar(); mostrar();
    } : null,
  });
}

let urlVisor = null;
async function verAdjunto(id, adjId) {
  const adj = (paciente(id).adjuntos || []).find(a => a.id === adjId);
  if (!adj) return;
  const dlg = $('#visor');
  const cuerpo = $('#visor-cuerpo');
  $('#visor-titulo').textContent = adj.descripcion || adj.nombre;
  $('#visor-acciones').innerHTML = '';
  cuerpo.innerHTML = '<p class="suave visor-mensaje">Descargando y descifrando…</p>';
  if (!dlg.open) dlg.showModal();
  try {
    const datos = await Adjuntos.bajar(adj.id);
    if (urlVisor) URL.revokeObjectURL(urlVisor);
    urlVisor = URL.createObjectURL(new Blob([datos], { type: adj.tipo }));
    const esImagen = adj.tipo.startsWith('image/'), esPdf = adj.tipo === 'application/pdf';
    $('#visor-acciones').innerHTML = `
      <a class="btn chico" href="${urlVisor}" target="_blank" rel="noopener">Abrir en pestaña nueva</a>
      <a class="btn chico" href="${urlVisor}" download="${esc(adj.nombre)}">Descargar</a>`;
    cuerpo.innerHTML = esImagen ? `<img src="${urlVisor}" alt="${esc(adj.nombre)}">`
      : esPdf && matchMedia('(min-width: 601px)').matches ? `<iframe src="${urlVisor}" title="${esc(adj.nombre)}"></iframe>`
      : `<p class="visor-mensaje">${esc(adj.nombre)} (${tamLegible(adj.tam)})<br><span class="suave">Tocá «Abrir en pestaña nueva» para verlo.</span></p>`;
  } catch (e) {
    console.error(e);
    cuerpo.innerHTML = `<p class="error-texto visor-mensaje">No se pudo abrir el archivo: ${esc(e.message)}</p>`;
  }
}
const cerrarVisor = () => $('#visor').close();
// También se cierra con Esc: al cerrarse por cualquier vía se libera el archivo descifrado.
$('#visor').addEventListener('close', () => {
  $('#visor-cuerpo').innerHTML = '';
  $('#visor-acciones').innerHTML = '';
  if (urlVisor) { URL.revokeObjectURL(urlVisor); urlVisor = null; }
});

// ---------- PDF de una evolución para compartir ----------
const ENCABEZADO_INICIAL = { nombre: 'Dr. Sebastián Maldonado', especialidad: 'Cardiología y electrofisiología', matricula: '', contacto: '' };
const lineasEncabezado = () => {
  const e = Object.assign({}, ENCABEZADO_INICIAL, S.db.encabezado);
  return [e.nombre, e.especialidad, e.matricula, e.contacto].filter(Boolean);
};
function editarEncabezado() {
  formulario({
    titulo: 'Encabezado de los PDF',
    campos: [
      { k: 'nombre', t: 'Nombre', req: true, ancho: true },
      { k: 'especialidad', t: 'Especialidad', ancho: true },
      { k: 'matricula', t: 'Matrícula (por ejemplo «MN 12345»)' },
      { k: 'contacto', t: 'Contacto (dirección, teléfono o mail)' },
    ],
    valores: Object.assign({}, ENCABEZADO_INICIAL, S.db.encabezado),
    onGuardar(d) { S.db.encabezado = d; guardar(); mostrar(); },
  });
}
let cargaJsPDF = null;
const cargarJsPDF = () => cargaJsPDF ||= new Promise((ok, mal) => {
  const sc = document.createElement('script');
  sc.src = 'vendor/jspdf.umd.min.js';
  sc.onload = () => ok(window.jspdf.jsPDF);
  sc.onerror = () => { cargaJsPDF = null; mal(new Error('No se pudo cargar el generador de PDF. Revisá la conexión.')); };
  document.head.append(sc);
});

// Arma un PDF A4 con el encabezado del médico; devuelve funciones para ir escribiendo de arriba hacia abajo.
async function nuevoPDF(titulo, fecha) {
  const jsPDF = await cargarJsPDF();
  const doc = new jsPDF({ unit: 'mm', format: 'a4' });
  const M = 20, ANCHO = 210 - 2 * M, ALTO_UTIL = 297 - 22;
  const AZUL = [31, 95, 139], GRIS = [95, 108, 123], TEXTO = [24, 33, 43];
  const pdf = { doc, y: 22, M, ANCHO, GRIS, TEXTO };
  pdf.espacio = h => { if (pdf.y + h > ALTO_UTIL) { doc.addPage(); pdf.y = 22; } };
  pdf.parrafo = (texto, { tam = 11, estilo = 'normal', color = TEXTO, interlineado = 5.2, sangria = 0 } = {}) => {
    doc.setFont('helvetica', estilo); doc.setFontSize(tam); doc.setTextColor(...color);
    for (const linea of doc.splitTextToSize(String(texto), ANCHO - sangria)) { pdf.espacio(interlineado); doc.text(linea, M + sangria, pdf.y); pdf.y += interlineado; }
  };
  pdf.rotulo = (t, { tam = 8.5 } = {}) => pdf.parrafo(t.toUpperCase(), { tam, estilo: 'bold', color: GRIS, interlineado: 4.5 });
  pdf.seccion = (t, texto) => {
    if (!texto) return;
    pdf.espacio(14); pdf.y += 3;
    pdf.rotulo(t); pdf.y += 0.5;
    pdf.parrafo(texto);
  };
  // Título de un bloque grande (Estudios, Evoluciones…) con una línea fina debajo.
  pdf.titulo = t => {
    pdf.espacio(20); pdf.y += 6;
    pdf.parrafo(t, { tam: 12.5, estilo: 'bold', color: AZUL, interlineado: 5.5 });
    doc.setDrawColor(225, 230, 236); doc.setLineWidth(0.3); doc.line(M, pdf.y - 3, M + ANCHO, pdf.y - 3); pdf.y += 2;
  };
  pdf.datosPaciente = (p, ref) => {
    const filas = [
      ['Paciente', nombreCompleto(p)],
      ['N° de historia', numeroCorto(p)],
      ['Nacimiento', p.fechaNac ? `${fechaLeg(p.fechaNac)} (${edadLarga(p.fechaNac, ref)}${ref ? ' a la fecha de la consulta' : ''})` : ''],
      ['Obra social', [p.obraSocial, p.nroAfiliado && 'N° ' + p.nroAfiliado].filter(Boolean).join(' · ')],
      ['DNI', p.dni],
    ].filter(f => f[1]);
    doc.setFillColor(243, 245, 248);
    doc.roundedRect(M, pdf.y - 4.5, ANCHO, filas.length * 5.6 + 5, 2, 2, 'F');
    for (const [t, v] of filas) {
      doc.setFont('helvetica', 'bold'); doc.setFontSize(9.5); doc.setTextColor(...GRIS); doc.text(t, M + 4, pdf.y);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(10.5); doc.setTextColor(...TEXTO);
      doc.text(doc.splitTextToSize(v, ANCHO - 44)[0], M + 38, pdf.y);
      pdf.y += 5.6;
    }
    pdf.y += 4;
    if (p.alergias) { pdf.y += 2; pdf.parrafo('Alergias: ' + p.alergias, { estilo: 'bold', color: [180, 35, 24] }); }
  };
  // Línea de firma a la derecha, con la imagen de la firma encima si está cargada.
  pdf.firma = () => {
    const enc = Object.assign({}, ENCABEZADO_INICIAL, S.db.encabezado);
    const centro = M + ANCHO - 35;
    const f = S.db.firma;
    // Firma con sello: la imagen ya trae nombre y matrícula, va sola y más grande, sin línea ni texto.
    if (f?.conSello) {
      const k = Math.min(70 / f.ancho, 38 / f.alto);
      const w = f.ancho * k, h = f.alto * k;
      pdf.espacio(h + 16); pdf.y += 12;
      doc.addImage(f.datos, 'PNG', centro - w / 2, pdf.y, w, h);
      pdf.y += h + 4;
      return;
    }
    pdf.espacio(40); pdf.y += 26;
    if (f) {
      const k = Math.min(60 / f.ancho, 24 / f.alto);
      const w = f.ancho * k, h = f.alto * k;
      doc.addImage(f.datos, 'PNG', centro - w / 2, pdf.y - h - 0.5, w, h);
    }
    doc.setDrawColor(...GRIS); doc.setLineWidth(0.3); doc.line(M + ANCHO - 70, pdf.y, M + ANCHO, pdf.y); pdf.y += 5;
    doc.setFont('helvetica', 'normal'); doc.setFontSize(9.5); doc.setTextColor(...GRIS);
    for (const l of [enc.nombre, enc.matricula].filter(Boolean)) { doc.text(l, centro, pdf.y, { align: 'center' }); pdf.y += 4.5; }
  };
  pdf.terminar = async (pie, nombreArchivo) => {
    const total = doc.getNumberOfPages();
    for (let i = 1; i <= total; i++) {
      doc.setPage(i);
      doc.setDrawColor(225, 230, 236); doc.setLineWidth(0.3); doc.line(M, 284, M + ANCHO, 284);
      doc.setFont('helvetica', 'normal'); doc.setFontSize(8.5); doc.setTextColor(...GRIS);
      doc.text(pie, M, 289);
      doc.text(`Página ${i} de ${total}`, M + ANCHO, 289, { align: 'right' });
    }
    nombreArchivo = nombreArchivo.normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/[^\w\- ]+/g, '').replace(/\s+/g, ' ').trim() + '.pdf';
    await entregarArchivo(new File([doc.output('blob')], nombreArchivo, { type: 'application/pdf' }));
  };

  // Encabezado del médico, título y fecha
  const [nombre, ...resto] = lineasEncabezado();
  pdf.parrafo(nombre, { tam: 15, estilo: 'bold', color: AZUL, interlineado: 6.5 });
  for (const l of resto) pdf.parrafo(l, { tam: 9.5, color: GRIS, interlineado: 4.6 });
  pdf.y += 2; doc.setDrawColor(...AZUL); doc.setLineWidth(0.6); doc.line(M, pdf.y, M + ANCHO, pdf.y); pdf.y += 9;
  doc.setFont('helvetica', 'bold'); doc.setFontSize(13); doc.setTextColor(...TEXTO);
  doc.text(titulo, M, pdf.y);
  doc.setFont('helvetica', 'normal'); doc.setFontSize(11);
  doc.text(fecha, M + ANCHO, pdf.y, { align: 'right' });
  pdf.y += 8;
  return pdf;
}
// En el celular abre el menú para compartir (WhatsApp, mail…); en la compu se descarga.
async function entregarArchivo(archivo) {
  if (navigator.canShare?.({ files: [archivo] }) && matchMedia('(pointer: coarse)').matches) {
    try { await navigator.share({ files: [archivo], title: archivo.name }); return; }
    catch (err) { if (err.name === 'AbortError') return; }
  }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(archivo);
  a.download = archivo.name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10000);
}
const nombreParaArchivo = p => [p.apellido, p.nombre].filter(Boolean).join(' ') || numeroCorto(p);

async function pdfEvolucion(p, e, boton) {
  if (!p || !e) return;
  boton.disabled = true;
  try {
    const pdf = await nuevoPDF('Evolución', fechaLeg(e.fecha));
    pdf.datosPaciente(p, e.fecha ? new Date(e.fecha + 'T00:00:00') : new Date());
    pdf.seccion('Motivo de consulta', e.motivo);
    pdf.seccion('Peso / talla', [e.peso && e.peso + ' kg', e.talla && e.talla + ' cm'].filter(Boolean).join(' · '));
    pdf.seccion('Evolución', e.texto);
    for (const [k, t] of APARTADOS_EVOLUCION) pdf.seccion(t, e[k]);
    pdf.firma();
    await pdf.terminar(`${nombreCompleto(p)} · Evolución del ${fechaLeg(e.fecha)}`, `Evolucion ${nombreParaArchivo(p)} ${e.fecha || ''}`);
  } catch (err) {
    console.error(err);
    alert('No se pudo generar el PDF: ' + err.message);
  } finally {
    boton.disabled = false;
  }
}

// ---------- Firma ----------
// Deja solo el trazo: lo claro (el papel) pasa a transparente, el resto a tinta azul oscuro, y se recorta al trazo.
function guardarFirma(canvas, esFoto) {
  const ctx = canvas.getContext('2d');
  const { width: w, height: h } = canvas;
  const img = ctx.getImageData(0, 0, w, h), d = img.data;
  // En una foto el papel no es blanco puro: el corte se toma bastante por debajo del tono medio del papel.
  let suma = 0;
  for (let i = 0; i < d.length; i += 4 * 16) suma += (d[i] + d[i + 1] + d[i + 2]) / 3;
  const papel = suma / (d.length / (4 * 16));
  const corte = esFoto ? papel - 75 : 250;
  let x0 = w, y0 = h, x1 = -1, y1 = -1;
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    const l = (d[i] + d[i + 1] + d[i + 2]) / 3;
    if (d[i + 3] > 0 && l < corte) {
      d[i] = 20; d[i + 1] = 35; d[i + 2] = 70;
      d[i + 3] = Math.min(255, Math.round((corte - l) / corte * 255 * 2.2));
      if (x < x0) x0 = x; if (x > x1) x1 = x; if (y < y0) y0 = y; if (y > y1) y1 = y;
    } else d[i + 3] = 0;
  }
  if (x1 < 0 || (x1 - x0) < 20) return 'No se encontró la firma en la imagen. Probá con más luz y un papel blanco.';
  ctx.putImageData(img, 0, 0);
  const m = 6, cw = x1 - x0 + 1 + 2 * m, ch = y1 - y0 + 1 + 2 * m;
  const k = Math.min(1, 700 / cw);
  const salida = document.createElement('canvas');
  salida.width = Math.round(cw * k); salida.height = Math.round(ch * k);
  salida.getContext('2d').drawImage(canvas, x0 - m, y0 - m, cw, ch, 0, 0, salida.width, salida.height);
  S.db.firma = { datos: salida.toDataURL('image/png'), ancho: salida.width, alto: salida.height };
  guardar(); mostrar();
  return '';
}
function dibujarFirma() {
  const dlg = $('#dlg'), form = $('#dlg-form');
  form.innerHTML = `<h2>Dibujar firma</h2>
    <p class="chico suave" style="margin-top:-8px">Firmá con el dedo (o con el mouse) dentro del recuadro.</p>
    <canvas id="lienzo-firma" class="lienzo-firma"></canvas>
    <p class="error-texto" id="lienzo-err"></p>
    <div class="pie-dialogo">
      <button type="button" class="btn izq" data-dlg="limpiar">Borrar y empezar de nuevo</button>
      <button type="button" class="btn" data-dlg="cancelar">Cancelar</button>
      <button type="submit" class="btn primario">Guardar firma</button>
    </div>`;
  dlg.showModal();
  const c = $('#lienzo-firma');
  const escala = devicePixelRatio || 1;
  c.width = c.clientWidth * escala; c.height = c.clientHeight * escala;
  const ctx = c.getContext('2d');
  const limpiar = () => { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, c.width, c.height); };
  limpiar();
  ctx.lineWidth = 2.6 * escala; ctx.lineCap = ctx.lineJoin = 'round'; ctx.strokeStyle = '#000';
  let dibujando = false, hayTrazo = false;
  const punto = ev => { const r = c.getBoundingClientRect(); return [(ev.clientX - r.left) * escala, (ev.clientY - r.top) * escala]; };
  c.onpointerdown = ev => { dibujando = true; c.setPointerCapture(ev.pointerId); ctx.beginPath(); ctx.moveTo(...punto(ev)); };
  c.onpointermove = ev => { if (!dibujando) return; ctx.lineTo(...punto(ev)); ctx.stroke(); hayTrazo = true; };
  c.onpointerup = c.onpointercancel = () => { dibujando = false; };
  form.onclick = ev => {
    const b = ev.target.closest('[data-dlg]');
    if (b?.dataset.dlg === 'cancelar') dlg.close();
    if (b?.dataset.dlg === 'limpiar') { limpiar(); hayTrazo = false; }
  };
  form.onsubmit = ev => {
    ev.preventDefault();
    const error = hayTrazo ? guardarFirma(c, false) : 'Primero dibujá tu firma.';
    if (error) $('#lienzo-err').textContent = error; else dlg.close();
  };
}

// ---------- Resumen de historia clínica ----------
const OPCIONES_EVOLUCIONES = { 'Las últimas 3': 3, 'La última': 1, 'Las últimas 5': 5, 'Las últimas 10': 10, 'Todas': Infinity, 'Ninguna': 0 };
// Texto de una evolución para pegar en el resumen.
function textoEvolucion(e) {
  const medidas = [e.peso && e.peso + ' kg', e.talla && e.talla + ' cm'].filter(Boolean).join(' · ');
  return [`${fechaLeg(e.fecha)}${e.motivo ? ' — ' + e.motivo : ''}`, medidas && 'Peso / talla: ' + medidas, e.texto,
    ...APARTADOS_EVOLUCION.map(([k, t]) => e[k] && `${t}: ${e[k]}`)].filter(Boolean).join('\n');
}

function dialogoResumen(p) {
  const evol = [...(p.evoluciones || [])].sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  const insertar = evol.length ? `<div class="campo ancho insertar-evol">
      <span>Agregar una evolución al texto</span>
      <div class="fila-insertar">
        <select id="evol-insertar" aria-label="Evolución para agregar">${evol.map(e =>
          `<option value="${esc(e.id)}">${fechaLeg(e.fecha)}${e.motivo ? ' — ' + esc(e.motivo.slice(0, 60)) : ''}</option>`).join('')}</select>
        <button type="button" class="btn" id="boton-insertar">${ICONO.mas}<span>Agregar</span></button>
      </div>
      <small class="ayuda">Se agrega donde está el cursor y después la podés corregir como quieras.</small>
    </div>` : '';
  formulario({
    titulo: 'Resumen de historia clínica — ' + nombreCompleto(p),
    intro: `<p class="chico suave" style="margin:-8px 0 16px">Incluye datos del paciente, alergias, antecedentes, medicación y diagnósticos.
      El texto del resumen se guarda como borrador en la ficha. Al final queda el lugar para firma y sello.</p>`,
    campos: [
      { k: 'destinatario', t: 'Dirigido a (opcional)', ancho: true },
      { k: 'comentario', t: 'Texto del resumen', tipo: 'area' },
      { tipo: 'html', html: insertar },
      { k: 'evoluciones', t: `Además, evoluciones completas al final (tiene ${evol.length})`, tipo: 'select', ops: Object.keys(OPCIONES_EVOLUCIONES) },
      ...((p.estudios || []).length ? [{ k: 'estudios', t: `Estudios cargados aparte (tiene ${p.estudios.length})`, tipo: 'select', ops: ['Todos', 'Ninguno'] }] : []),
    ],
    valores: { destinatario: p.borradorResumen?.destinatario, comentario: p.borradorResumen?.texto, evoluciones: 'Ninguna', estudios: 'Todos' },
    textoGuardar: 'Descargar PDF',
    async onGuardar(d, aviso) {
      aviso('Generando el PDF…');
      await pdfResumen(p, d);
    },
  });
  const form = $('#dlg-form'), area = form.elements.comentario;
  area.classList.add('texto-resumen');
  $('#boton-insertar')?.addEventListener('click', () => {
    const e = evol.find(x => x.id === $('#evol-insertar').value);
    if (!e) return;
    const antes = area.value.slice(0, area.selectionStart);
    const separador = !antes ? '' : antes.endsWith('\n\n') ? '' : antes.endsWith('\n') ? '\n' : '\n\n';
    area.setRangeText(separador + textoEvolucion(e) + '\n\n', area.selectionStart, area.selectionEnd, 'end');
    area.focus();
  });
  // Al cerrar (descargando o cancelando) se guarda el borrador si cambió.
  $('#dlg').addEventListener('close', () => {
    if (S.soloLectura) return;
    const borrador = { destinatario: form.elements.destinatario.value.trim(), texto: area.value.trim() };
    const anterior = p.borradorResumen || { destinatario: '', texto: '' };
    if (borrador.texto === anterior.texto && borrador.destinatario === anterior.destinatario) return;
    if (borrador.texto || borrador.destinatario) p.borradorResumen = borrador; else delete p.borradorResumen;
    guardar();
  }, { once: true });
}

async function pdfResumen(p, opciones) {
  const hoy = hoyISO();
  const pdf = await nuevoPDF('Resumen de historia clínica', fechaLeg(hoy));
  const evol = [...(p.evoluciones || [])].filter(e => e.fecha).sort((a, b) => a.fecha.localeCompare(b.fecha));
  if (opciones.destinatario) { pdf.parrafo('A: ' + opciones.destinatario, { estilo: 'bold' }); pdf.y += 3; }
  pdf.datosPaciente(p);
  if (evol.length) {
    pdf.parrafo(`En seguimiento desde el ${fechaLeg(evol[0].fecha)} · ${evol.length} consulta${evol.length === 1 ? '' : 's'} · última el ${fechaLeg(evol[evol.length - 1].fecha)}`,
      { tam: 9.5, color: pdf.GRIS });
  }
  // Texto del resumen: los renglones que empiezan con una fecha (evoluciones agregadas) van en negrita.
  if (opciones.comentario) {
    pdf.espacio(14); pdf.y += 3;
    pdf.rotulo('Resumen'); pdf.y += 0.5;
    for (const linea of opciones.comentario.split('\n')) {
      if (!linea.trim()) { pdf.y += 2.5; continue; }
      const esFecha = /^\d{1,2}\/\d{1,2}\/\d{2,4}\b/.test(linea.trim());
      if (esFecha) pdf.espacio(12);
      pdf.parrafo(linea, esFecha ? { estilo: 'bold' } : {});
    }
  }
  pdf.seccion('Antecedentes personales', p.antPersonales);
  pdf.seccion('Antecedentes familiares', p.antFamiliares);
  pdf.seccion('Medicación actual', p.medicacion);

  // Diagnósticos sin repetir, con la fecha en que aparecen por primera vez
  const dx = new Map();
  for (const e of evol) {
    if (!e.diagnostico) continue;
    const clave = normalizar(e.diagnostico).replace(/[.\s]+$/, '');
    if (!dx.has(clave)) dx.set(clave, { texto: e.diagnostico.replace(/[.\s]+$/, ''), desde: e.fecha });
  }
  pdf.seccion('Diagnósticos', [...dx.values()].map(d => `• ${d.texto} (desde ${fechaLeg(d.desde)})`).join('\n'));

  const estudios = opciones.estudios === 'Todos' ? [...(p.estudios || [])].sort((a, b) => (b.fecha || '').localeCompare(a.fecha || '')) : [];
  if (estudios.length) {
    pdf.titulo('Estudios complementarios');
    for (const e of estudios) {
      pdf.espacio(12); pdf.y += 2;
      pdf.parrafo(`${e.tipo === 'Otro' && e.detalle ? e.detalle : e.tipo}${e.fecha ? ' · ' + fechaLeg(e.fecha) : ''}`, { estilo: 'bold', tam: 10.5 });
      if (e.resultado) pdf.parrafo(e.resultado, { tam: 10.5, interlineado: 4.9 });
    }
  }

  const cuantas = OPCIONES_EVOLUCIONES[opciones.evoluciones] ?? 3;
  const elegidas = cuantas ? evol.slice(-cuantas).reverse() : [];
  if (elegidas.length) {
    pdf.titulo(elegidas.length === evol.length ? 'Evoluciones' : `Últimas evoluciones (${elegidas.length} de ${evol.length})`);
    for (const e of elegidas) {
      pdf.espacio(14); pdf.y += 3;
      pdf.parrafo(`${fechaLeg(e.fecha)}${e.motivo ? ' · ' + e.motivo : ''}`, { estilo: 'bold', tam: 10.5 });
      const medidas = [e.peso && e.peso + ' kg', e.talla && e.talla + ' cm'].filter(Boolean).join(' · ');
      for (const t of [medidas && 'Peso / talla: ' + medidas, e.texto, ...APARTADOS_EVOLUCION.map(([k, t]) => e[k] && `${t}: ${e[k]}`)]) {
        if (t) pdf.parrafo(t, { tam: 10.5, interlineado: 4.9 });
      }
    }
  }

  const adjuntos = p.adjuntos || [];
  if (adjuntos.length) {
    pdf.seccion('Documentación en la historia (no incluida en este resumen)',
      adjuntos.map(a => `• ${a.descripcion || a.nombre} (${[a.categoria, fechaLeg(a.fecha)].filter(Boolean).join(', ')})`).join('\n'));
  }
  pdf.firma();
  await pdf.terminar(`${nombreCompleto(p)} · Resumen de historia clínica · ${fechaLeg(hoy)}`, `Resumen HC ${nombreParaArchivo(p)} ${hoy}`);
}

function borrarPaciente(p) {
  const n = prompt(`Para eliminar a ${nombreCompleto(p)} con todas sus evoluciones y estudios, escribí ELIMINAR:`);
  if (!n || n.trim().toUpperCase() !== 'ELIMINAR') return false;
  S.db.pacientes = S.db.pacientes.filter(x => x !== p);
  (p.adjuntos || []).forEach(a => Adjuntos.borrar(a.id));
  guardar();
  location.hash = '#/';
}
function siguienteNumero() {
  const nums = S.db.pacientes.map(p => parseInt(p.numero, 10)).filter(n => !isNaN(n));
  return nums.length ? String(Math.max(...nums) + 1) : '1';
}

function editarRegistro(id, lista, regId) {
  const p = paciente(id);
  p[lista] = p[lista] || [];
  const reg = regId ? p[lista].find(r => r.id === regId) : null;
  const esEvol = lista === 'evoluciones';
  formulario({
    titulo: (reg ? 'Editar ' : 'Nueva ') + (esEvol ? 'evolución' : 'estudio') + ' — ' + nombreCompleto(p),
    campos: esEvol ? CAMPOS_EVOLUCION : CAMPOS_ESTUDIO,
    valores: esEvol
      // La medicación arranca con la del resumen clínico; al guardar, si es la consulta más reciente, se puede pasar al resumen.
      ? (reg ? Object.assign({}, reg, { actualizarMed: reg.fecha >= ultimaFecha(p) }) : { fecha: hoyISO(), medicacion: p.medicacion, actualizarMed: true })
      : reg || { fecha: hoyISO(), tipo: filtroEstudio[id] || '' },
    async onGuardar(d, aviso) {
      const archivos = d.archivos || [];
      delete d.archivos;
      if (esEvol) {
        if (d.actualizarMed && d.medicacion && d.medicacion !== p.medicacion) p.medicacion = d.medicacion;
        delete d.actualizarMed;
      }
      const destino = reg || Object.assign({ id: nuevoId(), creado: new Date().toISOString() }, d);
      if (archivos.length) {
        const nombre = d.tipo === 'Otro' && d.detalle ? d.detalle : d.tipo;
        await adjuntarArchivos(p, archivos, { categoria: 'Estudio', fecha: d.fecha, descripcion: nombre, estudioId: destino.id }, aviso);
      }
      if (reg) Object.assign(reg, d, { modificado: new Date().toISOString() });
      else p[lista].push(destino);
      guardar(); mostrar();
    },
    onBorrar: reg ? () => {
      const deEste = (p.adjuntos || []).filter(a => a.estudioId === reg.id);
      if (!confirm('¿Eliminar este registro?' + (deEste.length ? ` También se borran sus ${deEste.length} archivo(s) adjunto(s).` : '') + ' No se puede deshacer.')) return false;
      p[lista] = p[lista].filter(r => r !== reg);
      if (deEste.length) { p.adjuntos = p.adjuntos.filter(a => !deEste.includes(a)); deEste.forEach(a => Adjuntos.borrar(a.id)); }
      guardar(); mostrar();
    } : null,
  });
}

// ---------- Ajustes ----------
function vistaAjustes() {
  document.title = 'Ajustes — Historias Clínicas';
  const local = Almacen.modo() === 'local';
  const ro = S.soloLectura;
  $('#app').innerHTML = `
  <a class="volver" href="#/">${ICONO.atras}Pacientes</a>
  <div class="tarjeta">
    <h2>Datos y copias de seguridad</h2>
    ${local
      ? '<p>Modo prueba: los datos están solo en este navegador, <b>sin backup</b>.</p>'
      : `<p>Archivo principal: <b>${esc(DBX.ruta())}</b> en tu Dropbox.<br>
         Copia diaria en <b>${esc(DBX.carpeta())}/copias/</b>${pref.get('ultimoBackup') ? ' (última: ' + fechaLeg(pref.get('ultimoBackup')) + ')' : ''}.
         Los PDF y fotos adjuntos están en <b>${esc(DBX.carpeta())}/adjuntos/</b>.
         Además, Dropbox guarda el historial de versiones de cada archivo.</p>`}
    <p class="chico suave">Todos los archivos están cifrados con tu contraseña: sin ella no se pueden leer.</p>
    <div class="acciones">
      <button class="btn" data-accion="descargar-copia">Descargar copia cifrada a esta computadora</button>
    </div>
    <p class="chico suave" style="margin-bottom:0">La copia descargada tiene todas las historias; los PDF y fotos adjuntos quedan en Dropbox.</p>
    <div>
    </div>
  </div>

  ${ro ? '' : `<div class="tarjeta">
    <h2>Importar historias de Word</h2>
    <p class="chico">Seleccioná los archivos de Word (<b>.doc</b>, <b>.docx</b>) o de LibreOffice (<b>.odt</b>); podés elegir todos juntos. El nombre de cada archivo se toma como N° de historia
      y cada consulta con fecha pasa a ser una evolución; el Word completo queda en «Historia original completa». Si un N° ya existe, se actualiza lo que vino del Word sin tocar lo cargado en la app.</p>
    <div class="acciones">
      <label class="btn primario">Elegir archivos Word…<input type="file" data-destino="importar" accept=".docx,.doc,.odt" multiple hidden></label>
      <label class="btn">Elegir carpeta entera…<input type="file" data-destino="importar" webkitdirectory multiple hidden></label>
    </div>
    <div id="importacion" style="margin-top:12px"></div>
  </div>

  <div class="tarjeta">
    <h2>Revisar importación</h2>
    <p class="chico">Elegí otra vez todos los Word: la app los compara con lo cargado <b>sin cambiar nada</b> y te muestra qué archivos
      no están en la app y en qué fichas puede haber consultas que no se separaron.</p>
    <div class="acciones">
      <label class="btn">Elegir archivos para revisar…<input type="file" data-destino="revisar" accept=".docx,.doc,.odt" multiple hidden></label>
      <label class="btn">Elegir carpeta entera…<input type="file" data-destino="revisar" webkitdirectory multiple hidden></label>
    </div>
    <div id="revision" style="margin-top:12px"></div>
  </div>

  <div class="tarjeta">
    <h2>Encabezado de los PDF</h2>
    <p class="chico suave">Aparece arriba de las evoluciones que descargás o compartís en PDF.</p>
    <p class="pre" style="margin:0 0 12px">${esc(lineasEncabezado().join('\n'))}</p>
    <button class="btn" data-accion="editar-encabezado">Editar encabezado</button>
    <h3 style="margin-top:20px">Firma</h3>
    <p class="chico suave">Va arriba de la línea de firma en las evoluciones y resúmenes en PDF.
      Podés sacarle una foto a tu firma hecha en un papel blanco, o dibujarla con el dedo.</p>
    ${S.db.firma ? `<div class="firma-vista"><img src="${S.db.firma.datos}" alt="Tu firma"></div>
    <label class="casilla"><input type="checkbox" id="firma-sello" ${S.db.firma.conSello ? 'checked' : ''}>
      La imagen incluye el sello (nombre y matrícula): no repetirlos debajo de la firma</label>` : ''}
    <div class="acciones">
      <label class="btn">Subir foto de la firma<input type="file" id="foto-firma" accept="image/*" hidden></label>
      <button class="btn" data-accion="dibujar-firma">Dibujar firma</button>
      ${S.db.firma ? '<button class="btn peligro" data-accion="quitar-firma">Quitar firma</button>' : ''}
    </div>
    <p class="error-texto" id="firma-err"></p>
  </div>

  <div class="tarjeta">
    <h2>Seguridad</h2>
    <p class="chico suave">La app se bloquea sola después de ${CONFIG.minutosBloqueo} minutos sin uso.</p>
    <div class="acciones">
      <button class="btn" data-accion="cambiar-clave">Cambiar contraseña</button>
      <button class="btn peligro" data-accion="desconectar">${local ? 'Salir del modo prueba' : 'Desconectar este dispositivo de Dropbox'}</button>
    </div>
  </div>`}

  <div class="tarjeta">
    <h2>Resumen</h2>
    <p id="resumen-datos">${S.db.pacientes.length} pacientes · ${S.db.pacientes.reduce((n, p) => n + (p.evoluciones?.length || 0), 0)} evoluciones ·
      ${S.db.pacientes.reduce((n, p) => n + (p.estudios?.length || 0), 0)} estudios</p>
  </div>`;
  $('#firma-sello')?.addEventListener('change', e => { S.db.firma.conSello = e.target.checked; guardar(); });
  $('#foto-firma')?.addEventListener('change', async e => {
    const f = e.target.files[0];
    if (!f) return;
    try {
      const img = await createImageBitmap(f, { imageOrientation: 'from-image' });
      const c = document.createElement('canvas');
      const k = Math.min(1, 1600 / Math.max(img.width, img.height));
      c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
      c.getContext('2d').drawImage(img, 0, 0, c.width, c.height);
      const error = guardarFirma(c, true);
      if (error) $('#firma-err').textContent = error;
    } catch (err) { console.error(err); $('#firma-err').textContent = 'No se pudo leer la imagen.'; }
  });
  document.querySelectorAll('input[data-destino]').forEach(inp => inp.addEventListener('change', e => {
    const lista = [...e.target.files];
    e.target.value = ''; // permite volver a elegir los mismos archivos
    (inp.dataset.destino === 'importar' ? importarWord : revisarWord)(lista);
  }));
}

function descargarCopia() {
  cifrar(S.db).then(texto => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([texto], { type: 'application/octet-stream' }));
    a.download = 'historias-' + hoyISO() + '.hc';
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
}

function cambiarClave() {
  const dlg = $('#dlg'), form = $('#dlg-form');
  form.innerHTML = `<h2>Cambiar contraseña</h2>
    <label class="campo"><span>Contraseña actual</span><input type="password" name="actual" required autocomplete="current-password"></label>
    <label class="campo"><span>Contraseña nueva (mínimo 10 caracteres)</span><input type="password" name="p1" required minlength="10" autocomplete="new-password"></label>
    <label class="campo"><span>Repetir contraseña nueva</span><input type="password" name="p2" required autocomplete="new-password"></label>
    <p class="error-texto" id="dlg-err"></p>
    <div class="pie-dialogo"><button type="button" class="btn" data-dlg="cancelar">Cancelar</button><button type="submit" class="btn primario">Cambiar</button></div>`;
  form.onclick = ev => { if (ev.target.closest('[data-dlg=cancelar]')) dlg.close(); };
  form.onsubmit = async ev => {
    ev.preventDefault();
    const err = $('#dlg-err');
    const actual = form.elements.actual.value, p1 = form.elements.p1.value;
    if (p1 !== form.elements.p2.value) { err.textContent = 'Las contraseñas nuevas no coinciden.'; return; }
    try {
      await descifrar(await cifrar({ prueba: 1 }), actual);
    } catch { err.textContent = 'La contraseña actual no es correcta.'; return; }
    S.salt = crypto.getRandomValues(new Uint8Array(16));
    S.iter = ITERACIONES;
    S.clave = await derivarClave(p1, S.salt, S.iter);
    dlg.close();
    await guardar();
    alert(S.pendiente ? 'No se pudo guardar con la contraseña nueva. Revisá la conexión.' : 'Contraseña cambiada. Las copias diarias anteriores siguen abriéndose con la contraseña vieja.');
  };
  dlg.showModal();
}

// ---------- Importación de Word ----------
const ETIQUETAS_PERMITIDAS = new Set(['P', 'BR', 'STRONG', 'B', 'EM', 'I', 'U', 'UL', 'OL', 'LI', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TD', 'TH', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'SUP', 'SUB']);
function limpiarHTML(html) {
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const limpiar = nodo => {
    for (const hijo of [...nodo.childNodes]) {
      if (hijo.nodeType === 1) {
        limpiar(hijo);
        if (!ETIQUETAS_PERMITIDAS.has(hijo.tagName)) { hijo.replaceWith(...hijo.childNodes); continue; }
        for (const a of [...hijo.attributes]) if (!(/^(colspan|rowspan)$/i.test(a.name) && /^\d+$/.test(a.value))) hijo.removeAttribute(a.name);
      } else if (hijo.nodeType !== 3) hijo.remove();
    }
  };
  limpiar(doc.body);
  return doc.body.innerHTML;
}

function fechaDesdeTexto(d, m, a) {
  a = parseInt(a, 10); if (a < 100) a += a <= (new Date().getFullYear() % 100) ? 2000 : 1900;
  d = parseInt(d, 10); m = parseInt(m, 10);
  if (!(d >= 1 && d <= 31 && m >= 1 && m <= 12)) return '';
  return `${a}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}

// Las historias en Word tienen nombre, fecha de nacimiento y obra social; el resto queda en la historia importada.
// Una etiqueta cuenta solo si va seguida de «:» o «-», o si está sola en su renglón (celda de tabla):
// así «Paciente de 63 años» no se toma como nombre.
const ETQ_NOMBRE = /^(?:apellido\s*y\s*nombres?|nombre\s*y\s*apellidos?|paciente|nombres?)(?:\s*[:\-–]\s*(.*)|\s*)$/i;
// (No se usa \b porque en JavaScript la «ñ» no cuenta como letra: «años» terminaría en la etiqueta «os».)
const ETQ_NAC = /(?:^|[\s,;(])(?:fecha\s*de\s*nac(?:imiento)?|f\.?\s*(?:de\s*)?nac\.?|f\.?\s*n\.?)\s*[:.\-–]?\s*(\d.*|)$/i;
const ETQ_OS = /^(?:obra\s*social|o\.?\s?s\.?|prepaga|cobertura)\s*[:\-–]?\s*$|(?:^|[\s,;])(?:obra\s*social|o\.?\s?s\.?|prepaga|cobertura)\s*[:\-–]\s*(.*)$/i;
const CORTE = /[\s\-–,]+(?:edad\b|fecha\s*de\s*nac|f\.?\s*(?:de\s*)?nac|f\.?\s*n\.?\s*[:\-]|obra\s*social|o\.?\s?s\.?\s*[:\-]|prepaga|dni\b|d\.n\.i).*$/i;
const FECHA = /(\d{1,2})\s*[\/\-.]\s*(\d{1,2})\s*[\/\-.]\s*(\d{2,4})/;

function extraerDatos(texto) {
  const lineas = texto.split(/\n/).map(l => l.trim()).filter(Boolean);
  const cabecera = lineas.slice(0, 8);
  // Busca «Etiqueta: valor»; si el valor está en la línea siguiente (celdas de una tabla), lo toma de ahí.
  const buscar = (re, lista = lineas) => {
    for (let i = 0; i < lista.length; i++) {
      const m = lista[i].match(re);
      if (m) return (m[1] || '').trim() || (lista[i + 1] || '');
    }
    return '';
  };
  const d = {};

  let nombre = buscar(ETQ_NOMBRE, cabecera).replace(CORTE, '').trim();
  // Sin etiqueta: la primera línea de la cabecera sin números se toma como nombre.
  if (!nombre) nombre = cabecera.map(l => l.replace(CORTE, '').trim()).find(l => l && !/\d/.test(l) && l.length <= 60 && !ETQ_OS.test(l) && !/historia/i.test(l)) || '';
  nombre = nombre.replace(/[:.\s]+$/, '');
  if (nombre) {
    const partes = nombre.split(/\s*,\s*/);
    if (partes.length >= 2) { d.apellido = partes[0]; d.nombre = partes.slice(1).join(' '); } else d.apellido = nombre;
  }

  let m = buscar(ETQ_NAC, cabecera).match(FECHA);
  // Sin etiqueta: una fecha en los primeros renglones, salvo que la siga un texto largo
  // (en ese caso es la fecha de la primera consulta, no la de nacimiento).
  if (!m) {
    const i = cabecera.slice(0, 3).findIndex(l => FECHA.test(l));
    if (i >= 0 && (cabecera[i + 1] || '').length <= 40) m = cabecera[i].match(FECHA);
  }
  if (m) d.fechaNac = fechaDesdeTexto(m[1], m[2], m[3]);

  // Fecha de la última consulta: el renglón más reciente que es solo una fecha (como «17/5/2014»).
  const consultas = lineas.map(l => l.match(/^(\d{1,2})\s*[\/\-.]\s*(\d{1,2})\s*[\/\-.]\s*(\d{2,4})\s*[:\-–]?$/))
    .filter(Boolean).map(f => fechaDesdeTexto(f[1], f[2], f[3])).filter(f => f && f !== d.fechaNac && f <= hoyISO());
  if (consultas.length) d.ultimaConsultaImportada = consultas.sort().pop();

  const os = buscar(ETQ_OS, cabecera).replace(CORTE, '').trim();
  // «SWISS: 80000672996» → obra social «SWISS» y N° de afiliado aparte.
  // Hace falta «:», «N°»/«Nro» antes del número, o un número largo (así «OSDE 210» o «plan 2000» quedan enteros).
  const conAfiliado = os.match(/^(.*?\S)\s*(?:[:\-–]|\s(?:n[°º]|nro\.?|afiliado:?))\s*(\d[\d\s\-\/]{3,})$/i) || os.match(/^(.*?\S)\s+(\d{6,})$/);
  if (conAfiliado) { d.obraSocial = conAfiliado[1].trim(); d.nroAfiliado = conAfiliado[2].replace(/\s+/g, ''); }
  else if (os) d.obraSocial = os;

  for (const k of Object.keys(d)) if (!d[k]) delete d[k];
  return d;
}

// Corta la historia en consultas: cada renglón que es solo una fecha («25/4/2014», «19/5») abre una consulta nueva.
// Una fecha sin año toma el de la consulta anterior. «MC:», «Diagnóstico:» y «Conducta:» van a su campo.
const RENGLON_FECHA = /^(\d{1,2})\s*[\/\-.]\s*(\d{1,2})(?:\s*[\/\-.]\s*(\d{2,4}))?\s*[:\-–.]?$/;
const CAMPOS_CONSULTA = [
  ['motivo', /^(?:mc|m\.c\.|motivo(?:\s+de\s+consulta)?)\s*[:\-–]\s*(.+)$/i],
  ['diagnostico', /^(?:impresi[oó]n\s+diagn[oó]stica|diagn[oó]sticos?|dx|id)\s*[:\-–]\s*(.+)$/i],
  ['conducta', /^conducta\s*[:\-–]\s*(.+)$/i],
];
function extraerConsultas(texto) {
  const consultas = [];
  let actual = null, anio = null;
  for (const linea of texto.split('\n').map(l => l.trim())) {
    const m = linea.match(RENGLON_FECHA);
    if (m && (m[3] || anio)) {
      const fecha = fechaDesdeTexto(m[1], m[2], m[3] || anio);
      if (fecha) {
        anio = fecha.slice(0, 4);
        actual = { fecha, lineas: [] };
        consultas.push(actual);
        continue;
      }
    }
    if (actual) actual.lineas.push(linea);
  }
  return consultas.map(c => {
    const ev = { id: nuevoId(), fecha: c.fecha, importada: true };
    const resto = [];
    for (const l of c.lineas) {
      const campo = CAMPOS_CONSULTA.find(([k, re]) => !ev[k] && re.test(l));
      if (campo) ev[campo[0]] = l.match(campo[1])[1].trim();
      else resto.push(l);
    }
    ev.texto = resto.filter(Boolean).join('\n'); // mammoth separa los párrafos con renglones vacíos
    return ev;
  }).filter(ev => ev.texto || ev.motivo || ev.diagnostico || ev.conducta);
}

// .docx con mammoth (conserva negritas y tablas); .doc (Word 97-2003) con word-extractor, solo texto.
// Un .odt (LibreOffice / OpenOffice) es un zip: se busca content.xml en el índice del zip y se descomprime.
async function archivoDeZip(buf, nombre) {
  const dv = new DataView(buf);
  let fin = -1;
  for (let i = buf.byteLength - 22; i >= Math.max(0, buf.byteLength - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { fin = i; break; }
  if (fin < 0) throw new Error('no es un zip');
  let p = dv.getUint32(fin + 16, true);
  for (let k = dv.getUint16(fin + 10, true); k > 0 && dv.getUint32(p, true) === 0x02014b50; k--) {
    const largoNombre = dv.getUint16(p + 28, true);
    if (td.decode(new Uint8Array(buf, p + 46, largoNombre)) === nombre) {
      const metodo = dv.getUint16(p + 10, true), tam = dv.getUint32(p + 20, true), local = dv.getUint32(p + 42, true);
      const ini = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
      const datos = new Uint8Array(buf, ini, tam);
      if (metodo === 0) return td.decode(datos);
      return new Response(new Blob([datos]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).text();
    }
    p += 46 + largoNombre + dv.getUint16(p + 30, true) + dv.getUint16(p + 32, true);
  }
  throw new Error('falta ' + nombre);
}
// Texto de content.xml: un renglón por párrafo; cada fila de tabla en un renglón.
function textoOdt(xml) {
  const TXT = 'urn:oasis:names:tc:opendocument:xmlns:text:1.0';
  const doc = new DOMParser().parseFromString(xml, 'application/xml');
  const IGNORAR = new Set(['annotation', 'note', 'tracked-changes', 'sequence-decls']);
  const enLinea = nodo => {
    let t = '';
    for (const h of nodo.childNodes) {
      if (h.nodeType === 3) t += h.nodeValue;
      else if (h.nodeType !== 1 || IGNORAR.has(h.localName)) continue;
      else if (h.localName === 's') t += ' '.repeat(+(h.getAttributeNS(TXT, 'c') || 1));
      else if (h.localName === 'tab') t += '  ';
      else if (h.localName === 'line-break') t += '\n';
      else t += enLinea(h);
    }
    return t;
  };
  const lineas = [];
  const recorrer = nodo => {
    for (const h of nodo.children) {
      if (IGNORAR.has(h.localName)) continue;
      if (h.localName === 'p' || h.localName === 'h') lineas.push(...enLinea(h).split('\n'));
      else if (h.localName === 'table-row') {
        lineas.push([...h.children].filter(c => c.localName === 'table-cell')
          .map(c => [...c.getElementsByTagNameNS(TXT, 'p')].map(enLinea).join(' ').trim()).filter(Boolean).join('  '));
      } else recorrer(h);
    }
  };
  recorrer(doc.documentElement);
  return lineas.join('\n');
}

async function leerWord(f) {
  const buf = await f.arrayBuffer();
  const firma = new Uint8Array(buf.slice(0, 2));
  if (firma[0] === 0xd0 && firma[1] === 0xcf) {
    const { cuerpo, encabezados } = await window.leerDoc(buf);
    const texto = [encabezados, cuerpo].filter(t => t && t.trim()).join('\n').replace(/\t+/g, '  ');
    const html = texto.split('\n').map(l => l.trim() ? `<p>${esc(l)}</p>` : '').join('');
    return { html, texto };
  }
  if (/\.odt$/i.test(f.name)) {
    const texto = textoOdt(await archivoDeZip(buf, 'content.xml'));
    const html = texto.split('\n').map(l => l.trim() ? `<p>${esc(l)}</p>` : '').join('');
    return { html, texto };
  }
  const opciones = { convertImage: mammoth.images.imgElement(() => ({ src: '' })) };
  const [{ value: html }, { value: texto }] = await Promise.all([
    mammoth.convertToHtml({ arrayBuffer: buf }, opciones),
    mammoth.extractRawText({ arrayBuffer: buf }),
  ]);
  return { html, texto };
}

const numeroDe = f => f.name.replace(/\.(docx?|odt)$/i, '').trim();

// Separa los Word de lo demás que venga en la selección (temporales «~$…» de Word, PDF, imágenes…).
// La carpeta entera incluye las subcarpetas; ahí el nombre lleva la ruta.
function separarArchivos(lista) {
  let word = [];
  const temporales = [], otros = [];
  for (const f of lista) {
    if (/^~\$/.test(f.name) || /^\./.test(f.name)) temporales.push(f);
    else if (/\.(docx?|odt)$/i.test(f.name)) word.push(f);
    else otros.push(f);
  }
  // Una misma historia guardada en varios formatos (.doc, .docx, .odt): se usa la modificada más recientemente.
  const totalWord = word.length;
  const grupos = new Map();
  for (const f of word) { const n = numeroDe(f); grupos.set(n, [...(grupos.get(n) || []), f]); }
  const repetidas = [...grupos.values()].filter(g => g.length > 1).map(g => g.sort((a, b) => b.lastModified - a.lastModified));
  word = [...grupos.values()].map(g => g[0]);
  word.sort((a, b) => a.name.localeCompare(b.name, 'es', { numeric: true }));
  const ruta = f => f.webkitRelativePath || f.name;
  const fechaArchivo = f => new Date(f.lastModified).toLocaleDateString('es-AR');
  const porExt = {};
  for (const f of otros) { const e = (f.name.match(/\.[^.]+$/) || ['sin extensión'])[0].toLowerCase(); porExt[e] = (porExt[e] || 0) + 1; }
  const resumen = `<p class="chico">Recibidos <b>${lista.length}</b> archivos: <b>${totalWord}</b> de Word${repetidas.length ? ` (${word.length} historias distintas)` : ''}`
    + (temporales.length ? `, ${temporales.length} temporales u ocultos (ignorados)` : '')
    + (otros.length ? `, ${otros.length} de otro tipo (ignorados: ${Object.entries(porExt).map(([e, n]) => `${esc(e)} ×${n}`).join(', ')})` : '') + '.</p>'
    + (otros.length ? `<details><summary class="chico">Ver archivos ignorados</summary><ul class="chico">${otros.map(f => `<li>${esc(ruta(f))}</li>`).join('')}</ul></details>` : '')
    + (repetidas.length ? `<details><summary class="chico">${repetidas.length} historias están guardadas en más de un formato: se usa la versión modificada más recientemente</summary>
      <ul class="chico">${repetidas.map(g => `<li><b>${esc(g[0].name)}</b> (${fechaArchivo(g[0])}); no se usa${g.length > 2 ? 'n' : ''}: ${g.slice(1).map(f => `${esc(f.name)} (${fechaArchivo(f)})`).join(', ')}</li>`).join('')}</ul></details>` : '');
  return { word, resumen };
}

// Renglón que empieza con una fecha completa seguida de texto: puede ser una consulta que no se separó.
const FECHA_CON_TEXTO = /^(\d{1,2})\s*[\/\-.]\s*(\d{1,2})\s*[\/\-.]\s*(\d{2,4})\s*[:\-–.,]?\s+\S/;

async function revisarWord(archivos) {
  const zona = $('#revision');
  const { word, resumen } = separarArchivos(archivos);
  archivos = word;
  if (!archivos.length) { zona.innerHTML = resumen; return; }
  zona.innerHTML = `<div class="progreso"><div></div></div><p class="chico suave" id="rev-estado"></p>`;
  const barra = $('.progreso > div', zona), estado = $('#rev-estado');
  const porNumero = new Map(S.db.pacientes.filter(p => p.numero).map(p => [String(p.numero), p]));
  const enlace = p => `<a href="#/p/${encodeURIComponent(p.id)}">${esc(p.numero)} · ${esc(nombreCompleto(p))}</a>`;
  const faltan = [], desactualizadas = [], ilegibles = [], sinConsultas = [], dudosas = [];
  for (let i = 0; i < archivos.length; i++) {
    const f = archivos[i];
    estado.textContent = `Revisando ${i + 1} de ${archivos.length}: ${f.name}`;
    barra.style.width = ((i + 1) / archivos.length * 100) + '%';
    const numero = numeroDe(f);
    const p = porNumero.get(numero);
    let texto;
    try { texto = (await leerWord(f)).texto; } catch { ilegibles.push(f.name); continue; }
    if (!p) { faltan.push(f.name); continue; }
    if (p.importado?.archivo && p.importado.archivo !== f.name) desactualizadas.push(enlace(p) + ` <span class="suave">(en la app: ${esc(p.importado.archivo)}; más nuevo: ${esc(f.name)})</span>`);
    const lineas = texto.split('\n').map(l => l.trim()).filter(Boolean);
    // No cuenta las listas de resultados («ETT:» / «11/2013: …» / «29/4/2014: …»).
    const sospechosas = lineas.filter((l, j) => FECHA_CON_TEXTO.test(l) && !/:\s*$/.test(lineas[j - 1] || '') && !/^\d{1,2}\s*[\/\-.]\s*\d{1,4}/.test(lineas[j - 1] || ''));
    if (sospechosas.length) dudosas.push({ p, ejemplo: sospechosas[0], n: sospechosas.length });
    else if (!extraerConsultas(texto).length) sinConsultas.push(p);
    if (i % 10 === 9) await new Promise(r => setTimeout(r));
  }
  const bloque = (titulo, ayuda, items) => items.length ? `<details><summary>${titulo}: ${items.length}</summary>
    <p class="chico suave">${ayuda}</p><ul class="chico">${items.map(x => `<li>${x}</li>`).join('')}</ul></details>` : '';
  const todoBien = !faltan.length && !desactualizadas.length && !ilegibles.length && !sinConsultas.length && !dudosas.length;
  zona.innerHTML = resumen + `<p><b>Revisados ${archivos.length} archivos de Word.</b> ${todoBien ? 'No se encontraron problemas.' : ''}</p>
    ${bloque('No están en la app', 'Estos archivos no se importaron. Probá importarlos de nuevo.', faltan.map(esc))}
    ${bloque('No se pudieron leer', 'Pueden estar dañados o protegidos con contraseña. Abrilos en Word y guardalos de nuevo.', ilegibles.map(esc))}
    ${bloque('Con una versión más nueva sin importar', 'La historia está en más de un formato y en la app quedó una versión más vieja. Importá la carpeta entera otra vez para actualizarlas.', desactualizadas)}
    ${bloque('Fechas pegadas al texto', 'Estas fichas tienen renglones que empiezan con una fecha seguida de texto: puede ser una consulta que no se separó. Se muestra el primero.',
      dudosas.map(d => `${enlace(d.p)}<br><span class="suave">«${esc(d.ejemplo.slice(0, 90))}»${d.n > 1 ? ` y ${d.n - 1} más` : ''}</span>`))}
    ${bloque('Sin ninguna consulta separada', 'El Word no tiene fechas solas en un renglón. La historia está completa en «Historia original completa».', sinConsultas.map(enlace))}`;
}

async function importarWord(archivos) {
  const zona = $('#importacion');
  const { word, resumen } = separarArchivos(archivos);
  archivos = word;
  if (!archivos.length) { zona.innerHTML = resumen; return; }
  if (!window.mammoth || !window.leerDoc) { zona.innerHTML = '<p class="error-texto">No se cargó el lector de Word. Recargá la página.</p>'; return; }
  zona.innerHTML = `<div class="progreso"><div></div></div><p class="chico suave" id="imp-estado"></p>`;
  const barra = $('.progreso > div', zona), estado = $('#imp-estado');
  let nuevos = 0, actualizados = 0, evoluciones = 0;
  const errores = [];
  const porNumero = new Map(S.db.pacientes.filter(p => p.numero).map(p => [String(p.numero), p]));
  for (let i = 0; i < archivos.length; i++) {
    const f = archivos[i];
    estado.textContent = `Leyendo ${i + 1} de ${archivos.length}: ${f.name}`;
    barra.style.width = ((i + 1) / archivos.length * 100) + '%';
    try {
      const { html, texto } = await leerWord(f);
      const numero = numeroDe(f);
      const datos = extraerDatos(texto);
      const consultas = extraerConsultas(texto);
      evoluciones += consultas.length;
      const importado = { archivo: f.name, fecha: new Date().toISOString() };
      const existente = porNumero.get(numero);
      if (existente) {
        existente.historiaImportada = limpiarHTML(html);
        existente.importado = importado;
        textoImportado.delete(existente);
        for (const [k, v] of Object.entries(datos)) if (!existente[k] || k === 'ultimaConsultaImportada') existente[k] = v;
        // Se reemplazan las consultas que vinieron del Word; las cargadas en la app quedan como están.
        existente.evoluciones = (existente.evoluciones || []).filter(e => !e.importada).concat(consultas);
        actualizados++;
      } else {
        const p = Object.assign({ id: nuevoId(), creado: new Date().toISOString(), numero, evoluciones: consultas, estudios: [] },
          datos, { historiaImportada: limpiarHTML(html), importado });
        S.db.pacientes.push(p);
        porNumero.set(numero, p);
        nuevos++;
      }
    } catch (e) {
      console.error(e);
      errores.push(f.name + ': no se pudo leer (¿archivo dañado o protegido con contraseña?)');
    }
    if (i % 10 === 9) await new Promise(r => setTimeout(r));
  }
  estado.textContent = 'Guardando…';
  if (nuevos || actualizados) await guardar();
  const datos = $('#resumen-datos');
  if (datos) datos.textContent = `${S.db.pacientes.length} pacientes · ${S.db.pacientes.reduce((n, p) => n + (p.evoluciones?.length || 0), 0)} evoluciones · ${S.db.pacientes.reduce((n, p) => n + (p.estudios?.length || 0), 0)} estudios`;
  zona.innerHTML = resumen + `<p><b>Listo.</b> ${nuevos} pacientes nuevos, ${actualizados} actualizados, ${evoluciones} consultas separadas${errores.length ? `, ${errores.length} con problemas` : ''}.</p>
    ${errores.length ? `<details><summary>Ver archivos con problemas</summary><ul class="chico">${errores.map(e => `<li>${esc(e)}</li>`).join('')}</ul></details>` : ''}
    ${S.pendiente ? '<p class="error-texto">Ojo: no se pudo guardar en Dropbox. Revisá el aviso de arriba.</p>' : ''}
    <p class="chico suave">Revisá algunas fichas: los datos que no se reconocieron automáticamente (nombre, fecha de nacimiento u obra social) se pueden completar con «Editar datos».</p>`;
}

// ---------- Acciones ----------
document.addEventListener('click', ev => {
  const b = ev.target.closest('[data-accion]');
  if (!b) return;
  const { id, reg, tipo } = b.dataset;
  switch (b.dataset.accion) {
    case 'modo-prueba': pref.set('modo', 'local'); pantallaClave(); break;
    case 'bloquear': bloquear(); break;
    case 'reintentar': aviso(''); guardar(); break;
    case 'nuevo-paciente': editarPaciente(null); break;
    case 'editar-paciente': editarPaciente(id); break;
    case 'editar-resumen': editarResumenClinico(id); break;
    case 'nueva-evolucion': editarRegistro(id, 'evoluciones'); break;
    case 'editar-evolucion': editarRegistro(id, 'evoluciones', reg); break;
    case 'nuevo-estudio': editarRegistro(id, 'estudios'); break;
    case 'editar-estudio': editarRegistro(id, 'estudios', reg); break;
    case 'filtro-estudio': filtroEstudio[id] = tipo; mostrar(); break;
    case 'imprimir': print(); break;
    case 'pdf-evolucion': pdfEvolucion(paciente(id), (paciente(id).evoluciones || []).find(e => e.id === reg), b); break;
    case 'editar-encabezado': editarEncabezado(); break;
    case 'dibujar-firma': dibujarFirma(); break;
    case 'quitar-firma': if (confirm('¿Quitar la firma de los PDF?')) { delete S.db.firma; guardar(); mostrar(); } break;
    case 'resumen-pdf': dialogoResumen(paciente(id)); break;
    case 'adjuntar': editarAdjunto(id); break;
    case 'editar-adjunto': editarAdjunto(id, reg); break;
    case 'ver-adjunto': verAdjunto(id, reg); break;
    case 'cerrar-visor': cerrarVisor(); break;
    case 'descargar-copia': descargarCopia(); break;
    case 'cambiar-clave': cambiarClave(); break;
    case 'borrar-paciente': borrarPaciente(paciente(id)); break;
    case 'desconectar':
      if (confirm('¿Desconectar este dispositivo? Los datos en Dropbox no se borran; para volver a entrar tendrás que conectar Dropbox de nuevo.')) {
        colaGuardado.then(() => {
          ['modo', 'dbxRefresh', 'ultimoBackup'].forEach(k => pref.set(k, null));
          idb.set('cache', null).finally(() => location.replace(location.pathname));
        });
      }
      break;
  }
});

addEventListener('beforeprint', () => document.querySelectorAll('details').forEach(d => { d.dataset.cerrado = d.open ? '' : '1'; d.open = true; }));
addEventListener('afterprint', () => document.querySelectorAll('details[data-cerrado="1"]').forEach(d => { d.open = false; }));
addEventListener('beforeunload', ev => { if (S.pendiente) { ev.preventDefault(); ev.returnValue = ''; } });

// ---------- Inicio ----------
(async function iniciar() {
  const params = new URLSearchParams(location.search);
  if (params.get('code')) {
    history.replaceState(null, '', location.pathname);
    try {
      await DBX.completar(params.get('code'));
      pref.set('modo', 'dropbox');
    } catch (e) { return pantallaInicio(e.message); }
  } else if (params.get('error')) {
    history.replaceState(null, '', location.pathname);
    return pantallaInicio('No se autorizó el acceso a Dropbox.');
  }
  if (!window.crypto?.subtle) {
    $('#app').innerHTML = '<div class="centro tarjeta"><p class="error-texto">Este navegador no permite cifrar los datos. Abrí la app desde su dirección https.</p></div>';
    return;
  }
  const modo = Almacen.modo();
  if (modo === 'local' || (modo === 'dropbox' && DBX.conectado())) pantallaClave();
  else pantallaInicio();
})();
