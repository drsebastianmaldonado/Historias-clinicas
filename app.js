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
  async descargar(ruta) {
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
    return { texto: await r.text(), rev: meta.rev };
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

// ---------- Estado ----------
const S = { clave: null, salt: null, iter: ITERACIONES, db: null, rev: null, soloLectura: false, pendiente: false };
let colaGuardado = Promise.resolve();

function estadoGuardado(texto, error) {
  const el = $('#estado-guardado');
  el.textContent = texto;
  el.classList.toggle('error', !!error);
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
  estadoGuardado('Guardando…');
  colaGuardado = colaGuardado.then(async () => {
    try {
      await Almacen.escribir(await cifrar(S.db));
      S.pendiente = false;
      estadoGuardado('Guardado ' + new Date().toLocaleTimeString('es-AR', { hour: '2-digit', minute: '2-digit' }));
    } catch (e) {
      console.error(e);
      if (e instanceof ConflictoError) {
        estadoGuardado('No guardado', true);
        aviso('Los datos se modificaron desde otro dispositivo. <b>Recargá la página</b> para ver la versión más nueva (el último cambio que hiciste acá no se guardó).');
      } else {
        estadoGuardado('Error al guardar', true);
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
  { k: 'texto', t: 'Evolución / examen físico', tipo: 'area', ancho: true },
  { k: 'diagnostico', t: 'Diagnóstico', ancho: true },
  { k: 'conducta', t: 'Conducta', tipo: 'area', ancho: true },
];
const CAMPOS_ESTUDIO = [
  { k: 'tipo', t: 'Estudio', tipo: 'select', ops: TIPOS_ESTUDIO, req: true },
  { k: 'fecha', t: 'Fecha', tipo: 'date' },
  { k: 'detalle', t: 'Especificar (si es «Otro»)' },
  { k: 'resultado', t: 'Resultado / informe', tipo: 'area', ancho: true },
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
  estadoGuardado(S.db.modificado ? 'Última modificación: ' + new Date(S.db.modificado).toLocaleString('es-AR', { dateStyle: 'short', timeStyle: 'short' }) : '');
  iniciarBloqueo();
  window.addEventListener('hashchange', mostrar);
  mostrar();
}

function bloquear() {
  if (S.pendiente) {
    estadoGuardado('Guardando antes de bloquear…');
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
    <input type="search" id="q" placeholder="Buscar por apellido, nombre, N°, DNI, obra social o diagnóstico…" value="${esc(busqueda)}" autocomplete="off">
    <select id="orden" aria-label="Ordenar">
      <option value="apellido">Por apellido</option>
      <option value="numero">Por N° de historia</option>
      <option value="reciente">Consulta más reciente</option>
    </select>
    ${ro ? '' : `<button class="btn primario" data-accion="nuevo-paciente">+ Paciente nuevo</button>`}
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
    ...(p.evoluciones || []).flatMap(e => [e.motivo, e.texto, e.conducta]),
    ...(p.estudios || []).flatMap(e => [e.tipo, e.detalle, e.resultado])].join(' ')) + ' ' + (textoImportado.get(p) || '');
}

function filaPaciente(p) {
  const ult = ultimaFecha(p);
  const det = [p.fechaNac ? edad(p.fechaNac) : '', p.obraSocial, p.dni ? 'DNI ' + p.dni : ''].filter(Boolean).join(' · ');
  return `<li><a href="#/p/${encodeURIComponent(p.id)}">
    <span class="num">${esc(p.numero || '—')}</span>
    <span class="nom">${esc(nombreCompleto(p))}</span>
    <span class="fec">${ult ? 'Últ. consulta ' + fechaLeg(ult) : ''}</span>
    ${det ? `<span class="det">${esc(det)}</span>` : ''}
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
  const dato = (t, v) => v ? `<div><dt>${t}</dt><dd>${esc(v)}</dd></div>` : '';
  const texto = (t, v) => `<div class="tarjeta"><h2>${t}</h2>${v ? `<div class="pre">${esc(v)}</div>` : '<p class="vacio">Sin datos.</p>'}</div>`;
  const evol = [...(p.evoluciones || [])].sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  const filtro = filtroEstudio[id] || '';
  const todosEst = [...(p.estudios || [])].sort((a, b) => (b.fecha || '').localeCompare(a.fecha || ''));
  const tiposPresentes = TIPOS_ESTUDIO.filter(t => todosEst.some(e => e.tipo === t));
  const est = filtro ? todosEst.filter(e => e.tipo === filtro) : todosEst;

  $('#app').innerHTML = `
  <p class="no-imprimir"><a href="#/">← Volver a la lista</a></p>
  <div class="tarjeta">
    <div class="ficha-cab">
      <div>
        <h1>${esc(nombreCompleto(p))}</h1>
        <div class="suave">${p.numero ? 'Historia N° ' + esc(p.numero) : ''}${p.fechaNac ? ' · ' + esc(edad(p.fechaNac)) + ' (nac. ' + fechaLeg(p.fechaNac) + ')' : ''}</div>
      </div>
      <div class="acciones no-imprimir">
        ${ro ? '' : `<button class="btn chico" data-accion="editar-paciente" data-id="${esc(id)}">Editar datos</button>`}
        <button class="btn chico" data-accion="imprimir">Imprimir / PDF</button>
      </div>
    </div>
    <dl class="datos">
      ${dato('Sexo', p.sexo)}${dato('DNI', p.dni)}${dato('Obra social', p.obraSocial)}${dato('N° de afiliado', p.nroAfiliado)}
      ${dato('Teléfono', p.telefono)}${dato('Madre / padre / tutor', p.responsable)}${dato('Email', p.email)}
    </dl>
    ${p.alergias ? `<div class="alergia">Alergias: ${esc(p.alergias)}</div>` : ''}
  </div>

  <div class="bloques">
    ${texto('Medicación actual', p.medicacion)}
    ${texto('Antecedentes personales', p.antPersonales)}
    ${texto('Antecedentes familiares', p.antFamiliares)}
  </div>

  <div class="tarjeta">
    <div class="cabecera-seccion"><h2>Evoluciones</h2>
      ${ro ? '' : `<button class="btn primario chico" data-accion="nueva-evolucion" data-id="${esc(id)}">+ Evolución</button>`}</div>
    ${evol.length ? evol.map(e => `
      <div class="registro">
        <div class="registro-cab"><h3>${fechaLeg(e.fecha)}${e.motivo ? ' — ' + esc(e.motivo) : ''}${e.importada ? ' <span class="etiqueta" title="Consulta traída de la historia en Word">Word</span>' : ''}</h3>
          ${ro ? '' : `<button class="btn chico no-imprimir" data-accion="editar-evolucion" data-id="${esc(id)}" data-reg="${esc(e.id)}">Editar</button>`}</div>
        <dl>
          ${e.peso || e.talla ? `<dt>Peso / talla</dt><dd>${esc([e.peso && e.peso + ' kg', e.talla && e.talla + ' cm'].filter(Boolean).join(' · '))}</dd>` : ''}
          ${e.texto ? `<dt>Evolución</dt><dd>${esc(e.texto)}</dd>` : ''}
          ${e.diagnostico ? `<dt>Diagnóstico</dt><dd>${esc(e.diagnostico)}</dd>` : ''}
          ${e.conducta ? `<dt>Conducta</dt><dd>${esc(e.conducta)}</dd>` : ''}
        </dl>
      </div>`).join('') : '<p class="vacio">Sin evoluciones cargadas.</p>'}
  </div>

  <div class="tarjeta">
    <div class="cabecera-seccion"><h2>Estudios complementarios</h2>
      ${ro ? '' : `<button class="btn primario chico" data-accion="nuevo-estudio" data-id="${esc(id)}">+ Estudio</button>`}</div>
    ${tiposPresentes.length > 1 ? `<div class="filtros">
      <button data-accion="filtro-estudio" data-id="${esc(id)}" data-tipo="" class="${filtro ? '' : 'activo'}">Todos</button>
      ${tiposPresentes.map(t => `<button data-accion="filtro-estudio" data-id="${esc(id)}" data-tipo="${esc(t)}" class="${filtro === t ? 'activo' : ''}">${esc(t)}</button>`).join('')}
    </div>` : ''}
    ${est.length ? est.map(e => `
      <div class="registro">
        <div class="registro-cab"><div><span class="etiqueta">${esc(e.tipo === 'Otro' && e.detalle ? e.detalle : e.tipo)}</span> <span class="suave">${fechaLeg(e.fecha)}</span></div>
          ${ro ? '' : `<button class="btn chico no-imprimir" data-accion="editar-estudio" data-id="${esc(id)}" data-reg="${esc(e.id)}">Editar</button>`}</div>
        ${e.resultado ? `<div class="pre" style="margin-top:6px">${esc(e.resultado)}</div>` : ''}
      </div>`).join('') : '<p class="vacio">Sin estudios cargados.</p>'}
  </div>

  ${p.historiaImportada ? `
  <div class="tarjeta">
    <details ${p.evoluciones?.length ? '' : 'open'}>
      <summary>Historia original completa (Word${p.importado?.archivo ? ': ' + esc(p.importado.archivo) : ''})</summary>
      <div class="importada" style="margin-top:10px">${limpiarHTML(p.historiaImportada)}</div>
    </details>
  </div>` : ''}

  ${ro ? '' : `<p class="no-imprimir chico suave" style="text-align:right">
    <button class="btn chico peligro" data-accion="borrar-paciente" data-id="${esc(id)}">Eliminar paciente</button></p>`}`;
  scrollTo(0, 0);
}

// ---------- Formularios ----------
function campoHTML(c, v) {
  const val = esc(v ?? '');
  const req = c.req ? ' required' : '';
  let input;
  if (c.tipo === 'area') input = `<textarea name="${c.k}"${req}>${val}</textarea>`;
  else if (c.tipo === 'select') input = `<select name="${c.k}"${req}>${c.ops.map(o => `<option${o === (v ?? '') ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
  else input = `<input name="${c.k}" type="${c.tipo || 'text'}" value="${val}"${req} autocomplete="off">`;
  return `<label class="campo${c.tipo === 'area' || c.ancho ? ' ancho' : ''}"><span>${c.t}${c.req ? ' *' : ''}</span>${input}</label>`;
}

function formulario({ titulo, campos, valores = {}, onGuardar, onBorrar, textoBorrar = 'Eliminar' }) {
  const dlg = $('#dlg'), form = $('#dlg-form');
  form.innerHTML = `<h2>${esc(titulo)}</h2>
    <div class="rejilla">${campos.map(c => campoHTML(c, valores[c.k])).join('')}</div>
    <p class="error-texto" id="dlg-err"></p>
    <div class="pie-dialogo">
      ${onBorrar ? `<button type="button" class="btn peligro izq" data-dlg="borrar">${esc(textoBorrar)}</button>` : ''}
      <button type="button" class="btn" data-dlg="cancelar">Cancelar</button>
      <button type="submit" class="btn primario">Guardar</button>
    </div>`;
  const cerrar = () => { dlg.close(); form.onsubmit = null; form.onclick = null; };
  form.onclick = ev => {
    const b = ev.target.closest('[data-dlg]');
    if (!b) return;
    if (b.dataset.dlg === 'cancelar') cerrar();
    if (b.dataset.dlg === 'borrar' && onBorrar() !== false) cerrar();
  };
  form.onsubmit = ev => {
    ev.preventDefault();
    const datos = {};
    for (const c of campos) datos[c.k] = (form.elements[c.k].value || '').trim();
    const error = onGuardar(datos);
    if (error) { $('#dlg-err').textContent = error; return; }
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
function borrarPaciente(p) {
  const n = prompt(`Para eliminar a ${nombreCompleto(p)} con todas sus evoluciones y estudios, escribí ELIMINAR:`);
  if (!n || n.trim().toUpperCase() !== 'ELIMINAR') return false;
  S.db.pacientes = S.db.pacientes.filter(x => x !== p);
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
    valores: reg || { fecha: hoyISO(), tipo: filtroEstudio[id] || '' },
    onGuardar(d) {
      if (reg) Object.assign(reg, d, { modificado: new Date().toISOString() });
      else p[lista].push(Object.assign({ id: nuevoId(), creado: new Date().toISOString() }, d));
      guardar(); mostrar();
    },
    onBorrar: reg ? () => {
      if (!confirm('¿Eliminar este registro? No se puede deshacer.')) return false;
      p[lista] = p[lista].filter(r => r !== reg); guardar(); mostrar();
    } : null,
  });
}

// ---------- Ajustes ----------
function vistaAjustes() {
  document.title = 'Ajustes — Historias Clínicas';
  const local = Almacen.modo() === 'local';
  const ro = S.soloLectura;
  $('#app').innerHTML = `
  <p><a href="#/">← Volver a la lista</a></p>
  <div class="tarjeta">
    <h2>Datos y copias de seguridad</h2>
    ${local
      ? '<p>Modo prueba: los datos están solo en este navegador, <b>sin backup</b>.</p>'
      : `<p>Archivo principal: <b>${esc(DBX.ruta())}</b> en tu Dropbox.<br>
         Copia diaria en <b>${esc(DBX.carpeta())}/copias/</b>${pref.get('ultimoBackup') ? ' (última: ' + fechaLeg(pref.get('ultimoBackup')) + ')' : ''}.
         Además, Dropbox guarda el historial de versiones de cada archivo.</p>`}
    <p class="chico suave">Todos los archivos están cifrados con tu contraseña: sin ella no se pueden leer.</p>
    <div class="acciones">
      <button class="btn" data-accion="descargar-copia">Descargar copia cifrada a esta computadora</button>
    </div>
  </div>

  ${ro ? '' : `<div class="tarjeta">
    <h2>Importar historias de Word</h2>
    <p class="chico">Seleccioná los archivos de Word, <b>.doc</b> o <b>.docx</b> (podés elegir todos juntos). El nombre de cada archivo se toma como N° de historia
      y cada consulta con fecha pasa a ser una evolución; el Word completo queda en «Historia original completa». Si un N° ya existe, se actualiza lo que vino del Word sin tocar lo cargado en la app.</p>
    <label class="btn primario">Elegir archivos Word…<input type="file" id="archivos-word" accept=".docx,.doc" multiple hidden></label>
    <div id="importacion" style="margin-top:12px"></div>
  </div>

  <div class="tarjeta">
    <h2>Revisar importación</h2>
    <p class="chico">Elegí otra vez todos los Word: la app los compara con lo cargado <b>sin cambiar nada</b> y te muestra qué archivos
      no están en la app y en qué fichas puede haber consultas que no se separaron.</p>
    <label class="btn">Elegir archivos para revisar…<input type="file" id="archivos-revisar" accept=".docx,.doc" multiple hidden></label>
    <div id="revision" style="margin-top:12px"></div>
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
    <p>${S.db.pacientes.length} pacientes · ${S.db.pacientes.reduce((n, p) => n + (p.evoluciones?.length || 0), 0)} evoluciones ·
      ${S.db.pacientes.reduce((n, p) => n + (p.estudios?.length || 0), 0)} estudios</p>
  </div>`;
  const inp = $('#archivos-word');
  if (inp) inp.addEventListener('change', e => importarWord([...e.target.files]));
  const rev = $('#archivos-revisar');
  if (rev) rev.addEventListener('change', e => revisarWord([...e.target.files]));
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
async function leerWord(f) {
  const buf = await f.arrayBuffer();
  const firma = new Uint8Array(buf.slice(0, 2));
  if (firma[0] === 0xd0 && firma[1] === 0xcf) {
    const { cuerpo, encabezados } = await window.leerDoc(buf);
    const texto = [encabezados, cuerpo].filter(t => t && t.trim()).join('\n').replace(/\t+/g, '  ');
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

// Renglón que empieza con una fecha completa seguida de texto: puede ser una consulta que no se separó.
const FECHA_CON_TEXTO = /^(\d{1,2})\s*[\/\-.]\s*(\d{1,2})\s*[\/\-.]\s*(\d{2,4})\s*[:\-–.,]?\s+\S/;

async function revisarWord(archivos) {
  const zona = $('#revision');
  archivos = archivos.filter(f => !/^~\$/.test(f.name));
  if (!archivos.length) return;
  zona.innerHTML = `<div class="progreso"><div></div></div><p class="chico suave" id="rev-estado"></p>`;
  const barra = $('.progreso > div', zona), estado = $('#rev-estado');
  const porNumero = new Map(S.db.pacientes.filter(p => p.numero).map(p => [String(p.numero), p]));
  const vistos = new Map();
  const faltan = [], repetidos = [], ilegibles = [], sinConsultas = [], dudosas = [];
  archivos.sort((a, b) => a.name.localeCompare(b.name, 'es', { numeric: true }));
  for (let i = 0; i < archivos.length; i++) {
    const f = archivos[i];
    estado.textContent = `Revisando ${i + 1} de ${archivos.length}: ${f.name}`;
    barra.style.width = ((i + 1) / archivos.length * 100) + '%';
    const numero = f.name.replace(/\.docx?$/i, '').trim();
    if (vistos.has(numero)) repetidos.push(`${f.name} y ${vistos.get(numero)}`);
    vistos.set(numero, f.name);
    const p = porNumero.get(numero);
    let texto;
    try { texto = (await leerWord(f)).texto; } catch { ilegibles.push(f.name); continue; }
    if (!p) { faltan.push(f.name); continue; }
    const lineas = texto.split('\n').map(l => l.trim()).filter(Boolean);
    // No cuenta las listas de resultados («ETT:» / «11/2013: …» / «29/4/2014: …»).
    const sospechosas = lineas.filter((l, j) => FECHA_CON_TEXTO.test(l) && !/:\s*$/.test(lineas[j - 1] || '') && !/^\d{1,2}\s*[\/\-.]\s*\d{1,4}/.test(lineas[j - 1] || ''));
    if (sospechosas.length) dudosas.push({ p, ejemplo: sospechosas[0], n: sospechosas.length });
    else if (!extraerConsultas(texto).length) sinConsultas.push(p);
    if (i % 10 === 9) await new Promise(r => setTimeout(r));
  }
  const enlace = p => `<a href="#/p/${encodeURIComponent(p.id)}">${esc(p.numero)} · ${esc(nombreCompleto(p))}</a>`;
  const bloque = (titulo, ayuda, items) => items.length ? `<details><summary>${titulo}: ${items.length}</summary>
    <p class="chico suave">${ayuda}</p><ul class="chico">${items.map(x => `<li>${x}</li>`).join('')}</ul></details>` : '';
  const todoBien = !faltan.length && !repetidos.length && !ilegibles.length && !sinConsultas.length && !dudosas.length;
  zona.innerHTML = `<p><b>Revisados ${archivos.length} archivos.</b> ${todoBien ? 'No se encontraron problemas.' : ''}</p>
    ${bloque('No están en la app', 'Estos archivos no se importaron. Probá importarlos de nuevo.', faltan.map(esc))}
    ${bloque('No se pudieron leer', 'Pueden estar dañados o protegidos con contraseña. Abrilos en Word y guardalos de nuevo.', ilegibles.map(esc))}
    ${bloque('Archivos con el mismo número', 'Quedaron juntos en un solo paciente: el último importado reemplazó al otro.', repetidos.map(esc))}
    ${bloque('Fechas pegadas al texto', 'Estas fichas tienen renglones que empiezan con una fecha seguida de texto: puede ser una consulta que no se separó. Se muestra el primero.',
      dudosas.map(d => `${enlace(d.p)}<br><span class="suave">«${esc(d.ejemplo.slice(0, 90))}»${d.n > 1 ? ` y ${d.n - 1} más` : ''}</span>`))}
    ${bloque('Sin ninguna consulta separada', 'El Word no tiene fechas solas en un renglón. La historia está completa en «Historia original completa».', sinConsultas.map(enlace))}`;
}

async function importarWord(archivos) {
  const zona = $('#importacion');
  if (!archivos.length) return;
  if (!window.mammoth || !window.leerDoc) { zona.innerHTML = '<p class="error-texto">No se cargó el lector de Word. Recargá la página.</p>'; return; }
  zona.innerHTML = `<div class="progreso"><div></div></div><p class="chico suave" id="imp-estado"></p>`;
  const barra = $('.progreso > div', zona), estado = $('#imp-estado');
  let nuevos = 0, actualizados = 0, evoluciones = 0;
  const errores = [];
  const porNumero = new Map(S.db.pacientes.filter(p => p.numero).map(p => [String(p.numero), p]));
  archivos.sort((a, b) => a.name.localeCompare(b.name, 'es', { numeric: true }));
  for (let i = 0; i < archivos.length; i++) {
    const f = archivos[i];
    estado.textContent = `Leyendo ${i + 1} de ${archivos.length}: ${f.name}`;
    barra.style.width = ((i + 1) / archivos.length * 100) + '%';
    if (/^~\$/.test(f.name)) continue; // archivos temporales de Word
    if (!/\.docx?$/i.test(f.name)) { errores.push(f.name + ': no es un archivo de Word'); continue; }
    try {
      const { html, texto } = await leerWord(f);
      const numero = f.name.replace(/\.docx?$/i, '').trim();
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
  zona.innerHTML = `<p><b>Listo.</b> ${nuevos} pacientes nuevos, ${actualizados} actualizados, ${evoluciones} consultas separadas${errores.length ? `, ${errores.length} con problemas` : ''}.</p>
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
    case 'nueva-evolucion': editarRegistro(id, 'evoluciones'); break;
    case 'editar-evolucion': editarRegistro(id, 'evoluciones', reg); break;
    case 'nuevo-estudio': editarRegistro(id, 'estudios'); break;
    case 'editar-estudio': editarRegistro(id, 'estudios', reg); break;
    case 'filtro-estudio': filtroEstudio[id] = tipo; mostrar(); break;
    case 'imprimir': print(); break;
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
