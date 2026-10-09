/*
 * Interfaz de FirmaScope.
 *
 * No decide nada sobre la auditoria. Pinta el esquema que publica el nucleo,
 * envia las acciones de etapa y muestra lo que el nucleo concluye. Todo
 * criterio -- que opciones existen, que depende de que, que se valida, que se
 * concluye -- vive en Python, que es lo que esta cubierto por pruebas.
 *
 * El mismo esquema lo pinta el asistente de la CLI. Anadir una opcion en
 * `audit_core/options.py` la hace aparecer en las dos interfaces sin tocar
 * ninguna de las dos.
 */

'use strict';

/* ------------------------------------------------------------------ */
/* Transporte                                                          */
/* ------------------------------------------------------------------ */

/*
 * En Tauri se habla con el nucleo por `invoke`. En el panel (`firmascope
 * panel`) esta misma pagina la sirve el nucleo en 127.0.0.1 y se le habla por
 * HTTP, con el token que llega en el fragmento de la URL. Las pruebas inyectan
 * `window.firmascopeTransport` para ejercitar la interfaz en un navegador: es
 * una costura de prueba declarada, no un modo de produccion. Si no hay ninguno,
 * la interfaz lo dice en lugar de fingir que funciona.
 */
function resolveTransport() {
  if (window.firmascopeTransport) {
    return window.firmascopeTransport;
  }
  const invoke = window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke;
  if (invoke) {
    return {
      hello: () => invoke('core_hello'),
      call: (cmd, args) => invoke('core_call', { cmd: cmd, args: args || {} }),
      shutdown: () => invoke('core_shutdown'),
      pickFile: (title, extensions) =>
        invoke('pick_file', { title: title, extensions: extensions })
    };
  }
  return panelTransport();
}

/*
 * Transporte del panel. La URL que abre el navegador lleva un codigo de un
 * solo uso en el fragmento (`#code=...`): el fragmento no se envia al servidor
 * ni va en el Referer, pero la URL entera si aparece en la lista de procesos
 * del equipo mientras arranca el navegador. Por eso no es el token: se canjea
 * una vez por el token de la sesion y deja de valer. El token se guarda en
 * sessionStorage (de este origen, muere con la pestana) para sobrevivir a una
 * recarga, y cada orden lo lleva en una cabecera propia, que una pagina de otro
 * origen no puede anadir sin una comprobacion CORS que el panel nunca concede.
 *
 * Sin `shutdown`: cerrar o recargar la pestana no debe abortar una auditoria.
 * El panel se cierra con Ctrl-C en la terminal, que cierra el expediente.
 */
function panelTransport() {
  if (!/^https?:$/.test(location.protocol)) { return null; }
  const found = /(?:^#|&)code=([A-Za-z0-9_-]+)/.exec(location.hash);
  let code = found ? found[1] : null;
  if (code) { history.replaceState(null, '', location.pathname); }
  let token = null;
  try { token = sessionStorage.getItem('firmascope-token'); } catch (err) { token = null; }
  if (!code && !token) { return null; }

  async function request(path, headers, body) {
    const res = await fetch(path, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers),
      body: JSON.stringify(body)
    });
    let reply = null;
    try { reply = await res.json(); } catch (err) { reply = null; }
    if (!reply) { throw new Error('el panel respondio ' + res.status); }
    if (!reply.ok) { throw new Error(reply.error || 'error del nucleo'); }
    return reply.result;
  }

  async function ensureToken() {
    if (token) { return token; }
    if (!code) { throw new Error('sin acceso al panel: abra la direccion que imprimio la terminal'); }
    const once = code;
    code = null;
    token = (await request('/api/bootstrap', {}, { code: once })).token;
    try { sessionStorage.setItem('firmascope-token', token); } catch (err) { /* solo memoria */ }
    return token;
  }

  async function post(cmd, args) {
    const current = await ensureToken();
    return request('/api/call', { 'X-FS-Token': current }, { cmd: cmd, args: args || {} });
  }
  return { hello: () => post('hello'), call: post };
}

const transport = resolveTransport();

async function call(cmd, args) {
  if (!transport) {
    throw new Error('Esta interfaz debe ejecutarse dentro de la aplicacion de FirmaScope.');
  }
  return transport.call(cmd, args || {});
}

/* ------------------------------------------------------------------ */
/* Estado                                                              */
/* ------------------------------------------------------------------ */

const state = {
  schema: [],
  answers: {},
  password: null,
  warnings: [],
  session: null,
  stage: null,
  stages: [],
  credential: null,
  pollTimer: null,
  busy: false,
  login: null
};

const $ = (id) => document.getElementById(id);
const VIEWS = ['view-error', 'view-setup', 'view-consent', 'view-session',
               'view-live', 'view-report'];

function show(view) {
  VIEWS.forEach((id) => { $(id).hidden = (id !== view); });
}

let toastTimer = null;
function toast(message, bad) {
  const el = $('toast');
  el.textContent = message;
  el.className = bad ? 'bad' : '';
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, bad ? 7000 : 3500);
}

/* ------------------------------------------------------------------ */
/* Arranque                                                            */
/* ------------------------------------------------------------------ */

async function boot() {
  if (!transport) {
    $('error-detail').textContent =
      'Esta interfaz debe ejecutarse dentro de la aplicacion de FirmaScope.';
    show('view-error');
    return;
  }
  try {
    const hello = await transport.hello();
    $('version').textContent =
      `nucleo ${hello.firmascope} · protocolo ${hello.protocol} · ` +
      `python ${hello.environment.python}` +
      (hello.proxy_available ? ' · proxy disponible' : ' · sin proxy (nivel 4 degradado)');
    state.warnings = hello.real_credential_warnings || [];
    // Un aviso del nucleo sobre como se esta ejecutando (el del panel: hay un
    // puerto abierto). El texto lo pone el nucleo; aqui solo se muestra.
    if (hello.notice) {
      $('notice').textContent = hello.notice;
      $('notice').hidden = false;
    }

    const schema = await call('schema');
    state.schema = schema.options;
    state.answers = Object.assign({}, schema.defaults);
    // Que campos condicionales se ven lo decide el nucleo: sin preguntarle al
    // arrancar, el aislamiento (que depende del nivel) no aparecia hasta que
    // el operador cambiaba algo.
    await refreshValidation();
    show('view-setup');
  } catch (err) {
    $('error-detail').textContent = String(err && err.message ? err.message : err);
    show('view-error');
  }
}

/* ------------------------------------------------------------------ */
/* Configuracion: se pinta desde el esquema                            */
/* ------------------------------------------------------------------ */

function visibleOptions(group) {
  // El nucleo decide la visibilidad; aqui se replica solo la parte declarativa
  // que el esquema expone, y `validate` del nucleo tiene la ultima palabra.
  return state.schema.filter((opt) => opt.group === group && isVisible(opt));
}

/*
 * Las dependencias entre campos se declaran en Python. El esquema marca que un
 * campo es condicional pero no publica el predicado, asi que la interfaz
 * pregunta al nucleo cada vez que cambia algo: es una ida y vuelta mas, y a
 * cambio no hay dos copias de la misma regla que puedan discrepar.
 */
let visibleIds = null;
function isVisible(opt) {
  if (!opt.conditional) { return true; }
  return visibleIds ? visibleIds.indexOf(opt.id) !== -1 : false;
}

function field(opt) {
  const wrap = document.createElement('label');
  wrap.className = 'field';
  wrap.dataset.option = opt.id;

  const name = document.createElement('span');
  name.className = 'name';
  name.textContent = opt.label;
  wrap.appendChild(name);

  if (opt.help) {
    const help = document.createElement('span');
    help.className = 'help';
    help.textContent = opt.help;
    wrap.appendChild(help);
  }

  const value = state.answers[opt.id];

  if (opt.kind === 'choice') {
    const box = document.createElement('div');
    box.className = 'choices';
    opt.choices.forEach((choice) => {
      const item = document.createElement('label');
      item.className = 'choice' + (choice.danger ? ' danger' : '');
      const radio = document.createElement('input');
      radio.type = 'radio';
      radio.name = opt.id;
      radio.value = choice.value;
      radio.checked = String(value) === choice.value;
      radio.addEventListener('change', () => setAnswer(opt.id, choice.value));
      const text = document.createElement('span');
      const label = document.createElement('span');
      label.className = 'label';
      label.textContent = choice.label;
      text.appendChild(label);
      if (choice.help) {
        const note = document.createElement('span');
        note.className = 'note';
        note.textContent = ' — ' + choice.help;
        text.appendChild(note);
      }
      item.appendChild(radio);
      item.appendChild(text);
      box.appendChild(item);
    });
    wrap.appendChild(box);
    return wrap;
  }

  if (opt.kind === 'bool') {
    wrap.className = 'checkbox';
    wrap.textContent = '';
    const check = document.createElement('input');
    check.type = 'checkbox';
    check.checked = Boolean(value);
    check.addEventListener('change', () => setAnswer(opt.id, check.checked));
    const text = document.createElement('span');
    text.appendChild(name);
    if (opt.help) {
      const help = document.createElement('span');
      help.className = 'help';
      help.textContent = opt.help;
      text.appendChild(help);
    }
    wrap.appendChild(check);
    wrap.appendChild(text);
    return wrap;
  }

  if (opt.kind === 'path') {
    wrap.appendChild(pathControl(opt, value));
    return wrap;
  }

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = opt.placeholder || '';
  input.value = opt.kind === 'multi'
    ? (value || []).join(', ')
    : (value === null || value === undefined ? '' : String(value));
  input.addEventListener('change', () => {
    setAnswer(opt.id, opt.kind === 'multi'
      ? input.value.split(',').map((s) => s.trim()).filter(Boolean)
      : input.value);
  });
  wrap.appendChild(input);
  return wrap;
}

/*
 * Ruta de archivo. Se ofrece el selector nativo cuando el entorno lo tiene --
 * pedirle a alguien que teclee la ruta de su e.firma es una invitacion a
 * equivocarse, y un error aqui significa auditar con el archivo que no era --
 * y se deja igualmente el campo de texto, que es lo que funciona al pegar una
 * ruta o en un entorno sin dialogos.
 */
function pathControl(opt, value) {
  const row = document.createElement('span');
  row.className = 'row';

  const input = document.createElement('input');
  input.type = 'text';
  input.placeholder = opt.placeholder || '/ruta/al/archivo';
  input.value = value === null || value === undefined ? '' : String(value);
  input.addEventListener('change', () => setAnswer(opt.id, input.value));
  row.appendChild(input);

  if (transport && transport.pickFile) {
    const pick = document.createElement('button');
    pick.type = 'button';
    pick.textContent = 'Elegir archivo…';
    pick.addEventListener('click', async () => {
      try {
        const chosen = await transport.pickFile(
          opt.label, extensionsFor(opt.id));
        if (chosen) {
          input.value = chosen;
          await setAnswer(opt.id, chosen);
        }
      } catch (err) {
        toast('No se pudo abrir el selector: ' + (err.message || err), true);
      }
    });
    row.appendChild(pick);
  }
  if (opt.id === 'session_file') { row.appendChild(loginControl(input)); }
  return row;
}

/*
 * Inicio de sesion en el portal, fuera de la auditoria. El nucleo abre un
 * navegador sin instrumentar; la persona inicia sesion alli -- su contrasena
 * no pasa por esta interfaz ni por el puente -- y avisa con "Guardar sesion".
 * El estado vive en `state.login` porque el formulario se vuelve a pintar con
 * cada respuesta, y el boton debe seguir diciendo en que paso esta.
 */
function loginControl(input) {
  const box = document.createElement('span');
  box.className = 'row';
  const button = (text, handler) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = text;
    b.addEventListener('click', (ev) => { ev.preventDefault(); handler(); });
    box.appendChild(b);
    return b;
  };

  if (!state.login) {
    button('Iniciar sesion en el portal…', () => withBusy(async () => {
      // La direccion la saca el nucleo de las respuestas: la interfaz no
      // lee campos por su nombre.
      state.login = await call('login_start', { answers: state.answers });
      toast('Inicie sesion en la ventana que se abrio y pulse "Guardar sesion".');
      renderSetup();
    }));
    return box;
  }

  button('Guardar sesion', () => withBusy(async () => {
    const saved = await call('login_save');
    state.login = null;
    input.value = saved.path;
    await setAnswer('session_file', saved.path);
    toast(`Sesion guardada: ${saved.cookies} cookies de `
          + (saved.cookie_domains.join(', ') || 'ningun dominio'),
          saved.cookies === 0);
    renderSetup();
  }));
  button('Cancelar', () => withBusy(async () => {
    await call('login_cancel');
    state.login = null;
    renderSetup();
  }));
  return box;
}

function extensionsFor(id) {
  if (id === 'key_path') { return ['key', 'pem']; }
  if (id === 'cert_path') { return ['cer', 'crt', 'der']; }
  if (id === 'session_file') { return ['json']; }
  return [];
}

function renderSetup() {
  const basic = $('setup-form');
  const advanced = $('setup-advanced');
  basic.textContent = '';
  advanced.textContent = '';
  visibleOptions('basico').forEach((opt) => {
    // El consentimiento de credencial real tiene su propia pantalla.
    if (opt.id !== 'accept_real_risk') { basic.appendChild(field(opt)); }
  });
  visibleOptions('avanzado').forEach((opt) => advanced.appendChild(field(opt)));
}

async function setAnswer(id, value) {
  state.answers[id] = value;
  await refreshValidation();
}

async function refreshValidation() {
  try {
    const check = await call('validate', { answers: state.answers });
    visibleIds = check.visible;
    renderSetup();
    const box = $('setup-problems');
    if (check.problems.length) {
      box.textContent = '';
      const title = document.createElement('div');
      title.textContent = 'Falta corregir:';
      const list = document.createElement('ul');
      check.problems.forEach((p) => {
        const li = document.createElement('li');
        li.textContent = p;
        list.appendChild(li);
      });
      box.appendChild(title);
      box.appendChild(list);
      box.hidden = false;
    } else {
      box.hidden = true;
    }
    $('start').disabled = check.problems.length > 0;
    return check;
  } catch (err) {
    toast(String(err.message || err), true);
    return { problems: [String(err)], visible: [], needs_password: false };
  }
}

/* ------------------------------------------------------------------ */
/* Credencial real: consentimiento                                     */
/* ------------------------------------------------------------------ */

function askConsent() {
  const list = $('consent-warnings');
  list.textContent = '';
  state.warnings.forEach((w) => {
    const li = document.createElement('li');
    li.textContent = w;
    list.appendChild(li);
  });
  $('consent-input').value = '';
  show('view-consent');
}

/* ------------------------------------------------------------------ */
/* Sesion                                                              */
/* ------------------------------------------------------------------ */

async function start() {
  const check = await refreshValidation();
  if (check.problems.length) { return; }

  if (String(state.answers.credentials) === 'real' && !state.answers.accept_real_risk) {
    askConsent();
    return;
  }
  if (check.needs_password && !state.password) {
    const pwd = window.prompt('Contrasena de la clave privada');
    if (pwd === null) { return; }
    state.password = pwd;
  }

  await withBusy(async () => {
    const started = await call('start', {
      answers: state.answers,
      password: state.password
    });
    // La contrasena no se conserva en la interfaz mas de lo necesario.
    state.password = null;
    state.session = started;
    state.stage = started.stage;
    state.stages = started.stages;
    state.credential = started.credential;
    $('subtitle').textContent = started.target || 'sin objetivo: abra una pagina';
    renderCredential();
    renderStage();
    $('credential-warning').hidden = true;
    show('view-session');
    startPolling();
    toast(`Sesion ${started.session} iniciada`);
  });
}

/*
 * Copiar al portapapeles. `navigator.clipboard` exige un contexto seguro y no
 * todos los webviews lo ofrecen; el respaldo con una seleccion temporal
 * funciona en los que no. La ruta y la contrasena se pegan en el selector de
 * archivos y en el formulario del portal: teclearlas es donde se equivoca uno.
 */
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (err) { /* se intenta el respaldo */ }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (err) { ok = false; }
  area.remove();
  return ok;
}

function renderCredential() {
  const card = $('credential-card');
  const info = state.credential || {};
  if (!info.synthetic) { card.hidden = true; return; }
  const dl = $('credential-info');
  dl.textContent = '';
  [['.cer', info.cert_path], ['.key', info.key_path],
   ['contrasena', info.password]].forEach(([label, value]) => {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    const code = document.createElement('code');
    code.textContent = value || '';
    dd.appendChild(code);
    if (value) {
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'copy';
      copy.textContent = 'Copiar';
      copy.addEventListener('click', async () => {
        const ok = await copyText(String(value));
        toast(ok ? `${label} copiado` : 'No se pudo copiar; seleccione el texto', !ok);
      });
      dd.appendChild(copy);
    }
    dl.appendChild(dt);
    dl.appendChild(dd);
  });
  card.hidden = false;
}

function renderStage() {
  const stage = state.stage;
  if (!stage) { return; }
  $('stage-title').textContent = `${stage.index + 1}/${stage.total} · ${stage.title}`;
  const pill = $('stage-network');
  pill.textContent = stage.actual_network || stage.network;
  pill.className = 'pill ' + (stage.actual_network || stage.network);
  $('stage-instruction').textContent = stage.instruction;

  const note = $('stage-note');
  if (stage.irreversible_note) {
    note.textContent = stage.irreversible_note;
    note.hidden = false;
  } else {
    note.hidden = true;
  }

  const list = $('stage-list');
  list.textContent = '';
  state.stages.forEach((item) => {
    const li = document.createElement('li');
    if (item.index === stage.index) { li.className = 'current'; }
    const n = document.createElement('span');
    n.textContent = (item.index + 1) + '.';
    const t = document.createElement('span');
    t.textContent = item.title;
    const net = document.createElement('span');
    net.className = 'net';
    net.textContent = item.network;
    li.appendChild(n); li.appendChild(t); li.appendChild(net);
    list.appendChild(li);
  });

  document.querySelector('[data-action="back"]').disabled = !stage.allow_back;
  // En la ultima etapa el boton ya no lleva a otra etapa: cierra la sesion,
  // analiza y escribe el expediente. Llamarlo "Siguiente" no decia eso.
  document.querySelector('[data-action="next"]').textContent =
    stage.index === stage.total - 1 ? 'Finalizar y generar reporte' : 'Siguiente';
  // La credencial queda a la vista toda la sesion: en el piloto, el operador
  // volvio atras a repetir la firma y ya no tenia la ruta ni la contrasena.
  // En la etapa de firma se resalta, que es cuando se usa.
  const card = $('credential-card');
  card.hidden = !(state.credential && state.credential.synthetic);
  card.classList.toggle('focus', stage.name === 'sign');
}

async function stageAction(action) {
  if (action === 'cancel') {
    const ok = window.confirm(
      'Cancelar el proceso. El expediente se cierra con lo observado hasta ahora '
      + 'y la red se restablece. ¿Continuar?');
    if (!ok) { return; }
  }
  await withBusy(async () => {
    const result = await call('action', { action: action });
    state.stages = result.stages;
    if (result.autopilot) {
      const ap = result.autopilot;
      if (ap.signed) { toast('Piloto: formulario rellenado y firma solicitada'); }
      else if (ap.sent) { toast('Piloto: firma enviada'); }
      else if (ap.notes && ap.notes.length) {
        toast('Piloto: ' + ap.notes.join('; ') + '. Firme a mano en el navegador.', true);
      }
    }
    if (result.finished) {
      stopPolling();
      await finish(action === 'cancel');
      return;
    }
    state.stage = result.stage;
    renderStage();
  });
}

async function finish(aborted) {
  // El analisis del codigo del sitio puede tardar minutos en un portal real.
  // Sin este aviso la interfaz parecia congelada en la ultima etapa.
  const note = $('stage-note');
  note.textContent = 'Analizando el codigo del sitio y escribiendo el expediente. '
    + 'Puede tardar unos minutos; no cierre esta ventana.';
  note.hidden = false;
  await withBusy(async () => {
    const done = await call('finish', {
      aborted: Boolean(aborted),
      reason: aborted ? 'cancelado desde la interfaz' : ''
    });
    state.session = null;
    renderReport(done);
    show('view-report');
  });
}

/* ------------------------------------------------------------------ */
/* Latido: los eventos se piden, no se empujan                         */
/* ------------------------------------------------------------------ */

const LIVE_TYPES = {
  FILE_SELECTED: 1, FILE_READ: 1, PASSWORD_READ: 1, CRYPTO_IMPORT: 1,
  CRYPTO_DECRYPT: 1, CRYPTO_SIGN: 1, CRYPTO_EXPORT: 1, CRYPTO_WRAP: 1,
  STORAGE_WRITE: 1, NETWORK_OFF: 1, NETWORK_ON: 1, BEACON_SEND: 1,
  WEBSOCKET_SEND: 1, FORM_SUBMIT: 1, NETWORK_REQUEST: 1,
  // Errores de JavaScript de la pagina: si el portal se queda "cargando", es lo
  // primero que hay que ver, y sin esto solo estaban en el expediente.
  AGENT_ERROR: 1
};

function startPolling() {
  stopPolling();
  state.pollTimer = setInterval(poll, 700);
  poll();
}

function stopPolling() {
  if (state.pollTimer) { clearInterval(state.pollTimer); state.pollTimer = null; }
}

async function poll() {
  if (state.busy || !state.session) { return; }
  try {
    const beat = await call('poll');
    (beat.events || []).forEach(addEvent);
    const stats = beat.stats || {};
    $('session-status').textContent =
      `${stats.events || 0} eventos · ${stats.requests || 0} peticiones · ` +
      `red ${beat.network || '—'}` +
      (beat.dropped ? ` · ${beat.dropped} eventos descartados` : '');
    if (state.stage && beat.network) {
      state.stage.actual_network = beat.network;
      const pill = $('stage-network');
      pill.textContent = beat.network;
      pill.className = 'pill ' + beat.network;
    }
  } catch (err) {
    stopPolling();
    toast('Se perdio la conexion con el nucleo: ' + (err.message || err), true);
  }
}

const feedSeen = { count: 0 };
function addEvent(event) {
  // El nucleo avisa si el .key elegido en la pagina no es el de la sesion: en
  // el piloto del portal real se cargo la e.firma real en modo sintetico y
  // nada lo advirtio. El aviso se queda fijo; la lista de eventos se desplaza.
  const data0 = event.data || {};
  if (event.type === 'CHECKPOINT' && data0.name === 'credential-mismatch') {
    const box = $('credential-warning');
    box.textContent = data0.message || 'El .key cargado no es el de la sesion.';
    box.hidden = false;
    toast(box.textContent, true);
    return;
  }
  // Una salida de material privado se muestra siempre, sea del tipo que sea:
  // es lo unico de la lista que no puede pasar desapercibido.
  const privateEgress = Boolean(event.private_egress);
  if (!LIVE_TYPES[event.type] && !privateEgress) { return; }
  const feed = $('feed');
  const empty = feed.querySelector('.empty');
  if (empty) { empty.remove(); }

  const row = document.createElement('div');
  const blocked = Boolean(event.data && event.data.blocked);
  row.className = 'ev' + (blocked ? ' blocked' : '') + (privateEgress ? ' private' : '');

  const type = document.createElement('span');
  type.className = 't';
  type.textContent = event.type;

  const detail = document.createElement('span');
  detail.className = 'd';
  const data = event.data || {};
  const where = data.host || data.store || data.reason || data.algorithm
    || (data.message ? `${data.kind || 'error'}: ${data.message}` : '');
  const size = data.body_size || data.size || '';
  const mark = privateEgress
    ? (blocked ? '[INTENTO BLOQUEADO DE SACAR MATERIAL PRIVADO]' : '[SALIDA DE MATERIAL PRIVADO]')
    : (blocked ? '[BLOQUEADO]' : '');
  detail.textContent = [where, size, mark].filter(Boolean).join(' ');
  // La linea se recorta para que la lista siga legible; el texto completo
  // (un mensaje de error largo, una URL) queda al pasar el cursor.
  detail.title = detail.textContent;
  if (privateEgress) { row.setAttribute('role', 'alert'); }

  const tags = document.createElement('span');
  tags.className = 'g';
  tags.textContent = (event.tags || []).join(',');

  row.appendChild(type); row.appendChild(detail); row.appendChild(tags);
  feed.appendChild(row);

  // Se conserva una ventana: el expediente tiene el registro completo y esta
  // lista solo acompana lo que ocurre.
  feedSeen.count += 1;
  while (feed.childNodes.length > 300) { feed.removeChild(feed.firstChild); }
  feed.scrollTop = feed.scrollHeight;
}

/* ------------------------------------------------------------------ */
/* Acciones sueltas                                                    */
/* ------------------------------------------------------------------ */

async function navigate() {
  const url = $('url-input').value.trim();
  if (!url) { toast('Indique una direccion', true); return; }
  try {
    const result = await call('navigate', { url: url });
    toast('Abierto: ' + result.url + (result.is_target ? ' (objetivo de la sesion)' : ''));
    $('subtitle').textContent = result.target || result.url;
  } catch (err) {
    toast(String(err.message || err), true);
  }
}

async function setNetwork(offline) {
  try {
    const result = await call('network', { offline: offline });
    toast(result.offline ? 'Red aislada' : 'Red restablecida');
    await poll();
  } catch (err) {
    toast(String(err.message || err), true);
  }
}

async function openLive() {
  try {
    const live = await call('live_options');
    const form = $('live-form');
    form.textContent = '';
    live.options.forEach((opt) => {
      const saved = state.answers[opt.id];
      state.answers[opt.id] = live.current[opt.id];
      const node = field(opt);
      state.answers[opt.id] = saved;
      node.addEventListener('change', async () => {
        const input = node.querySelector('input:checked, input[type=text], input[type=checkbox]');
        let value;
        if (!input) { return; }
        if (input.type === 'checkbox') { value = input.checked; }
        else if (input.type === 'radio') { value = input.value; }
        else if (opt.kind === 'multi') {
          value = input.value.split(',').map((s) => s.trim()).filter(Boolean);
        } else { value = input.value; }
        try {
          const applied = await call('live', { option: opt.id, value: value });
          toast(applied.applied);
        } catch (err) {
          toast(String(err.message || err), true);
        }
      });
      form.appendChild(node);
    });
    show('view-live');
  } catch (err) {
    toast(String(err.message || err), true);
  }
}

/* ------------------------------------------------------------------ */
/* Reporte                                                             */
/* ------------------------------------------------------------------ */

const STATUS_LABEL = {
  CONFIRMED: 'CONFIRMADO', OBSERVED: 'OBSERVADO', POTENTIAL: 'POTENCIAL',
  NOT_OBSERVED: 'NO OBSERVADO', INCONCLUSIVE: 'SIN CONCLUIR'
};

function renderReport(done) {
  const report = done.report;
  $('report-path').textContent = done.package;
  const meta = $('report-meta');
  meta.textContent = '';
  if (!report) {
    const dt = document.createElement('dt');
    dt.textContent = 'Sin reporte';
    const dd = document.createElement('dd');
    dd.textContent = 'El expediente quedo incompleto. Revise ' + done.package;
    meta.appendChild(dt); meta.appendChild(dd);
    return;
  }

  const rows = [
    ['Sesion', report.session],
    ['Objetivo', report.target || '(ninguno)'],
    ['Nivel', `${report.level.value} (${report.level.name})`],
    ['Credencial', report.credential_mode],
    ['Observado', `${report.counts.events} eventos · ${report.counts.requests} peticiones · `
                  + `${report.counts.scripts} scripts`],
    ['Cadena', report.integrity.verified ? 'intacta' : 'ROTA']
  ];
  if (report.aborted) { rows.unshift(['Cancelada', report.abort_reason]); }
  rows.forEach(([label, value]) => {
    const dt = document.createElement('dt');
    dt.textContent = label;
    const dd = document.createElement('dd');
    dd.textContent = value;
    meta.appendChild(dt); meta.appendChild(dd);
  });

  const sensors = $('report-sensors');
  sensors.textContent = '';
  const s = report.sensors || {};
  const active = ['agent', 'cdp', 'isolation', 'proxy'].filter((k) => s[k]);
  const line = document.createElement('p');
  line.className = 'sub';
  line.textContent = 'Sensores activos: ' + (active.join(', ') || 'ninguno');
  sensors.appendChild(line);
  if (s.limitation) {
    const warn = document.createElement('p');
    warn.className = 'warn';
    warn.textContent = s.limitation;
    sensors.appendChild(warn);
  }

  const locality = $('report-locality').querySelector('tbody');
  locality.textContent = '';
  Object.entries(report.processing_locality || {}).forEach(([label, value]) => {
    const tr = document.createElement('tr');
    const td1 = document.createElement('td');
    td1.textContent = label;
    const td2 = document.createElement('td');
    td2.textContent = value;
    tr.appendChild(td1); tr.appendChild(td2);
    locality.appendChild(tr);
  });

  const box = $('report-findings');
  box.textContent = '';
  (report.findings || []).forEach((finding) => {
    const card = document.createElement('div');
    card.className = 'card';
    const item = document.createElement('div');
    item.className = 'finding ' + finding.status;
    const title = document.createElement('h4');
    const badge = document.createElement('span');
    badge.className = 'badge';
    badge.textContent = STATUS_LABEL[finding.status] || finding.status;
    const code = document.createElement('code');
    code.textContent = finding.rule_id;
    title.appendChild(badge);
    title.appendChild(code);
    title.appendChild(document.createTextNode(' ' + finding.title));
    const summary = document.createElement('p');
    summary.textContent = finding.summary;
    const sub = document.createElement('p');
    sub.className = 'sub';
    sub.textContent = `severidad ${finding.severity} · confianza ${finding.confidence}`;
    item.appendChild(title);
    item.appendChild(summary);
    item.appendChild(sub);
    if (finding.detail) {
      const details = document.createElement('details');
      const sum = document.createElement('summary');
      sum.textContent = 'Detalle';
      const pre = document.createElement('pre');
      pre.textContent = finding.detail;
      details.appendChild(sum);
      details.appendChild(pre);
      item.appendChild(details);
    }
    card.appendChild(item);
    box.appendChild(card);
  });
}

/* ------------------------------------------------------------------ */
/* Enlace de la interfaz                                               */
/* ------------------------------------------------------------------ */

/*
 * Bloquea los botones mientras el nucleo trabaja.
 *
 * Cuenta anidamientos en lugar de usar una bandera: una accion de etapa que
 * termina el recorrido llama a `finish` dentro de si misma, y con una bandera
 * simple la llamada interior se descartaba en silencio -- la auditoria
 * terminaba pero el reporte no se pintaba nunca.
 */
let busyDepth = 0;

async function withBusy(fn) {
  const outermost = busyDepth === 0;
  busyDepth += 1;
  state.busy = true;
  if (outermost) {
    document.querySelectorAll('button').forEach((b) => {
      b.dataset.wasDisabled = String(b.disabled);
      b.disabled = true;
    });
  }
  try {
    await fn();
  } catch (err) {
    toast(String(err && err.message ? err.message : err), true);
  } finally {
    busyDepth -= 1;
    if (busyDepth === 0) {
      state.busy = false;
      document.querySelectorAll('button').forEach((b) => {
        b.disabled = b.dataset.wasDisabled === 'true';
        delete b.dataset.wasDisabled;
      });
      if (state.stage && !$('view-session').hidden) { renderStage(); }
    }
  }
}

const ACTIONS = {
  'retry-hello': boot,
  start: start,
  next: () => stageAction('next'),
  back: () => stageAction('back'),
  retry: () => stageAction('retry'),
  cancel: () => stageAction('cancel'),
  navigate: navigate,
  offline: () => setNetwork(true),
  online: () => setNetwork(false),
  live: openLive,
  'live-close': () => show('view-session'),
  'consent-cancel': () => { state.answers.accept_real_risk = false; show('view-setup'); },
  'consent-ok': async () => {
    if ($('consent-input').value.trim() !== 'ACEPTO') {
      toast('Escriba ACEPTO exactamente para continuar.', true);
      return;
    }
    state.answers.accept_real_risk = true;
    await refreshValidation();
    show('view-setup');
    await start();
  },
  'new-session': () => { window.location.reload(); }
};

document.addEventListener('click', (event) => {
  const button = event.target.closest('[data-action]');
  if (!button) { return; }
  const handler = ACTIONS[button.dataset.action];
  if (handler) { event.preventDefault(); handler(); }
});

window.addEventListener('beforeunload', () => {
  if (transport && transport.shutdown) { transport.shutdown(); }
});

let booted = false;
function bootOnce() {
  if (booted) { return; }
  booted = true;
  boot();
}
document.addEventListener('DOMContentLoaded', bootOnce);
if (document.readyState !== 'loading') { bootOnce(); }
