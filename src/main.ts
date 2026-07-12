import "./styles.css";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openPath } from "@tauri-apps/plugin-opener";
import DOMPurify from "dompurify";

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A") {
    node.setAttribute("rel", "noopener noreferrer");
    node.setAttribute("target", "_blank");
  }
  // Imágenes embebidas del backend: permitir solo data: URIs, bloquear URLs externas
  if (node.tagName === "IMG") {
    const src = node.getAttribute("src") ?? "";
    if (src.startsWith("data:image/")) {
      node.setAttribute("src", src);
    } else {
      node.removeAttribute("src");
    }
  }
});

type Pantalla = "carga" | "decision" | "configuracion" | "login" | "principal" | "traduccion" | "archivos-guardados" | "comunicacion" | "frase" | "recuperacion" | "terminos" | "nombre" | "ajustes";
// VARIABLES DE SESIÓN — nunca van a window, se zeroizan al cerrar
// ============================================================
// M3: NO retenemos la llave maestra ni la contraseña en JS. Las strings de JS son
// inmutables, así que "0".repeat(n) no borra la memoria original — guardarlas solo
// aumentaba la superficie de exposición sin aportar nada. La subclave real vive en Rust
// (mlock + zeroize). Aquí basta un flag de "sesión activa" para la lógica de la UI.
let _sesionActiva = false;
let _sesionUsuario = "";
// Escapa caracteres HTML para prevenir XSS en innerHTML
// Úsala siempre que metas datos de usuario o de red en el DOM
function escapeHTML(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

let _renombraViejo = "";
let _renombraViejoG = "";
let _renombraArchivoRuta = "";
let _renombraEsGuardado = false;
let buzonParentPendienteG: string | null = null;

// Tipo compartido para nodos de buzón con árbol jerárquico
interface BuzonNodo { id: string; nombre: string; parent: string | null; }

let _buzonesCache: BuzonNodo[] = [];

// IDs de buzones colapsados (no muestran sus hijos)
const buzonesColapsados = new Set<string>();

function toggleColapso(id: string, sistema: string): void {
  if (buzonesColapsados.has(id)) {
    buzonesColapsados.delete(id);
  } else {
    buzonesColapsados.add(id);
  }
  if (sistema !== "trad") {
    cargarBuzonesGuardados();
  }
}

// Construye HTML del árbol de buzones recursivamente
function renderArbolBuzones(
  nodos: BuzonNodo[], parentId: string | null, profundidad: number,
  activo: string, sistema: "trad" | "guard"
): string {
  return nodos.filter(n => n.parent === parentId).map(n => {
    const esActivo = activo === n.id;
    const indent = 8 + profundidad * 14;
    const tieneHijos = nodos.some(h => h.parent === n.id);
    const colapsado = buzonesColapsados.has(n.id);
    // Use escapeHTML for HTML attribute context — browser decodes entities correctly via dataset.*
    const safeId = escapeHTML(n.id);
    const safeNombre = escapeHTML(n.nombre);

    // Drop handlers for trad still need inline strings (need event object), but IDs come
    // from Rust-generated hex so they can't carry injection payloads.
    const drop = sistema === "trad"
      ? `ondragover="allowDrop(event)" ondragleave="dragLeave(event)" ondrop="soltarEnBuzon(event,'${escapeHTML(n.id).replace(/'/g, "&#039;")}')"`
      : "";

    const selAction = sistema === "trad" ? "seleccionar-buzon" : "seleccionar-buzon-guardados";

    const toggleIcon = tieneHijos
      ? `<span data-action="toggle-colapso" data-buzon="${safeId}" data-sistema="${sistema}"
           style="cursor:pointer;font-size:0.6rem;opacity:0.6;padding:0 3px;transition:transform 0.15s;"
           title="${colapsado ? "Expandir" : "Colapsar"}">${colapsado ? "▶" : "▼"}</span>`
      : `<span style="display:inline-block;width:14px;"></span>`;

    const hijos = colapsado ? "" : renderArbolBuzones(nodos, n.id, profundidad + 1, activo, sistema);

    return `
      <div class="buzon-item ${esActivo ? "activo" : ""}" data-action="${selAction}" data-buzon="${safeId}" ${drop}
        style="padding-left:${indent}px;border:1px solid transparent;border-radius:3px;transition:background 0.2s,border-color 0.2s;">
        ${toggleIcon}
        <span class="buzon-icono" data-action="renombrar-buzon" data-buzon="${safeId}" data-nombre="${safeNombre}" data-sistema="${sistema}" style="cursor:pointer;" title="Renombrar">✎</span>
        <span class="buzon-nombre" style="flex:1" title="${safeNombre}">${safeNombre.toUpperCase()}</span>
        <span data-action="nuevo-subbuzon" data-buzon="${safeId}" data-sistema="${sistema}" style="color:var(--texto-secundario);cursor:pointer;font-size:0.85rem;opacity:0.5;padding:0 4px;" title="Nuevo subbuzón">+</span>
        <button type="button" data-action="borrar-buzon" data-buzon="${safeId}" data-sistema="${sistema}" style="background:transparent;border:none;color:var(--texto-secundario);cursor:pointer;font-size:0.7rem;opacity:0.4;padding:0 2px;" title="Eliminar">✕</button>
      </div>${hijos}`;
  }).join("");
}
// UTILIDADES UI

function mostrarPantalla(nombre: Pantalla): void {
  document.querySelectorAll<HTMLElement>(".pantalla")
    .forEach(p => p.classList.add("hidden"));
  document.getElementById(`pantalla-${nombre}`)?.classList.remove("hidden");
}

function mostrarMensaje(id: string, texto: string, esError: boolean): void {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = texto;
  el.className = esError ? "msg-error" : "msg-success";
  el.classList.remove("hidden");
}

function limpiarCampo(id: string): void {
  const el = document.getElementById(id) as HTMLInputElement | null;
  if (!el) return;
  el.value = "0".repeat(el.value.length);
  el.value = "";
}

function limpiarCamposSensibles(): void {
  ["master-key", "master-key-confirm", "user-pass", "user-pass-confirm",
    "login-pass", "login-pass-usuario"].forEach(limpiarCampo);
}

// CHAT — SISTEMA DE MENSAJES

function añadirMensajeUsuario(texto: string): void {
  const contenedor = document.getElementById("chat-mensajes");
  if (!contenedor) return;
  const burbuja = document.createElement("div");
  burbuja.className = "chat-burbuja usuario";
  burbuja.innerHTML = `
    <div class="burbuja-contenido derecha">
      <p class="burbuja-texto">${escapeHTML(texto)}</p>
      <span class="burbuja-hora">TÚ</span>
    </div>`;
  contenedor.appendChild(burbuja);
  scrollAlFinal();
}

function añadirMensajeArchivo(nombreArchivo: string, peso: string): void {
  const contenedor = document.getElementById("chat-mensajes");
  if (!contenedor) return;
  const burbuja = document.createElement("div");
  burbuja.className = "chat-burbuja usuario";
  burbuja.innerHTML = `
    <div class="burbuja-contenido derecha">
      <div class="burbuja-archivo">
        <span class="archivo-icono">◫</span>
        <div class="archivo-info">
          <span class="archivo-nombre">${escapeHTML(nombreArchivo)}</span>
          <span class="archivo-peso">${escapeHTML(peso)}</span>
        </div>
      </div>
      <span class="burbuja-hora">TÚ</span>
    </div>`;
  contenedor.appendChild(burbuja);
  scrollAlFinal();
}

function añadirMensajeBabel(texto: string, pie?: string): void {
  const contenedor = document.getElementById("chat-mensajes");
  if (!contenedor) return;
  const burbuja = document.createElement("div");
  burbuja.className = "chat-burbuja babel";
  burbuja.innerHTML = `
    <div class="burbuja-icono">B</div>
    <div class="burbuja-contenido">
      <p class="burbuja-texto">${escapeHTML(texto)}</p>
      <div style="display:flex;align-items:center;gap:10px;margin-top:4px;">
        <span class="burbuja-hora">${escapeHTML(pie ?? "BABEL")}</span>
        <button type="button" class="burbuja-btn-copiar" title="Copiar traducción">⊕</button>
      </div>
    </div>`;
  burbuja.querySelector(".burbuja-btn-copiar")?.addEventListener("click", () => {
    navigator.clipboard.writeText(texto).then(() => mostrarToast("Copiado", false)).catch(() => {});
  });
  contenedor.appendChild(burbuja);
  scrollAlFinal();
}

function añadirResultadoArchivo(nombreResultado: string, ruta: string): void {
  const contenedor = document.getElementById("chat-mensajes");
  if (!contenedor) return;

  const nombreLimpio = nombreResultado
    .replace(/\.babel$/, "")
    .replace(/_\d+$/, "")
    .replace(/^\d+_/, "");

  const burbuja = document.createElement("div");
  burbuja.className = "chat-burbuja babel";
  burbuja.innerHTML = `
    <div class="burbuja-icono">B</div>
    <div class="burbuja-contenido">
      <p class="burbuja-texto">Documento traducido y cifrado.</p>
      <div class="burbuja-resultado">
        <span class="archivo-icono">✓</span>
        <div class="archivo-info" style="min-width:0;overflow:hidden;">
          <span class="archivo-nombre" style="display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:180px;" title="${escapeHTML(nombreLimpio)}">${escapeHTML(nombreLimpio)}</span>
          <span class="archivo-peso">Cifrado AES-256-GCM</span>
        </div>
        <div style="display:flex;gap:6px;flex-shrink:0;">
          <button type="button" class="btn-descargar btn-ver-resultado" title="Ver documento">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </button>
          <button type="button" class="btn-descargar btn-exportar-resultado" title="Exportar documento">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
          </button>
        </div>
      </div>
      <span class="burbuja-hora">BABEL · Este documento no ha salido de tu ordenador</span>
    </div>`;
  const btnVer = burbuja.querySelector(".btn-ver-resultado") as HTMLButtonElement;
  btnVer?.addEventListener("click", () => verArchivo(ruta));
  const btnExportar = burbuja.querySelector(".btn-exportar-resultado") as HTMLButtonElement;
  btnExportar?.addEventListener("click", () => exportarArchivo(ruta));
  contenedor.appendChild(burbuja);
}

function scrollAlFinal(): void {
  const c = document.getElementById("chat-mensajes");
  if (c) c.scrollTop = c.scrollHeight;

}

function mostrarProcesando(visible: boolean): void {
  const el = document.getElementById("chat-procesando");
  if (!el) return;
  if (visible) {
    const textoEl = el.querySelector<HTMLElement>(".procesando-texto");
    const barraEl = document.getElementById("procesando-barra");
    if (textoEl) textoEl.textContent = "TRADUCIENDO";
    if (barraEl) barraEl.style.width = "0%";
    el.classList.remove("hidden");
    scrollAlFinal();
  } else {
    el.classList.add("hidden");
  }
}

// Borrar chat manualmente con zeroize de todos los textos en DOM
function borrarChat(): void {
  const contenedor = document.getElementById("chat-mensajes");
  if (!contenedor) return;

  // Zeroize de todos los textos de burbujas antes de eliminar
  contenedor.querySelectorAll(".burbuja-texto").forEach(el => {
    const len = el.textContent?.length ?? 0;
    el.textContent = "0".repeat(len);
    el.textContent = "";
  });

  while (contenedor.children.length > 1) {
    contenedor.removeChild(contenedor.lastChild!);
  }

  // Zeroize del input
  const input = document.getElementById("chat-input") as HTMLTextAreaElement;
  if (input) {
    input.value = "0".repeat(input.value.length);
    input.value = "";
    input.style.height = "auto";
  }
}

// DELEGATED CLICK HANDLER — reemplaza todos los onclick="..." del HTML
document.addEventListener("click", (e: MouseEvent) => {
  const el = (e.target as Element).closest<HTMLElement>("[data-action]");
  if (!el) return;
  const action = el.dataset.action!;
  switch (action) {
    // Navegación
    case "mostrar-pantalla": mostrarPantalla(el.dataset.pantalla! as Pantalla); break;
    case "volver-atras": volverAtras(); break;
    case "volver-al-panel": volverAlPanel(); break;
    case "volver-de-p2p": volverDeP2P(); break;
    case "ir-a-traduccion": irATraduccion(); break;
    case "ir-a-archivos": irAArchivos(); break;
    case "ir-a-recuperacion": irARecuperacion(); break;
    // Sesión / búnker
    case "crear-bunker": crearBunker(); break;
    case "intentar-acceso": intentarAcceso(); break;
    case "cerrar-sesion": cerrarSesion(); break;
    case "desbloquear-pantalla": desbloquearPantalla(); break;
    case "intentar-recuperacion": intentarRecuperacion(); break;
    case "aceptar-terminos": aceptarTerminos(); break;
    // UI
    case "toggle-sidebar": toggleSidebar(); break;
    case "toggle-contrasena": toggleContraseña(el.dataset.campo!); break;
    case "cambiar-tema": cambiarTema(el.dataset.tema!); break;
    case "ver-frase-app": verFraseApp(); break;
    case "cerrar-frase": cerrarFrase(); break;
    case "imprimir-frase": imprimirFrase(); break;
    case "cerrar-ver-frase": cerrarVerFrase(); break;
    case "cerrar-visor": cerrarVisor(); break;
    case "cerrar-visor-paralelo": cerrarVisorParalelo(); break;
    case "ver-comparacion": verComparacion(); break;
    // Traducción / chat
    case "enviar-mensaje": enviarMensaje(); break;
    case "seleccionar-archivo": seleccionarArchivo(); break;
    case "swap-idioma": swapIdiomaTraduccion(); break;
    case "limpiar-input": limpiarInputTraduccion(); break;
    case "borrar-chat": borrarChat(); break;
    case "eliminar-seleccionados": eliminarSeleccionados(); break;
    // Archivos guardados
    case "ver-archivo-guardado": verArchivoGuardado(); break;
    case "eliminar-sel-guardados": eliminarSeleccionadosGuardados(); break;
    case "cargar-archivos-guardados": cargarArchivosGuardados(); break;
    case "abrir-carpeta-guardados": abrirCarpetaBabelGuardados(); break;
    case "exportar-todo": exportarTodo(); break;
    case "abrir-importar-guardado": abrirImportarGuardado(); break;
    case "mostrar-input-buzon-guardado": mostrarInputBuzonGuardado(); break;
    case "confirmar-buzon-guardado": confirmarBuzonGuardado(); break;
    case "cancelar-buzon-guardado": cancelarBuzonGuardado(); break;
    case "seleccionar-buzon-guardados": seleccionarBuzonGuardados(el.dataset.buzon!); break;
    case "toggle-colapso": toggleColapso(el.dataset.buzon!, el.dataset.sistema ?? "guard"); break;
    case "renombrar-buzon":
      if (el.dataset.sistema === "trad") iniciarRenombrado(el.dataset.buzon!, el.dataset.nombre!);
      else iniciarRenombradoGuardado(el.dataset.buzon!, el.dataset.nombre!);
      break;
    case "nuevo-subbuzon":
      mostrarInputBuzonGuardado(el.dataset.buzon!);
      break;
    case "borrar-buzon":
      borrarBuzonGuardado(el.dataset.buzon!);
      break;
    case "guardar-nombre-display": guardarNombreDisplay(); break;
    // Renombrar modales
    case "cerrar-modal-renombrar": cerrarModalRenombrar(); break;
    case "confirmar-renombrar": confirmarRenombrar(); break;
    case "cerrar-modal-renombrar-archivo": cerrarModalRenombrarArchivo(); break;
    case "confirmar-renombrar-archivo": confirmarRenombrarArchivo(); break;
    // P2P
    case "iniciar-p2p": iniciarP2P(); break;
    case "buscar-dispositivos": buscarDispositivos(); break;
    case "conectar-p2p": conectarP2P(); break;
    case "enviar-mensaje-p2p": enviarMensajeP2P(); break;
    case "toggle-traduccion-p2p": toggleTraduccionP2P(); break;
    case "destruir-sesion-p2p": destruirSesionP2P(); break;
    case "cambiar-modo-p2p": cambiarModoP2P(el.dataset.modo!); break;
    case "aceptar-solicitud-p2p": aceptarSolicitudP2P(); break;
    case "rechazar-solicitud-p2p": rechazarSolicitudP2P(); break;
    // Email
    case "sincronizar-email": sincronizarEmail(); break;
    case "abrir-componer-email": abrirComponerEmail(); break;
    case "toggle-config-smtp": toggleConfigSmtp(); break;
    case "guardar-smtp": guardarConfigSmtp(); break;
    case "seleccionar-archivo-email": seleccionarArchivoEmail(); break;
    case "enviar-email": enviarEmail(); break;
    case "responder-email": responderEmail(); break;
    case "marcar-no-leido": marcarEmailNoLeido(); break;
    case "copiar-cuerpo-email": copiarCuerpoEmail(); break;
    case "cambiar-zoom-email": cambiarZoomEmail(Number(el.dataset.delta!)); break;
    case "eliminar-email-actual": eliminarEmailActual(); break;
    case "cerrar-visor-email": cerrarVisorEmail(); break;
    case "cerrar-compositor": cerrarCompositor(); break;
    case "insertar-plantilla": insertarPlantillaEmail(el.dataset.texto!); break;
  }
});

window.addEventListener("DOMContentLoaded", async () => {
  invoke("borrar_html_frase").catch(() => {});
  mostrarPantalla("carga");

  // Evento Rust: servidor USB listo → toast
  listen("servidor-usb-listo", () => {
    mostrarToast("Traductor listo", false);
  }).catch(() => {});

  // Evento Rust: monitor periódico detectó nueva amenaza de seguridad
  listen<string[]>("amenaza-detectada", (evento) => {
    const amenazas = evento.payload ?? [];
    if (amenazas.length > 0) mostrarAlertaAmenaza(amenazas);
  }).catch(() => {});

  // El comando traducir_documento_dialogo emite este evento justo tras elegir el archivo,
  // antes de empezar a traducir. Lo usamos para mostrar la burbuja "TÚ" y la barra.
  listen<{ nombre: string; ext: string }>("archivo-seleccionado", (evento) => {
    const { nombre, ext } = evento.payload;
    añadirMensajeArchivo(nombre, `${ext} · local`);
    mostrarProcesando(true);
  }).catch(() => {});

  // Progreso de traducción de documentos (PDF/DOCX/TXT)
  // Auto-muestra el elemento aunque nadie llamara mostrarProcesando(true) antes
  listen<{ pct: number; msg: string }>("progreso-traduccion", (evento) => {
    const { pct, msg } = evento.payload;
    const el = document.getElementById("chat-procesando");
    if (el?.classList.contains("hidden")) {
      el.classList.remove("hidden");
      scrollAlFinal();
    }
    const textoEl = document.querySelector<HTMLElement>(".procesando-texto");
    const barraEl = document.getElementById("procesando-barra");
    if (textoEl) textoEl.textContent = msg;
    if (barraEl) barraEl.style.width = `${Math.min(pct, 100)}%`;
  }).catch(() => {});

  // Parche 1: bloquear la sesión al perder el foco de ventana (cambio de app, screen-lock
  // del SO). Reduce la ventana en la que la subclave existe en RAM: bloquearPantalla() llama
  // a cerrar_sesion_rust → limpiar(), que zeroiza la clave en el backend. Gracia de 20s para
  // no bloquear en un alt-tab momentáneo; sólo bloquea si el foco sigue perdido al vencer.
  getCurrentWindow().onFocusChanged(({ payload: enfocado }) => {
    if (!enfocado && _sesionActiva) {
      if (_blurLockTimer) clearTimeout(_blurLockTimer);
      _blurLockTimer = setTimeout(() => {
        if (!document.hasFocus() && _sesionActiva) bloquearPantalla();
      }, 120_000);
    } else if (enfocado && _blurLockTimer) {
      clearTimeout(_blurLockTimer);
      _blurLockTimer = null;
    }
  }).catch(() => {});

  // Ocultar sidebar en fullscreen nativo (botón verde macOS)
  getCurrentWindow().onResized(async () => {
    const fs = await getCurrentWindow().isFullscreen().catch(() => false);
    document.body.classList.toggle("es-fullscreen", fs);
  }).catch(() => {});

  // Badge servidor: monitoreo continuo cada 5 s (verde=activo, rojo=caído)
  const badge = document.getElementById("nllb-badge");
  let servidorEstabaActivo = false;
  setInterval(async () => {
    try {
      const res = await fetch("http://127.0.0.1:5002/ping", { signal: AbortSignal.timeout(2000) });
      if (res.ok) {
        if (badge) {
          badge.style.background = "#22c55e";
          badge.style.opacity = "1";
          badge.title = "Servidor activo";
        }
        servidorEstabaActivo = true;
      } else { throw new Error(); }
    } catch {
      if (badge) {
        badge.style.background = "var(--error, #ef4444)";
        badge.style.opacity = "1";
        badge.title = "Servidor caído";
      }
      if (servidorEstabaActivo) {
        mostrarToast("Servidor de traducción desconectado", true);
        servidorEstabaActivo = false;
      }
    }
  }, 5000);

  try {
    const msg = await invoke<string>("verificar_entorno_seguro");
    const statusEl = document.getElementById("status-text");
    if (statusEl) {
      statusEl.textContent = msg;
      statusEl.style.color = "var(--dorado)";
    }
  } catch (amenaza) {
    const statusEl = document.getElementById("status-text");
    if (statusEl) {
      statusEl.textContent = "⚠ " + String(amenaza);
      statusEl.style.color = "var(--error)";
    }
    return;
  }

  await new Promise(r => setTimeout(r, 2500));

  const terminosAceptados = await invoke<boolean>("comprobar_terminos_aceptados");
  if (!terminosAceptados) {
    mostrarModalTerminos();
    return;
  }

  const bunkerExiste = await invoke<boolean>("comprobar_estado_bunker");
  mostrarPantalla(bunkerExiste ? "login" : "decision");
});

// CREAR BÚNKER

async function crearBunker(): Promise<void> {
  const maestra = (document.getElementById("master-key") as HTMLInputElement)?.value ?? "";
  const maestraC = (document.getElementById("master-key-confirm") as HTMLInputElement)?.value ?? "";
  const pass = (document.getElementById("user-pass") as HTMLInputElement)?.value ?? "";
  const passC = (document.getElementById("user-pass-confirm") as HTMLInputElement)?.value ?? "";

  if (!maestra || !pass) { mostrarMensaje("response-msg", "TODOS LOS CAMPOS SON OBLIGATORIOS", true); return; }
  if (maestra !== maestraC) { mostrarMensaje("response-msg", "LAS LLAVES MAESTRAS NO COINCIDEN", true); return; }
  if (pass !== passC) { mostrarMensaje("response-msg", "LAS CONTRASEÑAS NO COINCIDEN", true); return; }
  if (maestra.length < 12) { mostrarMensaje("response-msg", "LA LLAVE MAESTRA NECESITA AL MENOS 12 CARACTERES", true); return; }
  if (pass.length < 8) { mostrarMensaje("response-msg", "LA CONTRASEÑA NECESITA AL MENOS 8 CARACTERES", true); return; }

  mostrarMensaje("response-msg", "CIFRANDO BÚNKER CON AES-256-GCM...", false);

  try {
    await invoke<string>("crear_acceso_bunker", { maestra, usuario: "babel", pass });

    mostrarMensaje("response-msg", "GENERANDO FRASE DE RECUPERACIÓN...", false);
    // Generar y mostrar la frase BIP39 antes de ir al login
    const palabras = await invoke<string[]>("generar_frase_recuperacion", { maestra, passUsuario: pass });
    limpiarCamposSensibles();
    mostrarFrase(palabras);
  } catch (error) {
    mostrarMensaje("response-msg", String(error), true);
  }
}

// LOGIN

async function intentarAcceso(): Promise<void> {
  const llaveMaestra = (document.getElementById("login-pass") as HTMLInputElement)?.value ?? "";
  const passUsuario = (document.getElementById("login-pass-usuario") as HTMLInputElement)?.value ?? "";

  if (!llaveMaestra || !passUsuario) {
    mostrarMensaje("login-msg", "TODOS LOS CAMPOS SON OBLIGATORIOS", true);
    return;
  }
  mostrarMensaje("login-msg", "VERIFICANDO IDENTIDAD...", false);

  try {
    const ok = await invoke<boolean>("verificar_login", {
      pass: llaveMaestra,
      passUsuario
    });

    if (ok) {
      _sesionActiva = true;
      limpiarCamposSensibles();

      const nombreGuardado = localStorage.getItem("babel-nombre-display");
      const nombre = nombreGuardado ?? "";
      _sesionUsuario = nombre;
      const bienvenida = document.getElementById("bienvenida-usuario");
      if (bienvenida) bienvenida.textContent = nombre ? `Bienvenido, ${nombre}` : "Bienvenido";

      activarTimerInactividad();
      invoke<boolean>("tiene_config_email").then(ok => {
        _smtpConfigurado = ok;
        if (ok) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
      }).catch(() => { });

      if (nombreGuardado === null) {
        mostrarPantalla("nombre");
      } else {
        mostrarPantalla("principal");
        cargarAjustesTraduccion().catch(() => {});
      }

    } else {
      mostrarMensaje("login-msg", "CREDENCIALES INCORRECTAS", true);
      limpiarCampo("login-pass");
      limpiarCampo("login-pass-usuario");
    }
  } catch (e) {
    mostrarMensaje("login-msg", "ERROR: " + String(e), true);
  }
}

function toggleContraseña(id: string): void {
  const input = document.getElementById(id) as HTMLInputElement;
  const btn = input?.nextElementSibling as HTMLElement;
  if (!input) return;
  if (input.type === "password") {
    input.type = "text";
    btn?.classList.add("activo");
  } else {
    input.type = "password";
    btn?.classList.remove("activo");
  }
}

// ============================================================
// CHAT — ENVIAR TEXTO
// Llama a traducir_texto en Rust — se conectará a ElAlgoritmo
// cuando esté listo. Por ahora usa el diccionario en memoria.
// ============================================================

async function enviarMensaje(): Promise<void> {
  const input = document.getElementById("chat-input") as HTMLTextAreaElement;
  const texto = input?.value?.trim() ?? "";
  if (!texto) return;

  añadirMensajeUsuario(texto);

  // Zeroize del input
  input.value = "0".repeat(input.value.length);
  input.value = "";
  input.style.height = "auto";

  mostrarProcesando(true);

  try {

    const origenSel = (document.getElementById("selector-origen") as HTMLSelectElement)?.value ?? "es";
    const destinoSel = (document.getElementById("selector-destino") as HTMLSelectElement)?.value ?? "en";
    const idiomaActual = origenSel !== destinoSel ? `${origenSel}_${destinoSel}` : "es_en";
    const [traducido, sinTraducir] = await invoke<[string, number]>("traducir_texto", { texto, idioma: idiomaActual });
    mostrarProcesando(false);
    añadirMensajeBabel(traducido, "BABEL · traducción completada");
    if (sinTraducir > 0) {
      añadirMensajeBabel(
        `⚠ ${sinTraducir} palabra${sinTraducir > 1 ? "s" : ""} sin traducir — aparecerán en el diccionario cuando ElAlgoritmo las aprenda.`,
        "BABEL · aviso"
      );
    }
  } catch {
    mostrarProcesando(false);
    añadirMensajeBabel("Error al traducir. Verifica que hay sesión activa.", "BABEL · error");
  }
}

// TRADUCCIÓN — VÍA SELECTOR DE ARCHIVO

// Importa y traduce un documento vía diálogo nativo (NSOpenPanel).
// El comando Rust emite "archivo-seleccionado" nada más elegir el archivo (antes de
// traducir), y el listener de abajo lo usa para mostrar la burbuja "TÚ" y la barra.
async function seleccionarArchivo(): Promise<void> {
  try {
    const ruta = await invoke<string | null>("traducir_documento_dialogo");
    if (!ruta) return;
    mostrarProcesando(false);
    const partes = ruta.replace(/\\/g, "/").split("/");
    añadirResultadoArchivo(partes[partes.length - 1], ruta);
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error procesando archivo: " + String(error), "BABEL · error");
  }
}

function manejarSeleccion(event: Event): void {
  const input = event.target as HTMLInputElement;
  const archivo = input.files?.[0];
  if (archivo) procesarArchivo(archivo);
}

async function procesarArchivo(archivo: File): Promise<void> {
  const pesoKB = (archivo.size / 1024).toFixed(0);
  const ext = archivo.name.split(".").pop()?.toUpperCase() ?? "FILE";
  await advertirCalidadPdf(archivo.name);
  añadirMensajeArchivo(archivo.name, `${pesoKB} KB · ${ext}`);
  mostrarProcesando(true);

  try {
    const rutaResultado = await invoke<string>("traducir_documento", {
      nombreArchivo: archivo.name,
      contenido: Array.from(new Uint8Array(await archivo.arrayBuffer()))
    });
    mostrarProcesando(false);
    const partes = rutaResultado.replace(/\\/g, "/").split("/");
    añadirResultadoArchivo(partes[partes.length - 1], rutaResultado);
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error procesando archivo: " + String(error), "BABEL · error");
  }
}

// TRADUCCIÓN — VÍA DRAG & DROP NATIVO

async function advertirCalidadPdf(nombreArchivo: string): Promise<void> {
  if (!nombreArchivo.toLowerCase().endsWith(".pdf")) return;
  try {
    const h = await invoke<{ pdf2docx: boolean; libreoffice: boolean }>("verificar_herramientas_pdf");
    if (!h.pdf2docx || !h.libreoffice) {
      const falta = [!h.pdf2docx ? "pdf2docx" : "", !h.libreoffice ? "LibreOffice" : ""]
        .filter(Boolean).join(" y ");
      añadirMensajeBabel(
        `PDF sin ${falta}: se guardará solo el texto traducido, sin formato. Instálalos para conservar maquetación.`,
        "BABEL · aviso"
      );
    }
  } catch { /* silencioso */ }
}

async function procesarRuta(ruta: string): Promise<void> {
  const partes = ruta.replace(/\\/g, "/").split("/");
  const nombreArchivo = partes[partes.length - 1];
  const ext = nombreArchivo.split(".").pop()?.toUpperCase() ?? "FILE";

  await advertirCalidadPdf(nombreArchivo);
  añadirMensajeArchivo(nombreArchivo, `Arrastrado · ${ext}`);
  mostrarProcesando(true);

  try {
    const rutaResultado = await invoke<string>("traducir_documento_ruta", { ruta, nombreArchivo });
    mostrarProcesando(false);
    const partesRes = rutaResultado.replace(/\\/g, "/").split("/");
    añadirResultadoArchivo(partesRes[partesRes.length - 1], rutaResultado);
    scrollAlFinal();
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error procesando archivo: " + String(error), "BABEL · error");
  }
}

// SESIÓN Y NAVEGACIÓN

function toggleSidebar(): void {
  const sidebar = document.getElementById("chat-sidebar");
  if (!sidebar) return;
  const estaOculto = sidebar.classList.contains("hidden");
  if (estaOculto) {
    sidebar.classList.remove("hidden");
    localStorage.setItem("babel-sidebar", "1");
  } else {
    sidebar.classList.add("hidden");
    localStorage.setItem("babel-sidebar", "0");
  }
}

function toggleBorrarOriginal(activado: boolean): void {
  localStorage.setItem(LS_NO_PREG_BORRAR_ORIG, activado ? "si" : "");
}

function toggleBorradoAutomatico(activado: boolean): void {
  borradoAutomaticoActivado = activado;
  guardarAjustesTraduccion().catch(() => {});
}

// ============================================================
// SIDEBAR — SELECTOR DE CATEGORÍA DE DICCIONARIO
// Cuando el usuario cambia el tipo de diccionario en el sidebar,
// Rust recarga el diccionario filtrando solo esa categoría.
// ============================================================

async function cambiarCategoriaDiccionario(categoria: string): Promise<void> {
  try {
    await invoke("cambiar_categoria_diccionario", { categoria });
    añadirMensajeBabel(
      `Diccionario actualizado: ${categoria === "todos" ? "TODOS los vocabularios" : categoria.toUpperCase()}`,
      "BABEL · diccionario"
    );
    guardarAjustesTraduccion().catch(() => {});
  } catch (error) {
    console.error("Error cambiando categoría:", error);
  }
}

// SIDEBAR — SELECTOR DE IDIOMA DE TRADUCCIÓN — Sincroniza el selector del sidebar con el del header

async function cerrarSesion(): Promise<void> {
  limpiarCamposSensibles();
  borrarChat();
  _sesionActiva = false;
  _sesionUsuario = "0".repeat(_sesionUsuario.length); _sesionUsuario = "";
  _firmaEmail = "0".repeat(_firmaEmail.length); _firmaEmail = "";
  _cuerpoEmailOriginal = "";
  desactivarTimerInactividad();
  try { await invoke("cerrar_sesion_rust"); } catch { /* continúa cerrando aunque falle */ }
  limpiarCamposSensibles();
  localStorage.removeItem("babel-nombre-display");
  localStorage.removeItem("babel-buzon-activo");
  localStorage.removeItem("babel-buzon-activo-g");
  localStorage.removeItem("babel-sidebar");
  localStorage.removeItem("babel-idioma-ui");
  localStorage.removeItem("babel-tema");
  window.location.reload();
}

function volverAtras(): void {
  limpiarCamposSensibles();
  mostrarPantalla("decision");
}

let borradoAutomaticoActivado: boolean = true;

function volverAlPanel(): void {
  if (borradoAutomaticoActivado) borrarChat();
  mostrarPantalla("principal");
}

function sincronizarSelectoresIdioma(origen: string, destino: string): void {
  const s1 = document.getElementById("selector-origen") as HTMLSelectElement | null;
  const s2 = document.getElementById("selector-destino") as HTMLSelectElement | null;
  const a1 = document.getElementById("ajuste-idioma-origen") as HTMLSelectElement | null;
  const a2 = document.getElementById("ajuste-idioma-destino") as HTMLSelectElement | null;
  if (s1) s1.value = origen;
  if (s2) s2.value = destino;
  if (a1) a1.value = origen;
  if (a2) a2.value = destino;
}

async function cambiarIdiomaDesdeSelectores(): Promise<void> {
  const origen = (document.getElementById("selector-origen") as HTMLSelectElement)?.value ?? "es";
  const destino = (document.getElementById("selector-destino") as HTMLSelectElement)?.value ?? "en";
  if (origen === destino) {
    mostrarToast("Origen y destino son el mismo idioma", true);
    return;
  }
  sincronizarSelectoresIdioma(origen, destino);
  await cambiarIdioma(`${origen}_${destino}`);
  guardarAjustesTraduccion().catch(() => {});
}

async function cambiarIdiomaDesdeAjustes(): Promise<void> {
  const origen = (document.getElementById("ajuste-idioma-origen") as HTMLSelectElement)?.value ?? "es";
  const destino = (document.getElementById("ajuste-idioma-destino") as HTMLSelectElement)?.value ?? "en";
  if (origen === destino) {
    mostrarToast("Origen y destino son el mismo idioma", true);
    return;
  }
  sincronizarSelectoresIdioma(origen, destino);
  await cambiarIdioma(`${origen}_${destino}`);
  guardarAjustesTraduccion().catch(() => {});
}

function swapIdiomaTraduccion(): void {
  const sel1 = document.getElementById("selector-origen") as HTMLSelectElement;
  const sel2 = document.getElementById("selector-destino") as HTMLSelectElement;
  if (!sel1 || !sel2) return;
  const tmp = sel1.value;
  sel1.value = sel2.value;
  sel2.value = tmp;
  cambiarIdiomaDesdeSelectores();
}

function actualizarContadorPalabras(texto: string): void {
  const el = document.getElementById("contador-palabras");
  if (!el) return;
  if (!texto.trim()) { el.textContent = ""; return; }
  const palabras = texto.trim().split(/\s+/).length;
  const chars = texto.length;
  el.textContent = `${palabras} palabra${palabras !== 1 ? "s" : ""} · ${chars} caracteres`;
}

function toggleBtnLimpiar(valor: string): void {
  const btn = document.getElementById("btn-limpiar-input") as HTMLButtonElement;
  if (btn) btn.style.display = valor ? "block" : "none";
}

function limpiarInputTraduccion(): void {
  const input = document.getElementById("chat-input") as HTMLTextAreaElement;
  if (!input) return;
  input.value = "";
  input.style.height = "auto";
  actualizarContadorPalabras("");
  toggleBtnLimpiar("");
  input.focus();
}

async function cambiarIdioma(idioma: string): Promise<void> {
  await invoke("cambiar_idioma", { idioma });
}

// ARCHIVOS — BUZONES Y LISTADO

// Variable global — buzón activo
let buzonActivoGuardados: string = "todos";
let terminoBusquedaArchivos = "";
let terminoBusquedaBuzones = "";
let _smtpConfigurado: boolean = false;
// Tipo que refleja el struct Rust MetadatosArchivo
interface MetadatosArchivo {
  nombre: string;
  ruta: string;
  tamaño: number;
  fecha: string;
  idioma: string;
  buzon: string;
  buzon_id: string;
  es_traduccion: boolean;
}

// Carga y renderiza los archivos del buzón de guardados (sin traducir)
async function cargarArchivosGuardados(): Promise<void> {
  try {
    const archivos = await invoke<MetadatosArchivo[]>("listar_archivos_guardados", { buzon: buzonActivoGuardados });
    const lista = document.getElementById("lista-guardados");
    const count = document.getElementById("count-guardados");
    if (!lista) return;

    const totalStr = archivos.length >= 1000 ? "1000+" : String(archivos.length);
    if (count) count.textContent = `${totalStr} archivo${archivos.length !== 1 ? "s" : ""}${archivos.length >= 1000 ? " (lista truncada)" : ""}`;

    if (archivos.length === 0) {
      lista.innerHTML = `<div class="archivos-vacio">
        <p>No hay archivos guardados</p>
        <p class="archivos-vacio-sub">Arrastra documentos aquí para cifrarlos</p>
      </div>`;
    } else {
      const limpiarNombre = (n: string) =>
        n.replace(/\.babel$/, "")
         .replace(/__orig/g, "")
         .replace(/^[a-z]{2}-[a-z]{2}_/, "")
         .replace(/_\d{8,}$/, "")
         .trim();

      type Par = { orig?: MetadatosArchivo; trad?: MetadatosArchivo; guardado?: MetadatosArchivo };
      const grupos = new Map<string, Par>();

      for (const a of archivos) {
        const base = limpiarNombre(a.nombre);
        if (!grupos.has(base)) grupos.set(base, {});
        const g = grupos.get(base)!;
        if (!a.es_traduccion) g.guardado = a;
        else if (a.idioma === "original") g.orig = a;
        else g.trad = a;
      }

      if (count) count.textContent = `${grupos.size} archivo${grupos.size !== 1 ? "s" : ""}`;

      lista.innerHTML = Array.from(grupos.entries()).map(([base, g]) => {
        const nombre = escapeHTML(base);

        const fuenteOrig = g.orig ?? g.guardado;
        if (g.trad && fuenteOrig) {
          const kb = (g.trad.tamaño / 1024).toFixed(0);
          const idioma = g.trad.idioma.replace("_", "→").toUpperCase();
          return `
<div class="archivo-card" data-ruta="${escapeHTML(g.trad.ruta)}" data-ruta-orig="${escapeHTML(fuenteOrig.ruta)}" data-base="${escapeHTML(base)}" data-busqueda="${escapeHTML(base.toLowerCase().replace(/[\s_]+/g," ").trim())}" data-guardado="false" data-buzon-id="${escapeHTML(g.trad.buzon_id ?? "todos")}" draggable="true">
  <div class="archivo-card-header">
    <input type="checkbox" class="archivo-checkbox-g" data-action="seleccionar" style="accent-color:var(--dorado);cursor:pointer;flex-shrink:0;width:16px;height:16px;">
    <div class="archivo-card-info">
      <div class="archivo-card-nombre" style="display:flex;align-items:center;gap:8px;"><span class="card-nombre-texto">${nombre}</span>
        <button type="button" data-action="renombrar" style="background:none;border:none;color:var(--dorado);cursor:pointer;font-size:0.85rem;padding:0;opacity:0.7;">✎</button>
      </div>
      <div class="archivo-card-meta">${kb} KB · <span style="color:var(--dorado);">${escapeHTML(idioma)} · TRAD</span> · AES-256${g.trad.fecha ? ' · ' + escapeHTML(g.trad.fecha) : ''}</div>
    </div>
  </div>
  <div class="archivo-card-botones">
    <button type="button" class="btn-archivo btn-archivo-ver" data-action="ver-comparacion">◫ VER COMPARACIÓN</button>
    <button type="button" class="btn-archivo btn-archivo-exportar" data-action="exportar">EXPORTAR</button>
    <button type="button" class="btn-archivo" data-action="mover" style="opacity:0.7;">MOVER</button>
    <button type="button" class="btn-archivo" data-action="enviar" style="opacity:0.7;">✉</button>
  </div>
</div>`;
        }

        const a = g.guardado ?? g.trad ?? g.orig!;
        const kb = (a.tamaño / 1024).toFixed(0);
        return `
<div class="archivo-card" data-ruta="${escapeHTML(a.ruta)}" data-base="${escapeHTML(base)}" data-busqueda="${escapeHTML(base.toLowerCase().replace(/[\s_]+/g," ").trim())}" data-guardado="true" data-buzon-id="${escapeHTML(a.buzon_id ?? "todos")}" draggable="true">
  <div class="archivo-card-header">
    <input type="checkbox" class="archivo-checkbox-g" data-action="seleccionar" style="accent-color:var(--dorado);cursor:pointer;flex-shrink:0;width:16px;height:16px;">
    <div class="archivo-card-info">
      <div class="archivo-card-nombre" style="display:flex;align-items:center;gap:8px;"><span class="card-nombre-texto">${nombre}</span>
        <button type="button" data-action="renombrar" style="background:none;border:none;color:var(--dorado);cursor:pointer;font-size:0.85rem;padding:0;opacity:0.7;">✎</button>
      </div>
      <div class="archivo-card-meta">${kb} KB · GUARDADO · AES-256${a.fecha ? ' · ' + escapeHTML(a.fecha) : ''}</div>
    </div>
  </div>
  <div class="archivo-card-botones">
    <button type="button" class="btn-archivo btn-archivo-ver" data-action="ver">VER</button>
    <button type="button" class="btn-archivo" data-action="traducir-guardado" style="color:var(--dorado);border-color:var(--dorado);">TRADUCIR</button>
    <button type="button" class="btn-archivo btn-archivo-exportar" data-action="exportar">EXPORTAR</button>
    <button type="button" class="btn-archivo" data-action="mover" style="opacity:0.7;">MOVER</button>
    <button type="button" class="btn-archivo" data-action="enviar" style="opacity:0.7;">✉</button>
  </div>
</div>`;
      }).join("");

      if (terminoBusquedaArchivos) filtrarArchivosGuardados(terminoBusquedaArchivos);
    }

    lista.onclick = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      const btn = target.closest("[data-action]") as HTMLElement | null;

      if (!btn) {
        const card = target.closest(".archivo-card") as HTMLElement | null;
        if (!card) return;
        if (terminoBusquedaArchivos) {
          // En búsqueda: navegar al buzón que contiene el archivo
          seleccionarBuzonGuardados(card.dataset.buzonId ?? "todos");
        } else {
          // Modo normal: abrir el archivo
          const ruta = card.dataset.ruta ?? "";
          const rutaOrig = card.dataset.rutaOrig ?? "";
          if (rutaOrig) verComparacionRutas(rutaOrig, ruta);
          else verArchivo(ruta);
        }
        return;
      }

      const accion = btn.dataset.action;
      if (accion === "seleccionar") { actualizarSeleccionGuardados(); return; }
      if (accion === "resultado-buzon") {
        seleccionarBuzonGuardados(btn.dataset.buzon ?? "todos");
        return;
      }
      const card = btn.closest(".archivo-card") as HTMLElement | null;
      if (!card) return;
      const ruta = card.dataset.ruta ?? "";
      const rutaOrig = card.dataset.rutaOrig ?? "";
      const base2 = card.dataset.base ?? "";
      switch (accion) {
        case "ver-comparacion":
          if (terminoBusquedaArchivos) { seleccionarBuzonGuardados(card.dataset.buzonId ?? "todos"); break; }
          verComparacionRutas(rutaOrig, ruta); break;
        case "ver":
          if (terminoBusquedaArchivos) { seleccionarBuzonGuardados(card.dataset.buzonId ?? "todos"); break; }
          verArchivo(ruta); break;
        case "traducir-guardado": traducirArchivoGuardado(ruta); break;
        case "exportar": exportarArchivo(ruta); break;
        case "mover": moverArchivoGuardadoPopup(ruta, e); break;
        case "enviar": enviarArchivoDesdeArchivos(ruta); break;
        case "renombrar": e.stopPropagation(); iniciarRenombradoArchivo(ruta, base2); break;
      }
    };
    lista.ondragstart = (e: DragEvent) => {
      const card = (e.target as HTMLElement).closest(".archivo-card") as HTMLElement | null;
      if (!card) return;
      _rutaArrastrada = card.dataset.ruta ?? "";
      _esGuardadoArrastrado = card.dataset.guardado === "true";
    };

  } catch (error) {
    mostrarToast("Error cargando lista: " + String(error), true);
    console.error("Error cargando guardados:", error);
  }
}

// Muestra/oculta botones de acción según checkboxes marcados en buzones guardados
function actualizarSeleccionGuardados(): void {
  const seleccionados = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  const btnVer = document.getElementById("btn-ver-sel-g");
  const btnEliminar = document.getElementById("btn-eliminar-sel-g");
  if (btnVer) btnVer.classList.toggle("hidden", seleccionados.length === 0);
  if (btnEliminar) btnEliminar.classList.toggle("hidden", seleccionados.length === 0);
}

function actualizarBadgeEmail(n: number): void {
  const badge = document.getElementById("email-badge");
  if (!badge) return;
  if (n > 0) {
    badge.textContent = n > 99 ? "99+" : String(n);
    badge.classList.remove("hidden");
  } else {
    badge.classList.add("hidden");
  }
}

function filtrarBuzonesGuardados(texto: string): void {
  terminoBusquedaBuzones = texto.trim();
  const lista = document.getElementById("lista-buzones-g");
  if (!lista) return;
  lista.querySelector(".buzon-sin-resultados")?.remove();
  const q = terminoBusquedaBuzones.toLowerCase();
  const items = lista.querySelectorAll<HTMLElement>(".buzon-item");
  let hayResultados = false;
  items.forEach(item => {
    const nombre = (item.querySelector(".buzon-nombre")?.textContent ?? "").toLowerCase();
    if (nombre === "todos") { item.style.display = ""; return; }
    const visible = !q || nombre.includes(q);
    item.style.display = visible ? "" : "none";
    if (visible) hayResultados = true;
  });
  if (q && !hayResultados) {
    const div = document.createElement("div");
    div.className = "buzon-sin-resultados";
    div.style.cssText = "padding:8px 10px;font-size:0.58rem;letter-spacing:1px;color:var(--texto-secundario);opacity:0.5;text-align:center;";
    div.textContent = "Sin resultados";
    lista.appendChild(div);
  }
}

// Activa un buzón guardado y recarga su contenido
function seleccionarBuzonGuardados(id: string): void {
  buzonActivoGuardados = id;
  localStorage.setItem("babel-buzon-activo-g", id);
  terminoBusquedaArchivos = "";
  const inp = document.getElementById("buscar-archivos-g") as HTMLInputElement | null;
  if (inp) inp.value = "";
  const limpiar = document.getElementById("buscar-archivos-limpiar");
  if (limpiar) limpiar.classList.add("hidden");
  cargarBuzonesGuardados();
  cargarArchivosGuardados();
}

function filtrarArchivosGuardados(texto: string): void {
  terminoBusquedaArchivos = texto.trim();
  const lista = document.getElementById("lista-guardados");
  if (!lista) return;

  lista.querySelectorAll(".resultado-busqueda-inject").forEach(el => el.remove());
  lista.querySelector(".sin-resultados-busqueda")?.remove();

  const limpiar = document.getElementById("buscar-archivos-limpiar");
  if (limpiar) limpiar.classList.toggle("hidden", !terminoBusquedaArchivos);

  const vacioPermanente = lista.querySelector<HTMLElement>(".archivos-vacio");
  if (vacioPermanente) vacioPermanente.style.display = terminoBusquedaArchivos ? "none" : "";

  const normalizar = (s: string) => s.toLowerCase().replace(/[\s_ ]+/g, " ").trim();
  const q = normalizar(terminoBusquedaArchivos);
  const count = document.getElementById("count-guardados");

  const cards = lista.querySelectorAll<HTMLElement>(".archivo-card");
  let archivosVisibles = 0;
  cards.forEach(card => {
    const visible = !q || (card.dataset.busqueda ?? normalizar(card.dataset.base ?? "")).includes(q);
    card.style.display = visible ? "" : "none";
    if (visible) archivosVisibles++;
  });

  if (!q) {
    if (count) count.textContent = `${archivosVisibles} archivo${archivosVisibles !== 1 ? "s" : ""}`;
    return;
  }

  const buzonIds = new Set<string>();
  // Solo mostrar carpetas contenedoras cuando estamos en la vista "todos".
  // Si ya estamos dentro de un buzón específico, la carpeta es obvia y repetirla es ruido.
  if (buzonActivoGuardados === "todos") {
    cards.forEach(card => {
      if (card.style.display !== "none") {
        const bid = card.dataset.buzonId;
        if (bid && bid !== "todos") buzonIds.add(bid);
      }
    });
  }
  const buzonesMatch = _buzonesCache.filter(b => buzonIds.has(b.id));
  const frag = document.createDocumentFragment();

  if (buzonesMatch.length > 0) {
    const h = document.createElement("div");
    h.className = "resultado-seccion-titulo resultado-busqueda-inject";
    h.textContent = "CARPETAS";
    frag.appendChild(h);
    buzonesMatch.forEach(b => {
      const row = document.createElement("div");
      row.className = "resultado-buzon-item resultado-busqueda-inject";
      row.dataset.action = "resultado-buzon";
      row.dataset.buzon = b.id;
      row.innerHTML = `<span class="resultado-buzon-icono">\u25ab</span><span class="resultado-buzon-nombre">${escapeHTML(b.nombre.toUpperCase())}</span><span class="resultado-buzon-badge">CARPETA</span>`;
      frag.appendChild(row);
    });
  }

  if (archivosVisibles > 0) {
    const h = document.createElement("div");
    h.className = "resultado-seccion-titulo resultado-busqueda-inject";
    h.textContent = "ARCHIVOS";
    frag.appendChild(h);
  }

  lista.prepend(frag);

  const total = buzonesMatch.length + archivosVisibles;
  if (count) count.textContent = `${total} resultado${total !== 1 ? "s" : ""}`;

  if (total === 0) {
    const div = document.createElement("div");
    div.className = "sin-resultados-busqueda archivos-vacio resultado-busqueda-inject";
    div.innerHTML = `<p>Sin resultados</p><p class="archivos-vacio-sub">«${escapeHTML(q)}» no coincide con nada</p>`;
    lista.appendChild(div);
  }
}

// LS keys para preferencias "no volver a preguntar"
const LS_NO_PREG_BORRAR_ORIG = "babel_noPreg_borrarOrig";
const LS_NO_PREG_ELIMINAR    = "babel_noPreg_eliminar";

async function confirmarEliminar(n: number): Promise<boolean> {
  return confirmarConCheckbox({
    titulo: "ELIMINAR ARCHIVO",
    msg: `¿Eliminar ${n === 1 ? "este archivo" : `estos ${n} archivos`} de forma permanente?`,
    riesgos: [
      "El archivo será destruido con 3 pasadas de sobreescritura.",
      "No puede recuperarse de ninguna forma, ni con software de recuperación.",
      "Asegúrate de que no necesitas acceder a él nunca más.",
    ],
    textoOk: "ELIMINAR",
    lsKey: LS_NO_PREG_ELIMINAR,
  });
}

async function borrarRutas(rutas: string[]): Promise<number> {
  let errores = 0;
  for (const ruta of rutas) {
    try { await invoke("eliminar_archivo", { ruta }); }
    catch { errores++; }
  }
  return errores;
}

// Modal de confirmación reutilizable con checkbox "no volver a preguntar".
// Guarda en localStorage la elección del usuario si marca el checkbox.
// respetarNo: si true, un "no" guardado resuelve false sin mostrar el modal.
function confirmarConCheckbox(cfg: {
  titulo: string;
  msg: string;
  riesgos: string[];
  textoOk: string;
  lsKey: string;
  respetarNo?: boolean;
}): Promise<boolean> {
  const pref = localStorage.getItem(cfg.lsKey);
  if (pref === "si") return Promise.resolve(true);
  if (cfg.respetarNo && pref === "no") return Promise.resolve(false);

  return new Promise(resolve => {
    const modal     = document.getElementById("modal-confirmar")!;
    const tituloEl  = document.getElementById("modal-confirmar-titulo")!;
    const msgEl     = document.getElementById("modal-confirmar-msg")!;
    const riesgosEl = document.getElementById("modal-confirmar-riesgos")!;
    const noVolvEl  = document.getElementById("modal-confirmar-no-volver") as HTMLInputElement;
    const okBtn     = document.getElementById("modal-confirmar-ok")!;
    const cancelBtn = document.getElementById("modal-confirmar-cancelar")!;

    tituloEl.textContent = cfg.titulo;
    msgEl.textContent    = cfg.msg;
    riesgosEl.innerHTML  = cfg.riesgos.map(r => `<li>${escapeHTML(r)}</li>`).join("");
    okBtn.textContent    = cfg.textoOk;
    noVolvEl.checked     = false;

    modal.classList.remove("hidden");

    const cerrar = () => modal.classList.add("hidden");

    okBtn.onclick = () => {
      if (noVolvEl.checked) localStorage.setItem(cfg.lsKey, "si");
      cerrar(); resolve(true);
    };
    cancelBtn.onclick = () => {
      if (noVolvEl.checked) localStorage.setItem(cfg.lsKey, "no");
      cerrar(); resolve(false);
    };
  });
}

// Importa un archivo mediante el diálogo de selección nativo (NSOpenPanel).
// Tras cifrar y guardar, muestra un modal propio para preguntar si borrar el original,
// con opción de "no volver a preguntar" que se persiste en localStorage.
async function abrirImportarGuardado(): Promise<void> {
  try {
    const res = await invoke<{
      ruta_cifrada: string;
      nombre: string;
      original_borrado: boolean;
      tiene_original: boolean;
      token_borrado: string | null;
    } | null>("importar_archivo_dialogo");

    if (!res) return;

    if (buzonActivoGuardados !== "todos") {
      try {
        await invoke("mover_archivo_guardado", { ruta: res.ruta_cifrada, buzonDestino: buzonActivoGuardados });
      } catch (e) {
        console.error("Error moviendo al buzón:", e);
      }
    }

    let originalBorrado = false;
    if (res.tiene_original) {
      const confirmar = await confirmarConCheckbox({
        titulo: "BORRAR ORIGINAL",
        msg: "¿Eliminar el archivo original del ordenador?",
        riesgos: [
          "El archivo ya ha sido cifrado y guardado en Babel.",
          "Si eliminas el original, solo podrás acceder a él desde Babel.",
          "El borrado es de 3 pasadas — no puede recuperarse de ninguna forma.",
        ],
        textoOk: "ELIMINAR ORIGINAL",
        lsKey: LS_NO_PREG_BORRAR_ORIG,
        respetarNo: true,
      });
      if (confirmar) {
        try {
          originalBorrado = await invoke<boolean>("borrar_archivo_original", { token: res.token_borrado ?? "" });
        } catch (e) {
          mostrarToast(`Error al eliminar original: ${e}`, true);
        }
      }
    }

    const sufijo = originalBorrado ? " · original destruido de forma segura" : "";
    mostrarToast(`✓ ${res.nombre} guardado y cifrado${sufijo}`, false);
    await cargarArchivosGuardados();
  } catch (error) {
    mostrarToast(`Error importando: ${error}`, true);
  }
}

async function verArchivoGuardado(): Promise<void> {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  if (checkboxes.length === 0) return;

  const card = checkboxes[0].closest(".archivo-card") as HTMLElement;
  const ruta = card?.dataset.ruta;
  if (!ruta) return;

  try {
    const texto = await invoke<string>("ver_archivo", { ruta });
    const nombre = ruta.split("/").pop() ?? ruta;

    const modal = document.getElementById("modal-visor");
    const modalNombre = document.getElementById("modal-visor-nombre");
    const modalContenido = document.getElementById("modal-visor-contenido");

    if (!modal || !modalNombre || !modalContenido) return;
    modalNombre.textContent = nombre;
    renderizarEnContenedor(texto, modalContenido);
    modal.classList.remove("hidden");
  } catch (e) {
    mostrarToast("Error abriendo archivo: " + e, true);
  }
}
async function iniciarRenombradoGuardado(id: string, nombreActual: string): Promise<void> {
  _renombraViejoG = id;
  _renombraEsGuardado = true;
  const modal = document.getElementById("modal-renombrar");
  const input = document.getElementById("input-renombrar-buzon") as HTMLInputElement;
  if (!modal || !input) return;
  input.value = nombreActual;
  modal.classList.remove("hidden");
  input.focus();
  input.select();
}
async function iniciarRenombradoArchivo(ruta: string, nombreActual: string): Promise<void> {
  _renombraArchivoRuta = ruta;
  const modal = document.getElementById("modal-renombrar-archivo");
  const input = document.getElementById("input-renombrar-archivo") as HTMLInputElement;
  if (!modal || !input) return;
  input.value = nombreActual;
  modal.classList.remove("hidden");
  input.focus();
  input.select();
}

async function confirmarRenombrarArchivo(): Promise<void> {
  const input = document.getElementById("input-renombrar-archivo") as HTMLInputElement;
  const nombreNuevo = input?.value.trim() ?? "";
  cerrarModalRenombrarArchivo();
  if (!nombreNuevo) return;
  try {
    await invoke("renombrar_archivo", { ruta: _renombraArchivoRuta, nombreNuevo });
    await cargarArchivosGuardados();
    mostrarToast("Archivo renombrado", false);
  } catch (e) {
    mostrarToast("Error al renombrar", true);
  }
}

function cerrarModalRenombrarArchivo(): void {
  document.getElementById("modal-renombrar-archivo")?.classList.add("hidden");
}
// Elimina todos los archivos guardados seleccionados y recarga la lista
async function eliminarSeleccionadosGuardados(): Promise<void> {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  if (!checkboxes.length || !await confirmarEliminar(checkboxes.length)) return;
  const rutas: string[] = [];
  checkboxes.forEach(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement;
    if (card?.dataset.ruta) rutas.push(card.dataset.ruta);
    if (card?.dataset.rutaOrig) rutas.push(card.dataset.rutaOrig);
  });
  const errores = await borrarRutas(rutas);
  document.getElementById("btn-ver-sel-g")?.classList.add("hidden");
  document.getElementById("btn-eliminar-sel-g")?.classList.add("hidden");
  mostrarToast(errores ? `${errores} errores al eliminar` : "✓ Destruido de forma segura — irrecuperable", errores > 0);
  await cargarArchivosGuardados();
}

let dropZoneInicializada = false;

async function iniciarDropZone(): Promise<void> {
  if (dropZoneInicializada) return;

  await getCurrentWindow().onDragDropEvent(async (event) => {
    const enTraduccion = !document.getElementById("pantalla-traduccion")?.classList.contains("hidden");
    const enGuardados = !document.getElementById("pantalla-archivos-guardados")?.classList.contains("hidden");
    if (!enTraduccion && !enGuardados) return;

    const barra = document.getElementById("chat-input-barra");
    const zona = document.getElementById("drop-zone-guardados");
    const resetZona = () => {
      barra?.classList.remove("drag-activo");
      if (zona) { zona.style.borderColor = "var(--borde)"; zona.style.background = "transparent"; }
    };

    if (event.payload.type === "over") {
      if (enTraduccion) barra?.classList.add("drag-activo");
      if (enGuardados && zona) { zona.style.borderColor = "var(--dorado)"; zona.style.background = "rgba(197,160,89,0.05)"; }
    } else if (event.payload.type === "drop") {
      resetZona();
      const rutas = event.payload.paths;
      if (rutas && rutas.length > 0) {
        if (enTraduccion) procesarRuta(rutas[0]);
        if (enGuardados) for (const ruta of rutas) await guardarArchivoSinTraducir(ruta);
      }
    } else {
      resetZona();
    }
  });

  dropZoneInicializada = true;
}
// NAVEGACIÓN — ENTRE PANTALLAS Y ACCIONES DE ARCHIVO

// Abre en Finder la carpeta de archivos guardados cifrados
async function abrirCarpetaBabelGuardados(): Promise<void> {
  try {
    await invoke("abrir_carpeta_guardados");
  } catch (e) {
    mostrarToast("Error abriendo Finder: " + e, true);
  }
}

function irATraduccion(): void {
  mostrarPantalla("traduccion");
  setTimeout(() => iniciarDropZone(), 100);
}

// Cifra y guarda un archivo arrastrado sin traducirlo (solo cifrado)
async function guardarArchivoSinTraducir(rutaArchivo: string): Promise<void> {
  const nombre = rutaArchivo.split("/").pop() || "archivo";

  if (nombre.endsWith(".babel")) {
    mostrarToast("Los archivos .babel ya están cifrados", true);
    return;
  }

  // Verificar duplicados contra el sistema de archivos real (no solo DOM visible)
  const nombreBase = nombre.replace(/\.[^/.]+$/, "");
  const yaExiste = await invoke<boolean>("archivo_guardado_existe", { nombreBase }).catch(() => false);
  if (yaExiste) {
    mostrarToast(`"${nombre}" ya está guardado`, true);
    return;
  }

  try {
    const rutaCifrada = await invoke<string>("guardar_documento_sin_traducir", {
      nombreArchivo: nombre,
      rutaCompleta: rutaArchivo,

    });
    if (buzonActivoGuardados !== "todos") {
      try {
        await invoke("mover_archivo_guardado", { ruta: rutaCifrada, buzonDestino: buzonActivoGuardados });
      } catch (e) {
        console.error("Error moviendo al buzón:", e);
      }
    }
    mostrarToast(`✓ ${nombre} guardado y cifrado`, false);
    await cargarArchivosGuardados();

  } catch (error) {
    mostrarToast(`Error guardando: ${error}`, true);
  }
}

async function irAArchivos(): Promise<void> {
  mostrarPantalla("archivos-guardados");
  setTimeout(() => iniciarDropZone(), 100);
  await cargarBuzonesGuardados();
  await cargarArchivosGuardados();
}

// BUZONES DE GUARDADOS — CREAR, CARGAR, BORRAR, RENOMBRAR

// Carga el árbol de buzones guardados y lo renderiza en el sidebar
async function cargarBuzonesGuardados(): Promise<void> {
  try {
    const nodos = await invoke<BuzonNodo[]>("listar_buzones_guardados");
    _buzonesCache = nodos;
    const lista = document.getElementById("lista-buzones-g");
    if (!lista) return;
    lista.innerHTML = `
      <div class="buzon-item ${buzonActivoGuardados === "todos" ? "activo" : ""}" data-action="seleccionar-buzon-guardados" data-buzon="todos">
        <span class="buzon-icono">◫</span><span class="buzon-nombre">TODOS</span>
      </div>` + renderArbolBuzones(nodos, null, 0, buzonActivoGuardados, "guard");
    if (terminoBusquedaBuzones) filtrarBuzonesGuardados(terminoBusquedaBuzones);
  } catch (error) {
    console.error("Error cargando buzones guardados:", error);
  }
}

// Crea un nuevo buzón guardado (o subbuzón si se pasa parentId)
async function confirmarBuzonGuardado(): Promise<void> {
  const campo = document.getElementById("nombre-buzon-input-g") as HTMLInputElement;
  const nombre = campo?.value?.trim().toLowerCase();
  if (!nombre) return;
  try {
    await invoke("crear_buzon_guardado", { nombre, parent: buzonParentPendienteG });
    buzonParentPendienteG = null;
    cancelarBuzonGuardado();
    await cargarBuzonesGuardados();
  } catch (error) {
    console.error("Error creando buzón guardado:", error);
  }
}

// Muestra el input para crear un nuevo buzón en la sección de guardados
function mostrarInputBuzonGuardado(parentId: string | null = null): void {
  buzonParentPendienteG = parentId;
  const input = document.getElementById("input-buzon-nuevo-g");
  const campo = document.getElementById("nombre-buzon-input-g") as HTMLInputElement;
  input?.classList.remove("hidden");
  campo?.focus();
}

// Oculta el input y limpia el campo sin crear el buzón guardado
function cancelarBuzonGuardado(): void {
  const input = document.getElementById("input-buzon-nuevo-g");
  const campo = document.getElementById("nombre-buzon-input-g") as HTMLInputElement;
  input?.classList.add("hidden");
  if (campo) campo.value = "";
}

// Elimina un buzón guardado (y todos sus hijos) y recarga la lista
async function borrarBuzonGuardado(id: string): Promise<void> {
  try {
    await invoke("eliminar_buzon_guardado", { id });
    if (buzonActivoGuardados === id) buzonActivoGuardados = "todos";
    await cargarBuzonesGuardados();
  } catch (error) {
    console.error("Error borrando buzón guardado:", error);
  }
}

// MOVER ARCHIVOS GUARDADOS — popup selector de buzón destino

async function moverArchivoGuardadoPopup(ruta: string, event: MouseEvent): Promise<void> {
  document.querySelectorAll(".selector-buzon-popup").forEach(el => el.remove());
  let nodos: BuzonNodo[];
  const cmdBuzones = ruta.includes("/guardados/") ? "listar_buzones_guardados" : "listar_buzones";
  try { nodos = await invoke<BuzonNodo[]>(cmdBuzones); } catch (e) { mostrarToast("Error cargando buzones: " + String(e), true); return; }
  const popup = document.createElement("div");
  popup.className = "selector-buzon-popup";
  popup.style.cssText = `position:fixed;background:#0d0d0d;border:1px solid var(--dorado);border-radius:3px;z-index:999;min-width:160px;box-shadow:0 4px 20px rgba(0,0,0,0.5);max-height:60vh;overflow-y:auto;`;
  const top = event.clientY + 4;
  const left = event.clientX;

  const construirPopup = () => {
    popup.innerHTML = "";
    const agregar = (label: string, id: string, indent: number, tieneHijos: boolean) => {
      const item = document.createElement("div");
      const colapsado = buzonesColapsados.has(id);
      item.style.cssText = `display:flex;align-items:center;padding:8px ${16 + indent * 12}px;font-family:'Times New Roman', Times, serif;font-size:0.7rem;letter-spacing:2px;color:var(--dorado);cursor:pointer;`;
      if (tieneHijos) {
        const toggle = document.createElement("span");
        toggle.textContent = colapsado ? "▶ " : "▼ ";
        toggle.style.cssText = "font-size:0.55rem;opacity:0.6;margin-right:4px;";
        toggle.onclick = (e) => { e.stopPropagation(); buzonesColapsados.has(id) ? buzonesColapsados.delete(id) : buzonesColapsados.add(id); construirPopup(); };
        item.appendChild(toggle);
      } else {
        const spacer = document.createElement("span");
        spacer.style.cssText = "display:inline-block;width:14px;";
        item.appendChild(spacer);
      }
      const texto = document.createElement("span");
      texto.textContent = label;
      item.appendChild(texto);
      item.onmouseenter = () => item.style.background = "rgba(197,160,89,0.1)";
      item.onmouseleave = () => item.style.background = "";
      item.onclick = async () => {
        popup.remove();
        try {
          const cmd = ruta.includes("/guardados/") ? "mover_archivo_guardado" : "mover_archivo";
          await invoke(cmd, { ruta, buzonDestino: id });
          await cargarArchivosGuardados();
          mostrarToast(`Movido a ${label}`, false);
        } catch (error) { mostrarToast("Error: " + String(error), true); }
      };
      popup.appendChild(item);
    };
    agregar("TODOS", "todos", 0, false);
    const renderNodos = (parentId: string | null, depth: number) => {
      nodos.filter(n => n.parent === parentId).forEach(n => {
        const tieneHijos = nodos.some(h => h.parent === n.id);
        agregar(n.nombre.toUpperCase(), n.id, depth, tieneHijos);
        if (!buzonesColapsados.has(n.id)) renderNodos(n.id, depth + 1);
      });
    };
    renderNodos(null, 0);
  };

  construirPopup();
  popup.style.top = top + "px";
  popup.style.left = left + "px";
  document.body.appendChild(popup);
  setTimeout(() => { document.addEventListener("click", () => popup.remove(), { once: true }); }, 0);
}
// RENOMBRAR BUZONES — modal compartido para traducciones y guardados

// Abre el modal de renombrado para un buzón de traducciones (por ID)
async function iniciarRenombrado(id: string, nombreActual: string): Promise<void> {
  _renombraViejo = id;
  _renombraEsGuardado = false;
  const modal = document.getElementById("modal-renombrar");
  const input = document.getElementById("input-renombrar-buzon") as HTMLInputElement;
  if (!modal || !input) return;
  input.value = nombreActual;
  modal.classList.remove("hidden");
  input.focus();
  input.select();
}

async function confirmarRenombrar(): Promise<void> {
  const input = document.getElementById("input-renombrar-buzon") as HTMLInputElement;
  const nombreNuevo = input?.value.trim() ?? "";
  const esGuardado = _renombraEsGuardado;
  cerrarModalRenombrar();
  if (!nombreNuevo) return;
  try {
    if (esGuardado) {
      await invoke("renombrar_buzon_guardado", { id: _renombraViejoG, nombreNuevo });
      await cargarBuzonesGuardados();
    } else {
      await invoke("renombrar_buzon", { id: _renombraViejo, nombreNuevo });
    }
  } catch (e) {
    console.error("Error renombrando:", e);
    mostrarToast("Error al renombrar", true);
  }
}

// Cierra el modal de renombrado sin guardar cambios
function cerrarModalRenombrar(): void {
  document.getElementById("modal-renombrar")?.classList.add("hidden");
  _renombraEsGuardado = false;
}

// Descifra y exporta un archivo .babel — el usuario elige dónde guardarlo
async function exportarArchivo(ruta: string): Promise<void> {
  try {
    await invoke<string>("exportar_archivo", { ruta });
    mostrarToast("✓ Exportado correctamente", false);
  } catch (error) {
    const msg = String(error);
    if (msg.includes("cancelada") || msg.includes("cancelado")) return;
    mostrarToast("Error exportando: " + msg, true);
  }
}
// Exporta múltiples archivos con un único folder picker
async function exportarTodo(): Promise<void> {
  try {
    const archivos = await invoke<any[]>("listar_archivos_guardados", { buzon: "todos" });
    if (archivos.length === 0) { mostrarToast("No hay archivos para exportar", true); return; }
    const rutas = archivos.map((a: any) => a.ruta);
    const copiados = await invoke<number>("exportar_archivos_a_carpeta", { rutas });
    mostrarToast(`✓ ${copiados} archivos exportados`, false);
  } catch (error) {
    const msg = String(error);
    if (msg.includes("cancelada") || msg.includes("cancelado")) return;
    mostrarToast("Error: " + msg, true);
  }
}

// TOAST — NOTIFICACIONES TEMPORALES

// Muestra una notificación temporal en la parte inferior de la pantalla
function mostrarToast(mensaje: string, esError: boolean): void {
  const toast = document.createElement("div");
  toast.textContent = mensaje;
  toast.style.cssText = `
    position: fixed;
    bottom: 32px;
    left: 50%;
    transform: translateX(-50%);
    background: ${esError ? "#3a1a1a" : "#1a2a1a"};
    color: ${esError ? "#ff6b6b" : "var(--dorado)"};
    border: 1px solid ${esError ? "#ff6b6b44" : "var(--dorado)"};
    padding: 12px 28px;
    font-family: var(--fuente-titulo, 'Times New Roman', Times, serif);
    font-size: 0.85rem;
    letter-spacing: 0.12em;
    border-radius: 2px;
    z-index: 9999;
    opacity: 0;
    transition: opacity 0.3s ease;
  `;
  document.body.appendChild(toast);
  requestAnimationFrame(() => { toast.style.opacity = "1"; });
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Modal de seguridad persistente — amenaza detectada por el monitor en segundo plano.
// No se cierra automáticamente: el usuario debe escribir CONFIRMAR para continuar bajo riesgo.
function mostrarAlertaAmenaza(amenazas: string[]): void {
  if (document.getElementById("babel-amenaza-overlay")) return;
  const font = "var(--fuente-titulo,'Times New Roman',Times,serif)";
  const items = amenazas.map(a => `<li style="margin:4px 0;color:#ffaaaa;">${escapeHTML(a)}</li>`).join("");
  const overlay = document.createElement("div");
  overlay.id = "babel-amenaza-overlay";
  overlay.style.cssText = `position:fixed;inset:0;background:rgba(0,0,0,0.82);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:${font};`;
  overlay.innerHTML = `
    <div style="background:#1a0a0a;border:1px solid #ff4444;border-radius:4px;padding:36px 40px;max-width:480px;width:90%;box-shadow:0 0 40px #ff000044;text-align:center;">
      <div style="font-size:2rem;margin-bottom:16px;">⚠</div>
      <h2 style="color:#ff6b6b;font-size:1rem;letter-spacing:0.15em;margin:0 0 12px;">AMENAZA DETECTADA</h2>
      <p style="color:#aaa;font-size:0.8rem;letter-spacing:0.08em;margin:0 0 18px;">El monitor de seguridad ha detectado software potencialmente peligroso activo en este sistema:</p>
      <ul style="list-style:none;padding:0;margin:0 0 24px;font-size:0.78rem;letter-spacing:0.06em;text-align:left;">${items}</ul>
      <p style="color:#888;font-size:0.72rem;margin:0 0 20px;letter-spacing:0.06em;">Recomendación: cierra la sesión y verifica tu sistema antes de continuar.</p>
      <p style="color:#666;font-size:0.72rem;margin:0 0 8px;">Para continuar bajo riesgo escribe CONFIRMAR:</p>
      <input id="_amenaza-input" type="text" placeholder="CONFIRMAR" style="background:#0d0d0d;color:#aaa;border:1px solid #333;padding:8px 14px;font-family:${font};font-size:0.78rem;letter-spacing:0.1em;border-radius:2px;width:100%;box-sizing:border-box;margin-bottom:20px;text-align:center;">
      <div style="display:flex;gap:12px;justify-content:center;">
        <button id="_amenaza-cerrar" style="background:#3a0a0a;color:#ff6b6b;border:1px solid #ff444466;padding:10px 22px;font-family:${font};font-size:0.78rem;letter-spacing:0.12em;border-radius:2px;cursor:pointer;">CERRAR SESIÓN</button>
        <button id="_amenaza-continuar" style="background:#111;color:#555;border:1px solid #222;padding:10px 22px;font-family:${font};font-size:0.78rem;letter-spacing:0.12em;border-radius:2px;cursor:not-allowed;">CONTINUAR</button>
      </div>
    </div>`;
  document.body.appendChild(overlay);
  const input = overlay.querySelector<HTMLInputElement>("#_amenaza-input")!;
  const btnC = overlay.querySelector<HTMLButtonElement>("#_amenaza-continuar")!;
  input.addEventListener("input", () => {
    const ok = input.value.trim().toUpperCase() === "CONFIRMAR";
    btnC.style.color = ok ? "#888" : "#555";
    btnC.style.borderColor = ok ? "#444" : "#222";
    btnC.style.cursor = ok ? "pointer" : "not-allowed";
  });
  overlay.querySelector("#_amenaza-cerrar")!.addEventListener("click", () => { overlay.remove(); cerrarSesion(); });
  btnC.addEventListener("click", () => { if (input.value.trim().toUpperCase() === "CONFIRMAR") overlay.remove(); });
}

// Elimina todos los archivos seleccionados con zeroize
async function eliminarSeleccionados(): Promise<void> {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox:checked");
  if (!checkboxes.length || !await confirmarEliminar(checkboxes.length)) return;
  const rutas = Array.from(checkboxes)
    .map(cb => (cb.closest(".archivo-card") as HTMLElement)?.dataset.ruta)
    .filter((r): r is string => !!r);
  const errores = await borrarRutas(rutas);
  await cargarArchivosGuardados();
  mostrarToast(errores ? `${errores} archivos no se pudieron eliminar` : "✓ Destruido de forma segura — irrecuperable", errores > 0);
}
// CIERRE AUTOMÁTICO POR INACTIVIDAD
let timerInactividad: ReturnType<typeof setTimeout> | null = null;
let timerAvisoLock: ReturnType<typeof setTimeout> | null = null;
let _blurLockTimer: ReturnType<typeof setTimeout> | null = null; // Parche 1: bloqueo al perder foco
let _tiempoLockMs: number = 15 * 60 * 1000; // default hasta que carguen los ajustes

function resetearTimerInactividad(): void {
  if (timerInactividad) clearTimeout(timerInactividad);
  if (timerAvisoLock) clearTimeout(timerAvisoLock);
  timerInactividad = setTimeout(() => { bloquearPantalla(); }, _tiempoLockMs);
  const avisoMs = _tiempoLockMs - 2 * 60 * 1000;
  if (avisoMs > 0) {
    timerAvisoLock = setTimeout(() => {
      mostrarToast("La sesión se bloqueará en 2 minutos por inactividad", true);
    }, avisoMs);
  }
}

async function bloquearPantalla(): Promise<void> {
  desactivarTimerInactividad();
  _sesionActiva = false;
  try { await invoke("cerrar_sesion_rust"); } catch { /* continúa bloqueando aunque falle */ }
  const overlay = document.getElementById("pantalla-bloqueo");
  if (overlay) {
    overlay.classList.remove("hidden");
    setTimeout(() => {
      (document.getElementById("bloqueo-maestra") as HTMLInputElement | null)?.focus();
    }, 100);
  } else {
    cerrarSesion();
  }
}

async function desbloquearPantalla(): Promise<void> {
  const maestraEl = document.getElementById("bloqueo-maestra") as HTMLInputElement | null;
  const passEl = document.getElementById("bloqueo-pass") as HTMLInputElement | null;
  if (!maestraEl || !passEl) return;
  const maestra = maestraEl.value;
  const pass = passEl.value;
  if (!maestra || !pass) {
    mostrarMensaje("bloqueo-msg", "INTRODUCE TUS CREDENCIALES", true);
    return;
  }
  try {
    const ok = await invoke<boolean>("verificar_login", { pass: maestra, passUsuario: pass });
    if (ok) {
      _sesionActiva = true;
      maestraEl.value = "";
      passEl.value = "";
      const msgEl = document.getElementById("bloqueo-msg");
      if (msgEl) { msgEl.textContent = ""; msgEl.classList.add("hidden"); }
      _sesionUsuario = localStorage.getItem("babel-nombre-display") ?? "";
      document.getElementById("pantalla-bloqueo")?.classList.add("hidden");
      activarTimerInactividad();
      invoke<boolean>("tiene_config_email").then(ok2 => {
        _smtpConfigurado = ok2;
        if (ok2) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
      }).catch(() => {});
      cargarAjustesTraduccion().catch(() => {});
    } else {
      mostrarMensaje("bloqueo-msg", "CREDENCIALES INCORRECTAS", true);
      passEl.value = "";
    }
  } catch (e) {
    mostrarMensaje("bloqueo-msg", "ERROR: " + String(e), true);
  }
}

function activarTimerInactividad(): void {
  ["mousemove", "keydown", "mousedown", "touchstart", "click"].forEach(evento => {
    document.addEventListener(evento, resetearTimerInactividad);
  });
  resetearTimerInactividad();
}

function desactivarTimerInactividad(): void {
  if (timerInactividad) clearTimeout(timerInactividad);
  if (timerAvisoLock) clearTimeout(timerAvisoLock);
  ["mousemove", "keydown", "mousedown", "touchstart", "click"].forEach(evento => {
    document.removeEventListener(evento, resetearTimerInactividad);
  });
}
// VISOR INDIVIDUAL — modal simple

async function traducirArchivoGuardado(ruta: string): Promise<void> {
  irATraduccion();
  const nombreOrig = ruta.replace(/\\/g, "/").split("/").pop() ?? "archivo.babel";
  const nombreMostrado = nombreOrig.replace(/\.babel$/, "").replace(/^\d+_/, "");
  añadirMensajeArchivo(nombreMostrado, "GUARDADO · babel");
  mostrarProcesando(true);
  try {
    const rutaResultado = await invoke<string>("traducir_archivo_guardado", { ruta });
    mostrarProcesando(false);
    const nombreTrad = rutaResultado.replace(/\\/g, "/").split("/").pop() ?? rutaResultado;
    añadirResultadoArchivo(nombreTrad, rutaResultado);
    scrollAlFinal();
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error al traducir: " + String(error), "BABEL · error");
  }
}

async function verArchivo(ruta: string): Promise<void> {
  try {
    const texto = await invoke<string>("ver_archivo", { ruta });
    const nombre = ruta.split("/").pop() ?? ruta;
    const modal = document.getElementById("modal-visor");
    const modalNombre = document.getElementById("modal-visor-nombre");
    const modalContenido = document.getElementById("modal-visor-contenido");
    if (!modal || !modalNombre || !modalContenido) return;
    modalNombre.textContent = escapeHTML(nombre);
    renderizarEnContenedor(texto, modalContenido);
    modal.classList.remove("hidden");
  } catch (error) {
    mostrarToast("Error abriendo archivo: " + String(error), true);
  }
}

// ============================================================
// HELPER — Renderiza cualquier tipo de contenido en un contenedor.
// Gestiona el ciclo de vida del blob URL (PDF) para evitar memory leaks.
// Uso: renderizarEnContenedor(texto, contenedor, alturaVisor?)
// ============================================================
function renderizarEnContenedor(
  texto: string,
  contenedor: HTMLElement,
  alturaVisor = "65vh"
): void {
  // Revocar blob URL anterior si existe (evita memory leak)
  const prev = (contenedor as any)._blobUrl as string | undefined;
  if (prev) URL.revokeObjectURL(prev);
  (contenedor as any)._blobUrl = undefined;

  contenedor.innerHTML = "";
  if (texto.startsWith("data:image")) {
    const img = document.createElement("img");
    img.src = texto;
    img.style.cssText = `max-width:100%;max-height:${alturaVisor};object-fit:contain;border-radius:4px;display:block;margin:0 auto;`;
    contenedor.appendChild(img);
  } else if (texto.startsWith("html:")) {
    // HTML generado por el backend Rust (docx_a_html) — confiable, se permite style
    contenedor.innerHTML = DOMPurify.sanitize(texto.slice(5), {
      ALLOWED_TAGS: ["p", "div", "br", "span", "b", "i", "u", "strong", "em", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "a", "img", "h1", "h2", "h3", "h4", "blockquote", "pre", "code"],
      ALLOWED_ATTR: ["href", "alt", "title", "class", "width", "height", "style"],
      FORBID_ATTR: ["src", "onerror", "onload"],
      ALLOW_DATA_ATTR: false,
      FORCE_BODY: true,
    });
  } else if (texto.startsWith("pdf:")) {
    const blob = new Blob(
      [Uint8Array.from(atob(texto.slice(4)), c => c.charCodeAt(0))],
      { type: "application/pdf" }
    );
    const url = URL.createObjectURL(blob);
    (contenedor as any)._blobUrl = url;
    const iframe = document.createElement("iframe");
    iframe.src = url;
    iframe.style.cssText = `width:100%;height:${alturaVisor};border:none;border-radius:4px;`;
    contenedor.appendChild(iframe);
  } else {
    contenedor.textContent = texto;
  }
}

function cerrarVisor(): void {
  const modal = document.getElementById("modal-visor");
  const contenido = document.getElementById("modal-visor-contenido");
  if (contenido) {
    // Revocar blob URL si había un PDF abierto
    const prev = (contenido as any)._blobUrl as string | undefined;
    if (prev) URL.revokeObjectURL(prev);
    (contenido as any)._blobUrl = undefined;
    contenido.innerHTML = "";
  }
  modal?.classList.add("hidden");
}
// VISOR PARALELO — ver 1 o 2 archivos side by side

async function verComparacion(): Promise<void> {
  // Tomamos los primeros 2 checkboxes marcados — sin deduplicar por ruta
  // (ambas columnas muestran los mismos archivos, así que permitimos repetidos)
  const seleccionados = Array.from(
    document.querySelectorAll<HTMLInputElement>(".archivo-checkbox:checked")
  ).slice(0, 2);

  if (seleccionados.length === 0) return;

  const datos: { nombre: string; texto: string }[] = [];

  for (const cb of seleccionados) {
    const card = cb.closest(".archivo-card") as HTMLElement;
    const ruta = card?.dataset.ruta;
    const nombre = card?.querySelector(".archivo-card-nombre")?.textContent ?? "Archivo";
    if (!ruta) continue;
    try {
      const texto = await invoke<string>("ver_archivo", { ruta });
      datos.push({ nombre, texto });
    } catch (error) {
      mostrarToast("Error abriendo archivo: " + String(error), true);
      return;
    }
  }

  const modal = document.getElementById("modal-paralelo");
  const cont1 = document.getElementById("par-contenido-1");
  if (!modal || !cont1) return;
  const titulo1 = document.getElementById("par-titulo-1");
  const divisor = document.getElementById("par-divisor");
  const panel2 = document.getElementById("par-panel-2");
  const titulo2 = document.getElementById("par-titulo-2");
  const cont2 = document.getElementById("par-contenido-2");

  if (titulo1) titulo1.textContent = datos[0].nombre;
  if (cont1) renderizarEnContenedor(datos[0].texto, cont1, "55vh");

  if (datos.length === 2 && divisor && panel2 && titulo2 && cont2) {
    divisor.style.display = "block";
    panel2.style.display = "flex";
    titulo2.textContent = datos[1].nombre;
    renderizarEnContenedor(datos[1].texto, cont2, "55vh");
  } else {
    if (divisor) divisor.style.display = "none";
    if (panel2) panel2.style.display = "none";
  }

  modal.classList.remove("hidden");
}

async function verComparacionRutas(rutaOrig: string, rutaTrad: string): Promise<void> {
  try {
    const [textoOrig, textoTrad] = await Promise.all([
      invoke<string>("ver_archivo", { ruta: rutaOrig }),
      invoke<string>("ver_archivo", { ruta: rutaTrad }),
    ]);
    const modal = document.getElementById("modal-paralelo");
    const titulo1 = document.getElementById("par-titulo-1");
    const cont1 = document.getElementById("par-contenido-1");
    const divisor = document.getElementById("par-divisor");
    const panel2 = document.getElementById("par-panel-2");
    const titulo2 = document.getElementById("par-titulo-2");
    const cont2 = document.getElementById("par-contenido-2");
    if (!modal || !cont1) return;
    if (titulo1) titulo1.textContent = "ORIGINAL";
    if (cont1) renderizarEnContenedor(textoOrig, cont1, "55vh");
    if (divisor) divisor.style.display = "block";
    if (panel2) panel2.style.display = "flex";
    if (titulo2) titulo2.textContent = "TRADUCCIÓN";
    if (cont2) renderizarEnContenedor(textoTrad, cont2, "55vh");
    modal.classList.remove("hidden");
  } catch (error) {
    mostrarToast("Error abriendo comparación: " + String(error), true);
  }
}
function cerrarVisorParalelo(): void {
  const modal = document.getElementById("modal-paralelo");
  const cont1 = document.getElementById("par-contenido-1");
  const cont2 = document.getElementById("par-contenido-2");
  for (const cont of [cont1, cont2]) {
    if (!cont) continue;
    const prev = (cont as any)._blobUrl as string | undefined;
    if (prev) URL.revokeObjectURL(prev);
    (cont as any)._blobUrl = undefined;
    cont.innerHTML = "";
  }
  modal?.classList.add("hidden");
}
// BÚSQUEDA DE ARCHIVOS

// P2P — FUNCIONES

// P2P — ESTADO

let ipP2PConectada: string = "";
let intervalP2PPoll: number | null = null;
let p2pTraduccionActiva: boolean = false;

function cambiarModoP2P(modo: string): void {
  document.getElementById("p2p-selector-inicial")?.classList.add("hidden");

  const panelChat = document.getElementById("panel-p2p-chat");
  const panelEmail = document.getElementById("panel-p2p-email");
  const subtitulo = document.getElementById("p2p-subtitulo");

  if (modo === "chat") {
    panelChat?.classList.remove("hidden");
    panelEmail?.classList.add("hidden");
    detenerRecargaAutomatica();
    if (subtitulo) subtitulo.textContent = "CHAT · CIFRADO LOCAL";
  } else {
    panelChat?.classList.add("hidden");
    panelEmail?.classList.remove("hidden");
    if (subtitulo) subtitulo.textContent = "EMAIL · CIFRADO LOCAL";
    if (!_smtpConfigurado) {
      setTimeout(() => toggleConfigSmtp(), 300);
    } else {
      cargarBandejaEmail();
      iniciarRecargaAutomatica();
    }
  }
}

function volverDeP2P(): void {
  const selectorInicial = document.getElementById("p2p-selector-inicial");
  const panelChat = document.getElementById("panel-p2p-chat");
  const panelEmail = document.getElementById("panel-p2p-email");
  const subtitulo = document.getElementById("p2p-subtitulo");

  const enPanel = !panelChat?.classList.contains("hidden") || !panelEmail?.classList.contains("hidden");

  if (enPanel) {
    panelChat?.classList.add("hidden");
    panelEmail?.classList.add("hidden");
    selectorInicial?.classList.remove("hidden");
    detenerRecargaAutomatica();
    detenerPollP2P();
    if (subtitulo) subtitulo.textContent = "RED P2P · CIFRADO LOCAL";
  } else {
    detenerRecargaAutomatica();
    detenerPollP2P();
    mostrarPantalla("principal");
  }
}

// P2P — SERVIDOR (MODO RECIBIR)

async function iniciarP2P(): Promise<void> {
  const faseInicio = document.getElementById("p2p-fase-inicio");
  const faseCarga = document.getElementById("p2p-fase-carga");
  const miInfo = document.getElementById("p2p-mi-info");
  const miIp = document.getElementById("p2p-mi-ip");
  const estadoTexto = document.getElementById("p2p-estado-texto");
  const dot = document.getElementById("p2p-dot");

  if (faseInicio) faseInicio.style.display = "none";
  if (faseCarga) faseCarga.style.display = "flex";

  try {
    // Arranca servidor P2P en Rust y obtiene IP local
    const [_, ip] = await Promise.all([
      invoke("iniciar_servidor_p2p"),
      invoke<string>("obtener_ip_local")
    ]);

    setTimeout(() => {
      if (faseCarga) faseCarga.style.display = "none";
      if (faseInicio) faseInicio.style.display = "flex";
      if (miInfo) miInfo.style.display = "block";
      if (miIp) miIp.textContent = ip;
      if (estadoTexto) estadoTexto.textContent = "SERVIDOR ACTIVO — ESPERANDO CONEXIÓN";
      if (dot) { dot.style.background = "#f59e0b"; dot.style.opacity = "1"; }
      mostrarToast("Servidor P2P activo en " + ip, false);
      iniciarPollMensajes(); // Mac B empieza a escuchar solicitudes
    }, 1500);

  } catch (e) {
    if (faseCarga) faseCarga.style.display = "none";
    if (faseInicio) faseInicio.style.display = "flex";
    mostrarToast("Error iniciando servidor: " + String(e), true);
  }
}

// P2P — CLIENTE (MODO ENVIAR)
async function buscarDispositivos(): Promise<void> {
  const lista = document.getElementById("p2p-lista-peers");
  if (!lista) return;
  lista.style.display = "flex";
  lista.innerHTML = `<div style="font-family:'Times New Roman', Times, serif;font-size:0.6rem;letter-spacing:2px;color:var(--texto-secundario);text-align:center;">BUSCANDO...</div>`;

  try {
    const peers = await invoke<any[]>("buscar_peers_p2p");
    if (peers.length === 0) {
      lista.innerHTML = `<div style="font-family:'Times New Roman', Times, serif;font-size:0.6rem;letter-spacing:2px;color:var(--texto-secundario);text-align:center;opacity:0.5;">NO SE ENCONTRÓ NINGÚN BABEL</div>`;
      return;
    }
    lista.innerHTML = peers.map(p => `
      <button type="button" data-action="peer" data-ip="${escapeHTML(p.ip)}" data-nombre="${escapeHTML(p.nombre)}"
        style="background:rgba(201,168,76,0.06);border:1px solid rgba(201,168,76,0.2);
        color:var(--texto-principal);padding:10px 14px;cursor:pointer;border-radius:2px;
        display:flex;justify-content:space-between;align-items:center;width:100%;">
        <span style="font-family:'Times New Roman', Times, serif;font-size:0.65rem;letter-spacing:1px;">${escapeHTML(p.nombre)}</span>
        <span style="font-family:'Times New Roman', Times, serif;font-size:0.58rem;color:var(--dorado);opacity:0.7;">${escapeHTML(p.ip)}</span>
      </button>`).join("");
    lista.onclick = (e: MouseEvent) => {
      const btn = (e.target as HTMLElement).closest("[data-action='peer']") as HTMLElement | null;
      if (!btn) return;
      seleccionarPeer(btn.dataset.ip ?? "", btn.dataset.nombre ?? "");
    };
  } catch (e) {
    lista.innerHTML = `<div style="color:var(--error);font-size:0.6rem;text-align:center;">Error buscando dispositivos</div>`;
  }
}

function seleccionarPeer(ip: string, _nombre: string): void {
  const input = document.getElementById("p2p-ip-input") as HTMLInputElement;
  if (input) input.value = ip;
  const lista = document.getElementById("p2p-lista-peers");
  if (lista) lista.style.display = "none";
  conectarP2P();
}

async function conectarP2P(): Promise<void> {
  const ip = (document.getElementById("p2p-ip-input") as HTMLInputElement)?.value?.trim();
  if (!ip) { mostrarToast("Introduce la IP del destino", true); return; }

  const miIp = await invoke<string>("obtener_ip_local").catch(() => "desconocido");
  const miNombre = "Babel-" + miIp;
  const faseInicio = document.getElementById("p2p-fase-inicio");
  const faseCarga = document.getElementById("p2p-fase-carga");
  const faseChat = document.getElementById("p2p-fase-chat");
  const estadoTexto = document.getElementById("p2p-estado-texto");
  const dot = document.getElementById("p2p-dot");

  if (faseInicio) faseInicio.style.display = "none";
  if (faseCarga) faseCarga.style.display = "flex";

  try {
    await invoke("enviar_mensaje_p2p", { ip, mensaje: `__BABEL_SOLICITUD__:${miNombre}` });
    ipP2PConectada = ip;
    iniciarPollMensajes();
    setTimeout(() => {
      if (faseCarga) faseCarga.style.display = "none";
      if (faseChat) faseChat.style.display = "flex";
      if (estadoTexto) estadoTexto.textContent = `CONECTADO · ${ip}`;
      if (dot) { dot.style.background = "#22c55e"; dot.style.opacity = "1"; }
      añadirMensajeP2P("sistema", `Túnel mTLS establecido con Babel-Remoto (${ip})`);
    }, 1500);
  } catch (e) {
    if (faseCarga) faseCarga.style.display = "none";
    if (faseInicio) faseInicio.style.display = "flex";
    ipP2PConectada = "";
    mostrarToast("No se pudo conectar con " + ip + ": " + String(e), true);
  }
}

// P2P — CHAT Y TRADUCCIÓN EN TIEMPO REAL

function añadirMensajeP2P(tipo: "yo" | "ellos" | "sistema", texto: string, traduccion?: string): void {
  const contenedor = document.getElementById("p2p-mensajes");
  if (!contenedor) return;

  const div = document.createElement("div");

  if (tipo === "sistema") {
    div.style.cssText = "text-align:center;font-family:'Times New Roman', Times, serif;font-size:0.58rem;letter-spacing:2px;color:var(--texto-secundario);opacity:0.5;padding:4px 0;";
    div.textContent = texto;
  } else {
    const esYo = tipo === "yo";
    const textoTraducido = traduccion ? `<p style="font-family:'Times New Roman', Times, serif;font-size:0.78rem;color:var(--texto-secundario);margin:6px 0 0;font-style:italic;opacity:0.7;">${escapeHTML(traduccion)}</p>` : "";
    div.style.cssText = `display:flex;justify-content:${esYo ? "flex-end" : "flex-start"};margin-bottom:4px;`;
    div.innerHTML = `
      <div style="max-width:70%;background:${esYo ? "rgba(201,168,76,0.12)" : "rgba(255,255,255,0.05)"};
        border:1px solid ${esYo ? "rgba(201,168,76,0.3)" : "rgba(255,255,255,0.08)"};
        border-radius:3px;padding:10px 14px;">
        <p style="font-family:'Times New Roman', Times, serif;font-size:0.88rem;color:var(--texto-principal);margin:0;line-height:1.5;">${escapeHTML(texto)}</p>
        ${textoTraducido}
        <span style="font-family:'Times New Roman', Times, serif;font-size:0.55rem;letter-spacing:1px;color:var(--texto-secundario);opacity:0.5;display:block;margin-top:4px;">${esYo ? "TÚ" : "BABEL REMOTO"} · AES-256</span>
      </div>`;
  }

  contenedor.appendChild(div);
  contenedor.scrollTop = contenedor.scrollHeight;
}

async function enviarMensajeP2P(): Promise<void> {
  const input = document.getElementById("p2p-input") as HTMLTextAreaElement;
  const texto = input?.value?.trim();
  if (!texto) return;

  input.value = "";
  input.style.height = "40px";

  añadirMensajeP2P("yo", texto);

  if (ipP2PConectada) {
    try {
      await invoke("enviar_mensaje_p2p", {
        ip: ipP2PConectada,
        mensaje: texto
      });
    } catch (e) { mostrarToast("Error enviando mensaje P2P: " + String(e), true); }
  }
}

// Activa o desactiva la traducción automática de mensajes entrantes en P2P
function toggleTraduccionP2P(): void {
  p2pTraduccionActiva = !p2pTraduccionActiva;
  const btn = document.getElementById("p2p-btn-traduccion");
  if (btn) {
    btn.style.opacity = p2pTraduccionActiva ? "1" : "0.4";
    btn.textContent = p2pTraduccionActiva ? "TRADUCCIÓN ON" : "TRADUCCIÓN OFF";
  }
  mostrarToast(p2pTraduccionActiva ? "Traducción P2P activada" : "Traducción P2P desactivada", false);
}

// Detiene el polling de mensajes P2P y limpia el intervalo
function detenerPollP2P(): void {
  if (intervalP2PPoll) {
    clearInterval(intervalP2PPoll);
    intervalP2PPoll = null;
  }
}

async function manejarMensajeEntrante(texto: string): Promise<void> {
  if (p2pTraduccionActiva) {
    try {
      const origenSel = (document.getElementById("selector-origen") as HTMLSelectElement)?.value ?? "es";
      const destinoSel = (document.getElementById("selector-destino") as HTMLSelectElement)?.value ?? "en";
      const idioma = origenSel !== destinoSel ? `${origenSel}_${destinoSel}` : "es_en";
      const [traducido] = await invoke<[string, number]>("traducir_texto", { texto, idioma });
      añadirMensajeP2P("ellos", texto, traducido);
    } catch (_) {
      añadirMensajeP2P("ellos", texto);
    }
  } else {
    añadirMensajeP2P("ellos", texto);
  }
}

function iniciarPollMensajes(): void {
  if (intervalP2PPoll) return;
  intervalP2PPoll = window.setInterval(async () => {
    try {
      const mensajes = await invoke<string[]>("obtener_mensajes_p2p");
      for (const mensaje of mensajes) {
        if (mensaje.startsWith("__BABEL_SOLICITUD__:")) {
          const nombre = mensaje.replace("__BABEL_SOLICITUD__:", "");
          mostrarSolicitudP2P(nombre);
        } else if (mensaje === "__BABEL_ACEPTADO__") {
          const faseInicio = document.getElementById("p2p-fase-inicio");
          const faseCarga = document.getElementById("p2p-fase-carga");
          const faseChat = document.getElementById("p2p-fase-chat");
          const estadoTexto = document.getElementById("p2p-estado-texto");
          const dot = document.getElementById("p2p-dot");
          if (faseCarga) faseCarga.style.display = "none";
          if (faseInicio) faseInicio.style.display = "none";
          if (faseChat) faseChat.style.display = "flex";
          if (estadoTexto) estadoTexto.textContent = `CONECTADO · ${ipP2PConectada}`;
          if (dot) { dot.style.background = "#22c55e"; dot.style.opacity = "1"; }
        } else {
          await manejarMensajeEntrante(mensaje);
        }
      }
    } catch (_) { }
  }, 2000);
}
let _solicitudIpRemota = "";

function mostrarSolicitudP2P(nombre: string): void {
  const modal = document.getElementById("modal-solicitud-p2p");
  const nombreEl = document.getElementById("solicitud-nombre");
  if (!modal || !nombreEl) return;
  nombreEl.textContent = nombre;
  modal.classList.remove("hidden");
  // Extraer IP del nombre del remitente (formato "Babel-192.168.1.X")
  const ipExtraida = nombre.startsWith("Babel-") ? nombre.slice("Babel-".length) : "";
  const esIpValida = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ipExtraida);
  _solicitudIpRemota = esIpValida ? ipExtraida : ipP2PConectada;
}

async function aceptarSolicitudP2P(): Promise<void> {
  document.getElementById("modal-solicitud-p2p")?.classList.add("hidden");
  ipP2PConectada = _solicitudIpRemota;
  iniciarPollMensajes();
  const faseInicio = document.getElementById("p2p-fase-inicio");
  const faseChat = document.getElementById("p2p-fase-chat");
  const estadoTexto = document.getElementById("p2p-estado-texto");
  const dot = document.getElementById("p2p-dot");
  if (faseInicio) faseInicio.style.display = "none";
  if (faseChat) faseChat.style.display = "flex";
  if (estadoTexto) estadoTexto.textContent = `CONECTADO · ${_solicitudIpRemota}`;
  if (dot) { dot.style.background = "#22c55e"; dot.style.opacity = "1"; }
  if (_solicitudIpRemota) {
    await invoke("enviar_mensaje_p2p", {
      ip: _solicitudIpRemota,
      mensaje: "__BABEL_ACEPTADO__"
    });
  }
}

function rechazarSolicitudP2P(): void {
  document.getElementById("modal-solicitud-p2p")?.classList.add("hidden");
  _solicitudIpRemota = "";
}
function destruirSesionP2P(): void {
  const contenedor = document.getElementById("p2p-mensajes");
  const faseChat = document.getElementById("p2p-fase-chat");
  const faseInicio = document.getElementById("p2p-fase-inicio");
  const estadoTexto = document.getElementById("p2p-estado-texto");
  const dot = document.getElementById("p2p-dot");
  const miInfo = document.getElementById("p2p-mi-info");
  const input = document.getElementById("p2p-input") as HTMLTextAreaElement;

  // Zeroize de todos los mensajes en DOM
  if (contenedor) {
    contenedor.querySelectorAll("p").forEach(p => {
      p.textContent = "0".repeat(p.textContent?.length ?? 0);
      p.textContent = "";
    });
    contenedor.innerHTML = "";
  }
  if (input) { input.value = "0".repeat(input.value.length); input.value = ""; }

  ipP2PConectada = "";
  p2pTraduccionActiva = false;
  detenerPollP2P();

  if (faseChat) faseChat.style.display = "none";
  if (faseInicio) faseInicio.style.display = "flex";
  if (miInfo) miInfo.style.display = "none";
  if (estadoTexto) estadoTexto.textContent = "SIN CONEXIÓN";
  if (dot) { dot.style.background = "#f59e0b"; dot.style.opacity = "0.5"; }

  mostrarToast("Sesión destruida — borrado total", false);
}

// AJUSTES DE TRADUCCIÓN — guardado automático

async function guardarAjustesTraduccion(): Promise<void> {
  const origen = (document.getElementById("selector-origen") as HTMLSelectElement)?.value ?? "es";
  const destino = (document.getElementById("selector-destino") as HTMLSelectElement)?.value ?? "en";
  const categoria = (document.getElementById("tipo-diccionario") as HTMLSelectElement)?.value ?? "todos";
  const borradoAuto = (document.getElementById("toggle-borrado") as HTMLInputElement)?.checked ?? true;
  const timeoutMin = parseInt((document.getElementById("selector-timeout") as HTMLSelectElement)?.value ?? "15", 10);

  await invoke("save_settings", {
    settings: {
      borrar_al_salir: borradoAuto,
      diccionario: true,
      idioma_origen: origen,
      idioma_destino: destino,
      categoria: categoria,
      timeout_sesion_minutos: timeoutMin,
    }
  }).catch(() => {});
}

async function guardarTimeoutSesion(minutos: string): Promise<void> {
  const min = Math.max(2, Math.min(60, parseInt(minutos, 10)));
  _tiempoLockMs = min * 60 * 1000;
  resetearTimerInactividad();
  await guardarAjustesTraduccion();
  mostrarToast(`Bloqueo automático: ${min} min`, false);
}

async function cargarAjustesTraduccion(): Promise<void> {
  const s = await invoke<any>("load_settings");
  const origen = s.idioma_origen ?? "es";
  const destino = s.idioma_destino ?? "en";
  const categoria = s.categoria ?? "todos";
  const borradoAuto = s.borrar_al_salir ?? false;
  const timeoutMin: number = Math.max(2, Math.min(60, s.timeout_sesion_minutos ?? 15));

  _tiempoLockMs = timeoutMin * 60 * 1000;
  if (_sesionActiva) resetearTimerInactividad();

  const selectorTimeout = document.getElementById("selector-timeout") as HTMLSelectElement;
  if (selectorTimeout) selectorTimeout.value = String(timeoutMin);
  const tipoDiccionario = document.getElementById("tipo-diccionario") as HTMLSelectElement;
  if (tipoDiccionario) tipoDiccionario.value = categoria;
  const toggleBorrado = document.getElementById("toggle-borrado") as HTMLInputElement;
  if (toggleBorrado) toggleBorrado.checked = borradoAuto;
  borradoAutomaticoActivado = borradoAuto;

  if (origen !== destino) {
    sincronizarSelectoresIdioma(origen, destino);
    await cambiarIdioma(`${origen}_${destino}`).catch(() => {});
  }
  const sidebarAbierto = localStorage.getItem("babel-sidebar") !== "0";
  const sidebar = document.getElementById("chat-sidebar");
  if (sidebar) sidebar.classList.toggle("hidden", !sidebarAbierto);
  const toggleBorrarOrig = document.getElementById("toggle-borrar-orig") as HTMLInputElement | null;
  if (toggleBorrarOrig) toggleBorrarOrig.checked = localStorage.getItem(LS_NO_PREG_BORRAR_ORIG) === "si";
  const savedBuzonG = localStorage.getItem("babel-buzon-activo-g");
  if (savedBuzonG && savedBuzonG !== "todos") {
    const nodos = await invoke<BuzonNodo[]>("listar_buzones_guardados");
    buzonActivoGuardados = nodos.some(n => n.id === savedBuzonG) ? savedBuzonG : "todos";
  } else {
    buzonActivoGuardados = "todos";
  }
}

// EMAIL — FUNCIONES

let archivoEmailRuta: string = "";
let archivoEmailFile: File | null = null;
let intervaloBandeja: number | null = null;

// Inicia la recarga automática de la bandeja cada 5 minutos
function iniciarRecargaAutomatica(): void {
  if (intervaloBandeja) clearInterval(intervaloBandeja);
  intervaloBandeja = window.setInterval(() => {
    if (_smtpConfigurado) cargarBandejaEmail();
  }, 5 * 60 * 1000); // 5 minutos
}

// Para la recarga cuando el usuario sale de EMAIL
function detenerRecargaAutomatica(): void {
  if (intervaloBandeja) {
    clearInterval(intervaloBandeja);
    intervaloBandeja = null;
  }
}

// Interfaz que refleja el struct Rust EmailResumen
interface EmailResumen {
  id: number;
  remitente: string;
  asunto: string;
  fecha: string;
  tiene_adjunto: boolean;
  leido: boolean;
  snippet: string;
}

// Email seleccionado actualmente
const emailsVistos = new Set<number>();
let emailVisorActualId: number | null = null;
let _firmaEmail: string = "";
let _cuerpoEmailOriginal: string = "";
let _imapCargando = false;   // B1: evita sesiones IMAP concurrentes en lectura
let _imapMutando = false;    // B1: evita sesiones IMAP concurrentes en mutación

async function cargarBandejaEmail(): Promise<void> {
  if (_imapCargando) return;
  _imapCargando = true;
  const lista = document.getElementById("email-lista");
  if (!lista) { _imapCargando = false; return; }

  // B2: limpiar el buscador para que no quede un filtro inconsistente tras recargar
  const buscarEl = document.getElementById("email-buscar") as HTMLInputElement | null;
  if (buscarEl) buscarEl.value = "";

  lista.innerHTML = `<div class="email-vacio"><p class="email-vacio-titulo">Cargando...</p></div>`;

  try {
    const emails = await invoke<EmailResumen[]>("obtener_emails_tauri");

    if (emails.length === 0) {
      lista.innerHTML = `
        <div class="email-vacio">
          <span style="font-size:2rem;opacity:0.13;">✉</span>
          <p class="email-vacio-titulo">Bandeja vacía</p>
          <p class="email-vacio-sub">No hay correos en la bandeja</p>
        </div>`;
      return;
    }

    let noLeidos = 0;
    lista.innerHTML = emails.map(email => {
      const visto = emailsVistos.has(email.id) || email.leido;
      if (!visto) noLeidos++;
      return `
      <div class="email-item${visto ? "" : " no-leido"}" data-action="seleccionar-email" data-id="${Number(email.id)}">
        <div class="email-item-cabecera">
          <div class="email-item-remitente">${escapeHTML(email.remitente)}</div>
          ${!visto ? '<span class="email-punto-nuevo"></span>' : ""}
        </div>
        <div class="email-item-asunto">${escapeHTML(email.asunto)}</div>
        ${email.snippet ? `<div class="email-item-snippet">${escapeHTML(email.snippet)}</div>` : ""}
        <div class="email-item-meta">
          <span class="email-item-fecha">${formatearFechaEmail(email.fecha)}</span>
          ${email.tiene_adjunto ? '<span class="email-item-adjunto-icono" title="Tiene adjunto">📎</span>' : ""}
        </div>
      </div>`;
    }).join("");

    // Event delegation — evita onclick inline con IDs sin sanitizar
    lista.onclick = (e: MouseEvent) => {
      const item = (e.target as HTMLElement).closest("[data-action='seleccionar-email']") as HTMLElement | null;
      if (!item) return;
      const id = parseInt(item.dataset.id ?? "", 10);
      if (!Number.isFinite(id)) return;
      seleccionarEmail(id);
    };

    // Actualizar contador en el título y badge en botón EMAIL
    const tituloSidebar = document.querySelector(".email-sidebar-titulo");
    if (tituloSidebar) tituloSidebar.textContent = noLeidos > 0 ? `BANDEJA (${noLeidos})` : "BANDEJA";
    actualizarBadgeEmail(noLeidos);

  } catch (error) {
    lista.innerHTML = `
      <div class="email-vacio">
        <p class="email-vacio-titulo">Error cargando</p>
        <p class="email-vacio-sub">${escapeHTML(String(error))}</p>
      </div>`;
  } finally {
    _imapCargando = false;
  }
}

// Convierte fecha RFC 2822 a formato legible: hora si es hoy, día/mes si es anterior
function formatearFechaEmail(fecha: string): string {
  if (!fecha) return "";
  try {
    const d = new Date(fecha);
    if (isNaN(d.getTime())) return escapeHTML(fecha.substring(0, 16));
    const hoy = new Date();
    const esHoy = d.toDateString() === hoy.toDateString();
    if (esHoy) {
      return d.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
    }
    return d.toLocaleDateString("es-ES", { day: "2-digit", month: "short" });
  } catch {
    return escapeHTML(fecha.substring(0, 16));
  }
}
function renderizarCuerpoEmail(contenedor: HTMLElement, cuerpo: string): void {
  contenedor.innerHTML = "";
  if (!cuerpo || cuerpo.trim() === "") {
    contenedor.textContent = "Sin contenido de texto.";
    return;
  }
  const esHTML = /<(p|div|br|img|html|body|span|table)[^>]*>/i.test(cuerpo);
  if (esHTML) {
    contenedor.innerHTML = DOMPurify.sanitize(cuerpo, {
      ALLOWED_TAGS: ["p", "div", "br", "span", "b", "i", "u", "strong", "em", "ul", "ol", "li", "table", "thead", "tbody", "tr", "th", "td", "a", "img", "h1", "h2", "h3", "h4", "blockquote", "pre", "code"],
      ALLOWED_ATTR: ["href", "alt", "title", "class", "width", "height"],
      FORBID_ATTR: ["style", "src", "onerror", "onload"],
      ALLOW_DATA_ATTR: false,
      FORCE_BODY: true,
    });
  } else {
    // Texto plano: URLs como enlaces seguros, resto como textContent
    const partes = cuerpo.split(/(https?:\/\/[^\s]+)/g);
    for (const parte of partes) {
      if (/^https?:\/\//.test(parte)) {
        const a = document.createElement("a");
        a.href = parte;
        a.textContent = parte;
        a.style.color = "var(--dorado)";
        a.rel = "noopener noreferrer";
        a.target = "_blank";
        contenedor.appendChild(a);
      } else {
        contenedor.appendChild(document.createTextNode(parte));
      }
    }
  }
}
async function seleccionarEmail(id: number): Promise<void> {
  document.querySelectorAll(".email-item").forEach(el => el.classList.remove("activo"));
  const itemEl = document.querySelector(`.email-item[data-id="${id}"]`);
  itemEl?.classList.add("activo");
  emailsVistos.add(id);
  if (itemEl) { itemEl.classList.remove("no-leido"); itemEl.querySelector(".email-punto-nuevo")?.remove(); }

  const lectorVacio = document.getElementById("email-lector-vacio");
  const compositor = document.getElementById("email-compositor");
  const visor = document.getElementById("email-visor");
  const asuntoEl = document.getElementById("visor-asunto");
  const metaEl = document.getElementById("visor-meta");
  const adjuntosEl = document.getElementById("visor-adjuntos");
  const cuerpoEl = document.getElementById("email-visor-cuerpo");
  lectorVacio?.classList.add("hidden");
  compositor?.classList.add("hidden");
  visor?.classList.remove("hidden");

  if (asuntoEl) asuntoEl.textContent = "Cargando…";
  if (metaEl) metaEl.textContent = "";
  if (adjuntosEl) adjuntosEl.innerHTML = "";
  if (cuerpoEl) { cuerpoEl.innerHTML = '<div class="email-cargando">CARGANDO CORREO</div>'; _zoomEmailRem = 0.92; cuerpoEl.style.fontSize = ""; }

  try {
    const email = await invoke<{
      id: number; remitente: string; asunto: string;
      fecha: string; cuerpo: string; adjuntos: string[];
    }>("obtener_email_completo_tauri", { id });

    emailVisorActualId = email.id;
    if (asuntoEl) asuntoEl.textContent = email.asunto || "Sin asunto";
    if (metaEl) metaEl.textContent = `De: ${email.remitente} · ${formatearFechaEmail(email.fecha)}`;
    if (adjuntosEl) adjuntosEl.innerHTML = email.adjuntos.map(a => `<span class="email-adjunto-tag">📎 ${escapeHTML(a)}</span>`).join("");
    _cuerpoEmailOriginal = email.cuerpo;
    const idiomaEl = document.getElementById("email-idioma") as HTMLSelectElement;
    if (idiomaEl) idiomaEl.value = "ninguno";
    if (cuerpoEl) renderizarCuerpoEmail(cuerpoEl, email.cuerpo);
  } catch (error) {
    mostrarToast("Error cargando email: " + String(error), true);
    lectorVacio?.classList.remove("hidden");
    visor?.classList.add("hidden");
    emailVisorActualId = null;
  }
}

// Muestra el compositor de email y oculta el visor/lector vacío
function abrirComponerEmail(): void {
  document.getElementById("email-lector-vacio")?.classList.add("hidden");
  document.getElementById("email-visor")?.classList.add("hidden");
  const comp = document.getElementById("email-compositor");
  if (!comp) return;
  comp.classList.remove("hidden");
  comp.style.display = "flex";

  const cuerpo = document.getElementById("comp-cuerpo") as HTMLTextAreaElement;
  if (cuerpo && !cuerpo.value && _firmaEmail) {
    cuerpo.value = `\n\n—\n${_firmaEmail}`;
  }
}

// Cierra el compositor y limpia los campos y archivos adjuntos
function cerrarCompositor(): void {
  document.getElementById("email-compositor")?.classList.add("hidden");
  document.getElementById("email-lector-vacio")?.classList.remove("hidden");
  archivoEmailRuta = "";
  archivoEmailFile = null;
  const g = (id: string) => document.getElementById(id);
  const n = g("comp-archivo-nombre"); if (n) n.textContent = "📎 Adjuntar documento";
  const s = g("comp-estado"); if (s) s.textContent = "";
  for (const id of ["input-archivo-email","comp-destinatario","comp-asunto","comp-cc","comp-cco","comp-cuerpo"]) {
    const f = g(id) as HTMLInputElement | null; if (f) f.value = "";
  }
}

// Cierra el visor de email y muestra el estado vacío del lector
function cerrarVisorEmail(): void {
  document.getElementById("email-visor")?.classList.add("hidden");
  document.getElementById("email-lector-vacio")?.classList.remove("hidden");
  emailVisorActualId = null;
  _cuerpoEmailOriginal = "";
}

// Abre el selector de archivo del sistema para adjuntar al email
function seleccionarArchivoEmail(): void {
  document.getElementById("input-archivo-email")?.click();
}

// Actualiza el nombre del archivo adjunto en el compositor cuando el usuario selecciona uno
function manejarSeleccionArchivoEmail(event: Event): void {
  const input = event.target as HTMLInputElement;
  const archivo = input.files?.[0];
  if (!archivo) return;
  archivoEmailRuta = archivo.name;
  archivoEmailFile = archivo;
  const el = document.getElementById("comp-archivo-nombre");
  if (el) el.textContent = "📎 " + archivo.name;
}

// Muestra u oculta el panel de configuración de correo
function toggleConfigSmtp(): void {
  const panel = document.getElementById("panel-config-smtp");
  const estabaOculto = panel?.classList.contains("hidden");
  panel?.classList.toggle("hidden");
  if (estabaOculto && _firmaEmail) {
    const firmaEl = document.getElementById("smtp-firma") as HTMLTextAreaElement;
    if (firmaEl && !firmaEl.value) firmaEl.value = _firmaEmail;
  }
}

// Rellena automáticamente los campos SMTP/IMAP según el dominio del email introducido
function autorellenarSmtp(email: string): void {
  const dominio = email.split("@")[1]?.toLowerCase() ?? "";
  const config: Record<string, { smtp: string; imap: string }> = {
    "gmail.com": { smtp: "smtp.gmail.com", imap: "imap.gmail.com" },
    "outlook.com": { smtp: "smtp.office365.com", imap: "outlook.office365.com" },
    "hotmail.com": { smtp: "smtp.office365.com", imap: "outlook.office365.com" },
    "yahoo.com": { smtp: "smtp.mail.yahoo.com", imap: "imap.mail.yahoo.com" },
    "yahoo.es": { smtp: "smtp.mail.yahoo.com", imap: "imap.mail.yahoo.com" },
    "protonmail.com": { smtp: "smtp.protonmail.com", imap: "imap.protonmail.com" },
    "proton.me": { smtp: "smtp.protonmail.com", imap: "imap.protonmail.com" },
    "icloud.com": { smtp: "smtp.mail.me.com", imap: "imap.mail.me.com" },
  };
  const c = config[dominio];
  if (!c) return;
  const smtpEl = document.getElementById("smtp-servidor") as HTMLInputElement;
  const imapEl = document.getElementById("imap-servidor") as HTMLInputElement;
  if (smtpEl && !smtpEl.value) smtpEl.value = c.smtp;
  if (imapEl && !imapEl.value) imapEl.value = c.imap;
}

(window as any).autorellenarSmtp = autorellenarSmtp;
async function guardarConfigSmtp(): Promise<void> {
  const servidor = (document.getElementById("smtp-servidor") as HTMLInputElement)?.value.trim();
  const imapServidor = (document.getElementById("imap-servidor") as HTMLInputElement)?.value.trim();
  const usuario = (document.getElementById("smtp-usuario") as HTMLInputElement)?.value.trim();
  const password = (document.getElementById("smtp-password") as HTMLInputElement)?.value;
  const remitentes = (document.getElementById("smtp-remitentes") as HTMLInputElement)?.value.trim() ?? "";

  if (!servidor || !usuario || !password) {
    mostrarToast("Rellena todos los campos", true);
    return;
  }

  try {
    const firma = (document.getElementById("smtp-firma") as HTMLTextAreaElement)?.value.trim() ?? "";
    await invoke("guardar_config_email_tauri", {
      smtpServidor: servidor,
      imapDominio: imapServidor || servidor.replace("smtp.", "imap."),
      usuario,
      password,
      remitentes,
      firma,
    });
    _smtpConfigurado = true;
    _firmaEmail = firma;
    (document.getElementById("smtp-password") as HTMLInputElement).value = "";
    toggleConfigSmtp();
    mostrarToast("Configuración guardada y cifrada", false);
    await cargarBandejaEmail();
  } catch (error) {
    mostrarToast("Error: " + String(error), true);
  }
}

async function enviarEmail(): Promise<void> {
  const destinatario = (document.getElementById("comp-destinatario") as HTMLInputElement)?.value.trim();
  const cc = (document.getElementById("comp-cc") as HTMLInputElement)?.value.trim() ?? "";
  const cco = (document.getElementById("comp-cco") as HTMLInputElement)?.value.trim() ?? "";
  const asunto = (document.getElementById("comp-asunto") as HTMLInputElement)?.value.trim();
  const estado = document.getElementById("comp-estado");
  const cuerpo = (document.getElementById("comp-cuerpo") as HTMLTextAreaElement)?.value.trim() ?? "";

  if (!destinatario || !asunto) {
    mostrarToast("Rellena destinatario y asunto", true);
    return;
  }
  if (!archivoEmailFile && !archivoEmailRuta) {
    mostrarToast("Selecciona un archivo para adjuntar", true);
    return;
  }

  const confirmado = window.confirm(
    "AVISO DE SEGURIDAD\n\n" +
    "Vas a enviar este documento DESCIFRADO por email.\n" +
    "El destinatario podrá leerlo sin necesitar Babel.\n\n" +
    "¿Continuar?"
  );
  if (!confirmado) return;

  if (estado) estado.textContent = "Enviando...";

  try {
    if (archivoEmailFile) {
      const bytes = Array.from(new Uint8Array(await archivoEmailFile.arrayBuffer()));
      await invoke("enviar_bytes_cifrados_tauri", {
        nombreArchivo: archivoEmailFile.name,
        bytes,
        destinatario,
        cc,
        cco,
        asunto,
        cuerpo,
      });
    } else {
      await invoke("enviar_archivo_cifrado_tauri", {
        ruta: archivoEmailRuta,
        destinatario,
        cc,
        cco,
        asunto,
        cuerpo,
      });
    }
    if (estado) estado.textContent = "";
    mostrarToast("✓ Enviado cifrado", false);
    cerrarCompositor();
  } catch (error) {
    if (estado) estado.textContent = "";
    mostrarToast("Error enviando: " + String(error), true);
  }
}

async function sincronizarEmail(): Promise<void> {
  if (!_smtpConfigurado) {
    toggleConfigSmtp();
    return;
  }
  await cargarBandejaEmail();
}

function responderEmail(): void {
  const asuntoEl = document.getElementById("visor-asunto");
  const metaEl = document.getElementById("visor-meta");
  const asunto = asuntoEl?.textContent ?? "";
  const meta = metaEl?.textContent ?? "";
  const remitente = meta.replace(/^De: /, "").split(" · ")[0] ?? "";

  abrirComponerEmail();

  const destinatario = document.getElementById("comp-destinatario") as HTMLInputElement;
  const asuntoComp = document.getElementById("comp-asunto") as HTMLInputElement;
  if (destinatario) destinatario.value = remitente;
  if (asuntoComp && asunto) asuntoComp.value = asunto.startsWith("Re:") ? asunto : `Re: ${asunto}`;
}

let _zoomEmailRem: number = 0.92;

function cambiarZoomEmail(delta: number): void {
  _zoomEmailRem = Math.max(0.72, Math.min(1.5, _zoomEmailRem + delta * 0.1));
  const cuerpoEl = document.getElementById("email-visor-cuerpo");
  if (cuerpoEl) cuerpoEl.style.fontSize = `${_zoomEmailRem}rem`;
}

async function copiarCuerpoEmail(): Promise<void> {
  const cuerpoEl = document.getElementById("email-visor-cuerpo");
  if (!cuerpoEl) return;
  try {
    await navigator.clipboard.writeText(cuerpoEl.innerText);
    mostrarToast("Texto copiado al portapapeles", false);
  } catch {
    mostrarToast("No se pudo copiar el texto", true);
  }
}

async function marcarEmailNoLeido(): Promise<void> {
  if (emailVisorActualId === null || _imapMutando) return;
  _imapMutando = true;
  const id = emailVisorActualId;
  try {
    await invoke("marcar_no_leido_tauri", { id });
    const itemEl = document.querySelector(`.email-item[data-id="${id}"]`) as HTMLElement | null;
    if (itemEl) {
      itemEl.classList.add("no-leido");
      if (!itemEl.querySelector(".email-punto-nuevo")) {
        const punto = document.createElement("span");
        punto.className = "email-punto-nuevo";
        itemEl.querySelector(".email-item-cabecera")?.appendChild(punto);
      }
    }
    emailsVistos.delete(id);
    mostrarToast("Marcado como no leído", false);
  } catch (e) {
    mostrarToast("Error: " + String(e), true);
  } finally {
    _imapMutando = false;
  }
}

function insertarPlantillaEmail(texto: string): void {
  const cuerpo = document.getElementById("comp-cuerpo") as HTMLTextAreaElement;
  if (!cuerpo) return;
  const firma = _firmaEmail ? `\n\n—\n${_firmaEmail}` : "";
  cuerpo.value = texto + firma;
  cuerpo.focus();
}

async function eliminarEmailActual(): Promise<void> {
  if (emailVisorActualId === null || _imapMutando) return;
  _imapMutando = true;
  const id = emailVisorActualId;
  try {
    await invoke("eliminar_email_tauri", { id });
    cerrarVisorEmail();
    mostrarToast("Correo eliminado.", false);
    await cargarBandejaEmail();
  } catch (e) {
    mostrarToast(`Error eliminando: ${e}`, true);
  } finally {
    _imapMutando = false;
  }
}

async function cambiarIdiomaEmail(idioma: string): Promise<void> {
  const cuerpoEl = document.getElementById("email-visor-cuerpo");
  if (!cuerpoEl) return;
  if (idioma === "ninguno") {
    renderizarCuerpoEmail(cuerpoEl, _cuerpoEmailOriginal);
    return;
  }
  if (!_cuerpoEmailOriginal) return;
  cuerpoEl.innerHTML = '<div class="email-cargando">TRADUCIENDO...</div>';
  try {
    const textoPlano = _cuerpoEmailOriginal.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
    const [traducido] = await invoke<[string, number]>("traducir_texto", { texto: textoPlano, idioma });
    cuerpoEl.textContent = traducido;
  } catch (e) {
    renderizarCuerpoEmail(cuerpoEl, _cuerpoEmailOriginal);
    mostrarToast("Error al traducir: " + String(e), true);
    const sel = document.getElementById("email-idioma") as HTMLSelectElement;
    if (sel) sel.value = "ninguno";
  }
}

function filtrarEmails(texto: string): void {
  const q = texto.toLowerCase();
  document.querySelectorAll<HTMLElement>("#email-lista .email-item").forEach(item => {
    const remitente = item.querySelector(".email-item-remitente")?.textContent?.toLowerCase() ?? "";
    const asunto = item.querySelector(".email-item-asunto")?.textContent?.toLowerCase() ?? "";
    item.style.display = !q || remitente.includes(q) || asunto.includes(q) ? "" : "none";
  });
}

// Navega a EMAIL y abre el compositor con el archivo de ARCHIVOS ya adjuntado
async function enviarArchivoDesdeArchivos(ruta: string): Promise<void> {
  cambiarModoP2P("email");
  mostrarPantalla("comunicacion");
  abrirComponerEmail();
  archivoEmailRuta = ruta;
  const nombre = ruta.split("/").pop() ?? ruta;
  const el = document.getElementById("comp-archivo-nombre");
  if (el) el.textContent = "◫ " + nombre;
}
// BIP39 — FRASE DE RECUPERACIÓN

function mostrarFrase(palabras: string[]): void {
  const sidebar = document.getElementById("chat-sidebar");
  if (sidebar) sidebar.classList.add("hidden");
  const grid = document.getElementById("frase-grid");
  if (grid) {
    grid.innerHTML = palabras.map((p, i) => {
      return `<div class="palabra-bip39"><span class="palabra-numero">${i + 1}</span><span class="palabra-texto">${escapeHTML(p)}</span></div>`;
    }).join("");
  }
  mostrarPantalla("frase");
}

// Cierra la pantalla de frase y navega al login
function cerrarFrase(): void {
  mostrarPantalla("login");
}

// Navega a la pantalla de recuperación desde login
function irARecuperacion(): void {
  for (let i = 1; i <= 12; i++) {
    const input = document.getElementById(`rec-palabra-${i}`) as HTMLInputElement;
    if (input) input.value = "";
  }
  document.getElementById("recovery-msg")?.classList.add("hidden");
  mostrarPantalla("recuperacion");
}

async function imprimirFrase(): Promise<void> {
  const grid = document.getElementById("frase-grid");
  if (!grid) return;

  // Solo pasamos las 12 palabras; Rust valida contra el diccionario BIP39 y construye
  // la plantilla de impresión. No cruzamos HTML arbitrario por la frontera (sin superficie XSS).
  const palabras = Array.from(grid.querySelectorAll(".palabra-bip39")).map((el) =>
    (el.querySelector(".palabra-texto") as HTMLElement)?.textContent?.trim().toLowerCase() ?? ""
  );

  try {
    const ruta = await invoke<string>("guardar_html_frase", { palabras });
    await openPath(ruta);
    // Borrar el HTML con frase BIP39 tras 5s — tiempo suficiente para que Safari lo cargue
    setTimeout(() => invoke("borrar_html_frase").catch(() => {}), 5000);
  } catch (e) {
    const msg = document.getElementById("frase-msg");
    if (msg) {
      msg.textContent = "Error al abrir el documento de impresión.";
      msg.classList.remove("hidden");
    }
  }
}

// Intenta recuperar el búnker con las 12 palabras introducidas.
// recuperar_y_autenticar realiza recuperación + login en Rust — las credenciales
// nunca pasan por el heap JS ni por el DOM.
async function intentarRecuperacion(): Promise<void> {
  const palabras: string[] = [];
  for (let i = 1; i <= 12; i++) {
    const val = (document.getElementById(`rec-palabra-${i}`) as HTMLInputElement)?.value.trim().toLowerCase();
    if (!val) {
      mostrarMensaje("recovery-msg", `FALTA LA PALABRA ${i}`, true);
      return;
    }
    palabras.push(val);
  }

  mostrarMensaje("recovery-msg", "VERIFICANDO FRASE...", false);

  try {
    const aviso = await invoke<string>("recuperar_y_autenticar", { palabras });
    for (let i = 1; i <= 12; i++) {
      const el = document.getElementById(`rec-palabra-${i}`) as HTMLInputElement | null;
      if (el) { el.value = "0".repeat(el.value.length); el.value = ""; }
    }
    mostrarMensaje("recovery-msg",
      aviso ? `⚠ ${aviso} — Accediendo...` : `✓ FRASE VERIFICADA — ACCESO CONCEDIDO`, false);

    _sesionActiva = true;
    activarTimerInactividad();
    invoke<boolean>("tiene_config_email").then(ok => {
      _smtpConfigurado = ok;
      if (ok) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
    }).catch(() => {});

    setTimeout(() => {
      const nombreGuardado = localStorage.getItem("babel-nombre-display");
      _sesionUsuario = nombreGuardado ?? "";
      const bienvenida = document.getElementById("bienvenida-usuario");
      if (bienvenida) bienvenida.textContent = nombreGuardado ? `Bienvenido, ${nombreGuardado}` : "Bienvenido";
      if (nombreGuardado === null) {
        mostrarPantalla("nombre");
      } else {
        mostrarPantalla("principal");
        cargarAjustesTraduccion().catch(() => {});
      }
    }, 1500);

  } catch (error) {
    mostrarMensaje("recovery-msg", String(error), true);
  }
}

// Ver la frase desde dentro de la app (pantalla principal o configuración)
async function verFraseApp(): Promise<void> {
  try {
    const palabras = await invoke<string[]>("ver_frase_recuperacion");
    const modal = document.getElementById("modal-frase-app");
    const grid = document.getElementById("modal-frase-grid");
    if (!modal || !grid) return;
    grid.innerHTML = palabras.map((p, i) => {
      return `<div class="palabra-bip39"><span class="palabra-numero">${i + 1}</span><span class="palabra-texto">${escapeHTML(p)}</span></div>`;
    }).join("");
    modal.classList.remove("hidden");
  } catch (error) {
    mostrarToast("Error: " + String(error), true);
  }
}

// Zeroiza las palabras en el DOM y cierra el modal de frase
function cerrarVerFrase(): void {
  const modal = document.getElementById("modal-frase-app");
  const grid = document.getElementById("modal-frase-grid");
  // Zeroize de las palabras antes de cerrar
  if (grid) {
    grid.querySelectorAll(".palabra-texto").forEach(el => {
      el.textContent = "0".repeat(el.textContent?.length ?? 0);
      el.textContent = "";
    });
  }
  modal?.classList.add("hidden");
}
// TÉRMINOS DE USO

// Muestra el modal de términos de uso (solo al primer arranque)
function mostrarModalTerminos(): void {
  const modal = document.getElementById("modal-terminos");
  modal?.classList.remove("hidden");
}

async function aceptarTerminos(): Promise<void> {
  const checkbox = document.getElementById("terminos-checkbox") as HTMLInputElement;
  if (!checkbox?.checked) {
    mostrarToast("Debes aceptar los términos para continuar", true);
    return;
  }
  try {
    await invoke("aceptar_terminos");
    document.getElementById("modal-terminos")?.classList.add("hidden");
    const bunkerExiste = await invoke<boolean>("comprobar_estado_bunker");
    mostrarPantalla(bunkerExiste ? "login" : "decision");
  } catch (error) {
    mostrarToast("Error: " + String(error), true);
  }
}
// REGISTRO GLOBAL DE FUNCIONES — expuestas en window para dispatchInlineHandler
(window as any).crearBunker = crearBunker;
(window as any).intentarAcceso = intentarAcceso;
(window as any).manejarSeleccion = manejarSeleccion;
(window as any).toggleBorrarOriginal = toggleBorrarOriginal;
(window as any).toggleBorradoAutomatico = toggleBorradoAutomatico;
(window as any).cambiarIdiomaDesdeSelectores = cambiarIdiomaDesdeSelectores;
(window as any).cambiarIdiomaDesdeAjustes = cambiarIdiomaDesdeAjustes;
(window as any).cambiarCategoriaDiccionario = cambiarCategoriaDiccionario;

(window as any).manejarSeleccionArchivoEmail = manejarSeleccionArchivoEmail;
(window as any).cambiarIdiomaEmail = cambiarIdiomaEmail;
(window as any).confirmarRenombrar = confirmarRenombrar;
(window as any).cerrarModalRenombrar = cerrarModalRenombrar;
(window as any).confirmarRenombrarArchivo = confirmarRenombrarArchivo;
(window as any).cerrarModalRenombrarArchivo = cerrarModalRenombrarArchivo;
(window as any).guardarTimeoutSesion = guardarTimeoutSesion;
(window as any).filtrarEmails = filtrarEmails;

async function aprobarPeerPendiente(fingerprint: string): Promise<void> {
  try {
    await invoke("aprobar_peer_pendiente_cmd", { fingerprint });
    mostrarToast("Peer aprobado. Puede volver a conectarse.", false);
    await actualizarPeersPendientes();
  } catch (e) {
    mostrarToast(`Error aprobando peer: ${e}`, true);
  }
}

async function actualizarPeersPendientes(): Promise<void> {
  try {
    const pendientes = await invoke<string[]>("listar_peers_pendientes_cmd");
    const banner = document.getElementById("peers-pendientes-banner");
    if (!banner) return;
    if (pendientes.length === 0) {
      banner.style.display = "none";
      return;
    }
    banner.style.display = "block";
    banner.innerHTML = pendientes.map(p =>
      `<div style="display:flex;gap:8px;align-items:center;margin:4px 0">
        <span style="font-family:monospace;font-size:0.85rem">${escapeHTML(p)}</span>
        <button type="button" data-peer="${escapeHTML(p.split(':')[0])}" class="btn-aprobar-peer" style="background:var(--dorado);color:#000;border:none;border-radius:4px;padding:2px 8px;cursor:pointer">Aprobar</button>
      </div>`
    ).join("");
    banner.querySelectorAll<HTMLButtonElement>(".btn-aprobar-peer").forEach(btn => {
      btn.addEventListener("click", () => aprobarPeerPendiente(btn.dataset.peer ?? ""));
    });
  } catch { /* sin sesión activa */ }
}

let _rutaArrastrada: string = "";
let _esGuardadoArrastrado: boolean = false;

function allowDrop(event: DragEvent): void {
  event.preventDefault();
  (event.currentTarget as HTMLElement)?.classList.add("drag-sobre");
}

function dragLeave(event: DragEvent): void {
  (event.currentTarget as HTMLElement)?.classList.remove("drag-sobre");
}

async function soltarEnBuzon(event: DragEvent, buzonId: string): Promise<void> {
  event.preventDefault();
  (event.currentTarget as HTMLElement)?.classList.remove("drag-sobre");
  if (!_rutaArrastrada) return;
  try {
    const cmd = _esGuardadoArrastrado ? "mover_archivo_guardado" : "mover_archivo";
    await invoke(cmd, { ruta: _rutaArrastrada, buzonDestino: buzonId });
    await cargarArchivosGuardados();
    mostrarToast("✓ Archivo movido", false);
  } catch (e) {
    mostrarToast("Error al mover: " + String(e), true);
  }
  _rutaArrastrada = "";
}

(window as any).allowDrop = allowDrop;
(window as any).dragLeave = dragLeave;
(window as any).soltarEnBuzon = soltarEnBuzon;

// AJUSTES — Tema, Idioma UI, Ver Contraseña

const TRADUCCIONES_UI: Record<string, Record<string, string>> = {
  es: {
    traducir: "TRADUCIR", archivos: "ARCHIVOS", p2p: "P2P", ajustes: "⚙ AJUSTES", cerrarSesion: "CERRAR SESIÓN",
    borrarChat: "BORRAR CHAT", configuracion: "CONFIGURACIÓN", borrarAlSalir: "BORRAR AL SALIR",
    borrarAlSalirDesc: "Limpia el chat al volver al panel", emailAuto: "EMAIL AUTO", proximamente: "Próximamente",
    diccionario: "DICCIONARIO", vocabularioActivo: "Vocabulario activo", volver: "← VOLVER",
    verArchivo: "◫ VER ARCHIVO", eliminar: "✕ ELIMINAR", actualizar: "↺ ACTUALIZAR",
    exportarTodo: "↓ EXPORTAR TODO", importar: "+ IMPORTAR", tema: "TEMA", idiomaInterfaz: "IDIOMA DE LA INTERFAZ",
    bienvenido: "BIENVENIDO AL SISTEMA", bienvenidoSistema: "BIENVENIDO AL SISTEMA", accederBunker: "ACCEDER A BÚNKER EXISTENTE",
    autenticacion: "AUTENTICACIÓN REQUERIDA", ajustesTitulo: "AJUSTES", volverPanel: "← VOLVER AL PANEL",
    fraseRecuperacion: "FRASE DE RECUPERACIÓN", recuperarBunker: "RECUPERAR BÚNKER",
    traducidosGuardados: "TRADUCIDOS Y GUARDADOS", buzones: "BUZONES", archivosTitulo: "ARCHIVOS",
    noArchivos: "No hay archivos guardados", arrastra: "Arrastra documentos aquí para cifrarlos",
    buzonesTord: "BUZONES", finder: "◫ FINDER",
  },
  en: {
    traducir: "TRANSLATE", archivos: "FILES", p2p: "P2P", ajustes: "⚙ SETTINGS", cerrarSesion: "SIGN OUT",
    borrarChat: "CLEAR CHAT", configuracion: "SETTINGS", borrarAlSalir: "CLEAR ON EXIT",
    borrarAlSalirDesc: "Clears chat when returning to panel", emailAuto: "AUTO EMAIL", proximamente: "Coming soon",
    diccionario: "DICTIONARY", vocabularioActivo: "Active vocabulary", volver: "← BACK",
    verArchivo: "◫ VIEW FILE", eliminar: "✕ DELETE", actualizar: "↺ REFRESH",
    exportarTodo: "↓ EXPORT ALL", importar: "+ IMPORT", tema: "THEME", idiomaInterfaz: "INTERFACE LANGUAGE",
    bienvenido: "WELCOME TO THE SYSTEM", bienvenidoSistema: "WELCOME TO THE SYSTEM", accederBunker: "ACCESS EXISTING VAULT",
    autenticacion: "AUTHENTICATION REQUIRED", ajustesTitulo: "SETTINGS", volverPanel: "← BACK TO PANEL",
    fraseRecuperacion: "RECOVERY PHRASE", recuperarBunker: "RECOVER VAULT",
    traducidosGuardados: "TRANSLATED & SAVED", buzones: "FOLDERS", archivosTitulo: "FILES",
    noArchivos: "No saved files", arrastra: "Drag documents here to encrypt them",
    buzonesTord: "FOLDERS", finder: "◫ FINDER",
  },
  fr: {
    traducir: "TRADUIRE", archivos: "FICHIERS", p2p: "P2P", ajustes: "⚙ PARAMÈTRES", cerrarSesion: "DÉCONNEXION",
    borrarChat: "EFFACER CHAT", configuracion: "CONFIGURATION", borrarAlSalir: "EFFACER EN QUITTANT",
    borrarAlSalirDesc: "Efface le chat au retour au panneau", emailAuto: "EMAIL AUTO", proximamente: "Bientôt",
    diccionario: "DICTIONNAIRE", vocabularioActivo: "Vocabulaire actif", volver: "← RETOUR",
    verArchivo: "◫ VOIR FICHIER", eliminar: "✕ SUPPRIMER", actualizar: "↺ ACTUALISER",
    exportarTodo: "↓ TOUT EXPORTER", importar: "+ IMPORTER", tema: "THÈME", idiomaInterfaz: "LANGUE DE L'INTERFACE",
    bienvenido: "BIENVENUE DANS LE SYSTÈME", bienvenidoSistema: "BIENVENUE DANS LE SYSTÈME", accederBunker: "ACCÉDER AU COFFRE EXISTANT",
    autenticacion: "AUTHENTIFICATION REQUISE", ajustesTitulo: "PARAMÈTRES", volverPanel: "← RETOUR AU PANNEAU",
    fraseRecuperacion: "PHRASE DE RÉCUPÉRATION", recuperarBunker: "RÉCUPÉRER LE COFFRE",
    traducidosGuardados: "TRADUITS ET SAUVEGARDÉS", buzones: "DOSSIERS", archivosTitulo: "FICHIERS",
    noArchivos: "Aucun fichier sauvegardé", arrastra: "Faites glisser des documents ici pour les chiffrer",
    buzonesTord: "DOSSIERS", finder: "◫ FINDER",
  },
  ar: {
    traducir: "ترجمة", archivos: "ملفات", p2p: "P2P", ajustes: "⚙ إعدادات", cerrarSesion: "تسجيل الخروج",
    borrarChat: "مسح المحادثة", configuracion: "الإعدادات", borrarAlSalir: "مسح عند الخروج",
    borrarAlSalirDesc: "يمسح المحادثة عند العودة", emailAuto: "بريد تلقائي", proximamente: "قريباً",
    diccionario: "القاموس", vocabularioActivo: "المفردات النشطة", volver: "→ رجوع",
    verArchivo: "◫ عرض الملف", eliminar: "✕ حذف", actualizar: "↺ تحديث",
    exportarTodo: "↓ تصدير الكل", importar: "+ استيراد", tema: "المظهر", idiomaInterfaz: "لغة الواجهة",
    bienvenido: "مرحباً بك في النظام", bienvenidoSistema: "مرحباً بك في النظام", accederBunker: "الدخول إلى الخزنة",
    autenticacion: "المصادقة مطلوبة", ajustesTitulo: "الإعدادات", volverPanel: "→ العودة إلى اللوحة",
    fraseRecuperacion: "عبارة الاسترداد", recuperarBunker: "استرداد الخزنة",
    traducidosGuardados: "مترجم ومحفوظ", buzones: "المجلدات", archivosTitulo: "الملفات",
    noArchivos: "لا توجد ملفات محفوظة", arrastra: "اسحب المستندات هنا لتشفيرها",
    buzonesTord: "المجلدات", finder: "◫ FINDER",
  },
};

function cambiarIdiomaUI(idioma: string): void {
  const t = TRADUCCIONES_UI[idioma] ?? TRADUCCIONES_UI["es"];
  localStorage.setItem("babel-idioma-ui", idioma);
  const mapa: Record<string, string> = {
    "pantalla-texto-traducir": t.traducir, "pantalla-texto-archivos": t.archivos,
    "pantalla-texto-p2p": t.p2p, "pantalla-texto-ajustes": t.ajustes,
    "pantalla-texto-cerrar": t.cerrarSesion, "ui-borrar-chat": t.borrarChat,
    "ui-configuracion": t.configuracion, "ui-borrar-al-salir": t.borrarAlSalir,
    "ui-borrar-al-salir-desc": t.borrarAlSalirDesc, "ui-email-auto": t.emailAuto,
    "ui-proximamente": t.proximamente, "ui-diccionario": t.diccionario,
    "ui-vocabulario-activo": t.vocabularioActivo, "ui-volver-archivos": t.volver,
    "btn-ver-sel-g": t.verArchivo, "btn-eliminar-sel-g": t.eliminar,
    "ui-actualizar": t.actualizar, "ui-exportar-todo": t.exportarTodo,
    "ui-importar": t.importar, "ui-tema": t.tema,
    "ui-idioma-interfaz": t.idiomaInterfaz, "ui-bienvenido-sistema": t.bienvenidoSistema,
    "ui-acceder-bunker": t.accederBunker, "ui-autenticacion-requerida": t.autenticacion,
    "ui-ajustes-titulo": t.ajustesTitulo, "ui-volver-panel": t.volverPanel,
    "ui-frase-recuperacion": t.fraseRecuperacion, "ui-recuperar-bunker": t.recuperarBunker,
    "ui-traducidos-guardados": t.traducidosGuardados, "ui-buzones": t.buzones,
    "ui-finder": t.finder, "ui-archivos-titulo": t.archivosTitulo,
    "ui-no-archivos": t.noArchivos, "ui-arrastra": t.arrastra,
  };
  for (const [id, texto] of Object.entries(mapa)) {
    const el = document.getElementById(id);
    if (el) el.textContent = texto;
  }
  // RTL para árabe
  document.documentElement.setAttribute("dir", idioma === "ar" ? "rtl" : "ltr");
}

function cambiarTema(tema: string): void {
  document.documentElement.setAttribute("data-tema", tema);
  localStorage.setItem("babel-tema", tema);
  const _mapaTemasBtn: Record<string, string> = {
    "negro": "tema-negro",
    "blanco-dorado": "tema-blanco2",
    "crema": "tema-crema",
    "blanco-negro": "tema-blanco-negro",
  };
  Object.entries(_mapaTemasBtn).forEach(([t, id]) => {
    const btn = document.getElementById(id);
    if (btn) btn.style.opacity = t === tema ? "1" : "0.45";
  });
}

function cargarAjustesGuardados(): void {
  const tema = localStorage.getItem("babel-tema") ?? "negro";
  const idioma = localStorage.getItem("babel-idioma-ui") ?? "es";
  cambiarTema(tema);
  const selector = document.getElementById("selector-idioma-ui") as HTMLSelectElement;
  if (selector) { selector.value = idioma; cambiarIdiomaUI(idioma); }
}

// Registrar funciones globales
(window as any).cambiarIdiomaUI = cambiarIdiomaUI;

(window as any).enviarMensajeP2P = enviarMensajeP2P;
(window as any).guardarNombreDisplay = guardarNombreDisplay;

function guardarNombreDisplay(): void {
  const input = document.getElementById("input-nombre-display") as HTMLInputElement;
  const nombre = input?.value.trim() ?? "";
  // Guardar siempre (aunque esté vacío) para no volver a preguntar en futuros logins
  localStorage.setItem("babel-nombre-display", nombre);
  _sesionUsuario = nombre;
  const bienvenida = document.getElementById("bienvenida-usuario");
  if (bienvenida) bienvenida.textContent = nombre ? `Bienvenido, ${nombre}` : "Bienvenido";
  mostrarPantalla("principal");
  cargarAjustesTraduccion().catch(() => {});
}

// Cargar ajustes + UX global al arrancar

document.addEventListener("DOMContentLoaded", () => {
  cargarAjustesGuardados();
  cargarAjustesTraduccion().catch(() => {});

  document.getElementById("btn-cancelar-traduccion")?.addEventListener("click", async () => {
    try {
      await invoke("cancelar_traduccion_activa");
      mostrarProcesando(false);
      añadirMensajeBabel("Traducción cancelada.", "BABEL · cancelada");
    } catch { /* silencioso */ }
  });

  const inputBuscar = document.getElementById("buscar-archivos-g") as HTMLInputElement | null;
  const btnLimpiar = document.getElementById("buscar-archivos-limpiar") as HTMLButtonElement | null;
  inputBuscar?.addEventListener("input", () => filtrarArchivosGuardados(inputBuscar.value));
  btnLimpiar?.addEventListener("click", () => {
    if (inputBuscar) inputBuscar.value = "";
    filtrarArchivosGuardados("");
  });
  document.getElementById("ir-a-todos-btn")?.addEventListener("click", () => seleccionarBuzonGuardados("todos"));

  // Escape cierra cualquier modal visible
  document.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key !== "Escape") return;
    const modales = [
      "modal-visor", "modal-paralelo", "modal-frase-app",
      "modal-renombrar", "modal-solicitud-p2p", "modal-renombrar-archivo",
    ];
    for (const id of modales) {
      const el = document.getElementById(id);
      if (el && !el.classList.contains("hidden")) {
        el.classList.add("hidden");
        return;
      }
    }
  });

  // Recovery BIP39: Enter avanza al siguiente campo; en el 12 verifica
  // Paste en cualquier campo: si hay 12+ palabras, distribuye automáticamente
  const distribuirPaste = (e: ClipboardEvent) => {
    const texto = e.clipboardData?.getData("text") ?? "";
    const partes = texto.trim().split(/\s+/);
    if (partes.length < 12) return;
    e.preventDefault();
    for (let j = 0; j < 12; j++) {
      const campo = document.getElementById(`rec-palabra-${j + 1}`) as HTMLInputElement | null;
      if (campo) campo.value = partes[j].toLowerCase();
    }
    (document.getElementById("rec-palabra-12") as HTMLInputElement | null)?.focus();
  };
  for (let i = 1; i <= 12; i++) {
    const input = document.getElementById(`rec-palabra-${i}`) as HTMLInputElement | null;
    if (!input) continue;
    const siguiente = i < 12 ? document.getElementById(`rec-palabra-${i + 1}`) as HTMLInputElement : null;
    input.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Enter") {
        e.preventDefault();
        if (siguiente) siguiente.focus();
        else intentarRecuperacion();
      }
    });
    input.addEventListener("paste", distribuirPaste);
  }

  // P2P chat: Enter envía, Shift+Enter inserta nueva línea
  const p2pInput = document.getElementById("p2p-input") as HTMLTextAreaElement | null;
  if (p2pInput) {
    p2pInput.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        enviarMensajeP2P();
      }
    });
  }

  // Email compositor: Ctrl+Enter / Cmd+Enter envía el correo
  const compCuerpo = document.getElementById("comp-cuerpo") as HTMLTextAreaElement | null;
  if (compCuerpo) {
    compCuerpo.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        enviarEmail();
      }
    });
  }

  // Atajos globales de navegación (solo cuando el foco no está en un input/textarea)
  document.addEventListener("keydown", (e: KeyboardEvent) => {
    const enInput = ["INPUT", "TEXTAREA", "SELECT"].includes((e.target as Element)?.tagName ?? "");
    if (enInput) return;
    if (e.altKey && e.key === "t") { mostrarPantalla("traduccion"); return; }
    if (e.altKey && e.key === "e") {
      mostrarPantalla("comunicacion");
      cambiarModoP2P("email");
      return;
    }
    if (e.key === "F5") {
      e.preventDefault();
      if (_smtpConfigurado) { sincronizarEmail(); mostrarToast("Actualizando bandeja…", false); }
    }
  });

  bindOnclicks(document.documentElement);

  // Chat input: Enter envía (sin Shift), input actualiza contador y auto-resize.
  // No se usan atributos inline para evitar problemas con dispatchInlineHandler
  // (que no puede evaluar if-conditionals ni referencias a `this`).
  const chatInput = document.getElementById("chat-input") as HTMLTextAreaElement | null;
  if (chatInput) {
    chatInput.addEventListener("keydown", (e: KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        enviarMensaje();
      }
    });
    chatInput.addEventListener("input", () => {
      actualizarContadorPalabras(chatInput.value);
      toggleBtnLimpiar(chatInput.value);
      chatInput.style.height = "auto";
      chatInput.style.height = chatInput.scrollHeight + "px";
    });
  }

  // MutationObserver: convierte atributos on* en nuevos nodos dinámicos
  const INLINE_ATTRS = INLINE_EVENT_MAP.map(([a]) => a);
  new MutationObserver((muts) => {
    for (const m of muts) {
      m.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node instanceof HTMLElement && INLINE_ATTRS.some(a => node.hasAttribute(a))) bindOnclickEl(node);
        const selector = INLINE_ATTRS.map(a => `[${a}]`).join(",");
        node.querySelectorAll<HTMLElement>(selector).forEach(bindOnclickEl);
      });
    }
  }).observe(document.body, { childList: true, subtree: true });

  // Pantalla de bloqueo: Enter navega entre campos y dispara desbloqueo
  document.getElementById("bloqueo-maestra")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") (document.getElementById("bloqueo-pass") as HTMLInputElement | null)?.focus();
  });
  document.getElementById("bloqueo-pass")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") desbloquearPantalla();
  });
});

// Tauri v2 inyecta nonces en script-src; con nonces 'unsafe-inline' queda ignorado
// por spec CSP, bloqueando onclick="fn()". Convertimos todos a addEventListener.
// MutationObserver lo aplica también a HTML generado dinámicamente (buzones, etc.)
function parseOnclickArg(s: string): unknown {
  s = s.trim();
  if ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"'))) return s.slice(1, -1);
  if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
  if (s === "true") return true;
  if (s === "false") return false;
  return s;
}

function dispatchInlineHandler(raw: string, ev: Event) {
  for (const part of raw.split(";").map((s) => s.trim()).filter(Boolean)) {
    if (part === "event.stopPropagation()") { ev.stopPropagation(); continue; }
    if (part === "event.preventDefault()") { ev.preventDefault(); continue; }
    const m = part.match(/^([\wÀ-ɏ$]+)\((.*?)\)\s*$/s);
    if (!m) continue;
    const fn = (window as unknown as Record<string, unknown>)[m[1]];
    if (typeof fn !== "function") continue;
    const argsRaw = m[2].trim();
    if (!argsRaw) { (fn as () => void)(); continue; }
    const args = argsRaw.split(",").map(parseOnclickArg);
    (fn as (...a: unknown[]) => void)(...args);
  }
}

// Mapeo de atributos inline → eventos DOM equivalentes
const INLINE_EVENT_MAP: Array<[string, string]> = [
  ["onclick",      "click"],
  ["ondragover",   "dragover"],
  ["ondragleave",  "dragleave"],
  ["ondrop",       "drop"],
  ["onchange",     "change"],
  ["oninput",      "input"],
  ["onkeydown",    "keydown"],
  ["onkeyup",      "keyup"],
  ["onsubmit",     "submit"],
];

function bindOnclickEl(el: HTMLElement) {
  for (const [attr, evtName] of INLINE_EVENT_MAP) {
    const raw = el.getAttribute(attr);
    if (!raw) continue;
    el.removeAttribute(attr);
    el.addEventListener(evtName, (ev: Event) => dispatchInlineHandler(raw, ev));
  }
}

function bindOnclicks(root: Element) {
  const selector = INLINE_EVENT_MAP.map(([a]) => `[${a}]`).join(",");
  root.querySelectorAll<HTMLElement>(selector).forEach(bindOnclickEl);
}