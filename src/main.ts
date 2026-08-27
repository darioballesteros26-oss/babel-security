import "./styles.css";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openPath, openUrl } from "@tauri-apps/plugin-opener";
import DOMPurify from "dompurify";

DOMPurify.addHook("afterSanitizeAttributes", (node) => {
  if (node.tagName === "A") {
    node.setAttribute("rel", "noopener noreferrer");
    node.setAttribute("target", "_blank");
  }
  if (node.tagName === "IMG") {
    const src = node.getAttribute("src") ?? "";
    // Permitir data: URIs y URLs HTTPS (imágenes reales de emails); bloquear el resto
    if (src.startsWith("data:image/") || src.startsWith("https://")) {
      node.setAttribute("src", src);
    } else {
      node.removeAttribute("src");
    }
  }
});

type Pantalla = "carga" | "decision" | "configuracion" | "login" | "principal" | "traduccion" | "archivos-guardados" | "comunicacion" | "frase" | "recuperacion" | "terminos" | "nombre" | "ajustes" | "registro";
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
  // Guardar selección al salir de la pantalla de archivos guardados
  const pantallaActual = document.querySelector<HTMLElement>(".pantalla:not(.hidden)");
  if (pantallaActual?.id === "pantalla-archivos-guardados" && nombre !== "archivos-guardados") {
    _seleccionGuardadosGuardada = Array.from(
      document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked")
    ).map(cb => (cb.closest(".archivo-card") as HTMLElement | null)?.dataset.ruta ?? "").filter(Boolean);
  }
  document.querySelectorAll<HTMLElement>(".pantalla")
    .forEach(p => p.classList.add("hidden"));
  document.getElementById(`pantalla-${nombre}`)?.classList.remove("hidden");
  if (pantallaEsSensible(nombre)) iniciarVigilanciaCaptura();
  else detenerVigilanciaCaptura();
  if (nombre === "login") escanearKeyloggerAlEntrar();
  if (nombre === "principal" || nombre === "ajustes") {
    // Arrancar servidor sinc al entrar (idempotente) para ser siempre descubrible
    invoke<string>("iniciar_sinc_servidor").catch(() => {});
    iniciarPollSolicitudSinc();
  }
  if (nombre === "ajustes") {
    cargarListaEmparejados().catch(() => {});
    invoke<boolean | null>("leer_preferencia_autologin").then(pref => {
      const badge = document.getElementById("autologin-estado-badge");
      if (badge) badge.textContent = pref === true ? "ACTIVO" : pref === false ? "DESACTIVADO" : "NO CONFIGURADO";
    }).catch(() => {});
  }
  if (nombre === "registro") {
    _modoSospechas = false;
    const btnH = document.getElementById("btn-tab-registro");
    const btnS = document.getElementById("btn-tab-sospechas");
    const btnF = document.getElementById("btn-filtro-registro");
    if (btnH) { btnH.style.color = "var(--dorado)"; btnH.style.opacity = "1"; }
    if (btnS) { btnS.style.color = ""; btnS.style.opacity = "0.4"; }
    if (btnF) btnF.classList.remove("hidden");
    cargarRegistroDia().catch(() => {});
  }
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

// ENTRADA SEGURA (anti-keylogger) — activa el modo de entrada segura del SO
// mientras el foco está en cualquier campo de contraseña, y lo desactiva al salir.
// Se apoya en delegación (focusin/focusout) para cubrir campos que aparecen
// dinámicamente. El comando Rust es idempotente: activar/desactivar de más es inocuo.
function esCampoPassword(el: EventTarget | null): boolean {
  return el instanceof HTMLInputElement && el.type === "password";
}

function activarEntradaSeguraEnPasswords(): void {
  document.addEventListener("focusin", (e) => {
    if (esCampoPassword(e.target)) invoke("activar_entrada_segura").catch(() => {});
  });
  document.addEventListener("focusout", (e) => {
    if (esCampoPassword(e.target)) invoke("desactivar_entrada_segura").catch(() => {});
  });
  // Si el usuario cambia de app con el foco aún en la contraseña, liberamos el modo
  // seguro para no dejar el teclado del sistema bloqueado; lo re-activamos al volver.
  window.addEventListener("blur", () => {
    invoke("desactivar_entrada_segura").catch(() => {});
  });
  window.addEventListener("focus", () => {
    if (esCampoPassword(document.activeElement)) {
      invoke("activar_entrada_segura").catch(() => {});
    }
  });
  // Si al registrar los listeners ya hay un campo de contraseña con foco (p. ej. por
  // autofocus), el focusin inicial ya ocurrió: lo cubrimos activando aquí.
  if (esCampoPassword(document.activeElement)) {
    invoke("activar_entrada_segura").catch(() => {});
  }
}

// VIGILANCIA DE CAPTURA DE PANTALLA — mientras se muestra contenido sensible,
// consulta a Rust cada 3 s si hay grabación/compartición/duplicación activa. Si la
// hay, cubre la app con un overlay difuminado (oculta el contenido al capturador) y
// avisa. El contenido reaparece solo al cesar la captura.
let _vigilanciaCapturaId: number | null = null;
let _pollRatId: number | null = null;
let _pollBadgeId: number | null = null;
let _traduciendo = false;

const PANTALLAS_SENSIBLES: Pantalla[] =
  ["principal", "traduccion", "archivos-guardados", "comunicacion", "frase", "ajustes", "registro"];

function pantallaEsSensible(nombre: Pantalla): boolean {
  return PANTALLAS_SENSIBLES.includes(nombre);
}

function mostrarOverlayCaptura(indicadores: string[]): void {
  let ov = document.getElementById("captura-overlay");
  if (!ov) {
    ov = document.createElement("div");
    ov.id = "captura-overlay";
    ov.style.cssText =
      "position:fixed;inset:0;z-index:11000;backdrop-filter:blur(24px);" +
      "-webkit-backdrop-filter:blur(24px);background:rgba(10,10,10,0.82);" +
      "display:flex;align-items:center;justify-content:center;text-align:center;padding:32px;";
    document.body.appendChild(ov);
  }
  const items = indicadores.map(i => `<li style="margin:4px 0;color:#ffd7a8;">${escapeHTML(i)}</li>`).join("");
  ov.innerHTML = `
    <div style="max-width:460px;">
      <div style="font-size:2.6rem;margin-bottom:12px;">🛑</div>
      <h2 style="color:#c9a227;letter-spacing:2px;font-size:1rem;margin-bottom:10px;">POSIBLE CAPTURA DE PANTALLA</h2>
      <p style="color:#ccc;font-size:0.82rem;line-height:1.55;margin-bottom:14px;">
        Babel ha ocultado el contenido sensible porque detectó actividad de grabación o compartición de pantalla:
      </p>
      <ul style="list-style:none;padding:0;font-size:0.8rem;margin:0 0 12px;">${items}</ul>
      <p style="color:#888;font-size:0.72rem;">El contenido volverá a mostrarse automáticamente al detener la captura.</p>
    </div>`;
}

function ocultarOverlayCaptura(): void {
  document.getElementById("captura-overlay")?.remove();
}

// Aviso discreto (baja confianza): una app capaz de compartir está abierta pero no
// necesariamente capturando. Chip en la esquina, sin bloquear el contenido.
function mostrarChipCapturaBaja(avisos: string[]): void {
  let chip = document.getElementById("captura-aviso-chip");
  if (!chip) {
    chip = document.createElement("div");
    chip.id = "captura-aviso-chip";
    chip.style.cssText =
      "position:fixed;bottom:14px;right:14px;z-index:9500;max-width:260px;" +
      "background:rgba(30,24,10,0.92);border:1px solid rgba(201,162,39,0.5);" +
      "color:#e8c76b;border-radius:8px;padding:8px 12px;font-size:0.72rem;" +
      "letter-spacing:0.5px;box-shadow:0 4px 16px rgba(0,0,0,0.5);";
    document.body.appendChild(chip);
  }
  chip.textContent = "⚠ App de captura o videollamada abierta";
  chip.title = avisos.join("\n");
}

function ocultarChipCapturaBaja(): void {
  document.getElementById("captura-aviso-chip")?.remove();
}

interface EstadoCaptura { bloqueo: string[]; aviso: string[]; }

async function comprobarCapturaUnaVez(): Promise<void> {
  try {
    const est = await invoke<EstadoCaptura>("hay_captura_de_pantalla");
    // Alta confianza → ocultar el contenido con el overlay difuminado.
    if (est.bloqueo.length > 0) mostrarOverlayCaptura(est.bloqueo);
    else ocultarOverlayCaptura();
    // Baja confianza → solo aviso discreto, sin bloquear.
    if (est.aviso.length > 0) mostrarChipCapturaBaja(est.aviso);
    else ocultarChipCapturaBaja();
  } catch { /* silencioso — no bloquear la UI si el comando falla */ }
}

function iniciarVigilanciaCaptura(): void {
  if (_vigilanciaCapturaId !== null) return;
  void comprobarCapturaUnaVez();
  _vigilanciaCapturaId = window.setInterval(() => void comprobarCapturaUnaVez(), 3000);
}

function detenerVigilanciaCaptura(): void {
  if (_vigilanciaCapturaId !== null) {
    clearInterval(_vigilanciaCapturaId);
    _vigilanciaCapturaId = null;
  }
  ocultarOverlayCaptura();
  ocultarChipCapturaBaja();
}

// Escaneo de keyloggers/RATs en el momento exacto en que se va a teclear la maestra
// (login o desbloqueo), sin esperar al monitor periódico de 5 min. No bloquea la UI:
// corre en segundo plano y, si hay amenazas, muestra la alerta persistente existente.
function escanearKeyloggerAlEntrar(): void {
  invoke<string[]>("escanear_keylogger_ahora")
    .then(amenazas => { if (amenazas.length > 0) mostrarAlertaAmenaza(amenazas); })
    .catch(() => { /* silencioso */ });
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
  // Cerrar dropdown de filtro email si el click es fuera del menú
  const dropdown = document.getElementById("email-menu-dropdown");
  if (dropdown && !dropdown.classList.contains("hidden")) {
    const wrap = dropdown.closest(".email-menu-wrap");
    if (wrap && !wrap.contains(e.target as Node)) {
      dropdown.classList.add("hidden");
      document.querySelector(".email-menu-trigger")?.classList.remove("abierto");
    }
  }

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
    case "ver-terminos": mostrarModalTerminos(); break;
    // UI
    case "toggle-sidebar": toggleSidebar(); break;
    case "toggle-contrasena": toggleContraseña(el.dataset.campo!); break;
    case "cambiar-tema": cambiarTema(el.dataset.tema!); break;
    case "ver-frase-app": verFraseApp(); break;
    case "reconfigurar-autologin":
      invoke("guardar_preferencia_autologin", { activo: false }).catch(() => {});
      document.getElementById("modal-autologin-config")?.classList.remove("hidden");
      break;
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
    case "abrir-union-pdfs":             void abrirPanelUnion(); break;
    case "cerrar-union-pdfs":            cerrarPanelUnion(); break;
    case "confirmar-union-pdfs":         void confirmarUnion(); break;
    case "convertir-imagenes-pdf":       abrirModalImgAPdf(); break;
    case "confirmar-img-pdf-uno":        void convertirImagenesAPdf("uno"); break;
    case "confirmar-img-pdf-varios":     void convertirImagenesAPdf("varios"); break;
    case "cerrar-modal-img-pdf":         cerrarModalImgAPdf(); break;
    case "compartir-archivo-guardado":   mostrarMenuCompartir(); break;
    case "cerrar-menu-compartir":        cerrarMenuCompartir(); break;
    case "mas-opciones-compartir":       cerrarMenuCompartir(); compartirDirecto(); break;
    case "cerrar-onboarding-compartir":  void cerrarOnboardingCompartir(); break;
    case "mostrar-form-destino":         mostrarFormDestino(); break;
    case "cancelar-form-destino":        ocultarFormDestino(); break;
    case "guardar-form-destino":         void guardarFormDestino(); break;
    case "cerrar-modal-compartir": cerrarModalCompartir(); break;
    case "confirmar-compartir": confirmarCompartir(); break;
    case "revelar-en-finder": revelarEnFinder(); break;
    case "copiar-pass-compartir": copiarPassCompartir(); break;
    case "eliminar-sel-guardados": eliminarSeleccionadosGuardados(); break;
    case "abrir-carpeta-guardados": void abrirFinderInApp(); break;
    case "exportar-todo": exportarTodo(); break;
    case "abrir-importar-guardado": mostrarPopupImportar(el); break;
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
    // Sincronización de dispositivos
    case "abrir-sinc-dispositivos": abrirSincronizacion(); break;
    case "cerrar-sinc": cerrarSincronizacion(); break;
    case "refrescar-sinc": buscarDispositivosSinc(); break;
    case "aceptar-sinc": aceptarSinc(); break;
    case "rechazar-sinc": rechazarSinc(); break;
    case "probar-conexion-dispositivo":
      if (el.dataset.id) probarConexionDispositivo(el.dataset.id, el as HTMLButtonElement); break;
    case "aplicar-buzon-b2":
      if (el.dataset.id) aplicarPendientesB2(el.dataset.id, el as HTMLButtonElement); break;
    case "desemparejar-dispositivo":
      if (el.dataset.id) desemparejarDispositivo(el.dataset.id); break;
    // Email
    case "sincronizar-email": sincronizarEmail(); break;
    case "toggle-email-menu": {
      const trigger = el as HTMLElement;
      const dropdown = document.getElementById("email-menu-dropdown");
      const abierto = !dropdown?.classList.contains("hidden");
      dropdown?.classList.toggle("hidden", abierto);
      trigger.closest(".email-menu-trigger")?.classList.toggle("abierto", !abierto);
      break;
    }
    case "filtro-email": {
      const vista = (el as HTMLElement).dataset.vista ?? "todos";
      const label: Record<string, string> = {
        todos: "TODOS", noleidos: "NO LEÍDOS", destacados: "DESTACADOS", archivados: "ARCHIVADOS"
      };
      document.getElementById("email-vista-label")!.textContent = label[vista] ?? "TODOS";
      document.querySelectorAll(".email-menu-item").forEach(b => b.classList.remove("activo"));
      (el as HTMLElement).classList.add("activo");
      document.getElementById("email-menu-dropdown")?.classList.add("hidden");
      document.querySelector(".email-menu-trigger")?.classList.remove("abierto");
      _emailVista = vista;
      cerrarVisorEmail();
      if (vista === "archivados" || _emailsCache.length === 0) {
        cargarBandejaEmail();
      } else {
        renderizarListaEmail(filtrarEmailsVista(_emailsCache, vista));
      }
      break;
    }
    case "abrir-componer-email": abrirComponerEmail(); break;
    case "toggle-config-smtp": toggleConfigSmtp(); break;
    case "guardar-smtp": guardarConfigSmtp(); break;
    case "iniciar-oauth-gmail": iniciarOAuthGmail(); break;
    case "revocar-oauth-gmail": revocarOAuthGmail(); break;
    case "conectar-gmail-desde-modal": cerrarModalConfigurarEmail(); iniciarOAuthGmail(); break;
    case "cerrar-modal-configurar-email": cerrarModalConfigurarEmail(); break;
    case "seleccionar-archivo-email": seleccionarArchivoEmail(); break;
    case "enviar-email": enviarEmail(); break;
    case "enviar-email-seleccion": {
      const sel = document.querySelector<HTMLInputElement>(".archivo-checkbox-g:checked");
      if (!sel) break;
      const selCard = sel.closest(".archivo-card") as HTMLElement;
      const selRuta = selCard?.dataset.ruta ?? "";
      if (selRuta) enviarArchivoDesdeArchivos(selRuta);
      break;
    }
    case "responder-email": responderEmail(); break;
    case "reenviar-email": reenviarEmail(); break;
    case "marcar-no-leido": marcarEmailNoLeido(); break;
    case "archivar-email-actual": archivarEmailActual(); break;
    case "toggle-destacado-visor": toggleDestacadoActual(); break;
    case "limpiar-adjunto-email": limpiarAdjuntoEmail(); break;
    case "copiar-cuerpo-email": copiarCuerpoEmail(); break;
    case "cambiar-zoom-email": cambiarZoomEmail(Number(el.dataset.delta!)); break;
    case "eliminar-email-actual": eliminarEmailActual(); break;
    case "cerrar-visor-email": cerrarVisorEmail(); break;
    case "cerrar-compositor": cerrarCompositor(); break;
    case "insertar-plantilla": insertarPlantillaEmail(el.dataset.texto!); break;
    // Registro diario
    case "ir-a-registro": void irARegistro(); break;
    case "registro-dia-anterior":
      _registroFechaOffset -= 1;
      _registroFiltroIPs.clear();
      cargarRegistroDia().catch(() => {});
      break;
    case "registro-dia-siguiente":
      if (_registroFechaOffset < 0) { _registroFechaOffset += 1; _registroFiltroIPs.clear(); cargarRegistroDia().catch(() => {}); }
      break;
    case "tab-registro": activarTabRegistro(); break;
    case "tab-sospechas": activarTabSospechas(); break;
    case "abrir-filtro-registro": abrirFiltroRegistro(); break;
    case "limpiar-filtro-registro": limpiarFiltroRegistro(); break;
    case "aplicar-filtro-registro": aplicarFiltroRegistro(); break;
    case "confirmar-registro-primera-vez": void confirmarRegistroPrimeraVez(); break;
    case "cerrar-registro-primera-vez":
      document.getElementById("modal-registro-primera-vez")?.classList.add("hidden");
      break;
    case "cerrar-registro-popup":
      document.getElementById("modal-registro-popup")?.classList.add("hidden");
      break;
    case "informar-evento-registro": informarEventoRegistro(el); break;
    case "abrir-ajustes-registro": void abrirAjustesRegistro(); break;
    case "cerrar-ajustes-registro":
      document.getElementById("modal-ajustes-registro")?.classList.add("hidden");
      break;
    case "guardar-ajustes-registro": void guardarAjustesRegistro(); break;
    // Finder in-app
    case "cerrar-finder-inapp": document.getElementById("modal-finder-inapp")?.classList.add("hidden"); break;
    // Modal contraseña recuperada BIP39
    case "cerrar-pass-recuperado": cerrarPassRecuperado(); break;
    // Modal de actualización automática
    case "instalar-actualizacion": void instalarActualizacion(); break;
    case "cerrar-modal-actualizacion":
      document.getElementById("modal-actualizacion")?.classList.add("hidden");
      break;
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// REGISTRO DIARIO
// ══════════════════════════════════════════════════════════════════════════════

interface EventoDiario {
  tipo: string;
  timestamp: string;
  ip: string;
  detalle: string;
}

interface PreferenciasRegistro {
  hora: number;
  minuto: number;
  segundo: number;
  primera_vez: boolean;
}

let _registroFechaOffset = 0;
let _registroFiltroTipos: Set<string> = new Set();
let _registroFiltroIPs: Set<string> = new Set();
let _registroEventosCache: EventoDiario[] = [];
let _timerRegistroDiario: ReturnType<typeof setTimeout> | null = null;
let _modoSospechas = false;

function fechaConOffset(offset: number): string {
  const d = new Date();
  d.setDate(d.getDate() + offset);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

function labelFecha(offset: number): string {
  if (offset === 0) return "HOY";
  if (offset === -1) return "AYER";
  const d = new Date();
  d.setDate(d.getDate() + offset);
  return d.toLocaleDateString("es-ES", { day: "2-digit", month: "2-digit", year: "numeric" });
}

function tipoLabelRegistro(tipo: string): string {
  const labels: Record<string, string> = {
    login: "Acceso",
    ver_archivo: "Archivo visto",
    mover_archivo: "Archivo movido",
    traducir: "Traducción",
    descargar: "Descarga",
    importar: "Importación",
    eliminar: "Archivo eliminado",
    cerrar_sesion: "Sesión cerrada",
    sospecha_hw: "Copia no autorizada bloqueada",
    sospecha_rat: "Acceso remoto bloqueado",
  };
  return labels[tipo] ?? tipo;
}

function activarTabRegistro(): void {
  _modoSospechas = false;
  const btnH = document.getElementById("btn-tab-registro");
  const btnS = document.getElementById("btn-tab-sospechas");
  const btnF = document.getElementById("btn-filtro-registro");
  if (btnH) { btnH.style.color = "var(--dorado)"; btnH.style.opacity = "1"; }
  if (btnS) { btnS.style.color = ""; btnS.style.opacity = "0.4"; }
  if (btnF) btnF.classList.remove("hidden");
  cargarRegistroDia().catch(() => {});
}

function activarTabSospechas(): void {
  _modoSospechas = true;
  const btnH = document.getElementById("btn-tab-registro");
  const btnS = document.getElementById("btn-tab-sospechas");
  const btnF = document.getElementById("btn-filtro-registro");
  if (btnH) { btnH.style.color = ""; btnH.style.opacity = "0.4"; }
  if (btnS) { btnS.style.color = "var(--dorado)"; btnS.style.opacity = "1"; }
  if (btnF) btnF.classList.add("hidden");
  cargarRegistroDia().catch(() => {});
}

function renderizarSospechas(eventos: EventoDiario[]): void {
  const listaEl = document.getElementById("registro-lista")!;
  const resumenEl = document.getElementById("registro-resumen")!;

  const sospechas = eventos.filter(e => e.tipo === "sospecha_hw" || e.tipo === "sospecha_rat");

  const nHw = eventos.filter(e => e.tipo === "sospecha_hw").length;
  const nRat = eventos.filter(e => e.tipo === "sospecha_rat").length;
  resumenEl.innerHTML = sospechas.length > 0
    ? `<div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">
        ${nHw > 0 ? `<span class="registro-stat-alerta">⚠ ${nHw} copia${nHw !== 1 ? "s" : ""} no autorizada${nHw !== 1 ? "s" : ""}</span>` : ""}
        ${nRat > 0 ? `<span class="registro-stat-alerta" style="color:#ef4444;">⚠ ${nRat} acceso${nRat !== 1 ? "s" : ""} remoto${nRat !== 1 ? "s" : ""} bloqueado${nRat !== 1 ? "s" : ""}</span>` : ""}
      </div>`
    : `<div style="display:flex;gap:16px;align-items:center;">
        <span class="registro-stat" style="color:#22c55e;">✓ Sin sospechas detectadas</span>
      </div>`;

  if (sospechas.length === 0) {
    listaEl.innerHTML = `<p style="color:var(--texto-secundario);text-align:center;padding:32px 20px;font-size:0.7rem;letter-spacing:1px;">SIN SOSPECHAS REGISTRADAS</p>`;
    return;
  }

  // Si hay varias sospechas en el mismo día, mostrar entrada agrupada + detalles
  const agrupado = sospechas.length > 1
    ? `<div class="registro-evento registro-sospechoso" style="margin:8px 16px;border-radius:4px;">
        <div class="registro-evento-fila">
          <span class="registro-evento-tipo" style="color:#ef4444;letter-spacing:2px;">
            ${sospechas.length} AMENAZA${sospechas.length !== 1 ? "S" : ""} DETECTADA${sospechas.length !== 1 ? "S" : ""}
          </span>
          <span class="registro-badge-alerta">HOY</span>
        </div>
        <div style="margin-top:6px;padding-top:6px;border-top:1px solid rgba(239,68,68,0.15);">
          ${sospechas.map(ev => {
            const hora = ev.timestamp.split("T")[1] ?? "";
            const esRat = ev.tipo === "sospecha_rat";
            const etiqueta = esRat ? "RAT" : "COPIA";
            return `<div style="display:flex;justify-content:space-between;gap:8px;padding:3px 0;font-size:0.62rem;opacity:0.85;">
              <span style="font-family:monospace;color:var(--texto-secundario);flex-shrink:0;">${escapeHTML(hora)}</span>
              <span style="font-family:monospace;color:var(--texto-secundario);flex-shrink:0;">${escapeHTML(ev.ip)}</span>
              <span style="color:${esRat ? "#ef4444" : "var(--texto-secundario)"};flex-shrink:0;letter-spacing:1px;">[${etiqueta}]</span>
              <span style="color:var(--texto-secundario);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHTML(ev.detalle)}">${escapeHTML(ev.detalle)}</span>
            </div>`;
          }).join("")}
        </div>
      </div>`
    : "";

  const individuales = sospechas.length === 1
    ? sospechas.map(ev => {
        const hora = ev.timestamp.split("T")[1] ?? "";
        const esRat = ev.tipo === "sospecha_rat";
        const titulo = esRat ? "ACCESO REMOTO BLOQUEADO" : "COPIA NO AUTORIZADA BLOQUEADA";
        const badge = esRat ? "RAT" : "ELIMINADO";
        return `
          <div class="registro-evento registro-sospechoso">
            <div class="registro-evento-fila">
              <span class="registro-evento-tipo" style="${esRat ? "color:#ef4444;" : ""}">${titulo}</span>
              <span class="registro-evento-hora">${escapeHTML(hora)}</span>
            </div>
            <div class="registro-evento-fila" style="margin-top:2px;">
              <span class="registro-evento-ip">${escapeHTML(ev.ip)}</span>
              ${ev.detalle ? `<span class="registro-evento-nombre">${escapeHTML(ev.detalle)}</span>` : ""}
              <span class="registro-badge-alerta">${badge}</span>
            </div>
          </div>`;
      }).join("")
    : "";

  listaEl.innerHTML = agrupado + individuales;
}

async function irARegistro(): Promise<void> {
  document.getElementById("modal-registro-popup")?.classList.add("hidden");
  _registroFechaOffset = 0;
  _modoSospechas = false;
  // Restablecer el estado visual de las tabs
  const btnH = document.getElementById("btn-tab-registro");
  const btnS = document.getElementById("btn-tab-sospechas");
  const btnF = document.getElementById("btn-filtro-registro");
  if (btnH) { btnH.style.color = "var(--dorado)"; btnH.style.opacity = "1"; }
  if (btnS) { btnS.style.color = ""; btnS.style.opacity = "0.4"; }
  if (btnF) btnF.classList.remove("hidden");
  mostrarPantalla("registro");
}

async function cargarRegistroDia(): Promise<void> {
  const fecha = fechaConOffset(_registroFechaOffset);
  document.getElementById("registro-fecha-label")!.textContent = labelFecha(_registroFechaOffset);
  const btnSig = document.getElementById("btn-registro-siguiente") as HTMLButtonElement | null;
  if (btnSig) {
    btnSig.disabled = _registroFechaOffset >= 0;
    btnSig.style.opacity = _registroFechaOffset >= 0 ? "0.2" : "0.8";
    btnSig.style.cursor = _registroFechaOffset >= 0 ? "default" : "pointer";
  }

  try {
    const [eventos, ips] = await Promise.all([
      invoke<EventoDiario[]>("obtener_eventos_dia", { fecha }),
      invoke<string[]>("obtener_ips_historial"),
    ]);
    _registroEventosCache = eventos;
    if (_modoSospechas) {
      renderizarSospechas(eventos);
    } else {
      renderizarRegistro(eventos, ips);
    }
  } catch {
    document.getElementById("registro-lista")!.innerHTML =
      `<p style="color:var(--texto-secundario);text-align:center;padding:20px;font-size:0.7rem;letter-spacing:1px;">Sin eventos registrados.</p>`;
    document.getElementById("registro-resumen")!.innerHTML = "";
  }
}

function renderizarRegistro(eventos: EventoDiario[], ipsHistorial: string[]): void {
  const listaEl = document.getElementById("registro-lista")!;
  const resumenEl = document.getElementById("registro-resumen")!;

  const filtrados = eventos.filter(e =>
    e.tipo !== "sospecha_hw" &&
    e.tipo !== "sospecha_rat" &&
    (_registroFiltroTipos.size === 0 || _registroFiltroTipos.has(e.tipo)) &&
    (_registroFiltroIPs.size === 0 || _registroFiltroIPs.has(e.ip))
  ).slice().reverse();

  const logins = eventos.filter(e => e.tipo === "login").length;
  const archivos = eventos.filter(e =>
    ["ver_archivo", "traducir", "descargar", "importar"].includes(e.tipo)
  ).length;
  const sospechosos = eventos.filter(e =>
    e.tipo === "login" && e.ip !== "IP no disponible" && !ipsHistorial.includes(e.ip)
  ).length;

  resumenEl.innerHTML = `
    <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;">
      <span class="registro-stat">${logins} <small>acceso${logins !== 1 ? "s" : ""}</small></span>
      <span class="registro-stat">${archivos} <small>archivo${archivos !== 1 ? "s" : ""}</small></span>
      <span class="registro-stat">${eventos.filter(e => e.tipo !== "sospecha_hw" && e.tipo !== "sospecha_rat").length} <small>total</small></span>
      ${sospechosos > 0 ? `<span class="registro-stat-alerta">⚠ ${sospechosos} IP${sospechosos !== 1 ? "s" : ""} nueva${sospechosos !== 1 ? "s" : ""}</span>` : ""}
    </div>
  `;

  if (filtrados.length === 0) {
    listaEl.innerHTML = `<p style="color:var(--texto-secundario);text-align:center;padding:20px;font-size:0.7rem;letter-spacing:1px;">SIN EVENTOS${_registroFiltroTipos.size > 0 ? " CON ESTE FILTRO" : ""}</p>`;
    return;
  }

  listaEl.innerHTML = filtrados.map((ev) => {
    const esSospechoso = ev.tipo === "login" && ev.ip !== "IP no disponible" && !ipsHistorial.includes(ev.ip);
    const hora = ev.timestamp.split("T")[1] ?? "";
    return `
      <div class="registro-evento${esSospechoso ? " registro-sospechoso" : ""}">
        <div class="registro-evento-fila">
          <span class="registro-evento-tipo">${escapeHTML(tipoLabelRegistro(ev.tipo))}</span>
          <span class="registro-evento-hora">${escapeHTML(hora)}</span>
        </div>
        <div class="registro-evento-fila" style="margin-top:2px;">
          <span class="registro-evento-ip">${escapeHTML(ev.ip)}</span>
          ${ev.detalle ? `<span class="registro-evento-nombre">${escapeHTML(ev.detalle)}</span>` : ""}
          ${esSospechoso ? `<span class="registro-badge-alerta">IP NUEVA</span>` : ""}
        </div>
        <button type="button" class="registro-btn-informar"
          data-action="informar-evento-registro"
          data-tipo="${escapeHTML(ev.tipo)}"
          data-ts="${escapeHTML(ev.timestamp)}"
          data-ip="${escapeHTML(ev.ip)}"
          data-detalle="${escapeHTML(ev.detalle)}">
          INFORMAR A BABEL
        </button>
      </div>
    `;
  }).join("");
}

function informarEventoRegistro(el: HTMLElement): void {
  const tipo = el.dataset.tipo ?? "";
  const ts = el.dataset.ts ?? "";
  const ip = el.dataset.ip ?? "";
  const detalle = el.dataset.detalle ?? "";

  const asunto = encodeURIComponent(`[Babel] Actividad sospechosa — ${ts}`);
  const lineas = [
    "Hola equipo de Babel Security,",
    "",
    "He detectado una actividad que me parece sospechosa en mi cuenta de Babel.",
    "",
    "Detalles del evento:",
    `- Tipo: ${tipoLabelRegistro(tipo)}`,
    `- Fecha y hora: ${ts}`,
    `- IP registrada: ${ip}`,
    ...(detalle ? [`- Archivo: ${detalle}`] : []),
    "",
    "Por favor, ¿podéis revisarlo?",
    "",
    "Gracias.",
  ];
  const cuerpo = encodeURIComponent(lineas.join("\n"));
  openUrl(`mailto:securitybabel@gmail.com?subject=${asunto}&body=${cuerpo}`).catch(() => {});
}

function abrirFiltroRegistro(): void {
  document.querySelectorAll<HTMLInputElement>(".filtro-tipo").forEach(cb => {
    cb.checked = _registroFiltroTipos.has(cb.value);
  });
  // Poblar IPs únicas del día desde la caché
  const ipsUnicas = [...new Set(_registroEventosCache.map(e => e.ip).filter(ip => ip && ip !== "IP no disponible"))];
  const contenedor = document.getElementById("filtro-ips-contenedor");
  if (contenedor) {
    if (ipsUnicas.length === 0) {
      contenedor.innerHTML = `<p style="font-size:0.6rem;color:var(--texto-secundario);opacity:0.5;letter-spacing:1px;">Sin IPs registradas hoy</p>`;
    } else {
      contenedor.innerHTML = ipsUnicas.map(ip => `
        <label class="registro-filtro-label">
          <input type="checkbox" class="filtro-ip" value="${escapeHTML(ip)}"${_registroFiltroIPs.has(ip) ? " checked" : ""}>
          ${escapeHTML(ip)}
        </label>`).join("");
    }
  }
  document.getElementById("modal-filtro-registro")?.classList.remove("hidden");
}

function limpiarFiltroRegistro(): void {
  _registroFiltroTipos.clear();
  _registroFiltroIPs.clear();
  document.querySelectorAll<HTMLInputElement>(".filtro-tipo").forEach(cb => { cb.checked = false; });
  document.querySelectorAll<HTMLInputElement>(".filtro-ip").forEach(cb => { cb.checked = false; });
  document.getElementById("modal-filtro-registro")?.classList.add("hidden");
  cargarRegistroDia().catch(() => {});
}

function aplicarFiltroRegistro(): void {
  _registroFiltroTipos.clear();
  _registroFiltroIPs.clear();
  document.querySelectorAll<HTMLInputElement>(".filtro-tipo:checked").forEach(cb => {
    _registroFiltroTipos.add(cb.value);
  });
  document.querySelectorAll<HTMLInputElement>(".filtro-ip:checked").forEach(cb => {
    _registroFiltroIPs.add(cb.value);
  });
  document.getElementById("modal-filtro-registro")?.classList.add("hidden");
  cargarRegistroDia().catch(() => {});
}

function programarPopupRegistroDiario(hora: number, minuto: number, segundo: number): void {
  if (_timerRegistroDiario) {
    clearTimeout(_timerRegistroDiario);
    _timerRegistroDiario = null;
  }
  const ahora = new Date();
  const objetivo = new Date();
  objetivo.setHours(hora, minuto, segundo, 0);
  let ms = objetivo.getTime() - ahora.getTime();
  if (ms <= 0) ms += 24 * 60 * 60 * 1000;
  _timerRegistroDiario = setTimeout(() => {
    mostrarPopupResumenDiario().catch(() => {});
    programarPopupRegistroDiario(hora, minuto, segundo);
  }, ms);
}

async function mostrarPopupResumenDiario(): Promise<void> {
  const fecha = fechaConOffset(0);
  try {
    const [eventos, ips] = await Promise.all([
      invoke<EventoDiario[]>("obtener_eventos_dia", { fecha }),
      invoke<string[]>("obtener_ips_historial"),
    ]);

    const logins = eventos.filter(e => e.tipo === "login").length;
    const archivos = eventos.filter(e =>
      ["ver_archivo", "traducir", "descargar", "importar"].includes(e.tipo)
    ).length;
    const sospechosos = eventos.filter(e =>
      e.tipo === "login" && e.ip !== "IP no disponible" && !ips.includes(e.ip)
    );

    const popup = document.getElementById("registro-popup-contenido");
    if (popup) {
      popup.innerHTML = `
        <p style="font-size:0.72rem;color:var(--texto-secundario);margin:0 0 12px;letter-spacing:1px;">
          ${logins} acceso${logins !== 1 ? "s" : ""} · ${archivos} archivo${archivos !== 1 ? "s" : ""} tocado${archivos !== 1 ? "s" : ""}
        </p>
        ${sospechosos.length > 0 ? `
          <div style="background:rgba(239,68,68,0.08);border:1px solid rgba(239,68,68,0.3);border-radius:3px;padding:12px;margin-bottom:4px;">
            <strong style="font-size:0.7rem;color:#ef4444;letter-spacing:1px;">
              ⚠ ${sospechosos.length} acceso${sospechosos.length > 1 ? "s" : ""} desde IP nueva
            </strong>
            ${sospechosos.map(e => `
              <div style="font-size:0.65rem;opacity:0.8;margin-top:4px;font-family:monospace;">
                ${escapeHTML(e.timestamp.split("T")[1] ?? "")} — ${escapeHTML(e.ip)}
              </div>`).join("")}
          </div>
        ` : `<p style="font-size:0.72rem;color:#22c55e;letter-spacing:1px;margin:0;">✓ Sin actividad sospechosa</p>`}
      `;
    }
    document.getElementById("modal-registro-popup")?.classList.remove("hidden");
  } catch {
    // Silent — no interrumpir al usuario si el popup falla
  }
}

async function iniciarRegistroDiario(): Promise<void> {
  invoke("registrar_evento_diario", { tipo: "login", detalle: "" }).catch(() => {});
  try {
    const prefs = await invoke<PreferenciasRegistro>("obtener_preferencias_registro");
    // Aviso si se inicia sesión después de la hora programada para el registro
    if (!prefs.primera_vez) {
      const ahora = new Date();
      const horaConfig = prefs.hora * 60 + prefs.minuto;
      const horaActual = ahora.getHours() * 60 + ahora.getMinutes();
      if (horaActual > horaConfig) {
        const hStr = String(prefs.hora).padStart(2, "0");
        const mStr = String(prefs.minuto).padStart(2, "0");
        setTimeout(() => mostrarToast(`⚠ Acceso tardío — programado para las ${hStr}:${mStr}`, false), 1500);
      }
    }
    if (prefs.primera_vez) {
      const horaEl = document.getElementById("rp-hora") as HTMLInputElement | null;
      const minEl = document.getElementById("rp-minuto") as HTMLInputElement | null;
      const secEl = document.getElementById("rp-segundo") as HTMLInputElement | null;
      if (horaEl) horaEl.value = String(prefs.hora).padStart(2, "0");
      if (minEl) minEl.value = String(prefs.minuto).padStart(2, "0");
      if (secEl) secEl.value = String(prefs.segundo).padStart(2, "0");
      document.getElementById("modal-registro-primera-vez")?.classList.remove("hidden");
    } else {
      programarPopupRegistroDiario(prefs.hora, prefs.minuto, prefs.segundo);
    }
  } catch {
    // Silent
  }
}

async function confirmarRegistroPrimeraVez(): Promise<void> {
  const hora = Math.min(23, Math.max(0, parseInt((document.getElementById("rp-hora") as HTMLInputElement)?.value ?? "10", 10) || 0));
  const minuto = Math.min(59, Math.max(0, parseInt((document.getElementById("rp-minuto") as HTMLInputElement)?.value ?? "0", 10) || 0));
  const segundo = Math.min(59, Math.max(0, parseInt((document.getElementById("rp-segundo") as HTMLInputElement)?.value ?? "0", 10) || 0));
  try {
    await invoke("guardar_preferencias_registro", { hora, minuto, segundo });
    await invoke("marcar_primera_vez_registro");
    document.getElementById("modal-registro-primera-vez")?.classList.add("hidden");
    programarPopupRegistroDiario(hora, minuto, segundo);
    mostrarToast("Registro diario activado ✓", false);
  } catch (e) {
    mostrarToast("Error guardando preferencias: " + String(e), true);
  }
}

async function abrirAjustesRegistro(): Promise<void> {
  try {
    const prefs = await invoke<PreferenciasRegistro>("obtener_preferencias_registro");
    const horaEl = document.getElementById("ra-hora") as HTMLInputElement | null;
    const minEl = document.getElementById("ra-minuto") as HTMLInputElement | null;
    const secEl = document.getElementById("ra-segundo") as HTMLInputElement | null;
    if (horaEl) horaEl.value = String(prefs.hora).padStart(2, "0");
    if (minEl) minEl.value = String(prefs.minuto).padStart(2, "0");
    if (secEl) secEl.value = String(prefs.segundo).padStart(2, "0");
  } catch {
    // defaults stay
  }
  document.getElementById("modal-ajustes-registro")?.classList.remove("hidden");
}

async function guardarAjustesRegistro(): Promise<void> {
  const hora = Math.min(23, Math.max(0, parseInt((document.getElementById("ra-hora") as HTMLInputElement)?.value ?? "10", 10) || 0));
  const minuto = Math.min(59, Math.max(0, parseInt((document.getElementById("ra-minuto") as HTMLInputElement)?.value ?? "0", 10) || 0));
  const segundo = Math.min(59, Math.max(0, parseInt((document.getElementById("ra-segundo") as HTMLInputElement)?.value ?? "0", 10) || 0));
  try {
    await invoke("guardar_preferencias_registro", { hora, minuto, segundo });
    document.getElementById("modal-ajustes-registro")?.classList.add("hidden");
    programarPopupRegistroDiario(hora, minuto, segundo);
    mostrarToast(`Notificación configurada a las ${String(hora).padStart(2,"0")}:${String(minuto).padStart(2,"0")}:${String(segundo).padStart(2,"0")} ✓`, false);
  } catch (e) {
    mostrarToast("Error guardando: " + String(e), true);
  }
}

window.addEventListener("DOMContentLoaded", async () => {
  invoke("borrar_html_frase").catch(() => {});
  mostrarPantalla("carga");

  // Evento Rust: servidor USB listo → ocultar overlay + toast
  listen("servidor-usb-listo", () => {
    document.getElementById("servidor-cargando-overlay")?.classList.add("hidden");
    mostrarToast("Traductor listo", false);
  }).catch(() => {});

  // Evento Rust: el sidecar no pudo arrancar o expiró el timeout
  listen<string>("servidor-error", (ev) => {
    document.getElementById("servidor-cargando-overlay")?.classList.add("hidden");
    const msg = ev.payload ?? "El traductor no pudo iniciarse. Reinicia Babel.";
    mostrarToast(`⚠ ${msg}`, true);
  }).catch(() => {});

  // Verificar estado inicial del servidor (el sidecar puede llevar ya varios segundos arrancando)
  invoke<string>("estado_servidor_cmd").then((estado) => {
    if (estado === "cargando") {
      document.getElementById("servidor-cargando-overlay")?.classList.remove("hidden");
    }
  }).catch(() => {});

  // Evento Rust: monitor periódico detectó nueva amenaza de seguridad
  listen<string[]>("amenaza-detectada", (evento) => {
    const amenazas = evento.payload ?? [];
    if (amenazas.length > 0) mostrarAlertaAmenaza(amenazas);
  }).catch(() => {});

  // Evento Rust: resultado del flujo OAuth Gmail
  listen<{ ok: boolean; email?: string; error?: string }>("oauth_gmail_resultado", (ev) => {
    document.getElementById("oauth-progreso")?.classList.add("hidden");
    if (ev.payload.ok) {
      const emailMostrado = ev.payload.email || "Gmail";
      actualizarUIGmailOAuth(emailMostrado);
      _smtpConfigurado = true;
      _oauthGmailConectado = true;
      cerrarModalConfigurarEmail();
      mostrarToast(`Gmail conectado: ${emailMostrado}`, false);
      cargarBandejaEmail();
    } else {
      mostrarToast(`Error OAuth: ${ev.payload.error ?? "desconocido"}`, true);
    }
  }).catch(() => {});

  // Comprobar si ya hay OAuth Gmail guardado al iniciar sesión
  invoke<string | null>("estado_oauth_gmail_tauri").then((email) => {
    if (email) { actualizarUIGmailOAuth(email); _oauthGmailConectado = true; }
  }).catch(() => {});

  activarEntradaSeguraEnPasswords();

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

  // Progreso de la unión de PDFs (panel modal, no la pantalla de traducción).
  listen<{ pct: number; msg: string }>("progreso-union", (evento) => {
    const { pct, msg } = evento.payload;
    const textoEl = document.getElementById("union-progreso-texto");
    const barraEl = document.getElementById("union-progreso-barra");
    if (textoEl) textoEl.textContent = msg;
    if (barraEl) barraEl.style.width = `${Math.min(pct, 100)}%`;
  }).catch(() => {});

  // MODO SEGUNDO PLANO (fricción cero para "Guardar con Babel" desde el Finder):
  // ya NO bloqueamos la sesión al perder el foco de la ventana. El único cierre por
  // seguridad es el timeout de inactividad configurable (resetearTimerInactividad), que
  // sigue corriendo aunque la ventana esté en segundo plano/oculta y nunca puede
  // desactivarse del todo. Así, mientras la sesión esté viva, el clic derecho del Finder
  // cifra al instante sin ventana ni contraseña.

  // Al cerrar la ventana con sesión activa, ocultarla en vez de salir: el proceso sigue
  // vivo para servir guardados en segundo plano. Cmd+Q cierra Babel del todo.
  getCurrentWindow().onCloseRequested(async (event) => {
    if (_sesionActiva) {
      event.preventDefault();
      await getCurrentWindow().hide().catch(() => {});
    }
  }).catch(() => {});

  // FINDER — "Guardar con Babel": el backend cifra en silencio y emite un evento por
  // archivo procesado. Mostramos un toast y refrescamos la lista si procede.
  listen<{ nombre: string; ok: boolean; error?: string; originalNoBorrado?: boolean }>("finder-guardado", (e) => {
    const p = e.payload;
    if (p.ok) {
      mostrarToast(`Guardado en Babel: ${p.nombre}`, false);
      if (p.originalNoBorrado) mostrarToast(`El original no pudo borrarse — elimínalo manualmente desde el Finder`, true);
    } else mostrarToast(`No se pudo guardar ${p.nombre}: ${p.error ?? "error"}`, true);
    if (!document.getElementById("pantalla-archivos-guardados")?.classList.contains("hidden")) {
      cargarArchivosGuardados().catch(() => {});
    }
  }).catch(() => {});

  // FINDER — llegó un archivo pero la sesión estaba cerrada/caducada: mostrar la ventana
  // para pedir login. Tras autenticar, la cola se drena (ver intentarAcceso/desbloquear).
  listen("finder-necesita-login", () => {
    getCurrentWindow().show().catch(() => {});
    getCurrentWindow().setFocus().catch(() => {});
  }).catch(() => {});

  // Actualización disponible → mostrar popup
  listen<{ version: string; notas: string; fecha: string }>("actualizacion-disponible", (ev) => {
    const { version, notas } = ev.payload;
    const el = document.getElementById("modal-actualizacion");
    const elVer = document.getElementById("upd-version");
    const elNotas = document.getElementById("upd-notas");
    if (!el || !elVer || !elNotas) return;
    elVer.textContent = `Versión ${version}`;
    elNotas.textContent = notas || "Nueva versión disponible.";
    document.getElementById("upd-progreso")?.classList.add("hidden");
    document.getElementById("upd-botones")?.removeAttribute("style");
    el.classList.remove("hidden");
  }).catch(() => {});

  // Progreso de descarga/instalación
  listen<{ estado: string }>("actualizacion-progreso", (ev) => {
    const prog = document.getElementById("upd-progreso");
    const texto = document.getElementById("upd-progreso-texto");
    const botones = document.getElementById("upd-botones");
    if (prog && texto && botones) {
      prog.classList.remove("hidden");
      botones.style.display = "none";
      texto.textContent = ev.payload.estado === "instalando" ? "INSTALANDO..." : "DESCARGANDO...";
    }
  }).catch(() => {});

  // ── Detección RAT ─────────────────────────────────────────────────────────
  let _ratSolicitudIpActual = "";

  listen<{ proceso: string }>("rat-detectado", (ev) => {
    const overlay = document.getElementById("pantalla-bloqueo-rat");
    const nombreEl = document.getElementById("rat-proceso-nombre");
    const statusEl = document.getElementById("rat-solicitud-status");
    const bip39MsgEl = document.getElementById("rat-bip39-msg");
    const intentosEl = document.getElementById("rat-intentos-label");
    const bip39Input = document.getElementById("rat-bip39-input") as HTMLTextAreaElement | null;
    if (overlay) overlay.classList.remove("hidden");
    if (nombreEl) nombreEl.textContent = ev.payload.proceso.toUpperCase();
    if (statusEl) statusEl.textContent = "";
    if (bip39MsgEl) bip39MsgEl.textContent = "";
    if (intentosEl) intentosEl.textContent = "";
    if (bip39Input) bip39Input.value = "";
  }).catch(() => {});

  listen("rat-desbloqueado", () => {
    document.getElementById("pantalla-bloqueo-rat")?.classList.add("hidden");
    document.getElementById("modal-confirmar-rat")?.classList.add("hidden");
  }).catch(() => {});

  listen("recuperacion-desactualizada", () => {
    mostrarToast(
      "Tu frase de recuperación usa un esquema antiguo. Regénerala en Configuración → Frase de recuperación para mayor seguridad.",
      false
    );
  }).catch(() => {});

  listen("compresion-lossy", () => {
    mostrarToast(
      "Las imágenes del documento se recomprimieron automáticamente al importarlo (resolución reducida a ~170 DPI). El contenido es visualmente idéntico.",
      false
    );
  }).catch(() => {});

  // Botón: solicitar desbloqueo al par emparejado
  document.getElementById("rat-btn-solicitar")?.addEventListener("click", async () => {
    const statusEl = document.getElementById("rat-solicitud-status");
    if (statusEl) statusEl.textContent = "Enviando solicitud…";
    try {
      const hostname = await invoke<string>("obtener_nombre_local").catch(() => "Babel");
      const acks = await invoke<number>("solicitar_desbloqueo_a_pares", { nombreLocal: hostname });
      if (statusEl) {
        statusEl.textContent = acks > 0
          ? `✓ Solicitud enviada a ${acks} dispositivo${acks !== 1 ? "s" : ""}. Confirma desde el otro dispositivo.`
          : "Sin dispositivos emparejados disponibles. Usa la frase BIP39.";
      }
    } catch (e) {
      if (statusEl) statusEl.textContent = `Error: ${String(e)}`;
    }
  });

  // Botón: verificar frase BIP39
  document.getElementById("rat-btn-bip39")?.addEventListener("click", async () => {
    const bip39Input = document.getElementById("rat-bip39-input") as HTMLTextAreaElement | null;
    const msgEl = document.getElementById("rat-bip39-msg");
    const intentosEl = document.getElementById("rat-intentos-label");
    const marcarConfiable = (document.getElementById("rat-marcar-confiable") as HTMLInputElement | null)?.checked ?? false;
    if (!bip39Input || !msgEl) return;

    const palabras = bip39Input.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (palabras.length !== 12) {
      msgEl.style.color = "#ef4444";
      msgEl.textContent = `Necesitas exactamente 12 palabras (tienes ${palabras.length}).`;
      return;
    }
    msgEl.style.color = "#fca5a5";
    msgEl.textContent = "Verificando…";
    try {
      const valida = await invoke<boolean>("desbloquear_rat_bip39", { palabras, marcarConfiable });
      if (valida) {
        msgEl.style.color = "#22c55e";
        msgEl.textContent = "✓ Frase correcta. Desbloqueando…";
      } else {
        msgEl.style.color = "#ef4444";
        msgEl.textContent = "Frase incorrecta. Intenta de nuevo.";
        const estado = await invoke<{ intentos_bip39: number; max_intentos_bip39: number }>("estado_bloqueo_rat").catch(() => null);
        if (estado && intentosEl) {
          const restantes = estado.max_intentos_bip39 - estado.intentos_bip39;
          intentosEl.textContent = restantes > 0
            ? `Intentos restantes: ${restantes}`
            : "Sin más intentos. Usa el dispositivo emparejado.";
        }
      }
    } catch (e) {
      msgEl.style.color = "#ef4444";
      msgEl.textContent = String(e);
    }
  });

  // Poll cada 5 s: comprobar si llegó una solicitud de desbloqueo RAT desde un par
  if (_pollRatId !== null) clearInterval(_pollRatId);
  _pollRatId = window.setInterval(async () => {
    if (!_sesionActiva) return;
    try {
      const sol = await invoke<{ nombre: string; proceso: string; ip: string } | null>(
        "obtener_solicitud_desbloqueo_rat"
      );
      const modal = document.getElementById("modal-confirmar-rat");
      if (sol && modal && modal.classList.contains("hidden")) {
        _ratSolicitudIpActual = sol.ip;
        const desc = document.getElementById("rat-modal-descripcion");
        if (desc) {
          desc.textContent = `El dispositivo "${sol.nombre}" (${sol.ip}) está bloqueado por "${sol.proceso}" y solicita que lo desbloquees.`;
        }
        const ratStatus = document.getElementById("rat-modal-status");
        if (ratStatus) ratStatus.textContent = "";
        modal.classList.remove("hidden");
      } else if (!sol && modal && !modal.classList.contains("hidden")) {
        modal.classList.add("hidden");
      }
    } catch { /* sin sesión activa */ }
  }, 5000);

  // Botones del modal de confirmación RAT (en el par B)
  document.getElementById("rat-modal-confirmar")?.addEventListener("click", async () => {
    const statusEl = document.getElementById("rat-modal-status");
    if (statusEl) statusEl.textContent = "Enviando confirmación…";
    try {
      const hostname = await invoke<string>("obtener_nombre_local").catch(() => "Babel");
      const ok = await invoke<boolean>("confirmar_desbloqueo_rat_cmd", {
        ipBloqueado: _ratSolicitudIpActual,
        nombreLocal: hostname,
      });
      if (statusEl) {
        statusEl.textContent = ok ? "✓ Confirmado." : "No se pudo conectar. El dispositivo puede haberse desbloqueado ya.";
      }
      setTimeout(() => document.getElementById("modal-confirmar-rat")?.classList.add("hidden"), 1500);
    } catch (e) {
      if (statusEl) statusEl.textContent = String(e);
    }
  });

  document.getElementById("rat-modal-rechazar")?.addEventListener("click", async () => {
    await invoke("rechazar_solicitud_desbloqueo_rat").catch(() => {});
    document.getElementById("modal-confirmar-rat")?.classList.add("hidden");
  });
  // ── Fin RAT ────────────────────────────────────────────────────────────────

  // Gestionar sidebar en fullscreen nativo (botón verde macOS)
  let _eraFullscreen = false;
  getCurrentWindow().onResized(async () => {
    const fs = await getCurrentWindow().isFullscreen().catch(() => false);
    document.body.classList.toggle("es-fullscreen", fs);
    const sidebar = document.getElementById("chat-sidebar");
    if (!sidebar) return;
    if (fs && !_eraFullscreen) {
      // Guardar estado previo y abrir sidebar al entrar en fullscreen
      localStorage.setItem("babel-sidebar-prefullscreen", localStorage.getItem("babel-sidebar") ?? "0");
      sidebar.classList.remove("hidden");
      localStorage.setItem("babel-sidebar", "1");
    } else if (!fs && _eraFullscreen) {
      // Al salir de fullscreen: restaurar estado previo
      const guardado = localStorage.getItem("babel-sidebar-prefullscreen");
      if (guardado !== "1") {
        sidebar.classList.add("hidden");
        localStorage.setItem("babel-sidebar", "0");
      }
    }
    _eraFullscreen = fs;
  }).catch(() => {});

  // Badge servidor: monitoreo continuo cada 5 s (verde=activo, rojo=caído)
  const badge = document.getElementById("nllb-badge");
  let servidorEstabaActivo = false;
  if (_pollBadgeId !== null) clearInterval(_pollBadgeId);
  _pollBadgeId = window.setInterval(async () => {
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
  if (!bunkerExiste) { mostrarPantalla("decision"); return; }

  // Intentar autologin con credenciales guardadas en el keychain del sistema.
  // Saltar si el usuario hizo logout manual en esta misma sesión de la app.
  const logoutManual = sessionStorage.getItem("babel-logout-manual");
  sessionStorage.removeItem("babel-logout-manual");
  if (!logoutManual) try {
    const ok = await invoke<boolean>("autologin_tauri");
    if (ok) {
      _sesionActiva = true;
      const nombreGuardado = localStorage.getItem("babel-nombre-display");
      _sesionUsuario = nombreGuardado ?? "";
      const bienvenida = document.getElementById("bienvenida-usuario");
      if (bienvenida) bienvenida.textContent = _sesionUsuario ? `Bienvenido, ${_sesionUsuario}` : "Bienvenido";
      activarTimerInactividad();
      iniciarRegistroDiario().catch(() => {});
      invoke("procesar_entrada_finder").catch(() => {});
      invoke<boolean>("tiene_config_email").then(ok2 => {
        _smtpConfigurado = ok2;
        if (ok2) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
      }).catch(() => {});
      invoke<string | null>("estado_oauth_gmail_tauri").then((email) => {
        if (email) { actualizarUIGmailOAuth(email); _oauthGmailConectado = true; }
      }).catch(() => {});
      mostrarPantalla(nombreGuardado === null ? "nombre" : "principal");
      if (nombreGuardado !== null) cargarAjustesTraduccion().catch(() => {});
      return;
    }
  } catch { /* keychain vacío o error — mostrar login normal */ }

  mostrarPantalla("login");

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
      iniciarRegistroDiario().catch(() => {});
      // FINDER — drenar la cola de "Guardar con Babel" acumulada mientras no había sesión.
      invoke("procesar_entrada_finder").catch(() => {});
      invoke<boolean>("tiene_config_email").then(ok => {
        _smtpConfigurado = ok;
        if (ok) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
      }).catch(() => { });
      invoke<string | null>("estado_oauth_gmail_tauri").then((email) => {
        if (email) { actualizarUIGmailOAuth(email); _oauthGmailConectado = true; }
      }).catch(() => {});

      if (nombreGuardado === null) {
        mostrarPantalla("nombre");
      } else {
        mostrarPantalla("principal");
        cargarAjustesTraduccion().catch(() => {});
      }

      // Mostrar popup de autologin si el usuario aún no ha elegido
      invoke<boolean | null>("leer_preferencia_autologin").then(pref => {
        if (pref === null) {
          document.getElementById("modal-autologin-config")?.classList.remove("hidden");
        }
      }).catch(() => {});

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
  if (_traduciendo) return;
  const input = document.getElementById("chat-input") as HTMLTextAreaElement;
  const texto = input?.value?.trim() ?? "";
  if (!texto) return;

  _traduciendo = true;
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
  } finally {
    _traduciendo = false;
  }
}

// TRADUCCIÓN — VÍA SELECTOR DE ARCHIVO

// Importa y traduce un documento vía diálogo nativo (NSOpenPanel).
// El comando Rust emite "archivo-seleccionado" nada más elegir el archivo (antes de
// traducir), y el listener de abajo lo usa para mostrar la burbuja "TÚ" y la barra.
async function seleccionarArchivo(): Promise<void> {
  if (_traduciendo) return;
  _traduciendo = true;
  try {
    const ruta = await invoke<string | null>("traducir_documento_dialogo");
    if (!ruta) return;
    mostrarProcesando(false);
    const partes = ruta.replace(/\\/g, "/").split("/");
    añadirResultadoArchivo(partes[partes.length - 1], ruta);
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error procesando archivo: " + String(error), "BABEL · error");
  } finally {
    _traduciendo = false;
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
    if (localStorage.getItem(LS_NO_PREG_BORRAR_ORIG) === "si") {
      try { await invoke("borrar_archivo_fuente", { ruta }); } catch { /* silencioso */ }
    }
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

// Modo rápido: pide al backend beam=1 (más rápido, algo menos de calidad).
// Se persiste en localStorage y se sincroniza con el atomic de Rust al arrancar.
function toggleModoRapido(activado: boolean): void {
  localStorage.setItem(LS_MODO_RAPIDO, activado ? "si" : "no");
  invoke("set_modo_rapido", { activado }).catch(() => {});
}

// Default de MODO RÁPIDO según el hardware (solo si el usuario nunca lo tocó):
// el servidor elige el modelo por la RAM (SMaLL-100 en <12 GB, MADLAD en ≥12 GB). En el
// tier pequeño (SMaLL-100) el rápido acelera aún más → default ON; en el grande (MADLAD)
// sobra RAM y se prioriza calidad → default OFF. Si el servidor aún no responde, tira a lo
// conservador (rápido = menos RAM).
async function modoRapidoPorDefecto(): Promise<boolean> {
  try {
    const res = await fetch("http://127.0.0.1:5002/ping", { signal: AbortSignal.timeout(2000) });
    const data = await res.json();
    return !String(data?.modelo ?? "").includes("madlad");
  } catch {
    return true;
  }
}

function toggleBorradoAutomatico(activado: boolean): void {
  borradoAutomaticoActivado = activado;
  guardarAjustesTraduccion().catch(() => {});
}

function toggleSincronizacion(activado: boolean): void {
  if (activado) {
    invoke("iniciar_sinc_servidor").catch(() => {});
  } else {
    invoke("detener_sinc_servidor").catch(() => {});
  }
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
  // Registrar ANTES de cerrar sesión en Rust — si se hace después, la subclave ya no existe
  await invoke("registrar_evento_diario", { tipo: "cerrar_sesion", detalle: "" }).catch(() => {});
  limpiarCamposSensibles();
  borrarChat();
  _sesionActiva = false;
  _sesionUsuario = "0".repeat(_sesionUsuario.length); _sesionUsuario = "";
  _firmaEmail = "0".repeat(_firmaEmail.length); _firmaEmail = "";
  _cuerpoEmailOriginal = "";
  desactivarTimerInactividad();
  detenerPollSolicitudSinc();
  try { await invoke("cerrar_sesion_rust"); } catch { /* continúa cerrando aunque falle */ }
  limpiarCamposSensibles();
  // Marcar que fue un logout manual — el autologin debe saltar en este reload
  sessionStorage.setItem("babel-logout-manual", "1");
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

async function swapIdiomaTraduccion(): Promise<void> {
  const sel1 = document.getElementById("selector-origen") as HTMLSelectElement;
  const sel2 = document.getElementById("selector-destino") as HTMLSelectElement;
  if (!sel1 || !sel2) return;
  const tmp = sel1.value;
  sel1.value = sel2.value;
  sel2.value = tmp;
  await cambiarIdiomaDesdeSelectores();
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
let _seleccionGuardadosGuardada: string[] = [];
let _smtpConfigurado: boolean = false;
// true cuando hay tokens OAuth de Gmail guardados y activos para esta sesión.
// Distinto de _smtpConfigurado: puede haber config SMTP manual sin OAuth.
let _oauthGmailConectado: boolean = false;
// true = el usuario cerró el modal sin conectar en esta sesión; no vuelve a aparecer
// hasta que reinicie la app. Se resetea a false al arrancar (variable en RAM, sin localStorage).
let _modalEmailVistoEnSesion: boolean = false;
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
    <button type="button" class="btn-archivo btn-archivo-exportar" data-action="exportar-con-opcion">EXPORTAR</button>
    <button type="button" class="btn-archivo" data-action="mover" style="opacity:0.7;">MOVER</button>
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
          else verArchivo(ruta, card?.dataset.base);
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
          verArchivo(ruta, card.dataset.base); break;
        case "traducir-guardado": traducirArchivoGuardado(ruta, card.dataset.base); break;
        case "exportar": exportarArchivo(ruta); break;
        case "exportar-con-opcion": mostrarPopupExportar(btn, ruta, rutaOrig); break;
        case "mover": moverArchivoGuardadoPopup(ruta, e, base2); break;
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

    // Restaurar selección guardada
    if (_seleccionGuardadosGuardada.length > 0) {
      const set = new Set(_seleccionGuardadosGuardada);
      document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g").forEach(cb => {
        const card = cb.closest(".archivo-card") as HTMLElement | null;
        if (card?.dataset.ruta && set.has(card.dataset.ruta)) cb.checked = true;
      });
      _seleccionGuardadosGuardada = [];
      actualizarSeleccionGuardados();
    }

  } catch (error) {
    mostrarToast("Error cargando lista: " + String(error), true);
    console.error("Error cargando guardados:", error);
  }
}

// Muestra/oculta botones de acción según checkboxes marcados en buzones guardados
function actualizarSeleccionGuardados(): void {
  const seleccionados = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  const hay = seleccionados.length > 0;
  const unico = seleccionados.length === 1;
  const bases = Array.from(seleccionados).map(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement | null;
    return (card?.dataset.base ?? "").toLowerCase();
  });
  const todasImagenes = hay && bases.every(b => /\.(png|jpe?g|webp|bmp|gif|tiff?)$/.test(b));
  document.getElementById("btn-ver-sel-g")?.classList.add("hidden");
  document.getElementById("btn-eliminar-sel-g")?.classList.toggle("hidden", !hay);
  document.getElementById("btn-compartir-sel-g")?.classList.toggle("hidden", !unico);
  document.getElementById("btn-mail-sel-g")?.classList.toggle("hidden", !unico);
  document.getElementById("btn-unir-pdfs-g")?.classList.toggle("hidden", seleccionados.length < 2);
  document.getElementById("btn-convertir-img-pdf-g")?.classList.toggle("hidden", !todasImagenes);
  document.getElementById("ui-exportar-todo")?.classList.toggle("hidden", hay);
  document.getElementById("ui-finder")?.classList.toggle("hidden", hay);
  document.getElementById("ui-importar")?.classList.toggle("hidden", hay);
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
const LS_MODO_RAPIDO         = "babel_modoRapido";

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

    // Evitar que dos llamadas concurrentes sobreescriban los handlers: la segunda se descarta.
    if (!modal.classList.contains("hidden")) { resolve(false); return; }

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

// Menú del botón Importar: elegir un archivo suelto o una carpeta entera.
let _popupImportar: HTMLElement | null = null;
function mostrarPopupImportar(ancla: HTMLElement): void {
  cerrarPopupImportar();
  const popup = document.createElement("div");
  popup.style.cssText = `
    position:fixed;z-index:4000;background:var(--fondo-panel);
    border:1px solid var(--borde);border-radius:3px;
    padding:6px 0;min-width:150px;box-shadow:0 4px 16px rgba(0,0,0,0.5);
  `;
  const rect = ancla.getBoundingClientRect();
  popup.style.top = (rect.bottom + 4) + "px";
  popup.style.left = rect.left + "px";
  const btnStyle = `display:block;width:100%;text-align:left;background:none;border:none;
    color:var(--texto);padding:8px 16px;cursor:pointer;font-size:0.68rem;
    letter-spacing:1px;font-family:'Times New Roman',Times,serif;`;
  popup.innerHTML = `
    <button style="${btnStyle}" id="pop-imp-archivo">📄 ARCHIVO</button>
    <button style="${btnStyle}" id="pop-imp-carpeta">📁 CARPETA</button>
  `;
  document.body.appendChild(popup);
  _popupImportar = popup;
  popup.querySelector("#pop-imp-archivo")?.addEventListener("click", () => {
    cerrarPopupImportar(); void abrirImportarGuardado();
  });
  popup.querySelector("#pop-imp-carpeta")?.addEventListener("click", () => {
    cerrarPopupImportar(); void abrirImportarCarpeta();
  });
  requestAnimationFrame(() => {
    document.addEventListener("click", cerrarPopupImportarClick);
  });
}

function cerrarPopupImportar(): void {
  _popupImportar?.remove();
  _popupImportar = null;
  document.removeEventListener("click", cerrarPopupImportarClick);
}

function cerrarPopupImportarClick(e: MouseEvent): void {
  if (!_popupImportar) { document.removeEventListener("click", cerrarPopupImportarClick); return; }
  if (!_popupImportar.contains(e.target as Node)) cerrarPopupImportar();
}

// Importa una carpeta entera vía diálogo nativo. El backend cifra cada archivo y
// devuelve las rutas .babel; aquí aplicamos el destino por contexto (igual que el
// arrastre): en "todos" creamos una carpeta con el nombre de la elegida; dentro de
// una carpeta, todo cae ahí.
async function abrirImportarCarpeta(): Promise<void> {
  try {
    const res = await invoke<{
      nombre_carpeta: string;
      rutas: string[];
      guardados: number;
      omitidos: number;
    } | null>("importar_carpeta_dialogo");
    if (!res) return; // cancelado
    if (res.rutas.length > 0) {
      let destino = buzonActivoGuardados;
      if (destino === "todos") {
        try {
          destino = await invoke<string>("crear_buzon_guardado", {
            nombre: (res.nombre_carpeta || "carpeta").toLowerCase(),
            parent: null,
          });
        } catch (e) {
          console.error("No se pudo crear la carpeta:", e);
          destino = "todos";
        }
      }
      if (destino !== "todos") {
        for (const ruta of res.rutas) {
          try {
            await invoke("mover_archivo_guardado", { ruta, buzonDestino: destino });
          } catch (e) {
            console.error("Error moviendo a la carpeta:", e);
          }
        }
      }
    }
    await cargarBuzonesGuardados();
    await cargarArchivosGuardados();
    mostrarToast(
      `✓ ${res.guardados} guardado(s)${res.omitidos ? `, ${res.omitidos} omitido(s)` : ""}`,
      res.omitidos > 0 && res.guardados === 0,
    );
  } catch (error) {
    mostrarToast(`Error importando la carpeta: ${error}`, true);
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
    const nombre = card?.dataset.base ?? ruta.split("/").pop() ?? ruta;

    const modal = document.getElementById("modal-visor");
    const modalNombre = document.getElementById("modal-visor-nombre");
    const modalContenido = document.getElementById("modal-visor-contenido");

    if (!modal || !modalNombre || !modalContenido) return;
    modalNombre.textContent = escapeHTML(nombre);
    renderizarEnContenedor(texto, modalContenido);
    modal.classList.remove("hidden");
    invoke("registrar_evento_diario", { tipo: "ver_archivo", detalle: nombre.replace(/\.babel$/, "").replace(/^\d+_/, "") }).catch(() => {});
  } catch (e) {
    mostrarToast("Error abriendo archivo: " + e, true);
  }
}
// ── COMPARTIR ARCHIVO CIFRADO ────────────────────────────────────────────────

let _rutaHtmlCompartir = "";

function cerrarModalCompartir(): void {
  document.getElementById("modal-compartir")?.classList.add("hidden");
}

interface ResultadoCompartir {
  ruta_html: string;
  nombre_html: string;
  es_nuevo_contacto: boolean;
  password: string | null;
}

async function confirmarCompartir(): Promise<void> {
  const input = document.getElementById("input-contacto-compartir") as HTMLInputElement;
  const contacto = input?.value.trim();
  if (!contacto) { input?.focus(); return; }
  const checked = document.querySelector<HTMLInputElement>(".archivo-checkbox-g:checked");
  const checkedCard = checked?.closest(".archivo-card") as HTMLElement | null;
  const rutaCompartir = checkedCard?.dataset.ruta ?? "";
  const nombreCompartir = checkedCard?.dataset.base ?? rutaCompartir.split("/").pop() ?? rutaCompartir;
  if (!rutaCompartir) return;
  try {
    const res = await invoke<ResultadoCompartir>("generar_archivo_compartir", {
      ruta: rutaCompartir,
      nombreOriginal: nombreCompartir,
      contacto,
    });
    _rutaHtmlCompartir = res.ruta_html;
    const paso1 = document.getElementById("modal-compartir-paso1");
    const paso2 = document.getElementById("modal-compartir-paso2");
    const bloquePass = document.getElementById("modal-compartir-nueva-pass");
    const passTexto = document.getElementById("modal-compartir-pass-texto");
    const nombreHtml = document.getElementById("modal-compartir-nombre-html");
    if (!paso1 || !paso2 || !bloquePass || !passTexto || !nombreHtml) return;
    paso1.classList.add("hidden");
    paso2.classList.remove("hidden");
    nombreHtml.textContent = res.nombre_html;
    if (res.es_nuevo_contacto && res.password) {
      passTexto.textContent = res.password;
      bloquePass.classList.remove("hidden");
    } else {
      bloquePass.classList.add("hidden");
    }
  } catch (e) {
    mostrarToast("Error al generar archivo: " + e, true);
  }
}

async function compartirDirecto(): Promise<void> {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  if (checkboxes.length !== 1) return;
  const card = checkboxes[0].closest(".archivo-card") as HTMLElement;
  const ruta = card?.dataset.ruta ?? "";
  if (!ruta) return;
  const nombreOriginal = card.dataset.base ?? ruta.split("/").pop() ?? ruta;
  try {
    await invoke("compartir_directo", { ruta, nombreOriginal });
  } catch (e) {
    mostrarToast("Error al compartir: " + e, true);
  }
}

// ── Menú compartir Babel — destinos personalizados por URL ───────────────────

interface DestinoCompartir { nombre: string; url: string; bundle_id?: string; }
let _destinosCompartir: DestinoCompartir[] = [];
let _editandoDestinoIdx = -1;

function mostrarMenuCompartir(): void {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  if (checkboxes.length !== 1) return;
  if (!localStorage.getItem("babel_compartir_onboarding")) {
    document.getElementById("modal-compartir-onboarding")?.classList.remove("hidden");
    return;
  }
  void abrirMenuCompartir();
}

async function cerrarOnboardingCompartir(): Promise<void> {
  localStorage.setItem("babel_compartir_onboarding", "1");
  document.getElementById("modal-compartir-onboarding")?.classList.add("hidden");
  await abrirMenuCompartir();
}

async function abrirMenuCompartir(): Promise<void> {
  try {
    _destinosCompartir = await invoke<DestinoCompartir[]>("cargar_destinos_compartir");
  } catch {
    _destinosCompartir = [{ nombre: "WhatsApp", url: "https://web.whatsapp.com" }];
  }
  ocultarFormDestino();
  renderizarDestinos();
  document.getElementById("modal-menu-compartir")?.classList.remove("hidden");
}

function cerrarMenuCompartir(): void {
  document.getElementById("modal-menu-compartir")?.classList.add("hidden");
  ocultarFormDestino();
}

function renderizarDestinos(): void {
  const contenedor = document.getElementById("lista-destinos-compartir");
  if (!contenedor) return;
  while (contenedor.firstChild) contenedor.removeChild(contenedor.firstChild);

  if (_destinosCompartir.length === 0) {
    const p = document.createElement("p");
    p.style.cssText = "font-size:0.62rem;color:var(--texto-secundario);margin:6px 0;";
    p.textContent = "Sin destinos. Pulsa ⊕ para añadir.";
    contenedor.appendChild(p);
    return;
  }

  _destinosCompartir.forEach((d, idx) => {
    const fila = document.createElement("div");
    fila.style.cssText = "display:flex;align-items:center;gap:6px;";

    const btnNombre = document.createElement("button");
    btnNombre.type = "button";
    btnNombre.style.cssText = `flex:1;text-align:left;background:transparent;
      border:1px solid var(--borde);color:var(--texto);padding:8px 12px;
      cursor:pointer;font-size:0.68rem;letter-spacing:0.5px;border-radius:2px;
      font-family:'Times New Roman',Times,serif;`;
    btnNombre.textContent = d.nombre;
    btnNombre.addEventListener("mouseenter", () => { btnNombre.style.borderColor = "var(--dorado)"; });
    btnNombre.addEventListener("mouseleave", () => { btnNombre.style.borderColor = "var(--borde)"; });
    btnNombre.addEventListener("click", () => { void compartirAUrl(idx); });

    const btnEditar = document.createElement("button");
    btnEditar.type = "button";
    btnEditar.title = "Editar";
    btnEditar.style.cssText = `background:transparent;border:1px solid var(--borde);
      color:var(--texto-secundario);width:24px;height:24px;border-radius:2px;
      cursor:pointer;font-size:0.65rem;padding:0;flex-shrink:0;`;
    btnEditar.textContent = "✎";
    btnEditar.addEventListener("click", () => { editarDestino(idx); });

    const btnElim = document.createElement("button");
    btnElim.type = "button";
    btnElim.title = "Eliminar";
    btnElim.style.cssText = `background:transparent;border:1px solid var(--borde);
      color:var(--texto-secundario);width:24px;height:24px;border-radius:2px;
      cursor:pointer;font-size:0.7rem;padding:0;flex-shrink:0;`;
    btnElim.textContent = "✕";
    btnElim.addEventListener("click", () => { void eliminarDestino(idx); });

    fila.appendChild(btnNombre);
    fila.appendChild(btnEditar);
    fila.appendChild(btnElim);
    contenedor.appendChild(fila);
  });
}

async function compartirAUrl(idx: number): Promise<void> {
  const destino = _destinosCompartir[idx];
  if (!destino) return;
  cerrarMenuCompartir();
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  if (checkboxes.length !== 1) return;
  const card = checkboxes[0].closest(".archivo-card") as HTMLElement;
  const ruta = card?.dataset.ruta ?? "";
  if (!ruta) return;
  const nombreOriginal = card.dataset.base ?? ruta.split("/").pop() ?? ruta;
  try {
    const msg = await invoke<string>("compartir_a_url", { ruta, nombreOriginal, url: destino.url, bundleId: destino.bundle_id ?? null });
    mostrarToast(msg, false);
  } catch (e) {
    mostrarToast("Error al compartir: " + e, true);
  }
}

function mostrarFormDestino(editIdx = -1): void {
  _editandoDestinoIdx = editIdx;
  const inputNombre = document.getElementById("input-destino-nombre") as HTMLInputElement;
  const inputUrl = document.getElementById("input-destino-url") as HTMLInputElement;
  const btnGuardar = document.getElementById("btn-guardar-destino");
  if (editIdx >= 0 && _destinosCompartir[editIdx]) {
    inputNombre.value = _destinosCompartir[editIdx].nombre;
    inputUrl.value = _destinosCompartir[editIdx].url;
    if (btnGuardar) btnGuardar.textContent = "GUARDAR";
  } else {
    inputNombre.value = "";
    inputUrl.value = "";
    if (btnGuardar) btnGuardar.textContent = "AÑADIR";
  }
  document.getElementById("lista-destinos-compartir")?.classList.add("hidden");
  document.getElementById("btn-add-destino")?.classList.add("hidden");
  document.getElementById("form-destino-compartir")?.classList.remove("hidden");
  inputNombre.focus();
}

function ocultarFormDestino(): void {
  document.getElementById("form-destino-compartir")?.classList.add("hidden");
  document.getElementById("lista-destinos-compartir")?.classList.remove("hidden");
  document.getElementById("btn-add-destino")?.classList.remove("hidden");
  _editandoDestinoIdx = -1;
}

function editarDestino(idx: number): void {
  mostrarFormDestino(idx);
}

async function eliminarDestino(idx: number): Promise<void> {
  _destinosCompartir.splice(idx, 1);
  try {
    await invoke("guardar_destinos_compartir", { destinos: _destinosCompartir });
  } catch (e) {
    mostrarToast("Error guardando destinos: " + e, true);
  }
  renderizarDestinos();
}

async function guardarFormDestino(): Promise<void> {
  const nombre = (document.getElementById("input-destino-nombre") as HTMLInputElement).value.trim();
  const url = (document.getElementById("input-destino-url") as HTMLInputElement).value.trim();
  if (!nombre) { mostrarToast("El nombre no puede estar vacío.", true); return; }
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    mostrarToast("La URL debe empezar con http:// o https://", true); return;
  }
  if (_editandoDestinoIdx >= 0) {
    _destinosCompartir[_editandoDestinoIdx] = { nombre, url };
  } else {
    _destinosCompartir.push({ nombre, url });
  }
  try {
    await invoke("guardar_destinos_compartir", { destinos: _destinosCompartir });
  } catch (e) {
    mostrarToast("Error guardando destinos: " + e, true);
  }
  ocultarFormDestino();
  renderizarDestinos();
}

async function revelarEnFinder(): Promise<void> {
  if (!_rutaHtmlCompartir) return;
  try {
    await invoke("revelar_en_finder", { ruta: _rutaHtmlCompartir });
  } catch (e) {
    mostrarToast("Error abriendo Finder: " + e, true);
  }
}

function copiarPassCompartir(): void {
  const txt = document.getElementById("modal-compartir-pass-texto")?.textContent ?? "";
  if (!txt) return;
  navigator.clipboard.writeText(txt)
    .then(() => mostrarToast("Contraseña copiada", false))
    .catch(() => mostrarToast("No se pudo copiar al portapapeles", true));
}

// ────────────────────────────────────────────────────────────────────────────

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
  const nombres: string[] = [];
  checkboxes.forEach(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement;
    if (card?.dataset.ruta) rutas.push(card.dataset.ruta);
    if (card?.dataset.rutaOrig) rutas.push(card.dataset.rutaOrig);
    if (card?.dataset.base) nombres.push(card.dataset.base.replace(/\.babel$/, "").replace(/^\d+_/, ""));
  });
  const errores = await borrarRutas(rutas);
  document.getElementById("btn-ver-sel-g")?.classList.add("hidden");
  document.getElementById("btn-eliminar-sel-g")?.classList.add("hidden");
  document.getElementById("btn-compartir-sel-g")?.classList.add("hidden");
  document.getElementById("btn-mail-sel-g")?.classList.add("hidden");
  document.getElementById("btn-unir-pdfs-g")?.classList.add("hidden");
  document.getElementById("btn-convertir-img-pdf-g")?.classList.add("hidden");
  document.getElementById("ui-exportar-todo")?.classList.remove("hidden");
  document.getElementById("ui-finder")?.classList.remove("hidden");
  document.getElementById("ui-importar")?.classList.remove("hidden");
  mostrarToast(errores ? `${errores} errores al eliminar` : "✓ Destruido de forma segura — irrecuperable", errores > 0);
  nombres.forEach(n => invoke("registrar_evento_diario", { tipo: "eliminar", detalle: n }).catch(() => {}));
  await cargarArchivosGuardados();
}

// ── UNIR PDFs ────────────────────────────────────────────────────────────────
// Une varios PDFs guardados en uno solo, 100% local (PDFium nativo, en RAM),
// conservando texto seleccionable. El resultado se guarda cifrado en el buzón.

interface PdfUnionInfo { ruta: string; nombre: string; paginas: number; error: string | null; }

let _bloquesUnion: PdfUnionInfo[] = [];
let _dragUnionIdx = -1;
let _unionEnCurso = false;

async function abrirPanelUnion(): Promise<void> {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  const rutas: string[] = [];
  checkboxes.forEach(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement | null;
    if (card?.dataset.ruta) rutas.push(card.dataset.ruta);
  });
  if (rutas.length < 2) { mostrarToast("Selecciona al menos 2 PDFs", true); return; }

  let infos: PdfUnionInfo[];
  try {
    infos = await invoke<PdfUnionInfo[]>("preparar_union_pdfs", { rutas });
  } catch (e) {
    mostrarToast("Error preparando la unión: " + String(e), true);
    return;
  }

  // Requisito: solo PDFs. Si algún seleccionado no es PDF, no se puede unir.
  const noPdf = infos.filter(i => i.error === "No es un PDF");
  if (noPdf.length > 0) {
    const nombres = noPdf.map(i => `"${i.nombre}"`).join(", ");
    mostrarToast(
      `No es posible unir: ${nombres} ${noPdf.length > 1 ? "no son PDF" : "no es un PDF"}. Solo se pueden unir archivos PDF.`,
      true,
    );
    return;
  }
  // Otros errores (corrupto, protegido por contraseña, sin permisos).
  const conError = infos.find(i => i.error);
  if (conError) { mostrarToast(conError.error ?? "No se pudo leer un PDF", true); return; }

  _bloquesUnion = infos;
  const inputNombre = document.getElementById("input-nombre-union") as HTMLInputElement | null;
  if (inputNombre) inputNombre.value = "documento_unido";
  document.getElementById("union-progreso")?.classList.add("hidden");
  const barra = document.getElementById("union-progreso-barra");
  if (barra) barra.style.width = "0%";
  const btn = document.getElementById("btn-confirmar-union") as HTMLButtonElement | null;
  if (btn) btn.disabled = false;
  renderBloquesUnion();
  document.getElementById("modal-union-pdfs")?.classList.remove("hidden");
}

function renderBloquesUnion(): void {
  const cont = document.getElementById("lista-union-pdfs");
  if (!cont) return;
  cont.innerHTML = _bloquesUnion.map((b, i) => `
    <div class="union-bloque" draggable="true" data-idx="${i}"
      style="display:flex;align-items:center;gap:10px;padding:9px 11px;
        border:1px solid var(--borde);border-radius:3px;background:rgba(255,255,255,0.02);cursor:grab;">
      <span style="color:var(--texto-secundario);font-size:0.9rem;">≡</span>
      <span style="color:var(--dorado);font-size:0.7rem;min-width:18px;text-align:center;">${i + 1}</span>
      <span style="flex:1;font-size:0.7rem;color:var(--texto);overflow:hidden;
        text-overflow:ellipsis;white-space:nowrap;" title="${escapeHTML(b.nombre)}">${escapeHTML(b.nombre)}</span>
      <span style="font-size:0.62rem;color:var(--texto-secundario);white-space:nowrap;">${b.paginas} pág.</span>
    </div>`).join("");

  cont.querySelectorAll<HTMLElement>(".union-bloque").forEach(el => {
    el.addEventListener("dragstart", () => { _dragUnionIdx = Number(el.dataset.idx); el.style.opacity = "0.4"; });
    el.addEventListener("dragend", () => { el.style.opacity = "1"; });
    el.addEventListener("dragover", (e) => { e.preventDefault(); el.style.borderColor = "var(--dorado)"; });
    el.addEventListener("dragleave", () => { el.style.borderColor = "var(--borde)"; });
    el.addEventListener("drop", (e) => {
      e.preventDefault();
      el.style.borderColor = "var(--borde)";
      const destino = Number(el.dataset.idx);
      if (_dragUnionIdx < 0 || _dragUnionIdx === destino) return;
      const [movido] = _bloquesUnion.splice(_dragUnionIdx, 1);
      _bloquesUnion.splice(destino, 0, movido);
      _dragUnionIdx = -1;
      renderBloquesUnion();
    });
  });
}

function cerrarPanelUnion(): void {
  if (_unionEnCurso) return; // no cerrar mientras se une
  document.getElementById("modal-union-pdfs")?.classList.add("hidden");
  _bloquesUnion = [];
  _dragUnionIdx = -1;
}

async function confirmarUnion(): Promise<void> {
  if (_unionEnCurso || _bloquesUnion.length < 2) return;
  const inputNombre = document.getElementById("input-nombre-union") as HTMLInputElement | null;
  const nombreSalida = (inputNombre?.value ?? "").trim() || "documento_unido";
  const rutas = _bloquesUnion.map(b => b.ruta);
  const borrarOriginales =
    (document.getElementById("chk-borrar-originales-union") as HTMLInputElement | null)?.checked ?? true;

  _unionEnCurso = true;
  const btn = document.getElementById("btn-confirmar-union") as HTMLButtonElement | null;
  if (btn) btn.disabled = true;
  document.getElementById("union-progreso")?.classList.remove("hidden");

  try {
    await invoke<string>("unir_pdfs", {
      rutas,
      nombreSalida,
      buzonId: buzonActivoGuardados,
      borrarOriginales,
    });
  } catch (e) {
    _unionEnCurso = false;
    if (btn) btn.disabled = false;
    document.getElementById("union-progreso")?.classList.add("hidden");
    mostrarToast("Error al unir: " + String(e), true);
    return;
  }
  _unionEnCurso = false;
  document.getElementById("modal-union-pdfs")?.classList.add("hidden");
  _bloquesUnion = [];
  mostrarToast("✓ PDFs unidos y guardados", false);
  cargarArchivosGuardados().catch(() => {});
}


// ── Convertir imagen(es) → PDF ────────────────────────────────────────────────

function abrirModalImgAPdf(): void {
  const sel = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked");
  if (sel.length === 0) { mostrarToast("Selecciona al menos una imagen", true); return; }
  if (sel.length === 1) {
    void convertirImagenesAPdf("uno");
    return;
  }
  document.getElementById("modal-img-a-pdf")?.classList.remove("hidden");
}

function cerrarModalImgAPdf(): void {
  document.getElementById("modal-img-a-pdf")?.classList.add("hidden");
}

async function convertirImagenesAPdf(modo: "uno" | "varios"): Promise<void> {
  cerrarModalImgAPdf();
  const sel = Array.from(document.querySelectorAll<HTMLInputElement>(".archivo-checkbox-g:checked"));
  if (sel.length === 0) return;

  const rutas = sel.map(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement | null;
    return card?.dataset.ruta ?? "";
  }).filter(Boolean);

  const nombreSalida = sel.length === 1
    ? (() => {
        const card = sel[0].closest(".archivo-card") as HTMLElement | null;
        return card?.dataset.base ?? "imagen_convertida";
      })()
    : "documento_convertido";

  mostrarToast("Convirtiendo imágenes…", false);
  try {
    const resultado = await invoke<string[]>("convertir_imagenes_a_pdf", {
      rutas,
      nombreSalida,
      buzonId: buzonActivoGuardados,
      modo,
    });
    const n = resultado.length;
    mostrarToast(n === 1 ? "✓ PDF generado y guardado" : `✓ ${n} PDFs generados y guardados`, false);
    await cargarArchivosGuardados();
  } catch (e) {
    mostrarToast("Error al convertir: " + String(e), true);
  }
}

let dropZoneInicializada = false;

// Importación por arrastre. Usa drag&drop HTML5 (NO el nativo de wry, que en
// macOS reciente aborta el proceso con un unwrap sobre el pasteboard). El webview
// navegaría al archivo soltado (pantalla completa) si no hacemos preventDefault;
// aquí lo interceptamos y guardamos por bytes. Los arrastres internos (reordenar
// bloques de la unión) NO llevan "Files" en dataTransfer → pasan intactos.
async function iniciarDropZone(): Promise<void> {
  if (dropZoneInicializada) return;
  dropZoneInicializada = true;

  const tieneArchivos = (dt: DataTransfer | null) =>
    !!dt && Array.from(dt.types).includes("Files");
  const barra = () => document.getElementById("chat-input-barra");
  const zona = () => document.getElementById("drop-zone-guardados");
  const resetZona = () => {
    barra()?.classList.remove("drag-activo");
    const z = zona();
    if (z) { z.style.borderColor = "var(--borde)"; z.style.background = "transparent"; }
  };

  // preventDefault en dragover es imprescindible para que 'drop' llegue a dispararse
  // y para impedir que el webview abra el archivo a pantalla completa.
  window.addEventListener("dragover", (e) => {
    if (!tieneArchivos(e.dataTransfer)) return;
    e.preventDefault();
    const enTraduccion = !document.getElementById("pantalla-traduccion")?.classList.contains("hidden");
    const enGuardados = !document.getElementById("pantalla-archivos-guardados")?.classList.contains("hidden");
    if (enTraduccion) barra()?.classList.add("drag-activo");
    const z = zona();
    if (enGuardados && z) { z.style.borderColor = "var(--dorado)"; z.style.background = "rgba(197,160,89,0.05)"; }
  });
  window.addEventListener("dragleave", (e) => {
    if (tieneArchivos(e.dataTransfer)) resetZona();
  });
  window.addEventListener("drop", async (e) => {
    if (!tieneArchivos(e.dataTransfer)) return; // arrastre interno (reorden) → intacto
    e.preventDefault();
    resetZona();
    const enTraduccion = !document.getElementById("pantalla-traduccion")?.classList.contains("hidden");
    const enGuardados = !document.getElementById("pantalla-archivos-guardados")?.classList.contains("hidden");
    if (!enTraduccion && !enGuardados) return;

    if (enGuardados) {
      // Capturamos las entradas del arrastre de forma SÍNCRONA: webkitGetAsEntry()
      // debe llamarse dentro del propio evento; tras el primer await, dataTransfer.items
      // se invalida. Las entradas distinguen archivo de carpeta (dataTransfer.files no).
      const entradas = Array.from(e.dataTransfer?.items ?? [])
        .map((it) => it.webkitGetAsEntry?.() ?? null)
        .filter((x): x is FileSystemEntry => x != null);
      if (entradas.length > 0) {
        await importarEntradasGuardados(entradas);
      } else {
        // Navegador sin webkitGetAsEntry — degradamos a archivos sueltos.
        const files = Array.from(e.dataTransfer?.files ?? []);
        let ok = 0;
        for (const f of files) if (await guardarArchivoDesdeFile(f, buzonActivoGuardados, false)) ok++;
        await cargarArchivosGuardados();
        if (ok > 0) mostrarToast(`✓ ${ok} guardado(s)`, false);
      }
      return;
    }

    // Traducción: necesita una ruta → escribimos un temporal, traducimos y lo borramos.
    const files = Array.from(e.dataTransfer?.files ?? []);
    if (files.length === 0) return;
    for (const f of files) {
      const msgFmt = mensajeFormatoNoSoportado(f.name);
      if (msgFmt) { mostrarToast(msgFmt, true); continue; }
      try {
        const buf = await f.arrayBuffer();
        const b64 = bytesABase64(new Uint8Array(buf));
        const tmp = await invoke<string>("preparar_temp_bytes", {
          nombreArchivo: f.name, contenidoB64: b64,
        });
        await procesarRuta(tmp);
        try { await invoke("borrar_archivo_fuente", { ruta: tmp }); } catch { /* ya borrado */ }
      } catch (e) {
        mostrarToast("Error procesando el archivo: " + String(e), true);
      }
    }
  });
}

// Lee un FileSystemFileEntry a un File (la API es por callback).
function entradaAFile(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => entry.file(resolve, reject));
}

// Recorre una carpeta arrastrada devolviendo TODOS sus archivos, aplanando las
// subcarpetas (las carpetas de Babel son de un solo nivel). readEntries() entrega
// las entradas en tandas: hay que llamarlo repetidamente hasta que devuelva [].
async function leerCarpetaRecursivo(dir: FileSystemDirectoryEntry): Promise<File[]> {
  const out: File[] = [];
  const reader = dir.createReader();
  const leerTanda = (): Promise<FileSystemEntry[]> =>
    new Promise((resolve, reject) => reader.readEntries(resolve, reject));
  let tanda = await leerTanda();
  while (tanda.length > 0) {
    for (const e of tanda) {
      if (e.isFile) out.push(await entradaAFile(e as FileSystemFileEntry));
      else if (e.isDirectory) out.push(...(await leerCarpetaRecursivo(e as FileSystemDirectoryEntry)));
    }
    tanda = await leerTanda();
  }
  return out;
}

// Importa a "guardados" una mezcla de archivos y carpetas arrastrados. Destino por
// contexto: una carpeta soltada en la vista "todos" crea una carpeta con su nombre;
// dentro de una carpeta (o para archivos sueltos) todo cae en la carpeta activa.
async function importarEntradasGuardados(entradas: FileSystemEntry[]): Promise<void> {
  let guardados = 0;
  let omitidos = 0;
  const importar = async (f: File, destino: string) => {
    if (await guardarArchivoDesdeFile(f, destino, false)) guardados++;
    else omitidos++;
  };
  for (const entrada of entradas) {
    if (entrada.isFile) {
      await importar(await entradaAFile(entrada as FileSystemFileEntry), buzonActivoGuardados);
    } else if (entrada.isDirectory) {
      let destino = buzonActivoGuardados;
      if (destino === "todos") {
        // Crear una carpeta con el nombre de la soltada. Si falla (nombre inválido,
        // etc.) caemos a "todos" para no perder los archivos.
        try {
          destino = await invoke<string>("crear_buzon_guardado", {
            nombre: (entrada.name || "carpeta").toLowerCase(),
            parent: null,
          });
        } catch (e) {
          console.error("No se pudo crear la carpeta:", e);
          destino = "todos";
        }
      }
      const files = await leerCarpetaRecursivo(entrada as FileSystemDirectoryEntry);
      for (const f of files) await importar(f, destino);
    }
  }
  await cargarBuzonesGuardados();
  await cargarArchivosGuardados();
  if (guardados > 0 || omitidos > 0) {
    mostrarToast(`✓ ${guardados} guardado(s)${omitidos ? `, ${omitidos} omitido(s)` : ""}`, omitidos > 0 && guardados === 0);
  }
}

// Convierte bytes a base64 por bloques (btoa directo revienta la pila con arrays grandes).
function bytesABase64(bytes: Uint8Array): string {
  let binario = "";
  const bloque = 0x8000;
  for (let i = 0; i < bytes.length; i += bloque) {
    binario += String.fromCharCode(...bytes.subarray(i, i + bloque));
  }
  return btoa(binario);
}

// Devuelve un mensaje localizado cuando el formato del archivo no está soportado
// por Babel, con instrucciones concretas para convertirlo. Devuelve null si el
// formato sí está soportado (o no se reconoce — el backend dará su propio error).
function mensajeFormatoNoSoportado(nombre: string): string | null {
  const lang = localStorage.getItem("babel-idioma-ui") ?? "es";
  const ext = nombre.split(".").pop()?.toLowerCase() ?? "";

  type Msgs = { es: string; en: string; fr: string; ar: string };
  const msgs: Record<string, Msgs> = {
    pages: {
      es: "Este archivo es de Apple Pages y no se puede procesar directamente. Para usarlo con Babel, expórtalo a PDF o Word desde Pages: Archivo → Exportar a → PDF (o Word).",
      en: "This file is in Apple Pages format and cannot be processed directly. To use it with Babel, export it to PDF or Word from Pages: File → Export To → PDF (or Word).",
      fr: "Ce fichier est au format Apple Pages et ne peut pas être traité directement. Pour l'utiliser avec Babel, exportez-le en PDF ou Word depuis Pages : Fichier → Exporter vers → PDF (ou Word).",
      ar: "هذا الملف بتنسيق Apple Pages ولا يمكن معالجته مباشرةً. لاستخدامه مع Babel، صدّره بتنسيق PDF أو Word من Pages: ملف ← تصدير إلى ← PDF (أو Word).",
    },
    odt: {
      es: "Este archivo es de LibreOffice Writer (.odt) y no se puede procesar directamente. Guárdalo como Word desde LibreOffice: Archivo → Guardar como → Word 2007-365 (.docx).",
      en: "This file is in LibreOffice Writer format (.odt) and cannot be processed directly. Save it as Word from LibreOffice: File → Save As → Word 2007-365 (.docx).",
      fr: "Ce fichier est au format LibreOffice Writer (.odt) et ne peut pas être traité directement. Enregistrez-le comme Word depuis LibreOffice : Fichier → Enregistrer sous → Word 2007-365 (.docx).",
      ar: "هذا الملف بتنسيق LibreOffice Writer ‏(.odt) ولا يمكن معالجته مباشرةً. احفظه بتنسيق Word من LibreOffice: ملف ← حفظ باسم ← Word 2007-365 ‏(.docx).",
    },
    numbers: {
      es: "Este archivo es de Apple Numbers y no se puede procesar directamente. Expórtalo desde Numbers: Archivo → Exportar a → PDF.",
      en: "This file is in Apple Numbers format and cannot be processed directly. Export it from Numbers: File → Export To → PDF.",
      fr: "Ce fichier est au format Apple Numbers et ne peut pas être traité directement. Exportez-le depuis Numbers : Fichier → Exporter vers → PDF.",
      ar: "هذا الملف بتنسيق Apple Numbers ولا يمكن معالجته مباشرةً. صدّره من Numbers: ملف ← تصدير إلى ← PDF.",
    },
    key: {
      es: "Este archivo es de Apple Keynote y no se puede procesar directamente. Expórtalo desde Keynote: Archivo → Exportar a → PDF (o PowerPoint).",
      en: "This file is in Apple Keynote format and cannot be processed directly. Export it from Keynote: File → Export To → PDF (or PowerPoint).",
      fr: "Ce fichier est au format Apple Keynote et ne peut pas être traité directement. Exportez-le depuis Keynote : Fichier → Exporter vers → PDF (ou PowerPoint).",
      ar: "هذا الملف بتنسيق Apple Keynote ولا يمكن معالجته مباشرةً. صدّره من Keynote: ملف ← تصدير إلى ← PDF (أو PowerPoint).",
    },
    doc: {
      es: "El formato .doc (Word antiguo) no está soportado directamente. Ábrelo en Word y guárdalo como .docx: Archivo → Guardar como → Word (.docx).",
      en: "The .doc format (legacy Word) is not directly supported. Open it in Word and save it as .docx: File → Save As → Word (.docx).",
      fr: "Le format .doc (Word ancien) n'est pas pris en charge directement. Ouvrez-le dans Word et enregistrez-le en .docx : Fichier → Enregistrer sous → Word (.docx).",
      ar: "تنسيق .doc (Word القديم) غير مدعوم مباشرةً. افتحه في Word واحفظه بتنسيق .docx: ملف ← حفظ باسم ← Word ‏(.docx).",
    },
    xls: {
      es: "El formato .xls (Excel antiguo) no está soportado directamente. Ábrelo en Excel y expórtalo a PDF: Archivo → Exportar → Crear documento PDF.",
      en: "The .xls format (legacy Excel) is not directly supported. Open it in Excel and export to PDF: File → Export → Create PDF Document.",
      fr: "Le format .xls (Excel ancien) n'est pas pris en charge directement. Ouvrez-le dans Excel et exportez-le en PDF : Fichier → Exporter → Créer un document PDF.",
      ar: "تنسيق .xls (Excel القديم) غير مدعوم مباشرةً. افتحه في Excel وصدّره بصيغة PDF: ملف ← تصدير ← إنشاء مستند PDF.",
    },
    ppt: {
      es: "El formato .ppt (PowerPoint antiguo) no está soportado directamente. Ábrelo en PowerPoint y expórtalo a PDF: Archivo → Exportar → Crear documento PDF.",
      en: "The .ppt format (legacy PowerPoint) is not directly supported. Open it in PowerPoint and export to PDF: File → Export → Create PDF Document.",
      fr: "Le format .ppt (PowerPoint ancien) n'est pas pris en charge directement. Ouvrez-le dans PowerPoint et exportez-le en PDF : Fichier → Exporter → Créer un document PDF.",
      ar: "تنسيق .ppt (PowerPoint القديم) غير مدعوم مباشرةً. افتحه في PowerPoint وصدّره بصيغة PDF: ملف ← تصدير ← إنشاء مستند PDF.",
    },
    rtf: {
      es: "El formato .rtf no está soportado directamente. Ábrelo en TextEdit o Word y guárdalo como .docx o .txt.",
      en: "The .rtf format is not directly supported. Open it in TextEdit or Word and save it as .docx or .txt.",
      fr: "Le format .rtf n'est pas pris en charge directement. Ouvrez-le dans TextEdit ou Word et enregistrez-le en .docx ou .txt.",
      ar: "تنسيق .rtf غير مدعوم مباشرةً. افتحه في TextEdit أو Word واحفظه بتنسيق .docx أو .txt.",
    },
    ods: {
      es: "Este archivo es de LibreOffice Calc (.ods) y no se puede procesar directamente. Expórtalo como PDF desde LibreOffice: Archivo → Exportar como PDF.",
      en: "This file is in LibreOffice Calc format (.ods) and cannot be processed directly. Export it as PDF from LibreOffice: File → Export As PDF.",
      fr: "Ce fichier est au format LibreOffice Calc (.ods) et ne peut pas être traité directement. Exportez-le en PDF depuis LibreOffice : Fichier → Exporter en PDF.",
      ar: "هذا الملف بتنسيق LibreOffice Calc ‏(.ods) ولا يمكن معالجته مباشرةً. صدّره بصيغة PDF من LibreOffice: ملف ← تصدير بصيغة PDF.",
    },
    odp: {
      es: "Este archivo es de LibreOffice Impress (.odp) y no se puede procesar directamente. Expórtalo como PDF desde LibreOffice: Archivo → Exportar como PDF.",
      en: "This file is in LibreOffice Impress format (.odp) and cannot be processed directly. Export it as PDF from LibreOffice: File → Export As PDF.",
      fr: "Ce fichier est au format LibreOffice Impress (.odp) et ne peut pas être traité directement. Exportez-le en PDF depuis LibreOffice : Fichier → Exporter en PDF.",
      ar: "هذا الملف بتنسيق LibreOffice Impress ‏(.odp) ولا يمكن معالجته مباشرةً. صدّره بصيغة PDF من LibreOffice: ملف ← تصدير بصيغة PDF.",
    },
  };

  const entry = msgs[ext];
  if (!entry) return null;
  return entry[lang as keyof Msgs] ?? entry.es;
}

// Cifra y guarda un File arrastrado (sin ruta, solo bytes vía HTML5 drop).
// `destino`: carpeta donde queda; "todos" = sin mover. `recargar`: al importar en
// lote (una carpeta entera) se pasa false para no recargar la lista ni sacar un toast
// por cada archivo — quien llama muestra un resumen al final. Devuelve si se guardó.
async function guardarArchivoDesdeFile(
  file: File,
  destino: string = buzonActivoGuardados,
  recargar: boolean = true,
): Promise<boolean> {
  const nombre = file.name || "archivo";
  if (nombre.endsWith(".babel")) {
    if (recargar) mostrarToast("Los archivos .babel ya están cifrados", true);
    return false;
  }
  const msgFormato = mensajeFormatoNoSoportado(nombre);
  if (msgFormato) {
    if (recargar) mostrarToast(msgFormato, true);
    return false;
  }
  if (file.size > 150 * 1024 * 1024) {
    if (recargar) mostrarToast(`"${nombre}" supera el límite de 150 MB`, true);
    return false;
  }
  const nombreBase = nombre.replace(/\.[^/.]+$/, "");
  const yaExiste = await invoke<boolean>("archivo_guardado_existe", { nombreBase }).catch(() => false);
  if (yaExiste) {
    if (recargar) mostrarToast(`"${nombre}" ya está guardado`, true);
    return false;
  }
  try {
    const buf = await file.arrayBuffer();
    const b64 = bytesABase64(new Uint8Array(buf));
    const rutaCifrada = await invoke<string>("guardar_documento_desde_bytes", {
      nombreArchivo: nombre,
      contenidoB64: b64,
    });
    if (destino !== "todos") {
      try {
        await invoke("mover_archivo_guardado", { ruta: rutaCifrada, buzonDestino: destino });
      } catch (e) {
        console.error("Error moviendo a la carpeta:", e);
      }
    }
    if (recargar) {
      mostrarToast(`✓ ${nombre} guardado y cifrado`, false);
      await cargarArchivosGuardados();
    }
    invoke("registrar_evento_diario", { tipo: "importar", detalle: nombre }).catch(() => {});
    return true;
  } catch (error) {
    if (recargar) mostrarToast(`Error guardando: ${error}`, true);
    return false;
  }
}
// NAVEGACIÓN — ENTRE PANTALLAS Y ACCIONES DE ARCHIVO

// Abre la carpeta de guardados en el Finder del sistema (acceso directo interno)
async function abrirFinderSistema(): Promise<void> {
  try {
    await invoke("abrir_carpeta_guardados");
  } catch (e) {
    mostrarToast("Error abriendo Finder: " + e, true);
  }
}
(window as any).abrirFinderSistema = abrirFinderSistema;

function irATraduccion(): void {
  mostrarPantalla("traduccion");
  setTimeout(() => iniciarDropZone(), 100);
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
    const idiomaUI = localStorage.getItem("babel-idioma-ui") ?? "es";
    const tUI = TRADUCCIONES_UI[idiomaUI] ?? TRADUCCIONES_UI["es"];
    const labelTodos = (tUI.todos as string | undefined) ?? "TODOS";
    lista.innerHTML = `
      <div class="buzon-item ${buzonActivoGuardados === "todos" ? "activo" : ""}" data-action="seleccionar-buzon-guardados" data-buzon="todos">
        <span class="buzon-icono">◫</span><span class="buzon-nombre">${escapeHTML(labelTodos)}</span>
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
    const eraActivo = buzonActivoGuardados === id;
    if (eraActivo) buzonActivoGuardados = "todos";
    await cargarBuzonesGuardados();
    if (eraActivo) await cargarArchivosGuardados();
  } catch (error) {
    console.error("Error borrando buzón guardado:", error);
  }
}

// MOVER ARCHIVOS GUARDADOS — popup selector de buzón destino

async function moverArchivoGuardadoPopup(ruta: string, event: MouseEvent, nombreDisplay?: string): Promise<void> {
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
          const nombreMov = nombreDisplay ?? ruta.split("/").pop()?.replace(/\.babel$/, "") ?? ruta;
          invoke("registrar_evento_diario", { tipo: "mover_archivo", detalle: `${nombreMov} → ${label}` }).catch(() => {});
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
    const nombre = ruta.split("/").pop()?.replace(/\.babel$/, "").replace(/^\d+_/, "") ?? ruta;
    invoke("registrar_evento_diario", { tipo: "descargar", detalle: nombre }).catch(() => {});
  } catch (error) {
    const msg = String(error);
    if (msg.includes("cancelada") || msg.includes("cancelado")) return;
    mostrarToast("Error exportando: " + msg, true);
  }
}
let _popupExportar: HTMLElement | null = null;

function mostrarPopupExportar(ancla: HTMLElement, rutaTrad: string, rutaOrig: string): void {
  cerrarPopupExportar();
  const popup = document.createElement("div");
  popup.style.cssText = `
    position:fixed;z-index:4000;background:var(--fondo-panel);
    border:1px solid var(--borde);border-radius:3px;
    padding:6px 0;min-width:160px;box-shadow:0 4px 16px rgba(0,0,0,0.5);
  `;
  const rect = ancla.getBoundingClientRect();
  popup.style.top = (rect.bottom + 4) + "px";
  popup.style.left = rect.left + "px";

  const btnStyle = `display:block;width:100%;text-align:left;background:none;border:none;
    color:var(--texto);padding:8px 16px;cursor:pointer;font-size:0.68rem;
    letter-spacing:1px;font-family:'Times New Roman',Times,serif;`;

  popup.innerHTML = `
    <button style="${btnStyle}" id="pop-exp-trad">↓ TRADUCIDO</button>
    <button style="${btnStyle}" id="pop-exp-orig">↓ ORIGINAL</button>
  `;
  document.body.appendChild(popup);
  _popupExportar = popup;

  popup.querySelector("#pop-exp-trad")?.addEventListener("click", () => {
    cerrarPopupExportar(); exportarArchivo(rutaTrad);
  });
  popup.querySelector("#pop-exp-orig")?.addEventListener("click", () => {
    cerrarPopupExportar(); exportarArchivo(rutaOrig || rutaTrad);
  });

  requestAnimationFrame(() => {
    document.addEventListener("click", cerrarPopupExportarClick);
  });
}

function cerrarPopupExportar(): void {
  _popupExportar?.remove();
  _popupExportar = null;
  document.removeEventListener("click", cerrarPopupExportarClick);
}

function cerrarPopupExportarClick(e: MouseEvent): void {
  if (!_popupExportar) {
    document.removeEventListener("click", cerrarPopupExportarClick);
    return;
  }
  if (!_popupExportar.contains(e.target as Node)) {
    cerrarPopupExportar();
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
let _tiempoLockMs: number = 30 * 60 * 1000; // default 30 min

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

function pausarTimerInactividad(): void {
  // Al salir de la ventana se pausa el contador — no se bloquea por usar otra app
  if (timerInactividad) clearTimeout(timerInactividad);
  if (timerAvisoLock) clearTimeout(timerAvisoLock);
}

async function bloquearPantalla(): Promise<void> {
  desactivarTimerInactividad();
  _sesionActiva = false;
  try { await invoke("cerrar_sesion_rust"); } catch { /* continúa bloqueando aunque falle */ }
  const overlay = document.getElementById("pantalla-bloqueo");
  if (overlay) {
    overlay.classList.remove("hidden");
    escanearKeyloggerAlEntrar();
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
      // FINDER — drenar la cola de "Guardar con Babel" acumulada durante el bloqueo.
      invoke("procesar_entrada_finder").catch(() => {});
      invoke<boolean>("tiene_config_email").then(ok2 => {
        _smtpConfigurado = ok2;
        if (ok2) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
      }).catch(() => {});
      invoke<string | null>("estado_oauth_gmail_tauri").then((email) => {
        if (email) { actualizarUIGmailOAuth(email); _oauthGmailConectado = true; }
        else { _oauthGmailConectado = false; }
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
  // Pausar al salir de la ventana, reanudar al volver — no bloquear por usar otra app
  window.addEventListener("blur", pausarTimerInactividad);
  window.addEventListener("focus", resetearTimerInactividad);
  resetearTimerInactividad();
}

function desactivarTimerInactividad(): void {
  if (timerInactividad) clearTimeout(timerInactividad);
  if (timerAvisoLock) clearTimeout(timerAvisoLock);
  ["mousemove", "keydown", "mousedown", "touchstart", "click"].forEach(evento => {
    document.removeEventListener(evento, resetearTimerInactividad);
  });
  window.removeEventListener("blur", pausarTimerInactividad);
  window.removeEventListener("focus", resetearTimerInactividad);
}
// VISOR INDIVIDUAL — modal simple

async function traducirArchivoGuardado(ruta: string, nombreDisplay?: string): Promise<void> {
  irATraduccion();
  const nombreOrig = ruta.replace(/\\/g, "/").split("/").pop() ?? "archivo.babel";
  const nombreMostrado = nombreDisplay ?? nombreOrig.replace(/\.babel$/, "").replace(/^\d+_/, "");
  añadirMensajeArchivo(nombreMostrado, "GUARDADO · babel");
  mostrarProcesando(true);
  try {
    const rutaResultado = await invoke<string>("traducir_archivo_guardado", { ruta });
    mostrarProcesando(false);
    const nombreTrad = rutaResultado.replace(/\\/g, "/").split("/").pop() ?? rutaResultado;
    añadirResultadoArchivo(nombreTrad, rutaResultado);
    scrollAlFinal();
    // Mover el resultado al buzon donde estaba el original (si no es "todos")
    if (buzonActivoGuardados !== "todos") {
      invoke("mover_archivo_guardado", { ruta: rutaResultado, buzonDestino: buzonActivoGuardados }).catch(() => {});
    }
    invoke("registrar_evento_diario", { tipo: "traducir", detalle: nombreMostrado }).catch(() => {});
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error al traducir: " + String(error), "BABEL · error");
  }
}

async function verArchivo(ruta: string, nombreDisplay?: string): Promise<void> {
  try {
    const texto = await invoke<string>("ver_archivo", { ruta });
    const nombre = nombreDisplay ?? ruta.split("/").pop() ?? ruta;
    const modal = document.getElementById("modal-visor");
    const modalNombre = document.getElementById("modal-visor-nombre");
    const modalContenido = document.getElementById("modal-visor-contenido");
    if (!modal || !modalNombre || !modalContenido) return;
    modalNombre.textContent = escapeHTML(nombre);
    renderizarEnContenedor(texto, modalContenido);
    modal.classList.remove("hidden");
    invoke("registrar_evento_diario", { tipo: "ver_archivo", detalle: nombre.replace(/\.babel$/, "").replace(/^\d+_/, "") }).catch(() => {});
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
  if (cont1) renderizarEnContenedor(datos[0].texto, cont1, "100%");

  if (datos.length === 2 && divisor && panel2 && titulo2 && cont2) {
    divisor.style.display = "block";
    panel2.style.display = "flex";
    titulo2.textContent = datos[1].nombre;
    renderizarEnContenedor(datos[1].texto, cont2, "100%");
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
    if (cont1) renderizarEnContenedor(textoOrig, cont1, "100%");
    if (divisor) divisor.style.display = "block";
    if (panel2) panel2.style.display = "flex";
    if (titulo2) titulo2.textContent = "TRADUCCIÓN";
    if (cont2) renderizarEnContenedor(textoTrad, cont2, "100%");
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
    // Mostrar modal OAuth si no hay cuenta conectada (la función decide sola si procede)
    setTimeout(() => mostrarModalConfigurarEmail(), 300);
    if (_smtpConfigurado) {
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
  const timeoutMin = parseInt((document.getElementById("selector-timeout") as HTMLSelectElement)?.value ?? "60", 10);

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
  const min = Math.max(2, Math.min(120, parseInt(minutos, 10)));
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
  const timeoutMin: number = Math.max(2, Math.min(120, s.timeout_sesion_minutos ?? 60));

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
  const toggleRapido = document.getElementById("toggle-modo-rapido") as HTMLInputElement | null;
  // MODO RÁPIDO: si el usuario lo fijó a mano ("si"/"no") se respeta; si nunca lo tocó
  // (null) el default lo decide el hardware — ON en 8 GB (SMaLL-100), OFF en 16 GB (MADLAD).
  const lsRapido = localStorage.getItem(LS_MODO_RAPIDO);
  const modoRapidoAct = lsRapido === "si" ? true
    : lsRapido === "no" ? false
    : await modoRapidoPorDefecto();
  if (toggleRapido) toggleRapido.checked = modoRapidoAct;
  invoke("set_modo_rapido", { activado: modoRapidoAct }).catch(() => {});
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
  destacado: boolean;
  snippet: string;
}

// Email seleccionado actualmente
const emailsVistos = new Set<number>();
let emailVisorActualId: number | null = null;
let _emailVisorRemitente: string = "";
let _emailVista: string = "todos";
let _emailsCache: EmailResumen[] = [];
let _emailPaginaVis: number = 25;
let _firmaEmail: string = "";
let _cuerpoEmailOriginal: string = "";
let _imapCargando = false;   // B1: evita sesiones IMAP concurrentes en lectura
let _imapMutando = false;    // B1: evita sesiones IMAP concurrentes en mutación

function filtrarEmailsVista(emails: EmailResumen[], vista: string): EmailResumen[] {
  if (vista === "noleidos") return emails.filter(e => !e.leido && !emailsVistos.has(e.id));
  if (vista === "destacados") return emails.filter(e => e.destacado);
  return emails;
}

function renderizarListaEmail(emails: EmailResumen[], resetPagina = true): void {
  const lista = document.getElementById("email-lista");
  if (!lista) return;

  if (emails.length === 0) {
    lista.innerHTML = `
      <div class="email-vacio">
        <span style="font-size:2rem;opacity:0.13;">✉</span>
        <p class="email-vacio-titulo">Sin correos</p>
        <p class="email-vacio-sub">No hay correos en esta vista</p>
      </div>`;
    return;
  }

  if (resetPagina) _emailPaginaVis = 25;
  const visibles = emails.slice(0, _emailPaginaVis);
  const hayMas = emails.length > _emailPaginaVis;

  let noLeidos = 0;
  const html = visibles.map(email => {
    const visto = emailsVistos.has(email.id) || email.leido;
    if (!visto) noLeidos++;
    const idStr = String(Number(email.id));
    return `
    <div class="email-item${visto ? "" : " no-leido"}${email.destacado ? " destacado" : ""}"
         data-action="seleccionar-email" data-id="${idStr}">
      <div class="email-item-cabecera">
        <div class="email-item-remitente">${escapeHTML(formatearRemitente(email.remitente))}</div>
        ${!visto ? '<span class="email-punto-nuevo"></span>' : ""}
      </div>
      <div class="email-item-asunto">${escapeHTML(email.asunto)}</div>
      ${email.snippet ? `<div class="email-item-snippet">${escapeHTML(email.snippet)}</div>` : ""}
      <div class="email-item-meta">
        <span class="email-item-fecha">${formatearFechaEmail(email.fecha)}</span>
        <span class="email-item-meta-iconos">
          ${email.tiene_adjunto ? '<span title="Tiene adjunto">📎</span>' : ""}
        </span>
      </div>
      <div class="email-item-acciones">
        <button class="email-accion-mini${email.destacado ? " activo" : ""}" title="${email.destacado ? "Quitar estrella" : "Destacar"}"
          data-action="lista-destacar" data-id="${idStr}" data-val="${email.destacado ? "0" : "1"}">
          ${email.destacado ? "★" : "☆"}
        </button>
        <button class="email-accion-mini" title="Archivar" data-action="lista-archivar" data-id="${idStr}">▽</button>
        <button class="email-accion-mini peligro" title="Eliminar" data-action="lista-eliminar" data-id="${idStr}">🗑</button>
      </div>
    </div>`;
  }).join("");

  const btnMas = hayMas
    ? `<button class="email-cargar-mas" data-action="email-cargar-mas" data-total="${emails.length}">
         Cargar más (${emails.length - _emailPaginaVis} restantes)
       </button>`
    : "";

  lista.innerHTML = html + btnMas;

  lista.onclick = (e: MouseEvent) => {
    const target = e.target as HTMLElement;
    const btn = target.closest("[data-action]") as HTMLElement | null;
    if (!btn) return;
    const action = btn.dataset.action;
    if (action === "email-cargar-mas") {
      _emailPaginaVis += 25;
      renderizarListaEmail(filtrarEmailsVista(_emailsCache, _emailVista), false);
      return;
    }
    const id = parseInt(btn.dataset.id ?? "", 10);
    if (!Number.isFinite(id)) return;
    if (action === "seleccionar-email") { seleccionarEmail(id); return; }
    // Botones de acción en fila — stopPropagation para no abrir el email
    e.stopPropagation();
    if (action === "lista-archivar") { void accionListaEmail(id, "archivar"); return; }
    if (action === "lista-eliminar") { void accionListaEmail(id, "eliminar"); return; }
    if (action === "lista-destacar") {
      const destacar = btn.dataset.val === "1";
      void accionListaEmail(id, "destacado", destacar);
      return;
    }
  };

  const tituloSidebar = document.querySelector(".email-sidebar-titulo");
  if (tituloSidebar) tituloSidebar.textContent = noLeidos > 0 ? `BANDEJA (${noLeidos})` : "BANDEJA";
  actualizarBadgeEmail(noLeidos);
}

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
    const vistaImap = _emailVista === "archivados" ? "archivados" : "todos";
    const idsAnteriores = new Set(_emailsCache.map(e => e.id));
    const fetched = await invoke<EmailResumen[]>("obtener_emails_tauri", { vista: vistaImap });
    if (vistaImap === "todos") {
      // Detectar correos nuevos (solo en cargas posteriores a la primera)
      if (_emailsCache.length > 0) {
        const nuevos = fetched.filter(e => !idsAnteriores.has(e.id) && !e.leido);
        if (nuevos.length > 0) {
          mostrarToast(`${nuevos.length} correo${nuevos.length > 1 ? "s" : ""} nuevo${nuevos.length > 1 ? "s" : ""}`, false);
        }
      }
      _emailsCache = fetched;
    }

    const emails = _emailVista === "archivados" ? fetched : filtrarEmailsVista(fetched, _emailVista);

    if (emails.length === 0) {
      lista.innerHTML = `
        <div class="email-vacio">
          <span style="font-size:2rem;opacity:0.13;">✉</span>
          <p class="email-vacio-titulo">Sin correos</p>
          <p class="email-vacio-sub">No hay correos en esta vista</p>
        </div>`;
      return;
    }

    renderizarListaEmail(emails);
    return;

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
function formatearRemitente(remitente: string): string {
  // "Nombre <email@dominio>" → "Nombre"
  const match = remitente.match(/^(.+?)\s*<[^>]+>$/);
  if (match) {
    return match[1].trim().replace(/^["']|["']$/g, "") || remitente;
  }
  // Solo dirección email → mostrar la parte antes del @
  const atIdx = remitente.indexOf("@");
  if (atIdx > 0) return remitente.slice(0, atIdx);
  return remitente;
}

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
    const limpio = DOMPurify.sanitize(cuerpo, {
      ALLOWED_TAGS: ["p", "div", "br", "span", "b", "i", "u", "strong", "em", "ul", "ol", "li",
                     "table", "thead", "tbody", "tr", "th", "td", "a", "img",
                     "h1", "h2", "h3", "h4", "blockquote", "pre", "code", "font", "center", "hr"],
      ALLOWED_ATTR: ["href", "alt", "title", "class", "width", "height", "style",
                     "src", "align", "valign", "bgcolor", "color", "size", "border",
                     "cellpadding", "cellspacing"],
      FORBID_ATTR: ["onerror", "onload", "onclick", "onmouseover", "onfocus", "onblur"],
      ALLOW_DATA_ATTR: false,
      FORCE_BODY: true,
    });
    // Fondo blanco: los emails HTML asumen fondo blanco — sin esto el texto oscuro es invisible
    const wrapper = document.createElement("div");
    wrapper.style.cssText = "background:#ffffff;color:#222222;padding:20px 24px;border-radius:6px;line-height:1.6;font-family:sans-serif;";
    wrapper.innerHTML = limpio;
    // Bloquear tracking pixels: eliminar src de imágenes externas (solo data: permitido).
    // Esto impide que un email malicioso filtre la IP del usuario al abrirlo.
    wrapper.querySelectorAll("img").forEach(img => {
      const src = img.getAttribute("src") ?? "";
      if (!src.startsWith("data:image/")) {
        img.removeAttribute("src");
        img.setAttribute("alt", img.getAttribute("alt") || "[imagen externa bloqueada]");
        img.style.display = "none";
      }
    });
    contenedor.appendChild(wrapper);
    // Interceptar clicks en links para abrirlos en el navegador externo
    wrapper.querySelectorAll("a[href]").forEach(el => {
      el.addEventListener("click", (e) => {
        e.preventDefault();
        const href = (el as HTMLAnchorElement).href;
        if (href.startsWith("https://") || href.startsWith("http://")) {
          openUrl(href).catch(() => {});
        }
      });
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
        a.addEventListener("click", (e) => {
          e.preventDefault();
          openUrl(parte).catch(() => {});
        });
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
    _emailVisorRemitente = email.remitente;
    // Sincronizar estado destacado con el ítem de la lista
    const itemActual = document.querySelector(`.email-item[data-id="${email.id}"]`);
    _emailVisorDestacado = itemActual?.classList.contains("destacado") ?? false;
    const btnDest = document.getElementById("btn-destacar-visor");
    if (btnDest) btnDest.textContent = _emailVisorDestacado ? "★ Destacado" : "☆ Destacar";
    if (asuntoEl) asuntoEl.textContent = email.asunto || "Sin asunto";
    if (metaEl) metaEl.textContent = `De: ${email.remitente} · ${formatearFechaEmail(email.fecha)}`;
    if (adjuntosEl) adjuntosEl.innerHTML = email.adjuntos.map(a => `<span class="email-adjunto-tag">📎 ${escapeHTML(a)}</span>`).join("");
    _cuerpoEmailOriginal = email.cuerpo;
    if (cuerpoEl) renderizarCuerpoEmail(cuerpoEl, email.cuerpo);
  } catch (error) {
    mostrarToast("Error cargando email: " + String(error), true);
    lectorVacio?.classList.remove("hidden");
    visor?.classList.add("hidden");
    emailVisorActualId = null;
    _emailVisorRemitente = "";
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

// Quita el adjunto seleccionado sin cerrar el compositor
function limpiarAdjuntoEmail(): void {
  archivoEmailRuta = "";
  archivoEmailFile = null;
  const el = document.getElementById("comp-archivo-nombre");
  if (el) el.textContent = "📎 Adjuntar (opcional)";
}

// Cierra el compositor y limpia los campos y archivos adjuntos
function cerrarCompositor(): void {
  document.getElementById("email-compositor")?.classList.add("hidden");
  document.getElementById("email-lector-vacio")?.classList.remove("hidden");
  archivoEmailRuta = "";
  archivoEmailFile = null;
  const g = (id: string) => document.getElementById(id);
  const n = g("comp-archivo-nombre"); if (n) n.textContent = "📎 Adjuntar (opcional)";
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
  _emailVisorRemitente = "";
  _cuerpoEmailOriginal = "";
}

// Abre el selector de archivo en la carpeta ~/Babel
async function seleccionarArchivoEmail(): Promise<void> {
  try {
    const resultado = await invoke<[string, number[]] | null>("seleccionar_archivo_email_dialogo");
    if (!resultado) return;
    const [nombre, bytesArr] = resultado;
    archivoEmailFile = new File([new Uint8Array(bytesArr)], nombre);
    archivoEmailRuta = "";
    const el = document.getElementById("comp-archivo-nombre");
    if (el) el.textContent = "📎 " + nombre;
  } catch (e) {
    mostrarToast("Error abriendo selector: " + String(e), true);
  }
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

// ──────────────────────────────────────────────────────────────────────────────
// MODAL CONFIGURAR CORREO
// ──────────────────────────────────────────────────────────────────────────────

function mostrarModalConfigurarEmail(): void {
  // No mostrar si ya se cerró en esta sesión o si hay OAuth Gmail activo
  if (_modalEmailVistoEnSesion || _oauthGmailConectado) return;
  document.getElementById("modal-configurar-email")?.classList.remove("hidden");
}

function cerrarModalConfigurarEmail(): void {
  // Suprimir para el resto de la sesión (no persiste entre reinicios)
  _modalEmailVistoEnSesion = true;
  document.getElementById("modal-configurar-email")?.classList.add("hidden");
}

// ──────────────────────────────────────────────────────────────────────────────
// GMAIL OAUTH
// ──────────────────────────────────────────────────────────────────────────────

function actualizarUIGmailOAuth(email: string): void {
  const conectado = document.getElementById("oauth-estado-conectado");
  const desconectado = document.getElementById("oauth-estado-desconectado");
  const emailValor = document.getElementById("oauth-email-valor");
  const btnConectar = document.getElementById("btn-conectar-gmail");
  const btnDesconectar = document.getElementById("btn-desconectar-gmail");
  if (emailValor) emailValor.textContent = email;
  conectado?.classList.remove("hidden");
  desconectado?.classList.add("hidden");
  btnConectar?.classList.add("hidden");
  btnDesconectar?.classList.remove("hidden");
}

function resetUIGmailOAuth(): void {
  const conectado = document.getElementById("oauth-estado-conectado");
  const desconectado = document.getElementById("oauth-estado-desconectado");
  const btnConectar = document.getElementById("btn-conectar-gmail");
  const btnDesconectar = document.getElementById("btn-desconectar-gmail");
  conectado?.classList.add("hidden");
  desconectado?.classList.remove("hidden");
  btnConectar?.classList.remove("hidden");
  btnDesconectar?.classList.add("hidden");
}

async function iniciarOAuthGmail(): Promise<void> {
  const progreso = document.getElementById("oauth-progreso");
  progreso?.classList.remove("hidden");
  try {
    const url = await invoke<string>("iniciar_oauth_gmail_tauri");
    if (!url.startsWith("https://accounts.google.com/")) {
      throw new Error("URL OAuth inesperada — abortado por seguridad.");
    }
    await openUrl(url);
  } catch (e) {
    progreso?.classList.add("hidden");
    mostrarToast("Error iniciando OAuth: " + String(e), true);
  }
}

async function revocarOAuthGmail(): Promise<void> {
  try {
    await invoke("revocar_oauth_gmail_tauri");
    resetUIGmailOAuth();
    _smtpConfigurado = false;
    _oauthGmailConectado = false;
    _modalEmailVistoEnSesion = false;
    mostrarToast("Gmail desconectado", false);
  } catch (e) {
    mostrarToast("Error al desconectar: " + String(e), true);
  }
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

  const tieneAdjunto = !!(archivoEmailFile || archivoEmailRuta);

  // Solo mostrar aviso de seguridad si se adjunta un documento de Babel (descifrado)
  if (tieneAdjunto) {
    const confirmado = window.confirm(
      "AVISO DE SEGURIDAD\n\n" +
      "Vas a enviar este documento DESCIFRADO por email.\n" +
      "El destinatario podrá leerlo sin necesitar Babel.\n\n" +
      "¿Continuar?"
    );
    if (!confirmado) return;
  }

  if (estado) estado.textContent = "Enviando...";

  try {
    if (!tieneAdjunto) {
      // Email de solo texto — sin adjunto
      await invoke("enviar_solo_texto_tauri", { destinatario, asunto, cuerpo, cc, cco });
    } else if (archivoEmailFile) {
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
    mostrarToast(tieneAdjunto ? "✓ Enviado cifrado" : "✓ Enviado", false);
    cerrarCompositor();
    await cargarBandejaEmail();
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

function textoPlanoDeEmail(cuerpo: string): string {
  // Extrae texto legible de HTML o devuelve el texto plano tal cual
  if (!cuerpo.trim().startsWith("<")) return cuerpo;
  const div = document.createElement("div");
  // Sanitizar antes de asignar: evita que imágenes externas del HTML carguen en el div temporal
  div.innerHTML = DOMPurify.sanitize(cuerpo, { ALLOWED_TAGS: [], KEEP_CONTENT: true });
  return div.innerText;
}

function bloquesCita(cuerpo: string): string {
  return textoPlanoDeEmail(cuerpo)
    .split("\n")
    .map(l => `> ${l}`)
    .join("\n");
}

function responderEmail(): void {
  const asuntoEl = document.getElementById("visor-asunto");
  const asunto = asuntoEl?.textContent ?? "";
  const metaEl = document.getElementById("visor-meta");
  const meta = metaEl?.textContent ?? "";

  abrirComponerEmail();

  const destinatario = document.getElementById("comp-destinatario") as HTMLInputElement;
  const asuntoComp = document.getElementById("comp-asunto") as HTMLInputElement;
  const cuerpoComp = document.getElementById("comp-cuerpo") as HTMLTextAreaElement;

  if (destinatario) destinatario.value = _emailVisorRemitente;
  if (asuntoComp && asunto) asuntoComp.value = asunto.startsWith("Re:") ? asunto : `Re: ${asunto}`;

  if (cuerpoComp && _cuerpoEmailOriginal) {
    const firma = _firmaEmail ? `\n\n—\n${_firmaEmail}` : "";
    cuerpoComp.value = `${firma}\n\n${meta}\n${bloquesCita(_cuerpoEmailOriginal)}`;
    cuerpoComp.setSelectionRange(0, 0);
    cuerpoComp.scrollTop = 0;
  }
}

function reenviarEmail(): void {
  const asuntoEl = document.getElementById("visor-asunto");
  const asunto = asuntoEl?.textContent ?? "";
  const metaEl = document.getElementById("visor-meta");
  const meta = metaEl?.textContent ?? "";

  abrirComponerEmail();

  const asuntoComp = document.getElementById("comp-asunto") as HTMLInputElement;
  const cuerpoComp = document.getElementById("comp-cuerpo") as HTMLTextAreaElement;

  if (asuntoComp && asunto) asuntoComp.value = asunto.startsWith("Fwd:") ? asunto : `Fwd: ${asunto}`;

  if (cuerpoComp && _cuerpoEmailOriginal) {
    const firma = _firmaEmail ? `\n\n—\n${_firmaEmail}` : "";
    cuerpoComp.value = `${firma}\n\n---------- Mensaje reenviado ----------\n${meta}\n\n${textoPlanoDeEmail(_cuerpoEmailOriginal)}`;
    cuerpoComp.setSelectionRange(0, 0);
    cuerpoComp.scrollTop = 0;
  }
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

async function accionListaEmail(id: number, accion: "archivar" | "eliminar" | "destacado", destacar?: boolean): Promise<void> {
  if (_imapMutando) return;
  _imapMutando = true;
  try {
    if (accion === "archivar") {
      await invoke("archivar_email_tauri", { id });
      document.querySelector(`.email-item[data-id="${id}"]`)?.remove();
      if (emailVisorActualId === id) cerrarVisorEmail();
      mostrarToast("Archivado.", false);
    } else if (accion === "eliminar") {
      await invoke("eliminar_email_tauri", { id });
      document.querySelector(`.email-item[data-id="${id}"]`)?.remove();
      if (emailVisorActualId === id) cerrarVisorEmail();
      mostrarToast("Eliminado.", false);
    } else if (accion === "destacado") {
      const val = destacar ?? true;
      await invoke("marcar_destacado_tauri", { id, destacar: val });
      const itemEl = document.querySelector(`.email-item[data-id="${id}"]`) as HTMLElement | null;
      if (itemEl) {
        itemEl.classList.toggle("destacado", val);
        const btn = itemEl.querySelector("[data-action='lista-destacar']") as HTMLElement | null;
        if (btn) { btn.dataset.val = val ? "0" : "1"; btn.textContent = val ? "★" : "☆"; btn.classList.toggle("activo", val); }
      }
    }
  } catch (e) {
    mostrarToast(`Error: ${e}`, true);
  } finally {
    _imapMutando = false;
  }
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

async function archivarEmailActual(): Promise<void> {
  if (emailVisorActualId === null || _imapMutando) return;
  _imapMutando = true;
  const id = emailVisorActualId;
  try {
    await invoke("archivar_email_tauri", { id });
    cerrarVisorEmail();
    mostrarToast("Correo archivado.", false);
    await cargarBandejaEmail();
  } catch (e) {
    mostrarToast(`Error archivando: ${e}`, true);
  } finally {
    _imapMutando = false;
  }
}

let _emailVisorDestacado = false;

async function toggleDestacadoActual(): Promise<void> {
  if (emailVisorActualId === null || _imapMutando) return;
  _imapMutando = true;
  const id = emailVisorActualId;
  const nuevoValor = !_emailVisorDestacado;
  try {
    await invoke("marcar_destacado_tauri", { id, destacar: nuevoValor });
    _emailVisorDestacado = nuevoValor;
    const btn = document.getElementById("btn-destacar-visor");
    if (btn) btn.textContent = nuevoValor ? "★ Destacado" : "☆ Destacar";
    mostrarToast(nuevoValor ? "⭐ Destacado" : "☆ Quitado de destacados", false);
    // Actualizar lista sin recargar IMAP
    const itemEl = document.querySelector(`.email-item[data-id="${id}"]`) as HTMLElement | null;
    if (itemEl) {
      itemEl.classList.toggle("destacado", nuevoValor);
      const btnLista = itemEl.querySelector("[data-action='toggle-destacado-lista']") as HTMLElement | null;
      if (btnLista) { btnLista.dataset.destacar = nuevoValor ? "0" : "1"; btnLista.textContent = nuevoValor ? "★" : "☆"; }
      const iconos = itemEl.querySelector(".email-item-meta-iconos");
      if (iconos) {
        const estrella = iconos.querySelector("span[title='Destacado']");
        if (nuevoValor && !estrella) { const s = document.createElement("span"); s.title = "Destacado"; s.textContent = "⭐"; iconos.appendChild(s); }
        else if (!nuevoValor && estrella) estrella.remove();
      }
    }
  } catch (e) {
    mostrarToast(`Error: ${e}`, true);
  } finally {
    _imapMutando = false;
  }
}

// Acciones rápidas desde los botones de la lista (sin abrir el email)



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
    const resultado = await invoke<{ aviso: string; pass_recuperado: string }>("recuperar_y_autenticar", { palabras });
    for (let i = 1; i <= 12; i++) {
      const el = document.getElementById(`rec-palabra-${i}`) as HTMLInputElement | null;
      if (el) { el.value = "0".repeat(el.value.length); el.value = ""; }
    }
    const aviso = resultado.aviso;
    const passRecuperado = resultado.pass_recuperado;
    mostrarMensaje("recovery-msg",
      aviso ? `⚠ ${aviso} — Accediendo...` : `✓ FRASE VERIFICADA — ACCESO CONCEDIDO`, false);

    _sesionActiva = true;
    activarTimerInactividad();
    invoke<boolean>("tiene_config_email").then(ok => {
      _smtpConfigurado = ok;
      if (ok) invoke<string>("obtener_firma_email").then(f => { _firmaEmail = f; }).catch(() => {});
    }).catch(() => {});

    // Mostrar la contraseña recuperada antes de entrar al panel
    if (passRecuperado) mostrarPassRecuperado(passRecuperado);

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

function mostrarPassRecuperado(pass: string): void {
  const modal = document.getElementById("modal-pass-recuperado");
  const valor = document.getElementById("pass-recuperado-valor");
  if (!modal || !valor) return;
  valor.textContent = pass;
  modal.classList.remove("hidden");
}

function cerrarPassRecuperado(): void {
  const modal = document.getElementById("modal-pass-recuperado");
  const valor = document.getElementById("pass-recuperado-valor");
  if (valor) { valor.textContent = "0".repeat(valor.textContent?.length ?? 0); valor.textContent = ""; }
  modal?.classList.add("hidden");
}

function irAFechaRegistro(fechaISO: string): void {
  if (!fechaISO) return;
  const [y, m, d] = fechaISO.split("-").map(Number);
  const objetivo = new Date(y, m - 1, d);
  objetivo.setHours(0, 0, 0, 0);
  const hoy = new Date();
  hoy.setHours(0, 0, 0, 0);
  const diff = Math.round((objetivo.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24));
  if (diff > 0) {
    mostrarToast("No puedes navegar a fechas futuras.", false);
    return;
  }
  _registroFechaOffset = diff;
  _registroFiltroIPs.clear();
  cargarRegistroDia().catch(() => {});
  // Limpiar el input para que se pueda seleccionar la misma fecha otra vez
  const inp = document.getElementById("registro-buscar-fecha") as HTMLInputElement | null;
  if (inp) inp.value = "";
}
(window as any).irAFechaRegistro = irAFechaRegistro;

async function abrirFinderInApp(): Promise<void> {
  const modal = document.getElementById("modal-finder-inapp");
  const lista = document.getElementById("finder-inapp-lista");
  const conteo = document.getElementById("finder-conteo");
  const rutaLabel = document.getElementById("finder-ruta-label");
  if (!modal || !lista) return;
  lista.innerHTML = `<p style="text-align:center;font-size:0.65rem;letter-spacing:1px;color:var(--texto-secundario);padding:20px;opacity:0.5;">CARGANDO…</p>`;
  modal.classList.remove("hidden");
  try {
    const archivos = await invoke<MetadatosArchivo[]>("listar_archivos_guardados", { buzon: "todos" });
    if (rutaLabel) rutaLabel.textContent = `~/Babel/guardados · ${buzonActivoGuardados.toUpperCase()}`;
    if (conteo) conteo.textContent = `${archivos.length} archivo${archivos.length !== 1 ? "s" : ""}`;
    if (archivos.length === 0) {
      lista.innerHTML = `<p style="text-align:center;font-size:0.65rem;letter-spacing:1px;color:var(--texto-secundario);padding:30px;opacity:0.5;">SIN ARCHIVOS</p>`;
      return;
    }
    lista.innerHTML = archivos.map(a => {
      const nombre = a.nombre.replace(/\.babel$/, "").replace(/^\d+_/, "");
      const peso = a.tamaño ? `${Math.round(a.tamaño / 1024)} KB` : "";
      const buzon = a.buzon && a.buzon !== "todos" ? a.buzon : "";
      return `
        <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;border:1px solid var(--borde);
          border-radius:3px;cursor:pointer;transition:border-color 0.15s;"
          onmouseenter="this.style.borderColor='var(--borde-dorado)'"
          onmouseleave="this.style.borderColor='var(--borde)'"
          onclick="verArchivoDesdeFinderInApp('${escapeHTML(a.ruta ?? "")}')">
          <span style="font-size:1.2rem;flex-shrink:0;opacity:0.6;">◫</span>
          <div style="flex:1;min-width:0;">
            <div style="font-family:'Times New Roman',Times,serif;font-size:0.72rem;letter-spacing:1px;
              color:var(--texto-principal);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
              title="${escapeHTML(nombre)}">${escapeHTML(nombre)}</div>
            <div style="font-size:0.58rem;color:var(--texto-secundario);opacity:0.5;letter-spacing:0.5px;margin-top:2px;">
              ${escapeHTML(peso)}${buzon ? ` · ${escapeHTML(buzon)}` : ""} · AES-256-GCM
            </div>
          </div>
        </div>`;
    }).join("");
  } catch (e) {
    lista.innerHTML = `<p style="text-align:center;font-size:0.65rem;color:#ef4444;padding:20px;">${escapeHTML(String(e))}</p>`;
  }
}

async function verArchivoDesdeFinderInApp(ruta: string): Promise<void> {
  document.getElementById("modal-finder-inapp")?.classList.add("hidden");
  try {
    const texto = await invoke<string>("ver_archivo", { ruta });
    const modal = document.getElementById("modal-visor");
    const modalContenido = document.getElementById("modal-visor-contenido");
    const modalNombre = document.getElementById("modal-visor-nombre");
    if (!modal || !modalContenido) return;
    const nombre = ruta.split("/").pop()?.replace(/\.babel$/, "") ?? ruta;
    if (modalNombre) modalNombre.textContent = nombre;
    renderizarEnContenedor(texto, modalContenido);
    modal.classList.remove("hidden");
  } catch (e) {
    mostrarToast("Error abriendo archivo: " + String(e), true);
  }
}
(window as any).verArchivoDesdeFinderInApp = verArchivoDesdeFinderInApp;

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
(window as any).toggleModoRapido = toggleModoRapido;
(window as any).toggleBorradoAutomatico = toggleBorradoAutomatico;
(window as any).toggleSincronizacion = toggleSincronizacion;
(window as any).cambiarIdiomaDesdeSelectores = cambiarIdiomaDesdeSelectores;
(window as any).cambiarIdiomaDesdeAjustes = cambiarIdiomaDesdeAjustes;
(window as any).cambiarCategoriaDiccionario = cambiarCategoriaDiccionario;

(window as any).manejarSeleccionArchivoEmail = manejarSeleccionArchivoEmail;
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

const TRADUCCIONES_UI: Record<string, Record<string, string | Record<string, string>>> = {
  es: {
    traducir: "TRADUCIR", archivos: "ARCHIVOS", p2p: "P2P", ajustes: "⚙ AJUSTES", cerrarSesion: "CERRAR SESIÓN",
    borrarChat: "BORRAR CHAT", configuracion: "CONFIGURACIÓN", borrarAlSalir: "BORRAR AL SALIR",
    borrarAlSalirDesc: "Limpia el chat al volver al panel", emailAuto: "EMAIL AUTO", proximamente: "Próximamente",
    diccionario: "DICCIONARIO", vocabularioActivo: "Vocabulario activo", volver: "← VOLVER",
    verArchivo: "◫ VER ARCHIVO", eliminar: "✕ ELIMINAR", compartir: "⇪ COMPARTIR", unirPdfs: "⊕ UNIR PDFs",
    exportarTodo: "↓ EXPORTAR TODO", importar: "+ IMPORTAR", tema: "TEMA", idiomaInterfaz: "IDIOMA DE LA INTERFAZ",
    bienvenido: "BIENVENIDO AL SISTEMA", bienvenidoSistema: "BIENVENIDO AL SISTEMA", accederBunker: "ACCEDER A BÚNKER EXISTENTE",
    autenticacion: "AUTENTICACIÓN REQUERIDA", ajustesTitulo: "AJUSTES", volverPanel: "← VOLVER AL PANEL",
    fraseRecuperacion: "FRASE DE RECUPERACIÓN", recuperarBunker: "RECUPERAR BÚNKER",
    traducidosGuardados: "TRADUCIDOS Y GUARDADOS", buzones: "CARPETAS", archivosTitulo: "ARCHIVOS",
    noArchivos: "No hay archivos guardados", arrastra: "Arrastra documentos aquí para cifrarlos",
    buzonesTord: "CARPETAS", finder: "◫ FINDER", todos: "TODOS",
    idiomaNames: { es: "Español", en: "Inglés", fr: "Francés", ar: "Árabe", de: "Alemán", ru: "Ruso", zh: "Chino" },
    modalEmailTitulo: "CONFIGURAR CORREO",
    modalEmailDesc: "Para leer y enviar correos desde Babel, conecta tu cuenta de Gmail.",
    modalEmailBtnConectar: "CONECTAR CON GMAIL",
    modalEmailAviso: "Tu correo se conecta de forma segura a través de Google. Babel nunca ve ni almacena tu contraseña. Autoriza solo desde dispositivos en los que confíes.",
    modalEmailBtnPosponer: "Ahora no",
  },
  en: {
    traducir: "TRANSLATE", archivos: "FILES", p2p: "P2P", ajustes: "⚙ SETTINGS", cerrarSesion: "SIGN OUT",
    borrarChat: "CLEAR CHAT", configuracion: "SETTINGS", borrarAlSalir: "CLEAR ON EXIT",
    borrarAlSalirDesc: "Clears chat when returning to panel", emailAuto: "AUTO EMAIL", proximamente: "Coming soon",
    diccionario: "DICTIONARY", vocabularioActivo: "Active vocabulary", volver: "← BACK",
    verArchivo: "◫ VIEW FILE", eliminar: "✕ DELETE", compartir: "⇪ SHARE", unirPdfs: "⊕ MERGE PDFs",
    exportarTodo: "↓ EXPORT ALL", importar: "+ IMPORT", tema: "THEME", idiomaInterfaz: "INTERFACE LANGUAGE",
    bienvenido: "WELCOME TO THE SYSTEM", bienvenidoSistema: "WELCOME TO THE SYSTEM", accederBunker: "ACCESS EXISTING VAULT",
    autenticacion: "AUTHENTICATION REQUIRED", ajustesTitulo: "SETTINGS", volverPanel: "← BACK TO PANEL",
    fraseRecuperacion: "RECOVERY PHRASE", recuperarBunker: "RECOVER VAULT",
    traducidosGuardados: "TRANSLATED & SAVED", buzones: "FOLDERS", archivosTitulo: "FILES",
    noArchivos: "No saved files", arrastra: "Drag documents here to encrypt them",
    buzonesTord: "FOLDERS", finder: "◫ FINDER", todos: "ALL",
    idiomaNames: { es: "Spanish", en: "English", fr: "French", ar: "Arabic", de: "German", ru: "Russian", zh: "Chinese" },
    modalEmailTitulo: "SET UP EMAIL",
    modalEmailDesc: "To read and send emails from Babel, connect your Gmail account.",
    modalEmailBtnConectar: "CONNECT WITH GMAIL",
    modalEmailAviso: "Your email connects securely through Google. Babel never sees or stores your password. Only authorize this on devices you trust.",
    modalEmailBtnPosponer: "Not now",
  },
  fr: {
    traducir: "TRADUIRE", archivos: "FICHIERS", p2p: "P2P", ajustes: "⚙ PARAMÈTRES", cerrarSesion: "DÉCONNEXION",
    borrarChat: "EFFACER CHAT", configuracion: "CONFIGURATION", borrarAlSalir: "EFFACER EN QUITTANT",
    borrarAlSalirDesc: "Efface le chat au retour au panneau", emailAuto: "EMAIL AUTO", proximamente: "Bientôt",
    diccionario: "DICTIONNAIRE", vocabularioActivo: "Vocabulaire actif", volver: "← RETOUR",
    verArchivo: "◫ VOIR FICHIER", eliminar: "✕ SUPPRIMER", compartir: "⇪ PARTAGER", unirPdfs: "⊕ FUSIONNER PDF",
    exportarTodo: "↓ TOUT EXPORTER", importar: "+ IMPORTER", tema: "THÈME", idiomaInterfaz: "LANGUE DE L'INTERFACE",
    bienvenido: "BIENVENUE DANS LE SYSTÈME", bienvenidoSistema: "BIENVENUE DANS LE SYSTÈME", accederBunker: "ACCÉDER AU COFFRE EXISTANT",
    autenticacion: "AUTHENTIFICATION REQUISE", ajustesTitulo: "PARAMÈTRES", volverPanel: "← RETOUR AU PANNEAU",
    fraseRecuperacion: "PHRASE DE RÉCUPÉRATION", recuperarBunker: "RÉCUPÉRER LE COFFRE",
    traducidosGuardados: "TRADUITS ET SAUVEGARDÉS", buzones: "DOSSIERS", archivosTitulo: "FICHIERS",
    noArchivos: "Aucun fichier sauvegardé", arrastra: "Faites glisser des documents ici pour les chiffrer",
    buzonesTord: "DOSSIERS", finder: "◫ FINDER", todos: "TOUS",
    idiomaNames: { es: "Espagnol", en: "Anglais", fr: "Français", ar: "Arabe", de: "Allemand", ru: "Russe", zh: "Chinois" },
    modalEmailTitulo: "CONFIGURER LE COURRIER",
    modalEmailDesc: "Pour lire et envoyer des courriels depuis Babel, connectez votre compte Gmail.",
    modalEmailBtnConectar: "CONNECTER AVEC GMAIL",
    modalEmailAviso: "Votre courrier se connecte de manière sécurisée via Google. Babel ne voit ni ne stocke jamais votre mot de passe. N'autorisez ceci que depuis des appareils de confiance.",
    modalEmailBtnPosponer: "Pas maintenant",
  },
  ar: {
    traducir: "ترجمة", archivos: "ملفات", p2p: "P2P", ajustes: "⚙ إعدادات", cerrarSesion: "تسجيل الخروج",
    borrarChat: "مسح المحادثة", configuracion: "الإعدادات", borrarAlSalir: "مسح عند الخروج",
    borrarAlSalirDesc: "يمسح المحادثة عند العودة", emailAuto: "بريد تلقائي", proximamente: "قريباً",
    diccionario: "القاموس", vocabularioActivo: "المفردات النشطة", volver: "→ رجوع",
    verArchivo: "◫ عرض الملف", eliminar: "✕ حذف", compartir: "⇪ مشاركة", unirPdfs: "⊕ دمج PDF",
    exportarTodo: "↓ تصدير الكل", importar: "+ استيراد", tema: "المظهر", idiomaInterfaz: "لغة الواجهة",
    bienvenido: "مرحباً بك في النظام", bienvenidoSistema: "مرحباً بك في النظام", accederBunker: "الدخول إلى الخزنة",
    autenticacion: "المصادقة مطلوبة", ajustesTitulo: "الإعدادات", volverPanel: "→ العودة إلى اللوحة",
    fraseRecuperacion: "عبارة الاسترداد", recuperarBunker: "استرداد الخزنة",
    traducidosGuardados: "مترجم ومحفوظ", buzones: "المجلدات", archivosTitulo: "الملفات",
    noArchivos: "لا توجد ملفات محفوظة", arrastra: "اسحب المستندات هنا لتشفيرها",
    buzonesTord: "المجلدات", finder: "◫ FINDER", todos: "الكل",
    idiomaNames: { es: "الإسبانية", en: "الإنجليزية", fr: "الفرنسية", ar: "العربية", de: "الألمانية", ru: "الروسية", zh: "الصينية" },
    modalEmailTitulo: "إعداد البريد الإلكتروني",
    modalEmailDesc: "لقراءة رسائلك وإرسالها من بابل، اربط حساب Gmail الخاص بك.",
    modalEmailBtnConectar: "ربط حساب Gmail",
    modalEmailAviso: "يتصل بريدك بشكل آمن عبر Google. لا يرى بابل ولا يخزن كلمة مرورك. لا تصرح إلا على الأجهزة التي تثق بها.",
    modalEmailBtnPosponer: "ليس الآن",
  },
};

function cambiarIdiomaUI(idioma: string): void {
  const t = TRADUCCIONES_UI[idioma] ?? TRADUCCIONES_UI["es"];
  const s = (v: string | Record<string, string> | undefined): string => (typeof v === "string" ? v : "");
  localStorage.setItem("babel-idioma-ui", idioma);
  const mapa: Record<string, string> = {
    "pantalla-texto-traducir": s(t.traducir), "pantalla-texto-archivos": s(t.archivos),
    "pantalla-texto-p2p": s(t.p2p), "pantalla-texto-ajustes": s(t.ajustes),
    "pantalla-texto-cerrar": s(t.cerrarSesion), "ui-borrar-chat": s(t.borrarChat),
    "ui-configuracion": s(t.configuracion), "ui-borrar-al-salir": s(t.borrarAlSalir),
    "ui-borrar-al-salir-desc": s(t.borrarAlSalirDesc), "ui-email-auto": s(t.emailAuto),
    "ui-proximamente": s(t.proximamente), "ui-diccionario": s(t.diccionario),
    "ui-vocabulario-activo": s(t.vocabularioActivo), "ui-volver-archivos": s(t.volver),
    "btn-ver-sel-g": s(t.verArchivo), "btn-compartir-sel-g": s(t.compartir), "btn-eliminar-sel-g": s(t.eliminar),
    "btn-unir-pdfs-g": s(t.unirPdfs),
    "ui-exportar-todo": s(t.exportarTodo), "ui-importar": s(t.importar), "ui-tema": s(t.tema),
    "ui-idioma-interfaz": s(t.idiomaInterfaz), "ui-bienvenido-sistema": s(t.bienvenidoSistema),
    "ui-acceder-bunker": s(t.accederBunker), "ui-autenticacion-requerida": s(t.autenticacion),
    "ui-ajustes-titulo": s(t.ajustesTitulo), "ui-volver-panel": s(t.volverPanel),
    "ui-frase-recuperacion": s(t.fraseRecuperacion), "ui-recuperar-bunker": s(t.recuperarBunker),
    "ui-traducidos-guardados": s(t.traducidosGuardados), "ui-buzones": s(t.buzones),
    "ui-finder": s(t.finder), "ui-archivos-titulo": s(t.archivosTitulo),
    "ui-no-archivos": s(t.noArchivos), "ui-arrastra": s(t.arrastra),
    "modal-email-titulo": s(t.modalEmailTitulo),
    "modal-email-desc": s(t.modalEmailDesc),
    "modal-email-btn-conectar": s(t.modalEmailBtnConectar),
    "modal-email-aviso": s(t.modalEmailAviso),
    "modal-email-btn-posponer": s(t.modalEmailBtnPosponer),
  };
  for (const [id, texto] of Object.entries(mapa)) {
    const el = document.getElementById(id);
    if (el) el.textContent = texto;
  }
  // Actualizar opciones de selectores de idioma con nombres en el idioma de la IU
  const nombres = (t.idiomaNames ?? {}) as Record<string, string>;
  const ordenOpciones = ["es", "en", "fr", "ar", "de", "ru", "zh"];
  for (const selId of ["selector-origen", "selector-destino"]) {
    const sel = document.getElementById(selId) as HTMLSelectElement | null;
    if (!sel) continue;
    const valorActual = sel.value;
    sel.innerHTML = ordenOpciones.map(cod => {
      const nombre = nombres[cod] ?? cod;
      return `<option value="${cod}">${nombre}</option>`;
    }).join("");
    sel.value = valorActual;
  }
  // Actualizar el elemento TODOS en los buzones
  document.querySelectorAll<HTMLElement>(".buzon-nombre").forEach(el => {
    if (el.textContent === "TODOS" || el.textContent === "ALL" || el.textContent === "TOUS" || el.textContent === "الكل") {
      el.textContent = s(t.todos) || "TODOS";
    }
  });
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

async function instalarActualizacion(): Promise<void> {
  try {
    await invoke("instalar_actualizacion");
  } catch (e) {
    console.error("Error al instalar actualización:", e);
  }
}
(window as any).instalarActualizacion = instalarActualizacion;
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

  // Modal autologin — activar
  function actualizarBadgeAutologin(activo: boolean) {
    const badge = document.getElementById("autologin-estado-badge");
    if (badge) badge.textContent = activo ? "ACTIVO" : "DESACTIVADO";
  }
  function cerrarAutologinModal(activo: boolean) {
    invoke("guardar_preferencia_autologin", { activo }).catch(() => {});
    document.getElementById("modal-autologin-config")?.classList.add("hidden");
    actualizarBadgeAutologin(activo);
  }
  document.getElementById("autologin-btn-activar")?.addEventListener("click", () => cerrarAutologinModal(true));
  document.getElementById("autologin-btn-no")?.addEventListener("click", () => cerrarAutologinModal(false));
  document.getElementById("autologin-btn-no-alt")?.addEventListener("click", () => cerrarAutologinModal(false));

  // Listener seguro para el buscador de fechas del historial (backup del onchange inline)
  document.getElementById("registro-buscar-fecha")?.addEventListener("change", (e) => {
    irAFechaRegistro((e.target as HTMLInputElement).value);
  });

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
  document.getElementById("input-contacto-compartir")?.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key === "Enter") { e.preventDefault(); confirmarCompartir(); }
    if (e.key === "Escape") cerrarModalCompartir();
  });

  document.addEventListener("keydown", (e: KeyboardEvent) => {
    if (e.key !== "Escape") return;
    const modales = [
      "modal-visor", "modal-paralelo", "modal-frase-app",
      "modal-renombrar", "modal-solicitud-p2p", "modal-renombrar-archivo",
      "modal-sinc",
      "modal-compartir-onboarding", "modal-menu-compartir", "modal-compartir",
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

// ═══════════════════════════════════════════════════════════════════════════
// SINCRONIZACIÓN DE DISPOSITIVOS
// ═══════════════════════════════════════════════════════════════════════════

interface DispositivoPublico { id: string; nombre: string; ts: number; ip_ultima: string; }
interface SolicitudSinc { nombre: string; ip: string; tiene_b2: boolean; }
interface ResultadoEmparejamiento { emparejado: boolean; nombre: string; b2_enviado: boolean; b2_conflicto: boolean; }

let _sincPollInterval: number | null = null;
let _sincDecisionTomada = false; // evita re-mostrar modal tras aceptar/rechazar

function abrirSincronizacion(): void {
  document.getElementById("modal-sinc")?.classList.remove("hidden");
  mostrarFaseSinc("busqueda");
  invoke<string>("iniciar_sinc_servidor").catch(() => {});
  cargarListaEmparejados();
  buscarDispositivosSinc();
  iniciarPollSolicitudSinc();
}

function cerrarSincronizacion(): void {
  document.getElementById("modal-sinc")?.classList.add("hidden");
  // No detenemos el poll de solicitudes — puede haber una solicitud entrante pendiente
}

function mostrarFaseSinc(fase: "busqueda" | "espera" | "resultado"): void {
  const fases: Record<string, string> = {
    busqueda: "sinc-fase-busqueda",
    espera:   "sinc-fase-espera",
    resultado: "sinc-fase-resultado",
  };
  for (const [key, id] of Object.entries(fases)) {
    const el = document.getElementById(id);
    if (el) el.style.display = key === fase ? "" : "none";
  }
}

async function buscarDispositivosSinc(): Promise<void> {
  const lista = document.getElementById("sinc-lista-peers-modal");
  const msg = document.getElementById("sinc-msg-buscando");
  if (!lista) return;
  lista.innerHTML = "";
  if (msg) msg.textContent = "Buscando dispositivos Babel en la red local...";
  try {
    const peers = await invoke<Array<{ip: string; nombre: string; puerto: number}>>("buscar_dispositivos_sinc");
    if (msg) msg.textContent = peers.length
      ? `${peers.length} dispositivo(s) encontrado(s)`
      : "No se encontró ningún Babel en la red local.";
    for (const p of peers) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.style.cssText = "width:100%;padding:12px 16px;background:rgba(201,168,76,0.05);" +
        "border:1px solid rgba(201,168,76,0.3);color:var(--dorado);cursor:pointer;" +
        "font-family:'Times New Roman',Times,serif;font-size:0.7rem;letter-spacing:2px;" +
        "text-align:left;display:flex;justify-content:space-between;align-items:center;";
      btn.innerHTML = `<span>${escapeHTML(p.nombre)}</span>` +
        `<span style="font-size:0.55rem;opacity:0.5;letter-spacing:1px;">${escapeHTML(p.ip)}</span>`;
      btn.addEventListener("click", () => seleccionarDispSinc(p.ip, p.nombre));
      lista.appendChild(btn);
    }
  } catch (e) {
    if (msg) msg.textContent = "Error buscando dispositivos: " + String(e);
  }
}

async function seleccionarDispSinc(ip: string, nombre: string): Promise<void> {
  const nomEl = document.getElementById("sinc-nombre-destino");
  if (nomEl) nomEl.textContent = nombre;
  mostrarFaseSinc("espera");
  try {
    const res = await invoke<ResultadoEmparejamiento>("solicitar_emparejamiento_sinc", { ip });
    if (res.emparejado) {
      mostrarResultadoSinc(true, res.nombre, undefined, res.b2_enviado, res.b2_conflicto);
      cargarListaEmparejados();
    } else {
      mostrarResultadoSinc(false, "");
    }
  } catch (e) {
    mostrarResultadoSinc(false, "", String(e));
  }
}

function mostrarResultadoSinc(ok: boolean, nombre: string, error?: string, b2Enviado?: boolean, b2Conflicto?: boolean): void {
  mostrarFaseSinc("resultado");
  const icono = document.getElementById("sinc-resultado-icono");
  const texto = document.getElementById("sinc-resultado-texto");
  const sub   = document.getElementById("sinc-resultado-sub");
  if (ok) {
    if (icono) icono.textContent = "◈";
    if (texto) texto.textContent = `EMPAREJADO CON ${nombre.toUpperCase()}`;
    let subTexto = "La clave compartida ha sido guardada de forma segura.";
    if (b2Conflicto) {
      subTexto += " — El otro dispositivo ya tiene credenciales de buzón distintas; no se sobreescribieron.";
    } else if (b2Enviado) {
      subTexto += " — Credenciales de buzón compartidas con el dispositivo remoto.";
    }
    if (sub) sub.textContent = subTexto;
    const toastExtra = b2Conflicto ? " (conflicto de credenciales B2)" : b2Enviado ? " + acceso al buzón compartido" : "";
    mostrarToast(`Emparejado con ${nombre}${toastExtra}`, false);
  } else {
    if (icono) { icono.textContent = "✕"; icono.style.color = "rgba(255,80,80,0.7)"; }
    if (texto) { texto.textContent = "EMPAREJAMIENTO RECHAZADO"; texto.style.color = "rgba(255,80,80,0.7)"; }
    if (sub) sub.textContent = error || "El otro dispositivo rechazó la solicitud o no respondió.";
  }
}

async function aceptarSinc(): Promise<void> {
  _sincDecisionTomada = true;
  document.getElementById("modal-solicitud-sinc")?.classList.add("hidden");
  try {
    await invoke("aceptar_emparejamiento_sinc");
    cargarListaEmparejados();
    mostrarToast("Emparejamiento aceptado — clave guardada.", false);
  } catch (e) {
    mostrarToast("Error al aceptar: " + String(e), true);
  }
}

async function rechazarSinc(): Promise<void> {
  _sincDecisionTomada = true;
  document.getElementById("modal-solicitud-sinc")?.classList.add("hidden");
  try {
    await invoke("rechazar_emparejamiento_sinc");
  } catch (_) {}
}

interface ResultadoConexionDirecta {
  ok: boolean;
  via_buzon: boolean;
  ip_publica_remota: string;
  latencia_ms: number;
  error: string;
}

interface ConteoB2 {
  id_par: string;
  nombre: string;
  n: number;
}

interface ResultadoAplicarB2 {
  key: string;
  tipo: string;
  contenido: string;
  nombre_origen: string;
  timestamp: number;
}

async function probarConexionDispositivo(id: string, btn: HTMLButtonElement): Promise<void> {
  const textoOriginal = btn.textContent ?? "PROBAR";
  btn.textContent = "···";
  btn.disabled = true;
  try {
    const res = await invoke<ResultadoConexionDirecta>("probar_conexion_dispositivo", { id });
    if (res.ok) {
      btn.textContent = `✓ ${res.latencia_ms}ms`;
      btn.style.color = "rgba(100,200,100,0.9)";
      btn.style.borderColor = "rgba(100,200,100,0.4)";
      mostrarToast(`Conexión directa OK — IP pública: ${res.ip_publica_remota} (${res.latencia_ms} ms)`, false);
    } else if (res.via_buzon) {
      btn.textContent = "✉ buzón";
      btn.style.color = "rgba(201,168,76,0.9)";
      btn.style.borderColor = "rgba(201,168,76,0.4)";
      mostrarToast(`Dispositivo offline — ${escapeHTML(res.error)}`, false);
      cargarListaEmparejados(); // refresca badges de pendientes
    } else {
      btn.textContent = "✗";
      btn.style.color = "rgba(255,80,80,0.7)";
      btn.style.borderColor = "rgba(255,80,80,0.3)";
      mostrarToast(res.error || "Conexión directa no disponible.", true);
    }
  } catch (e) {
    btn.textContent = "✗";
    btn.style.color = "rgba(255,80,80,0.7)";
    btn.style.borderColor = "rgba(255,80,80,0.3)";
    mostrarToast("Error al probar conexión: " + String(e), true);
  } finally {
    setTimeout(() => {
      btn.textContent = textoOriginal;
      btn.style.color = "";
      btn.style.borderColor = "";
      btn.disabled = false;
    }, 5000);
  }
}

async function desemparejarDispositivo(id: string): Promise<void> {
  try {
    await invoke("desemparejar_dispositivo", { id });
    cargarListaEmparejados();
    mostrarToast("Dispositivo desemparejado.", false);
  } catch (e) {
    mostrarToast("Error: " + String(e), true);
  }
}

async function cargarListaEmparejados(): Promise<void> {
  const contenedor = document.getElementById("sinc-lista-emparejados");
  if (!contenedor) return;
  try {
    const lista = await invoke<DispositivoPublico[]>("listar_dispositivos_emparejados");
    if (!lista || lista.length === 0) {
      contenedor.innerHTML =
        `<div style="font-family:'Times New Roman',Times,serif;font-size:0.58rem;` +
        `letter-spacing:1px;color:var(--texto-secundario);opacity:0.45;text-align:center;padding:4px 0;">` +
        `Sin dispositivos emparejados</div>`;
      return;
    }
    // Obtener conteos de buzón B2 para todos los pares (falla silenciosa si B2 no configurado)
    let conteos: ConteoB2[] = [];
    try { conteos = await invoke<ConteoB2[]>("verificar_buzones_todos"); } catch (_) {}

    contenedor.innerHTML = "";
    for (const d of lista) {
      const fecha = new Date(d.ts * 1000).toLocaleDateString("es-ES", { day: "2-digit", month: "short", year: "numeric" });
      const conteo = conteos.find(c => c.id_par === d.id);
      const nPend = conteo?.n ?? 0;
      const buzonLabel = nPend > 0 ? `BUZÓN (${nPend})` : "BUZÓN";
      const buzonColor = nPend > 0 ? "rgba(201,168,76,0.9)" : "rgba(201,168,76,0.35)";
      const buzonBorder = nPend > 0 ? "rgba(201,168,76,0.5)" : "rgba(201,168,76,0.15)";

      const fila = document.createElement("div");
      fila.style.cssText = "display:flex;align-items:center;justify-content:space-between;" +
        "padding:10px 12px;border:1px solid rgba(201,168,76,0.15);";
      fila.innerHTML =
        `<div style="flex:1;min-width:0;">` +
        `<div style="font-family:'Times New Roman',Times,serif;font-size:0.68rem;` +
        `color:var(--dorado);letter-spacing:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">` +
        `${escapeHTML(d.nombre)}</div>` +
        `<div style="font-family:'Times New Roman',Times,serif;font-size:0.55rem;` +
        `color:var(--texto-secundario);opacity:0.5;letter-spacing:0.5px;margin-top:2px;">` +
        `${escapeHTML(d.ip_ultima)} · ${fecha}</div>` +
        `</div>` +
        `<div style="display:flex;gap:6px;flex-shrink:0;margin-left:12px;">` +
        `<button type="button" data-action="probar-conexion-dispositivo" data-id="${escapeHTML(d.id)}"` +
        ` style="background:transparent;border:1px solid rgba(197,160,89,0.3);` +
        `color:var(--dorado);padding:4px 10px;cursor:pointer;font-family:'Times New Roman',Times,serif;` +
        `font-size:0.52rem;letter-spacing:1.5px;">PROBAR</button>` +
        `<button type="button" data-action="aplicar-buzon-b2" data-id="${escapeHTML(d.id)}"` +
        ` style="background:transparent;border:1px solid ${buzonBorder};` +
        `color:${buzonColor};padding:4px 10px;cursor:pointer;font-family:'Times New Roman',Times,serif;` +
        `font-size:0.52rem;letter-spacing:1.5px;">${buzonLabel}</button>` +
        `<button type="button" data-action="desemparejar-dispositivo" data-id="${escapeHTML(d.id)}"` +
        ` style="background:transparent;border:1px solid rgba(255,80,80,0.3);` +
        `color:rgba(255,80,80,0.7);padding:4px 10px;cursor:pointer;font-family:'Times New Roman',Times,serif;` +
        `font-size:0.52rem;letter-spacing:1.5px;">QUITAR</button>` +
        `</div>`;
      contenedor.appendChild(fila);
      bindOnclicks(fila);
    }

    // Auto-aplicar pendientes al abrir Ajustes (spec: verificar y aplicar automáticamente al arrancar)
    verificarYAplicarBuzones(lista.map(d => d.id));
  } catch (_) {}
}

// Guard para evitar que verificarYAplicarBuzones → cargarListaEmparejados → verificarYAplicarBuzones
// cause un bucle infinito cuando hay ítems pendientes.
let _aplicandoBuzon = false;

async function verificarYAplicarBuzones(ids: string[]): Promise<void> {
  if (_aplicandoBuzon) return;
  _aplicandoBuzon = true;
  let huboItems = false;
  try {
    for (const id of ids) {
      try {
        const resultados = await invoke<ResultadoAplicarB2[]>("aplicar_pendientes_buzon", { id });
        for (const r of resultados) {
          const fecha = new Date(r.timestamp * 1000).toLocaleString("es-ES", {
            day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
          });
          mostrarToast(
            `Buzón: mensaje de ${escapeHTML(r.nombre_origen)} recibido el ${fecha}`,
            false
          );
          huboItems = true;
        }
      } catch (_) { /* B2 no configurado o sin red, ignorar */ }
    }
  } finally {
    _aplicandoBuzon = false;
  }
  // Refrescar badges solo tras liberar el guard (la segunda llamada a
  // cargarListaEmparejados vuelve a llamar verificarYAplicarBuzones pero el
  // guard la hace salir inmediatamente, rompiendo el bucle).
  if (huboItems) cargarListaEmparejados();
}

async function aplicarPendientesB2(id: string, btn: HTMLButtonElement): Promise<void> {
  const textoOriginal = btn.textContent ?? "BUZÓN";
  btn.textContent = "···";
  btn.disabled = true;
  try {
    const resultados = await invoke<ResultadoAplicarB2[]>("aplicar_pendientes_buzon", { id });
    if (resultados.length === 0) {
      mostrarToast("No hay mensajes pendientes en el buzón para este dispositivo.", false);
    } else {
      for (const r of resultados) {
        const fecha = new Date(r.timestamp * 1000).toLocaleString("es-ES", {
          day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit"
        });
        mostrarToast(
          `Buzón: ${escapeHTML(r.nombre_origen)} — ${escapeHTML(r.tipo)} (${fecha})`,
          false
        );
      }
      cargarListaEmparejados(); // refrescar badges
    }
  } catch (e) {
    mostrarToast("Error al acceder al buzón B2: " + escapeHTML(String(e)), true);
  } finally {
    setTimeout(() => {
      btn.textContent = textoOriginal;
      btn.disabled = false;
    }, 3000);
  }
}

function iniciarPollSolicitudSinc(): void {
  if (_sincPollInterval !== null) return;
  _sincPollInterval = window.setInterval(async () => {
    try {
      const sol = await invoke<SolicitudSinc | null>("obtener_solicitud_sinc");
      if (sol && !_sincDecisionTomada) {
        const modal = document.getElementById("modal-solicitud-sinc");
        if (modal && modal.classList.contains("hidden")) {
          _sincDecisionTomada = false;
          const nomEl  = document.getElementById("sinc-sol-nombre");
          const ipEl   = document.getElementById("sinc-sol-ip");
          const b2El   = document.getElementById("sinc-sol-b2-aviso");
          if (nomEl) nomEl.textContent = sol.nombre;
          if (ipEl)  ipEl.textContent  = sol.ip;
          if (b2El) b2El.style.display = sol.tiene_b2 ? "" : "none";
          modal.classList.remove("hidden");
        }
      } else if (!sol) {
        _sincDecisionTomada = false; // solicitud limpiada por Rust → resetear flag
      }
    } catch (_) {}
  }, 2000);
}

function detenerPollSolicitudSinc(): void {
  if (_sincPollInterval !== null) {
    clearInterval(_sincPollInterval);
    _sincPollInterval = null;
  }
}

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

// ──────────────────────────────────────────────────────────────────────────────
// TESTS MODAL CONFIGURAR CORREO
// Ejecutar desde la consola del browser: window.__babelTest.modalEmail()
// ──────────────────────────────────────────────────────────────────────────────
(window as any).__babelTest = {
  modalEmail(): void {
    let ok = 0;
    let fail = 0;
    const assert = (cond: boolean, msg: string) => {
      if (cond) { console.log(`  ✓ ${msg}`); ok++; }
      else       { console.error(`  ✗ ${msg}`); fail++; }
    };

    console.group("Tests: modal configurar correo");

    // T1: sin OAuth y sin haber cerrado → modal visible
    _oauthGmailConectado = false;
    _modalEmailVistoEnSesion = false;
    mostrarModalConfigurarEmail();
    assert(
      !document.getElementById("modal-configurar-email")?.classList.contains("hidden"),
      "T1: aparece cuando no hay cuenta conectada"
    );

    // T2: cerrarlo lo oculta y activa bandera de sesión
    cerrarModalConfigurarEmail();
    assert(
      document.getElementById("modal-configurar-email")?.classList.contains("hidden") ?? false,
      "T2: se oculta al cerrarlo"
    );
    assert(_modalEmailVistoEnSesion as boolean, "T2: bandera de sesión queda activada");

    // T3: después de cerrarlo en la sesión no reaparece
    mostrarModalConfigurarEmail();
    assert(
      document.getElementById("modal-configurar-email")?.classList.contains("hidden") === true,
      "T3: no reaparece si ya fue cerrado en la sesión"
    );

    // T4: con OAuth conectado nunca aparece (aunque se resetee la bandera)
    _oauthGmailConectado = true;
    _modalEmailVistoEnSesion = false;
    mostrarModalConfigurarEmail();
    assert(
      document.getElementById("modal-configurar-email")?.classList.contains("hidden") === true,
      "T4: no aparece si ya hay OAuth Gmail activo"
    );

    // Restaurar estado real
    _oauthGmailConectado = false;
    _modalEmailVistoEnSesion = false;
    document.getElementById("modal-configurar-email")?.classList.add("hidden");

    console.groupEnd();
    console.log(`Resultado: ${ok}/${ok + fail} tests pasaron`);
  },
};
