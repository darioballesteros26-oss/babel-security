import "./styles.css";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { openPath } from "@tauri-apps/plugin-opener";
import DOMPurify from "dompurify";

type Pantalla = "carga" | "decision" | "configuracion" | "login" | "principal" | "traduccion" | "archivos-guardados" | "comunicacion" | "frase" | "recuperacion" | "terminos" | "nombre";
// VARIABLES DE SESIÓN — nunca van a window, se zeroizan al cerrar
// ============================================================
let _sesionPass = "";
let _sesionMaestra = "";
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
let buzonParentPendiente: string | null = null;
let buzonParentPendienteG: string | null = null;

// Tipo compartido para nodos de buzón con árbol jerárquico
interface BuzonNodo { id: string; nombre: string; parent: string | null; }

// IDs de buzones colapsados (no muestran sus hijos)
const buzonesColapsados = new Set<string>();

function toggleColapso(id: string, sistema: string): void {
  if (buzonesColapsados.has(id)) {
    buzonesColapsados.delete(id);
  } else {
    buzonesColapsados.add(id);
  }
  if (sistema === "trad") {
    cargarBuzones();
  } else {
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

    const drop = sistema === "trad"
      ? `ondragover="allowDrop(event)" ondragleave="dragLeave(event)" ondrop="soltarEnBuzon(event,'${n.id}')"`
      : "";
    const onSel = sistema === "trad"
      ? `seleccionarBuzon('${n.id}')`
      : `seleccionarBuzonGuardados('${n.id}')`;
    const onMas = sistema === "trad"
      ? `event.stopPropagation();mostrarInputBuzon('${n.id}')`
      : `event.stopPropagation();mostrarInputBuzonGuardado('${n.id}')`;
    const onRen = sistema === "trad"
      ? `event.stopPropagation();iniciarRenombrado('${n.id}','${escapeHTML(n.nombre).replace(/'/g, "&#039;")}')`
      : `event.stopPropagation();iniciarRenombradoGuardado('${n.id}','${escapeHTML(n.nombre).replace(/'/g, "&#039;")}')`;
    const onDel = sistema === "trad"
      ? `event.stopPropagation();borrarBuzon('${n.id}')`
      : `event.stopPropagation();borrarBuzonGuardado('${n.id}')`;

    const toggleIcon = tieneHijos
      ? `<span onclick="event.stopPropagation();toggleColapso('${n.id}','${sistema}')"
           style="cursor:pointer;font-size:0.6rem;opacity:0.6;padding:0 3px;transition:transform 0.15s;"
           title="${colapsado ? "Expandir" : "Colapsar"}">${colapsado ? "▶" : "▼"}</span>`
      : `<span style="display:inline-block;width:14px;"></span>`;

    const hijos = colapsado ? "" : renderArbolBuzones(nodos, n.id, profundidad + 1, activo, sistema);

    return `
      <div class="buzon-item ${esActivo ? "activo" : ""}" onclick="${onSel}" ${drop}
        style="padding-left:${indent}px;border:1px solid transparent;border-radius:3px;transition:background 0.2s,border-color 0.2s;">
        ${toggleIcon}
        <span class="buzon-icono" onclick="${onRen}" style="cursor:pointer;" title="Renombrar">✎</span>
        <span class="buzon-nombre" style="flex:1">${escapeHTML(n.nombre).toUpperCase()}</span>
        <span onclick="${onMas}" style="color:var(--texto-secundario);cursor:pointer;font-size:0.85rem;opacity:0.5;padding:0 4px;" title="Nuevo subbuzón">+</span>
        <button type="button" onclick="${onDel}" style="background:transparent;border:none;color:var(--texto-secundario);cursor:pointer;font-size:0.7rem;opacity:0.4;padding:0 2px;" title="Eliminar">✕</button>
      </div>${hijos}`;
  }).join("");
}
// ============================================================
// UTILIDADES UI
// ============================================================

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

// ============================================================
// CHAT — SISTEMA DE MENSAJES
// ============================================================

let ultimaRutaResultado: string = "";

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
      <span class="burbuja-hora">${escapeHTML(pie ?? "BABEL")}</span>
    </div>`;
  contenedor.appendChild(burbuja);
  scrollAlFinal();
}

function añadirResultadoArchivo(nombreResultado: string, ruta: string): void {
  const contenedor = document.getElementById("chat-mensajes");
  if (!contenedor) return;

  // Quitar prefijo de usuario si existe (usuario_archivo.babel → archivo.babel)
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
   <button type="button" class="btn-descargar btn-ver-resultado" title="Ver documento">
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
    <circle cx="12" cy="12" r="3"/>
  </svg>
</button>

      </div>
      <span class="burbuja-hora">BABEL · Este documento no ha salido de tu ordenador</span>
    </div>`;
  const btnVer = burbuja.querySelector(".btn-ver-resultado") as HTMLButtonElement;
  btnVer?.addEventListener("click", () => verArchivo(ruta));
  contenedor.appendChild(burbuja);
}

function scrollAlFinal(): void {
  const c = document.getElementById("chat-mensajes");
  if (c) c.scrollTop = c.scrollHeight;

}


function mostrarProcesando(visible: boolean): void {
  const el = document.getElementById("chat-procesando");
  if (!el) return;
  visible ? el.classList.remove("hidden") : el.classList.add("hidden");
  if (visible) scrollAlFinal();
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

  // Eliminar todos los mensajes dinámicos — deja solo la bienvenida
  while (contenedor.children.length > 1) {
    contenedor.removeChild(contenedor.lastChild!);
  }

  ultimaRutaResultado = "";

  // Zeroize del input
  const input = document.getElementById("chat-input") as HTMLTextAreaElement;
  if (input) {
    input.value = "0".repeat(input.value.length);
    input.value = "";
    input.style.height = "auto";
  }
}


// ============================================================
// ARRANQUE
// ============================================================

window.addEventListener("DOMContentLoaded", async () => {
  mostrarPantalla("carga");

  // Evento Rust: servidor USB listo → toast
  listen("servidor-usb-listo", () => {
    mostrarToast("Traductor listo", false);
  }).catch(() => {});

  // Badge NLLB: poll /ping cada 2s hasta que responda
  const badge = document.getElementById("nllb-badge");
  const checkNllb = setInterval(async () => {
    try {
      const res = await fetch("http://127.0.0.1:5002/ping");
      if (res.ok && badge) {
        badge.style.background = "#22c55e";
        badge.style.opacity = "1";
        badge.title = "NLLB activo";
        clearInterval(checkNllb);
      }
    } catch { }
  }, 2000);


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

// ============================================================
// CREAR BÚNKER
// ============================================================

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

// ============================================================
// LOGIN
// ============================================================

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
      _sesionPass = passUsuario;
      _sesionMaestra = llaveMaestra;
      limpiarCamposSensibles();

      const nombreGuardado = localStorage.getItem("babel-nombre-display");
      const nombre = nombreGuardado ?? "";
      _sesionUsuario = nombre;
      const bienvenida = document.getElementById("bienvenida-usuario");
      if (bienvenida) bienvenida.textContent = nombre ? `Bienvenido, ${nombre}` : "Bienvenido";

      activarTimerInactividad();
      invoke<boolean>("tiene_config_email").then(ok => { _smtpConfigurado = ok; }).catch(() => { });

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

// ============================================================
// TRADUCCIÓN — VÍA SELECTOR DE ARCHIVO
// ============================================================

function seleccionarArchivo(): void {
  document.getElementById("input-archivo")?.click();
}

function manejarSeleccion(event: Event): void {
  const input = event.target as HTMLInputElement;
  const archivo = input.files?.[0];
  if (archivo) procesarArchivo(archivo);
}

async function procesarArchivo(archivo: File): Promise<void> {
  const pesoKB = (archivo.size / 1024).toFixed(0);
  const ext = archivo.name.split(".").pop()?.toUpperCase() ?? "FILE";
  añadirMensajeArchivo(archivo.name, `${pesoKB} KB · ${ext}`);
  mostrarProcesando(true);

  try {
    const rutaResultado = await invoke<string>("traducir_documento", {
      nombreArchivo: archivo.name,
      contenido: Array.from(new Uint8Array(await archivo.arrayBuffer()))
    });
    mostrarProcesando(false);
    ultimaRutaResultado = rutaResultado;
    const partes = rutaResultado.replace(/\\/g, "/").split("/");
    añadirResultadoArchivo(partes[partes.length - 1], rutaResultado);
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error procesando archivo: " + String(error), "BABEL · error");
  }
}

// ============================================================
// TRADUCCIÓN — VÍA DRAG & DROP NATIVO
// ============================================================

async function procesarRuta(ruta: string): Promise<void> {
  const partes = ruta.replace(/\\/g, "/").split("/");
  const nombreArchivo = partes[partes.length - 1];
  const ext = nombreArchivo.split(".").pop()?.toUpperCase() ?? "FILE";

  añadirMensajeArchivo(nombreArchivo, `Arrastrado · ${ext}`);
  mostrarProcesando(true);

  try {
    const rutaResultado = await invoke<string>("traducir_documento_ruta", { ruta, nombreArchivo });
    mostrarProcesando(false);
    ultimaRutaResultado = rutaResultado;
    const partesRes = rutaResultado.replace(/\\/g, "/").split("/");
    añadirResultadoArchivo(partesRes[partesRes.length - 1], rutaResultado);
    scrollAlFinal();
  } catch (error) {
    mostrarProcesando(false);
    añadirMensajeBabel("Error procesando archivo: " + String(error), "BABEL · error");
  }
}

// ============================================================
// DESCARGA
// ============================================================

async function descargarArchivo(ruta: string, nombre: string): Promise<void> {
  try {
    const bytes = await invoke<number[]>("leer_resultado", { ruta });
    const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.download = nombre;
    a.href = url;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    añadirMensajeBabel("Error al descargar: " + String(error), "BABEL · error");
  }
}

async function descargarResultado(): Promise<void> {
  if (!ultimaRutaResultado) return;
  const partes = ultimaRutaResultado.replace(/\\/g, "/").split("/");
  await descargarArchivo(ultimaRutaResultado, partes[partes.length - 1]);
}

// ============================================================
// SESIÓN Y NAVEGACIÓN
// ============================================================

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

// ============================================================
// SIDEBAR — SELECTOR DE IDIOMA DE TRADUCCIÓN
// Sincroniza el selector del sidebar con el del header
// ============================================================

async function cerrarSesion(): Promise<void> {
  limpiarCamposSensibles();
  borrarChat();
  // Zeroizar credenciales de sesión
  _sesionPass = "0".repeat(_sesionPass.length); _sesionPass = "";
  _sesionMaestra = "0".repeat(_sesionMaestra.length); _sesionMaestra = "";
  _sesionUsuario = "0".repeat(_sesionUsuario.length); _sesionUsuario = "";
  desactivarTimerInactividad();
  await invoke("cerrar_sesion_rust");
  limpiarCamposSensibles();
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



async function cambiarIdiomaDesdeSelectores(): Promise<void> {
  const origen = (document.getElementById("selector-origen") as HTMLSelectElement)?.value ?? "es";
  const destino = (document.getElementById("selector-destino") as HTMLSelectElement)?.value ?? "en";
  if (origen === destino) {
    mostrarToast("Origen y destino son el mismo idioma", true);
    return;
  }
  await cambiarIdioma(`${origen}_${destino}`);
  guardarAjustesTraduccion().catch(() => {});
}

async function cambiarIdioma(idioma: string): Promise<void> {
  await invoke("cambiar_idioma", { idioma });
}

// ============================================================
// ARCHIVOS — BUZONES Y LISTADO
// ============================================================

// Variable global — buzón activo
let buzonActivo: string = "todos";
let buzonActivoGuardados: string = "todos";
let _smtpConfigurado: boolean = false;
// Tipo que refleja el struct Rust MetadatosArchivo
interface MetadatosArchivo {
  nombre: string;
  ruta: string;
  tamaño: number;
  fecha: string;
  idioma: string;
  buzon: string;
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
      return;
    }

    const limpiarNombre = (n: string) =>
      n.replace(/\.babel$/, "").replace(/__orig/g, "").replace(/_\d{8,}$/, "").trim();

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

      if (g.trad && g.orig) {
        const kb = (g.trad.tamaño / 1024).toFixed(0);
        const idioma = g.trad.idioma.replace("_", "→").toUpperCase();
        return `
<div class="archivo-card" data-ruta="${escapeHTML(g.trad.ruta)}" data-ruta-orig="${escapeHTML(g.orig.ruta)}" data-base="${escapeHTML(base)}" data-guardado="false" draggable="true">
  <div class="archivo-card-header">
    <input type="checkbox" class="archivo-checkbox-g" data-action="seleccionar" style="accent-color:var(--dorado);cursor:pointer;flex-shrink:0;width:16px;height:16px;">
    <div class="archivo-card-info">
      <div class="archivo-card-nombre" style="display:flex;align-items:center;gap:8px;">${nombre}
        <button type="button" data-action="renombrar" style="background:none;border:none;color:var(--dorado);cursor:pointer;font-size:0.85rem;padding:0;opacity:0.7;">✎</button>
      </div>
      <div class="archivo-card-meta">${kb} KB · <span style="color:var(--dorado);">${escapeHTML(idioma)} · TRAD</span> · AES-256</div>
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
<div class="archivo-card" data-ruta="${escapeHTML(a.ruta)}" data-base="${escapeHTML(base)}" data-guardado="true" draggable="true">
  <div class="archivo-card-header">
    <input type="checkbox" class="archivo-checkbox-g" data-action="seleccionar" style="accent-color:var(--dorado);cursor:pointer;flex-shrink:0;width:16px;height:16px;">
    <div class="archivo-card-info">
      <div class="archivo-card-nombre" style="display:flex;align-items:center;gap:8px;">${nombre}
        <button type="button" data-action="renombrar" style="background:none;border:none;color:var(--dorado);cursor:pointer;font-size:0.85rem;padding:0;opacity:0.7;">✎</button>
      </div>
      <div class="archivo-card-meta">${kb} KB · GUARDADO · AES-256</div>
    </div>
  </div>
  <div class="archivo-card-botones">
    <button type="button" class="btn-archivo btn-archivo-ver" data-action="ver">VER</button>
    <button type="button" class="btn-archivo btn-archivo-exportar" data-action="exportar">EXPORTAR</button>
    <button type="button" class="btn-archivo" data-action="mover" style="opacity:0.7;">MOVER</button>
    <button type="button" class="btn-archivo" data-action="enviar" style="opacity:0.7;">✉</button>
  </div>
</div>`;
    }).join("");

    lista.onclick = (e: MouseEvent) => {
      const btn = (e.target as HTMLElement).closest("[data-action]") as HTMLElement | null;
      if (!btn) return;
      const accion = btn.dataset.action;
      if (accion === "seleccionar") { actualizarSeleccionGuardados(); return; }
      const card = btn.closest(".archivo-card") as HTMLElement | null;
      if (!card) return;
      const ruta = card.dataset.ruta ?? "";
      const rutaOrig = card.dataset.rutaOrig ?? "";
      const base2 = card.dataset.base ?? "";
      switch (accion) {
        case "ver-comparacion": verComparacionRutas(rutaOrig, ruta); break;
        case "ver": verArchivo(ruta); break;
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

// Filtra la lista de archivos guardados por texto de búsqueda
function filtrarArchivosGuardados(texto: string): void {
  const cards = document.querySelectorAll<HTMLElement>("#lista-guardados .archivo-card");
  const q = texto.toLowerCase();
  cards.forEach(card => {
    const nombre = card.querySelector(".archivo-card-nombre")?.textContent?.toLowerCase() ?? "";
    card.style.display = nombre.includes(q) ? "" : "none";
  });
}

// Activa un buzón guardado y recarga su contenido
function seleccionarBuzonGuardados(id: string): void {
  buzonActivoGuardados = id;
  localStorage.setItem("babel-buzon-activo-g", id);
  cargarBuzonesGuardados();
  cargarArchivosGuardados();
}

function abrirImportarGuardado(): void {
  document.getElementById("input-archivo-guardado")?.click();
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
  if (checkboxes.length === 0) return;

  const rutas: string[] = [];
  checkboxes.forEach(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement;
    const ruta = card?.dataset.ruta;
    const rutaOrig = card?.dataset.rutaOrig;
    if (ruta) rutas.push(ruta);
    if (rutaOrig) rutas.push(rutaOrig);
  });

  let errores = 0;
  for (const ruta of rutas) {
    try {
      await invoke("eliminar_archivo", { ruta });
    } catch {
      errores++;
    }
  }

  document.getElementById("btn-ver-sel-g")?.classList.add("hidden");
  document.getElementById("btn-eliminar-sel-g")?.classList.add("hidden");
  mostrarToast(errores === 0 ? `✓ Destruido de forma segura — irrecuperable` : `${errores} errores al eliminar`, errores > 0);
  await cargarArchivosGuardados();
}


let dropZoneInicializada = false;

async function iniciarDropZone(): Promise<void> {
  if (dropZoneInicializada) return;

  const textarea = document.getElementById("chat-input") as HTMLTextAreaElement;
  if (textarea) {
    textarea.addEventListener("input", () => {
      textarea.style.height = "auto";
      textarea.style.height = textarea.scrollHeight + "px";
    });
  }

  await getCurrentWindow().onDragDropEvent(async (event) => {
    // Detectar qué pantalla está activa
    const enTraduccion = !document.getElementById("pantalla-traduccion")?.classList.contains("hidden");
    const enGuardados = !document.getElementById("pantalla-archivos-guardados")?.classList.contains("hidden");

    if (!enTraduccion && !enGuardados) return;

    const barra = document.getElementById("chat-input-barra");
    const zona = document.getElementById("drop-zone-guardados");

    if (event.payload.type === "over") {
      if (enTraduccion) barra?.classList.add("drag-activo");
      if (enGuardados && zona) {
        zona.style.borderColor = "var(--dorado)";
        zona.style.background = "rgba(197,160,89,0.05)";
      }
    } else if (event.payload.type === "drop") {
      barra?.classList.remove("drag-activo");
      if (zona) {
        zona.style.borderColor = "var(--borde)";
        zona.style.background = "transparent";
      }
      const rutas = event.payload.paths;
      if (rutas && rutas.length > 0) {
        if (enTraduccion) procesarRuta(rutas[0]);
        if (enGuardados) {
          for (const ruta of rutas) {
            await guardarArchivoSinTraducir(ruta);
          }
        }
      }
    } else {
      barra?.classList.remove("drag-activo");
      if (zona) {
        zona.style.borderColor = "var(--borde)";
        zona.style.background = "transparent";
      }
    }
  });

  dropZoneInicializada = true;
}
// ============================================================
// NAVEGACIÓN — ENTRE PANTALLAS Y ACCIONES DE ARCHIVO
// ============================================================

// Abre en Finder la carpeta de archivos guardados cifrados
async function abrirCarpetaBabelGuardados(): Promise<void> {
  try {
    await invoke("abrir_carpeta_guardados");
  } catch (e) {
    mostrarToast("Error abriendo Finder: " + e, true);
  }
}

(window as any).abrirCarpetaBabelGuardados = abrirCarpetaBabelGuardados;
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

  // Duplicado: si ya hay una card con el mismo nombre base, no guardar
  const nombreBase = nombre.replace(/\.[^/.]+$/, "").toLowerCase();
  const cardsExistentes = document.querySelectorAll<HTMLElement>("#lista-guardados .archivo-card-nombre");
  for (const card of cardsExistentes) {
    const textoCard = (card.textContent ?? "").trim().toLowerCase();
    if (textoCard === nombreBase) {
      mostrarToast(`"${nombre}" ya está guardado`, true);
      return;
    }
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


// Maneja la selección de archivo desde el explorador del sistema para guardarlo cifrado
async function manejarSeleccionGuardado(event: Event): Promise<void> {
  const input = event.target as HTMLInputElement;
  const archivo = input.files?.[0];
  if (!archivo) return;

  if (archivo.name.endsWith(".babel")) {
    mostrarToast("Los archivos .babel ya están cifrados", true);
    input.value = "";
    return;
  }

  try {
    const bytes = Array.from(new Uint8Array(await archivo.arrayBuffer()));
    const rutaCifrada = await invoke<string>("guardar_bytes_sin_traducir", {
      nombreArchivo: archivo.name,
      contenido: bytes,
    });
    if (buzonActivoGuardados !== "todos") {
      try {
        await invoke("mover_archivo_guardado", { ruta: rutaCifrada, buzonDestino: buzonActivoGuardados });
      } catch (e) {
        console.error("Error moviendo al buzón:", e);
      }
    }
    mostrarToast(`✓ ${archivo.name} guardado y cifrado`, false);
    await cargarArchivosGuardados();
  } catch (error) {
    mostrarToast(`Error guardando: ${error}`, true);
  }
  input.value = "";
}

async function irAArchivos(): Promise<void> {
  mostrarPantalla("archivos-guardados");
  setTimeout(() => iniciarDropZone(), 100);
  await cargarBuzonesGuardados();
  await cargarArchivosGuardados();
}

// ============================================================
// BUZONES DE TRADUCCIONES — CREAR, CANCELAR, CONFIRMAR
// ============================================================

// Muestra el input para escribir el nombre del nuevo buzón de traducciones
// Si se pasa parentId, el buzón se creará como hijo de ese buzón
function mostrarInputBuzon(parentId: string | null = null): void {
  buzonParentPendiente = parentId;
  const input = document.getElementById("input-buzon-nuevo");
  const campo = document.getElementById("nombre-buzon-input") as HTMLInputElement;
  input?.classList.remove("hidden");
  campo?.focus();
}

// Oculta el input y limpia el campo sin crear el buzón
function cancelarBuzon(): void {
  buzonParentPendiente = null;
  const input = document.getElementById("input-buzon-nuevo");
  const campo = document.getElementById("nombre-buzon-input") as HTMLInputElement;
  input?.classList.add("hidden");
  if (campo) campo.value = "";
}
// ============================================================
// BUZONES DE GUARDADOS — CREAR, CARGAR, BORRAR, RENOMBRAR
// ============================================================

// Carga el árbol de buzones guardados y lo renderiza en el sidebar
async function cargarBuzonesGuardados(): Promise<void> {
  try {
    const nodos = await invoke<BuzonNodo[]>("listar_buzones_guardados");
    const lista = document.getElementById("lista-buzones-g");
    if (!lista) return;
    lista.innerHTML = `
      <div class="buzon-item ${buzonActivoGuardados === "todos" ? "activo" : ""}" onclick="seleccionarBuzonGuardados('todos')">
        <span class="buzon-icono">◫</span><span class="buzon-nombre">TODOS</span>
      </div>` + renderArbolBuzones(nodos, null, 0, buzonActivoGuardados, "guard");
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

// Carga el árbol de buzones de traducciones y los renderiza con soporte de drag & drop
async function cargarBuzones(): Promise<void> {
  try {
    const nodos = await invoke<BuzonNodo[]>("listar_buzones");
    const lista = document.getElementById("lista-buzones");
    if (!lista) return;
    lista.innerHTML = `
      <div class="buzon-item ${buzonActivo === "todos" ? "activo" : ""}" onclick="seleccionarBuzon('todos')"
        ondragover="allowDrop(event)" ondragleave="dragLeave(event)" ondrop="soltarEnBuzon(event,'todos')"
        style="border:1px solid transparent;border-radius:3px;transition:background 0.2s,border-color 0.2s;">
        <span class="buzon-icono">◫</span><span class="buzon-nombre">TODOS</span>
      </div>` + renderArbolBuzones(nodos, null, 0, buzonActivo, "trad");
  } catch (error) {
    console.error("Error cargando buzones:", error);
  }
}
// ============================================================
// MOVER ARCHIVOS GUARDADOS — popup selector de buzón destino
// ============================================================

async function moverArchivoGuardadoPopup(ruta: string, event: MouseEvent): Promise<void> {
  document.querySelectorAll(".selector-buzon-popup").forEach(el => el.remove());
  const nodos = await invoke<BuzonNodo[]>("listar_buzones_guardados");
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
      item.style.cssText = `display:flex;align-items:center;padding:8px ${16 + indent * 12}px;font-family:'Josefin Sans',sans-serif;font-size:0.7rem;letter-spacing:2px;color:var(--dorado);cursor:pointer;`;
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
// ============================================================
// RENOMBRAR BUZONES — modal compartido para traducciones y guardados
// ============================================================

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
      await cargarBuzones();
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

// Elimina un buzón de traducciones (y todos sus hijos) y vuelve a "todos" si era el activo
async function borrarBuzon(id: string): Promise<void> {
  try {
    await invoke("eliminar_buzon", { id });
    if (buzonActivo === id) buzonActivo = "todos";
    await cargarBuzones();
  } catch (error) {
    console.error("Error borrando buzón:", error);
  }
}

// Activa un buzón de traducciones (afecta al guardar la siguiente traducción)
async function seleccionarBuzon(id: string): Promise<void> {
  buzonActivo = id;
  localStorage.setItem("babel-buzon-activo", id);
  await cargarBuzones();
}

// Descifra y exporta un archivo .babel a la carpeta Descargas del usuario
async function exportarArchivo(ruta: string): Promise<void> {
  try {
    await invoke<string>("exportar_archivo", { ruta });
    mostrarToast("✓ Exportado a Descargas", false);
  } catch (error) {
    mostrarToast("Error exportando: " + String(error), true);
  }
}
async function exportarTodo(): Promise<void> {
  try {
    const archivos = await invoke<any[]>("listar_archivos_guardados", { buzon: "todos" });
    if (archivos.length === 0) { mostrarToast("No hay archivos para exportar", true); return; }
    let errores = 0;
    for (const a of archivos) {
      try { await invoke("exportar_archivo", { ruta: a.ruta }); }
      catch { errores++; }
    }
    mostrarToast(errores === 0 ? `✓ ${archivos.length} archivos exportados a Descargas` : `${errores} errores al exportar`, errores > 0);
  } catch (e) {
    mostrarToast("Error: " + String(e), true);
  }
}
(window as any).exportarTodo = exportarTodo;

// ============================================================
// TOAST — NOTIFICACIONES TEMPORALES
// ============================================================

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
    font-family: var(--fuente-titulo, 'Cormorant Garamond', serif);
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

// ============================================================
// SELECCIÓN CON FEEDBACK VISUAL
// ============================================================

// Muestra/oculta botones de acción según checkboxes marcados.
// También aplica highlight dorado a las cards seleccionadas.
function actualizarSeleccion(): void {
  // Feedback visual en cada card
  document.querySelectorAll<HTMLElement>(".archivo-card").forEach(card => {
    const cb = card.querySelector<HTMLInputElement>(".archivo-checkbox");
    if (cb?.checked) {
      card.style.borderColor = "var(--dorado)";
      card.style.boxShadow = "0 0 0 1px rgba(197,160,89,0.3), inset 0 0 20px rgba(197,160,89,0.04)";
      card.style.background = "rgba(197,160,89,0.06)";
    } else {
      card.style.borderColor = "";
      card.style.boxShadow = "";
      card.style.background = "";
    }
  });

  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox:checked");
  const btnEliminar = document.getElementById("btn-eliminar-sel");
  const btnVer = document.getElementById("btn-ver-sel");

  // Botón ELIMINAR — aparece con cualquier cantidad seleccionada
  if (checkboxes.length > 0) {
    btnEliminar?.classList.remove("hidden");
    if (btnEliminar) btnEliminar.textContent = `✕ ELIMINAR (${checkboxes.length})`;
  } else {
    btnEliminar?.classList.add("hidden");
  }

  // Botón VER — solo con 1 o 2 seleccionados
  if (checkboxes.length === 1 || checkboxes.length === 2) {
    btnVer?.classList.remove("hidden");
    if (btnVer) btnVer.textContent = checkboxes.length === 2 ? "◫ VER COMPARACIÓN" : "◫ VER ARCHIVO";
  } else {
    btnVer?.classList.add("hidden");
  }
}

// Elimina todos los archivos seleccionados con zeroize
async function eliminarSeleccionados(): Promise<void> {
  const checkboxes = document.querySelectorAll<HTMLInputElement>(".archivo-checkbox:checked");
  if (checkboxes.length === 0) return;

  // Recoger rutas de los archivos seleccionados
  const rutas: string[] = [];
  checkboxes.forEach(cb => {
    const card = cb.closest(".archivo-card") as HTMLElement;
    const ruta = card?.dataset.ruta;
    if (ruta) rutas.push(ruta);
  });

  // Eliminar uno a uno con zeroize
  let errores = 0;
  for (const ruta of rutas) {
    try {
      await invoke("eliminar_archivo", { ruta });
    } catch {
      errores++;
    }
  }

  // Recargar la lista
  await cargarArchivosGuardados();

  if (errores > 0) {
    mostrarToast(`${errores} archivos no se pudieron eliminar`, true);
  } else {
    mostrarToast(`✓ Destruido de forma segura — irrecuperable`, false);
  }
}
// ============================================================
// CIERRE AUTOMÁTICO POR INACTIVIDAD — 10 minutos
// ============================================================
let timerInactividad: ReturnType<typeof setTimeout> | null = null;

function resetearTimerInactividad(): void {
  if (timerInactividad) clearTimeout(timerInactividad);
  timerInactividad = setTimeout(() => {
    cerrarSesion();
  }, 15 * 60 * 1000); // 15 minutos de inactividad
}

function activarTimerInactividad(): void {
  ["mousemove", "keydown", "mousedown", "touchstart", "click"].forEach(evento => {
    document.addEventListener(evento, resetearTimerInactividad);
  });
  resetearTimerInactividad();
}

function desactivarTimerInactividad(): void {
  if (timerInactividad) clearTimeout(timerInactividad);
  ["mousemove", "keydown", "mousedown", "touchstart", "click"].forEach(evento => {
    document.removeEventListener(evento, resetearTimerInactividad);
  });
}
// ============================================================
// VISOR INDIVIDUAL — modal simple
// ============================================================

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
      ALLOWED_ATTR: ["href", "src", "alt", "title", "class", "width", "height", "style"],
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
// ============================================================
// VISOR PARALELO — ver 1 o 2 archivos side by side
// ============================================================

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
  const titulo1 = document.getElementById("par-titulo-1");
  const cont1 = document.getElementById("par-contenido-1");
  const divisor = document.getElementById("par-divisor");
  const panel2 = document.getElementById("par-panel-2");
  const titulo2 = document.getElementById("par-titulo-2");
  const cont2 = document.getElementById("par-contenido-2");

  if (!modal || !cont1) return;

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
// ============================================================
// MOVER ARCHIVOS ENTRE BUZONES — selector popup
// ============================================================

async function mostrarSelectorBuzon(ruta: string, boton: HTMLElement): Promise<void> {
  document.querySelectorAll(".selector-buzon-popup").forEach(el => el.remove());
  const nodos = await invoke<BuzonNodo[]>("listar_buzones");
  const popup = document.createElement("div");
  popup.className = "selector-buzon-popup";
  popup.style.cssText = `position:absolute;background:#0d0d0d;border:1px solid var(--dorado);border-radius:3px;z-index:999;min-width:140px;box-shadow:0 4px 20px rgba(0,0,0,0.5);max-height:60vh;overflow-y:auto;`;

  const construirPopup = () => {
    popup.innerHTML = "";
    const agregar = (label: string, id: string, indent: number, tieneHijos: boolean) => {
      const item = document.createElement("div");
      const colapsado = buzonesColapsados.has(id);
      item.style.cssText = `display:flex;align-items:center;padding:8px ${16 + indent * 12}px;font-family:'Josefin Sans',sans-serif;font-size:0.7rem;letter-spacing:2px;color:var(--dorado);cursor:pointer;`;
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
  const rect = boton.getBoundingClientRect();
  popup.style.top = (rect.bottom + window.scrollY + 4) + "px";
  popup.style.left = rect.left + "px";
  document.body.appendChild(popup);
  setTimeout(() => { document.addEventListener("click", () => popup.remove(), { once: true }); }, 0);
}

// ============================================================
// BÚSQUEDA DE ARCHIVOS
// ============================================================

// ============================================================
// P2P — FUNCIONES
// ============================================================

// ============================================================
// P2P — ESTADO
// ============================================================

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

// ============================================================
// P2P — SERVIDOR (MODO RECIBIR)
// ============================================================

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

// ============================================================
// P2P — CLIENTE (MODO ENVIAR)
// ============================================================
async function buscarDispositivos(): Promise<void> {
  const lista = document.getElementById("p2p-lista-peers");
  if (!lista) return;
  lista.style.display = "flex";
  lista.innerHTML = `<div style="font-family:'Josefin Sans',sans-serif;font-size:0.6rem;letter-spacing:2px;color:var(--texto-secundario);text-align:center;">BUSCANDO...</div>`;

  try {
    const peers = await invoke<any[]>("buscar_peers_p2p");
    if (peers.length === 0) {
      lista.innerHTML = `<div style="font-family:'Josefin Sans',sans-serif;font-size:0.6rem;letter-spacing:2px;color:var(--texto-secundario);text-align:center;opacity:0.5;">NO SE ENCONTRÓ NINGÚN BABEL</div>`;
      return;
    }
    lista.innerHTML = peers.map(p => `
      <button type="button" data-action="peer" data-ip="${escapeHTML(p.ip)}" data-nombre="${escapeHTML(p.nombre)}"
        style="background:rgba(201,168,76,0.06);border:1px solid rgba(201,168,76,0.2);
        color:var(--texto-principal);padding:10px 14px;cursor:pointer;border-radius:2px;
        display:flex;justify-content:space-between;align-items:center;width:100%;">
        <span style="font-family:'Josefin Sans',sans-serif;font-size:0.65rem;letter-spacing:1px;">${escapeHTML(p.nombre)}</span>
        <span style="font-family:'Josefin Sans',sans-serif;font-size:0.58rem;color:var(--dorado);opacity:0.7;">${escapeHTML(p.ip)}</span>
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

// ============================================================
// P2P — CHAT Y TRADUCCIÓN EN TIEMPO REAL
// ============================================================

function añadirMensajeP2P(tipo: "yo" | "ellos" | "sistema", texto: string, traduccion?: string): void {
  const contenedor = document.getElementById("p2p-mensajes");
  if (!contenedor) return;

  const div = document.createElement("div");

  if (tipo === "sistema") {
    div.style.cssText = "text-align:center;font-family:'Josefin Sans',sans-serif;font-size:0.58rem;letter-spacing:2px;color:var(--texto-secundario);opacity:0.5;padding:4px 0;";
    div.textContent = texto;
  } else {
    const esYo = tipo === "yo";
    const textoTraducido = traduccion ? `<p style="font-family:'Cormorant Garamond',serif;font-size:0.78rem;color:var(--texto-secundario);margin:6px 0 0;font-style:italic;opacity:0.7;">${escapeHTML(traduccion)}</p>` : "";
    div.style.cssText = `display:flex;justify-content:${esYo ? "flex-end" : "flex-start"};margin-bottom:4px;`;
    div.innerHTML = `
      <div style="max-width:70%;background:${esYo ? "rgba(201,168,76,0.12)" : "rgba(255,255,255,0.05)"};
        border:1px solid ${esYo ? "rgba(201,168,76,0.3)" : "rgba(255,255,255,0.08)"};
        border-radius:3px;padding:10px 14px;">
        <p style="font-family:'Cormorant Garamond',serif;font-size:0.88rem;color:var(--texto-principal);margin:0;line-height:1.5;">${escapeHTML(texto)}</p>
        ${textoTraducido}
        <span style="font-family:'Josefin Sans',sans-serif;font-size:0.55rem;letter-spacing:1px;color:var(--texto-secundario);opacity:0.5;display:block;margin-top:4px;">${esYo ? "TÚ" : "BABEL REMOTO"} · AES-256</span>
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

  // Mostrar mensaje propio inmediatamente
  añadirMensajeP2P("yo", texto);

  if (ipP2PConectada) {
    try {
      await invoke("enviar_mensaje_p2p", {
        ip: ipP2PConectada,
        mensaje: texto
      });
    } catch (_) { }
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
  // Ir a fase chat
  const faseInicio = document.getElementById("p2p-fase-inicio");
  const faseChat = document.getElementById("p2p-fase-chat");
  const estadoTexto = document.getElementById("p2p-estado-texto");
  const dot = document.getElementById("p2p-dot");
  if (faseInicio) faseInicio.style.display = "none";
  if (faseChat) faseChat.style.display = "flex";
  if (estadoTexto) estadoTexto.textContent = `CONECTADO · ${_solicitudIpRemota}`;
  if (dot) { dot.style.background = "#22c55e"; dot.style.opacity = "1"; }
  // Enviar aceptación al otro
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

  // Resetear estado
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

// ============================================================
// AJUSTES DE TRADUCCIÓN — guardado automático
// ============================================================

async function guardarAjustesTraduccion(): Promise<void> {
  const origen = (document.getElementById("selector-origen") as HTMLSelectElement)?.value ?? "es";
  const destino = (document.getElementById("selector-destino") as HTMLSelectElement)?.value ?? "en";
  const categoria = (document.getElementById("tipo-diccionario") as HTMLSelectElement)?.value ?? "todos";
  const borradoAuto = (document.getElementById("toggle-borrado") as HTMLInputElement)?.checked ?? true;

  await invoke("save_settings", {
    settings: {
      borrar_al_salir: borradoAuto,
      diccionario: true,
      idioma_origen: origen,
      idioma_destino: destino,
      categoria: categoria,
    }
  }).catch(() => {});
}

async function cargarAjustesTraduccion(): Promise<void> {
  const s = await invoke<any>("load_settings");
  const origen = s.idioma_origen ?? "es";
  const destino = s.idioma_destino ?? "en";
  const categoria = s.categoria ?? "todos";
  const borradoAuto = s.borrar_al_salir ?? false;

  // Aplicar ajustes cargados a los controles reales de la UI
  const tipoDiccionario = document.getElementById("tipo-diccionario") as HTMLSelectElement;
  if (tipoDiccionario) tipoDiccionario.value = categoria;
  const toggleBorrado = document.getElementById("toggle-borrado") as HTMLInputElement;
  if (toggleBorrado) toggleBorrado.checked = borradoAuto;
  borradoAutomaticoActivado = borradoAuto;

  if (origen !== destino) {
    const selectorOrigen = document.getElementById("selector-origen") as HTMLSelectElement;
    const selectorDestino = document.getElementById("selector-destino") as HTMLSelectElement;
    if (selectorOrigen) selectorOrigen.value = origen;
    if (selectorDestino) selectorDestino.value = destino;
    await cambiarIdioma(`${origen}_${destino}`).catch(() => {});
  }
  // Restaurar estado del sidebar
  const sidebarAbierto = localStorage.getItem("babel-sidebar") === "1";
  const sidebar = document.getElementById("chat-sidebar");
  if (sidebar) {
    if (sidebarAbierto) sidebar.classList.remove("hidden");
    else sidebar.classList.add("hidden");
  }
  buzonActivo = localStorage.getItem("babel-buzon-activo") ?? "todos";
  const savedBuzonG = localStorage.getItem("babel-buzon-activo-g");
  if (savedBuzonG && savedBuzonG !== "todos") {
    const nodos = await invoke<BuzonNodo[]>("listar_buzones_guardados");
    const existe = nodos.some(n => n.id === savedBuzonG);
    buzonActivoGuardados = existe ? savedBuzonG : "todos";
  } else {
    buzonActivoGuardados = "todos";
  }
}

// ============================================================
// EMAIL — FUNCIONES
// ============================================================

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

// Abre en Finder la carpeta principal de Babel con todos los archivos cifrados
async function abrirCarpetaBabel(): Promise<void> {
  try {
    await invoke("abrir_carpeta_babel");
  } catch (error) {
    mostrarToast("Error abriendo carpeta: " + String(error), true);
  }
}

// Interfaz que refleja el struct Rust EmailResumen
interface EmailResumen {
  id: number;
  remitente: string;
  asunto: string;
  fecha: string;
  tiene_adjunto: boolean;
}

// Email seleccionado actualmente
let emailSeleccionado: EmailResumen | null = null;

async function cargarBandejaEmail(): Promise<void> {
  const lista = document.getElementById("email-lista");
  if (!lista) return;

  lista.innerHTML = `<div class="email-vacio"><p>Cargando...</p></div>`;

  try {
    const emails = await invoke<EmailResumen[]>("obtener_emails_tauri");

    if (emails.length === 0) {
      lista.innerHTML = `
        <div class="email-vacio">
          <p>Sin correos</p>
          <p style="font-size:0.6rem;opacity:0.5;margin-top:4px;">La bandeja está vacía</p>
        </div>`;
      return;
    }

    lista.innerHTML = emails.map(email => `
      <div class="email-item" onclick="seleccionarEmail(${email.id})" data-id="${email.id}">
        <div class="email-item-remitente">${escapeHTML(email.remitente)}</div>
        <div class="email-item-asunto">${escapeHTML(email.asunto)}</div>
        <div class="email-item-fecha">${formatearFechaEmail(email.fecha)}</div>
      </div>
    `).join("");

  } catch (error) {
    lista.innerHTML = `
      <div class="email-vacio">
        <p>Error cargando emails</p>
        <p style="font-size:0.6rem;opacity:0.5;margin-top:4px;">${escapeHTML(String(error))}</p>
      </div>`;
  }
}

// Convierte fecha RFC 2822 a formato legible: hora si es hoy, día/mes si es anterior
function formatearFechaEmail(fecha: string): string {
  if (!fecha) return "";
  // Intentamos parsear la fecha del email (formato RFC 2822)
  try {
    const d = new Date(fecha);
    if (isNaN(d.getTime())) return fecha.substring(0, 16);
    const hoy = new Date();
    const esHoy = d.toDateString() === hoy.toDateString();
    if (esHoy) {
      return d.toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit" });
    }
    return d.toLocaleDateString("es-ES", { day: "2-digit", month: "short" });
  } catch {
    return fecha.substring(0, 16);
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
      ALLOWED_ATTR: ["href", "src", "alt", "title", "class", "width", "height"],
      FORBID_ATTR: ["style"],
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
  document.querySelector(`.email-item[data-id="${id}"]`)?.classList.add("activo");

  const lectorVacio = document.getElementById("email-lector-vacio");
  const compositor = document.getElementById("email-compositor");
  const visor = document.getElementById("email-visor");
  lectorVacio?.classList.add("hidden");
  compositor?.classList.add("hidden");

  try {
    const email = await invoke<{
      id: number;
      remitente: string;
      asunto: string;
      fecha: string;
      cuerpo: string;
      adjuntos: string[];
    }>("obtener_email_completo_tauri", { id });

    if (visor) {
      visor.classList.remove("hidden");
      visor.innerHTML = `
        <div class="email-visor-header" style="display: flex; justify-content: space-between; align-items: flex-start;"> 
          <div style="flex: 1; min-width: 0;">
            <div style="font-family: 'Cormorant Garamond', serif; font-size: 1.1rem; color: var(--texto-principal); letter-spacing: 0.05em; margin-bottom: 6px;">
              ${escapeHTML(email.asunto)}
            </div>
            
            <div style="font-family: 'Josefin Sans', sans-serif; font-size: 0.65rem; letter-spacing: 1px; color: var(--texto-secundario);">
              ${escapeHTML(email.remitente)} · ${formatearFechaEmail(email.fecha)}
            </div>

            ${email.adjuntos.length > 0 ? `
              <div style="margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap;">
                ${email.adjuntos.map(a => `
                  <span style="font-family: 'Josefin Sans', sans-serif; font-size: 0.6rem; letter-spacing: 1px; color: var(--dorado); border: 1px solid var(--borde-dorado); padding: 2px 8px; border-radius: 2px;">
                    ◫ ${escapeHTML(a)}
                  </span>
                `).join("")}
              </div>
            ` : ""}
          </div>

          <button type="button" onclick="cerrarVisorEmail()" style="background: transparent; border: none; color: var(--texto-secundario); cursor: pointer; font-size: 1rem; flex-shrink: 0; padding: 4px;">
            ✕
          </button>
        </div>

        <div id="email-visor-cuerpo" style="padding: 24px 28px; overflow-y: auto; flex: 1; font-family: 'Cormorant Garamond', serif; font-size: 0.95rem; color: var(--texto-principal); line-height: 1.8; word-break: break-word; letter-spacing: 0.02em;">
        </div>
      `;

      const cuerpoEl = visor.querySelector<HTMLElement>("#email-visor-cuerpo");
      if (cuerpoEl) renderizarCuerpoEmail(cuerpoEl, email.cuerpo);
    }
  } catch (error) {
    mostrarToast("Error cargando email: " + String(error), true);
    lectorVacio?.classList.remove("hidden");
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
}

// Cierra el compositor y limpia los campos y archivos adjuntos
function cerrarCompositor(): void {
  document.getElementById("email-compositor")?.classList.add("hidden");
  document.getElementById("email-lector-vacio")?.classList.remove("hidden");
  archivoEmailRuta = "";
  archivoEmailFile = null;
  const nombre = document.getElementById("comp-archivo-nombre");
  if (nombre) nombre.textContent = "◫ Adjuntar archivo";
  const estado = document.getElementById("comp-estado");
  if (estado) estado.textContent = "";
  const inputFile = document.getElementById("input-archivo-email") as HTMLInputElement;
  if (inputFile) inputFile.value = "";
}

// Cierra el visor de email y muestra el estado vacío del lector
function cerrarVisorEmail(): void {
  document.getElementById("email-visor")?.classList.add("hidden");
  document.getElementById("email-lector-vacio")?.classList.remove("hidden");
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
  if (el) el.textContent = "◫ " + archivo.name;
}

// Muestra u oculta el panel de configuración SMTP/IMAP
function toggleConfigSmtp(): void {
  const panel = document.getElementById("panel-config-smtp");
  panel?.classList.toggle("hidden");
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
    await invoke("guardar_config_email_tauri", {
      smtpServidor: servidor,
      imapDominio: imapServidor || servidor.replace("smtp.", "imap."),
      usuario,
      password,
      remitentes,
    });
    _smtpConfigurado = true;
    (document.getElementById("smtp-password") as HTMLInputElement).value = "";
    toggleConfigSmtp();
    mostrarToast("Configuración guardada y cifrada", false);
    // Cargar bandeja inmediatamente tras guardar config
    await cargarBandejaEmail();
  } catch (error) {
    mostrarToast("Error: " + String(error), true);
  }
}

async function enviarEmail(): Promise<void> {
  const destinatario = (document.getElementById("comp-destinatario") as HTMLInputElement)?.value.trim();
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
      // Archivo seleccionado desde el explorador del sistema
      const bytes = Array.from(new Uint8Array(await archivoEmailFile.arrayBuffer()));
      await invoke("enviar_bytes_cifrados_tauri", {
        nombreArchivo: archivoEmailFile.name,
        bytes,
        destinatario,
        asunto,
        cuerpo,
      });
    } else {
      await invoke("enviar_archivo_cifrado_tauri", {
        ruta: archivoEmailRuta,
        destinatario,
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

// Placeholder — traducción de emails está pendiente de implementar
function cambiarIdiomaEmail(_idioma: string): void {
  mostrarToast("Traducción de emails — próximamente", false);
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
// ============================================================
// BIP39 — FRASE DE RECUPERACIÓN
// ============================================================

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
  // Limpiar inputs si los hubiera de un intento anterior
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

  const palabras = Array.from(grid.querySelectorAll(".palabra-bip39")).map((el, i) => {
    const texto = (el.querySelector(".palabra-texto") as HTMLElement)?.textContent?.trim() ?? "";
    return `<div class="palabra"><span class="num">${i + 1}</span><span class="txt">${escapeHTML(texto)}</span></div>`;
  });

  const fechaHoy = new Date().toLocaleDateString("es-ES", { year: "numeric", month: "long", day: "numeric" });

  const html = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Babel Security — Frase de Recuperación</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: Georgia, 'Times New Roman', serif; background: #fff; color: #1a1a1a; padding: 48px 56px; }
  header { text-align: center; border-bottom: 2px solid #1a1a1a; padding-bottom: 20px; margin-bottom: 32px; }
  h1 { font-size: 22px; letter-spacing: 6px; font-weight: 400; margin-bottom: 6px; }
  .subtitle { font-size: 10px; letter-spacing: 3px; color: #555; text-transform: uppercase; }
  .grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-bottom: 40px; }
  .palabra { display: flex; align-items: center; gap: 12px; border: 1px solid #ccc; padding: 12px 16px; }
  .num { font-size: 10px; color: #999; min-width: 16px; text-align: right; font-family: 'Courier New', monospace; }
  .txt { font-size: 15px; letter-spacing: 0.5px; }
  footer { border-top: 1px solid #ccc; padding-top: 16px; display: flex; justify-content: space-between; }
  .aviso { font-size: 9px; letter-spacing: 1.5px; color: #888; text-transform: uppercase; }
  @media print { body { padding: 32px 40px; } }
</style>
</head>
<body>
  <header>
    <h1>BABEL SECURITY</h1>
    <p class="subtitle">Frase de recuperación BIP39 &mdash; Documento confidencial</p>
  </header>
  <div class="grid">${palabras.join("")}</div>
  <footer>
    <span class="aviso">⚠ Guarda este documento bajo llave &mdash; No compartas con nadie</span>
    <span class="aviso">${fechaHoy}</span>
  </footer>
</body>
</html>`;

  try {
    const ruta = await invoke<string>("guardar_html_frase", { html });
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

// Intenta recuperar el búnker con las 12 palabras introducidas
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
    const [maestra, passUsuario] = await invoke<[string, string]>("recuperar_con_frase", { palabras });

    // Rellenar los campos del login con las credenciales recuperadas
    const campoPass = document.getElementById("login-pass-usuario") as HTMLInputElement;
    if (campoPass) campoPass.value = passUsuario;
    const campoMaestra = document.getElementById("login-pass") as HTMLInputElement;
    if (campoMaestra) campoMaestra.value = maestra;

    mostrarMensaje("recovery-msg", `✓ LLAVE MAESTRA RECUPERADA — SE HA RELLENADO EL LOGIN`, false);

    // Limpiar campos de recuperación
    for (let i = 1; i <= 12; i++) {
      const input = document.getElementById(`rec-palabra-${i}`) as HTMLInputElement;
      if (input) {
        // Zeroize manual
        input.value = "0".repeat(input.value.length);
        input.value = "";
      }
    }

    setTimeout(() => {
      mostrarPantalla("login");
      // Enfocar el campo de contraseña de usuario para que sea lo único que falta
      setTimeout(() => {
        document.getElementById("login-pass-usuario")?.focus();
      }, 100);
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
// ============================================================
// BUZONES DE TRADUCCIONES — CONFIRMAR CREACIÓN
// (función principal del flujo crear buzón de traducción)
// ============================================================

// Lee el nombre del input y llama a Rust para crear el buzón en .buzones.babel
async function confirmarBuzon(): Promise<void> {
  const campo = document.getElementById("nombre-buzon-input") as HTMLInputElement;
  const nombre = campo?.value?.trim().toLowerCase() ?? "";
  if (!nombre) return;
  try {
    await invoke("crear_buzon", { nombre, parent: buzonParentPendiente });
    buzonParentPendiente = null;
    cancelarBuzon();
    await cargarBuzones();
  } catch (error) {
    console.error("Error creando buzón:", error);
  }
}
// ============================================================
// TÉRMINOS DE USO
// ============================================================

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
// ============================================================
// EXPORTAR AL HTML
// ============================================================
// ============================================================
// REGISTRO GLOBAL DE FUNCIONES
// Las funciones se exponen en window para poder llamarlas desde
// atributos onclick en el HTML (Tauri no permite módulos ES directos)
// ============================================================
(window as any).mostrarPantalla = mostrarPantalla;
(window as any).irATraduccion = irATraduccion;
(window as any).crearBunker = crearBunker;
(window as any).intentarAcceso = intentarAcceso;
(window as any).cerrarSesion = cerrarSesion;
(window as any).volverAtras = volverAtras;
(window as any).volverAlPanel = volverAlPanel;
(window as any).seleccionarArchivo = seleccionarArchivo;
(window as any).manejarSeleccion = manejarSeleccion;
(window as any).enviarMensaje = enviarMensaje;
(window as any).descargarResultado = descargarResultado;
(window as any).borrarChat = borrarChat;
(window as any).toggleSidebar = toggleSidebar;
(window as any).toggleBorradoAutomatico = toggleBorradoAutomatico;
(window as any).cambiarIdioma = cambiarIdioma;
(window as any).cambiarIdiomaDesdeSelectores = cambiarIdiomaDesdeSelectores;
(window as any).cambiarCategoriaDiccionario = cambiarCategoriaDiccionario;
(window as any).toggleContraseña = toggleContraseña;

(window as any).seleccionarBuzon = seleccionarBuzon;
(window as any).exportarArchivo = exportarArchivo;
(window as any).verArchivo = verArchivo;
(window as any).cerrarVisor = cerrarVisor;

(window as any).mostrarInputBuzon = mostrarInputBuzon;
(window as any).cancelarBuzon = cancelarBuzon;
(window as any).confirmarBuzon = confirmarBuzon;
(window as any).actualizarSeleccion = actualizarSeleccion;
(window as any).eliminarSeleccionados = eliminarSeleccionados;
(window as any).borrarBuzon = borrarBuzon;
(window as any).mostrarSelectorBuzon = mostrarSelectorBuzon;
(window as any).cambiarModoP2P = cambiarModoP2P;
(window as any).volverDeP2P = volverDeP2P;
(window as any).iniciarP2P = iniciarP2P;
(window as any).conectarP2P = conectarP2P;
(window as any).abrirComponerEmail = abrirComponerEmail;
(window as any).cerrarCompositor = cerrarCompositor;
(window as any).cerrarVisorEmail = cerrarVisorEmail;
(window as any).seleccionarArchivoEmail = seleccionarArchivoEmail;
(window as any).manejarSeleccionArchivoEmail = manejarSeleccionArchivoEmail;
(window as any).toggleConfigSmtp = toggleConfigSmtp;
(window as any).guardarConfigSmtp = guardarConfigSmtp;
(window as any).enviarEmail = enviarEmail;
(window as any).cambiarIdiomaEmail = cambiarIdiomaEmail;
(window as any).enviarArchivoDesdeArchivos = enviarArchivoDesdeArchivos;
(window as any).verComparacion = verComparacion;
(window as any).cerrarVisorParalelo = cerrarVisorParalelo;
(window as any).mostrarFrase = mostrarFrase;
(window as any).cerrarFrase = cerrarFrase;
(window as any).irARecuperacion = irARecuperacion;
(window as any).intentarRecuperacion = intentarRecuperacion;
(window as any).verFraseApp = verFraseApp;
(window as any).cerrarVerFrase = cerrarVerFrase;
(window as any).aceptarTerminos = aceptarTerminos;
(window as any).mostrarModalTerminos = mostrarModalTerminos;
(window as any).cargarBandejaEmail = cargarBandejaEmail;
(window as any).seleccionarEmail = seleccionarEmail;
(window as any).emailSeleccionado = emailSeleccionado;
(window as any).abrirCarpetaBabel = abrirCarpetaBabel;
(window as any).iniciarPollMensajes = iniciarPollMensajes;
(window as any).iniciarRenombrado = iniciarRenombrado;
(window as any).confirmarRenombrar = confirmarRenombrar;
(window as any).cerrarModalRenombrar = cerrarModalRenombrar;
(window as any).buscarDispositivos = buscarDispositivos;
(window as any).seleccionarPeer = seleccionarPeer;
(window as any).aceptarSolicitudP2P = aceptarSolicitudP2P;
(window as any).rechazarSolicitudP2P = rechazarSolicitudP2P;
(window as any).irAArchivos = irAArchivos;
(window as any).cargarArchivosGuardados = cargarArchivosGuardados;
(window as any).filtrarArchivosGuardados = filtrarArchivosGuardados;
(window as any).seleccionarBuzonGuardados = seleccionarBuzonGuardados;
(window as any).verArchivoGuardado = verArchivoGuardado;
(window as any).eliminarSeleccionadosGuardados = eliminarSeleccionadosGuardados;
(window as any).cargarBuzonesGuardados = cargarBuzonesGuardados;
(window as any).actualizarSeleccionGuardados = actualizarSeleccionGuardados;
(window as any).confirmarBuzonGuardado = confirmarBuzonGuardado;
(window as any).mostrarInputBuzonGuardado = mostrarInputBuzonGuardado;
(window as any).cancelarBuzonGuardado = cancelarBuzonGuardado;
(window as any).borrarBuzonGuardado = borrarBuzonGuardado;
(window as any).iniciarRenombradoGuardado = iniciarRenombradoGuardado;
(window as any).manejarSeleccionGuardado = manejarSeleccionGuardado;
(window as any).abrirImportarGuardado = abrirImportarGuardado;
(window as any).moverArchivoGuardadoPopup = moverArchivoGuardadoPopup;
(window as any).imprimirFrase = imprimirFrase;
(window as any).toggleColapso = toggleColapso;
(window as any).iniciarRenombradoArchivo = iniciarRenombradoArchivo;
(window as any).confirmarRenombrarArchivo = confirmarRenombrarArchivo;
(window as any).cerrarModalRenombrarArchivo = cerrarModalRenombrarArchivo;
(window as any).verComparacionRutas = verComparacionRutas;


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


// ============================================================
// AJUSTES — Tema, Idioma UI, Ver Contraseña
// ============================================================

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
  },
};

function cambiarIdiomaUI(idioma: string): void {
  const t = TRADUCCIONES_UI[idioma] ?? TRADUCCIONES_UI["es"];
  localStorage.setItem("babel-idioma-ui", idioma);
  const mapa: Record<string, string> = {
    "pantalla-texto-traducir": t.traducir,
    "pantalla-texto-archivos": t.archivos,
    "pantalla-texto-p2p": t.p2p,
    "pantalla-texto-ajustes": t.ajustes,
    "pantalla-texto-cerrar": t.cerrarSesion,
    "ui-borrar-chat": t.borrarChat,
    "ui-configuracion": t.configuracion,
    "ui-borrar-al-salir": t.borrarAlSalir,
    "ui-borrar-al-salir-desc": t.borrarAlSalirDesc,
    "ui-email-auto": t.emailAuto,
    "ui-proximamente": t.proximamente,
    "ui-diccionario": t.diccionario,
    "ui-vocabulario-activo": t.vocabularioActivo,
    "ui-volver-archivos": t.volver,
    "btn-ver-sel-g": t.verArchivo,
    "btn-eliminar-sel-g": t.eliminar,
    "ui-actualizar": t.actualizar,
    "ui-exportar-todo": t.exportarTodo,
    "ui-importar": t.importar,
    "ui-tema": t.tema,
    "ui-idioma-interfaz": t.idiomaInterfaz,
    "ui-bienvenido": t.bienvenido,
    "ui-bienvenido-sistema": t.bienvenidoSistema,
    "ui-acceder-bunker": t.accederBunker,
    "ui-autenticacion-requerida": t.autenticacion,
    "ui-ajustes-titulo": t.ajustesTitulo,
    "ui-volver-panel": t.volverPanel,
    "ui-frase-recuperacion": t.fraseRecuperacion,
    "ui-recuperar-bunker": t.recuperarBunker,
    "ui-traducidos-guardados": t.traducidosGuardados,
    "ui-buzones": t.buzones,
    "ui-archivos-titulo": t.archivosTitulo,
    "ui-no-archivos": t.noArchivos,
    "ui-arrastra": t.arrastra,
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
  // Marcar botón activo visualmente
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
(window as any).cambiarTema = cambiarTema;
(window as any).cambiarIdiomaUI = cambiarIdiomaUI;

(window as any).enviarMensajeP2P = enviarMensajeP2P;
(window as any).destruirSesionP2P = destruirSesionP2P;
(window as any).guardarAjustesTraduccion = guardarAjustesTraduccion;
(window as any).toggleTraduccionP2P = toggleTraduccionP2P;
(window as any).manejarMensajeEntrante = manejarMensajeEntrante;
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

// Cargar ajustes al arrancar
document.addEventListener("DOMContentLoaded", cargarAjustesGuardados);
document.addEventListener("DOMContentLoaded", cargarAjustesTraduccion);

// ============================================================
// UX GLOBAL — Escape cierra modales, Enter navega recovery, paste BIP39
// ============================================================
document.addEventListener("DOMContentLoaded", () => {
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

  bindOnclicks(document.documentElement);

  // MutationObserver: convierte onclick= en nuevos nodos dinámicos (buzones, emails…)
  new MutationObserver((muts) => {
    for (const m of muts) {
      m.addedNodes.forEach((node) => {
        if (!(node instanceof Element)) return;
        if (node instanceof HTMLElement && node.hasAttribute("onclick")) bindOnclickEl(node);
        node.querySelectorAll<HTMLElement>("[onclick]").forEach(bindOnclickEl);
      });
    }
  }).observe(document.body, { childList: true, subtree: true });
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

function bindOnclickEl(el: HTMLElement) {
  const raw = el.getAttribute("onclick");
  if (!raw) return;
  el.removeAttribute("onclick");
  el.addEventListener("click", (ev: MouseEvent) => {
    for (const part of raw.split(";").map((s) => s.trim()).filter(Boolean)) {
      if (part === "event.stopPropagation()") { ev.stopPropagation(); continue; }
      if (part === "event.preventDefault()") { ev.preventDefault(); continue; }
      // [\wÀ-ɏ$]+ cubre letras latinas extendidas (ñ, á…)
      const m = part.match(/^([\wÀ-ɏ$]+)\((.*?)\)\s*$/s);
      if (!m) continue;
      const fn = (window as unknown as Record<string, unknown>)[m[1]];
      if (typeof fn !== "function") continue;
      const argsRaw = m[2].trim();
      if (!argsRaw) { (fn as () => void)(); continue; }
      const args = argsRaw.split(",").map(parseOnclickArg);
      (fn as (...a: unknown[]) => void)(...args);
    }
  });
}

function bindOnclicks(root: Element) {
  root.querySelectorAll<HTMLElement>("[onclick]").forEach(bindOnclickEl);
}