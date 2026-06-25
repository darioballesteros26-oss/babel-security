import { defineConfig } from "vite";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// Plugin que inyecta un mock de __TAURI_INTERNALS__ solo en dev y solo cuando
// no hay Tauri real (navegador sin backend). No afecta el build de producción.
const tauriDevMock = {
  name: "tauri-dev-mock",
  apply: "serve" as const,
  transformIndexHtml: (html: string) =>
    html.replace(
      "<head>",
      `<head><script>
if (!window.__TAURI_INTERNALS__) {
  const _inv = async (cmd) => {
    const m = {
      verificar_sesion: { autenticado: false },
      load_settings: { idioma_origen:"es", idioma_destino:"en", categoria:"todos", borrar_al_salir:true },
      listar_buzones: [], listar_buzones_guardados: [],
      listar_archivos_guardados: [],
      obtener_version: "0.1.0-dev",
      cambiar_idioma: null, cambiar_categoria_diccionario: null,
      save_settings: null, cargar_idioma_ui: "es",
    };
    console.log("[tauri-mock]", cmd);
    return cmd in m ? m[cmd] : null;
  };
  window.__TAURI_INTERNALS__ = { invoke: _inv, transformCallback: (cb) => { const id=Math.random(); return id; }, convertFileSrc: p=>p };
  window.__TAURI__ = { core: { invoke: _inv } };
}
</script>`
    ),
};

// https://vite.dev/config/
export default defineConfig(async () => ({

  plugins: [tauriDevMock],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    watch: {
      ignored: (path: string) => !path.includes('/src/') && !path.includes('/src-tauri/src/'),
    },
  },
}));