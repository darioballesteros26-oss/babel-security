# Guardar con Babel — integración con el clic derecho del Finder (macOS)

Añade una opción **"Guardar con Babel"** al menú contextual del Finder que cifra
(AES-256-GCM con la clave maestra), importa al búnker y borra de forma segura el
original — **sin fricción**: instantáneo y sin contraseña mientras haya sesión activa.

---

## 1. Mecanismo elegido y por qué

| Pieza | Mecanismo | Motivo |
|-------|-----------|--------|
| Entrada en el menú del Finder | **Quick Action / Servicio de macOS** (Automator, en `~/Library/Services`) | Funciona **hoy sin Apple Developer ID** ni firma. Se instala copiando un archivo. Aparece en clic derecho → *Acciones rápidas* / *Servicios*. |
| Extensión ⇄ app | **URL scheme `babel://`** (plugin oficial `tauri-plugin-deep-link`) | Es el IPC nativo que **mejor encaja con Tauri 2**. No necesita App Group ni XPC (que exigirían firma con Developer ID). `open babel://…` funciona desde un simple shell. |
| Transporte del archivo | **Carpeta de staging** `~/Babel/entrada_finder/` | Bajo App Sandbox un path que llega por URL **no** es *user-selected* y la app firmada no podría leerlo. La carpeta de staging vive dentro del directorio de Babel (lectura siempre permitida) y actúa como **cola durable** si la sesión está bloqueada/cerrada. |

### Flujo

```
Finder (clic derecho) → Quick Action "Guardar con Babel"
   → guardar_con_babel.sh:
       · copia cada archivo compatible a  ~/Babel/entrada_finder/<uuid>__<nombre>
       · escribe el sidecar               ~/Babel/entrada_finder/<uuid>.orig  (ruta original)
       · open "babel://guardar"
   → Babel (tauri-plugin-deep-link, on_open_url):
       · CON sesión activa   → cifra e importa a ~/Babel/guardados/, borra staged
                                y original de forma segura. Sin ventana ni contraseña.
       · SIN sesión activa   → muestra la ventana y pide contraseña una vez (Opción A);
                                tras login, drena la cola de entrada_finder/.
```

El **borrado seguro del original** lo hace Babel en Rust (`borrar_seguro`, 3 pasadas +
fsync), **solo tras cifrar con éxito** — el usuario nunca pierde datos si algo falla.

---

## 2. Instalación (desarrollo / DMG local)

```bash
cd finder-extension
./instalar.sh          # copia el helper + el .workflow a ~/Library/Services
```

Luego, clic derecho sobre un PDF/DOCX/TXT/PNG/JPG → *Acciones rápidas* → **Guardar con Babel**.
Si no aparece, actívalo en *Ajustes del Sistema → Extensiones → Finder / Acciones rápidas*.

Desinstalar: `./desinstalar.sh`.

> **Nota (macOS) sobre el URL scheme:** LaunchServices enruta `babel://` a la app a partir
> del `CFBundleURLTypes` del **Info.plist del bundle**. Por eso el esquema funciona con la
> app **empaquetada** (`npm run tauri build`, luego abrir `Babel Security.app`), no con
> `npm run tauri dev` (que ejecuta el binario suelto, sin Info.plist). Para probar el flujo
> completo end-to-end, usa el build empaquetado. La lógica de cifrado/cola está cubierta
> además por tests unitarios (`cargo test finder`) que no dependen del bundle.

---

## 3. Qué haría falta para DISTRIBUIR (firma / entitlements)

En cuanto haya un **Apple Developer ID**:

1. **URL scheme** — ya queda configurado en `tauri.conf.json`
   (`plugins.deep-link.desktop.schemes = ["babel"]`); Tauri inyecta `CFBundleURLTypes`
   en el Info.plist del bundle. Solo hay que **firmar** la app (`codesign` con Developer ID)
   para que LaunchServices la registre de forma estable.

2. **Borrado seguro del original bajo App Sandbox** — la app está sandboxed
   (`src-tauri/Entitlements.plist`) con solo `files.user-selected.read-write`. El original
   vive **fuera** del contenedor, así que la app firmada+sandboxed **no puede borrarlo**.
   Opciones para producción:
   - Añadir el entitlement de excepción temporal
     `com.apple.security.temporary-exception.files.absolute-path.read-write`
     (ya está **comentado** en `Entitlements.plist` con instrucciones), **o**
   - Migrar a un **App Extension FinderSync** firmado + **App Group** compartido con la app,
     de modo que el borrado lo haga la propia extensión (con acceso al archivo elegido).

   En el build de **desarrollo/DMG no sandboxed** (el actual) el borrado del original
   funciona directamente sin nada extra.

3. **Quick Action** — no requiere firma (vive en `~/Library/Services` del usuario). Si en el
   futuro se prefiere un ítem **directo** en el menú contextual (sin submenú *Acciones
   rápidas*), habría que empaquetar un **FinderSync `.appex`** dentro de `Babel Security.app`,
   lo que **sí** exige Developer ID + entitlements.

---

## 4. Manejo de errores (no rompe nunca)

- Tipo de archivo no compatible → el Quick Action lo ignora; Babel lo rechaza en
  `cifrar_y_guardar_desde_ruta`.
- Permisos denegados / fallo de cifrado → se registra con `log::error!` en Babel; el
  original **no** se borra y la copia staged en claro se limpia. Se emite `finder-guardado`
  con `ok:false` y la UI muestra un aviso.
- Babel cerrado → `open babel://` lo lanza; la cola espera en `entrada_finder/`.

---

## 5. Nota de seguridad (trade-off aceptado)

Entre el *staging* y el cifrado existe una copia en claro dentro de
`~/Babel/entrada_finder/` (instantáneo con sesión activa; persiste hasta el login si la
sesión está bloqueada). Es coherente con la carpeta `tmp/` que ya usa el traductor y se
borra con `borrar_seguro` tras procesar. El modo segundo plano relaja el bloqueo-al-perder-
foco: la sesión ahora solo caduca por el **timeout de inactividad configurable**
(por defecto 60 min; nunca desactivable), lo que habilita la fricción cero.

---

## 6. Ficheros

```
finder-extension/
├── Guardar con Babel.workflow/      # bundle Automator (Quick Action)
│   └── Contents/{Info.plist, document.wflow}
├── guardar_con_babel.sh             # lógica: staging + open babel://guardar
├── instalar.sh                      # instala helper + workflow, refresca Servicios
├── desinstalar.sh
└── README.md
```
