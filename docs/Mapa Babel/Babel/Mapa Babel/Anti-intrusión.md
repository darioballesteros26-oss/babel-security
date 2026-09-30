# 🛡️ Anti-intrusión

Defensas contra control remoto, exfiltración masiva y sustitución del binario.
**Módulos:** `rat_detector.rs`, `acceso_masivo.rs`, `integridad.rs`

## Tres capas
- **RAT** (`rat_detector.rs`): detecta control remoto (TeamViewer/AnyDesk/screensharing…) y **bloquea la bóveda**; desbloqueo por par TCP o frase BIP39.
- **Acceso masivo** (`acceso_masivo.rs`): bloquea la sesión tras **5 descifrados en 10 s** (anti-exfiltración).
- **Integridad** (`integridad.rs`): huella de build embebida vs `~/Babel/.integridad` (detecta binario sustituido). Capa codesign informativa hasta tener Developer ID.

## Funciones clave
- `detectar_rat_activo`, `iniciar_monitor_rat`, `es_rat_bloqueado`, `verificar_no_bloqueado_rat`.
- `desbloquear_rat_desde_red`, `verificar_frase_bip` — desbloqueo.
- `acceso_masivo::registrar_descifrado` — cuenta y bloquea.
- `integridad::verificar_integridad_binario`.

## Relacionado
Gatea comandos sensibles (`verificar_no_bloqueado_rat`). Registra en [[Registro Diario]]. Ver [[Cifrado]], [[Babel]].
