-- Envoltorio de "Fondo Personal.app".
-- Ejecuta el motor instalador.sh que vive dentro del bundle (Resources).
-- Usa "path to resource": resuelve DENTRO del app aunque haya App Translocation.
set scriptPath to POSIX path of (path to resource "instalador.sh")
do shell script "/bin/bash " & quoted form of scriptPath
