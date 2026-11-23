#!/usr/bin/env bash
#
# SonarQube local para el Sistema Web Clínica OWASP Top 10 2021.
#
#   ./scripts/sonar.sh iniciar    Levanta SonarQube y crea el token la 1.ª vez.
#   ./scripts/sonar.sh analizar   Ejecuta pruebas/cobertura y el análisis.
#   ./scripts/sonar.sh detener    Apaga los contenedores (conserva los datos).
#   ./scripts/sonar.sh estado     Muestra el estado del servidor.
#
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RAIZ"

COMPOSE=(docker compose -f docker-compose.sonarqube.yml)
URL="http://localhost:9000"
ARCHIVO_ENTORNO=".env.sonar"
ADMIN_USUARIO="admin"
ADMIN_PASSWORD_POR_DEFECTO="Clinica#Sonar2026"

log() { printf '\033[1;34m[sonar]\033[0m %s\n' "$*"; }
error() { printf '\033[1;31m[sonar]\033[0m %s\n' "$*" >&2; }

esperar_sonarqube() {
  log "Esperando a que SonarQube esté disponible en $URL ..."
  for _ in $(seq 1 120); do
    estado="$(curl -fsS "$URL/api/system/status" 2>/dev/null \
      | python3 -c 'import sys,json; print(json.load(sys.stdin).get("status",""))' 2>/dev/null || true)"
    if [ "$estado" = "UP" ]; then
      log "SonarQube está operativo."
      return 0
    fi
    sleep 5
  done
  error "SonarQube no respondió a tiempo. Revisa: docker compose -f docker-compose.sonarqube.yml logs sonarqube"
  return 1
}

iniciar() {
  if ! docker info >/dev/null 2>&1; then
    error "El daemon de Docker no está activo. Inícialo con: sudo systemctl start docker"
    exit 1
  fi

  "${COMPOSE[@]}" up -d sonarqube-db sonarqube
  esperar_sonarqube

  if [ -f "$ARCHIVO_ENTORNO" ]; then
    log "Token existente en $ARCHIVO_ENTORNO (no se regenera)."
    return 0
  fi

  local password="${SONAR_ADMIN_PASSWORD:-$ADMIN_PASSWORD_POR_DEFECTO}"
  log "Configurando la contraseña del administrador y generando el token..."

  if ! curl -fsS -u "admin:admin" -X POST "$URL/api/users/change_password" \
      --data-urlencode "login=$ADMIN_USUARIO" \
      --data-urlencode "previousPassword=admin" \
      --data-urlencode "password=$password" >/dev/null; then
    error "No se pudo cambiar la contraseña inicial de admin."
    error "Si ya la cambiaste antes, define SONAR_ADMIN_PASSWORD con la actual y borra el volumen para reiniciar."
    exit 1
  fi

  local token
  token="$(curl -fsS -u "$ADMIN_USUARIO:$password" -X POST \
    "$URL/api/user_tokens/generate" \
    --data-urlencode "name=clinica-owasp-$(date +%Y%m%d%H%M%S)" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')"

  {
    printf 'SONAR_TOKEN=%s\n' "$token"
    printf 'SONAR_ADMIN_PASSWORD=%s\n' "$password"
  } > "$ARCHIVO_ENTORNO"
  chmod 600 "$ARCHIVO_ENTORNO"
  log "Credenciales guardadas en $ARCHIVO_ENTORNO (ignorado por git)."
  log "Acceso web: $URL  (admin / $password)"
}

analizar() {
  if [ ! -f "$ARCHIVO_ENTORNO" ]; then
    error "Falta $ARCHIVO_ENTORNO. Ejecuta primero: ./scripts/sonar.sh iniciar"
    exit 1
  fi
  # shellcheck disable=SC1090
  set -a; source "$ARCHIVO_ENTORNO"; set +a
  export SONAR_TOKEN

  local python="backend/venv/bin/python"
  [ -x "$python" ] || python="$(command -v python3)"
  local python_abs="$RAIZ/$python"
  [ -x "$python_abs" ] || python_abs="$(command -v python3)"

  log "Ejecutando pruebas del backend y generando cobertura XML..."
  ( cd "$RAIZ/backend" && "$python_abs" -m pytest \
      --cov=src --cov-report=xml:coverage.xml --cov-report=term-missing -q )

  # coverage.py escribe la ruta absoluta del host; el escáner la lee dentro del
  # contenedor en /usr/src, así que se deja relativa a la raíz del proyecto.
  python3 - "$RAIZ/backend/coverage.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

ruta = sys.argv[1]
arbol = ET.parse(ruta)
for fuente in arbol.getroot().find("sources"):
    fuente.text = "backend/src"
arbol.write(ruta, encoding="UTF-8", xml_declaration=True)
PY

  log "Ejecutando análisis de SonarQube (espera al Quality Gate)..."
  "${COMPOSE[@]}" --profile scan run --rm sonar-scanner

  log "Análisis finalizado. Resultado:"
  curl -fsS -u "admin:${SONAR_ADMIN_PASSWORD}" \
    "$URL/api/qualitygates/project_status?projectKey=clinica-owasp" \
    | python3 -c 'import sys,json; e=json.load(sys.stdin)["projectStatus"]; print("Quality Gate:", e["status"]); [print(" -",c["metricKey"],"=",c.get("actualValue"),"->",c["status"]) for c in e["conditions"]]'
}

detener() {
  "${COMPOSE[@]}" down
}

estado() {
  "${COMPOSE[@]}" ps
  curl -fsS "$URL/api/system/status" 2>/dev/null \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print("SonarQube:", d.get("status"), d.get("version",""))' \
    || error "SonarQube no responde en $URL"
}

case "${1:-}" in
  iniciar) iniciar ;;
  analizar) analizar ;;
  detener) detener ;;
  estado) estado ;;
  *)
    printf 'Uso: %s {iniciar|analizar|detener|estado}\n' "$0"
    exit 1
    ;;
esac
