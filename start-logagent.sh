#!/usr/bin/env bash
# Starts your trained model (if present) and the logagent dashboard. Linux/macOS counterpart of start-logagent.ps1.
#   ./start-logagent.sh [--no-browser] [--port 8765] [--model-port 8081]
# Ctrl+C (or closing the terminal) stops both. A model server that was already running is left alone.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

port=8765
model_port=8081
no_browser=""
while [ $# -gt 0 ]; do
    case "$1" in
        --no-browser) no_browser="--no-browser" ;;
        --port) port="$2"; shift ;;
        --model-port) model_port="$2"; shift ;;
        -h|--help) sed -n '2,4p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

[ -f logagent.toml ] || cp config.example.toml logagent.toml
mkdir -p data

url_ok() { curl -sf --max-time 2 "$1" >/dev/null 2>&1; }
python=$(command -v python3 || command -v python)
dash="http://127.0.0.1:$port/"

# Started from the desktop shortcut, the terminal closes on exit: keep it open on failure so the error is readable.
pause_on_error() {
    local rc=${1:-$?}
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ] && [ -t 0 ]; then
        read -r -p "logagent stopped with an error (exit $rc). Press Enter to close. " _ || true
    fi
}
trap pause_on_error EXIT

open_browser() {
    [ -n "$no_browser" ] && return
    { command -v xdg-open >/dev/null && xdg-open "$dash"; } >/dev/null 2>&1 ||
        { command -v open >/dev/null && open "$dash"; } >/dev/null 2>&1 || true
}

# --- already running? open it instead of starting a second copy
if url_ok "${dash}api/status"; then
    echo "[dashboard] already running at $dash - opening it"
    open_browser
    exit 0
fi
if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "[dashboard] port $port is in use by another program. Free it or use --port <n>." >&2
    exit 1
fi

# --- model server
model_pid=""
train_py=.venv-train/bin/python
if url_ok "http://127.0.0.1:$model_port/v1/models"; then
    echo "[model] already running on :$model_port"
elif [ -x "$train_py" ] && compgen -G "models/*/adapter" >/dev/null; then
    echo "[model] starting your trained model on :$model_port (log: data/model.log) ..."
    "$train_py" -W ignore trainer/serve.py --port "$model_port" >data/model.log 2>&1 &
    model_pid=$!
    deadline=$((SECONDS + 180))
    until url_ok "http://127.0.0.1:$model_port/v1/models"; do
        if ! kill -0 "$model_pid" 2>/dev/null; then
            echo "[model] exited early; see data/model.log. Continuing with rules only." >&2; model_pid=""; break
        fi
        if [ "$SECONDS" -gt "$deadline" ]; then
            echo "[model] not ready after 180 s; continuing (dashboard shows model status)." >&2; break
        fi
        sleep 2
    done
    [ -n "$model_pid" ] && url_ok "http://127.0.0.1:$model_port/v1/models" && echo "[model] ready"
else
    echo "[model] no trained model found (models/*/adapter or .venv-train missing) - running with rules only." >&2
fi

ui_pid=""
cleanup() {
    local rc=$?
    if [ -n "$ui_pid" ] && kill -0 "$ui_pid" 2>/dev/null; then kill "$ui_pid"; wait "$ui_pid" 2>/dev/null || true; fi
    if [ -n "$model_pid" ] && kill -0 "$model_pid" 2>/dev/null; then
        kill "$model_pid"; wait "$model_pid" 2>/dev/null || true; echo "[model] stopped"
    fi
    pause_on_error "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP

# --- dashboard
echo "[dashboard] http://127.0.0.1:$port/   (Ctrl+C to stop)"
# run in the background and wait, so a signal reaches the trap immediately instead of after the dashboard exits
"$python" -m logagent ui --port "$port" $no_browser &
ui_pid=$!
wait "$ui_pid"
