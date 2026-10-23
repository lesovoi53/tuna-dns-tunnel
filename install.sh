#!/usr/bin/env bash
set -euo pipefail
base=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
test -f "$base/tuna_dns/backend.py" || { echo 'Скачайте и распакуйте полный дистрибутив TUNA DNS Tunnel.' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'Установите python3 (не ниже 3.11).' >&2; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else "Нужен Python 3.11 или новее")'
export PYTHONPATH="$base"
case "${1:-}" in
    --update) shift; exec python3 -m tuna_dns.cli update "$@" ;;
    --help|-h) exec python3 -m tuna_dns.cli install --help ;;
    *) exec python3 -m tuna_dns.cli install "$@" ;;
esac
