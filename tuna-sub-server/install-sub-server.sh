#!/usr/bin/env bash
# ==============================================================================
# TUNA Subscription Server — Installation Script
# Target OS: Debian 12 / 13, Ubuntu 24.04 / 26.04 (amd64)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}================================================================${NC}"
echo -e "${CYAN}          TUNA Subscription Server — Установка сервиса           ${NC}"
echo -e "${CYAN}================================================================${NC}"

if [[ "${EUID}" -ne 0 ]]; then
    echo -e "${RED}[ERROR] Скрипт должен быть запущен от имени root!${NC}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. Проверка наличия Python 3 (3.11+)
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${YELLOW}[!] Python 3 не обнаружен. Установка python3...${NC}"
    apt-get update -y && apt-get install -y python3
fi

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Нужен Python 3.11 или новее")'
PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[✓] Обнаружен Python ${PYTHON_VER}${NC}"

# Проверка синтаксиса и загрузки модуля
python3 - "$SCRIPT_DIR/tuna-subscriptions.py" <<'PY'
import importlib.util, pathlib, sys
sys.path.insert(0, str(pathlib.Path(sys.argv[1]).parent))
spec = importlib.util.spec_from_file_location('tuna_validate', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
config = pathlib.Path('/etc/tuna-subscriptions/config.toml')
if config.exists():
    module.load_config(str(config))
PY

# 2. Создание системного пользователя tuna-sub
if ! id -u tuna-sub >/dev/null 2>&1; then
    echo -e "${CYAN}[*] Создание системного пользователя 'tuna-sub'...${NC}"
    useradd --system --no-create-home --shell /usr/sbin/nologin tuna-sub
else
    echo -e "${GREEN}[✓] Пользователь 'tuna-sub' уже существует.${NC}"
fi

# 3. Создание директорий с ограниченными правами
echo -e "${CYAN}[*] Настройка защищенных директорий...${NC}"
mkdir -p /etc/tuna-subscriptions
chmod 0750 /etc/tuna-subscriptions
chown root:tuna-sub /etc/tuna-subscriptions

mkdir -p /var/lib/tuna-subscriptions
chmod 0700 /var/lib/tuna-subscriptions
chown tuna-sub:tuna-sub /var/lib/tuna-subscriptions

mkdir -p /var/log/tuna-subscriptions
chmod 0750 /var/log/tuna-subscriptions
chown tuna-sub:tuna-sub /var/log/tuna-subscriptions

# 4. Копирование исполняемых файлов
echo -e "${CYAN}[*] Установка исполняемых файлов...${NC}"
install -m 0644 "$SCRIPT_DIR/tuna_connection_groups.py" /usr/local/bin/tuna_connection_groups.py
install -m 0755 "$SCRIPT_DIR/tuna-groups.py" /usr/local/bin/tuna-groups
install -m 0755 "$SCRIPT_DIR/tuna-subscriptions.py" /usr/local/bin/tuna-subscriptions

# 5. Копирование конфигурационного файла (если еще не существует)
if [[ ! -f /etc/tuna-subscriptions/config.toml ]]; then
    echo -e "${CYAN}[*] Инициализация конфигурации /etc/tuna-subscriptions/config.toml...${NC}"
    if [[ -f "${SCRIPT_DIR}/config.toml.example" ]]; then
        cp -f "${SCRIPT_DIR}/config.toml.example" /etc/tuna-subscriptions/config.toml
    else
        cat << 'EOF' > /etc/tuna-subscriptions/config.toml
[server]
bind_address = "127.0.0.1"
port = 22217
max_request_body_size = 65536

[database]
path = "/var/lib/tuna-subscriptions/subscriptions.db"

[limits]
max_nickname_length = 64
max_uri_length = 4096
max_users = 1000

[logging]
file = "/var/log/tuna-subscriptions/service.log"
level = "INFO"
EOF
    fi
    chmod 0640 /etc/tuna-subscriptions/config.toml
    chown root:tuna-sub /etc/tuna-subscriptions/config.toml
else
    echo -e "${GREEN}[✓] Конфигурация /etc/tuna-subscriptions/config.toml уже существует (сохранена).${NC}"
fi

# 6. Установка и запуск службы systemd
echo -e "${CYAN}[*] Настройка службы systemd...${NC}"
install -m 0644 "${SCRIPT_DIR}/tuna-subscriptions.service" /etc/systemd/system/tuna-subscriptions.service
systemctl daemon-reload
systemctl enable tuna-subscriptions.service
systemctl restart tuna-subscriptions.service
sleep 1

# 7. Проверка статуса
if systemctl is-active --quiet tuna-subscriptions.service; then
    echo -e "${GREEN}================================================================${NC}"
    echo -e "${GREEN} [✓] Сервис tuna-subscriptions успешно запущен и работает!      ${NC}"
    echo -e "${GREEN}================================================================${NC}"
    echo -e "Адрес API: ${CYAN}http://127.0.0.1:22217${NC}"
    echo -e "База данных: ${CYAN}/var/lib/tuna-subscriptions/subscriptions.db${NC}"
    echo -e "Лог-файл: ${CYAN}/var/log/tuna-subscriptions/service.log${NC}"
    echo -e ""
    echo -e "Пример проверки локального API:"
    echo -e "  curl -s http://127.0.0.1:22217/api/users"
    echo -e "Статус службы:"
    echo -e "  systemctl status tuna-subscriptions"
else
    echo -e "${YELLOW}[!] Служба tuna-subscriptions установлена, но в данный момент не активна.${NC}"
    echo -e "  Проверьте логи: journalctl -u tuna-subscriptions.service -n 20"
fi
