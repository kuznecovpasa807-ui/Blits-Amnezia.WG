#!/bin/bash
# Скрипт диагностики сервера для AmneziaWG Web Panel MVP
echo "=== ДИАГНОСТИКА СЕРВЕРА ==="
echo "Время запуска: $(date)"
echo ""

echo "--- Архитектура процессора ---"
uname -m

echo ""
echo "--- Операционная система ---"
if [ -f /etc/os-release ]; then
    cat /etc/os-release | grep -E "^(NAME|VERSION)="
else
    uname -a
fi

echo ""
echo "--- Свободная память ---"
free -h

echo ""
echo "--- Свободное место на диске ---"
df -h /

echo ""
echo "--- Тип виртуализации ---"
if command -v systemd-detect-virt >/dev/null 2>&1; then
    systemd-detect-virt
else
    echo "systemd-detect-virt не найден"
fi

echo ""
echo "--- Прослушиваемые порты (TCP/UDP) ---"
ss -lntup

echo ""
echo "--- Сетевые интерфейсы и IP ---"
ip addr

echo ""
echo "--- Сетевые маршруты ---"
ip route

echo ""
echo "--- Статус UFW (Брандмауэр) ---"
if command -v ufw >/dev/null 2>&1; then
    ufw status verbose
else
    echo "ufw не установлен в системе"
fi

echo ""
echo "--- Проверка утилит WireGuard и AmneziaWG ---"
if command -v wg >/dev/null 2>&1; then
    echo "Стандартный Wireguard (wg): УСТАНОВЛЕН ($(which wg))"
else
    echo "Стандартный Wireguard (wg): НЕ установлен"
fi

if command -v awg >/dev/null 2>&1; then
    echo "AmneziaWG (awg): УСТАНОВЛЕН ($(which awg))"
else
    echo "AmneziaWG (awg): НЕ установлен"
fi

echo ""
echo "=== ДИАГНОСТИКА ЗАВЕРШЕНА ==="
