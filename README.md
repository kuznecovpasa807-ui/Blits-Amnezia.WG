# Blitz AmneziaWG Panel

Веб-панель для AmneziaWG VPN с установкой одной командой.

## Что умеет

- создает и редактирует VPN-клиентов;
- выдает конфиги и QR-коды для AmneziaVPN;
- поддерживает Amnezia 2.0 / 3.1 и Amnezia 1 / Legacy;
- настраивает полный и раздельный туннель;
- добавляет маршруты Google/YouTube для split tunnel;
- меняет порт, домен, язык, секретный web path и пароль из панели;
- делает бэкапы и восстановление;
- дает серверное меню командой `blits`;
- после установки запускает self-check и показывает, что работает.

## Быстрая установка

Запустите на чистом Ubuntu/Debian сервере от root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Blits-dev-vibe/Blits-Amnezia.WG/main/install.sh)
```

Автоматическая установка без вопросов:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Blits-dev-vibe/Blits-Amnezia.WG/main/install.sh) --yes
```

С доменом и HTTPS:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Blits-dev-vibe/Blits-Amnezia.WG/main/install.sh) --domain vpn.example.com --email admin@example.com
```

## Управление

После установки откройте меню:

```bash
blits
```

В меню можно посмотреть адрес панели, сменить порт или домен, включить HTTPS, перегенерировать секретный путь и API token, сменить пароль, посмотреть логи, сделать бэкап и перезапустить панель.

## Проверка

Проверить сервер можно командой:

```bash
cd /opt/blitz-amnezia-panel
bash check_server.sh
```

Короткая проверка:

```bash
bash check_server.sh --quick
```

## Обновление

```bash
cd /opt/blitz-amnezia-panel
git pull origin main
docker compose up -d --build
```

Если включен HTTPS:

```bash
docker compose --profile ssl up -d --build
```

## Важно

Не публикуйте базу, приватные ключи, `.env`, токены и бэкапы. В них находятся доступы к панели и VPN.

## Лицензия

MIT
