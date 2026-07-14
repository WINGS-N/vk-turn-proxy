# WINGS V VKTP

WINGS V VKTP - форк [vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) для работы с клиентами [WINGS V](https://github.com/WINGS-N/WINGSV).

Проброс трафика WireGuard/Xray через TURN сервера ВК звонков. Пакеты идут параллельными потоками через TURN-сервер по протоколу STUN ChannelData, на peer-сервере распаковываются и форвардятся в WireGuard (или TCP-бэкенд для VLESS-режима). Логин/пароль от TURN генерируются из ссылки на звонок.

## Чем отличается от upstream

- **WRAP SRTP-mimicry obfuscation** - между DTLS-туннелем и UDP-сокетом добавлен слой AEAD-шифрования (`SRTP-AES-GCM` или `SRTP-ChaCha20-Poly1305`), который маскирует DTLS-трейлер под SRTP-пакет. Это обходит content-фильтрацию VK на канале ChannelData.
- **In-band negotiation ключей WRAP через mu/v1 SessionHello** - клиент может предложить ключ в handshake, серверу не нужен предустановленный.
- **DoH-фоллбэк** - клиент умеет в DNS-over-HTTPS, включая встроенный список endpoint'ов с bootstrap-IP, чтобы не зависеть от системного резолвера.
- **TURN address rotation** - на ошибку dial'а клиент пробует следующий TURN-адрес из VK-credential до того как пометить ссылку битой.
- **mu/v1 session protocol** - длинноживущие multi-worker сессии без передоговорки на каждый поток.

## Установка сервера

Скачать бинарник:

```bash
curl -L -o server https://github.com/WINGS-N/vk-turn-proxy/releases/latest/download/server-linux-amd64 && chmod +x server
```

Релизы собираются под несколько платформ и архитектур - имя ассета `server-<os>-<arch>`:

- **linux**: `amd64`, `arm64`, `386`, `arm` (v7), `mipsle`, `mips`, `mips64le`, `riscv64`
- **windows**: `amd64`, `386`, `arm64` (с суффиксом `.exe`)
- **android**: `arm64`, `arm`

Сервер под darwin (macOS) не собирается - тянет linux-only netlink/wg-apply; там доступен только клиент.

Запуск:

```bash
./server -listen 0.0.0.0:56000 -udp-connect 127.0.0.1:<порт wg>
```

### systemd

`/etc/systemd/system/vk-turn-proxy.service`:

```ini
[Unit]
Description=VK Turn Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/vk-turn-proxy/server-linux-amd64 -listen 0.0.0.0:56000 -udp-connect 127.0.0.1:<wg_port>
KillMode=process
Restart=always
RestartSec=5
User=nobody
Group=nogroup
StandardOutput=append:/var/log/vk-turn-proxy/vk-turn-proxy.log
StandardError=append:/var/log/vk-turn-proxy/vk-turn-proxy_error.log
SyslogIdentifier=vk-turn-proxy

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now vk-turn-proxy
```

## Клиент

Основной клиент - Android-приложение [WINGS V](https://github.com/WINGS-N/WINGSV). Все ниже перечисленные флаги доступны в его настройках VK TURN.

Для отладки клиент можно запустить вручную:

```bash
curl -L -o client https://github.com/WINGS-N/vk-turn-proxy/releases/latest/download/client-android-arm64 && chmod +x client
./client -listen 127.0.0.1:9000 -peer <ip сервера>:56000 -vk-link <VK ссылка>
```

Клиент собирается под `linux`, `windows` (`.exe`), `darwin` (macOS, amd64/arm64) и `android` - ассет `client-<os>-<arch>`.

В клиентском конфиге WireGuard поменять адрес сервера на `127.0.0.1:9000`, MTU 1280.

### AllowedIPs

В конфиге WireGuard клиента строка:

```
AllowedIPs = 0.0.0.0/0, ::0
```

означает "разрешить весь интернет". Для VK TURN нужно исключить IP адреса ВК (диапазон `155.212.192.0/20`, к которому клиент подключается для звонков), иначе подключение к TURN зациклится через туннель.

Замените `AllowedIPs` на вариант с исключённым VK-диапазоном:

```
AllowedIPs = 0.0.0.0/1, 128.0.0.0/4, 144.0.0.0/5, 152.0.0.0/7, 154.0.0.0/8, 155.0.0.0/9, 155.128.0.0/10, 155.192.0.0/12, 155.208.0.0/14, 155.212.0.0/17, 155.212.128.0/18, 155.212.208.0/20, 155.212.224.0/19, 155.213.0.0/16, 155.214.0.0/15, 155.216.0.0/13, 155.224.0.0/11, 156.0.0.0/6, 160.0.0.0/3, 192.0.0.0/2
```

Для подсчёта собственного списка исключений: [procustodibus AllowedIPs calculator](https://www.procustodibus.com/blog/2021/03/wireguard-allowedips-calculator/).

## Конфигурация (TOML)

Современный способ настроить сервер - файл `/etc/wings/vktp/config.toml` (путь переопределяется env-переменной `WINGS_VKTP_CONFIG`). Флаги при этом можно вообще не передавать в unit.

- Формат - плоский TOML-сабсет `ключ = значение`, где **имя ключа совпадает с именем флага** (без ведущего `-`): `listen`, `udp-connect`, `grpc-token`, `panel-grpc`, `node-id` и т.д. Вложенные таблицы и массивы не поддерживаются.
- Приоритет: **флаг командной строки > файл > встроенный дефолт**. То есть флаг всегда перекрывает значение из файла.
- На первом запуске (если файла ещё нет) сервер сам пишет туда самодокументированный шаблон: сконфигурированные опции - активными строками, остальные - закомментированными с их дефолтами. После этого флаги можно убрать из unit и править только файл.
- Неизвестный ключ (опечатка) игнорируется, а не роняет старт.

Пример `config.toml`:

```toml
listen = "0.0.0.0:56000"
udp-connect = "127.0.0.1:51820"
# управляющий API для панели
grpc-listen = "0.0.0.0:25612"
grpc-token = "<token>"
# обратный канал к панели
panel-grpc = "panel.example.org:9091"
node-id = "<node-id>"
# managed WireGuard
wg-apply = true
wg-key-file = "/etc/wings/vktp/wg.key"
```

Флаги ниже остаются полностью рабочими и удобны для отладки/ручного запуска; в проде предпочтителен `config.toml`.

## Флаги

### WRAP SRTP-mimicry

Слой обфускации поверх DTLS, маскирует payload под SRTP-кадр чтобы пройти content-фильтр на ChannelData.

**Сервер:**

| Флаг | Default | Описание |
|---|---|---|
| `-wrap-mode` | `on` | `off` - игнорировать WRAP-предложения клиента; `on` - принимать. |
| `-wrap-cipher` | `any` | Допустимые AEAD: `any`, `srtp-aes-gcm`, `srtp-chacha20-poly1305`. |
| `-wrap-key` | empty | Фиксированный 32-byte ключ (64 hex chars). Если задан, перекрывает client proposal. |
| `-wrap-accept-client-keys` | `true` | Принимать `wrap_key_proposal` из SessionHello клиента когда `-wrap-key` пуст. Отключить чтобы заставить сервер использовать только свой preset. |

**Клиент:**

| Флаг | Default | Описание |
|---|---|---|
| `-wrap-mode` | `off` | `off` / `preferred` (fallback на raw при отказе сервера) / `required` (fail connect при отказе). |
| `-wrap-cipher` | `srtp-aes-gcm` | `srtp-aes-gcm` или `srtp-chacha20-poly1305`. |
| `-wrap-key` | empty | 32-byte ключ в hex. Если пусто и mode != off, генерируется при старте. |
| `-wrap-send-key` | `true` | Передавать `wrap_key_proposal` в mu/v1 SessionHello. Отключить чтобы сервер использовал свой preset. |

### DNS

| Флаг | Default | Описание |
|---|---|---|
| `-dns` | `auto` | `auto` (UDP/53 с фоллбэком на DoH), `udp`, `doh`. |
| `-user-dns` | empty | Пользовательские резолверы перед встроенным списком. Форматы: `https://host/dns-query` (DoH), `udp://ip[:port]` или `ip[:port]` (UDP/53). Разделители: запятая или newline. |

### Прочие новые/изменённые флаги

| Флаг | Описание |
|---|---|
| `-vk-link` | Принимает comma-separated список ссылок (priority order). |
| `-vk-link-secondary` | Фоллбэк-ссылка для случая когда все primary в cooldown. |
| `-captcha-solver` | `bypass` / `v2` (дефолт) / `v1`. `bypass` - captcha-free путь через VK Calls (`api.vk.me` / VK Connect) с legacy-солвером как фолбэк; `v2` - улучшенный солвер; `v1` - старый. |
| `-manual-captcha` | Пропустить авто-решение капчи и сразу уйти в ручной браузерный флоу. |
| `-vk-auth` | `anonymous` (дефолт) / `account`. В `account` реле запрашивает у хост-приложения вход в VK-аккаунт (WebView) и получает turn_server creds обратно. |
| `-browser-fp` | Семейство браузерного фингерпринта для HTTP+TLS impersonation: `safari` (дефолт) / `chrome` / `edge` / `firefox` / `auto` (случайный на сессию). |
| `-tcp-flavor` | `auto` (negotiate) / `direct` (smux над DTLS) / `legacy` (KCP+smux). |
| `-creds-group-size` | Воркеров на TURN identity (default 12). |
| `-session-mode` | `mainline` / `mu` / `auto`. mu - long-lived multi-worker sessions с in-band SessionHello. |
| `-session-id` | Override session ID (hex, 32 chars) для mu mode. |
| `-udp-connect` / `-tcp-connect` (сервер) | Раздельные UDP- и TCP-бэкенды (новый стиль; `-connect` остался как deprecated alias). |
| `-transport` (клиент) | `datagram` или `tcp` (новый стиль вместо deprecated `-vless`). |
| `-protect-sock` (клиент) | Unix-сокет для `VpnService.protect(fd)` IPC, нужен для роутинга от Android. |
| `-tui` (сервер) | `auto` / `on` / `off` - interactive TUI с метриками сессий. |

## Интеграция с панелью WINGS V

Сервер умеет работать как управляемая нода панели [WINGS V](https://github.com/WINGS-N/v.wingsnet.org): панель по gRPC программирует WireGuard-пиры (managed-клиенты), а сервер по обратному каналу тянет с панели конфиг и лимиты трафика. Проще всего подключить ноду скриптом `connect.sh` с панели, который сам пишет `config.toml`; ниже - соответствующие флаги.

**Management API (панель -> реле):**

| Флаг | Default | Описание |
|---|---|---|
| `-grpc-listen` | empty | `ip:port` управляющего API для панели (пусто - выключено). |
| `-grpc-token` | empty | Bearer-токен, который панель предъявляет на управляющем API. Он же используется как bearer в обратную сторону (единый токен). |
| `-grpc-cert` / `-grpc-key` | empty | TLS-серт/ключ для управляющего API (пусто - плейнтекст). |

**Обратный канал (реле -> панель, DTLS PROVISION):**

| Флаг | Default | Описание |
|---|---|---|
| `-panel-grpc` | empty | Provisioning gRPC endpoint панели, включает DTLS PROVISION-путь. |
| `-panel-ca-pin` | empty | SPKI-пин CA панели (`sha256/<base64>`) для self-signed панели; пусто - проверка через системный trust. |
| `-panel-insecure` | `false` | Дозваниваться до панели по plaintext h2c вместо TLS (только доверенная локальная сеть). |
| `-node-id` | empty | ID этой ноды, как она зарегистрирована в панели. |

**Managed WireGuard (программирование пиров ядром):**

| Флаг | Default | Описание |
|---|---|---|
| `-wg-apply` | `false` | Программировать пиры на живой kernel-WG интерфейс (нужен root). |
| `-wg-interface` | `wg-wingsv` | Имя туннельного интерфейса. |
| `-wg-listen-port` | `51820` | Порт WireGuard-интерфейса. |
| `-wg-address` | `10.66.66.1/24` | Адрес WireGuard-интерфейса (CIDR). |
| `-wg-tunnel-cidr` | `10.66.66.0/24` | Пул адресов для managed-пиров. |
| `-wg-key-file` | empty | Путь для персиста приватного WG-ключа сервера, чтобы публичный ключ был стабилен между рестартами (пусто - генерируется заново каждый старт). |

## VLESS-режим

`-transport=tcp` (или `-vless`) пробрасывает TCP-стримы через TURN-туннель с помощью KCP/smux вместо UDP-датаграмм.

Сервер:

```bash
./server -listen 0.0.0.0:56000 -tcp-connect 127.0.0.1:443 -transport=tcp
```

Клиент:

```bash
./client -peer <ip сервера>:56000 -vk-link <VK ссылка> -listen 127.0.0.1:9000 -transport=tcp
```

Затем подключить любой VLESS-клиент к `127.0.0.1:9000`.

## Direct mode

`-no-dtls` отправляет пакеты без DTLS-обфускации (можно подключиться к обычному WireGuard). Может привести к бану VK - использовать на свой страх.
