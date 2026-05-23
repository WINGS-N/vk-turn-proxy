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
| `-captcha-solver` | `v1` или `v2` (улучшенный, дефолт). |
| `-tcp-flavor` | `auto` (negotiate) / `direct` (smux над DTLS) / `legacy` (KCP+smux). |
| `-creds-group-size` | Воркеров на TURN identity (default 12). |
| `-session-mode` | `mainline` / `mu` / `auto`. mu - long-lived multi-worker sessions с in-band SessionHello. |
| `-session-id` | Override session ID (hex, 32 chars) для mu mode. |
| `-udp-connect` / `-tcp-connect` (сервер) | Раздельные UDP- и TCP-бэкенды (новый стиль; `-connect` остался как deprecated alias). |
| `-transport` (клиент) | `datagram` или `tcp` (новый стиль вместо deprecated `-vless`). |
| `-protect-sock` (клиент) | Unix-сокет для `VpnService.protect(fd)` IPC, нужен для роутинга от Android. |
| `-tui` (сервер) | `auto` / `on` / `off` - interactive TUI с метриками сессий. |

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
