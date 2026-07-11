# awg-web — быстрый старт

Предусловие: на сервере (Linux x86_64) **уже запущен контейнер AmneziaWG**
(`amnezia-awg`) — его ставит и обновляет нативное приложение Amnezia. awg-web
работает параллельно и контейнер НЕ создаёт.

Два пути: установщик (проще) или вручную.

---

## Способ A — установщик (рекомендуется)

Кросс-платформенный бинарник сам по SSH проверит контейнер и развернёт панель
(бинарник awg-web + static + config + systemd). Ничего качать на сервере не
нужно — всё встроено в установщик.

1. Возьми бинарник под свою ОС из `dist/`:
   - Windows — `awg-web-installer-windows-amd64.exe`
   - Linux — `awg-web-installer-linux-amd64`
   - macOS — `awg-web-installer-macos-intel` (Intel) / `awg-web-installer-macos-apple-silicon` (Apple Silicon)
2. Запусти и ответь на вопросы: адрес сервера, доступ (пароль/SSH-ключ), порт
   панели, логин/пароль панели, внешний адрес, режим доступа (только
   localhost+SSH-туннель / публичный порт).
3. Готово — установщик напечатает URL панели.

Всё то же можно задать флагами (для автоматизации), список — `installer -h`:

```
awg-web-installer-linux-amd64 \
  -host СЕРВЕР -user root -password 'ПАРОЛЬ' \
  -web-port 10001 -admin-user admin -admin-pass 'ПАРОЛЬ_ПАНЕЛИ' \
  -endpoint СЕРВЕР -expose local -yes
```

### Собрать установщики самому

Установщик встраивает свежий linux-бинарник awg-web + `static/` (через
`go:embed`), поэтому сначала кладём ассеты, потом собираем 4 цели в `dist/`:

```bash
mkdir -p cmd/installer/assets/static
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cmd/installer/assets/awg-web .
cp static/* cmd/installer/assets/static/

CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/awg-web-installer-windows-amd64.exe        ./cmd/installer
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/awg-web-installer-linux-amd64             ./cmd/installer
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/awg-web-installer-macos-intel            ./cmd/installer
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/awg-web-installer-macos-apple-silicon    ./cmd/installer
```

`dist/` и `cmd/installer/assets/` — в `.gitignore` (бинарники не тащим в git;
установщик запускается на машине админа, не на сервере).

---

## Способ B — вручную (готовый бинарник)

Всё уже собрано (Go 1.22, linux/amd64, статическая линковка — работает на любом
Linux x86_64 без установки Go).

### 1. Скопировать на сервер

```bash
scp -r awg-web hashpw static config.example.json awg-web.service user@сервер:/tmp/
ssh user@сервер
sudo mkdir -p /opt/awg-web && sudo mv /tmp/{awg-web,hashpw,static,awg-web.service} /opt/awg-web/
cd /opt/awg-web
sudo cp /tmp/config.example.json config.json
sudo chmod +x awg-web hashpw && sudo chmod 600 config.json
```

### 2. Задать логин и пароль

```bash
sudo ./hashpw -config ./config.json -user admin
```

Спросит пароль дважды (ввод скрыт), запишет bcrypt-хэш в `config.json`.

### 3. Поправить config.json

```json
{
  "listen_addr": "0.0.0.0:10001",
  "container": "amnezia-awg",
  "wg_interface": "wg0",
  "clients_table_path": "/opt/amnezia/awg/clientsTable",
  "wg_conf_path": "/opt/amnezia/awg/wg0.conf",
  "client_endpoint": "АДРЕС_ИЛИ_ДОМЕН",
  "client_dns": "1.1.1.1, 1.0.0.1",
  "auth_user": "admin",
  "auth_pass_hash": "...",
  "tls_cert_path": "",
  "tls_key_path": "",
  "traffic_state_path": "./awg-web-traffic.json"
}
```

Поменяй имя контейнера/порт при необходимости. `client_endpoint` можно указать
без порта — определится через `docker port`. Для TLS укажи
`tls_cert_path`/`tls_key_path` (иначе HTTP — см. предупреждение ниже).

### 4. Проверить руками

```bash
sudo ./awg-web -config ./config.json
```

Открой `http://IP-сервера:10001` — должен спросить логин/пароль. Ctrl+C и дальше
к systemd.

### 5. Поставить как systemd-сервис

```bash
sudo cp awg-web.service /etc/systemd/system/awg-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now awg-web
sudo systemctl status awg-web
```

Сервис поднимется на 10001/tcp и будет стартовать при перезагрузке.

### Смена пароля позже

```bash
cd /opt/awg-web
sudo ./hashpw -config ./config.json -user admin
sudo systemctl restart awg-web
```

---

## ⚠️ Перед тем как открывать порт наружу

Без TLS Basic Auth передаёт пароль практически открытым текстом (base64, не
шифрует). Варианты:

- **Только localhost + SSH-туннель** (в установщике — режим `local`): панель
  слушает `127.0.0.1`, заходишь `ssh -L 10001:127.0.0.1:10001 user@сервер`.
- **TLS**: укажи `tls_cert_path`/`tls_key_path` (сертификат Let's Encrypt через
  `certbot certonly --standalone -d твой-домен`).
- Плюс файрвол, ограничивающий доступ к порту по IP.

---

## Восстановление сервера из бэкапа

Отдельного шага в установке не нужно: экспорт и импорт резервной копии
(клиенты или полная идентичность сервера) делаются **в самой панели** после
развёртывания (раздел «Резерв»).
