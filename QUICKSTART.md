# awg-web — установка готового бинарника (без сборки)

Всё уже собрано (Go 1.22, linux/amd64, статическая линковка — работает
на любом Linux x86_64 без установки Go). Нужно просто скопировать,
задать пароль и запустить.

## 1. Скопировать на сервер

```bash
scp -r awg-web-dist user@сервер:/tmp/
ssh user@сервер
sudo mv /tmp/awg-web-dist /opt/awg-web
cd /opt/awg-web
chmod +x awg-web hashpw
```

## 2. Задать логин и пароль

```bash
./hashpw -config ./config.json -user admin
```

Спросит пароль дважды (ввод скрыт), запишет bcrypt-хэш в `config.json`.

## 3. (опционально) Поправить config.json

Открой `config.json` — по умолчанию там:

```json
{
  "listen_addr": "0.0.0.0:10001",
  "container": "amnezia-awg",
  "wg_interface": "wg0",
  "clients_table_path": "/opt/amnezia/awg/clientsTable",
  ...
}
```

Поменяй, если у тебя другое имя контейнера/порт/etc. Если хочешь TLS —
укажи `tls_cert_path`/`tls_key_path` (иначе будет обычный HTTP — см.
предупреждение ниже).

## 4. Проверить руками

```bash
./awg-web -config ./config.json
```

Открой `http://IP-сервера:10001` — должен спросить логин/пароль. Останови
(Ctrl+C) и переходи к systemd, чтобы не держать запущенным вручную.

## 5. Поставить как systemd-сервис

```bash
sudo cp awg-web.service /etc/systemd/system/awg-web.service
sudo chmod 600 /opt/awg-web/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now awg-web
sudo systemctl status awg-web
sudo journalctl -u awg-web -f
```

Готово — сервис поднимется на 10001/tcp и будет автоматически стартовать
при перезагрузке сервера.

## Смена пароля позже

```bash
cd /opt/awg-web
sudo ./hashpw -config ./config.json -user admin
sudo systemctl restart awg-web
```

## ⚠️ Перед тем как открывать порт наружу

Без TLS Basic Auth передаёт пароль практически открытым текстом — не
шифрует, просто base64. Варианты:

- Указать `tls_cert_path`/`tls_key_path` в `config.json` (сертификат
  Let's Encrypt через `certbot certonly --standalone -d твой-домен` —
  либо любой другой способ его получить).
- Либо не открывать порт 10001 в интернет вообще, а заходить на панель
  только через сам WireGuard-туннель (слушать на VPN-адресе сервера,
  например `10.8.1.254:10001`).
- Плюс — файрвол, ограничивающий доступ к порту по IP.

Подробности и полное описание всех полей `config.json` — в основном
README.md (в архиве с исходниками, если понадобится).
