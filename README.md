## Установка и интерфейс
Смотри QUICKSTART.md в коревой директории

## WEB-приложение для контроля клиентов Amnezia-VPN

![Смотри ScreenShot.png в корневой директории](ScreenShot.png?raw=true)

### Описание
**ВНИМАНИЕ** при изменении конфига перезапустить сервис `systemctl restart awg-web`!

**ВНИМАНИЕ** при изменении формата конфига и полей исправить файлы на серверах!

Amnezia VPN не умеет удобно управлять клиентами: блокировать/разблокировать, смотреть статистику и кто онлайн, добавлять/удалять пиров без десктопного приложения. awg-web — параллельная веб-панель поверх уже поднятого контейнера `amnezia-awg` (сам контейнер ставит и обновляет нативное приложение Amnezia; панель его НЕ создаёт).

Возможности:
- таблица клиентов из контейнера `amnezia-awg` (имя, IP, endpoint, объём трафика, последний handshake, статус) — обновляется **инкрементально раз в секунду**, без перерисовки и мигания;
- **блокировка/разблокировка** клиента (iptables RAW внутри контейнера);
- **перевыпуск** конфига клиента — новая пара ключей + QR, тот же IP/имя/PSK (старый утерянный ключ инвалидируется);
- **добавление/удаление** клиентов в нативном формате Amnezia (совместимо с приложением: пир в `wg0.conf` + запись в `clientsTable`, применяется через `wg syncconf` без даунтайма);
- **учёт трафика** по клиентам (iptables mangle-счётчики в FORWARD), **персистентный** — переживает перезапуск контейнера и awg-web; первичный сид берётся из накопительных полей Amnezia (`dataReceived`/`dataSent`);
- **резервная копия / восстановление** сервера прямо в панели — экспорт бандла и импорт в двух режимах: только клиенты (пиры) либо полная идентичность сервера (ключи+PSK+обфускация; тогда старые клиентские конфиги остаются валидны, нужен лишь DNS);
- тёмная/светлая тема, поиск по имени/IP, фильтры (онлайн/заблокированные/не подключались).

Внутри контейнера обычно есть `iptables`. Если нужно установить: `apk add iptables` (образ Amnezia на Alpine).

Для работы с WEB приложением обязательно:
- выбрать порт WEB (по умолчанию `10001`)
- должен работать контейнер Amnezia (по умолчанию `amnezia-awg`)
- интерфейс контейнера по умолчанию `wg0` (внутри контейнера)
- для перевыпуска сертификатов указать ENDPOINT:PORT в конфиге
- можно указать свои DNS для перевыпуска конфига клиента
- рекомендуется использовать сертификаты TLS для WEB-сайта
- создать пароль с помощью утилиты `hashpw`

Сертификаты можно создать через Let's encrypt.

Пример конфига перед запуском приложения (config.json):
```json
{
  "listen_addr": "0.0.0.0:10001",
  "container": "amnezia-awg",
  "wg_interface": "wg0",
  "clients_table_path": "/opt/amnezia/awg/clientsTable",
  "wg_conf_path": "/opt/amnezia/awg/wg0.conf",
  "client_endpoint": "ADDR_OR_NAME[:PORT]",
  "client_dns": "1.1.1.1, 1.0.0.1",
  "auth_user": "admin",
  "auth_pass_hash": "",
  "tls_cert_path": "",
  "tls_key_path": "",
  "traffic_state_path": "./awg-web-traffic.json"
}
```
- `client_endpoint` можно указать только адресом/доменом без порта — порт панель определит сама через `docker port`.
- `traffic_state_path` — файл на диске хоста, где копится трафик по клиентам (переживает перезапуск). Пустая строка отключает персистентность.

### Установка установщиком (рекомендуется)
Кросс-платформенный установщик (Windows/Linux/macOS) сам по SSH проверит сервер и развернёт панель: зальёт встроенные бинарник awg-web + `static`, напишет `config.json` и systemd-юнит, запустит сервис. Контейнер `amnezia-awg` должен быть уже поднят нативным приложением Amnezia — установщик его НЕ создаёт.

Запусти бинарник под свою ОС из `dist/` (собираются из `cmd/installer`, см. QUICKSTART.md):
- `awg-web-installer-windows-amd64.exe`
- `awg-web-installer-linux-amd64`
- `awg-web-installer-macos-intel` / `awg-web-installer-macos-apple-silicon`

Мастер спросит: адрес сервера, доступ (пароль или SSH-ключ), порт панели, логин/пароль панели (хэш bcrypt считается локально, на сервер уходит только хэш), внешний адрес, режим доступа (только localhost + SSH-туннель / публичный порт + `ufw`). Всё то же можно задать флагами — `installer -h`.

### Установка приложения из репозитория git (вручную)
Если файлы на локальном хосте, то:
скопировать файлы в каталог `/opt/awg-web` сервера-хоста, в котором контейнер.
Пример (если порт 22 - можно не указывать):
```powershell
scp -P 22 -r .\awg-web\* user@yoursite.domain:/opt/awg-web/
```

Установка из GIT:
Пример:
```bash
# каталог /opt вероятно уже есть
cd /opt || { echo "Is the Amneizia AWG installed?"; exit 1; }

# скачать репо
#git config --global credential.helper store
git clone https://gitflic.ru/project/mitrios/awg-web.git
cd cd awg-web/

# Узнать порт контейнера для конфига (в конфиге использовать IP или NAME по необходимости)
docker port amnezia-awg | awk -F'[:/]' '{print $3}'

# Конфиг создать и исправить его!
cp config.example.json config.json
chmod 600 config.json

# если нет сертификата у сервера но есть доменное имя (ОТКРЫТЬ ПОРТ 80)
#iptables -P INPUT ACCEPT
#certbot certonly --standalone -d yoursite.com
#iptables -P INPUT DROP

# Задать пароль - по умолчанию или с явным указанием конфига и юзернейма
./hashpw
#./hashpw -config ./config.json -user admin

# Запустить сервис
sudo cp awg-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now awg-web
```

При запуске `#certbot certonly --standalone -d yoursite.com` для получения сертификата, вывод:
```
...
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/yoursite.com/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/yoursite.com/privkey.pem
...
```
Эти пути и файлы сертификатов прописать в кавычках в конфиге (ниже)

Вот состав файлов:
```sql
├── QUICKSTART.md
├── awg-web
├── awg-web.service
├── config.json
├── hashpw
└── static
    ├── app.js
    ├── index.html
    └── style.css
```



Если нужно проверить без сервиса - разовый запуск:
```bash
# Выход C-c
/opt/awg-web/awg-web -config /opt/awg-web/config.json
```
