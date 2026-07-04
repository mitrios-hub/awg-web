## WEB-приложение для контроля клиентов Amnezia-VPN

### Описание
Amneia VPN не умет блокировать/разблокировать доступ пользователей, неудобно смотреть статистику и кто онлайн, обслуживать подключения крайне неудобно. В данном коде реализовано WEB-приложение, которое выполняет задачи, аналогичные [[amnezia_userctl_tui|TUI приложению]]:
- достает из docker контейнера `amnezia-awg` данные клиентов
- показывает таблицу подключенных клиентов и данные пира, плюс статус блокировки
- умеет блокировать/разблокировать клиентов через RAW таблицу сетевого фильтра (блокировка и разблокировка производятся внутри контейнера, в котором уже есть утилита `iptables`)

Если внутри контейнера нет `iptables`, то установить: `pkg add iptables`

Для работы с WEB приложением обязательно:
- выбрать порт WEB (по умолчанию `10001`)
- должен работать контейнер Amnezia (по умолчанию `amnezia-awg`)
- интерфейс контейнера по умолчанию `wg0` (внутри контейнера)
- рекомендуется использовать сертификаты TLS для WEB-сайта
- создать пароль с помощью утилиты `hashpw`

Сертификаты можно создать через [[install_x-ui#Основной способ|Let's encrypt]]

Вот пример конфига перед запуском приложения:
```json
└─# cat config.json
{
  "listen_addr": "0.0.0.0:10001",
  "container": "amnezia-awg",
  "wg_interface": "wg0",
  "clients_table_path": "/opt/amnezia/awg/clientsTable",
  "auth_user": "admin",
  "auth_pass_hash": "$2a$10$XunIzOVbXAJYNR7r6pOS4.6MZTdOPFiZsUtezIJ6Fkb/XByKvz4zG",
  "tls_cert_path": "/root/cert/yoursite.domain/fullchain.pem",
  "tls_key_path": "/root/cert/yoursite.domain/privkey.pem"
```

### Установка приложения
Скачать приложение. Вот состав файлов:
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
Скопировать файлы в каталог `/opt/awg-web` сервера-хоста, в котором контейнер. Проверить наличие и имя контейнеров:
`docker ps -a`
`docker ps -a | grep amnezia`

Права на конфиг:
```bash
sudo chmod 600 config.json
```

Задать имя админа и пароль (имя юзера и хэш пароля сохраняются в конфиге)
```bash
./hashpw -config ./config.json -user admin
```

Создать сервис приложения (автозапуск и работа как сервис)
```bash
sudo cp awg-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now awg-web
```

Если нужно проверить без сервиса - разовый запуск:
```bash
# Выход C-c
/opt/awg-web/awg-web -config /opt/awg-web/config.json
```
