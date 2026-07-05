
## WEB-приложение для контроля клиентов Amnezia-VPN

### Описание
**ВНИМАНИЕ** при изменении конфига перезапустить сервис `systemctl restart awg-web`!
**ВНИМЕНИЕ** при изменении формата конфига и полей исправить файлы на серверах!

Amneia VPN не умет блокировать/разблокировать доступ пользователей, неудобно смотреть статистику и кто онлайн, обслуживать подключения крайне неудобно. В данном коде реализовано WEB-приложение, которое выполняет задачи, аналогичные [[amnezia_userctl_tui|TUI приложению]]:
- достает из docker контейнера `amnezia-awg` данные клиентов
- показывает таблицу подключенных клиентов и данные пира, плюс статус блокировки
- умеет блокировать/разблокировать клиентов через RAW таблицу сетевого фильтра (блокировка и разблокировка производятся внутри контейнера, в котором уже есть утилита `iptables`)

Если внутри контейнера нет `iptables`, то установить: `pkg add iptables`

Для работы с WEB приложением обязательно:
- выбрать порт WEB (по умолчанию `10001`)
- должен работать контейнер Amnezia (по умолчанию `amnezia-awg`)
- интерфейс контейнера по умолчанию `wg0` (внутри контейнера)
- для перевыпуска сертификатов указать ENDPOINT:PORT в конфиге
- можно указать свои DNS для перевыпуска конфига клиента
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
  "wg_conf_path": "/opt/amnezia/awg/wg0.conf",
  "client_endpoint": "ADDR_OR_NAME:PORT",
  "client_dns": "1.1.1.1, 1.0.0.1",
  "auth_user": "admin",
  "auth_pass_hash": "",
  "tls_cert_path": "",
  "tls_key_path": ""
}
```

### Установка приложения из репозитория git
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
