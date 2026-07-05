package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config — все настраиваемые параметры сервера, хранятся в JSON-файле
// рядом с бинарником (по умолчанию ./config.json).
type Config struct {
	// ListenAddr — адрес и порт, на котором слушает сервер.
	// "0.0.0.0:10001" — слушать на всех интерфейсах, порт 10001.
	ListenAddr string `json:"listen_addr"`

	Container        string `json:"container"`
	WgInterface      string `json:"wg_interface"`
	ClientsTablePath string `json:"clients_table_path"`
	// WgConfPath — путь к файлу конфигурации интерфейса (wg0.conf) внутри
	// контейнера. Нужен для функции "Перевыпустить" — оттуда читаются
	// параметры обфускации (Jc/Jmin/Jmax/S1/S2/H1-H4) и куда пишется новый
	// публичный ключ пира при перевыпуске.
	WgConfPath string `json:"wg_conf_path"`

	// ClientEndpoint — публичный адрес сервера (host:port), который
	// прописывается в генерируемых клиентских конфигах как Endpoint.
	// Сервер не может определить это сам (изнутри контейнера не видно
	// собственного публичного IP), поэтому задаётся явно. Без этого поля
	// функция "Перевыпустить" работать не будет.
	ClientEndpoint string `json:"client_endpoint"`
	// ClientDNS — DNS-серверы, прописываемые в генерируемый конфиг клиента.
	ClientDNS string `json:"client_dns"`

	AuthUser string `json:"auth_user"`
	// AuthPassHash — bcrypt-хэш пароля. НЕ хранит пароль в открытом виде.
	// Формируется утилитой ./hashpw (см. cmd/hashpw).
	AuthPassHash string `json:"auth_pass_hash"`

	// TLSCertPath / TLSKeyPath — пути к сертификату и приватному ключу.
	// Если оба поля пустые — сервер поднимается по обычному HTTP
	// (незашифрованное соединение). Если заполнено только одно из двух —
	// это ошибка конфигурации, сервер откажется стартовать.
	TLSCertPath string `json:"tls_cert_path"`
	TLSKeyPath  string `json:"tls_key_path"`
}

func DefaultConfig() Config {
	return Config{
		ListenAddr:       "0.0.0.0:10001",
		Container:        "amnezia-awg",
		WgInterface:      "wg0",
		ClientsTablePath: "/opt/amnezia/awg/clientsTable",
		WgConfPath:       "/opt/amnezia/awg/wg0.conf",
		ClientDNS:        "1.1.1.1, 1.0.0.1",
		AuthUser:         "admin",
	}
}

// LoadConfig читает конфиг из файла. Если файла нет — возвращает конфиг
// по умолчанию (вызывающий код сам решает, фатально это или нет).
func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, fmt.Errorf("файл конфигурации %s не найден", path)
		}
		return cfg, fmt.Errorf("не удалось прочитать %s: %w", path, err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("не удалось разобрать %s как JSON: %w", path, err)
	}
	return cfg, nil
}

// SaveConfig сохраняет конфиг в файл в читаемом виде (с отступами).
// Используется утилитой hashpw при обновлении пароля.
func SaveConfig(path string, cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать конфиг: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("не удалось записать %s: %w", path, err)
	}
	return nil
}
