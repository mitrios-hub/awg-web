package main

// Ключ vpn:// в «родном» формате AmneziaVPN — том же, что приложение делает
// при «Поделиться подключением»: JSON с containers, сжатый qCompress. Обычный
// .conf внутри ключа приложение тоже понимает, но тогда само называет
// подключение «Сервер 1»; в родном формате имя берётся из поля description.
//
// Структура повторяет то, что приложение строит само из импортированного
// .conf (ImportController::extractWireGuardConfig, amnezia-client 5.0.3):
// при импорте результат получается тот же, отличается только имя.

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"

	"awg-web/internal/config"
)

var confDNSRe = regexp.MustCompile(`DNS = (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b).*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)`)

// confFields — «ключ = значение» из всех секций, как читает приложение
// (повторный ключ перекрывает предыдущий).
func confFields(conf string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(conf, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			continue
		}
		if i := strings.Index(t, "="); i > 0 {
			m[strings.TrimSpace(t[:i])] = strings.TrimSpace(t[i+1:])
		}
	}
	return m
}

// amneziaNativeKey упаковывает клиентский .conf в родной формат приложения с
// именем подключения description. ok=false — в конфиге нет обязательных
// полей; тогда стоит отдать обычный amneziaKey(conf).
func amneziaNativeKey(conf, description string) (string, bool) {
	f := confFields(conf)
	host, portStr, err := net.SplitHostPort(f["Endpoint"])
	port, perr := strconv.Atoi(portStr)
	if err != nil || perr != nil || host == "" ||
		f["PrivateKey"] == "" || f["Address"] == "" || f["PublicKey"] == "" {
		return "", false
	}

	last := map[string]any{
		"config":          conf,
		"hostName":        host,
		"port":            port,
		"client_priv_key": f["PrivateKey"],
		"client_ip":       f["Address"],
		"server_pub_key":  f["PublicKey"],
	}
	if v := f["PresharedKey"]; v != "" {
		last["psk_key"] = v
	}
	if v := f["MTU"]; v != "" {
		last["mtu"] = v
	}
	if v := f["PersistentKeepalive"]; v != "" {
		last["persistent_keep_alive"] = v
	}
	allowed := []string{}
	for _, s := range strings.Split(f["AllowedIPs"], ",") {
		if s = strings.TrimSpace(s); s != "" {
			allowed = append(allowed, s)
		}
	}
	last["allowed_ips"] = allowed

	protocol, container := "wireguard", "amnezia-wireguard"
	for _, k := range obfuscationKeys { // имена ключей AWG в приложении совпадают с .conf
		if v := f[k]; v != "" {
			last[k] = v
			protocol, container = "awg", "amnezia-awg"
		}
	}
	if _, ok := last["mtu"]; !ok {
		last["mtu"] = strconv.Itoa(clientMTU)
	}

	lastJSON, err := json.Marshal(last)
	if err != nil {
		return "", false
	}
	server := map[string]any{
		"containers": []any{map[string]any{
			"container": container,
			protocol: map[string]any{
				"last_config":        string(lastJSON),
				"isThirdPartyConfig": true,
				"port":               portStr,
				"transport_proto":    "udp",
			},
		}},
		"defaultContainer": container,
		"description":      description,
		"hostName":         host,
	}
	if m := confDNSRe.FindStringSubmatch(conf); m != nil {
		server["dns1"], server["dns2"] = m[1], m[2]
	}
	data, err := json.Marshal(server)
	if err != nil {
		return "", false
	}
	return amneziaKey(string(data)), true
}

// lookupClientName — имя клиента из clientsTable по его публичному ключу
// ("" — не нашлось). Переменная — чтобы подменять в тестах без docker.
var lookupClientName = func(cfg config.Config, pub string) string {
	entries, err := fetchClients(cfg)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.ClientID == pub {
			return strings.TrimSpace(e.UserData.ClientName)
		}
	}
	return ""
}

// clientConnectionName — имя подключения в приложении у клиента: из настройки
// client_connection_name (одно на всех), иначе имя клиента в панели (ищется
// по публичному ключу, выведенному из PrivateKey конфига), иначе hostname
// сервера, иначе адрес из Endpoint.
func clientConnectionName(cfg config.Config, conf string) string {
	if n := strings.TrimSpace(cfg.ClientConnectionName); n != "" {
		return n
	}
	if pub, ok := pubFromConf(conf); ok {
		if n := lookupClientName(cfg, pub); n != "" && n != "—" {
			return n
		}
	}
	if hostName != "" {
		return hostName
	}
	if h, _, err := net.SplitHostPort(confFields(conf)["Endpoint"]); err == nil {
		return h
	}
	return "AmneziaWG"
}

// clientKey — ключ для страницы /conf/: родной формат с именем, а если
// конфиг почему-то не разобрался — обычный .conf в ключе.
func clientKey(cfg config.Config, conf string) string {
	if k, ok := amneziaNativeKey(conf, clientConnectionName(cfg, conf)); ok {
		return k
	}
	return amneziaKey(conf)
}
