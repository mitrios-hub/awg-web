// awg-web installer — кросс-платформенный мастер (Windows/Linux/macOS),
// который по SSH разворачивает awg-web на сервере, где УЖЕ поднят контейнер
// AmneziaWG (его пользователь ставит/обновляет нативным приложением Amnezia —
// наш софт работает параллельно и контейнер не создаёт).
//
// Что делает: подключается по SSH → проверяет Docker и наличие запущенного
// контейнера amnezia-awg → спрашивает порт панели, логин/пароль панели, внешний
// адрес и режим доступа → заливает встроенные (go:embed) бинарник awg-web +
// static, пишет config.json и systemd-юнит, запускает сервис.
//
// Значения можно задать флагами (для автоматизации/тестов); чего не хватает —
// спросит интерактивно.
package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

//go:embed assets
var assets embed.FS

const remoteDir = "/opt/awg-web"

type opts struct {
	host, sshPort, user, password, keyPath, keyPass string
	webPort, adminUser, adminPass, endpoint         string
	container, expose                               string
	assumeYes                                       bool
}

func main() {
	var o opts
	flag.StringVar(&o.host, "host", "", "адрес сервера (IP или домен)")
	flag.StringVar(&o.sshPort, "ssh-port", "22", "SSH-порт")
	flag.StringVar(&o.user, "user", "root", "SSH-пользователь")
	flag.StringVar(&o.password, "password", "", "SSH-пароль")
	flag.StringVar(&o.keyPath, "key", "", "путь к приватному SSH-ключу (вместо пароля)")
	flag.StringVar(&o.keyPass, "key-pass", "", "пароль к ключу, если зашифрован")
	flag.StringVar(&o.webPort, "web-port", "10001", "TCP-порт панели awg-web")
	flag.StringVar(&o.adminUser, "admin-user", "admin", "логин панели")
	flag.StringVar(&o.adminPass, "admin-pass", "", "пароль панели")
	flag.StringVar(&o.endpoint, "endpoint", "", "внешний адрес сервера для клиентских конфигов (IP/домен)")
	flag.StringVar(&o.container, "container", "amnezia-awg", "имя контейнера AmneziaWG")
	flag.StringVar(&o.expose, "expose", "", "доступ к панели: local (127.0.0.1 + SSH-туннель) или public")
	flag.BoolVar(&o.assumeYes, "yes", false, "не задавать вопросы (для автоматизации)")
	flag.Parse()

	if err := run(&o); err != nil {
		fmt.Fprintf(os.Stderr, "\n✗ Ошибка: %v\n", err)
		os.Exit(1)
	}
}

var stdin = bufio.NewReader(os.Stdin)

func ask(prompt, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", prompt, def)
	} else {
		fmt.Printf("%s: ", prompt)
	}
	line, _ := stdin.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func askSecret(prompt string) string {
	fmt.Printf("%s: ", prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil { // не TTY (например, пайп) — читаем как обычную строку
		line, _ := stdin.ReadString('\n')
		return strings.TrimSpace(line)
	}
	return strings.TrimSpace(string(b))
}

func run(o *opts) error {
	fmt.Println("== Установщик awg-web ==")
	fmt.Println("Требуется: сервер Linux с уже запущенным контейнером AmneziaWG")
	fmt.Println("(его ставит/обновляет нативное приложение Amnezia — установщик его НЕ создаёт).")
	fmt.Println()

	if o.host == "" {
		o.host = ask("Адрес сервера (IP/домен)", "")
	}
	if o.host == "" {
		return fmt.Errorf("не задан адрес сервера")
	}

	// 1) подключение по SSH
	client, err := connect(o)
	if err != nil {
		return err
	}
	defer client.Close()
	fmt.Printf("✓ SSH-подключение к %s@%s установлено\n", o.user, o.host)

	// 2) проверки окружения
	if out, err := runCmd(client, "docker version --format '{{.Server.Version}}'"); err != nil {
		return fmt.Errorf("Docker на сервере недоступен (%s). Установи Docker и повтори", strings.TrimSpace(out))
	}
	names, _ := runCmd(client, "docker ps --format '{{.Names}}'")
	if !contains(strings.Fields(names), o.container) {
		fmt.Printf("\n✗ Запущенный контейнер %q не найден. Запущенные контейнеры:\n%s\n", o.container, indent(names))
		return fmt.Errorf("сначала подними сервер AmneziaWG нативным приложением Amnezia, затем запусти установщик снова")
	}
	fmt.Printf("✓ Контейнер %s запущен\n", o.container)

	// 3) параметры панели
	if o.webPort == "" {
		o.webPort = ask("Порт панели awg-web", "10001")
	}
	if o.adminUser == "" {
		o.adminUser = ask("Логин панели", "admin")
	}
	for o.adminPass == "" {
		p1 := askSecret("Пароль панели")
		p2 := askSecret("Повтори пароль")
		if p1 != "" && p1 == p2 {
			o.adminPass = p1
		} else {
			fmt.Println("  пароли не совпадают или пустые, ещё раз")
		}
	}
	if o.endpoint == "" {
		detected := detectPublicHost(client, o.host)
		o.endpoint = ask("Внешний адрес сервера для клиентских конфигов (IP/домен)", detected)
	}
	if o.expose == "" {
		fmt.Println("\nДоступ к панели:")
		fmt.Println("  1) local  — слушать только 127.0.0.1, ходить через SSH-туннель (безопасно, рекомендуется)")
		fmt.Println("  2) public — открытый порт (HTTP+Basic Auth), откроется ufw")
		if ask("Выбор (1/2)", "1") == "2" {
			o.expose = "public"
		} else {
			o.expose = "local"
		}
	}
	listenAddr := "127.0.0.1:" + o.webPort
	if o.expose == "public" {
		listenAddr = "0.0.0.0:" + o.webPort
	}

	// 4) bcrypt-хэш пароля панели (локально, пароль на сервер в открытом виде не уходит)
	hash, err := bcrypt.GenerateFromPassword([]byte(o.adminPass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("не удалось захэшировать пароль: %w", err)
	}

	if !o.assumeYes {
		fmt.Printf("\nСтавлю awg-web на %s: порт %s (%s), контейнер %s, endpoint %s\n",
			o.host, o.webPort, o.expose, o.container, o.endpoint)
		if strings.ToLower(ask("Продолжить? (y/n)", "y")) != "y" {
			return fmt.Errorf("отменено пользователем")
		}
	}

	// 5) заливаем бинарник + static
	fmt.Println("\nЗаливаю файлы…")
	if out, err := runCmd(client, "mkdir -p "+shq(remoteDir)); err != nil {
		return fmt.Errorf("не удалось создать %s: %s", remoteDir, out)
	}
	if err := uploadAssets(client); err != nil {
		return err
	}

	// 6) config.json
	cfg := map[string]any{
		"listen_addr":        listenAddr,
		"container":          o.container,
		"wg_interface":       "wg0",
		"clients_table_path": "/opt/amnezia/awg/clientsTable",
		"wg_conf_path":       "/opt/amnezia/awg/wg0.conf",
		"client_endpoint":    o.endpoint,
		"client_dns":         "1.1.1.1, 1.0.0.1",
		"auth_user":          o.adminUser,
		"auth_pass_hash":     string(hash),
		"tls_cert_path":      "",
		"tls_key_path":       "",
		"traffic_state_path": remoteDir + "/awg-web-traffic.json",
	}
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	if err := upload(client, remoteDir+"/config.json", cfgJSON, "600"); err != nil {
		return fmt.Errorf("не удалось записать config.json: %w", err)
	}

	// 7) systemd-юнит
	if err := upload(client, "/etc/systemd/system/awg-web.service", []byte(systemdUnit), "644"); err != nil {
		return fmt.Errorf("не удалось записать systemd-юнит: %w", err)
	}
	if out, err := runCmd(client, "systemctl daemon-reload && systemctl enable --now awg-web"); err != nil {
		return fmt.Errorf("не удалось запустить сервис: %s", out)
	}

	// 8) firewall для публичного режима
	if o.expose == "public" {
		runCmd(client, "command -v ufw >/dev/null 2>&1 && ufw status | grep -q active && ufw allow "+o.webPort+"/tcp || true")
	}

	// 9) проверка (с ретраями — systemd поднимается не мгновенно)
	active := ""
	for i := 0; i < 15; i++ {
		time.Sleep(1 * time.Second)
		out, _ := runCmd(client, "systemctl is-active awg-web")
		if active = strings.TrimSpace(out); active == "active" {
			break
		}
	}
	if active != "active" {
		logs, _ := runCmd(client, "journalctl -u awg-web -n 20 --no-pager 2>&1")
		return fmt.Errorf("сервис не поднялся (статус %q). Лог:\n%s", active, logs)
	}

	fmt.Println("\n✓ Готово! awg-web установлен и запущен.")
	if o.expose == "public" {
		fmt.Printf("  Панель: http://%s:%s\n", o.host, o.webPort)
	} else {
		fmt.Printf("  Панель слушает 127.0.0.1:%s. Доступ через SSH-туннель:\n    ssh -L %s:127.0.0.1:%s %s@%s\n  затем открой http://127.0.0.1:%s\n",
			o.webPort, o.webPort, o.webPort, o.user, o.host, o.webPort)
	}
	fmt.Printf("  Логин: %s (пароль — который ты задал)\n", o.adminUser)
	fmt.Println("  Восстановление сервера из бэкапа — в самой панели (раздел «Резерв»).")
	return nil
}

func connect(o *opts) (*ssh.Client, error) {
	var authm []ssh.AuthMethod
	switch {
	case o.keyPath != "":
		key, err := os.ReadFile(o.keyPath)
		if err != nil {
			return nil, fmt.Errorf("не удалось прочитать ключ %s: %w", o.keyPath, err)
		}
		var signer ssh.Signer
		if o.keyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(key, []byte(o.keyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}
		if err != nil {
			return nil, fmt.Errorf("не удалось разобрать ключ (зашифрован? укажи -key-pass): %w", err)
		}
		authm = append(authm, ssh.PublicKeys(signer))
	default:
		if o.password == "" {
			o.password = askSecret(fmt.Sprintf("SSH-пароль для %s@%s", o.user, o.host))
		}
		authm = append(authm, ssh.Password(o.password))
	}

	cfg := &ssh.ClientConfig{
		User:            o.user,
		Auth:            authm,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	addr := net.JoinHostPort(o.host, o.sshPort)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к %s: %w", addr, err)
	}
	return client, nil
}

func runCmd(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	err = sess.Run(cmd)
	return buf.String(), err
}

func upload(client *ssh.Client, remote string, data []byte, mode string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	cmd := fmt.Sprintf("mkdir -p %s && cat > %s && chmod %s %s",
		shq(path.Dir(remote)), shq(remote), mode, shq(remote))
	var buf bytes.Buffer
	sess.Stderr = &buf
	if err := sess.Run(cmd); err != nil {
		return fmt.Errorf("%w (%s)", err, buf.String())
	}
	return nil
}

// uploadAssets заливает встроенные бинарник awg-web (chmod 755) и static/*.
func uploadAssets(client *ssh.Client) error {
	return fs.WalkDir(assets, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := assets.ReadFile(p)
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, "assets/")
		remote := remoteDir + "/" + rel
		mode := "644"
		if rel == "awg-web" {
			mode = "755"
		}
		fmt.Printf("  → %s (%d KiB)\n", rel, len(data)/1024)
		return upload(client, remote, data, mode)
	})
}

// detectPublicHost пытается определить внешний адрес сервера.
func detectPublicHost(client *ssh.Client, fallback string) string {
	for _, cmd := range []string{
		"curl -s --max-time 5 https://ifconfig.me",
		"curl -s --max-time 5 https://api.ipify.org",
		"hostname -I | awk '{print $1}'",
	} {
		if out, err := runCmd(client, cmd); err == nil {
			if ip := strings.TrimSpace(out); ip != "" && !strings.Contains(ip, " ") {
				return ip
			}
		}
	}
	return fallback
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func indent(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		b.WriteString("    " + line + "\n")
	}
	return b.String()
}

// shq — одинарные кавычки для безопасной подстановки пути в sh.
func shq(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

const systemdUnit = `[Unit]
Description=AmneziaWG web panel
After=docker.service
Requires=docker.service

[Service]
Type=simple
WorkingDirectory=/opt/awg-web
ExecStart=/opt/awg-web/awg-web -config /opt/awg-web/config.json
Restart=on-failure
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
`
