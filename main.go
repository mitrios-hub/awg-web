// awg-web — веб-панель управления пользователями AmneziaWG.
//
// Логика полностью повторяет bash-скрипт awg_userctl.sh:
//   - имена и "последний handshake" читаются из clientsTable (штатное поле
//     Amnezia), а не парсятся из "wg show dump" (у AmneziaWG формат колонок
//     дампа ненадёжен для парсинга по позиции);
//   - endpoint и статус блокировки берутся из "wg show <if> dump" и
//     "iptables -t raw -S PREROUTING" соответственно;
//   - при дублях IP в дампе выбирается запись с более свежим handshake;
//   - блокировка/разблокировка — те же команды iptables в raw/PREROUTING,
//     что и в исходном bash-скрипте;
//   - данные обновляются только по явному запросу (кнопка "Обновить"),
//     никакого автообновления на бэкенде нет.
//
// Все параметры (адрес/порт, доступ к контейнеру, логин, хэш пароля, TLS)
// берутся из JSON-файла конфигурации (по умолчанию ./config.json).
// Хэш пароля формируется отдельной утилитой ./hashpw — см. README.md.
//
// Сборка:
//
//	go mod tidy
//	go build -o awg-web .
//	go build -o hashpw ./cmd/hashpw
//
// Запуск:
//
//	./awg-web -config ./config.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"

	"awg-web/internal/config"
)

// ===================== МОДЕЛИ =====================

type ClientEntry struct {
	ClientID string `json:"clientId"`
	UserData struct {
		AllowedIps      string `json:"allowedIps"`
		ClientName      string `json:"clientName"`
		CreationDate    string `json:"creationDate"`
		DataReceived    string `json:"dataReceived"`
		DataSent        string `json:"dataSent"`
		LatestHandshake string `json:"latestHandshake"`
	} `json:"userData"`
}

type User struct {
	Num            int    `json:"num"`
	IP             string `json:"ip"`
	Name           string `json:"name"`
	Endpoint       string `json:"endpoint"`
	Handshake      string `json:"handshake"`
	NeverSeen      bool   `json:"neverSeen"`
	Blocked        bool   `json:"blocked"`
	RecentlyActive bool   `json:"recentlyActive"`
}

type Summary struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Blocked   int `json:"blocked"`
	NeverSeen int `json:"neverSeen"`
}

type UsersResponse struct {
	Users     []User    `json:"users"`
	Summary   Summary   `json:"summary"`
	FetchedAt time.Time `json:"fetchedAt"`
	Container string    `json:"container"`
}

// ===================== СБОР ДАННЫХ =====================

var rawDropRe = regexp.MustCompile(`-s\s+(\d+\.\d+\.\d+\.\d+)(/32)?.*-j\s+DROP`)

// ===================== ПЕРЕВЫПУСК КЛИЕНТА =====================
//
// "Перевыпустить" не восстанавливает утерянный приватный ключ клиента —
// это математически невозможно (сервер никогда не хранил приватный ключ,
// только производный от него публичный). Вместо этого генерируется НОВАЯ
// пара ключей, и публичный ключ пира в wg0.conf заменяется на новый —
// тот же IP, то же имя, тот же PSK, но с чистого листа. Старый (утерянный)
// ключ при этом инвалидируется.

type wgInterfaceParams struct {
	Jc, Jmin, Jmax, S1, S2 string
	H1, H2, H3, H4         string
}

type confPeer struct {
	PublicKey    string
	PresharedKey string
	AllowedIPs   string
}

var kvLineRe = regexp.MustCompile(`^\s*([A-Za-z0-9]+)\s*=\s*(.+?)\s*$`)

func parseWgConfInterface(conf string) wgInterfaceParams {
	var p wgInterfaceParams
	inInterface := false
	for _, line := range strings.Split(conf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[Interface]" {
			inInterface = true
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inInterface = false
			continue
		}
		if !inInterface {
			continue
		}
		m := kvLineRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		switch m[1] {
		case "Jc":
			p.Jc = m[2]
		case "Jmin":
			p.Jmin = m[2]
		case "Jmax":
			p.Jmax = m[2]
		case "S1":
			p.S1 = m[2]
		case "S2":
			p.S2 = m[2]
		case "H1":
			p.H1 = m[2]
		case "H2":
			p.H2 = m[2]
		case "H3":
			p.H3 = m[2]
		case "H4":
			p.H4 = m[2]
		}
	}
	return p
}

// findPeerByIP ищет в wg0.conf блок [Peer] с нужным AllowedIPs.
func findPeerByIP(conf, ip string) (confPeer, bool) {
	blocks := strings.Split(conf, "[Peer]")
	target := ip + "/32"
	for _, block := range blocks[1:] { // blocks[0] — всё до первого [Peer] (секция [Interface])
		var peer confPeer
		for _, line := range strings.Split(block, "\n") {
			m := kvLineRe.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			switch m[1] {
			case "PublicKey":
				peer.PublicKey = m[2]
			case "PresharedKey":
				peer.PresharedKey = m[2]
			case "AllowedIPs":
				peer.AllowedIPs = m[2]
			}
		}
		for _, a := range strings.Split(peer.AllowedIPs, ",") {
			if strings.TrimSpace(a) == target {
				return peer, true
			}
		}
	}
	return confPeer{}, false
}

func buildClientConfig(priv, ip string, cfg config.Config, p wgInterfaceParams, serverPub, psk string) string {
	dns := cfg.ClientDNS
	if dns == "" {
		dns = "1.1.1.1, 1.0.0.1"
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", priv)
	fmt.Fprintf(&b, "Address = %s/32\n", ip)
	fmt.Fprintf(&b, "DNS = %s\n", dns)
	if p.Jc != "" {
		fmt.Fprintf(&b, "Jc = %s\nJmin = %s\nJmax = %s\nS1 = %s\nS2 = %s\nH1 = %s\nH2 = %s\nH3 = %s\nH4 = %s\n",
			p.Jc, p.Jmin, p.Jmax, p.S1, p.S2, p.H1, p.H2, p.H3, p.H4)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPub)
	fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", cfg.ClientEndpoint)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}

var unsafeFilenameRe = regexp.MustCompile(`[^A-Za-z0-9_\-]+`)

func sanitizeFilename(name string) string {
	s := unsafeFilenameRe.ReplaceAllString(name, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		s = "client"
	}
	return s
}

// updateClientIDInTable переносит clientId (=публичный ключ) на новый в
// clientsTable, чтобы имя клиента осталось привязано к тому же IP. Если
// записи не было вовсе (orphan-пир) — создаёт новую с этим IP.
func updateClientIDInTable(cfg config.Config, ip, newPub string) (string, error) {
	raw, err := dockerExec(cfg.Container, "cat", cfg.ClientsTablePath)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать clientsTable: %w (%s)", err, raw)
	}
	var entries []ClientEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return "", fmt.Errorf("не удалось разобрать clientsTable: %w", err)
	}

	name := ""
	found := false
	for i := range entries {
		entryIP := strings.SplitN(entries[i].UserData.AllowedIps, "/", 2)[0]
		if entryIP == ip {
			entries[i].ClientID = newPub
			name = entries[i].UserData.ClientName
			found = true
			break
		}
	}
	if !found {
		var e ClientEntry
		e.ClientID = newPub
		e.UserData.AllowedIps = ip + "/32"
		entries = append(entries, e)
	}

	data, err := json.MarshalIndent(entries, "", "    ")
	if err != nil {
		return "", fmt.Errorf("не удалось сериализовать clientsTable: %w", err)
	}
	if err := dockerWriteFile(cfg.Container, cfg.ClientsTablePath, string(data)); err != nil {
		return "", fmt.Errorf("не удалось сохранить clientsTable: %w", err)
	}
	return name, nil
}

type ReissueResponse struct {
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Filename    string `json:"filename"`
	ConfigText  string `json:"configText"`
	QRPngBase64 string `json:"qrPngBase64"`
}

func reissueClient(cfg config.Config, ip string) (ReissueResponse, error) {
	if cfg.ClientEndpoint == "" {
		return ReissueResponse{}, fmt.Errorf("в конфиге не задан client_endpoint (публичный адрес сервера) — добавь его в config.json и перезапусти сервис")
	}

	confText, err := dockerExec(cfg.Container, "cat", cfg.WgConfPath)
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось прочитать %s: %w (%s)", cfg.WgConfPath, err, confText)
	}

	oldPeer, ok := findPeerByIP(confText, ip)
	if !ok {
		return ReissueResponse{}, fmt.Errorf("пир с IP %s не найден в %s", ip, cfg.WgConfPath)
	}
	ifaceParams := parseWgConfInterface(confText)

	serverPubOut, err := dockerExec(cfg.Container, "wg", "show", cfg.WgInterface, "public-key")
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось получить публичный ключ сервера: %w (%s)", err, serverPubOut)
	}
	serverPub := strings.TrimSpace(serverPubOut)

	newPrivOut, err := dockerExec(cfg.Container, "wg", "genkey")
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось сгенерировать новый приватный ключ: %w (%s)", err, newPrivOut)
	}
	newPriv := strings.TrimSpace(newPrivOut)

	newPubOut, err := dockerExecStdin(cfg.Container, newPriv+"\n", "wg", "pubkey")
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось вычислить публичный ключ: %w (%s)", err, newPubOut)
	}
	newPub := strings.TrimSpace(newPubOut)

	// 1) применяем изменение "живьём", без разрыва остальных пиров
	if out, err := dockerExec(cfg.Container, "wg", "set", cfg.WgInterface, "peer", oldPeer.PublicKey, "remove"); err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось удалить старый пир из живого интерфейса: %w (%s)", err, out)
	}
	if out, err := dockerExecStdin(cfg.Container, oldPeer.PresharedKey+"\n",
		"wg", "set", cfg.WgInterface, "peer", newPub, "preshared-key", "/dev/stdin", "allowed-ips", ip+"/32"); err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось добавить новый пир в живой интерфейс: %w (%s)", err, out)
	}

	// 2) сохраняем изменение на диск, чтобы оно пережило перезапуск контейнера
	newConfText := strings.Replace(confText, "PublicKey = "+oldPeer.PublicKey, "PublicKey = "+newPub, 1)
	if err := dockerWriteFile(cfg.Container, cfg.WgConfPath, newConfText); err != nil {
		return ReissueResponse{}, fmt.Errorf("живой интерфейс обновлён, НО не удалось сохранить %s на диске — при перезапуске контейнера изменение потеряется: %w", cfg.WgConfPath, err)
	}

	// 3) переносим clientId в clientsTable на новый ключ, чтобы имя не потерялось
	name, err := updateClientIDInTable(cfg, ip, newPub)
	if err != nil {
		log.Printf("перевыпуск %s: живой интерфейс и wg0.conf обновлены, но clientsTable — нет: %v", ip, err)
	}
	if name == "" {
		name = "—"
	}

	confOut := buildClientConfig(newPriv, ip, cfg, ifaceParams, serverPub, oldPeer.PresharedKey)

	png, err := qrcode.Encode(confOut, qrcode.Medium, 512)
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("конфиг перевыпущен, но не удалось сгенерировать QR-код: %w", err)
	}

	return ReissueResponse{
		IP:          ip,
		Name:        name,
		Filename:    sanitizeFilename(name) + ".conf",
		ConfigText:  confOut,
		QRPngBase64: base64.StdEncoding.EncodeToString(png),
	}, nil
}

func dockerExec(container string, args ...string) (string, error) {
	full := append([]string{"exec", container}, args...)
	cmd := exec.Command("docker", full...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// dockerExecStdin — то же самое, но с передачей данных на стандартный ввод
// команды внутри контейнера (нужно для "wg pubkey", "wg set ... preshared-key
// /dev/stdin" и записи файлов через "cat > path").
func dockerExecStdin(container, stdin string, args ...string) (string, error) {
	full := append([]string{"exec", "-i", container}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// dockerWriteFile перезаписывает файл внутри контейнера целиком.
func dockerWriteFile(container, path, content string) error {
	out, err := dockerExecStdin(container, content, "sh", "-c", "cat > "+shellQuote(path))
	if err != nil {
		return fmt.Errorf("%w (%s)", err, out)
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func fetchClients(cfg config.Config) ([]ClientEntry, error) {
	out, err := dockerExec(cfg.Container, "cat", cfg.ClientsTablePath)
	if err != nil {
		return nil, fmt.Errorf("не удалось прочитать %s в контейнере %s: %w (%s)", cfg.ClientsTablePath, cfg.Container, err, out)
	}
	var entries []ClientEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, fmt.Errorf("не удалось разобрать clientsTable как JSON: %w", err)
	}
	return entries, nil
}

// wgPeer — сырые данные из "wg show <if> dump" по одному пиру.
type wgPeer struct {
	endpoint string
	hsEpoch  int64
}

func fetchWgDump(cfg config.Config) (map[string]wgPeer, error) {
	out, err := dockerExec(cfg.Container, "wg", "show", cfg.WgInterface, "dump")
	result := map[string]wgPeer{}
	if err != nil {
		// Не фатально: без wg-интерфейса просто не будет endpoint'ов.
		return result, nil
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) <= 1 {
		return result, nil
	}
	// первая строка — сам интерфейс, пропускаем
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 5 {
			continue
		}
		endpoint := fields[2]
		allowedIps := fields[3]
		ip := strings.SplitN(strings.SplitN(allowedIps, ",", 2)[0], "/", 2)[0]
		if ip == "" {
			continue
		}
		hs, _ := strconv.ParseInt(fields[4], 10, 64)

		// при дублях IP в дампе — оставляем запись с более свежим handshake
		if existing, ok := result[ip]; !ok || hs > existing.hsEpoch {
			result[ip] = wgPeer{endpoint: endpoint, hsEpoch: hs}
		}
	}
	return result, nil
}

func fetchBlockedSet(cfg config.Config) (map[string]bool, error) {
	out, err := dockerExec(cfg.Container, "iptables", "-t", "raw", "-S", "PREROUTING")
	blocked := map[string]bool{}
	if err != nil {
		return blocked, nil
	}
	for _, line := range strings.Split(out, "\n") {
		m := rawDropRe.FindStringSubmatch(line)
		if len(m) >= 2 {
			blocked[m[1]] = true
		}
	}
	return blocked, nil
}

// buildUsers собирает единый список пользователей из трёх источников,
// в точности повторяя логику bash-версии скрипта.
func buildUsers(cfg config.Config, includeNeverSeen bool) (UsersResponse, error) {
	clients, err := fetchClients(cfg)
	if err != nil {
		return UsersResponse{}, err
	}
	wgPeers, err := fetchWgDump(cfg)
	if err != nil {
		return UsersResponse{}, err
	}
	blocked, err := fetchBlockedSet(cfg)
	if err != nil {
		return UsersResponse{}, err
	}

	nameByIP := map[string]string{}
	hsStrByIP := map[string]string{}
	knownIPs := map[string]bool{}

	for _, c := range clients {
		ip := strings.SplitN(c.UserData.AllowedIps, "/", 2)[0]
		if ip == "" {
			continue
		}
		knownIPs[ip] = true
		if c.UserData.ClientName != "" {
			nameByIP[ip] = c.UserData.ClientName
		}
		if c.UserData.LatestHandshake != "" {
			hsStrByIP[ip] = c.UserData.LatestHandshake
		}
	}
	for ip := range wgPeers {
		knownIPs[ip] = true
	}

	ips := make([]string, 0, len(knownIPs))
	for ip := range knownIPs {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return ipLess(ips[i], ips[j]) })

	users := make([]User, 0, len(ips))
	summary := Summary{}
	num := 0

	for _, ip := range ips {
		name := nameByIP[ip]
		if name == "" {
			name = "—"
		}

		endpoint := "N/A"
		if p, ok := wgPeers[ip]; ok {
			endpoint = p.endpoint
		}

		var handshake string
		neverSeen := false
		if hs, ok := hsStrByIP[ip]; ok {
			handshake = hs
		} else if p, ok := wgPeers[ip]; ok && p.hsEpoch > 0 {
			handshake = time.Unix(p.hsEpoch, 0).Format("2006-01-02 15:04:05")
		} else {
			handshake = "никогда"
			neverSeen = true
		}

		if neverSeen && !includeNeverSeen {
			continue
		}

		num++
		isBlocked := blocked[ip]

		recentlyActive := false
		if p, ok := wgPeers[ip]; ok && p.hsEpoch > 0 {
			if time.Since(time.Unix(p.hsEpoch, 0)) <= 3*time.Minute {
				recentlyActive = true
			}
		}

		summary.Total++
		if isBlocked {
			summary.Blocked++
		} else {
			summary.Active++
		}
		if neverSeen {
			summary.NeverSeen++
		}

		users = append(users, User{
			Num:            num,
			IP:             ip,
			Name:           name,
			Endpoint:       endpoint,
			Handshake:      handshake,
			NeverSeen:      neverSeen,
			Blocked:        isBlocked,
			RecentlyActive: recentlyActive,
		})
	}

	return UsersResponse{
		Users:     users,
		Summary:   summary,
		FetchedAt: time.Now(),
		Container: cfg.Container,
	}, nil
}

// ipLess — сравнение IPv4-адресов по октетам (для сортировки 10.8.1.2 < 10.8.1.10).
func ipLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 4 && i < len(pa) && i < len(pb); i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return a < b
}

// ===================== ДЕЙСТВИЯ (блокировка/разблокировка) =====================

var ipOnlyRe = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

func blockIP(cfg config.Config, ip string) error {
	out, err := dockerExec(cfg.Container, "iptables", "-t", "raw", "-I", "PREROUTING", "1", "-s", ip, "-j", "DROP")
	if err != nil {
		return fmt.Errorf("iptables: %w (%s)", err, out)
	}
	return nil
}

func unblockIP(cfg config.Config, ip string) error {
	// удаляем все совпадающие правила (на случай дублей), как и в bash-версии
	for {
		_, err := dockerExec(cfg.Container, "iptables", "-t", "raw", "-D", "PREROUTING", "-s", ip, "-j", "DROP")
		if err != nil {
			break
		}
	}
	return nil
}

// ===================== АУТЕНТИФИКАЦИЯ (bcrypt) =====================

// bcryptBasicAuth — Basic Auth со сравнением пароля через bcrypt-хэш из
// конфига (вместо gin.BasicAuth, который сравнивает пароли в открытом виде).
func bcryptBasicAuth(user, hash string) gin.HandlerFunc {
	return func(c *gin.Context) {
		reqUser, reqPass, ok := c.Request.BasicAuth()
		validUser := ok && subtleEqual(reqUser, user)
		validPass := ok && bcrypt.CompareHashAndPassword([]byte(hash), []byte(reqPass)) == nil

		if !validUser || !validPass {
			c.Header("WWW-Authenticate", `Basic realm="awg-web"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// ===================== HTTP =====================

func main() {
	configPath := flag.String("config", "./config.json", "путь к JSON-файлу конфигурации")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf(
			"Не удалось загрузить конфигурацию: %v\n"+
				"Скопируй config.example.json в %s, укажи логин и сформируй хэш пароля утилитой ./hashpw",
			err, *configPath,
		)
	}
	if cfg.AuthUser == "" || cfg.AuthPassHash == "" {
		log.Fatalf(
			"В конфиге (%s) не заданы auth_user / auth_pass_hash.\n"+
				"Сформируй хэш пароля: ./hashpw -config %s -user <логин>",
			*configPath, *configPath,
		)
	}
	if (cfg.TLSCertPath == "") != (cfg.TLSKeyPath == "") {
		log.Fatal("В конфиге указан только один из tls_cert_path/tls_key_path — нужны оба либо ни одного")
	}

	tlsEnabled := cfg.TLSCertPath != "" && cfg.TLSKeyPath != ""
	if !tlsEnabled {
		log.Println("⚠ tls_cert_path/tls_key_path не заданы в конфиге — сервер поднимается по НЕЗАШИФРОВАННОМУ HTTP. " +
			"Basic Auth без TLS передаёт пароль практически открытым текстом. Не открывай этот порт в интернет напрямую.")
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	authorized := r.Group("/", bcryptBasicAuth(cfg.AuthUser, cfg.AuthPassHash))

	authorized.StaticFS("/static", http.Dir("./static"))
	authorized.GET("/", func(c *gin.Context) {
		c.File("./static/index.html")
	})

	api := authorized.Group("/api")
	{
		api.GET("/users", func(c *gin.Context) {
			includeNever := c.Query("includeNever") == "true"
			resp, err := buildUsers(cfg, includeNever)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, resp)
		})

		api.POST("/users/:ip/block", func(c *gin.Context) {
			ip := c.Param("ip")
			if !ipOnlyRe.MatchString(ip) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "некорректный IP"})
				return
			}
			if err := blockIP(cfg, ip); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})

		api.POST("/users/:ip/unblock", func(c *gin.Context) {
			ip := c.Param("ip")
			if !ipOnlyRe.MatchString(ip) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "некорректный IP"})
				return
			}
			if err := unblockIP(cfg, ip); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true})
		})

		api.POST("/users/:ip/reissue", func(c *gin.Context) {
			ip := c.Param("ip")
			if !ipOnlyRe.MatchString(ip) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "некорректный IP"})
				return
			}
			resp, err := reissueClient(cfg, ip)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, resp)
		})
	}

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	log.Printf("awg-web слушает на %s://%s (контейнер: %s, интерфейс: %s, конфиг: %s)",
		scheme, cfg.ListenAddr, cfg.Container, cfg.WgInterface, *configPath)

	if tlsEnabled {
		log.Fatal(r.RunTLS(cfg.ListenAddr, cfg.TLSCertPath, cfg.TLSKeyPath))
	} else {
		log.Fatal(r.Run(cfg.ListenAddr))
	}
}
