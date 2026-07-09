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
	"sync"
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
		AllowedIps      string `json:"allowedIps,omitempty"`
		ClientName      string `json:"clientName"`
		CreationDate    string `json:"creationDate"`
		DataReceived    string `json:"dataReceived,omitempty"`
		DataSent        string `json:"dataSent,omitempty"`
		LatestHandshake string `json:"latestHandshake,omitempty"`
	} `json:"userData"`
}

type User struct {
	Num            int    `json:"num"`
	IP             string `json:"ip"`
	Name           string `json:"name"`
	Endpoint       string `json:"endpoint"`
	Handshake      string `json:"handshake"`
	TrafficBytes   int64  `json:"trafficBytes"`
	NeverSeen      bool   `json:"neverSeen"`
	Blocked        bool   `json:"blocked"`
	RecentlyActive bool   `json:"recentlyActive"`
}

// AppVersion — версия панели. Обновляется вручную при значимых изменениях,
// чтобы можно было визуально свериться (в шапке панели), что деплой на
// сервере реально подтянул актуальный код после git pull + пересборки.
const AppVersion = "1.1"

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
	Version   string    `json:"version"`
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

// resolveClientEndpoint возвращает host:port для клиентского конфига.
// Если в конфиге client_endpoint уже указан с портом ("1.2.3.4:35357") —
// используется как есть. Если указан только хост ("1.2.3.4") — порт
// определяется автоматически через "docker port", чтобы не дублировать
// его вручную и не рассинхронизироваться при изменении ListenPort.
var dockerPortRe = regexp.MustCompile(`->\s*[\d.:a-fA-F\[\]]+:(\d+)\s*$`)

func resolveClientEndpoint(cfg config.Config) (string, error) {
	if cfg.ClientEndpoint == "" {
		return "", fmt.Errorf("client_endpoint не задан в конфиге")
	}
	if strings.Contains(cfg.ClientEndpoint, ":") {
		return cfg.ClientEndpoint, nil
	}

	out, err := exec.Command("docker", "port", cfg.Container).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("client_endpoint указан без порта (%q), а автоопределение через 'docker port' не удалось: %w (%s)",
			cfg.ClientEndpoint, err, out)
	}
	var port string
	for _, line := range strings.Split(string(out), "\n") {
		if m := dockerPortRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			port = m[1]
			break
		}
	}
	if port == "" {
		return "", fmt.Errorf("client_endpoint указан без порта, но не удалось разобрать вывод 'docker port %s': %s", cfg.Container, out)
	}
	return cfg.ClientEndpoint + ":" + port, nil
}

func buildClientConfig(priv, ip string, cfg config.Config, p wgInterfaceParams, serverPub, psk, endpoint string) string {
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
		// AmneziaWG новых версий добавляет в клиентский конфиг ещё пустые поля
		// I1-I5 (в нашем серверном wg0.conf их нет). Пишем их для совпадения с
		// конфигом, который отдаёт штатное приложение Amnezia.
		b.WriteString("I1 = \nI2 = \nI3 = \nI4 = \nI5 = \n")
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPub)
	fmt.Fprintf(&b, "PresharedKey = %s\n", psk)
	b.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")
	fmt.Fprintf(&b, "Endpoint = %s\n", endpoint)
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
// clientsTable, чтобы имя клиента осталось привязано к тому же клиенту.
// Ищем по СТАРОМУ публичному ключу, а не по IP — у части клиентов в
// clientsTable вообще нет поля allowedIps (см. случаи вида timur01/02/03),
// а clientId есть всегда.
func updateClientIDInTable(cfg config.Config, oldPub, ip, newPub string) (string, error) {
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
		if entries[i].ClientID == oldPub {
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
	Warning     string `json:"warning,omitempty"`
}

func reissueClient(cfg config.Config, ip string) (ReissueResponse, error) {
	endpoint, err := resolveClientEndpoint(cfg)
	if err != nil {
		return ReissueResponse{}, err
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
	var warning string
	if ifaceParams.Jc == "" {
		warning = "В секции [Interface] файла " + cfg.WgConfPath + " не найдены параметры обфускации " +
			"(Jc/Jmin/Jmax/S1/S2/H1-H4). Сгенерированный конфиг будет без них — если версия AmneziaWG " +
			"на сервере их требует, клиент может не подключиться. Обычно это значит, что wg0.conf " +
			"устарел относительно версии приложения — стоит свериться с актуальным форматом конфига " +
			"после обновления контейнера amnezia-awg."
	}

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

	// 1) сохраняем новый публичный ключ в конфиг на диске
	newConfText := strings.Replace(confText, "PublicKey = "+oldPeer.PublicKey, "PublicKey = "+newPub, 1)
	if err := dockerWriteFile(cfg.Container, cfg.WgConfPath, newConfText); err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось сохранить %s: %w", cfg.WgConfPath, err)
	}

	// 2) применяем изменение "живьём" через wg syncconf — он атомарно
	// сверяет живое состояние интерфейса с файлом и накатывает только
	// разницу, не трогая остальных пиров. Это надёжнее, чем ручные
	// "wg set ... remove/add": по опыту, ручной способ иногда не
	// применялся до перезапуска контейнера, а syncconf — штатный путь
	// именно для "перечитать конфиг без даунтайма".
	syncCmd := fmt.Sprintf("wg syncconf %s <(wg-quick strip %s)", cfg.WgInterface, cfg.WgConfPath)
	if out, err := dockerExec(cfg.Container, "bash", "-c", syncCmd); err != nil {
		return ReissueResponse{}, fmt.Errorf(
			"новый ключ сохранён в %s, но не удалось применить его живьём через wg syncconf: %w (%s). "+
				"Изменение вступит в силу при следующем перезапуске контейнера amnezia-awg",
			cfg.WgConfPath, err, out)
	}

	// 3) переносим clientId в clientsTable на новый ключ, чтобы имя не потерялось
	name, err := updateClientIDInTable(cfg, oldPeer.PublicKey, ip, newPub)
	if err != nil {
		log.Printf("перевыпуск %s: живой интерфейс и wg0.conf обновлены, но clientsTable — нет: %v", ip, err)
	}
	if name == "" {
		name = "—"
	}

	confOut := buildClientConfig(newPriv, ip, cfg, ifaceParams, serverPub, oldPeer.PresharedKey, endpoint)

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
		Warning:     warning,
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

// wgPeerInfo — данные одного пира из человекочитаемого "wg show <if>".
// Этот формат (в отличие от машинного "wg show <if> dump") устойчив к
// дополнительным полям обфускации AmneziaWG: каждая строка подписана
// ("endpoint:", "allowed ips:", "latest handshake:"), поэтому не важно,
// сколько всего полей и в каком порядке — ломаться нечему.
type wgPeerInfo struct {
	AllowedIPs    string
	Endpoint      string
	HandshakeText string // как есть от wg, например "4 minutes, 30 seconds ago"; пусто, если рукопожатий не было
}

var peerHeaderRe = regexp.MustCompile(`^peer:\s*(\S+)`)

func fetchWgShow(cfg config.Config) (map[string]wgPeerInfo, error) {
	out, err := dockerExec(cfg.Container, "wg", "show", cfg.WgInterface)
	result := map[string]wgPeerInfo{}
	if err != nil {
		// Не фатально: без живого интерфейса просто не будет live-данных.
		return result, nil
	}

	var curKey string
	var cur wgPeerInfo
	flush := func() {
		if curKey != "" {
			result[curKey] = cur
		}
	}

	for _, line := range strings.Split(out, "\n") {
		if m := peerHeaderRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			flush()
			curKey = m[1]
			cur = wgPeerInfo{}
			continue
		}
		if curKey == "" {
			continue // ещё не дошли до первого "peer:" — это блок "interface:"
		}
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "endpoint:"):
			cur.Endpoint = strings.TrimSpace(strings.TrimPrefix(t, "endpoint:"))
		case strings.HasPrefix(t, "allowed ips:"):
			cur.AllowedIPs = strings.TrimSpace(strings.TrimPrefix(t, "allowed ips:"))
		case strings.HasPrefix(t, "latest handshake:"):
			cur.HandshakeText = strings.TrimSpace(strings.TrimPrefix(t, "latest handshake:"))
		}
	}
	flush()
	return result, nil
}

// formatHandshake превращает текст "latest handshake" из wg
// ("13 days, 13 hours, 43 minutes, 52 seconds ago") в компактный вид без
// слова "назад": "13д 13ч 43м 52с". Ведущие и хвостовые нулевые единицы
// опускаются. Если распознать не удалось (например, абсолютная дата у
// orphan-пиров) — строка возвращается как есть.
var handshakeUnitRe = regexp.MustCompile(`(\d+)\s*(week|day|hour|minute|second)s?`)

func formatHandshake(s string) string {
	if s == "" {
		return ""
	}
	var d, h, m, sec int
	matched := false
	for _, mm := range handshakeUnitRe.FindAllStringSubmatch(s, -1) {
		n, _ := strconv.Atoi(mm[1])
		matched = true
		switch mm[2] {
		case "week":
			d += n * 7
		case "day":
			d += n
		case "hour":
			h += n
		case "minute":
			m += n
		case "second":
			sec += n
		}
	}
	if !matched {
		return s
	}
	vals := []int{d, h, m, sec}
	suf := []string{"д", "ч", "м", "с"}
	first, last := -1, -1
	for i, v := range vals {
		if v > 0 {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first < 0 {
		return "0с"
	}
	parts := make([]string, 0, 4)
	for i := first; i <= last; i++ {
		parts = append(parts, strconv.Itoa(vals[i])+suf[i])
	}
	return strings.Join(parts, " ")
}

// isRecentHandshake — грубая эвристика "живой прямо сейчас" по тексту от
// wg (часы/дни/недели — не недавно; минуты — недавно, если меньше 3;
// только секунды — точно недавно).
func isRecentHandshake(text string) bool {
	if text == "" {
		return false
	}
	if strings.Contains(text, "day") || strings.Contains(text, "week") ||
		strings.Contains(text, "month") || strings.Contains(text, "year") || strings.Contains(text, "hour") {
		return false
	}
	if strings.Contains(text, "minute") {
		m := regexp.MustCompile(`(\d+)\s*minute`).FindStringSubmatch(text)
		if m == nil {
			return false
		}
		n, _ := strconv.Atoi(m[1])
		return n < 3
	}
	return strings.Contains(text, "second")
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

// buildUsers собирает единый список пользователей. Ключ сопоставления —
// ПУБЛИЧНЫЙ КЛЮЧ (clientId в clientsTable = "peer:" в wg show), а не IP:
// у части клиентов (замечено на новых записях вида timur01/02/03)
// clientsTable вообще не содержит поле allowedIps, поэтому сопоставление
// по IP молча теряло таких пользователей. IP/endpoint/последний handshake
// берутся из живого "wg show <if>" — он не зависит от того, обновляет ли
// сама Amnezia clientsTable вовремя (а она, судя по всему, не всегда).
func buildUsers(cfg config.Config, includeNeverSeen bool) (UsersResponse, error) {
	clients, err := fetchClients(cfg)
	if err != nil {
		return UsersResponse{}, err
	}
	wgPeers, err := fetchWgShow(cfg)
	if err != nil {
		return UsersResponse{}, err
	}
	blocked, err := fetchBlockedSet(cfg)
	if err != nil {
		return UsersResponse{}, err
	}

	nameByKey := map[string]string{}
	knownKeys := map[string]bool{}

	for _, c := range clients {
		if c.ClientID == "" {
			continue
		}
		knownKeys[c.ClientID] = true
		if c.UserData.ClientName != "" {
			nameByKey[c.ClientID] = c.UserData.ClientName
		}
	}
	for pub := range wgPeers {
		knownKeys[pub] = true
	}

	keys := make([]string, 0, len(knownKeys))
	for k := range knownKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	users := make([]User, 0, len(keys))
	summary := Summary{}
	num := 0

	for _, key := range keys {
		peer, haveLive := wgPeers[key]

		ip := ""
		if haveLive {
			ip = strings.SplitN(strings.SplitN(peer.AllowedIPs, ",", 2)[0], "/", 2)[0]
		}
		if ip == "" {
			// запасной путь: вдруг это старая запись, где allowedIps есть
			// только в clientsTable (обратная совместимость)
			for _, c := range clients {
				if c.ClientID == key && c.UserData.AllowedIps != "" {
					ip = strings.SplitN(c.UserData.AllowedIps, "/", 2)[0]
					break
				}
			}
		}
		if ip == "" {
			// негде взять IP вообще — показать нечего, пропускаем
			continue
		}

		name := nameByKey[key]
		if name == "" {
			name = "—"
		}

		endpoint := "N/A"
		handshake := "никогда"
		neverSeen := true
		recentlyActive := false
		if haveLive {
			if peer.Endpoint != "" {
				endpoint = peer.Endpoint
			}
			if peer.HandshakeText != "" {
				handshake = formatHandshake(peer.HandshakeText)
				neverSeen = false
				recentlyActive = isRecentHandshake(peer.HandshakeText)
			}
		}

		// "Никогда не подключавшиеся" считаем всегда — счётчик в карточке
		// должен показывать их реальное количество независимо от того,
		// включены ли они в видимый список (галочка includeNeverSeen).
		if neverSeen {
			summary.NeverSeen++
		}

		if neverSeen && !includeNeverSeen {
			continue
		}

		num++
		isBlocked := blocked[ip]

		summary.Total++
		if isBlocked {
			summary.Blocked++
		} else {
			summary.Active++
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

	sort.Slice(users, func(i, j int) bool { return ipLess(users[i].IP, users[j].IP) })
	for i := range users {
		users[i].Num = i + 1
	}

	// трафик по клиентам из iptables-счётчиков (кэш ~1 мин; правила для новых/
	// нативно созданных клиентов добавляются автоматически, счёт с нуля)
	ips := make([]string, len(users))
	for i := range users {
		ips[i] = users[i].IP
	}
	traffic := getTraffic(cfg, ips)
	for i := range users {
		users[i].TrafficBytes = traffic[users[i].IP]
	}

	return UsersResponse{
		Users:     users,
		Summary:   summary,
		FetchedAt: time.Now(),
		Container: cfg.Container,
		Version:   AppVersion,
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

// ===================== УЧЁТ ТРАФИКА (iptables-счётчики) =====================
//
// Трафик считаем правилами-счётчиками в таблице mangle (штатное место для
// учёта, не мешает маршрутизации). Для каждого клиента два правила в
// собственной цепочке AWG_ACCT: по источнику (отдано клиентом) и по назначению
// (получено клиентом) — без -j, поэтому пакет только считается и идёт дальше.
// Итог по клиенту = сумма обоих. Если правила для клиента нет (новый, создан
// нативно в Amnezia, или контейнер перезапущен и правила сбросились) — оно
// добавляется и считается с нуля. Данные кэшируются очень коротко (trafficTTL),
// только чтобы схлопнуть всплеск одновременных запросов (несколько вкладок), —
// по сути обновляются каждую секунду вместе с опросом фронтенда.

const trafficChain = "AWG_ACCT"
const trafficTTL = 500 * time.Millisecond

var (
	trafficMu   sync.Mutex
	trafficAt   time.Time
	trafficData map[string]int64
)

// acctRuleRe разбирает строку из "iptables-save -c -t mangle":
// "[pkts:bytes] -A AWG_ACCT -s 10.8.1.2/32" (или -d).
var acctRuleRe = regexp.MustCompile(`^\[\d+:(\d+)\]\s+-A\s+` + trafficChain + `\s+(-[sd])\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

// ensureTrafficChain создаёт цепочку AWG_ACCT и вешает переход на неё из
// mangle/FORWARD (идемпотентно).
//
// Почему FORWARD, а не PREROUTING: на PREROUTING для ВХОДЯЩИХ пакетов адрес
// назначения ещё равен публичному IP сервера (обратный NAT происходит позже),
// поэтому правило "-d <клиент>" не срабатывает и download не считается. На
// FORWARD IP клиента виден в обе стороны: исходящие — ещё до SNAT (src=клиент),
// входящие — уже после обратного DNAT (dst=клиент). Это даёт корректный up+down.
func ensureTrafficChain(cfg config.Config) error {
	// -N вернёт ошибку, если цепочка уже есть — это нормально, игнорируем.
	_, _ = dockerExec(cfg.Container, "iptables", "-t", "mangle", "-N", trafficChain)

	// Миграция со старой (неверной) точки учёта v0.8: снимаем все переходы из
	// PREROUTING и, если что-то сняли, обнуляем счётчики, чтобы корректный учёт
	// на FORWARD стартовал с чистого листа (старые значения были только upload).
	migrated := false
	for {
		if _, err := dockerExec(cfg.Container, "iptables", "-t", "mangle", "-D", "PREROUTING", "-j", trafficChain); err != nil {
			break
		}
		migrated = true
	}
	if migrated {
		_, _ = dockerExec(cfg.Container, "iptables", "-t", "mangle", "-F", trafficChain)
	}

	if _, err := dockerExec(cfg.Container, "iptables", "-t", "mangle", "-C", "FORWARD", "-j", trafficChain); err != nil {
		if out, err := dockerExec(cfg.Container, "iptables", "-t", "mangle", "-I", "FORWARD", "1", "-j", trafficChain); err != nil {
			return fmt.Errorf("не удалось добавить переход в mangle/FORWARD: %w (%s)", err, out)
		}
	}
	return nil
}

// readAcctCounters читает текущие счётчики цепочки AWG_ACCT. up[ip]/down[ip] —
// байты по источнику/назначению; наличие ключа означает, что правило для этого
// IP уже есть.
func readAcctCounters(cfg config.Config) (up, down map[string]int64) {
	up, down = map[string]int64{}, map[string]int64{}
	out, err := dockerExec(cfg.Container, "iptables-save", "-c", "-t", "mangle")
	if err != nil {
		return up, down
	}
	for _, line := range strings.Split(out, "\n") {
		m := acctRuleRe.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		bytes, _ := strconv.ParseInt(m[1], 10, 64)
		ip := m[3]
		if m[2] == "-s" {
			up[ip] = bytes
		} else {
			down[ip] = bytes
		}
	}
	return up, down
}

// refreshTraffic гарантирует наличие правил для всех переданных IP (добавляя
// недостающие — счёт с нуля) и возвращает суммарный трафик по каждому.
func refreshTraffic(cfg config.Config, ips []string) map[string]int64 {
	if err := ensureTrafficChain(cfg); err != nil {
		log.Printf("учёт трафика: %v", err)
		return map[string]int64{}
	}
	up, down := readAcctCounters(cfg)
	for _, ip := range ips {
		if !ipOnlyRe.MatchString(ip) {
			continue
		}
		if _, ok := up[ip]; !ok {
			if _, err := dockerExec(cfg.Container, "iptables", "-t", "mangle", "-A", trafficChain, "-s", ip); err == nil {
				up[ip] = 0
			}
		}
		if _, ok := down[ip]; !ok {
			if _, err := dockerExec(cfg.Container, "iptables", "-t", "mangle", "-A", trafficChain, "-d", ip); err == nil {
				down[ip] = 0
			}
		}
	}
	total := map[string]int64{}
	for ip, b := range up {
		total[ip] += b
	}
	for ip, b := range down {
		total[ip] += b
	}
	return total
}

// getTraffic возвращает трафик по клиентам. Короткий кэш (trafficTTL) лишь
// схлопывает одновременные запросы; при опросе раз в секунду данные фактически
// обновляются каждую секунду.
func getTraffic(cfg config.Config, ips []string) map[string]int64 {
	trafficMu.Lock()
	defer trafficMu.Unlock()
	if trafficData != nil && time.Since(trafficAt) < trafficTTL {
		return trafficData
	}
	trafficData = refreshTraffic(cfg, ips)
	trafficAt = time.Now()
	return trafficData
}

// ===================== ДОБАВЛЕНИЕ / УДАЛЕНИЕ КЛИЕНТОВ =====================
//
// Формат хранения клиента у AmneziaWG (проверено на реальном сервере):
//   - пир живёт в ДВУХ файлах: [Peer] в wg0.conf и запись в clientsTable;
//     отдельного стороннего состояния приложение Amnezia не хранит, поэтому
//     правки этих двух файлов сохраняют совместимость с нативным приложением;
//   - связь между ними — по публичному ключу (clientId == PublicKey пира);
//   - IP авторитетно задаётся в wg0.conf (AllowedIPs), в clientsTable его
//     может не быть вовсе;
//   - при СОЗДАНИИ клиента приложение пишет минимальную запись
//     {clientId, userData:{clientName, creationDate}} — поля статистики
//     добавляются позже самим приложением, поэтому мы их не пишем;
//   - PSK общий на всех пиров, новый клиент использует тот же.

// clientNameRe — допустимые символы имени клиента: буквы (в т.ч. кириллица),
// цифры, пробел и часть пунктуации (штатные имена бывают вида
// "Admin [Windows 11 Version 24H2]"). Управляющие символы и кавычки запрещены.
var clientNameRe = regexp.MustCompile(`^[\p{L}\p{N} _.\-\[\]()]{1,128}$`)

var allowedIPRe = regexp.MustCompile(`AllowedIPs\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/32`)

// wgSyncConf применяет текущий wg0.conf к живому интерфейсу без даунтайма —
// тот же штатный путь, что и у перевыпуска.
func wgSyncConf(cfg config.Config) error {
	syncCmd := fmt.Sprintf("wg syncconf %s <(wg-quick strip %s)", cfg.WgInterface, cfg.WgConfPath)
	if out, err := dockerExec(cfg.Container, "bash", "-c", syncCmd); err != nil {
		return fmt.Errorf("не удалось применить конфиг через wg syncconf: %w (%s). "+
			"Изменение вступит в силу при следующем перезапуске контейнера %s", err, out, cfg.Container)
	}
	return nil
}

// dockerBackup делает резервную копию файла внутри контейнера (path.bak) —
// подстраховка перед структурными правками wg0.conf/clientsTable.
func dockerBackup(cfg config.Config, path string) error {
	out, err := dockerExec(cfg.Container, "sh", "-c", "cp "+shellQuote(path)+" "+shellQuote(path+".bak"))
	if err != nil {
		return fmt.Errorf("не удалось сделать резервную копию %s: %w (%s)", path, err, out)
	}
	return nil
}

// sharedPSK достаёт общий PresharedKey из первого [Peer] в wg0.conf.
func sharedPSK(conf string) (string, error) {
	for _, block := range strings.Split(conf, "[Peer]")[1:] {
		for _, line := range strings.Split(block, "\n") {
			if m := kvLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] == "PresharedKey" {
				return m[2], nil
			}
		}
	}
	return "", fmt.Errorf("в wg0.conf не найден PresharedKey ни в одном [Peer] — не с чего взять общий PSK")
}

// subnetPrefix возвращает префикс подсети ("10.8.1.") из строки Address секции
// [Interface] (например "Address = 10.8.1.0/24").
func subnetPrefix(conf string) (string, error) {
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
		if m := kvLineRe.FindStringSubmatch(trimmed); m != nil && m[1] == "Address" {
			addr := strings.SplitN(strings.TrimSpace(m[2]), "/", 2)[0]
			octets := strings.Split(addr, ".")
			if len(octets) != 4 {
				return "", fmt.Errorf("не удалось разобрать Address %q в [Interface]", m[2])
			}
			return strings.Join(octets[:3], ".") + ".", nil
		}
	}
	return "", fmt.Errorf("в секции [Interface] wg0.conf не найден Address")
}

// allocateFreeIP выбирает наименьший свободный адрес /24. Занятые адреса берутся
// из wg0.conf (авторитетный источник — в clientsTable IP может не быть).
// Диапазон 1..254; .0 занят самим сервером (Address = X.Y.Z.0/24).
func allocateFreeIP(conf string) (string, error) {
	prefix, err := subnetPrefix(conf)
	if err != nil {
		return "", err
	}
	used := map[int]bool{}
	for _, m := range allowedIPRe.FindAllStringSubmatch(conf, -1) {
		if strings.HasPrefix(m[1], prefix) {
			if n, err := strconv.Atoi(strings.TrimPrefix(m[1], prefix)); err == nil {
				used[n] = true
			}
		}
	}
	for n := 1; n <= 254; n++ {
		if !used[n] {
			return prefix + strconv.Itoa(n), nil
		}
	}
	return "", fmt.Errorf("нет свободных адресов в подсети %s0/24", prefix)
}

// addClientToTable дописывает в clientsTable минимальную запись нового клиента
// в нативном формате Amnezia: clientId (= публичный ключ) + clientName +
// creationDate (ctime-формат, как пишет само приложение).
func addClientToTable(cfg config.Config, pub, name string) error {
	raw, err := dockerExec(cfg.Container, "cat", cfg.ClientsTablePath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать clientsTable: %w (%s)", err, raw)
	}
	var entries []ClientEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("не удалось разобрать clientsTable: %w", err)
	}
	var e ClientEntry
	e.ClientID = pub
	e.UserData.ClientName = name
	e.UserData.CreationDate = time.Now().Format("Mon Jan _2 15:04:05 2006")
	entries = append(entries, e)

	if err := dockerBackup(cfg, cfg.ClientsTablePath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(entries, "", "    ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать clientsTable: %w", err)
	}
	return dockerWriteFile(cfg.Container, cfg.ClientsTablePath, string(data))
}

// addClient создаёт нового клиента: генерирует пару ключей, выделяет свободный
// IP, дописывает [Peer] в wg0.conf и запись в clientsTable, применяет живьём и
// возвращает готовый конфиг + QR.
func addClient(cfg config.Config, name string) (ReissueResponse, error) {
	name = strings.TrimSpace(name)
	if !clientNameRe.MatchString(name) {
		return ReissueResponse{}, fmt.Errorf("недопустимое имя клиента (буквы, цифры, пробел, . _ - [ ] ( ), до 128 символов)")
	}

	endpoint, err := resolveClientEndpoint(cfg)
	if err != nil {
		return ReissueResponse{}, err
	}

	confText, err := dockerExec(cfg.Container, "cat", cfg.WgConfPath)
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось прочитать %s: %w (%s)", cfg.WgConfPath, err, confText)
	}
	ifaceParams := parseWgConfInterface(confText)

	psk, err := sharedPSK(confText)
	if err != nil {
		return ReissueResponse{}, err
	}
	ip, err := allocateFreeIP(confText)
	if err != nil {
		return ReissueResponse{}, err
	}

	serverPubOut, err := dockerExec(cfg.Container, "wg", "show", cfg.WgInterface, "public-key")
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось получить публичный ключ сервера: %w (%s)", err, serverPubOut)
	}
	serverPub := strings.TrimSpace(serverPubOut)

	privOut, err := dockerExec(cfg.Container, "wg", "genkey")
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось сгенерировать приватный ключ: %w (%s)", err, privOut)
	}
	priv := strings.TrimSpace(privOut)
	pubOut, err := dockerExecStdin(cfg.Container, priv+"\n", "wg", "pubkey")
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось вычислить публичный ключ: %w (%s)", err, pubOut)
	}
	pub := strings.TrimSpace(pubOut)

	// 1) дописываем блок [Peer] в wg0.conf (с резервной копией)
	if err := dockerBackup(cfg, cfg.WgConfPath); err != nil {
		return ReissueResponse{}, err
	}
	newConf := strings.TrimRight(confText, "\n") + "\n\n" +
		fmt.Sprintf("[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n", pub, psk, ip)
	if err := dockerWriteFile(cfg.Container, cfg.WgConfPath, newConf); err != nil {
		return ReissueResponse{}, fmt.Errorf("не удалось записать %s: %w", cfg.WgConfPath, err)
	}

	// 2) применяем живьём
	if err := wgSyncConf(cfg); err != nil {
		return ReissueResponse{}, err
	}

	// 3) запись в clientsTable (не критично для подключения: если не удастся —
	// клиент уже работает, просто останется без имени в списке)
	if err := addClientToTable(cfg, pub, name); err != nil {
		log.Printf("добавление %q (%s): пир в wg0.conf создан, но запись в clientsTable — нет: %v", name, ip, err)
	}

	confOut := buildClientConfig(priv, ip, cfg, ifaceParams, serverPub, psk, endpoint)
	png, err := qrcode.Encode(confOut, qrcode.Medium, 512)
	if err != nil {
		return ReissueResponse{}, fmt.Errorf("клиент добавлен, но не удалось сгенерировать QR-код: %w", err)
	}

	var warning string
	if ifaceParams.Jc == "" {
		warning = "В [Interface] wg0.conf нет параметров обфускации (Jc/…): конфиг может не подключиться, если версия AmneziaWG их требует."
	}
	return ReissueResponse{
		IP:          ip,
		Name:        name,
		Filename:    sanitizeFilename(name) + ".conf",
		ConfigText:  confOut,
		QRPngBase64: base64.StdEncoding.EncodeToString(png),
		Warning:     warning,
	}, nil
}

// removePeerByIP убирает из текста wg0.conf блок [Peer], чей AllowedIPs
// совпадает с ip/32. Возвращает новый текст и признак, что блок был найден.
func removePeerByIP(conf, ip string) (string, bool) {
	parts := strings.Split(conf, "[Peer]")
	var b strings.Builder
	b.WriteString(parts[0]) // секция [Interface] и всё до первого [Peer]
	removed := false
	target := ip + "/32"
	for _, block := range parts[1:] {
		match := false
		for _, line := range strings.Split(block, "\n") {
			if m := kvLineRe.FindStringSubmatch(strings.TrimSpace(line)); m != nil && m[1] == "AllowedIPs" {
				for _, a := range strings.Split(m[2], ",") {
					if strings.TrimSpace(a) == target {
						match = true
					}
				}
			}
		}
		if match {
			removed = true
			continue
		}
		b.WriteString("[Peer]")
		b.WriteString(block)
	}
	return b.String(), removed
}

// removeClientFromTable убирает запись клиента из clientsTable по публичному
// ключу (clientId) с запасным сопоставлением по allowedIps.
func removeClientFromTable(cfg config.Config, pub, ip string) error {
	raw, err := dockerExec(cfg.Container, "cat", cfg.ClientsTablePath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать clientsTable: %w (%s)", err, raw)
	}
	var entries []ClientEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return fmt.Errorf("не удалось разобрать clientsTable: %w", err)
	}
	target := ip + "/32"
	kept := make([]ClientEntry, 0, len(entries))
	for _, e := range entries {
		if e.ClientID == pub || (e.UserData.AllowedIps != "" && e.UserData.AllowedIps == target) {
			continue
		}
		kept = append(kept, e)
	}
	if err := dockerBackup(cfg, cfg.ClientsTablePath); err != nil {
		return err
	}
	data, err := json.MarshalIndent(kept, "", "    ")
	if err != nil {
		return fmt.Errorf("не удалось сериализовать clientsTable: %w", err)
	}
	return dockerWriteFile(cfg.Container, cfg.ClientsTablePath, string(data))
}

// deleteClient удаляет клиента: убирает [Peer] из wg0.conf, запись из
// clientsTable, применяет живьём и снимает возможную блокировку iptables.
func deleteClient(cfg config.Config, ip string) error {
	confText, err := dockerExec(cfg.Container, "cat", cfg.WgConfPath)
	if err != nil {
		return fmt.Errorf("не удалось прочитать %s: %w (%s)", cfg.WgConfPath, err, confText)
	}
	peer, ok := findPeerByIP(confText, ip)
	if !ok {
		return fmt.Errorf("пир с IP %s не найден в %s", ip, cfg.WgConfPath)
	}
	newConf, removed := removePeerByIP(confText, ip)
	if !removed {
		return fmt.Errorf("не удалось вырезать [Peer] блок для %s из %s", ip, cfg.WgConfPath)
	}

	if err := dockerBackup(cfg, cfg.WgConfPath); err != nil {
		return err
	}
	if err := dockerWriteFile(cfg.Container, cfg.WgConfPath, newConf); err != nil {
		return fmt.Errorf("не удалось записать %s: %w", cfg.WgConfPath, err)
	}
	if err := wgSyncConf(cfg); err != nil {
		return err
	}

	if err := removeClientFromTable(cfg, peer.PublicKey, ip); err != nil {
		log.Printf("удаление %s: пир убран из wg0.conf, но запись в clientsTable — нет: %v", ip, err)
	}
	_ = unblockIP(cfg, ip) // на случай, если клиент был заблокирован — не оставляем висячее правило
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

		api.POST("/clients", func(c *gin.Context) {
			var body struct {
				Name string `json:"name"`
			}
			if err := c.ShouldBindJSON(&body); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "ожидается JSON {\"name\": \"...\"}"})
				return
			}
			resp, err := addClient(cfg, body.Name)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, resp)
		})

		api.POST("/users/:ip/delete", func(c *gin.Context) {
			ip := c.Param("ip")
			if !ipOnlyRe.MatchString(ip) {
				c.JSON(http.StatusBadRequest, gin.H{"error": "некорректный IP"})
				return
			}
			if err := deleteClient(cfg, ip); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusOK, gin.H{"ok": true})
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
