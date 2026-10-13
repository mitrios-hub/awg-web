package main

// Автоматические страницы /conf/<имя>. При добавлении клиента и при
// перевыпуске его ключей панель сама кладёт конфиг в cfg.PublicConfDir.
// Состояние страницы — расширение файла:
//
//	<имя>.conf — ждёт первого подключения (страница открыта);
//	<имя>.off  — выключена (404): так её делает publicConfLoop после первого
//	             handshake клиента (v2.8; до этого файл удалялся) или админ;
//	<имя>.on   — включена админом вручную, панель её сама больше не трогает.
//
// Выключенная страница остаётся с той же ссылкой: если клиент потеряет
// конфиг, админ включит её кнопкой в панели, отправит ссылку и выключит.
// Перевыпуск ключей заменяет страницу новой (новая ссылка, снова «ждёт
// подключения»), удаление клиента — убирает. При переименовании клиента
// страница не переезжает — уже отправленная ссылка продолжает работать.
// Принадлежность файла клиенту определяется по самому конфигу — публичный
// ключ выводится из его PrivateKey, поэтому отдельных индексов не нужно и
// файлы, положенные руками, обрабатываются так же.

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"awg-web/internal/config"
)

const publicConfCheckEvery = 20 * time.Second

const (
	pageExtPending = ".conf"
	pageExtOn      = ".on"
	pageExtOff     = ".off"
)

// Состояния страницы для API/интерфейса.
const (
	PageStatePending = "pending"
	PageStateOn      = "on"
	PageStateOff     = "off"
)

var pageStateByExt = map[string]string{
	pageExtPending: PageStatePending,
	pageExtOn:      PageStateOn,
	pageExtOff:     PageStateOff,
}

var pageExtByState = map[string]string{
	PageStatePending: pageExtPending,
	PageStateOn:      pageExtOn,
	PageStateOff:     pageExtOff,
}

var (
	// publicConfEnabled — маршруты /conf/ зарегистрированы (есть шаблон и
	// каталог не отключён); без них класть файлы бессмысленно.
	publicConfEnabled bool
	// publicConfMu сериализует работу с каталогом: добавление/перевыпуск из
	// API и фоновая проверка не должны пересекаться.
	publicConfMu sync.Mutex
)

// pubFromConf — публичный ключ клиента по PrivateKey из его конфига.
func pubFromConf(conf string) (string, bool) {
	priv := interfaceField(conf, "PrivateKey")
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", false
	}
	pub, err := curve25519.X25519(raw, curve25519.Basepoint)
	if err != nil {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(pub), true
}

const (
	slugTailLen      = 8
	slugTailAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// publicConfSlug — имя для ссылки: имя клиента и случайный хвост
// (nl-arthur0-k7f3q2xm). Хвост не даёт угадать ссылку по имени — на странице
// рабочий конфиг. Из кириллицы, пробелов и скобок остаётся безопасная часть
// (или «client»), длина — в пределах publicConfNameRe.
func publicConfSlug(name string) string {
	base := strings.Trim(unsafeFilenameRe.ReplaceAllString(name, "_"), "_-")
	if base == "" {
		base = "client"
	}
	if lim := 64 - 1 - slugTailLen; len(base) > lim {
		base = strings.TrimRight(base[:lim], "_-")
	}
	return base + "-" + randomTail()
}

func randomTail() string {
	b := make([]byte, slugTailLen)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error()) // без случайности ссылку выдавать нельзя
	}
	for i := range b {
		b[i] = slugTailAlphabet[int(b[i])%len(slugTailAlphabet)]
	}
	return string(b)
}

// publicPage — файл страницы в каталоге раздачи.
type publicPage struct {
	Slug  string
	Pub   string
	State string // PageState*
}

func (p publicPage) file(dir string) string {
	return filepath.Join(dir, p.Slug+pageExtByState[p.State])
}

// publicConfFiles — все страницы каталога в любом состоянии. Файлы, из
// которых ключ не вывести, пропускаются (их не трогаем).
func publicConfFiles(dir string) []publicPage {
	var res []publicPage
	entries, err := os.ReadDir(dir)
	if err != nil {
		return res
	}
	for _, e := range entries {
		n := e.Name()
		ext := filepath.Ext(n)
		state, known := pageStateByExt[ext]
		slug := strings.TrimSuffix(n, ext)
		if !e.Type().IsRegular() || !known || !publicConfNameRe.MatchString(slug) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if pub, ok := pubFromConf(string(data)); ok {
			res = append(res, publicPage{Slug: slug, Pub: pub, State: state})
		}
	}
	return res
}

// PublicPageInfo — страница клиента для списка в панели.
type PublicPageInfo struct {
	Path  string `json:"publicPath"`
	State string `json:"publicState"`
}

// publicConfPathsByPub — публичный ключ → его страница, для кнопки ссылки в
// списке клиентов.
func publicConfPathsByPub(cfg config.Config) map[string]PublicPageInfo {
	res := map[string]PublicPageInfo{}
	if !publicConfEnabled {
		return res
	}
	publicConfMu.Lock()
	defer publicConfMu.Unlock()
	for _, p := range publicConfFiles(cfg.PublicConfDir) {
		res[p.Pub] = PublicPageInfo{Path: "/conf/" + p.Slug, State: p.State}
	}
	return res
}

func removePublicConfLocked(dir, pub string) []string {
	var removed []string
	for _, p := range publicConfFiles(dir) {
		if p.Pub == pub && os.Remove(p.file(dir)) == nil {
			removed = append(removed, p.Slug)
		}
	}
	return removed
}

// publishClientConf кладёт конфиг клиента на страницу /conf/<имя> и
// возвращает путь страницы. Прежние страницы этого клиента (oldPub — ключ до
// перевыпуска, pub — текущий) убираются. Ошибка не фатальна для вызывающего:
// клиент уже создан, ссылки просто не будет.
func publishClientConf(cfg config.Config, name, ip, oldPub, pub, conf string) (string, error) {
	if !publicConfEnabled {
		return "", nil
	}
	publicConfMu.Lock()
	defer publicConfMu.Unlock()

	dir := cfg.PublicConfDir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("не удалось создать каталог %s: %w", dir, err)
	}
	if oldPub != "" {
		removePublicConfLocked(dir, oldPub)
	}
	removePublicConfLocked(dir, pub)

	slug := publicConfSlug(name)
	tmp := filepath.Join(dir, "."+slug+".tmp")
	if err := os.WriteFile(tmp, []byte(conf), 0o600); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("не удалось записать конфиг для ссылки: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, slug+pageExtPending)); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("не удалось записать конфиг для ссылки: %w", err)
	}
	log.Printf("conf: страница /conf/%s создана для %s (%s), закроется после первого подключения", slug, name, ip)
	return "/conf/" + slug, nil
}

var errPageNotFound = errors.New("страница не найдена")

// setPublicConfEnabled — кнопка в панели: включить (.on) или выключить
// (.off) страницу. Ссылка остаётся прежней. При включении время файла
// обновляется, чтобы лимит public_conf_days считался от включения.
func setPublicConfEnabled(cfg config.Config, slug string, enabled bool) (PublicPageInfo, error) {
	if !publicConfEnabled || !publicConfNameRe.MatchString(slug) {
		return PublicPageInfo{}, errPageNotFound
	}
	publicConfMu.Lock()
	defer publicConfMu.Unlock()
	dir := cfg.PublicConfDir
	for _, p := range publicConfFiles(dir) {
		if p.Slug != slug {
			continue
		}
		next := PublicPageInfo{Path: "/conf/" + slug, State: PageStateOff}
		if enabled {
			next.State = PageStateOn
		}
		if p.State != next.State {
			to := publicPage{Slug: slug, State: next.State}.file(dir)
			if err := os.Rename(p.file(dir), to); err != nil {
				return PublicPageInfo{}, fmt.Errorf("не удалось переключить страницу: %w", err)
			}
			if enabled {
				now := time.Now()
				os.Chtimes(to, now, now)
			}
			log.Printf("conf: страница /conf/%s %s админом", slug, map[bool]string{true: "включена", false: "выключена"}[enabled])
		}
		return next, nil
	}
	return PublicPageInfo{}, errPageNotFound
}

// dropClientConf убирает страницу клиента (при удалении клиента).
func dropClientConf(cfg config.Config, pub string) {
	if cfg.PublicConfDir == "" || pub == "" {
		return
	}
	publicConfMu.Lock()
	defer publicConfMu.Unlock()
	for _, slug := range removePublicConfLocked(cfg.PublicConfDir, pub) {
		log.Printf("conf: страница /conf/%s удалена вместе с клиентом", slug)
	}
}

// fetchLatestHandshakes — публичный ключ → unix-время последнего handshake
// (0 — ещё не было). В отличие от fetchWgShow, ошибку возвращает: по пустому
// ответу трогать страницы нельзя.
func fetchLatestHandshakes(cfg config.Config) (map[string]int64, error) {
	out, err := dockerExec(cfg.Container, "wg", "show", cfg.WgInterface, "latest-handshakes")
	if err != nil {
		return nil, fmt.Errorf("%w (%s)", err, strings.TrimSpace(out))
	}
	return parseLatestHandshakes(out), nil
}

func parseLatestHandshakes(out string) map[string]int64 {
	res := map[string]int64{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil {
			continue
		}
		res[f[0]] = ts
	}
	return res
}

// prunePublicConfs — одна проверка: закрыть страницы подключившихся клиентов
// (только ждущие подключения — включённые админом не трогаем) и удалить
// страницы клиентов, которых на сервере больше нет.
func prunePublicConfs(cfg config.Config, hs map[string]int64) {
	publicConfMu.Lock()
	defer publicConfMu.Unlock()
	dir := cfg.PublicConfDir
	for _, p := range publicConfFiles(dir) {
		ts, known := hs[p.Pub]
		switch {
		case known && ts > 0 && p.State == PageStatePending:
			off := publicPage{Slug: p.Slug, State: PageStateOff}.file(dir)
			if err := os.Rename(p.file(dir), off); err == nil {
				log.Printf("conf: страница /conf/%s выключена — клиент подключился", p.Slug)
			}
		case !known && len(hs) > 0:
			// пустой список пиров — скорее интерфейс ещё поднимается, а не
			// «все удалены»; по нему не чистим
			if err := os.Remove(p.file(dir)); err == nil {
				log.Printf("conf: страница /conf/%s удалена — такого клиента на сервере больше нет", p.Slug)
			}
		}
	}
}

func publicConfLoop(cfg config.Config) {
	t := time.NewTicker(publicConfCheckEvery)
	defer t.Stop()
	for range t.C {
		if len(publicConfFiles(cfg.PublicConfDir)) == 0 {
			continue
		}
		hs, err := fetchLatestHandshakes(cfg)
		if err != nil {
			continue
		}
		prunePublicConfs(cfg, hs)
	}
}
