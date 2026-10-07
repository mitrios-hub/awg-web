package main

// Автоматические страницы /conf/<имя> (v2.6). При добавлении клиента и при
// перевыпуске его ключей панель сама кладёт <имя>.conf в cfg.PublicConfDir,
// а publicConfLoop удаляет файл, как только у клиента прошёл первый
// handshake: ссылка живёт ровно до первого подключения. При переименовании
// клиента страница не переезжает — уже отправленная ссылка продолжает работать. Принадлежность файла
// клиенту определяется по самому конфигу — публичный ключ выводится из его
// PrivateKey, поэтому никаких отдельных индексов не нужно и файлы,
// положенные руками (как первые ссылки на nl1), обрабатываются так же.

import (
	"crypto/rand"
	"encoding/base64"
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

var (
	// publicConfEnabled — маршруты /conf/ зарегистрированы (есть шаблон и
	// каталог не отключён); без них класть файлы бессмысленно.
	publicConfEnabled bool
	// publicConfMu сериализует работу с каталогом: добавление/перевыпуск из
	// API и фоновая чистка не должны пересекаться.
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

// publicConfFiles — имя ссылки → публичный ключ для всех файлов каталога.
// Файлы, из которых ключ не вывести, пропускаются (их не трогаем).
func publicConfFiles(dir string) map[string]string {
	res := map[string]string{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return res
	}
	for _, e := range entries {
		n := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(n, ".conf") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			continue
		}
		if pub, ok := pubFromConf(string(data)); ok {
			res[strings.TrimSuffix(n, ".conf")] = pub
		}
	}
	return res
}

// publicConfPathsByPub — публичный ключ → путь ожидающей страницы, для
// кнопки «скопировать ссылку» в списке клиентов.
func publicConfPathsByPub(cfg config.Config) map[string]string {
	res := map[string]string{}
	if !publicConfEnabled {
		return res
	}
	publicConfMu.Lock()
	defer publicConfMu.Unlock()
	for slug, pub := range publicConfFiles(cfg.PublicConfDir) {
		res[pub] = "/conf/" + slug
	}
	return res
}

func removePublicConfLocked(dir, pub string) []string {
	var removed []string
	for slug, p := range publicConfFiles(dir) {
		if p == pub && os.Remove(filepath.Join(dir, slug+".conf")) == nil {
			removed = append(removed, slug)
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
	if err := os.Rename(tmp, filepath.Join(dir, slug+".conf")); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("не удалось записать конфиг для ссылки: %w", err)
	}
	log.Printf("conf: страница /conf/%s создана для %s (%s), удалится после первого подключения", slug, name, ip)
	return "/conf/" + slug, nil
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
// ответу удалять страницы нельзя.
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

// prunePublicConfs — одна проверка: убрать страницы подключившихся клиентов
// и клиентов, которых на сервере больше нет.
func prunePublicConfs(cfg config.Config, hs map[string]int64) {
	publicConfMu.Lock()
	defer publicConfMu.Unlock()
	dir := cfg.PublicConfDir
	for slug, pub := range publicConfFiles(dir) {
		ts, known := hs[pub]
		var why string
		switch {
		case known && ts > 0:
			why = "клиент подключился"
		case !known && len(hs) > 0:
			// пустой список пиров — скорее интерфейс ещё поднимается, а не
			// «все удалены»; по нему не чистим
			why = "такого клиента на сервере больше нет"
		default:
			continue
		}
		if err := os.Remove(filepath.Join(dir, slug+".conf")); err == nil {
			log.Printf("conf: страница /conf/%s удалена — %s", slug, why)
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
