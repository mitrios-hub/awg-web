package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"

	"awg-web/internal/config"
)

// testKeyConf — клиентский конфиг со свежей парой ключей и её публичный ключ.
func testKeyConf(t *testing.T) (conf, pub string) {
	t.Helper()
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		t.Fatal(err)
	}
	p, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	conf = "[Interface]\nAddress = 10.8.2.40/32\nPrivateKey = " + base64.StdEncoding.EncodeToString(priv) +
		"\n\n[Peer]\nPublicKey = c2VydmVy\nEndpoint = nl1.example:28049\n"
	return conf, base64.StdEncoding.EncodeToString(p)
}

func TestPubFromConf(t *testing.T) {
	conf, want := testKeyConf(t)
	if got, ok := pubFromConf(conf); !ok || got != want {
		t.Fatalf("pubFromConf = %q, %v; ждали %q", got, ok, want)
	}
	if _, ok := pubFromConf("[Interface]\nPrivateKey = мусор\n"); ok {
		t.Errorf("битый ключ принят")
	}
}

func TestPublicConfSlug(t *testing.T) {
	cases := map[[2]string]string{
		{"nl-arthur0", "10.8.2.7"}:  "nl-arthur0",
		{"Вера", "10.8.2.10"}:       "client-10-8-2-10",
		{"anna phone", "10.8.2.11"}: "anna_phone-10-8-2-11",
		{"tv (зал)", "10.8.2.12"}:   "tv-10-8-2-12",
	}
	for in, want := range cases {
		got := publicConfSlug(in[0], in[1])
		if got != want {
			t.Errorf("publicConfSlug(%q, %q) = %q, ждали %q", in[0], in[1], got, want)
		}
		if !publicConfNameRe.MatchString(got) {
			t.Errorf("%q не годится для ссылки", got)
		}
	}
}

func TestPublicConfLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{PublicConfDir: filepath.Join(dir, "pc")} // каталога ещё нет
	publicConfEnabled = true
	defer func() { publicConfEnabled = false }()
	exists := func(slug string) bool {
		_, err := os.Stat(filepath.Join(cfg.PublicConfDir, slug+".conf"))
		return err == nil
	}

	// добавление: страница появляется, каталог создаётся с правами только владельца
	conf1, pub1 := testKeyConf(t)
	path, err := publishClientConf(cfg, "nl-ksu0", "10.8.2.8", "", pub1, conf1)
	if err != nil || path != "/conf/nl-ksu0" || !exists("nl-ksu0") {
		t.Fatalf("добавление: %q, %v", path, err)
	}

	// второй клиент с тем же именем не затирает первого
	conf2, pub2 := testKeyConf(t)
	path2, _ := publishClientConf(cfg, "nl-ksu0", "10.8.2.9", "", pub2, conf2)
	if path2 != "/conf/nl-ksu0-10-8-2-9" || !exists("nl-ksu0") {
		t.Fatalf("тёзка: %q", path2)
	}

	// переименование переносит ожидающую страницу
	renameClientConf(cfg, pub1, "nl-ksenia0", "10.8.2.8")
	if exists("nl-ksu0") || !exists("nl-ksenia0") {
		t.Fatalf("переименование не перенесло страницу")
	}

	// перевыпуск: старая страница уходит, новая — с новым ключом
	conf3, pub3 := testKeyConf(t)
	if _, err := publishClientConf(cfg, "nl-ksenia0", "10.8.2.8", pub1, pub3, conf3); err != nil {
		t.Fatal(err)
	}
	if got := publicConfFiles(cfg.PublicConfDir)["nl-ksenia0"]; got != pub3 {
		t.Fatalf("после перевыпуска на странице ключ %q, ждали новый", got)
	}

	// проверка handshakes: пустой ответ ничего не трогает
	prunePublicConfs(cfg, map[string]int64{})
	if !exists("nl-ksenia0") || !exists("nl-ksu0-10-8-2-9") {
		t.Fatalf("пустой список пиров удалил страницы")
	}
	// ещё не подключались — страницы на месте
	prunePublicConfs(cfg, map[string]int64{pub3: 0, pub2: 0})
	if !exists("nl-ksenia0") || !exists("nl-ksu0-10-8-2-9") {
		t.Fatalf("удалено до подключения")
	}
	// первый handshake — страница исчезает, у второго остаётся
	prunePublicConfs(cfg, map[string]int64{pub3: 1791400000, pub2: 0})
	if exists("nl-ksenia0") || !exists("nl-ksu0-10-8-2-9") {
		t.Fatalf("после подключения: ksenia %v, тёзка %v", exists("nl-ksenia0"), exists("nl-ksu0-10-8-2-9"))
	}
	// клиента удалили на сервере мимо панели — страница тоже уходит
	prunePublicConfs(cfg, map[string]int64{pub3: 1791400000})
	if exists("nl-ksu0-10-8-2-9") {
		t.Fatalf("страница удалённого клиента осталась")
	}

	// удаление клиента из панели
	conf4, pub4 := testKeyConf(t)
	publishClientConf(cfg, "nl-tmp0", "10.8.2.20", "", pub4, conf4)
	dropClientConf(cfg, pub4)
	if exists("nl-tmp0") {
		t.Fatalf("страница удалённого клиента осталась")
	}
}

func TestParseLatestHandshakes(t *testing.T) {
	got := parseLatestHandshakes("AAA=\t0\nBBB=\t1791400000\n\nмусор\n")
	if len(got) != 2 || got["AAA="] != 0 || got["BBB="] != 1791400000 {
		t.Fatalf("parseLatestHandshakes = %v", got)
	}
}
