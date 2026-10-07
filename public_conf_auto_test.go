package main

import (
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
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
	cases := map[string]string{
		"nl-arthur0":            "nl-arthur0-",
		"Вера":                  "client-",
		"anna phone":            "anna_phone-",
		"tv (зал)":              "tv-",
		strings.Repeat("x", 80): strings.Repeat("x", 55) + "-",
	}
	for in, prefix := range cases {
		got := publicConfSlug(in)
		if !strings.HasPrefix(got, prefix) || len(got) != len(prefix)+slugTailLen {
			t.Errorf("publicConfSlug(%q) = %q, ждали %q + %d случайных", in, got, prefix, slugTailLen)
		}
		if !publicConfNameRe.MatchString(got) {
			t.Errorf("%q не годится для ссылки", got)
		}
	}
	if publicConfSlug("nl-a0") == publicConfSlug("nl-a0") {
		t.Errorf("хвост не случайный")
	}
}

func TestPublicConfLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{PublicConfDir: filepath.Join(dir, "pc")} // каталога ещё нет
	publicConfEnabled = true
	defer func() { publicConfEnabled = false }()
	exists := func(path string) bool {
		_, err := os.Stat(filepath.Join(cfg.PublicConfDir, strings.TrimPrefix(path, "/conf/")+".conf"))
		return err == nil
	}

	// добавление: страница появляется (каталог создаётся сам), в ссылке имя + хвост
	conf1, pub1 := testKeyConf(t)
	path1, err := publishClientConf(cfg, "nl-ksu0", "10.8.2.8", "", pub1, conf1)
	if err != nil || !strings.HasPrefix(path1, "/conf/nl-ksu0-") || !exists(path1) {
		t.Fatalf("добавление: %q, %v", path1, err)
	}

	// второй клиент с тем же именем получает свою ссылку
	conf2, pub2 := testKeyConf(t)
	path2, _ := publishClientConf(cfg, "nl-ksu0", "10.8.2.9", "", pub2, conf2)
	if path2 == path1 || !exists(path1) || !exists(path2) {
		t.Fatalf("тёзка: %q и %q", path1, path2)
	}

	// перевыпуск: старая страница уходит, новая — с новым ключом
	conf3, pub3 := testKeyConf(t)
	path3, err := publishClientConf(cfg, "nl-ksu0", "10.8.2.8", pub1, pub3, conf3)
	if err != nil || exists(path1) || !exists(path3) {
		t.Fatalf("перевыпуск: старая %v, новая %v, %v", exists(path1), exists(path3), err)
	}
	if got := publicConfPathsByPub(cfg)[pub3]; got != path3 {
		t.Fatalf("publicConfPathsByPub = %q, ждали %q", got, path3)
	}

	// проверка handshakes: пустой ответ ничего не трогает
	prunePublicConfs(cfg, map[string]int64{})
	if !exists(path3) || !exists(path2) {
		t.Fatalf("пустой список пиров удалил страницы")
	}
	// ещё не подключались — страницы на месте
	prunePublicConfs(cfg, map[string]int64{pub3: 0, pub2: 0})
	if !exists(path3) || !exists(path2) {
		t.Fatalf("удалено до подключения")
	}
	// первый handshake — страница исчезает, у второго остаётся
	prunePublicConfs(cfg, map[string]int64{pub3: 1791400000, pub2: 0})
	if exists(path3) || !exists(path2) {
		t.Fatalf("после подключения: подключившийся %v, тёзка %v", exists(path3), exists(path2))
	}
	// клиента удалили на сервере мимо панели — страница тоже уходит
	prunePublicConfs(cfg, map[string]int64{pub3: 1791400000})
	if exists(path2) {
		t.Fatalf("страница удалённого клиента осталась")
	}

	// удаление клиента из панели
	conf4, pub4 := testKeyConf(t)
	path4, _ := publishClientConf(cfg, "nl-tmp0", "10.8.2.20", "", pub4, conf4)
	dropClientConf(cfg, pub4)
	if exists(path4) {
		t.Fatalf("страница удалённого клиента осталась")
	}
}

func TestParseLatestHandshakes(t *testing.T) {
	got := parseLatestHandshakes("AAA=\t0\nBBB=\t1791400000\n\nмусор\n")
	if len(got) != 2 || got["AAA="] != 0 || got["BBB="] != 1791400000 {
		t.Fatalf("parseLatestHandshakes = %v", got)
	}
}
