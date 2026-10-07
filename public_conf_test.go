package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"awg-web/internal/config"
)

const testClientConf = "[Interface]\nPrivateKey = cHJpdmF0ZS1rZXktZm9yLXRlc3RzLW9ubHktMDAwMDA=\nAddress = 10.8.2.7/32\nDNS = 1.1.1.1, 1.0.0.1\nMTU = 1280\nJc = 4\nI1 = <r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>\n\n[Peer]\nPublicKey = c2VydmVyLXB1YmxpYy1rZXktZm9yLXRlc3RzLTAwMDA=\nPresharedKey = cHNrLWZvci10ZXN0cy1vbmx5LTAwMDAwMDAwMDAwMDA=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = nl1.example.org:28049\nPersistentKeepalive = 25\n"

// Ключ vpn:// должен разворачиваться ровно так, как это делает AmneziaVPN:
// base64url без '=' → qUncompress (4 байта длины big-endian + zlib).
func TestAmneziaKeyRoundTrip(t *testing.T) {
	key := amneziaKey(testClientConf)
	if !strings.HasPrefix(key, "vpn://") {
		t.Fatalf("ключ без префикса vpn://: %.20s", key)
	}
	body := strings.TrimPrefix(key, "vpn://")
	if strings.ContainsAny(body, "+/=") {
		t.Fatalf("в ключе символы не из base64url или выравнивание '=': %s", body)
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("base64url: %v", err)
	}
	if n := binary.BigEndian.Uint32(raw[:4]); int(n) != len(testClientConf) {
		t.Fatalf("заголовок qCompress: длина %d, ждали %d", n, len(testClientConf))
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		t.Fatalf("zlib: %v", err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != testClientConf {
		t.Fatalf("после распаковки конфиг другой:\n%s", got)
	}
}

func newPublicConfServer(t *testing.T, cfg config.Config) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	registerPublicConf(r, cfg)
	return r
}

func get(r *gin.Engine, url string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
	return w
}

func TestPublicConfServesPageFileAndQR(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nl-test0.conf"), []byte(testClientConf), 0600); err != nil {
		t.Fatal(err)
	}
	r := newPublicConfServer(t, config.Config{PublicConfDir: dir})

	w := get(r, "/conf/nl-test0")
	if w.Code != http.StatusOK {
		t.Fatalf("страница: код %d", w.Code)
	}
	page := w.Body.String()
	if !strings.Contains(page, `href="`+amneziaKey(testClientConf)+`"`) {
		t.Errorf("на странице нет ссылки vpn:// (html/template мог заменить схему на #ZgotmplZ)")
	}
	if strings.Contains(page, "ZgotmplZ") {
		t.Errorf("html/template забраковал значение на странице")
	}
	if !strings.Contains(page, "<h1>nl-test0</h1>") || !strings.Contains(page, "/conf/nl-test0/qr.png") {
		t.Errorf("на странице нет имени клиента или QR")
	}
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("X-Robots-Tag"), "noindex") {
		t.Errorf("нет заголовков против кэша/индексации: %v", w.Header())
	}

	w = get(r, "/conf/nl-test0/file")
	if w.Code != http.StatusOK || w.Body.String() != testClientConf {
		t.Fatalf("файл: код %d, тело совпадает: %v", w.Code, w.Body.String() == testClientConf)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != `attachment; filename="nl-test0.conf"` {
		t.Errorf("Content-Disposition = %q", cd)
	}

	w = get(r, "/conf/nl-test0/qr.png")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(w.Body.Bytes(), []byte("\x89PNG")) {
		t.Fatalf("QR: код %d, тип %q", w.Code, w.Header().Get("Content-Type"))
	}
}

func TestPublicConfNotFound(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "nl-old0.conf"), []byte(testClientConf), 0600)
	old := time.Now().Add(-15 * 24 * time.Hour)
	os.Chtimes(filepath.Join(dir, "nl-old0.conf"), old, old)
	os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("x"), 0600)
	os.Mkdir(filepath.Join(dir, "sub.conf"), 0700)

	r := newPublicConfServer(t, config.Config{PublicConfDir: dir, PublicConfDays: 14})
	for _, u := range []string{
		"/conf/nobody",         // нет файла
		"/conf/nl-old0",        // срок вышел (задан предел 14 дней)
		"/conf/nl-old0/file",   //
		"/conf/nl-old0/qr.png", //
		"/conf/secret.txt",     // точка в имени недопустима
		"/conf/..%2fsecret",    // попытка выйти из каталога
		"/conf/sub",            // каталог, а не файл
		"/conf/" + strings.Repeat("a", 65),
	} {
		if w := get(r, u); w.Code != http.StatusNotFound {
			t.Errorf("%s: код %d, ждали 404", u, w.Code)
		}
	}

	// срок продлевается настройкой
	r = newPublicConfServer(t, config.Config{PublicConfDir: dir, PublicConfDays: 30})
	if w := get(r, "/conf/nl-old0"); w.Code != http.StatusOK {
		t.Errorf("public_conf_days=30: код %d, ждали 200", w.Code)
	}

	// без предела (по умолчанию) страница живёт, пока клиент не подключится
	r = newPublicConfServer(t, config.Config{PublicConfDir: dir})
	if w := get(r, "/conf/nl-old0"); w.Code != http.StatusOK {
		t.Errorf("public_conf_days=0: код %d, ждали 200", w.Code)
	}

	// пустой каталог в настройке — маршрутов нет вовсе
	r = newPublicConfServer(t, config.Config{})
	if w := get(r, "/conf/nl-old0"); w.Code != http.StatusNotFound {
		t.Errorf("public_conf_dir пуст: код %d, ждали 404", w.Code)
	}
}
