package main

import (
	"bytes"
	"encoding/xml"
	"html/template"
	"os"
	"strings"
	"testing"
)

// renderIndex рендерит static/index.html так же, как обработчик "/".
func renderIndex(t *testing.T, host string) string {
	t.Helper()

	tmpl, err := template.ParseFiles("static/index.html")
	if err != nil {
		t.Fatalf("разбор index.html: %v", err)
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, map[string]any{"Version": AppVersion, "AuthUser": "admin", "Host": host}); err != nil {
		t.Fatalf("рендер index.html: %v", err)
	}
	return b.String()
}

// Имя сервера стоит перед «AmneziaWG» и в шапке, и в заголовке вкладки.
func TestIndexShowsHostName(t *testing.T) {
	out := renderIndex(t, "nl1")
	for _, want := range []string{
		"<title>nl1 - AmneziaWG · Панель управления</title>",
		`<div class="brand__title">nl1 - AmneziaWG <span class="brand__version" id="appVersion">`,
		`<link rel="icon" href="/favicon.svg" type="image/svg+xml">`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("в index.html нет %q", want)
		}
	}
}

// Без имени шапка прежняя — без висящего « - ».
func TestIndexWithoutHostName(t *testing.T) {
	out := renderIndex(t, "")
	if !strings.Contains(out, "<title>AmneziaWG · Панель управления</title>") {
		t.Error("заголовок без имени сервера изменился")
	}
	if strings.Contains(out, " - AmneziaWG") {
		t.Error("без имени сервера в шапке остался разделитель")
	}
}

// Имя сервера приходит из ОС, но в HTML всё равно должно экранироваться.
func TestIndexEscapesHostName(t *testing.T) {
	out := renderIndex(t, `<b>x</b>`)
	if strings.Contains(out, "<b>x</b>") {
		t.Error("имя сервера попало в HTML без экранирования")
	}
}

// favicon.svg — корректный SVG, и на него ссылаются обе страницы.
func TestFavicon(t *testing.T) {
	data, err := os.ReadFile("static/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	var root struct{ XMLName xml.Name }
	if err := xml.Unmarshal(data, &root); err != nil || root.XMLName.Local != "svg" {
		t.Fatalf("static/favicon.svg — не SVG: %v %q", err, root.XMLName.Local)
	}
	login, err := os.ReadFile("static/login.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(login), `href="/favicon.svg"`) {
		t.Error("login.html не ссылается на /favicon.svg")
	}
}
