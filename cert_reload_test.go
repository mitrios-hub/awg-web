package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair генерирует самоподписанный сертификат с заданным CN и кладёт
// его рядом с ключом в PEM-формате.
func writePair(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("генерация ключа: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("создание сертификата: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatalf("запись сертификата: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("сериализация ключа: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("запись ключа: %v", err)
	}
}

// cnOf достаёт CN из сертификата, который отдал certReloader.
func cnOf(t *testing.T, cr *certReloader) string {
	t.Helper()
	c, err := cr.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate вернул ошибку: %v", err)
	}
	if c == nil || len(c.Certificate) == 0 {
		t.Fatal("GetCertificate вернул пустой сертификат")
	}
	parsed, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("разбор сертификата: %v", err)
	}
	return parsed.Subject.CommonName
}

// touch сдвигает mtime вперёд, чтобы изменение заметили независимо от
// гранулярности файловой системы.
func touch(t *testing.T, paths ...string) {
	t.Helper()
	future := time.Now().Add(10 * time.Second)
	for _, p := range paths {
		if err := os.Chtimes(p, future, future); err != nil {
			t.Fatalf("Chtimes %s: %v", p, err)
		}
	}
}

// Главный сценарий: продление сертификата подхватывается без перезапуска.
func TestCertReloaderPicksUpRenewal(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	writePair(t, certPath, keyPath, "old.example.org")

	cr, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	if got := cnOf(t, cr); got != "old.example.org" {
		t.Fatalf("на старте отдан CN %q, ожидался old.example.org", got)
	}

	// Имитируем работу acme.sh: файлы перезаписаны новой парой.
	writePair(t, certPath, keyPath, "new.example.org")
	touch(t, certPath, keyPath)

	if got := cnOf(t, cr); got != "new.example.org" {
		t.Fatalf("после продления отдан CN %q, ожидался new.example.org — сертификат не перечитан", got)
	}
}

// Битый файл не должен ронять сервер и рвать соединения: продолжаем отдавать
// последний рабочий сертификат.
func TestCertReloaderKeepsLastGoodOnBrokenFile(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	writePair(t, certPath, keyPath, "good.example.org")
	cr, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}

	// acme.sh успел записать только половину — сертификат обрезан.
	if err := os.WriteFile(certPath, []byte("-----BEGIN CERTIFICATE-----\nобрывок\n"), 0o644); err != nil {
		t.Fatalf("порча файла: %v", err)
	}
	touch(t, certPath)

	if got := cnOf(t, cr); got != "good.example.org" {
		t.Fatalf("при битом файле отдан CN %q, ожидался прежний good.example.org", got)
	}
}

// Неверные пути должны валить старт, а не всплывать при первом запросе.
func TestCertReloaderFailsFastOnMissingFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := newCertReloader(filepath.Join(dir, "нет.pem"), filepath.Join(dir, "нет.key")); err == nil {
		t.Fatal("ожидалась ошибка на несуществующих путях, получен nil")
	}
}

// Без изменений на диске файлы не перечитываются лишний раз.
func TestCertReloaderStableWhenUnchanged(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")

	writePair(t, certPath, keyPath, "stable.example.org")
	cr, err := newCertReloader(certPath, keyPath)
	if err != nil {
		t.Fatalf("newCertReloader: %v", err)
	}
	first, _ := cr.GetCertificate(nil)
	second, _ := cr.GetCertificate(nil)
	if first != second {
		t.Fatal("сертификат перечитан без изменения файлов — лишняя работа на каждом рукопожатии")
	}
}
