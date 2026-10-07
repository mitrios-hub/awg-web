package main

// Временная раздача клиентских конфигов по открытой ссылке
// https://<панель>/conf/<имя>: страница без пароля с кнопкой «Открыть в
// AmneziaVPN» (ссылка vpn://, на Android открывает приложение и сразу
// импортирует конфиг), «Поделиться» (файл .conf через системное меню — путь
// для iPhone, где у приложения нет своей схемы ссылок), копированием ключа,
// скачиванием файла и QR-кодом.
//
// Приватных ключей клиентов панель не хранит, поэтому раздаётся только то,
// что лежит файлом <имя>.conf в cfg.PublicConfDir (его кладут туда при
// заведении клиента). Нет файла или он старше cfg.PublicConfDays дней — 404,
// такой же, как на любой несуществующий адрес. Выключить раздачу целиком —
// удалить каталог.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/skip2/go-qrcode"

	"awg-web/internal/config"
)

const defaultPublicConfDays = 14

// Имя в ссылке — только то, что безопасно как имя файла: никаких точек и
// слешей, значит и выхода из каталога через ../ быть не может.
var publicConfNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// amneziaKey упаковывает конфиг в ключ vpn:// в том формате, который
// принимает приложение AmneziaVPN (ImportController::extractConfigFromData):
// base64url без '=' от qCompress — 4 байта длины исходника (big-endian) и
// поток zlib. После распаковки приложение видит обычный [Interface]/[Peer]
// и разбирает его так же, как импортированный файл.
func amneziaKey(conf string) string {
	var buf bytes.Buffer
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(conf)))
	buf.Write(n[:])
	zw, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression) // ошибка только при неверном уровне
	zw.Write([]byte(conf))
	zw.Close()
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

func publicConfDays(cfg config.Config) int {
	if cfg.PublicConfDays > 0 {
		return cfg.PublicConfDays
	}
	return defaultPublicConfDays
}

// loadPublicConf читает <имя>.conf из каталога раздачи. ok=false — нет
// каталога/файла, имя недопустимо или срок ссылки вышел.
func loadPublicConf(cfg config.Config, name string, now time.Time) (text string, expires time.Time, ok bool) {
	if cfg.PublicConfDir == "" || !publicConfNameRe.MatchString(name) {
		return "", time.Time{}, false
	}
	p := filepath.Join(cfg.PublicConfDir, name+".conf")
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", time.Time{}, false
	}
	expires = fi.ModTime().Add(time.Duration(publicConfDays(cfg)) * 24 * time.Hour)
	if !now.Before(expires) {
		return "", time.Time{}, false
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		return "", time.Time{}, false
	}
	return string(data), expires, true
}

func publicConfHeaders(c *gin.Context) {
	// ключи не должны оседать в кэшах, поисковиках и Referer у сторонних сайтов
	c.Header("Cache-Control", "no-store")
	c.Header("X-Robots-Tag", "noindex, nofollow")
	c.Header("Referrer-Policy", "no-referrer")
	c.Header("X-Content-Type-Options", "nosniff")
}

func publicConfNotFound(c *gin.Context) {
	// тот же ответ, что у gin на неизвестный маршрут
	c.String(http.StatusNotFound, "404 page not found")
}

// registerPublicConf вешает публичные маршруты /conf/*. Шаблон страницы
// читается с диска один раз; если его нет (static/ старой версии) — панель
// работает дальше, просто без раздачи.
func registerPublicConf(r *gin.Engine, cfg config.Config) {
	if cfg.PublicConfDir == "" {
		return
	}
	tmpl, err := template.ParseFiles("./static/conf.html")
	if err != nil {
		log.Printf("⚠ раздача конфигов по ссылке /conf/ отключена: не удалось разобрать ./static/conf.html: %v", err)
		return
	}

	r.GET("/conf/:name", func(c *gin.Context) {
		name := c.Param("name")
		publicConfHeaders(c)
		text, expires, ok := loadPublicConf(cfg, name, time.Now())
		if !ok {
			publicConfNotFound(c)
			return
		}
		log.Printf("conf: страница %s открыта с %s", name, c.Request.RemoteAddr)
		c.Header("Content-Type", "text/html; charset=utf-8")
		err := tmpl.Execute(c.Writer, gin.H{
			"Name":    name,
			"Host":    hostName,
			"Conf":    text,
			"Key":     template.URL(amneziaKey(text)), // иначе html/template заменит схему vpn: на #ZgotmplZ
			"KeyText": amneziaKey(text),
			"Until":   expires.Format("02.01.2006"),
		})
		if err != nil {
			log.Printf("conf: не удалось отрендерить страницу %s: %v", name, err)
		}
	})

	r.GET("/conf/:name/file", func(c *gin.Context) {
		name := c.Param("name")
		publicConfHeaders(c)
		text, _, ok := loadPublicConf(cfg, name, time.Now())
		if !ok {
			publicConfNotFound(c)
			return
		}
		log.Printf("conf: файл %s.conf скачан с %s", name, c.Request.RemoteAddr)
		c.Header("Content-Disposition", `attachment; filename="`+name+`.conf"`)
		c.Data(http.StatusOK, "application/octet-stream", []byte(text))
	})

	r.GET("/conf/:name/qr.png", func(c *gin.Context) {
		name := c.Param("name")
		publicConfHeaders(c)
		text, _, ok := loadPublicConf(cfg, name, time.Now())
		if !ok {
			publicConfNotFound(c)
			return
		}
		// в QR — сам текст конфига, как в панели: сканер AmneziaVPN узнаёт
		// [Interface]/[Peer], а ключ vpn:// из QR он не разбирает
		png, err := qrcode.Encode(text, qrcode.Medium, 512)
		if err != nil {
			c.String(http.StatusInternalServerError, "не удалось сгенерировать QR-код")
			return
		}
		c.Data(http.StatusOK, "image/png", png)
	})

	state := "каталога нет — ссылки не работают"
	if fi, err := os.Stat(cfg.PublicConfDir); err == nil && fi.IsDir() {
		state = "каталог есть"
	}
	log.Printf("раздача конфигов по ссылке /conf/<имя> из %s, срок %d дн. (%s)", cfg.PublicConfDir, publicConfDays(cfg), state)
}
