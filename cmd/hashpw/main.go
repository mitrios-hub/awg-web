// hashpw — утилита формирования bcrypt-хэша пароля для awg-web.
//
// Спрашивает пароль дважды (ввод не отображается на экране), считает
// bcrypt-хэш и записывает его вместе с логином в JSON-конфиг сервера, не
// трогая остальные поля (адрес, TLS-пути и т.д.).
//
// Использование:
//
//	./hashpw -config ./config.json -user admin
//
// Если файла конфигурации ещё нет — создаётся новый, с настройками по
// умолчанию (адрес 0.0.0.0:10001 и т.д.), которые потом можно поправить
// вручную в JSON.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"awg-web/internal/config"
)

func main() {
	configPath := flag.String("config", "./config.json", "путь к JSON-файлу конфигурации")
	user := flag.String("user", "", "логин (необязательно; если не указан — логин в конфиге не меняется)")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Printf("Конфиг %s не найден или повреждён — будет создан новый с настройками по умолчанию", *configPath)
		cfg = config.DefaultConfig()
	}

	stdin := bufio.NewReader(os.Stdin)

	if *user != "" {
		cfg.AuthUser = *user
	}
	if cfg.AuthUser == "" {
		fmt.Print("Логин: ")
		line, _ := stdin.ReadString('\n')
		cfg.AuthUser = strings.TrimSpace(line)
	}
	if cfg.AuthUser == "" {
		log.Fatal("логин не может быть пустым")
	}

	pass1, err := readPasswordHidden(stdin, "Пароль: ")
	if err != nil {
		log.Fatalf("не удалось прочитать пароль: %v", err)
	}
	pass2, err := readPasswordHidden(stdin, "Повтори пароль: ")
	if err != nil {
		log.Fatalf("не удалось прочитать пароль: %v", err)
	}
	if pass1 != pass2 {
		log.Fatal("пароли не совпадают")
	}
	if len(pass1) < 8 {
		log.Fatal("пароль слишком короткий (минимум 8 символов)")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(pass1), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("не удалось посчитать хэш: %v", err)
	}
	cfg.AuthPassHash = string(hash)

	if err := config.SaveConfig(*configPath, cfg); err != nil {
		log.Fatalf("не удалось сохранить конфиг: %v", err)
	}

	fmt.Printf("Готово: логин %q и новый хэш пароля записаны в %s\n", cfg.AuthUser, *configPath)
}

// readPasswordHidden читает строку из уже открытого reader'а (важно
// использовать ОДИН общий bufio.Reader на весь ввод — иначе при повторном
// создании reader'а часть уже прочитанных из stdin байт теряется в буфере
// предыдущего экземпляра) с отключённым эхом терминала (через stty), чтобы
// пароль не светился на экране. stty специфичен для Linux/macOS-терминалов,
// что соответствует целевой платформе деплоя (Linux-сервер).
func readPasswordHidden(stdin *bufio.Reader, prompt string) (string, error) {
	fmt.Print(prompt)

	// пробуем отключить эхо; если stty недоступен (например, ввод не из
	// терминала) — просто читаем как есть
	sttyPath, sttyErr := exec.LookPath("stty")
	if sttyErr == nil {
		cmdOff := exec.Command(sttyPath, "-echo")
		cmdOff.Stdin = os.Stdin
		_ = cmdOff.Run()
		defer func() {
			cmdOn := exec.Command(sttyPath, "echo")
			cmdOn.Stdin = os.Stdin
			_ = cmdOn.Run()
			fmt.Println()
		}()
	}

	line, err := stdin.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}
