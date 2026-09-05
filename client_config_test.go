package main

import (
	"strings"
	"testing"

	"awg-web/internal/config"
)

// serverConf3_1 — как выглядит [Interface] сервера на AmneziaWG 3.1 со всеми
// включёнными механизмами обфускации (значения взяты из рабочего awg0.conf).
const serverConf3_1 = `[Interface]
Address = 10.9.1.0/24
ListenPort = 51820
PrivateKey = qO5uSZ2S1nJiT0hV3lS7c0GmT3vXk9pAaBcDeFgHiJk=
Jc = 6
Jmin = 8
Jmax = 80
S1 = 45
S2 = 110
S3 = 55
S4 = 95
H1 = 366668901
H2 = 85513001
H3 = 928397738
H4 = 481523791
I1 = <b 0xc00000000108><r 8><b 0x00><r 1170>
I2 = <t><r 24>
I3 = <rc 12><rd 6><r 32>
I4 = <r 96>
I5 = <b 0x160303><r 64>
HeaderProtectionKey = 8bmXQK1lFQ0Ty6ZbYw5w9m2gJ3xUcPnV4tRsAeIoUu0=
ContentPaddingAddition = 8-64
RekeyAfterTime = 100-140
RekeyTimeout = 4-7
RejectAfterTime = 170-200
KeepaliveTimeout = 8-14
MaxHandshakeAttempts = 16-22
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = xTIBA8dSp2GLW1Ht4hFbnCQfWXWvMkTgqBTiDdyxSFI=
AllowedIPs = 10.9.1.1/32
`

// TestClientConfigCarriesObfuscation — самое важное свойство выдаваемого
// конфига: всё, что должно совпадать у сервера и клиента, реально доезжает до
// клиента. Разъедется хоть один параметр — handshake молча перестанет
// проходить, а по логам это почти не диагностируется.
func TestClientConfigCarriesObfuscation(t *testing.T) {
	p := parseWgConfInterface(serverConf3_1)
	if !p.hasObfuscation() {
		t.Fatal("обфускация в конфиге сервера не распознана")
	}
	out := buildClientConfig(
		"cGxhY2Vob2xkZXJDbGllbnRQcml2YXRlS2V5MDAwMDA=", "10.9.1.5",
		config.Config{ClientDNS: "1.1.1.1, 1.0.0.1"},
		p,
		"xTIBA8dSp2GLW1Ht4hFbnCQfWXWvMkTgqBTiDdyxSFI=",
		"cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHM=",
		"217.177.34.217:51820",
	)

	want := map[string]string{
		"Jc": "6", "Jmin": "8", "Jmax": "80",
		"S1": "45", "S2": "110", "S3": "55", "S4": "95",
		"H1": "366668901", "H2": "85513001", "H3": "928397738", "H4": "481523791",
		"I1":                     "<b 0xc00000000108><r 8><b 0x00><r 1170>",
		"I2":                     "<t><r 24>",
		"I3":                     "<rc 12><rd 6><r 32>",
		"I4":                     "<r 96>",
		"I5":                     "<b 0x160303><r 64>",
		"HeaderProtectionKey":    "8bmXQK1lFQ0Ty6ZbYw5w9m2gJ3xUcPnV4tRsAeIoUu0=",
		"ContentPaddingAddition": "8-64",
		"RekeyAfterTime":         "100-140",
		"RekeyTimeout":           "4-7",
		"RejectAfterTime":        "170-200",
		"KeepaliveTimeout":       "8-14",
		"MaxHandshakeAttempts":   "16-22",
		"RandomTrailers":         "on",
		"DisableCookies":         "on",
	}
	for k, v := range want {
		if !strings.Contains(out, "\n"+k+" = "+v+"\n") {
			t.Errorf("в конфиге клиента нет строки %q = %q:\n%s", k, v, out)
		}
	}

	// Приватный ключ сервера не должен утечь клиенту ни при каких условиях.
	if strings.Contains(out, "qO5uSZ2S1nJiT0hV3lS7c0GmT3vXk9pAaBcDeFgHiJk=") {
		t.Error("в конфиг клиента попал приватный ключ сервера")
	}
	// MTU обязателен: с паддингом 3.1 дефолтные 1420 на части сетей рвут пакеты.
	if !strings.Contains(out, "\nMTU = 1280\n") {
		t.Error("в конфиге клиента нет MTU = 1280")
	}
}

// TestClientConfigLegacyServer — на сервере старого поколения новых ключей нет,
// и пустых строк вида "I1 = " в клиентском конфиге быть не должно: awg-quick на
// них падает (amnezia-vpn/amneziawg-tools#40).
func TestClientConfigLegacyServer(t *testing.T) {
	legacy := `[Interface]
Address = 10.8.1.0/24
PrivateKey = qO5uSZ2S1nJiT0hV3lS7c0GmT3vXk9pAaBcDeFgHiJk=
Jc = 4
Jmin = 8
Jmax = 80
S1 = 15
S2 = 40
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890
`
	p := parseWgConfInterface(legacy)
	out := buildClientConfig("priv", "10.8.1.5", config.Config{}, p, "pub", "psk", "example.com:51820")
	for _, k := range []string{"I1", "I2", "I3", "I4", "I5", "S3", "S4", "HeaderProtectionKey", "RandomTrailers"} {
		if strings.Contains(out, "\n"+k+" =") {
			t.Errorf("в конфиг клиента попал пустой ключ %q, которого нет у сервера:\n%s", k, out)
		}
	}
	if !strings.Contains(out, "\nJc = 4\n") || !strings.Contains(out, "\nH4 = 4567890\n") {
		t.Errorf("потеряна легаси-обфускация:\n%s", out)
	}
}
