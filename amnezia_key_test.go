package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"awg-web/internal/config"
)

// decodeAmneziaKey — обратное amneziaKey, как его разворачивает приложение.
func decodeAmneziaKey(t *testing.T, key string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(key, "vpn://"))
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zlib.NewReader(bytes.NewReader(raw[4:]))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(zr)
	if int(binary.BigEndian.Uint32(raw[:4])) != len(out) {
		t.Fatalf("длина в заголовке %d, распаковано %d", binary.BigEndian.Uint32(raw[:4]), len(out))
	}
	return out
}

func TestAmneziaNativeKey(t *testing.T) {
	key, ok := amneziaNativeKey(testClientConf, "nl1")
	if !ok {
		t.Fatal("конфиг не разобран")
	}
	var server struct {
		Containers []map[string]json.RawMessage `json:"containers"`
		Default    string                       `json:"defaultContainer"`
		Desc       string                       `json:"description"`
		Host       string                       `json:"hostName"`
		DNS1, DNS2 string
	}
	data := decodeAmneziaKey(t, key)
	if err := json.Unmarshal(data, &server); err != nil {
		t.Fatal(err)
	}
	if server.Desc != "nl1" || server.Default != "amnezia-awg" || server.Host != "nl1.example.org" || len(server.Containers) != 1 {
		t.Fatalf("сервер: %+v", server)
	}
	var proto struct {
		LastConfig  string `json:"last_config"`
		ThirdParty  bool   `json:"isThirdPartyConfig"`
		Port, Proto string `json:"-"`
	}
	if err := json.Unmarshal(server.Containers[0]["awg"], &proto); err != nil || !proto.ThirdParty {
		t.Fatalf("контейнер awg: %s", server.Containers[0]["awg"])
	}
	var last map[string]any
	if err := json.Unmarshal([]byte(proto.LastConfig), &last); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"config": testClientConf, "hostName": "nl1.example.org", "port": float64(28049),
		"client_ip": "10.8.2.7/32", "mtu": "1280", "Jc": "4", "persistent_keep_alive": "25",
		"I1": "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001c00c000100010000105a00044d583737>",
	}
	for k, v := range want {
		if last[k] != v {
			t.Errorf("last_config[%s] = %v, ждали %v", k, last[k], v)
		}
	}
	for _, k := range []string{"client_priv_key", "server_pub_key", "psk_key"} {
		if s, _ := last[k].(string); s == "" {
			t.Errorf("last_config без %s", k)
		}
	}
	// приложение решает «это родной формат» по слову containers
	if !bytes.Contains(data, []byte("containers")) {
		t.Errorf("нет containers")
	}
}

func TestClientKeyFallbackAndName(t *testing.T) {
	broken := "[Interface]\nPrivateKey = x\n\n[Peer]\nPublicKey = y\n" // без Endpoint/Address
	if got := clientKey(config.Config{}, broken); got != amneziaKey(broken) {
		t.Errorf("неразобранный конфиг должен уходить обычным ключом")
	}
	if n := clientConnectionName(config.Config{ClientConnectionName: " Trubodur NL "}, testClientConf); n != "Trubodur NL" {
		t.Errorf("имя из настройки: %q", n)
	}
}
