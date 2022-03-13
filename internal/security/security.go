package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"github.com/toshokan/frontier/internal/config"
)

func EncryptMessage(cfg *config.Config, msg string, label string) (string, error) {
	cipherText, err := rsa.EncryptOAEP(sha512.New(),
		rand.Reader,
		&cfg.PrivateKey.PublicKey,
		[]byte(msg),
		[]byte(label))

	if err != nil {
		return "", err
	}
	encodedMessage := base64.URLEncoding.EncodeToString(cipherText)
	return encodedMessage, nil
}

func DecryptMessage(cfg *config.Config, encryptedMsg string, label string) (string, error) {
	messageBytes, err := base64.URLEncoding.DecodeString(encryptedMsg)
	if err != nil {
		return "", err
	}
	cipherText, err := rsa.DecryptOAEP(sha512.New(),
		rand.Reader,
		cfg.PrivateKey,
		messageBytes,
		[]byte(label))

	if err != nil {
		return "", err
	}
	return string(cipherText), nil
}

func EncryptAsJson(cfg *config.Config, val interface{}, label string) (string, error) {
	b, err := json.Marshal(val)
	if err != nil {
		return "", err
	}
	return EncryptMessage(cfg, string(b), label)
}

func DecryptAsJson(cfg *config.Config, data string, val interface{}, label string) error {
	data, err := DecryptMessage(cfg, data, label)
	if err != nil {
		return err
	}
	if err = json.Unmarshal([]byte(data), val); err != nil {
		return err
	}
	return nil
}
