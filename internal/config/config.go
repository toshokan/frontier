package config

import (
	"crypto/rsa"
	"log"
	"os"
	"reflect"
	"encoding/pem"
	"io/ioutil"
	"crypto/x509"
	"errors"
)

type Config struct {
	ClientId         string `env:"CLIENT_ID"`
	ClientSecret     string `env:"CLIENT_SECRET"`
	BaseUrl          string `env:"BASE_URL"`
	AuthEndpoint     string `env:"AUTH_ENDPOINT"`
	TokenEndpoint    string `env:"TOKEN_ENDPOINT"`
	UserInfoEndpoint string `env:"USER_INFO_ENDPOINT"`
	Scopes           string `env:"SCOPES"`
	PrivateKeyPath   string `env:"PRIVATE_KEY_PATH"`
	PrivateKey       *rsa.PrivateKey
}

func LoadEnv() (cfg Config) {
	log.Print("Loading configuration from environment")
	t := reflect.TypeOf(cfg)
	obj := reflect.ValueOf(&cfg).Elem()
	for _, field := range reflect.VisibleFields(t) {
		envVar := field.Tag.Get("env")
		if envVar != "" {
			value, ok := os.LookupEnv(envVar)
			if !ok {
				log.Fatalf("Missing value for %s", envVar)
			}
			obj.FieldByName(field.Name).SetString(value)
			log.Printf("Loaded %s", field.Name)
		}
	}
	key, err := loadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		log.Fatalf("Failed to load private key: %s", err)
	}
	cfg.PrivateKey = key
	return cfg
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der, _ := pem.Decode(bytes)
	if der == nil {
		return nil, errors.New("No PEM block in private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(der.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}
