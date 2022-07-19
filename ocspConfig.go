package main

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"time"
)

// значения по умолчанию для "опасных" флагов
const (
	defaultOcspNonceSize             = 8    // байт
	defaultOcspMaxResponseSize int64 = 8192 // байт
	defaultOcspRetryInterval         = "15m"
)

// ocspConfig определяет структуру с настройками взаимодействия с OCSP сервером.
type ocspConfig struct {
	// Disabled флаг позволяет отключить опрос OCSP сервера при установке в значение true.
	Disabled bool `json:"disabled" yaml:"disabled"`

	// URL OCSP сервера
	URL string `json:"url" yaml:"url"`

	// Timeout сетевого взаимодействия. Должно быть значение допустимое для time.ParseDuration().
	// Пустая строка - без таймаута.
	Timeout      string        `json:"timeout" yaml:"timeout"`
	TimeoutValue time.Duration `json:"-" yaml:"-"`

	// DigestOID OID алгоритма хеширования, использованного для вычисления значений полей NameDigest, KeyDigest (компонентов CertID)
	DigestOID      string                `json:"digestoid" yaml:"digestoid"`
	DigestOIDValue asn1.ObjectIdentifier `json:"-" yaml:"-"`

	// NameDigest содержит значение хеша имени издателя сертификата в поле Cert/CertFile, закодированное в base64.
	NameDigest      string `json:"namedigest" yaml:"namedigest"`
	NameDigestValue []byte `json:"-" yaml:"-"`

	// KeyDigest содержит значение хеша открытого ключа издателя сертификата в поле Cert/CertFile, закодированное в base64.
	KeyDigest      string `json:"keydigest" yaml:"keydigest"`
	KeyDigestValue []byte `json:"-" yaml:"-"`

	// Cert содержит сертификат, чей статус проверяем. Значение поля это ASN.1 DER закодированный в base64.
	// Если установлено это поле, то значение в поле CertFile игнорируется.
	// При этом хотя бы одно из них должно быть указано.
	Cert string `json:"cert" yaml:"cert"`

	// CertFile содержит путь к файлу с сертификатом, чей статус проверяем. Файл может содержать
	// сертификат как в ASN.1 DER, так и в PEM.
	// Файл читаем только если поле Cert пустое. При этом хотя бы одно из этих полей должно быть указано.
	CertFile string `json:"certfile" yaml:"certfile"`

	// Разобранный сертификат. Поле получаем путем обработки полей Cert - читаем из конфига или
	// CertFile - читаем из файла.
	Certificate *x509.Certificate `json:"-" yaml:"-"`

	// NonceSize содержит размер nonce в байтах. Если установлено 0, то nonce не используется.
	// В 0 можно установить только параметрами командной строки.
	NonceSize int `json:"noncesize" yaml:"noncesize"`

	// RetryCount содержит количество повторов отправки запросов о статусе.
	// 0 - бесконечно.
	RetryCount int `json:"retrycount" yaml:"retrycount"`

	// RetryInterval содержит временной интервал между двумя попытками отправки запросов о статусе.
	// Должно быть значение допустимое для time.ParseDuration().
	// По умолчанию устанавливается в 15m.
	// Пустая строка - без интервала. Использовать в этом режиме крайне НЕ рекомендуется.
	// Режим работы без интервала можно установить только параметром командной строки.
	RetryInterval      string        `json:"retryinterval" yaml:"retryinterval"`
	RetryIntervalValue time.Duration `json:"-" yaml:"-"`

	// MaxResponseSize определяет максимально допустимый размер ответа от сервера OCSP в байтах.
	// Если установлен в 0, то размер не ограничен.
	MaxResponseSize *int64 `json:"maxresponsesize" yaml:"maxresponsesize"`
}

// SetDefaults позволяет инициализировать не заданные/критичные поля значениями по умолчанию.
func (cfg *ocspConfig) SetDefaults() {
	if cfg == nil {
		return
	}
	if cfg.NonceSize < 1 {
		cfg.NonceSize = defaultOcspNonceSize
	}
	if cfg.RetryInterval == "" {
		cfg.RetryInterval = defaultOcspRetryInterval
	}
	if cfg.MaxResponseSize == nil {
		cfg.MaxResponseSize = new(int64)
	}
	if *cfg.MaxResponseSize == 0 {
		*cfg.MaxResponseSize = defaultOcspMaxResponseSize
	}
}

// UpdateCommandLine позволяет проверить и установить значения объекта конфигурации из
// параметров командной строки.
func (cfg *ocspConfig) UpdateCommandLine(givenFlags []*flag.Flag) {
	if cfg == nil {
		return
	}
	for _, f := range givenFlags {
		switch f.Name {
		case "ocsp.disabled":
			cfg.Disabled = *clpOcspDisabled
		case "ocsp.url":
			cfg.URL = *clpOcspURL
		case "ocsp.timeout":
			cfg.Timeout = *clpOcspTimeout
		case "ocsp.digestoid":
			cfg.DigestOID = *clpOcspDigestOID
		case "ocsp.namedigest":
			cfg.NameDigest = *clpOcspNameDigest
		case "ocsp.keydigest":
			cfg.KeyDigest = *clpOcspKeyDigest
		case "ocsp.cert":
			cfg.Cert = *clpOcspCert
		case "ocsp.certfile":
			cfg.CertFile = *clpOcspCertFile
		case "ocsp.noncesize":
			cfg.NonceSize = *clpOcspNonceSize
		case "ocsp.retrycount":
			cfg.RetryCount = *clpOcspRetryCount
		case "ocsp.retryinterval":
			cfg.RetryInterval = *clpOcspRetryInterval
		case "ocsp.maxresponsesize":
			*cfg.MaxResponseSize = *clpOcspMaxResponseSize
		}
	}
}

// Validate проверяет формат и наличие необходимых параметров, декодирует нужные значения и т.д.
func (cfg *ocspConfig) Validate() error {
	var err error
	if cfg == nil {
		return errors.New("nil OCSP config object")
	}

	if cfg.Disabled {
		return nil
	}

	if cfg.URL == "" {
		return errors.New("invalid OCSP config: empty URL")
	}

	if cfg.Timeout != "" {
		cfg.TimeoutValue, err = time.ParseDuration(cfg.Timeout)
		if err != nil {
			return fmt.Errorf("invalid OCSP config: failed to parse timeout: [%w]", err)
		}
	}

	cfg.DigestOIDValue, err = oidToAsn(cfg.DigestOID)
	if err != nil {
		return fmt.Errorf("invalid OCSP config: failed to parse digestoid: [%w]", err)
	}

	cfg.NameDigestValue, err = base64.StdEncoding.DecodeString(cfg.NameDigest)
	if err != nil {
		return fmt.Errorf("invalid OCSP config: failed to parse OCSP namedigest: [%w]", err)
	}
	if len(cfg.NameDigestValue) == 0 {
		return errors.New("invalid OCSP config: decoded OCSP namedigest is empty")
	}

	cfg.KeyDigestValue, err = base64.StdEncoding.DecodeString(cfg.KeyDigest)
	if err != nil {
		return fmt.Errorf("invalid OCSP config: failed to parse OCSP keydigest: [%w]", err)
	}
	if len(cfg.KeyDigestValue) == 0 {
		return errors.New("invalid OCSP config: decoded OCSP keydigest is empty")
	}

	cfg.Certificate, err = loadCertificate(cfg.Cert, cfg.CertFile)
	if err != nil {
		return fmt.Errorf("invalid OCSP config: failed to load certificate: [%w]", err)
	}

	if cfg.NonceSize < 0 {
		return errors.New("invalid OCSP config: noncesize")
	}

	if cfg.RetryCount < 0 {
		return errors.New("invalid OCSP config: retrycount")
	}

	if cfg.RetryInterval != "" {
		cfg.RetryIntervalValue, err = time.ParseDuration(cfg.RetryInterval)
		if err != nil {
			return fmt.Errorf("invalid OCSP config: failed to parse retryinterval: [%w]", err)
		}
	}

	if cfg.MaxResponseSize == nil {
		return errors.New("invalid OCSP config: nil maxresponsesize")
	}
	if *cfg.MaxResponseSize < 0 {
		return errors.New("invalid OCSP config: maxresponsesize")
	}

	return nil
}
