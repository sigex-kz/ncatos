package main

import (
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"time"
)

// значения по умолчанию для "опасных" флагов
const (
	defaultTspNonceSize             = 8    // байт
	defaultTspMaxResponseSize int64 = 8192 // байт
	defaultTspRetryInterval         = "15m"
)

// tspConfig определяет структуру с настройками взаимодействия с TSP сервером.
type tspConfig struct {
	// Disabled флаг позволяет отключить опрос TSP сервера при установке в значение true.
	Disabled bool `json:"disabled" yaml:"disabled"`

	// URL TSP сервера
	URL string `json:"url" yaml:"url"`

	// Timeout сетевого взаимодействия. Должно быть значение допустимое для time.ParseDuration().
	// Пустая строка - без таймаута.
	Timeout      string        `json:"timeout" yaml:"timeout"`
	TimeoutValue time.Duration `json:"-" yaml:"-"`

	// PolicyOID содержит значение OID алгоритма политики формирования метки времени. Фактически
	// определяет алгоритм подписи метки времени.
	// Предполагается, что данный OID будет иметь одно из следующих значений:
	//   - "1.2.398.3.3.2.6.1" - политика для подписи квитанции метки времени на алгоритме ГОСТ 34.310-2004 с OID 1.2.398.3.10.1.1.1.2;
	//   - "1.2.398.3.3.2.6.2" - политика для подписи квитанции метки времени на алгоритме RSA-SHA256;
	//   - "1.2.398.3.3.2.6.3" - политика для подписи квитанции метки времени на алгоритме ГОСТ 34.310-2004 с OID 1.3.6.1.4.1.6801.1.2.2;
	//   - "1.2.398.3.3.2.6.4" - политика для подписи квитанции метки времени на алгоритме ГОСТ 34.10-2015 (512) с OID 1.2.398.3.10.1.1.2.3.2;
	PolicyOID      string                `json:"policyoid" yaml:"policyoid"`
	PolicyOIDValue asn1.ObjectIdentifier `json:"-" yaml:"-"`

	// DigestOID OID алгоритма хеширования, использованного для вычисления значения хеша
	// данных на которую получаем метку времени (здесь tspMessageImprint.hashAlgorithm).
	DigestOID      string                `json:"digestoid" yaml:"digestoid"`
	DigestOIDValue asn1.ObjectIdentifier `json:"-" yaml:"-"`

	// Digest содержит значение хеша данных на которую получаем метку времени (здесь MessageImprint.HashedMessage), закодированное в base64.
	// Если данное поле содержит пустую строку, то должно быть указано не нулевой значение в поле DigestSize.
	Digest      string `json:"digest" yaml:"digest"`
	DigestValue []byte `json:"-" yaml:"-"`

	// DigestSize содержит размер случайно генерируемых данных в байтах, используемых как значение хеша данных,
	// на которые получаем метку времени. Т.е. если в поле Digest пустая строка, то вместо значения хеша
	// используются случайно сгенерированные данные указанного размера.
	// Размер метки должен указываться в соответствии с алгоритмом в поле DigestOID.
	// Данное поле должно содержать не нулевое значение, если в поле Digest пустая строка.
	DigestSize int `json:"digestsize" yaml:"digestsize"`

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

	// MaxResponseSize определяет максимально допустимый размер ответа от сервера TSP в байтах.
	// Если установлен в 0, то размер не ограничен.
	MaxResponseSize *int64 `json:"maxresponsesize" yaml:"maxresponsesize"`
}

// SetDefaults позволяет инициализировать не заданные/критичные поля значениями по умолчанию.
func (cfg *tspConfig) SetDefaults() {
	if cfg == nil {
		return
	}
	if cfg.NonceSize < 1 {
		cfg.NonceSize = defaultTspNonceSize
	}
	if cfg.RetryInterval == "" {
		cfg.RetryInterval = defaultTspRetryInterval
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
func (cfg *tspConfig) UpdateCommandLine(givenFlags []*flag.Flag) {
	if cfg == nil {
		return
	}
	for _, f := range givenFlags {
		switch f.Name {
		case "tsp.disabled":
			cfg.Disabled = *clpTspDisabled
		case "tsp.url":
			cfg.URL = *clpTspURL
		case "tsp.timeout":
			cfg.Timeout = *clpTspTimeout
		case "tsp.digestoid":
			cfg.DigestOID = *clpTspDigestOID
		case "tsp.policyoid":
			cfg.PolicyOID = *clpTspPolicyOID
		case "tsp.digest":
			cfg.Digest = *clpTspDigest
		case "tsp.digestsize":
			cfg.DigestSize = *clpTspDigestSize
		case "tsp.noncesize":
			cfg.NonceSize = *clpTspNonceSize
		case "tsp.retrycount":
			cfg.RetryCount = *clpTspRetryCount
		case "tsp.retryinterval":
			cfg.RetryInterval = *clpTspRetryInterval
		case "ocsp.maxresponsesize":
			*cfg.MaxResponseSize = *clpTspMaxResponseSize
		}
	}
}

// Validate проверяет формат и наличие необходимых параметров, декодирует нужные значения и т.д.
func (cfg *tspConfig) Validate() error {
	var err error
	if cfg == nil {
		return errors.New("nil TSP config object")
	}

	if cfg.Disabled {
		return nil
	}

	if cfg.URL == "" {
		return errors.New("invalid TSP config: empty URL")
	}

	if cfg.Timeout != "" {
		cfg.TimeoutValue, err = time.ParseDuration(cfg.Timeout)
		if err != nil {
			return fmt.Errorf("invalid TSP config: failed to parse timeout: [%w]", err)
		}
	}

	cfg.PolicyOIDValue, err = oidToAsn(cfg.PolicyOID)
	if err != nil {
		return fmt.Errorf("invalid TSP config: failed to parse policyoid: [%w]", err)
	}

	cfg.DigestOIDValue, err = oidToAsn(cfg.DigestOID)
	if err != nil {
		return fmt.Errorf("invalid TSP config: failed to parse digestoid: [%w]", err)
	}

	if cfg.Digest != "" {
		cfg.DigestValue, err = base64.StdEncoding.DecodeString(cfg.Digest)
		if err != nil {
			return fmt.Errorf("invalid TSP config: failed to parse digest: [%w]", err)
		}
	}
	if len(cfg.DigestValue) == 0 {
		if cfg.DigestSize < 1 {
			return errors.New("invalid TSP config: digestsize")
		}
	}

	if cfg.NonceSize < 0 {
		return errors.New("invalid TSP config: noncesize")
	}

	if cfg.RetryCount < 0 {
		return errors.New("invalid TSP config: retrycount")
	}

	if cfg.RetryInterval != "" {
		cfg.RetryIntervalValue, err = time.ParseDuration(cfg.RetryInterval)
		if err != nil {
			return fmt.Errorf("invalid TSP config: failed to parse retryinterval: [%w]", err)
		}
	}

	if cfg.MaxResponseSize == nil {
		return errors.New("invalid TSP config: nil maxresponsesize")
	}
	if *cfg.MaxResponseSize < 0 {
		return errors.New("invalid TSP config: maxresponsesize")
	}

	return nil
}
