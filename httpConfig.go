package main

import (
	"errors"
	"flag"
	"fmt"
	"time"
)

// значения по умолчанию для "опасных" флагов
const (
	defaultHTTPMaxResponseSize int64 = 8192 // байт
	defaultHTTPRetryInterval         = "15m"
)

// httpConfig определяет структуру с настройками взаимодействия с HTTP сервером.
type httpConfig struct {
	// Disabled флаг позволяет отключить опрос HTTP сервера при установке в значение true.
	Disabled bool `json:"disabled" yaml:"disabled"`

	// URL HTTP сервера
	URL string `json:"url" yaml:"url"`

	// Timeout сетевого взаимодействия. Должно быть значение допустимое для time.ParseDuration().
	// Пустая строка - без таймаута.
	Timeout      string        `json:"timeout" yaml:"timeout"`
	TimeoutValue time.Duration `json:"-" yaml:"-"`

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

	// MaxResponseSize определяет максимально допустимый размер ответа от сервера HTTP в байтах.
	// Если установлен в 0, то размер не ограничен.
	MaxResponseSize *int64 `json:"maxresponsesize" yaml:"maxresponsesize"`
}

// SetDefaults позволяет инициализировать не заданные/критичные поля значениями по умолчанию.
func (cfg *httpConfig) SetDefaults() {
	if cfg == nil {
		return
	}
	if cfg.RetryInterval == "" {
		cfg.RetryInterval = defaultHTTPRetryInterval
	}
	if cfg.MaxResponseSize == nil {
		cfg.MaxResponseSize = new(int64)
	}
	if *cfg.MaxResponseSize == 0 {
		*cfg.MaxResponseSize = defaultHTTPMaxResponseSize
	}
}

// UpdateCommandLine позволяет проверить и установить значения объекта конфигурации из
// параметров командной строки.
func (cfg *httpConfig) UpdateCommandLine(givenFlags []*flag.Flag) {
	if cfg == nil {
		return
	}
	for _, f := range givenFlags {
		switch f.Name {
		case "http.disabled":
			cfg.Disabled = *clpHTTPDisabled
		case "http.url":
			cfg.URL = *clpHTTPURL
		case "http.timeout":
			cfg.Timeout = *clpHTTPTimeout
		case "http.retrycount":
			cfg.RetryCount = *clpHTTPRetryCount
		case "http.retryinterval":
			cfg.RetryInterval = *clpHTTPRetryInterval
		case "http.maxresponsesize":
			*cfg.MaxResponseSize = *clpHTTPMaxResponseSize
		}
	}
}

// Validate проверяет формат и наличие необходимых параметров, декодирует нужные значения и т.д.
func (cfg *httpConfig) Validate() error {
	var err error
	if cfg == nil {
		return errors.New("nil HTTP config object")
	}

	if cfg.Disabled {
		return nil
	}

	if cfg.URL == "" {
		return errors.New("invalid HTTP config: empty URL")
	}

	if cfg.Timeout != "" {
		cfg.TimeoutValue, err = time.ParseDuration(cfg.Timeout)
		if err != nil {
			return fmt.Errorf("invalid HTTP config: failed to parse timeout: [%w]", err)
		}
	}

	if cfg.RetryCount < 0 {
		return errors.New("invalid HTTP config: retrycount")
	}

	if cfg.RetryInterval != "" {
		cfg.RetryIntervalValue, err = time.ParseDuration(cfg.RetryInterval)
		if err != nil {
			return fmt.Errorf("invalid HTTP config: failed to parse retryinterval: [%w]", err)
		}
	}

	if cfg.MaxResponseSize == nil {
		return errors.New("invalid HTTP config: nil maxresponsesize")
	}
	if *cfg.MaxResponseSize < 0 {
		return errors.New("invalid HTTP config: maxresponsesize")
	}

	return nil
}
