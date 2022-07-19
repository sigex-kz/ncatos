package main

import (
	"errors"
	"flag"
)

// metricsConfig определяет структуру с параметрами сбора метрик через Prometheus
type metricsConfig struct {
	// Enabled позволяет включить сбор метрик и предоставление их через указанный в
	// Address адрес.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Address по которому будут предоставляться метрики.
	// Поле указывается в формате "host:port". Метрики не собираются, если в поле
	// указана пустая строка.
	//
	// Выдержка из документации по go ([net.Dial(https://pkg.go.dev/net#Dial)]()):
	//   "The host must be a literal IP address, or a host name that can be
	//    resolved to IP addresses. The port must be a literal port number
	//    or a service name. If the host is a literal IPv6 address it must
	//    be enclosed in square brackets, as in "[2001:db8::1]:80" or
	//    "[fe80::1%zone]:80".
	Address string `json:"address" yaml:"address"`
}

// SetDefaults позволяет инициализировать не заданные/критичные поля значениями по умолчанию.
func (cfg *metricsConfig) SetDefaults() {
	if cfg == nil {
		return
	}
}

// UpdateCommandLine позволяет проверить и установить значения объекта конфигурации из
// параметров командной строки.
func (cfg *metricsConfig) UpdateCommandLine(givenFlags []*flag.Flag) {
	if cfg == nil {
		return
	}
	for _, f := range givenFlags {
		switch f.Name {
		case "metrics.enabled":
			cfg.Enabled = *clpMetricsEnabled
		case "metrics.address":
			cfg.Address = *clpMetricsAddress
		}
	}
}

// Validate проверяет формат и наличие необходимых параметров, декодирует нужные значения и т.д.
func (cfg *metricsConfig) Validate() error {
	if cfg == nil {
		return errors.New("nil metrics config object")
	}

	if !cfg.Enabled {
		return nil
	}
	if cfg.Address == "" {
		cfg.Enabled = false
	}

	return nil
}
