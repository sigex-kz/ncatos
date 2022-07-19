package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"
)

// newAppLogger создает объект ведения протокола по заданному объекту конфигурации.
// По завершении работы с протоколом следует вызвать возвращаемую функцию его закрытия.
func newAppLogger(cfg *logConfig) (*zerolog.Logger, func(), error) {
	outCloseFunc := func() {}
	if cfg == nil {
		return nil, outCloseFunc, errors.New("nil logger config object")
	}

	out := zerolog.Nop()
	if cfg.Enabled {
		var lw []io.Writer
		if cfg.Console {
			lw = append(lw, os.Stdout)
		}
		if cfg.FileName != "" {
			logFile, err := os.OpenFile(filepath.Clean(cfg.FileName), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
			if err != nil {
				return nil, outCloseFunc, fmt.Errorf("failed to create log file:[%w]", err)
			}
			outCloseFunc = func() {
				// закрываем файл
				_ = logFile.Close() //nolint:errcheck // ошибку закрытия файла протокола можно игнорировать
			}
			lw = append(lw, zerolog.SyncWriter(logFile))
		}
		if len(lw) > 0 {
			out = zerolog.New(io.MultiWriter(lw...))
		}
	}

	// базовая настройка
	out = out.With().Timestamp().Logger()
	return &out, outCloseFunc, nil
}

// logConfig определяет структуру с параметрами журналирования
type logConfig struct {
	// Disabled позволяет отключить протоколирование (значение true)
	Disabled bool `json:"disabled" yaml:"disabled"`

	// Enabled позволяет включить протоколирование.
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Console позволяет вести протоколирование в консоль (значение true)
	Console bool `json:"console" yaml:"console"`

	// Filename содержит строку с именем файла в которую следует вести протокол.
	// Если строка пустая, то протоколирование в файл не ведется.
	// Размер файла не отслеживается.
	FileName string `json:"filename" yaml:"filename"`

	// Verbose позволяет выводить дополнительную информацию при протоколировании.
	// Например, содержимое ответов и запросов к серверу.
	Verbose bool `json:"verbose" yaml:"verbose"`
}

// SetDefaults позволяет инициализировать не заданные/критичные поля значениями по умолчанию.
func (cfg *logConfig) SetDefaults() {
	if cfg == nil {
		return
	}
}

// UpdateCommandLine позволяет проверить и установить значения объекта конфигурации из
// параметров командной строки.
func (cfg *logConfig) UpdateCommandLine(givenFlags []*flag.Flag) {
	if cfg == nil {
		return
	}
	for _, f := range givenFlags {
		switch f.Name {
		case "log.enabled":
			cfg.Enabled = *clpLogEnabled
		case "log.console":
			cfg.Console = *clpLogConsole
		case "log.verbose":
			cfg.Verbose = *clpLogVerbose
		case "log.filename":
			cfg.FileName = *clpLogFileName
		}
	}
}

// Validate проверяет формат и наличие необходимых параметров, декодирует нужные значения и т.д.
func (cfg *logConfig) Validate() error {
	if cfg == nil {
		return errors.New("nil logger config object")
	}

	if !cfg.Enabled {
		return nil
	}
	if !cfg.Console && cfg.FileName == "" {
		cfg.Enabled = false
	}

	return nil
}
