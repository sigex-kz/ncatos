package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

/* Определение и разбор файла конфигурации */

// appConfig определяет структуру файла конфигурации.
// Файл конфигурации должен быть определен в формате JSONC.
type appConfig struct {
	// Настройки протоколирования
	Log logConfig `json:"log" yaml:"log"`
	// Настройки предоставления метрик по HTTP
	Metrics metricsConfig `json:"metrics" yaml:"metrics"`
	// Настройки взаимодействия с OCSP сервером
	OCSP ocspConfig `json:"ocsp,omitempty" yaml:"ocsp,omitempty"`
	// Настройки взаимодействия с TSP сервером
	TSP tspConfig `json:"tsp,omitempty" yaml:"tsp,omitempty"`
}

// buildConfig создает объект конфигурации, считав настройки из файла и дополнив
// их параметрами командной строки. Параметры командной строки имеют приоритет.
func buildConfig() (*appConfig, error) {
	var out appConfig

	// пробуем декодировать из файла (jsonc!)
	if clpConfigPath != nil && *clpConfigPath != "" {
		fn := filepath.Clean(*clpConfigPath)
		jcEncoded, readFileError := os.ReadFile(fn)
		if readFileError != nil {
			return nil, fmt.Errorf("failed to read config file: [%s], [%w]", fn, readFileError)
		}

		yamlDecoder := yaml.NewDecoder(bytes.NewReader(jcEncoded))
		yamlDecoder.KnownFields(true)
		if decodeError := yamlDecoder.Decode(&out); decodeError != nil {
			return nil, fmt.Errorf("failed to parse config file: [%s], [%w]", fn, decodeError)
		}
	}

	// установим параметры по умолчанию
	out.Log.SetDefaults()
	out.Metrics.SetDefaults()
	out.OCSP.SetDefaults()
	out.TSP.SetDefaults()

	// обработаем параметры командной строки. Сначала получим их список
	var givenFlags []*flag.Flag
	flag.CommandLine.Visit(func(f *flag.Flag) {
		givenFlags = append(givenFlags, f)
	})

	// затем вызовем функции обновления соответствующих объектов
	out.Log.UpdateCommandLine(givenFlags)
	out.Metrics.UpdateCommandLine(givenFlags)
	out.OCSP.UpdateCommandLine(givenFlags)
	out.TSP.UpdateCommandLine(givenFlags)

	// проверим, декодируя переданные параметры в нужный формат
	if validateError := out.Log.Validate(); validateError != nil {
		return nil, validateError
	}
	if validateError := out.Metrics.Validate(); validateError != nil {
		return nil, validateError
	}
	if validateError := out.OCSP.Validate(); validateError != nil {
		return nil, validateError
	}
	if validateError := out.TSP.Validate(); validateError != nil {
		return nil, validateError
	}

	return &out, nil
}
