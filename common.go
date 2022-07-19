package main

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

/* Различные общие функции и определения */

// поддерживаемы типы HTTP протоколов
type protocolType string

const (
	protoOCSP protocolType = "ocsp"
	protoTSP  protocolType = "tsp"
)

// поддерживаемы типы ошибок
type responseErrorType string

const (
	responseErrorNet      responseErrorType = "net"
	responseErrorHTTP     responseErrorType = "http"
	responseErrorAsn      responseErrorType = "asn1"
	responseErrorContents responseErrorType = "contents"
)

// waitForTimeout сервисная функция, позволяющая дождаться таймаута или отмены контекста
func waitForTimeout(ctx context.Context, timeout time.Duration) {
	if ctx.Err() != nil || timeout == 0 {
		return
	}
	tm := time.NewTimer(timeout)
	defer tm.Stop()
	select {
	case <-tm.C:
	case <-ctx.Done():
	}
}

// random позволяет сгенерировать случайный данные размером size байт.
// Если size <= 0, то возвращает пустой массив.
func random(size int) ([]byte, error) {
	if size < 1 {
		return []byte{}, nil
	}

	out := make([]byte, size)
	//nolint:gosec // not crypto random generator is intentionally used here for
	generatedSize, err := rand.New(rand.NewSource(time.Now().UnixNano())).Read(out)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random data: [%+w]", err)
	}
	if generatedSize != size {
		return nil, fmt.Errorf("not enough random data generated: [%d], [%d]", generatedSize, size)
	}
	return out, nil
}

// oidToAsn сервисная функция позволяющая сконвертировать строковое представление OID-а в структуру asn1.ObjectIdentifier
func oidToAsn(oid string) (asn1.ObjectIdentifier, error) {
	if oid == "" {
		return asn1.ObjectIdentifier{}, errors.New("empty OID")
	}

	// делим строковое представление с разделителем '.'
	ids := strings.Split(oid, ".")

	if len(ids) < 2 { //nolint:gomnd // в OID-е должно быть как минимум 2 элемента
		return asn1.ObjectIdentifier{}, fmt.Errorf("invalid OID parts length: %d", len(ids))
	}

	// пытаемся сконвертировать строквые представления элементов OID-а в числа
	intIds := make([]int, len(ids))
	var convertError error
	for i, v := range ids {
		if intIds[i], convertError = strconv.Atoi(v); convertError != nil {
			return asn1.ObjectIdentifier{}, fmt.Errorf("failed to convert OID part: [%d], [%s], [%w]", i, v, convertError)
		}
	}

	// возвращаем сформированный OID
	return asn1.ObjectIdentifier(intIds), nil
}

// loadCertificate позволяет загрузить и разобрать сертификат.
//
// Сначала проверяем параметр `cert` - если не пустая строка, то должна содержать ASN.1 DER в base64.
// Иначе в параметре `certFileName` должно быть имя файла сертификата. Считываем файл и
// пытаемся декодировать - сначала как PEM, затем как ASN.1 DER.
func loadCertificate(cert, certFileName string) (*x509.Certificate, error) {
	var (
		err     error
		derCert []byte
	)

	switch {
	case cert != "":
		// декодируем из base64
		derCert, err = base64.StdEncoding.DecodeString(cert)
		if err != nil {
			return nil, fmt.Errorf("failed to decode from cert: [%w]", err)
		}

	case certFileName != "":
		// читаем сертификат из файла
		fn := filepath.Clean(certFileName)
		fileContents, readFileError := os.ReadFile(fn)
		if readFileError != nil {
			return nil, fmt.Errorf("failed to read from certfile: [%s], [%w]", fn, readFileError)
		}

		// пытаемся декодировать как PEM, если не получилось - это ASN.1 DER
		var pemblock *pem.Block
		pemblock, derCert = pem.Decode(fileContents)
		if pemblock != nil {
			if pemblock.Type != "CERTIFICATE" {
				return nil, fmt.Errorf("invalid certificate PEM header: [%s]", pemblock.Type)
			}
			derCert = pemblock.Bytes
		}

	default:
		return nil, errors.New("cert/certfile not configured")
	}

	// здесь должен быть буфер с закодированным сертификатом
	if len(derCert) == 0 {
		return nil, errors.New("failed to load certificate (nil)")
	}

	// парсим сертификат из ASN.1 DER
	out, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: [%w]", err)
	}
	return out, nil
}
