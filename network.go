package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

/*
  Реализация сетевого взаимодействия.
*/

// netResult содержит результаты обработки сетевого запроса
type networkResult struct {
	// HTTP статус код
	StatusCode int

	// Время обработки (от оправки запроса до чтения заголовков ответа)
	SendReceiveTime time.Duration

	// Тип содержимого
	ContentType string

	// Тело ответа
	Body []byte
}

// postRequest создает HTTP запрос с указанными данными, отправляет его серверу,
// дожидается ответа и считывает тело ответа.
//
// Максимально считывается maxResponseSize байт ответа.
func postRequest(ctx context.Context, client *http.Client, protocol protocolType, url string, maxSize int64, body []byte) (networkResult, error) {
	// создаем объект под результат обработки
	result := networkResult{}

	// создаем HTTP запрос
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return result, fmt.Errorf("failed to create HTTP request: [%s], [%w]", url, err)
	}

	// устанавливаем заголовок
	switch protocol {
	case protoOCSP:
		httpRequest.Header.Set("Content-Type", "application/ocsp-request")
	case protoTSP:
		httpRequest.Header.Set("Content-Type", "application/timestamp-query")
	}

	// отправляем ответ серверу и дожидаемся ответа (таймаут определен в клиенте)
	// здесь же считаем статистику времени обработки запроса.
	startTime := time.Now()
	httpResponse, err := client.Do(httpRequest)
	result.SendReceiveTime = time.Since(startTime)
	if err != nil {
		return result, fmt.Errorf("failed to post request: [%s], [%w]", url, err)
	}

	// в любом случае закрываем тело ответа
	defer func() {
		_ = httpResponse.Body.Close() //nolint:errcheck // ошибка закрытия тела ответа неважна в данном случае
	}()

	// запоминаем статус код и тип содержимого
	result.StatusCode = httpResponse.StatusCode
	result.ContentType = httpResponse.Header.Get("Content-Type")

	// считываем тело с учетом максимального размера
	if maxSize > 0 {
		limitedReader := &io.LimitedReader{
			R: httpResponse.Body,
			N: maxSize,
		}
		result.Body, err = io.ReadAll(limitedReader)
		if err == nil && limitedReader.N == 0 {
			err = fmt.Errorf("maximum response body size exceeded: [%d]", maxSize)
		}
	} else {
		result.Body, err = io.ReadAll(httpResponse.Body)
	}

	return result, err
}
