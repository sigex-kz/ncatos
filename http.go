package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// httpMonitorStart проверяет конфигурацию и запускает goroutine-у мониторинга HTTP сервера.
//
// ctx - контекст выхода. При отмене данного контекста все запущенные goroutine-ы должны завершить работу.
// Возвращает канал, который будет закрыт при ошибке запуска/завершении работы goroutine-ы мониторинга.
// В остальных случаях через него будут возвращены результаты работы мониторинга
func httpMonitorStart(ctx context.Context) <-chan error {
	cfg := getAppContext().Config.HTTP
	resultChannel := make(chan error, 1)

	// создаем логгер для HTTP
	ml := getAppContext().Logger.With().
		Str("module", "monitor").Str("protocol", string(protoHTTP)).
		Str("url", cfg.URL).Logger()

	// создаем клиента для работы с HTTP с поддержкой сетевого таймута
	mc := &http.Client{
		Transport: &http.Transport{},
		Timeout:   cfg.TimeoutValue,
	}

	// объект метрик
	mt := getAppContext().Metrics

	// флаг вывода расширенного лога
	verbose := getAppContext().Config.Log.Verbose

	// запускаем gorotuine-у монитора
	sch := make(chan struct{})
	go func() {
		// горутина инициализирована - закрываем канал запуска
		close(sch)

		var lastError error

		// при выходе пишем ошибку и закрываем канал
		defer func() {
			// выводим ошибку в канал и в протокол
			le := ml.Log()
			if lastError != nil {
				select {
				case resultChannel <- lastError:
				default:
				}
				le.Err(lastError)
			}
			le.Msg("stop")
			// всегда закрываем канал
			close(resultChannel)
		}()

		// основной цикл обработки
		for i := 0; cfg.RetryCount == 0 || i < cfg.RetryCount; i++ {
			// выходим из goroutine-ы при отмене контекста
			if ctx.Err() != nil {
				break
			}

			// создаем событие протокола
			le := ml.Log().Int("num", i+1)

			// отправляем запрос на сервер
			nr, err := getRequest(ctx, mc, cfg.URL, *cfg.MaxResponseSize)
			if nr.StatusCode == 0 && nr.SendReceiveTime == 0 {
				// произошла ошибка при формировании запроса - завершаем goroutine-у
				lastError = errors.New("failed to create HTTP request")
				break
			}

			// обновляем статистику времени обработки запроса
			mt.RequestProcessingTimeObserve(protoHTTP, nr.SendReceiveTime)

			// выведем тело и время обработки запроса в протокол
			if verbose {
				le.Str("response", base64.StdEncoding.EncodeToString(nr.Body)).
					Dur("processingTime", nr.SendReceiveTime)
			}

			// наконец обработаем ошибку postRequest
			if err != nil {
				if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
					// отменен основной контекст - просто выходим из goroutine-ы
					break
				}

				// обновляем статистику и протоколируем ошибку
				mt.ResponseError(protoHTTP, responseErrorNet)
				le.Str("errorType", string(responseErrorNet)).Err(fmt.Errorf("receive HTTP response: [%w]", err)).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// проверим HTTP статус код ответа - успешные коды в диапазоне (200,300)
			if nr.StatusCode < http.StatusOK || nr.StatusCode >= http.StatusMultipleChoices {
				mt.ResponseError(protoHTTP, responseErrorHTTP)
				err = fmt.Errorf("receive HTTP response: invalid HTTP status code: [%d]: [%s]", nr.StatusCode, http.StatusText(nr.StatusCode))
				le.Str("errorType", string(responseErrorHTTP)).Err(err).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			le.Msg("request succeed")

			// пишем доп. данные
			if verbose {
				le.Int("statusCode", nr.StatusCode).Str("contentType", nr.ContentType)
			}

			// ждем указанный таймаут
			if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
				waitForTimeout(ctx, cfg.RetryIntervalValue)
			}
		}
	}()
	<-sch

	ml.Log().
		Int("retryCount", cfg.RetryCount).Dur("retryInterval", cfg.RetryIntervalValue).
		Msg("start")
	return resultChannel
}
