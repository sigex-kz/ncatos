package main

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/rs/zerolog"
)

// ocspMonitor представляет собой тело goroutine-ы, выполняющей мониторинг настроенного
// в appContext.Config.OCSP сервера.
// ctx - контекст по закрытии которого необходимо завершить работу goroutine-ы.
// startupChannel - канал, который должен быть закрыт после корректной инциализации
//   goroutine-ы. При этом если при инициализации произошла ошибка, то она передается
//   в канал. В противном случае в канале nil (или ничего).
// resultChannel - канал, с помощью которого отслеживается завершение goroutine-ы. Чтение из
//   данного канала разрешено только после закрытия startupChannel. В общем случае канал
//   закрывается при отмене ctx. Единственная ошибка, приводящая к другому варианту завершения
//   goroutine-ы - ошибка создания запроса (при генерации nonce, например).
func ocspMonitorStart(ctx context.Context) <-chan error {
	cfg := getAppContext().Config.OCSP
	resultChannel := make(chan error, 1)

	// создаем логгер для OCSP
	ml := getAppContext().Logger.With().
		Str("module", "monitor").Str("protocol", string(protoOCSP)).
		Str("url", cfg.URL).Logger()

	// создаем шаблон запроса
	req := &ocspRequest{
		TBSRequest: ocspTBSRequest{
			RequestList: []ocspSingleRequest{
				{
					ReqCert: ocspCertID{
						HashAlgorithm: pkix.AlgorithmIdentifier{
							Algorithm:  cfg.DigestOIDValue,
							Parameters: asn1.NullRawValue,
						},
						NameHash:      cfg.NameDigestValue,
						IssuerKeyHash: cfg.KeyDigestValue,
						SerialNumber:  cfg.Certificate.SerialNumber,
					},
				},
			},
		},
	}

	// создаем клиента для работы с HTTP с поддержкой сетевого таймута
	mc := &http.Client{
		Transport: &http.Transport{},
		Timeout:   cfg.TimeoutValue,
	}

	// объект метрик
	mt := getAppContext().Metrics

	// флаг вывода расширенного лога
	verbose := getAppContext().Config.Log.Verbose

	// запускаем собственно goroutine-y мониторинка
	sch := make(chan struct{})
	go func() {
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

			// кодируем запрос
			reqEnc, nonce, encodeError := ocspEncodeRequest(req, cfg.NonceSize)
			if encodeError != nil {
				// при ошибках кодирования запроса - завершаем goroutine-у
				lastError = encodeError
				break
			}

			// создаем событие протокола
			le := ml.Log().Int("num", i+1)
			if verbose {
				le.Str("request", base64.StdEncoding.EncodeToString(reqEnc)).
					Str("nonce", base64.StdEncoding.EncodeToString(nonce))
			}

			// отправляем запрос на сервер
			nr, err := postRequest(ctx, mc, protoOCSP, cfg.URL, *cfg.MaxResponseSize, reqEnc)
			if nr.StatusCode == 0 && nr.SendReceiveTime == 0 {
				// произошла ошибка при формировании запроса - завершаем goroutine-у
				lastError = errors.New("failed to create OCSP HTTP request")
				break
			}

			// обновляем статистику времени обработки запроса
			mt.RequestProcessingTimeObserve(protoOCSP, nr.SendReceiveTime)

			// выведем тело запроса в протокол (даже при ошибке)
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
				mt.ResponseError(protoOCSP, responseErrorNet)
				le.Str("errorType", string(responseErrorNet)).Err(fmt.Errorf("receive OCSP response: [%w]", err)).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// проверим HTTP статус код ответа - успешные коды в диапазоне (200,300)
			if nr.StatusCode < http.StatusOK || nr.StatusCode >= http.StatusMultipleChoices {
				mt.ResponseError(protoOCSP, responseErrorHTTP)
				err = fmt.Errorf("receive OCSP response: invalid HTTP status code: [%d]: [%s]", nr.StatusCode, http.StatusText(nr.StatusCode))
				le.Str("errorType", string(responseErrorHTTP)).Err(err).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// пишем доп. данные об ответе
			if verbose {
				le.Int("statusCode", nr.StatusCode).Str("contentType", nr.ContentType)
			}

			// декодируем ответ
			var resp ocspResponse
			if _, decodeError := asn1.Unmarshal(nr.Body, &resp); decodeError != nil {
				mt.ResponseError(protoOCSP, responseErrorAsn)
				le.Str("errorType", string(responseErrorAsn)).Err(fmt.Errorf("decode OCSP response: [%w]", decodeError)).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// проверяем содержимое ответа
			if validateError := ocspResponseValidate(&resp, req, nonce, verbose, le); validateError != nil {
				mt.ResponseError(protoOCSP, responseErrorContents)
				le.Str("errorType", string(responseErrorContents)).Err(fmt.Errorf("validate OCSP response: [%w]", validateError)).Msg("request failed")
			} else {
				le.Msg("request succeed")
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

// ocspEncodeRequest позволяет закодировать OCSP запрос в ASN.1.
// Если передан не нулевой размер nonceSize, то функция генерирует случайный nonce указанного размера
// и добавляет его в запрос перед кодированием.
//
// Возвращает закодированный запрос, nonce (для проверки) и ошибку.
// Следует учитывать, что возвращаемый nonce закодирован как ASN.1 OCTET STRING (т.е. в соответствующем
// расширении Value дважды упакован в ASN.1 OCTET STRING).
func ocspEncodeRequest(request *ocspRequest, nonceSize int) (encoded, nonce []byte, outError error) {
	if nonceSize > 0 {
		// генерируем случайный nonce
		nonce, outError = random(nonceSize)
		if outError != nil {
			return nil, nil, outError
		}
		// кодируем nonce в ASN.1 OCTET STRING
		nonce, outError = asn1.Marshal(nonce)
		if outError != nil {
			return nil, nil, fmt.Errorf("failed to encode OCSP nonce to ASN.1:[%w]", outError)
		}
		// добавляем его в запрос
		request.TBSRequest.RequestExtensions = []pkix.Extension{
			{
				Id:       oidOCSPNonceExtension,
				Critical: false,
				Value:    nonce,
			},
		}
	}

	// кодируем CertID
	if len(request.TBSRequest.RequestList[0].ReqCert.Raw) == 0 {
		request.TBSRequest.RequestList[0].ReqCert.Raw, outError = asn1.Marshal(request.TBSRequest.RequestList[0].ReqCert)
		if outError != nil {
			return nil, nil, fmt.Errorf("failed to encode OCSP request CertID: [%w]", outError)
		}
	}

	// кодируем запрос в ASN.1
	encoded, outError = asn1.Marshal(*request)
	if outError != nil {
		return nil, nil, fmt.Errorf("failed to encode OCSP request: [%w]", outError)
	}
	return encoded, nonce, outError
}

// ocspResponseValidate проверяет корректность декодированного OCSP ответа и сравнивает
// его содержимое с отправленным запросом.
// Если указан флаг verbose, то в le должна записываться доп. информация о содержимом ответа.
func ocspResponseValidate(response *ocspResponse, request *ocspRequest, nonce []byte, verbose bool, le *zerolog.Event) error {
	// проверяем статус ответа
	if response.ResponseStatus != asn1.Enumerated(0) {
		return fmt.Errorf("invalid OCSP ResponseStatus: %d", int(response.ResponseStatus))
	}

	// проверяем тип и содержимое - должен быть непустой ocspBasicResponse
	if !response.ResponseBytes.ResponseType.Equal(oidOCSPBasicResponse) {
		return fmt.Errorf("invalid OCSP ResponseType: [%s]", response.ResponseBytes.ResponseType.String())
	}
	if len(response.ResponseBytes.Response) == 0 {
		return errors.New("empty OCSP BasicResponse")
	}

	// декодируем BasicResponse
	var basicResponse ocspBasicResponse
	if _, decodeError := asn1.Unmarshal(response.ResponseBytes.Response, &basicResponse); decodeError != nil {
		return fmt.Errorf("failed to decode OCSP BasicRespons: [%w]", decodeError)
	}

	// выведем алгоритм подписи
	if verbose {
		le.Str("respSignAlgorithm", basicResponse.SignatureAlgorithm.Algorithm.String())
	}

	// ищем информацию со статусом для CertID из сертификата
	var found bool
	for i := range basicResponse.TBSResponseData.Responses {
		if bytes.Equal(basicResponse.TBSResponseData.Responses[i].CertID.Raw, request.TBSRequest.RequestList[0].ReqCert.Raw) {
			found = true
			break
		}
	}
	if !found {
		return errors.New("no status info for certificate in OCSP response")
	}

	// проверяем наличие nonce
	if len(nonce) > 0 {
		found = false
		for i := range basicResponse.TBSResponseData.Extensions {
			ext := basicResponse.TBSResponseData.Extensions[i]
			if ext.Id.Equal(oidOCSPNonceExtension) {
				if !bytes.Equal(ext.Value, nonce) {
					return errors.New("OCSP response nonce mismatch")
				}
				found = true
				break
			}
		}
		if !found {
			return errors.New("nonce not found in OCSP response")
		}
	}

	return nil
}
