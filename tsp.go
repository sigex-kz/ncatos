package main

import (
	"bytes"
	"context"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"github.com/rs/zerolog"
)

// tspMonitorStart проверяет конфигурацию и запускает goroutine-у мониторинга TSP сервера.
//
// ctx - контекст выхода. При отмене данного контекста все запущенные goroutine-ы должны завершить работу.
// Возвращает канал, который будет закрыт при ошибке запуска/завершении работы goroutine-ы мониторинга.
// В остальных случаях через него будут возвращены результаты работы мониторинга
func tspMonitorStart(ctx context.Context) <-chan error {
	cfg := getAppContext().Config.TSP
	resultChannel := make(chan error, 1)

	// создаем логгер для TSP
	ml := getAppContext().Logger.With().
		Str("module", "monitor").Str("protocol", string(protoTSP)).
		Str("url", cfg.URL).Logger()

	// создаем шаблон запроса
	req := &tspRequest{
		Version: 1,
		MessageImprint: tspMessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  cfg.DigestOIDValue,
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: nil,
		},
		ReqPolicy: cfg.PolicyOIDValue,
		Nonce:     nil,
		CertReq:   true,
	}

	// создаем клиента для работы с HTTP с поддержкой сетевого таймута
	mc := &http.Client{
		Transport: &http.Transport{},
		Timeout:   cfg.TimeoutValue,
	}

	// проверим есть ли у нас хеш данных на который получаем метку времени
	digestSize := cfg.DigestSize
	if len(cfg.DigestValue) != 0 {
		// установим постоянный хеш в запрос
		req.MessageImprint.HashedMessage = cfg.DigestValue
		// запомним, что не надо генерировать случайные данные при создании запроса.
		digestSize = 0
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

			// кодируем запрос
			reqEnc, encodeError := tspEncodeRequest(req, digestSize, cfg.NonceSize)
			if encodeError != nil {
				// при ошибках кодирования запроса - завершаем goroutine-у
				lastError = encodeError
				break
			}

			// создаем событие протокола
			le := ml.Log().Int("num", i+1)
			if verbose {
				le.Str("request", base64.StdEncoding.EncodeToString(reqEnc)).
					Str("digest", base64.StdEncoding.EncodeToString(req.MessageImprint.HashedMessage)).
					Str("nonce", base64.StdEncoding.EncodeToString(req.Nonce.Bytes()))
			}

			// отправляем запрос на сервер
			nr, err := postRequest(ctx, mc, protoTSP, cfg.URL, *cfg.MaxResponseSize, reqEnc)
			if nr.StatusCode == 0 && nr.SendReceiveTime == 0 {
				// произошла ошибка при формировании запроса - завершаем goroutine-у
				lastError = errors.New("failed to create TSP HTTP request")
				break
			}

			// обновляем статистику времени обработки запроса
			mt.RequestProcessingTimeObserve(protoTSP, nr.SendReceiveTime)

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
				mt.ResponseError(protoTSP, responseErrorNet)
				le.Str("errorType", string(responseErrorNet)).Err(fmt.Errorf("receive TSP response: [%w]", err)).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// проверим HTTP статус код ответа - успешные коды в диапазоне (200,300)
			if nr.StatusCode < http.StatusOK || nr.StatusCode >= http.StatusMultipleChoices {
				mt.ResponseError(protoTSP, responseErrorHTTP)
				err = fmt.Errorf("receive TSP response: invalid HTTP status code: [%d]: [%s]", nr.StatusCode, http.StatusText(nr.StatusCode))
				le.Str("errorType", string(responseErrorHTTP)).Err(err).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// пишем доп. данные
			if verbose {
				le.Int("statusCode", nr.StatusCode).Str("contentType", nr.ContentType)
			}

			// декодируем
			var resp tspResp
			if _, decodeError := asn1.Unmarshal(nr.Body, &resp); decodeError != nil {
				mt.ResponseError(protoTSP, responseErrorAsn)
				le.Str("errorType", string(responseErrorAsn)).Err(fmt.Errorf("decode TSP response: [%w]", decodeError)).Msg("request failed")
				if cfg.RetryCount == 0 || i != cfg.RetryCount-1 {
					waitForTimeout(ctx, cfg.RetryIntervalValue)
				}
				continue
			}

			// проверяем содержимое
			if validateError := tspResponseValidate(&resp, req, verbose, le); validateError != nil {
				mt.ResponseError(protoTSP, responseErrorContents)
				le.Str("errorType", string(responseErrorContents)).Err(fmt.Errorf("validate TSP response: [%w]", validateError)).Msg("request failed")
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

// tspEncodeRequest позволяет закодировать TSP запрос в ASN.1.
//
// Если указан не нулевой размер digestSize, то при вызове генерируется случайный
// блок данных в качестве MessageImprint.HashedMessage.
//
// Если передан не нулевой размер nonceSize, то функция генерирует случайный
// nonce указанного размера.
//
// request модифицируется при вызове функции. Значение его полей можно использовать
// при проверке
func tspEncodeRequest(request *tspRequest, digestSize, nonceSize int) (encoded []byte, outError error) {
	if digestSize > 0 {
		// генерируем случайные данные в качестве хеша
		request.MessageImprint.HashedMessage, outError = random(digestSize)
		if outError != nil {
			return nil, fmt.Errorf("failed to generate TSP HashedMessage: [%d], [%w]", digestSize, outError)
		}
	}

	request.Nonce = nil
	if nonceSize > 0 {
		// генерируем случайный nonce
		nonce, randError := random(nonceSize)
		if randError != nil {
			return nil, fmt.Errorf("failed to generate TSP nonce: [%d], [%w]", nonceSize, randError)
		}
		request.Nonce = new(big.Int).SetBytes(nonce)
	}

	// кодируем MessageImprint
	request.MessageImprint.Raw, outError = asn1.Marshal(request.MessageImprint)
	if outError != nil {
		return nil, fmt.Errorf("failed to encode TSP MessageImprint: [%w]", outError)
	}

	// кодируем запрос в ASN.1
	encoded, outError = asn1.Marshal(*request)
	if outError != nil {
		return nil, fmt.Errorf("failed to encode TSP request: [%w]", outError)
	}
	return encoded, outError
}

// tspResponseValidate проверяет корректность декодированного TSP ответа и сравнивает
// его содержимое с отправленным запросом.
func tspResponseValidate(response *tspResp, request *tspRequest, verbose bool, le *zerolog.Event) error {
	// проверяем статус ответа
	if response.Status.Status != tspResponseStatusGranted && response.Status.Status != tspResponseStatusGrantedWithMods {
		return fmt.Errorf("invalid TSP response Status: %d", response.Status.Status)
	}

	// проверяем OID типа CMS
	if !response.TimeStampToken.ContentType.Equal(oidTSPCmsSignedData) {
		return fmt.Errorf("invalid TSP TimeStampToken OID: [%s]", response.TimeStampToken.ContentType.String())
	}

	// должна быть одна подпись
	if len(response.TimeStampToken.Content.SignerInfos) != 1 {
		return fmt.Errorf("single signature under TSP TimeStampToken expected: [%d]", len(response.TimeStampToken.Content.SignerInfos))
	}

	// выведем алгоритмы подписи/хеширования
	if verbose {
		le.Str("respDigestAlgorithm", response.TimeStampToken.Content.SignerInfos[0].DigestAlgorithm.Algorithm.String()).
			Str("respSignAlgorithm", response.TimeStampToken.Content.SignerInfos[0].SignatureAlgorithm.Algorithm.String())
	}

	// проверим OID содержимого CMS
	if !response.TimeStampToken.Content.EncapContentInfo.EContentType.Equal(oidTSPTimeStampTokenContent) {
		return fmt.Errorf("invalid TSP EncapContentInfo OID: [%s]", response.TimeStampToken.Content.EncapContentInfo.EContentType.String())
	}

	// декодируем метку времени
	encodedTstInfo := response.TimeStampToken.Content.EncapContentInfo.EContent
	if len(encodedTstInfo) < 1 {
		return fmt.Errorf("invalid TSP TSTInfo encoded size: [%d]", len(encodedTstInfo))
	}

	var ti tspTSTInfo
	if _, decodeError := asn1.Unmarshal(encodedTstInfo, &ti); decodeError != nil {
		return fmt.Errorf("failed to decode TSTInfo: [%w]", decodeError)
	}

	// проверяем содержимое. Сначала политику
	if !ti.Policy.Equal(request.ReqPolicy) {
		return fmt.Errorf("TSP policy OID mismatch: [%s], [%s]", ti.Policy.String(), request.ReqPolicy.String())
	}

	// затем MessageImprint
	if !bytes.Equal(ti.MessageImprint.Raw, request.MessageImprint.Raw) {
		return errors.New("TSP MessageImprint mismatch")
	}

	// и если есть nonce
	if request.Nonce != nil {
		if ti.Nonce == nil {
			return errors.New("TSP response nonce mismatch (nil)")
		}
		if ti.Nonce.Cmp(request.Nonce) != 0 {
			return errors.New("TSP nonce mismatch")
		}
	}

	return nil
}
