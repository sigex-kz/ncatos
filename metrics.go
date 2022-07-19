package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

/*
  Функции и определения, относящиеся к мониторингу через prometheus
*/

// startMetricsServer создает, иницилизирует и запускает HTTP сервер
// предоставления статистики. Для корректной остановки сервера следует
// вызывать возвращаемую функцию останова, с указанием таймаута останова.
//
// Также возвращается канал по которому можно отследить ошибки ListenAndServe()
// созданного сервера (т.е. фактически сервер прекратил обслуживать клиентские
// запросы).
func startMetricsServer() (stopFunc func(time.Duration), failureChannel <-chan error) {
	// создаем логгер для OCSP
	ml := getAppContext().Logger.With().
		Str("module", "server").Str("protocol", "http").
		Str("address", getAppContext().Config.Metrics.Address).
		Str("path", "/metrics").Logger()

	// создаем новый mux, которй будет обслуживать только один маршрут
	// с зарезервированным путем
	mux := http.NewServeMux()
	mux.Handle("/metrics", getAppContext().Metrics.Handler())

	// создаем экземпляр сервера
	srv := &http.Server{
		Addr:         getAppContext().Config.Metrics.Address,
		Handler:      mux,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	stopFunc = func(shutdownTimeout time.Duration) {
		shutdownCtx, shutdownCxtCancel := context.WithTimeout(context.Background(), shutdownTimeout)

		stch := make(chan struct{})
		go func() {
			_ = srv.Shutdown(shutdownCtx) //nolint:errcheck // ошибка останова сервера метрик неинтересна
			close(stch)
		}()
		<-stch
		shutdownCxtCancel()
	}

	// и запускаем его в отдельной goroutine-е
	resultChannel := make(chan error, 1)
	sch := make(chan struct{})
	go func() {
		close(sch)
		srvError := srv.ListenAndServe()
		if srvError != nil {
			select {
			case resultChannel <- srvError:
			default:
			}
		}
		ml.Log().Msg("stop")
		close(resultChannel)
	}()
	<-sch

	ml.Log().Msg("start")
	return stopFunc, resultChannel
}

// metrics содержит реестр и регистрируемые в нем метрки prometheus
type metrics struct {
	// Реестр, используемый для хранения метрик
	registry *prometheus.Registry

	// Вектор гистограмм времени обработки запросов (здесь от отправки запроса до получения ответа),
	// разделенный по протоколу.
	requestProcessingTimes *prometheus.HistogramVec

	// Вектор счетчиков ошибок, разделенный по протоколу и типу
	responseErrors *prometheus.CounterVec

	// Вектор для индикации информации о сборке
	buildInfo *prometheus.GaugeVec

	// Вектор для индикации информации о конфигурации
	configInfo *prometheus.GaugeVec
}

// newMetrics создает новый объект с метриками и регистрирует их в переданном реестре.
// Если реестр не передан, то используется реестр prometheus по умолчанию (prometheus.DefaultRegistrer)
func newMetrics(registry *prometheus.Registry) *metrics {
	// создаем объект метрик
	out := &metrics{
		registry: registry,
	}

	// регистрируем. Для этого сначала определяем место регистрации
	var registerer prometheus.Registerer = out.registry
	if out.registry == nil {
		registerer = prometheus.DefaultRegisterer
	}
	factory := promauto.With(registerer)

	// регистрируем
	out.requestProcessingTimes = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "ncatos",
			Name:      "requests_processing_time",
			Help:      "Amount of time spent processing HTTP requests (seconds), partitioned by protocol (ocsp|tsp).",
			// Здесь можно определить другой набор Bucket-ов: Buckets []float64
			// По умолчанию используется prometheus.DefBuckets = []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}
		},
		[]string{"protocol"},
	)

	out.responseErrors = factory.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "ncatos",
			Name:      "responses_errors",
			Help:      "How many requests failed, partitioned by protocol (ocsp|tsp) and type (net|http|asn1|contents).",
		},
		[]string{"protocol", "errorType"},
	)

	out.buildInfo = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ncatos",
			Name:      "build_info",
			Help:      "Indicate build info of the current running app.",
		},
		[]string{"version", "timestamp"},
	)

	out.configInfo = factory.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "ncatos",
			Name:      "config_info",
			Help:      "Indicate loaded config info.",
		},
		[]string{"hash"},
	)

	// обратимся к зарегистрированным элемента векторов - таким образом зададим их нулевое значение
	out.requestProcessingTimes.WithLabelValues(string(protoOCSP))
	out.responseErrors.WithLabelValues(string(protoOCSP), string(responseErrorNet))
	out.responseErrors.WithLabelValues(string(protoOCSP), string(responseErrorHTTP))
	out.responseErrors.WithLabelValues(string(protoOCSP), string(responseErrorAsn))
	out.responseErrors.WithLabelValues(string(protoOCSP), string(responseErrorContents))

	out.requestProcessingTimes.WithLabelValues(string(protoTSP))
	out.responseErrors.WithLabelValues(string(protoTSP), string(responseErrorNet))
	out.responseErrors.WithLabelValues(string(protoTSP), string(responseErrorHTTP))
	out.responseErrors.WithLabelValues(string(protoTSP), string(responseErrorAsn))
	out.responseErrors.WithLabelValues(string(protoTSP), string(responseErrorContents))

	out.buildInfo.WithLabelValues(AppVersion, BuildTimeStamp).Add(1)

	out.configInfo.WithLabelValues(ConfigHash).Add(1)

	return out
}

// RequestProcessingTimeStart начинает отсчет времени обработки запроса по указанному
// протоколу.
// Для останова необходимо вызвать возвращаемую функцию.
func (ms *metrics) RequestProcessingTimeStart(p protocolType) func() {
	if ms == nil || ms.requestProcessingTimes == nil {
		return func() {}
	}
	processingTimeStart := time.Now()
	return func() {
		ms.requestProcessingTimes.WithLabelValues(string(p)).Observe(time.Since(processingTimeStart).Seconds())
	}
}

// RequestProcessingTimeObserve позволяет непосредственно обновить метрику для выбранного протокола.
func (ms *metrics) RequestProcessingTimeObserve(p protocolType, d time.Duration) {
	if ms == nil || ms.requestProcessingTimes == nil {
		return
	}
	ms.requestProcessingTimes.WithLabelValues(string(p)).Observe(d.Seconds())
}

// ResponseError позволяет увеличить счетчик ошибок для указанного протокола и типа ошибки.
func (ms *metrics) ResponseError(p protocolType, et responseErrorType) {
	if ms == nil || ms.responseErrors == nil {
		return
	}
	ms.responseErrors.WithLabelValues(string(p), string(et)).Inc()
}

// Handler возвращает HTTP обработчик для предоставления зарегистрированных метрик
func (ms *metrics) Handler() http.Handler {
	if ms == nil {
		panic(errors.New("metrics object not created"))
	}

	registerer := prometheus.DefaultRegisterer
	gatherer := prometheus.DefaultGatherer
	if ms.registry != nil {
		registerer = ms.registry
		gatherer = ms.registry
	}

	// InstrumentMetricHandler добавляет две метрики:
	//   - "promhttp_metric_handler_requests_total" - вектор счетчиков запросов на считывание метрик (разделены по HTTP статус коду)
	//   - "promhttp_metric_handler_requests_in_flight" - gauge c количествоv одновременных считываний метрик
	return promhttp.InstrumentMetricHandler(registerer, promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{}))
}
