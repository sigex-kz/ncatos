package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
)

var (
	// AppVersion содержит версию приложения.
	// Устанавливается с помощью -ldflags "-X main.AppVersion=1.0.0"
	AppVersion string
	// BuildTimeStamp содаржит метку времени сборки
	// Устанавливается с помощью -ldflags "-X 'main.BuildTimeStamp=$(date)'"
	BuildTimeStamp string
)

var (
	// ConfigHash содержит хеш конфигурационного файла.
	ConfigHash string
)

var (
	// Eдинственный экземпляр контекста приложения
	// Cоздается и изменяется только при запуске приложения в main(!).
	// В остальных местах обращение к контексту следует выполнять вызовом getAppContext().
	appCtxSingleInstance *appContext

	// сколько ждать завершения мониторов. Ждать нужно для корректного вывода статистики в консоль
	shutdownDelay = time.Second
)

// Получить текущий (единственный) контекст приложения.
// В случае, если контекст не был создан - panic-ует.
func getAppContext() *appContext {
	if appCtxSingleInstance == nil {
		panic(errors.New("access to not inited appContext"))
	}
	return appCtxSingleInstance
}

// Структура контекста приложения. Структура должна содержать поля доступные
// во всем приложении.
type appContext struct {
	// Конфигурация. В объекте конфигурации все поля не nil.
	Config *appConfig
	// Логгер. После инициализации контекста здесь не может быть nil.
	Logger *zerolog.Logger
	// Метрики.
	Metrics *metrics
}

func main() {
	// код завершения
	exitCode := 0
	defer os.Exit(exitCode)

	// разбираем параметры командной строки
	flag.CommandLine.Usage = clpUsageFunc
	flag.CommandLine.SetOutput(os.Stderr)
	flag.Parse()
	if clpShowHelp != nil && *clpShowHelp {
		flag.CommandLine.Usage()
		return
	}

	// создаем контекст приложения
	appCtxSingleInstance = &appContext{}

	// загружаем объект конфигурации
	var err error
	appCtxSingleInstance.Config, err = buildConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		exitCode = 1
		return
	}

	// установим глобальные настройки и создадим объект logger-а (отсюда пишем только через него)
	zerolog.TimestampFieldName = "time"
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	zerolog.DurationFieldUnit = time.Millisecond
	zerolog.DurationFieldInteger = true
	var loggerCloseFunc func()
	appCtxSingleInstance.Logger, loggerCloseFunc, err = newAppLogger(&getAppContext().Config.Log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		exitCode = 2
	}

	getAppContext().Logger.Log().Msg("start")
	startupTime := time.Now()
	defer func() {
		getAppContext().Logger.Log().
			Dur("upTime", time.Since(startupTime)).
			Int("exitCode", exitCode).
			Msg("stop")
		loggerCloseFunc()
	}()

	// создаем и регистрируем метрики. Передать nil для стандартного реестра (+метрики golang)
	if getAppContext().Config.Metrics.Enabled {
		appCtxSingleInstance.Metrics = newMetrics(prometheus.NewRegistry())
	}

	// создаем контекст, при отмене которого завершатся goroutine-ы мониторов
	exitCtx, exitCtxCancel := context.WithCancel(context.Background())
	defer exitCtxCancel()

	// запускаем горутины мониторов и сервер
	var ocspChannel, tspChannel, httpChannel, srvMetricsChannel <-chan error

	if !getAppContext().Config.OCSP.Disabled {
		ocspChannel = ocspMonitorStart(exitCtx)
	} else {
		getAppContext().Logger.Log().Msg("OCSP disabled")
	}

	if !getAppContext().Config.TSP.Disabled {
		tspChannel = tspMonitorStart(exitCtx)
	} else {
		getAppContext().Logger.Log().Msg("TSP disabled")
	}

	if !getAppContext().Config.HTTP.Disabled {
		httpChannel = httpMonitorStart(exitCtx)
	} else {
		getAppContext().Logger.Log().Msg("HTTP disabled")
	}

	// хотя бы один канал должен быть запущен
	if ocspChannel == nil && tspChannel == nil && httpChannel == nil {
		getAppContext().Logger.Log().Msg("nothing to do (all monitors disabled)")
		exitCode = 5
		return
	}

	// запускаем сервер для предоставления статистики
	if getAppContext().Config.Metrics.Enabled {
		var srvMetricStopFunc func(time.Duration)
		srvMetricStopFunc, srvMetricsChannel = startMetricsServer()
		defer srvMetricStopFunc(shutdownDelay)
	}

	// останов утилиты может быть выполнен по Ctrl+c - для этого обработаем системный сигнал
	osChannel := make(chan os.Signal, 1)
	signal.Notify(osChannel, os.Interrupt, syscall.SIGTERM)

	// ожидаем любой ошибки или останова утилиты
	var stopError error

	for {
		select {
		case stopError = <-ocspChannel:
			ocspChannel = nil
			if stopError != nil {
				stopError = fmt.Errorf("OCSP failed: [%w]", stopError)
				exitCode = 7
			}

		case stopError = <-tspChannel:
			tspChannel = nil
			if stopError != nil {
				stopError = fmt.Errorf("TSP failed: [%w]", stopError)
				exitCode = 8
			}

		case stopError = <-httpChannel:
			httpChannel = nil
			if stopError != nil {
				stopError = fmt.Errorf("HTTP failed: [%w]", stopError)
				exitCode = 8
			}

		case stopError = <-srvMetricsChannel:
			stopError = fmt.Errorf("metrics server failed: [%w]", stopError)
			exitCode = 9

		case <-osChannel:
			exitCtxCancel()
			exitCode = 0
		}
		if exitCtx.Err() != nil || stopError != nil || (ocspChannel == nil && tspChannel == nil && httpChannel == nil) {
			break
		}
	}
	if stopError != nil {
		// ошибку остановки пишем сначала в лог
		getAppContext().Logger.Log().Err(stopError).Msg("unexpected failure")
		// затем в stderr
		fmt.Fprintln(os.Stderr, stopError.Error())
	}
}
