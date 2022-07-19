# ncatos

Опрос и сбор статистики OCSP/TSP серверов, разработан для мониторинга сервисов НУЦ РК.

Запуск с преднастроенной конфигурацией `./ncatos -config=config.yaml`.

Эталонный конфигурационный файл (OCSP проверяет сертификат сервиса OCSP НУЦ): `/config/config.yml`.

Пример файла описания сервиса **systemd** приведен в фале `/systemd/ncatos.service`.

## Установка и запуск сервиса:
```
mkdir /opt/ncatos
cd /opt/ncatos
wget ...
unzip ...
ln -s /opt/ncatos/ncatos.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable ncatos
service ncatos start
```

## Сборка из исходных кодов
Требует установленного `go1.18`, собираем командой: `go build -mod=vendor .`.
