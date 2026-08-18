# Signature Verifier

Отдельный stateless-сервис для Linux/amd64 в Docker. Он принимает точные байты документа и detached CAdES-BES подпись. Нативный helper использует `CadesVerifyDetachedMessage` из `libcades.so` для проверки всех подписантов, связи с документом, цепочки и статуса отзыва на текущее время.

Сервис дополнительно проверяет текущий период действия сертификата и `KeyUsage`, извлекает сертификат подписанта без парсинга локализованного stdout. Документ, подпись, raw DER и данные подписанта не пишутся в логи.

## API

```bash
curl -sS http://localhost:8080/v1/signatures/verify \
  -F document=@ek-demo-document.txt \
  -F signature=@ek-demo-document.txt.sig
```

Сокращённый успешный ответ:

```json
{
  "decision": "indeterminate",
  "valid": true,
  "code": "VALID",
  "checks": {
    "contentBinding": "passed",
    "signatureValue": "passed",
    "certificatePeriod": "passed",
    "certificateChain": "passed",
    "revocation": "passed"
  },
  "signers": [{
    "index": 0,
    "valid": true,
    "certificate": {
      "commonName": "Иванов Иван Иванович",
      "organizationName": "ООО Пример",
      "inn": "7700000000",
      "ogrn": "1027700000000",
      "validFrom": "2026-01-01T00:00:00Z",
      "validTo": "2027-01-01T00:00:00Z"
    }
  }],
  "authorization": {
    "status": "not_checked",
    "code": "EXTERNAL_AUTHORIZATION_REQUIRED"
  }
}
```

`valid` означает технически корректную подпись всех подписантов. `decision` остаётся `indeterminate`: сертификат подтверждает ключ и идентификаторы владельца, но не полномочие подписывать конкретный документ. Для решения `accepted` потребуется внешний источник полномочий и контекст ожидаемой организации/роли.

Невалидная подпись возвращается с HTTP 200 и `decision: rejected`. Некорректный multipart получает 400, недоступный helper — 503, timeout — 504. Лимиты: документ 25 MiB, подпись 5 MiB, максимум 32 подписанта.

При ошибке helper verifier пишет отдельную JSON-запись `signature verification helper diagnostic` с теми же `request_id` и `parent_request_id`. Поле `helper_stage` показывает последний безопасный этап без содержимого документа, подписи и сертификата. `stage=verify_started` при последующем timeout означает зависание внутри `CadesVerifyDetachedMessage`; проверьте цепочку доверия и доступ контейнера к CRL/OCSP/AIA сертификата.

Поле `helper_pid` в итоговой JSON-записи позволяет сопоставить запрос со строками системной трассировки CryptoPro вида `cades-verify[PID]`. Для staging трассировка `cades`/`ocsp` включается build argument `ENABLE_CRYPTOPRO_TRACE=true`; CryptoPro отправляет её в syslog через `/dev/log`. Настройка внешнего файла и ротации описана в infrastructure README. Трассировка может содержать сведения о сертификатах и сетевых адресах, поэтому в production оставляйте флаг выключенным.

## Разработка

```bash
go test ./...
go vet ./...
go run .
```

Без нативного helper локальный API запускается, но `/health/ready` возвращает 503. Тесты не требуют CryptoPro.

## Docker и CryptoPro

Базовый образ должен быть Debian-совместимым Linux/amd64 и содержать лицензированный CryptoPro CSP. Dockerfile проверяет пакет `cprocsp-pki-cades-64`, компилирует `native/cades_verify.c` против `cades.h`/`libcades.so` и не добавляет дистрибутивы или лицензии в репозиторий.

Требования и цены описаны в [LICENSING.md](LICENSING.md), другие сертифицированные средства и риски самописной проверки — в [CRYPTO_ALTERNATIVES.md](CRYPTO_ALTERNATIVES.md).

Сборка базового образа из официального `linux-amd64_deb.tgz` выполняется из корня этого репозитория:

```bash
mkdir -p /tmp/cryptopro-build
tar -xzf ~/Downloads/linux-amd64_deb.tgz -C /tmp/cryptopro-build
docker build --platform linux/amd64 \
  -f Dockerfile.cryptopro \
  -t cryptopro-csp:5.0 \
  /tmp/cryptopro-build
```

Затем:

```bash
docker build --platform linux/amd64 \
  -t signature-verifier:dev .

docker run --rm --platform linux/amd64 \
  -p 8080:8080 signature-verifier:dev
```

> **Только для разработки:** по умолчанию образ доверяет корню `CRYPTO-PRO Test Center 2` от 28.04.2026. Никогда не продвигайте `signature-verifier:dev` в production. Боевой образ обязательно пересобирайте без тестового УЦ:

```bash
docker build --platform linux/amd64 \
  --build-arg INCLUDE_TEST_CA=false \
  -t signature-verifier:prod .
```

Проверить образ можно по label `verifier.cryptopro-test-ca-included`. В production устанавливайте только утверждённые организацией доверенные УЦ отдельным управляемым процессом.

В trust store контейнера должны быть актуальные корневые и промежуточные сертификаты; контейнеру нужен сетевой доступ к CRL/OCSP. Проверки состояния: `GET /health/live` и `GET /health/ready`.

API возвращает персональные данные сертификата и должен публиковаться только во внутреннем контуре с аутентификацией и авторизацией на уровне gateway.
