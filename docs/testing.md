# Тестирование

Набор проверок хранится в репозитории и запускается одинаковыми командами локально и в CI. Новый баг добавляется к существующему сценарию или отдельным тестом рядом с затронутым пакетом.

## Команды

| Команда | Окружение и результат |
| --- | --- |
| `make test-unit` | Go `-race`, `go vet`, Изолированные Vitest/RTL unit-компоненты, TS/Vite; без БД и Docker |
| `make test-regression` | React UI-regression → PostgreSQL integration → сборка/start demo → API/SSH/отказы |
| `make test-regression-ui` | Функциональные DOM-сценарии URL/приглашения/modal error и инкрементальных операций большой группы без потери участников |
| `make test-regression-db` | Только integration: отдельная БД `linpam_test`, build tag `integration`, Go `-race` |
| `make test-regression-api` | Только последовательные сценарии работающего demo |
| `make test-regression-freebsd` | Настоящая disposable FreeBSD VM; [установка и настройки](freebsd.md) |
| `make test-load` | Изолированная `linpam_load`: каталог 20k и synthetic mTLS/gRPC agents |
| `make test-all` | Unit + функциональная регрессия; нагрузка отдельно |
| `make demo` | Стенд с сохранением данных/секретов и seed оператора |
| `make dashboards` | Воспроизводимая генерация Grafana JSON из PromQL |

Unit вообще не компилирует integration/load fixtures, даже если DSN уже есть в окружении. PostgreSQL сценарии используют build tag `integration`; большой каталог — `loadtest`. Integration разрешает только `linpam_test`, нагрузка — только `linpam_load`; fixtures очищаются в изолированных БД. `.local/acceptance.lock` сериализует сквозные проверки demo. Старые `make test`, `test-integration`, `test-e2e` оставлены как алиасы.

Нагрузка никогда не запускается автоматически командой `test-all` или обычным push/PR в CI. `HEIMDALL_LOAD_AGENTS=5000 make test-load` меняет число соединений (по умолчанию 20 000); DB projection всегда проверяет 20 000 пользователей. Нужна свободная RAM Docker для CP и генератора; команда сама не останавливает сторонние контейнеры. Логи и JSON генератора сохраняйте отдельно: `make test-load > .local/load-report.log 2>&1`.

## Постоянные сценарии

| Слой | Проверяемое поведение |
| --- | --- |
| Identity/credentials/RBAC | Защищённые UID/login/home/shell, ключи и fingerprint, native sudoers, token scopes/groups, нормализация null collections |
| PKI/security | Сертификаты, подпись и digest манифеста, чужой signing key, trailing JSON, TOTP/recovery, password hashes |
| Root bootstrap/activity | Сохранение root enrollment intent, запрет подмены nonce/token hash и symlink; OpenSSH managed/unmanaged/failure parser |
| Gateway | ACK/resources/revision/generation, admission и bounded delivery |
| REST/MCP/inventory | Audience/origin/permission, отказ cookie inventory, конфигурационное выключение Swagger/MCP, формат/изоляция хостов |
| React | RBAC с legacy null sudo, приглашение при действующей сессии, отсутствие слоганов, URL страницы, видимая modal/API/render ошибка; удаление сообщений обзора с подтверждением/отменой и обновлением обоих списков |
| PostgreSQL | Транзакционный отзыв, каталоги, иерархия/cycle, сервисная УЗ, group roles/unbind, MFA intersection, optimistic settings, токен после блокировки; удаление сообщения: RBAC, текущая версия, аудит, отсутствие native-задач |
| Каталог 20k | Полная projection 20 000 УЗ укладывается в payload limit, cursor без дубликатов/пропусков, literal substring search |
| `check-demo.py` | Приглашение, реальные УЗ/SSH/sudo, CP outage, agent outage, offline revoke/alerts, текущие API/MCP scopes, вечный ban ключа, token revoke |
| `check-recovery.py` | MFA/replay/recovery one-use, потерянный ACK, восстановление сертификата, disabled POSIX migration, symlink drift/incident/repair |
| `check-features.py` | Non-null roles, runtime settings, сервисный inventory/наследование scopes, блокировка владельца, single CP failure, Rabbit outage fallback, посторонний SSH-вход/закрытие инцидента с аудитом, Grafana/live metrics |
| `check-enrollment.py` | Новая одноразовая Linux-нода, signed apply, root binding и native checkpoint; cleanup удаляет тестовый контейнер и только его проверенную ephemeral fixture из БД, сохраняя аудит |

Сквозные тесты создают уникальные УЗ и используют публичные API. Проверки восстановления дополнительно инъецируют строго ограниченный сбой в demo БД/управляемом файле. Они временно останавливают **сервисы Heimdall**; пользовательские сторонние кластеры не затрагиваются. УЗ удаляются логически с сохранением tombstone, поэтому история тестов остаётся в аудите. Feature-test сохраняет и восстанавливает settings/group, не сокращая TTL существующих demo-ключей.

## Отчёты и CI

`.local/web-unit.xml` и `.local/web-regression.xml` — отдельные JUnit отчёты. Сквозные проверки записывают `.local/verification.json`, `recovery-verification.json`, `feature-verification.json`, `enrollment-verification.json` с результатами и временем. Для полного локального лога удобно использовать `make test-all > .local/test-all.log 2>&1`.

`.github/workflows/tests.yml` имеет отдельные jobs `unit`, `regression`, `load`; последний запускается только вручную через workflow_dispatch. Workflow добавлен, но фактический запуск GitHub Actions подтверждается только после публикации репозитория и запуска на GitHub.

Предыдущие измерения `.local/load-report-20000.json` подтверждают 20 000 synthetic mTLS gRPC agents на одном CP, нулевые failed attempts и подтверждение wide update. `.local/load-report-5000.json` — меньший прогон. Они измеряют соединения и протокол ACK, не native Linux provisioning. Для повторения нужен отдельный `linpam_load` и достаточная RAM Docker; `compose.load.yaml` не запускается обычным demo.

## Что остаётся отдельной проверкой

Аппаратный WebAuthn/SK требует устройства; реальные Telegram, Mattermost, OIDC и LDAP требуют credentials/test provider. Linux native тесты выполняются на Debian Bookworm/OpenSSH/sudo. FreeBSD проверяется отдельной VM; другие версии/дистрибутивы требуют матрицы. HA capacity 20k, production broker quorum, restore PostgreSQL/PITR, CA/signing rotation и длительный soak требуют выделенного окружения. Unit/UI tests используют DOM simulation; визуальная проверка реального браузера дополняет их, но не выдаётся за автоматическую browser E2E suite.

Новый load-стенд использует две реплики CP за отдельным HAProxy и отдельный RabbitMQ. Grafana `Heimdall · нагрузка` отделяет этот job от основного приложения; основные alerts относятся только к основному Heimdall, поэтому выключенный load-стенд не создаёт ложный CP outage. Synthetic clients проверяют подпись/digest, отвечают ACK и отправляют heartbeat; они не создают native УЗ.

## Зафиксированный прогон Heimdall

Прогон от 05.10.2026: 20 000 одновременно подключённых mTLS/gRPC клиентов за HAProxy, две реплики CP (по 10 000 соединений на каждой), отдельный RabbitMQ; все 20 000 подтвердили ревизию и отправляли heartbeat, failed attempts = 0. Разнесённое подключение заняло 250,04 секунды, широкое изменение — 6,22 секунды, удержание после изменения — 45 секунд. Клиенты проверяли Ed25519 signature/digest. Отчёты: `.local/load-report-current-20000.json`, `.local/load-distribution-20000.json`; лог отдельно от unit/regression.

Каталог 20k: manifest 8 066 981 байт, projection 0,934 секунды, тест с пагинацией/поиском 1,751 секунды. Это отдельный DB load-сценарий, не 20k native процессов provisioning. При наблюдении CP использовали около 0,9 ГБ каждый, генератор 1,87 ГБ, HAProxy 246 МБ. Лимит proxy увеличен с 256 до 512 МБ по результату этого измерения. Soak 45 секунд не подтверждает длительную устойчивость; отказ одной CP при полной нагрузке и распределённый production quorum проверяются отдельно.

## Проверки нового UX

`httpapi/factors_test.go` проверяет независимое начало регистрации TOTP после Passkey, запрет скрытой замены существующего TOTP и запрет регистрации через API-токен; Redis перехватывается in-process hook без сети. `application/factor_policy_test.go` фиксирует пересечение требований. Integration-сценарии `postgres/factor_enrollment_test.go` и `postgres/factor_policy_test.go` проверяют сохранение Passkey при добавлении TOTP, личные требования поверх обязательного минимума, откат запрещённой отвязки и административное восстановление. `Account.regression.test.tsx` и `FactorManager.regression.test.tsx` проверяют доступность регистрации при ограниченной сессии, понятный минимум политики и защиту последнего обязательного Passkey. Эти новые тесты добавлены без запуска, в соответствующие unit и regression наборы; нагрузка остаётся отдельной.

Добавлены постоянные сценарии `SudoEditor.test.ts`, `SudoEditor.regression.test.tsx`, `PeopleGroups.regression.test.tsx`, `postgres/collections_test.go`: native рендер аргументов, сохранение сложного текста между вкладками, удаление строки после пустых строк; изменение одной видимой membership без перезаписи 20k UUID; поиск/стабильные страницы, unlimited join с независимым TTL/use ceiling, запрет повышения роли через группу, last-admin safeguard и атомарное закрытие инцидентов.

`native/recovery_test.go` фиксирует материализацию delta: изменение или блокировка одной УЗ сохраняет UNIX-группы другой УЗ в автономном журнале; full заменяет набор определений, а delta не может переопределить идентичность группы. Эти сценарии также добавлены без запуска.

`check-enrollment.py` дополнен реальными UNIX group/sudoers и mandatory label grant/revoke. `check-freebsd.py` включает дополнительные UNIX memberships через `pw`. Сценарии удаляют собственные временные группы/роли после удаления fixture-ноды и логической блокировки fixture-пользователя, сохраняют аудит. Первая native enrollment-проверка больше не зависит от наличия постороннего demo-оператора на одноразовой ноде.

По просьбе пользователя полный прогон после этих изменений **отложен** до фиксации UX. Команды компиляции/сборки и ручной просмотр Compose UI не считаются выполненными unit/regression/load suites. Старые PASS/load-отчёты не относятся автоматически к новой модели. Следующий запуск: отдельно unit, затем integration/regression, отдельно load.


Дополнены сценарии каталога собственного доступа (UNIX-назначения, наследование, MAC, поиск и keyset-пагинация), отсутствие операторских запросов у обычного пользователя и отмена опасного изменения до HTTP-запроса. В API-тестах проверяется неизменность подтверждённого тела запроса. Эти сценарии подготовлены; по текущему указанию пользователя наборы unit, integration/regression и load не запускаются до фиксации всего UX. Компиляция и ручная проверка стенда не заменяют результаты этих наборов.


Новые регрессионные сценарии: независимые методы native-входа и `sync_to_nodes`, безопасная ротация обязательного TOTP, Markdown version conflict/seed preservation, фильтры до пагинации, токены TTL/uses/auto-expiry, единый node health, конфигурация одного агента YAML/ENV/CLI. `check-demo.py` проверяет key-only роль и отклонение UNIX-пароля; FreeBSD harness использует один бинарник/rc.d и отдельную explicit password+key роль. В текущей UX-итерации suites **не запускаются** по указанию пользователя; сборка и ручная проверка стенда фиксируются отдельно от автоматических тестов.

Новые сценарии этой итерации (suites пока не запущены):

| Уровень | Сценарий |
| --- | --- |
| Unit Go native | UID/saved UID/audit UID; SSH monitor и sudo descendants; listener/root/PID1/чужие пользователи исключены; orphan journal/PID reuse |
| Unit Go application | Анализ пересечений с наследованием; native permissions не выдают Heimdall права; анализ не меняет определения ролей |
| Unit Go HTTP | Полнота зарегистрированных REST маршрутов в OpenAPI, ссылки моделей, уникальные operationId, browser/public/bearer security, cursor headers |
| Unit React | Scope-specific граф без ложных путей; общая связь хранит все assignment IDs для выделения |
| Unit Swagger JS | Выполняется реальный bootstrap script Go-шаблона: GET схемы без method, отмена записи, CSRF для подтверждённой записи; bearer secret не сохраняется UI |
| Unit Markdown | Таблицы и task lists; запрет HTML, unsafe URL и внешних изображений сохранён |
| Regression React | Граф отдельной вкладкой по правам; серверная пагинация; выбор UNIX-связи без невыданных прав Heimdall |
| Integration PostgreSQL | users.manage не обходит roles.manage/sudo.manage через supplementary, замену участников или primary GID; граф требует все read permissions |
| Regression Compose | Реальная открытая SSH-сессия + nohup + дочерний sudo sleep прекращаются при full revoke до ACK; повторный SSH отклонён |
| Load | Отдельный tier; нагрузка графа и массового native process teardown не измерена, 20k старых streams не является проверкой новой версии |
