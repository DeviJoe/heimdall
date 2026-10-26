# Агент FreeBSD

Control plane и протокол общие с Linux. Native executor использует `pw`, `/etc/master.passwd`, `/usr/local/etc/sudoers.d` и `/usr/local/sbin/visudo`. Устанавливается один бинарник `heimdall-agent`, запускаемый root. Он запускает сетевой дочерний процесс под UID/GID 998; root-супервизор применяет только подписанные манифесты и проверяет peer credentials через `LOCAL_PEERCRED`. SSH и sudo работают при остановке обоих процессов и control plane. Отзыв подтверждается только после удаления ключей/sudo, замены password hash на `*`, nologin и истечения УЗ.

## Установка

Соберите бинарник нужной архитектуры:

```sh
ARCH=amd64 make agent-freebsd
# Для ARM64: ARCH=arm64 make agent-freebsd
```

На FreeBSD установите `sudo` и, если назначается `/bin/bash`, `bash`: `pkg install sudo bash`. Значение `/bin/bash` манифеста отображается в `/usr/local/bin/bash`. `/bin/sh` и `/usr/sbin/nologin` сохраняются. Home допускается непосредственно под `/home` или `/usr/home`; принимается только штатная root-owned ссылка `/home -> /usr/home`, произвольные ссылки запрещены.

Скопируйте `.local/freebsd/heimdall-agent` и файлы `deployments/freebsd/` в одну временную root-owned директорию ноды. Выполните `sh install.sh` из этой директории. Установка откажет при коллизии сервисного UID/GID; чужая УЗ не присваивается агенту.

Передайте доверенные `ca.pem` и raw Ed25519 `state.pub` через отдельный административный канал в `/usr/local/etc/heimdall/` (root:wheel, 0644). Получите Join-токен с требуемым сроком и лимитом в UI для нужной группы. Заполните `/usr/local/etc/heimdall/agent.yaml` (root:wheel, 0600): адрес API, gRPC, ожидаемое имя TLS-сервера, имя ноды и `join_token`. Приоритет: YAML → ENV → CLI. Имена полей приведены в agent.yaml.example; секрет можно передать через HEIMDALL_JOIN_TOKEN.

Агент подключает root-owned Match User политику после глобальных параметров и до внешних Match-блоков. Глобальный PasswordAuthentication рекомендуется выключить; разрешение пароля управляемым пользователям устанавливается явно ролью. Не изменяйте аварийный доступ вручную без `sshd -t` и `sshd -T -C user=...,host=localhost,addr=127.0.0.1`. Нужен абсолютный корректный PidFile. Не используйте сетевой AuthorizedKeysCommand или PAM callback к CP.

```sh
sysrc heimdall_helper_enable=NO heimdall_agent_enable=YES
# При обновлении старой установки сначала остановите прежний helper:
service heimdall_helper onestop 2>/dev/null || true
service heimdall_agent start
```

Root-супервизор фиксирует enrollment intent до первого join. После `in_sync` Join token можно убрать из конфигурации; сертификат и identity находятся в `/var/db/heimdall-agent`, root checkpoint/desired/journal — `/var/db/heimdall-helper`. Не удаляйте эти директории при обновлении. Единая служба и лог — `/var/log/heimdall-agent.log`; telemetry читает `/var/log/auth.log` и сохраняет неподтверждённые события до ACK.

## Проверка

`make test-regression-freebsd` выполняется на **одноразовой VM**, доступной по SSH root с ключом. Скрипт откажет без `/var/run/heimdall-test-vm`; этот маркер создаётся оператором тестового окружения, агент его не создаёт. По умолчанию используется localhost:22221 и `.local/freebsd/vm-key`. Настройки: `HEIMDALL_FREEBSD_HOST`, `HEIMDALL_FREEBSD_PORT`, `HEIMDALL_FREEBSD_KEY`, `HEIMDALL_FREEBSD_API`, `HEIMDALL_FREEBSD_GRPC`. Последние адреса должны быть доступны из гостевой системы; для QEMU user networking это `https://10.0.2.2:8443` и `10.0.2.2:9443`.

Проверяются enrollment/signature/root binding, реальные УЗ и password hash, public-key SSH/sudo, остановка агента, offline revoke, блокировка, миграция disabled UID/GID/login/home и повторная активация. Отчёт — `.local/freebsd-verification.json`. Скрипт изменяет sshd конфигурацию только этой VM и создаёт уникальные fixtures; после теста блокирует тестовую ноду и удаляет тестовую УЗ логически.

Docker Compose использует Linux-ядро и не подтверждает работу FreeBSD. Кросс-компиляция проверяет сборку; функциональная регрессия требует FreeBSD VM/хоста. Официальные справочники: [pw(8)](https://man.freebsd.org/cgi/man.cgi?query=pw&sektion=8), [daemon(8)](https://man.freebsd.org/cgi/man.cgi?query=daemon&sektion=8).

Именованные UNIX-группы и memberships задаются в отдельном UNIX-каталоге UI; явное назначение группы на дерево нод работает одинаково для Linux и FreeBSD. Агент использует `pw groupadd/groupmod`, проверяет managed GID/name и снимает supplementary memberships при отзыве. Оригинальный sudoers синтаксис проходит через установленный `visudo`; UI предлагает конструктор и текстовую вкладку. Последние изменения групп/пагинации ещё не проходили новый native regression: полный прогон отложен по запросу пользователя.
