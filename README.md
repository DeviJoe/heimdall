# Heimdall

Go control plane, React/Material UI, агент Linux/FreeBSD, PostgreSQL, Redis и RabbitMQ.

## Локальный стенд

```sh
make demo
```

Скрипт создаёт локальные секреты в `.env` с правами `0600`, собирает образы и запускает две реплики control plane, HAProxy, четыре Linux-ноды с настоящим sshd, Prometheus, Alertmanager и Grafana. Повторный запуск сохраняет данные и секреты.

| Сервис | Адрес | Вход |
| --- | --- | --- |
| Heimdall | http://localhost:5180 | `admin`, пароль `HEIMDALL_ADMIN_PASSWORD` из `.env` |
| API | https://localhost:8443/api/v1 | Bearer-токен; доверенная CA стенда |
| Swagger | http://localhost:5180/swagger | Сессия с `api_docs.read` |
| MCP | http://localhost:5180/mcp | Bearer-токен с audience `mcp` |
| Linux SSH | localhost:22220 | `operator`, ключ из `.local/operator-credentials.json` |
| Дополнительные ноды | localhost:22222 / 22223 / 22224 | `linux-stage` / `linux-web` / `linux-db` |
| Grafana | http://localhost:3001/d/heimdall-operations | `admin`, `HEIMDALL_GRAFANA_PASSWORD` из `.env` |
| Prometheus | http://localhost:9091 | Локальный стенд |
| Alertmanager | http://localhost:9093 | Локальный стенд |

Web-пароль `operator` и актуальный путь к его SSH-ключу записаны в `.local/operator-credentials.json`. Действующие политики факторов/RBAC применяются и к демо-пользователям; повторное заполнение стенда не сбрасывает их. Для настройки примеров используется временная локальная development-УЗ, которая удаляется после заполнения; реальные факторы администратора сохраняются. Не публикуйте `.env`, `.local` и Docker volumes. Telegram, Mattermost, LDAP и OIDC требуют настройки реальных провайдеров в `config/controlplane.yaml`.

```sh
docker compose up -d --scale controlplane=3
docker compose logs --tail=100 controlplane linux-node
```

## Проверки

```sh
make test-unit        # Без стенда: Go race/vet, React, сборка frontend
make test-regression  # PostgreSQL, API, SSH/sudo, отказы, MFA, inventory, HA
make test-load        # Отдельная БД: каталог 20k и 20k mTLS/gRPC соединений
make test-all         # Unit + регрессия; без нагрузки
make test-regression-freebsd  # Отдельная disposable FreeBSD VM
```

Сквозные тесты изменяют демонстрационный стенд и временно останавливают его сервисы. Подробности и ограничения: [тестирование](docs/testing.md). [Архитектура и ревью](docs/architecture.md). [Ansible inventory](docs/ansible.md).

Агент FreeBSD: [установка и проверка](docs/freebsd.md). При обновлении с LinPam сохраняются БД, Compose volumes, идентификаторы нод, wire namespace gRPC и уже применённые УЗ/ключи/sudo. `make demo` переносит старые имена переменных `.env` в `HEIMDALL_*` без смены секретов.
