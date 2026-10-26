# API, MCP и Ansible

В разделе **API и MCP** создайте токен: имя, срок, audience, scopes и группы нод. Токен не может расширить разрешения владельца. Используйте сервисную учётку для автоматизации; у неё нет браузерного входа. Включение синхронизации UNIX-учётки требуется только если ей нужен нативный доступ на серверы.

## Динамический Ansible inventory

У владельца должны быть UNIX-назначения на целевые ноды, включённая синхронизация и право `inventory.read`. В токене разрешите audience `api`, scope `inventory.read` и нужные группы.

```sh
export HEIMDALL_URL=https://heimdall.example
export HEIMDALL_API_TOKEN=your-secret-token
curl --fail --silent --show-error \
  -H "Authorization: Bearer ${HEIMDALL_API_TOKEN}" \
  "${HEIMDALL_URL}/api/v1/ansible/inventory"
```

Ответ содержит группы, `_meta.hostvars`, `ansible_host`, `ansible_port` и `ansible_user`. Секреты SSH не возвращаются. Inventory отбирается по RBAC владельца и токена, статусу пользователя, обязательным факторам и мандатному допуску. Токен администратора без UNIX-назначений не получает все серверы автоматически.

Сохраните следующий исполняемый скрипт как `inventory.sh`:

```sh
#!/bin/sh
set -eu
: "${HEIMDALL_URL:?required}" "${HEIMDALL_API_TOKEN:?required}"
case "${1:---list}" in
  --list) exec curl --fail --silent --show-error \
    -H "Authorization: Bearer ${HEIMDALL_API_TOKEN}" \
    "${HEIMDALL_URL}/api/v1/ansible/inventory" ;;
  --host) printf '%s\n' '{}' ;;
  *) exit 2 ;;
esac
```

```sh
chmod 700 inventory.sh
ansible-inventory -i ./inventory.sh --list
ansible -i ./inventory.sh all -m ping
```

Используйте доверенный TLS CA; для локального Compose можно указать `CURL_CA_BUNDLE` с CA стенда. Не отключайте TLS-проверку в производственной автоматизации. Токен передавайте из secret manager, не сохраняйте в inventory, Git или журнале CI.

## MCP и Swagger

MCP endpoint — `/mcp`; токен должен разрешать audience `mcp` и соответствующие scopes. Каждый инструмент проверяет права. Swagger доступен на `/swagger`, спецификация — `/api/v1/openapi.json`. Их доступность ограничена конфигурацией и настройками администратора. Право `api_docs.read` относится к Swagger; `documentation.read` позволяет API-токену читать встроенную документацию.
