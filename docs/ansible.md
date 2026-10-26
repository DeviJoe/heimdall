# Динамический Ansible inventory

`GET /api/v1/ansible/inventory` возвращает JSON script inventory с `_meta.hostvars`, `all.children` и группами хостов. Доступен только API Bearer-токенам.

## Права и выпуск токена

1. Создайте/выберите человека или сервисную УЗ. Назначьте ему UNIX-доступ через `UNIX-группа → группа нод → роль`, либо совместимое прямое назначение native-роли и роль с permission `inventory.read` на те же группы. Назначение на родителя наследуется потомками.
2. В «Токены» выберите владельца (сервисную УЗ может выбирать администратор), audience `api`, scope `inventory.read`, разрешённые группы и срок. Secret показывается один раз.
3. В «Ноды» задайте SSH-адрес и порт каждой ноды. По умолчанию используется имя ноды и порт 22. Укажите адрес, достижимый с Ansible controller; агентский адрес control plane не является SSH-адресом ноды.

На каждом запросе проверяются status и актуальный RBAC владельца, audience/expiry/revocation токена, scope/group restrictions и UNIX-доступ, включая мандатные уровни/категории. Токен с `nodes.read` без `inventory.read` недостаточен. Административная роль без UNIX-доступа также не включает хост. Cookie-сессия не даёт inventory. Заблокированный владелец получает 401, недостаточные scopes — 403.

Отключённые ноды не возвращаются. Offline ноды остаются: потеря связи агента не означает запрет SSH. Наличие в inventory выражает разрешение, а не подтверждение SSH-доступности и не обещание, что pending изменение уже применилось. Перед операциями, требующими подтверждённого отзыва, проверяйте статусы синхронизации.

## Подключение

```sh
chmod +x scripts/heimdall-inventory.py
export HEIMDALL_URL=https://heimdall.example.org
export HEIMDALL_CA_FILE=/path/to/trusted-ca.pem
```

`HEIMDALL_API_TOKEN` задайте через secret manager или защищённое окружение процесса Ansible. Не помещайте secret в репозиторий, URL или shell history. Для локального Compose используйте публичный CA стенда:

```sh
mkdir -p .local
docker compose cp linux-node:/trust/ca.pem .local/heimdall-ca.pem
export HEIMDALL_URL=https://localhost:8443
export HEIMDALL_CA_FILE="$PWD/.local/heimdall-ca.pem"
```

API/TLS проверяются без `--insecure`; системные корневые CA используются, если `HEIMDALL_CA_FILE` не задан. Inventory-скрипт отказывается работать с HTTP и завершается ненулевым кодом при ошибке API/TLS, не подставляя устаревший кеш.

```sh
scripts/heimdall-inventory.py --list
ansible-inventory -i scripts/heimdall-inventory.py --list
ansible-inventory -i scripts/heimdall-inventory.py --graph
ansible all -i scripts/heimdall-inventory.py -m ping --private-key /path/to/key
```

Для доступа к демо-нode с host-машины поставьте SSH-адрес `localhost`: `linux-demo` — порт `22220`, `linux-stage` — `22222`, `linux-web` — `22223`, `linux-db` — `22224`. Используйте токен владельца `operator` с `inventory.read` и его актуальный приватный SSH-ключ. Токен разрешает прочитать inventory; аутентификация к sshd выполняется отдельно ключом/паролем и локальными правами Linux.

## Формат

Имя хоста `n_<UUID без дефисов>`, группы `g_<UUID без дефисов>`. Идентификаторы стабильны при переименовании. Hostvars содержат `ansible_host`, `ansible_port`, `ansible_user` (login владельца токена), `heimdall_node_id`, `heimdall_node_name`, `heimdall_group_id`. `_meta.hostvars` позволяет Ansible получить переменные одним запросом, не вызывая `--host` для каждого сервера. `--host <inventory_name>` также поддерживается.

Inventory не содержит private keys, пароли или произвольные команды Ansible. Иерархия доступных групп отражается в `children`; неавторизованные хосты не раскрываются через родительскую группу. Лимит — 20 000 хостов; превышение является ошибкой.

API отдаёт `Cache-Control: no-store`. Не включайте долгий внешний inventory cache, если важен немедленный отзыв полномочий API. Даже ранее сохранённый inventory не отменяет блокировку Linux-УЗ после native ACK.

Формат script inventory описан в [официальной документации Ansible](https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_dynamic_inventory.html). Автоматические сценарии: `internal/application/inventory_test.go`, `internal/transport/httpapi/inventory_test.go`, `internal/platform/postgres/policies_test.go`, `scripts/check-features.py`.
