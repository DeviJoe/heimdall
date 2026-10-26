package httpapi

import (
	"fmt"
	"strings"
)

type apiOperation struct {
	Method, Path, Summary, Tag, Rights, Input, Output, Auth string
	Created, Page                                           bool
}

func openAPIOperations() []apiOperation {
	ops := []apiOperation{}
	add := func(method, path, summary, tag, rights, input, output, auth string) {
		ops = append(ops, apiOperation{Method: method, Path: "/api/v1/" + path, Summary: summary, Tag: tag, Rights: rights, Input: input, Output: output, Auth: auth})
	}
	list := func(path, summary, tag, rights, model string) {
		add("get", path, summary, tag, rights, "", "[]"+model, "either")
		ops[len(ops)-1].Page = true
	}
	write := func(method, path, summary, tag, rights, input, output string) {
		add(method, path, summary, tag, rights, input, output, "either")
	}
	add("post", "auth/login", "Войти по паролю", "Авторизация", "Публичный браузерный вход; X-Heimdall-CSRF: 1.", "PasswordLogin", "LoginResult", "public-browser")
	add("post", "auth/totp", "Завершить TOTP-вход", "Авторизация", "Одноразовый challenge предыдущего входа.", "TOTPLogin", "LoginResult", "public-browser")
	add("post", "auth/invitation", "Принять приглашение и задать пароль Heimdall", "Авторизация", "Одноразовый invitation token; не устанавливает UNIX-пароль.", "InvitationInput", "LoginResult", "public-browser")
	add("post", "auth/passkey/begin", "Начать вход с passkey", "Авторизация", "Login активной human-учётки.", "LoginName", "WebAuthnOptions", "public-browser")
	add("post", "auth/passkey/finish", "Подтвердить вход с passkey", "Авторизация", "WebAuthn assertion и одноразовый challenge cookie.", "WebAuthnCredential", "LoginResult", "public-browser")
	add("post", "auth/logout", "Завершить текущую браузерную сессию", "Авторизация", "Текущая сессия.", "", "OK", "browser")
	add("get", "me", "Прочитать профиль и эффективную политику входа", "Профиль", "Текущий аутентифицированный пользователь; permissions — каталог имён, реальные права в principal.", "", "Me", "either")
	add("get", "me/native-policy", "Узнать разрешённые способы UNIX-входа", "Профиль", "Браузерная сессия владельца.", "", "NativeAccessPolicy", "browser")
	add("get", "users/{id}/native-policy", "Узнать политику UNIX-входа пользователя", "Пользователи", "Владелец или users.manage глобально; browser only.", "", "NativeAccessPolicy", "browser")
	list("me/nodes", "Доступные владельцу ноды", "Профиль", "Браузерная сессия; назначенный native доступ, sync_to_nodes, факторы и мандатный допуск.", "AccessibleNode")
	ops[len(ops)-1].Auth = "browser"
	list("users/{id}/nodes", "Проверить доступ пользователя к нодам", "Пользователи", "Владелец или users.manage глобально; browser only.", "AccessibleNode")
	ops[len(ops)-1].Auth = "browser"
	for _, mode := range []string{"", "rotate/"} {
		title := "Подключить"
		if mode != "" {
			title = "Заменить"
		}
		add("post", "me/totp/"+mode+"begin", title+" TOTP: получить secret и QR URI", "Факторы", "Браузерная сессия владельца. Замена оставляет старый TOTP рабочим до finish.", "", "TOTPEnrollment", "browser")
		add("post", "me/totp/"+mode+"finish", title+" TOTP: проверить код", "Факторы", "Браузерная сессия владельца; проверенный код нового TOTP. Замена отзывает прежние браузерные сессии и recovery codes.", "TOTPCode", "FactorRegistered", "browser")
	}
	add("post", "me/passkey/begin", "Добавить passkey: получить challenge", "Факторы", "Браузерная сессия владельца; существующий TOTP не мешает добавлению passkey.", "", "WebAuthnOptions", "browser")
	add("post", "me/passkey/finish", "Добавить passkey: проверить credential", "Факторы", "Браузерная сессия владельца; WebAuthn attestation.", "WebAuthnCredential", "FactorRegistered", "browser")
	add("put", "me/factor-policy", "Усилить личные требования факторов", "Факторы", "Браузерная сессия владельца. Минимум администратора ослабить нельзя.", "MFAPolicyInput", "OperationAccepted", "browser")
	add("get", "users/{id}/factors", "Список passkey и состояние TOTP", "Факторы", "Владелец или users.manage глобально. Не возвращает TOTP secret/ключи WebAuthn.", "", "Factors", "either")
	write("put", "users/{id}/passkeys/{key}", "Переименовать passkey", "Факторы", "Владелец или users.manage глобально.", "NameInput", "OK")
	write("delete", "users/{id}/passkeys/{key}", "Отвязать passkey", "Факторы", "Владелец без ослабления обязательного минимума; users.manage может выполнить сброс с повторной регистрацией.", "", "OperationAccepted")
	write("delete", "users/{id}/totp", "Отозвать TOTP для повторной регистрации", "Факторы", "Владелец без ослабления обязательного минимума; users.manage может выполнить административный сброс. Сессии Heimdall отзываются.", "", "OperationAccepted")
	list("users", "Найти пользователей", "Пользователи", "users.read глобально.", "User")
	write("post", "users", "Создать пользователя / сервисную учётку", "Пользователи", "users.manage глобально. UNIX-доступ запрещён до явного назначения.", "UserCreate", "UserCreated")
	ops[len(ops)-1].Created = true
	write("put", "users/{id}", "Обновить UNIX-профиль и параметры пользователя", "Пользователи", "users.manage глобально; самообслуживание ограничено разрешёнными полями. POSIX migration требует подтверждённого отключения.", "UserUpdate", "OperationAccepted")
	write("post", "users/{id}/status", "Активировать, заблокировать или удалить пользователя", "Пользователи", "users.manage глобально; нельзя удалить/заблокировать последнего администратора. disabled/deleted завершают серверные процессы после доставки.", "UserStatusInput", "OperationAccepted")
	write("put", "users/{id}/linux-password", "Установить/очистить отдельный UNIX-пароль", "Пользователи", "Владелец или users.manage глобально. Непустой пароль требует sync_to_nodes и явного allow_password.", "UnixPasswordInput", "OperationAccepted")
	write("put", "users/{id}/mfa-policy", "Изменить административный минимум факторов", "Факторы", "users.manage глобально. Личное усиление продолжает действовать.", "MFAPolicyInput", "OperationAccepted")
	list("users/{id}/keys", "Ключи пользователя", "SSH-ключи", "Владелец с self scope или users.read глобально.", "SSHKey")
	write("post", "users/{id}/keys", "Добавить SSH-ключ", "SSH-ключи", "Владелец или users.manage; проверяется SK-only политика. TTL задаётся администратором, fingerprint нельзя использовать повторно.", "SSHKeyInput", "SSHKeyCreated")
	ops[len(ops)-1].Created = true
	write("delete", "keys/{id}", "Безвозвратно отозвать SSH fingerprint", "SSH-ключи", "Владелец или users.manage; ключ удаляется после доставки. Сама сессия остаётся, если полный доступ пользователя не отозван.", "", "OperationAccepted")
	list("roles", "Найти роли управления / UNIX-доступа", "Роли и назначения", "roles.read глобально или roles.manage глобально.", "Role")
	write("post", "roles", "Создать или обновить роль", "Роли и назначения", "roles.manage глобально; нельзя предоставить права, которых нет у инициатора. Изменение sudo требует sudo.manage. Последний администратор защищён.", "RoleInput", "OperationAccepted")
	write("delete", "roles/{id}", "Удалить роль и её назначения", "Роли и назначения", "roles.manage; затронутые native права пересчитываются, последний администратор защищён.", "", "OperationAccepted")
	list("users/{id}/bindings", "Персональные назначения (исключения)", "Роли и назначения", "Владелец или users.read глобально.", "Binding")
	write("post", "bindings", "Назначить персональное исключение", "Роли и назначения", "roles.manage на области; права роли не выше прав инициатора; sudo.manage для sudo.", "BindingInput", "OperationAccepted")
	write("delete", "bindings/{id}", "Отозвать персональное назначение", "Роли и назначения", "roles.manage на области. Удаление последнего native разрешения завершает процессы на затронутых нодах.", "", "OperationAccepted")
	list("unix-assignments", "Найти UNIX-группа → роль → группа нод", "Роли и назначения", "roles.read или roles.manage на области. Каталог определений ролей читается отдельно с глобальными правами.", "UnixAssignmentSummary")
	write("post", "unix-assignments", "Назначить UNIX-группе вход / sudo", "Роли и назначения", "users.manage глобально, roles.manage на области; native роль, sudo.manage если выдаётся sudo. Права Heimdall не предоставляются.", "UnixAssignment", "OperationAccepted")
	write("delete", "unix-assignments/{id}", "Отозвать UNIX-назначение", "Роли и назначения", "roles.manage на области. Полный отзыв завершает процессы после подтверждения агента.", "", "OperationAccepted")
	add("get", "access/graph", "Граф назначений и рекомендации", "Роли и назначения", "roles.read + users.read + nodes.read глобально. Ограниченный анализ одной страницы; не проверка эффективного входа.", "", "AccessGraph", "either")
	ops[len(ops)-1].Page = true
	list("user-groups", "Найти группы людей / политики факторов", "Группы людей", "users.read глобально.", "PeopleGroupSummary")
	write("post", "user-groups", "Создать/изменить группу людей", "Группы людей", "users.manage; изменения членства группы с ролями дополнительно проверяют roles.manage/sudo.manage и делегируемые права.", "PeopleGroupInput", "OperationAccepted")
	write("delete", "user-groups/{id}", "Удалить группу людей", "Группы людей", "users.manage; права затронутых назначений; защищён последний администратор.", "", "OperationAccepted")
	write("post", "user-groups/move", "Перенести до 500 пользователей", "Группы людей", "users.manage; права на назначения источника и назначения. Группы факторной политики эксклюзивны.", "PeopleMoveInput", "OperationAccepted")
	write("post", "user-groups/{id}/members/remove", "Удалить участников группы людей", "Группы людей", "users.manage и права на затронутые назначения.", "PeopleRemoveInput", "OperationAccepted")
	list("user-groups/{id}/bindings", "Назначения группе людей", "Группы людей", "users.read глобально + roles.read/roles.manage на области.", "Binding")
	write("post", "user-groups/{id}/bindings", "Назначить роль группе людей", "Группы людей", "users.manage и roles.manage; проверяются права инициатора и sudo.manage.", "GroupBindingInput", "OperationAccepted")
	write("delete", "user-groups/{id}/bindings/{binding}", "Отозвать роль у группы людей", "Группы людей", "users.manage и roles.manage на области.", "", "OperationAccepted")
	list("unix-groups", "Найти UNIX-группы по cn / gidNumber", "UNIX-каталог", "users.read глобально.", "UnixGroupSummary")
	add("get", "unix-groups/{id}", "Прочитать UNIX-группу", "UNIX-каталог", "users.read глобально.", "", "UnixGroupSummary", "either")
	list("users/{id}/unix-groups", "Primary / supplementary группы пользователя", "UNIX-каталог", "Владелец или users.read глобально.", "UnixMembership")
	write("post", "unix-groups", "Создать/изменить UNIX-группу", "UNIX-каталог", "users.manage; имя/GID существующей группы неизменяемы. Оmitted members сохраняет состав.", "UnixGroupInput", "OperationAccepted")
	write("post", "unix-groups/{id}/members", "Изменить supplementary членство", "UNIX-каталог", "users.manage и разрешения на назначения UNIX-группы. 1–500 участников в сумме.", "UnixMembersInput", "OperationAccepted")
	write("delete", "unix-groups/{id}", "Удалить UNIX-группу", "UNIX-каталог", "users.manage; сначала снимите назначения и перенесите primary GID пользователей.", "", "OperationAccepted")
	list("groups", "Найти группы нод / дочерние группы", "Ноды", "nodes.read / nodes.manage / roles.manage на области либо назначенный native доступ.", "NodeGroup")
	write("post", "groups", "Создать группу нод", "Ноды", "nodes.manage; родитель входит в разрешённую область.", "NodeGroupInput", "NodeGroupCreated")
	write("put", "groups/{id}", "Изменить имя/родителя группы нод", "Ноды", "nodes.manage; цикл запрещён, глубина до 32.", "NodeGroupInput", "OperationAccepted")
	write("delete", "groups/{id}", "Удалить пустую группу нод", "Ноды", "nodes.manage глобально; сначала перенесите ноды/детей. Назначения на пустую группу удаляются автоматически.", "", "OperationAccepted")
	list("nodes", "Найти ноды и состояние синхронизации", "Ноды", "nodes.read на области.", "Node")
	write("put", "nodes/{id}", "Переместить или выключить управление нодой", "Ноды", "nodes.manage исходной/целевой области. disabled сохраняет локальные учётки, не означает отзыв пользователей.", "NodeInput", "OperationAccepted")
	write("post", "nodes/move", "Перенести до 500 нод", "Ноды", "nodes.manage на всех исходных и целевой группе; пересчитывает доступ.", "MoveNodesInput", "OperationAccepted")
	write("put", "nodes/{id}/ssh", "Настроить SSH-адрес для подключения / inventory", "Ноды", "nodes.manage на области.", "NodeSSHInput", "OK")
	write("post", "nodes/{id}/retry", "Поставить повторную сверку в очередь", "Синхронизация", "sync.retry на области. Обычно не нужен: агенты и очередь повторяют автоматически.", "", "OperationAccepted")
	add("post", "nodes/{id}/recovery-token", "Одноразовое восстановление сертификата ноды", "Присоединение нод", "nodes.manage на области; browser only; 600 секунд.", "", "RecoveryToken", "browser")
	list("join-tokens", "Только действующие токены присоединения", "Присоединение нод", "nodes.manage на области; истёкшие/отозванные/исчерпанные скрыты, expiry журналируется.", "JoinToken")
	write("post", "join-tokens", "Выпустить именованный join token", "Присоединение нод", "nodes.manage на области. TTL и max_uses независимы; секрет показан один раз.", "JoinTokenInput", "TokenSecret")
	write("put", "join-tokens/{id}", "Изменить TTL / число присоединений", "Присоединение нод", "nodes.manage на области; не продлевает уже выданные сертификаты.", "JoinTokenUpdate", "OK")
	write("delete", "join-tokens/{id}", "Отозвать токен присоединения", "Присоединение нод", "nodes.manage; уже присоединённые ноды и сертификаты не отключаются.", "", "OK")
	add("post", "agent/join", "Первое присоединение агента", "Присоединение нод", "Join secret в теле; проверка срока/лимита атомарна. TLS server CA/pin проверяется агентом.", "AgentJoin", "AgentCertificate", "public")
	ops[len(ops)-1].Created = true
	add("post", "agent/recover", "Восстановление сертификата существующей ноды", "Присоединение нод", "Одноразовый node-bound recovery secret в теле; сохраняется node_id.", "AgentRecover", "AgentCertificate", "public")
	ops[len(ops)-1].Created = true
	add("get", "summary", "Счётчики нод и инцидентов", "Синхронизация", "nodes.read на области.", "", "Summary", "either")
	list("operations", "Принятые изменения и их результаты", "Синхронизация", "sync.read на области; видимость собственных операций ограничена текущими правами.", "SyncOperation")
	list("operations/{id}/targets", "Подтверждения целевых нод", "Синхронизация", "sync.read на области. applied означает завершённые native изменения и прекращение процессов полного отзыва.", "SyncTarget")
	list("users/{id}/sync", "Состояние доставки UNIX-профиля", "Синхронизация", "Владелец либо users.read / sync.read на области.", "UserSync")
	add("get", "events/fleet", "SSE: инвалидация состояния нод", "Синхронизация", "Браузерная сессия, nodes.read или sync.read; поток не выдаёт данные ресурсов, клиенты повторяют GET после события.", "", "SSE", "browser")
	list("incidents", "Инциденты с поиском / пагинацией", "Инциденты и аудит", "incidents.read на области.", "Incident")
	write("post", "incidents/{id}/acknowledge", "Подтвердить получение инцидента", "Инциденты и аудит", "incidents.manage на области.", "", "OK")
	write("post", "incidents/{id}/resolve", "Закрыть изученный инцидент активности", "Инциденты и аудит", "incidents.manage; инцидент синхронизации закрывается после подтверждённого восстановления.", "", "OK")
	write("post", "incidents/resolve", "Закрыть 1–500 инцидентов атомарно", "Инциденты и аудит", "incidents.manage на каждой области; activity incidents only.", "IncidentsInput", "OK")
	list("audit", "Аудит действий", "Инциденты и аудит", "audit.read глобально.", "AuditEvent")
	list("security/events", "SSH-события с именами нод", "Инциденты и аудит", "security.read на области.", "SecurityEvent")
	list("security/labels", "Мандатные метки и допуски", "Безопасность и настройки", "security.manage глобально.", "LabelPolicy")
	write("post", "security/labels", "Настроить уровень/категории допуска", "Безопасность и настройки", "security.manage глобально; несовместимый допуск отзывает native доступ.", "LabelPolicy", "OperationAccepted")
	add("get", "settings", "Текущие административные настройки", "Безопасность и настройки", "settings.manage глобально.", "", "Settings", "either")
	write("put", "settings", "Сохранить настройки с проверкой версии", "Безопасность и настройки", "settings.manage глобально; version CAS (409 при конфликте), SSH TTL/пороги алертов/Swagger/MCP. Изменение node_certificate_ttl_seconds запускает перевыпуск на всех нодах. Применение UNIX-состояния смотрите в targets, завершение перевыпуска — GET settings certificates_pending=0 и node.certificate_status=current. Offline-ноды остаются pending до подключения.", "Settings", "OperationAccepted")
	list("tokens", "Действующие API/MCP токены", "Токены и автоматизация", "Владелец; tokens.manage видит service владельцев. self scope для token-запросов.", "Token")
	add("post", "tokens", "Создать ограниченный API/MCP токен", "Токены и автоматизация", "Browser only; self для владельца, tokens.manage для service. Токен не может повышать актуальные права.", "TokenInput", "TokenIssued", "browser")
	write("delete", "tokens/{id}", "Отозвать API/MCP токен", "Токены и автоматизация", "Владелец; tokens.manage для service. Через bearer нужен self.", "", "OK")
	add("get", "ansible/inventory", "Ansible dynamic inventory доступных хостов", "Токены и автоматизация", "Только Bearer с audience api и inventory.read, актуальные native назначения и мандатные ограничения владельца. Браузерная cookie отклоняется.", "", "Inventory", "bearer")
	add("get", "auth/providers", "Настроенные OIDC/LDAP провайдеры", "Интеграции", "Публичные имена; секреты не возвращаются.", "", "[]Provider", "public")
	add("get", "auth/oidc/{provider}/start", "Перенаправить к OIDC провайдеру", "Интеграции", "Публичный browser redirect, state cookie.", "", "Redirect", "public")
	add("get", "auth/oidc/{provider}/callback", "OIDC callback", "Интеграции", "Одноразовый state cookie + code провайдера; server exchange/verifier.", "", "Redirect", "public")
	write("post", "identities", "Привязать внешнюю OIDC identity", "Интеграции", "integrations.manage глобально, настроенный провайдер.", "IdentityInput", "OK")
	add("get", "integrations/status", "Состояние синхронизации каталогов", "Интеграции", "integrations.manage глобально.", "", "[]IntegrationStatus", "either")
	add("get", "notifications", "Свои каналы уведомлений", "Интеграции", "Владелец.", "", "[]NotificationChannel", "either")
	write("delete", "notifications/{id}", "Отвязать канал уведомлений", "Интеграции", "Владелец.", "", "OK")
	add("post", "me/notifications/{provider}/start", "Связать Telegram / Mattermost через OAuth", "Интеграции", "Browser only; настроенный провайдер. Возвращает URL для перехода.", "", "OAuthURL", "browser")
	add("post", "integrations/telegram/webhook", "Приём Telegram updates", "Интеграции", "Только при включённом Telegram; X-Telegram-Bot-Api-Secret-Token из конфигурации.", "TelegramUpdate", "OK", "telegram")
	list("announcements", "Активные сообщения в обзоре", "Сообщения и документация", "Владелец; all=true требует announcements.manage глобально.", "Announcement")
	write("post", "announcements", "Создать/изменить Markdown сообщение", "Сообщения и документация", "announcements.manage глобально; version CAS; active interval starts_at/ends_at.", "Announcement", "OperationAccepted")
	write("delete", "announcements/{id}", "Удалить сообщение с проверкой версии", "Сообщения и документация", "announcements.manage глобально; query version обязателен, CAS предотвращает удаление изменённого сообщения.", "", "OperationAccepted")
	list("documentation", "Найти статьи документации (без Markdown)", "Сообщения и документация", "Любой browser пользователь, включая регистрацию факторов; bearer требует documentation.read глобально.", "DocumentationPage")
	add("get", "documentation/{slug}", "Прочитать полную Markdown статью", "Сообщения и документация", "Любой browser пользователь; bearer documentation.read глобально.", "", "DocumentationPage", "either")
	write("put", "documentation/{slug}", "Создать/изменить Markdown статью", "Сообщения и документация", "documentation.manage глобально; version CAS, slug задаёт path.", "DocumentationInput", "OperationAccepted")
	add("get", "openapi.json", "OpenAPI 3.0 описание", "Токены и автоматизация", "api_docs.read глобально; Swagger включён в YAML и runtime.", "", "OpenAPIDocument", "either")
	for _, health := range []string{"live", "ready"} {
		ops = append(ops, apiOperation{Method: "get", Path: "/health/" + health, Summary: "Health " + health, Tag: "Диагностика", Rights: "Публичный endpoint для балансировщика; ready проверяет PostgreSQL и Redis.", Output: "Health", Auth: "public"})
	}
	return ops
}
func openAPI() specObject {
	models := openAPIModels()
	models["DocumentationInput"] = specBody(specObject{"title": specString("Заголовок."), "markdown": specObject{"type": "string", "maxLength": 262144, "description": "Markdown, до 256 КиБ; HTML/внешние изображения не исполняются."}, "version": specInt("0 для создания, текущая версия при изменении.", 0, 2147483646)}, "title", "markdown", "version")
	models["TelegramUpdate"] = specObject{"type": "object", "additionalProperties": true, "description": "Telegram Bot API Update; обязательная проверка webhook secret."}
	models["OpenAPIDocument"] = specObject{"type": "object", "additionalProperties": true, "description": "OpenAPI 3.0.3 document."}
	paths := specObject{}
	tags := []any{}
	seenTags := map[string]bool{}
	for _, op := range openAPIOperations() {
		if !seenTags[op.Tag] {
			tags = append(tags, specObject{"name": op.Tag})
			seenTags[op.Tag] = true
		}
		description := "**Доступ:** " + op.Rights
		if op.Output == "OperationAccepted" || op.Output == "UserCreated" || op.Output == "SSHKeyCreated" || op.Output == "NodeGroupCreated" {
			description += "\n\nИзменение принято транзакционно, но доставка на ноды асинхронна. Проверяйте operation_id и статусы целевых нод. Отзыв считается завершённым после ACK всех целевых агентов, включая завершение сессий/процессов. Offline-нода остаётся неподтверждённой."
		}
		if op.Page {
			description += "\n\nKeyset pagination: прочитайте `X-Heimdall-Next-Cursor` ответа и передайте `after` следующего GET с теми же фильтрами. Пустой курсор — конец. Клиент не должен собирать все страницы ради отображения списка."
		}
		operationID := op.Method + "_" + strings.NewReplacer("/", "_", "{", "", "}", "", "-", "_", ".", "_").Replace(strings.TrimPrefix(op.Path, "/"))
		v := specObject{"summary": op.Summary, "description": description, "operationId": operationID, "tags": []string{op.Tag}, "x-heimdall-authorization": op.Rights}
		security := []any{specObject{"cookieAuth": []string{}}, specObject{"bearerAuth": []string{}}}
		switch op.Auth {
		case "public", "public-browser":
			security = []any{}
		case "browser":
			security = []any{specObject{"cookieAuth": []string{}}}
		case "bearer":
			security = []any{specObject{"bearerAuth": []string{}}}
		case "telegram":
			security = []any{specObject{"telegramWebhook": []string{}}}
		}
		v["security"] = security
		params := []any{}
		for _, part := range strings.Split(op.Path, "/") {
			if strings.HasPrefix(part, "{") {
				name := strings.Trim(part, "{}")
				s := specString("Идентификатор ресурса.")
				if name == "id" || name == "binding" {
					s = specUUID("UUID ресурса.")
				}
				if name == "slug" {
					s["pattern"] = "^[a-z][a-z0-9-]{0,79}$"
				}
				if name == "key" {
					s["description"] = "Passkey credential ID (base64url), URL-encoded."
				}
				params = append(params, specObject{"in": "path", "name": name, "required": true, "schema": s})
			}
		}
		if op.Page {
			maximum, def := 500, 100
			if op.Output == "[]DocumentationPage" || op.Output == "[]AccessibleNode" {
				maximum = 100
			}
			if op.Output == "AccessGraph" {
				maximum = 100
				def = 25
			}
			limit := specInt("Количество элементов; неверный/пустой limit использует значение по умолчанию.", 1, maximum)
			limit["default"] = def
			params = append(params, specObject{"in": "query", "name": "limit", "schema": limit}, specObject{"in": "query", "name": "after", "schema": specString("Непрозрачный курсор ответа; не разбирайте и не создавайте вручную.")})
		}
		if op.Method == "get" {
			for name, s := range openAPIFilters(op.Path) {
				params = append(params, specObject{"in": "query", "name": name, "schema": s})
			}
		}
		if op.Method == "delete" && op.Path == "/api/v1/announcements/{id}" {
			params = append(params, specObject{"in": "query", "name": "version", "required": true, "schema": specInt("Текущая версия GET.", 1, 2147483646)})
		}
		if op.Method != "get" && (op.Auth == "browser" || op.Auth == "either" || op.Auth == "public-browser") {
			params = append(params, specObject{"in": "header", "name": "X-Heimdall-CSRF", "required": op.Auth == "browser" || op.Auth == "public-browser", "schema": specEnum("Для cookie-сессии обязателен 1 и same-origin. Bearer не требует CSRF.", "1")})
		}
		if len(params) > 0 {
			v["parameters"] = params
		}
		if op.Input != "" {
			v["requestBody"] = specObject{"required": true, "content": specObject{"application/json": specObject{"schema": ref(op.Input)}}}
		}
		responses := specObject{}
		code := "200"
		if op.Created {
			code = "201"
		}
		success := specObject{"description": "Успешный результат."}
		if op.Output == "Redirect" {
			code = "302"
			success = specObject{"description": "Перенаправление браузера.", "headers": specObject{"Location": specObject{"schema": specString("URL перехода.")}}}
		} else if op.Output == "SSE" {
			success["content"] = specObject{"text/event-stream": specObject{"schema": specString("SSE: event fleet, data changed; keepalive комментарии. Reconnect раз в минуту повторно проверяет session RBAC."), "example": "event: fleet\ndata: changed\n\n"}}
		} else {
			responseSchema := ref(op.Output)
			if strings.HasPrefix(op.Output, "[]") {
				responseSchema = specArray(ref(strings.TrimPrefix(op.Output, "[]")))
			}
			success["content"] = specObject{"application/json": specObject{"schema": responseSchema}}
		}
		if op.Page {
			success["headers"] = specObject{"X-Heimdall-Next-Cursor": specObject{"description": "Курсор следующей страницы либо пустая строка.", "schema": specString("Непрозрачный курсор.")}}
		}
		if strings.HasPrefix(op.Path, "/api/v1/auth/") && op.Method == "post" {
			success["headers"] = specObject{"Set-Cookie": specObject{"description": "HttpOnly SameSite=Strict session/challenge; Secure вне development.", "schema": specString("linpam_session — совместимое имя cookie.")}}
		}
		responses[code] = success
		for c, d := range map[string]string{"400": "Неверный JSON/параметры, нарушены правила модели.", "401": "Требуется аутентификация; сессия истекла/отозвана или токен не подходит.", "403": "RBAC/scope/CSRF запрещает операцию либо факторный минимум не выполнен.", "404": "Ресурс отсутствует или endpoint выключен.", "409": "Конфликт версии, дубликат/отозванный fingerprint.", "429": "Ограничение частоты / занятый обработчик; повторите с backoff.", "500": "Ошибка хранилища или сервера.", "503": "Зависимость или интеграция недоступна."} {
			responses[c] = specObject{"description": d + " Некоторые auth/health ошибки имеют пустое тело.", "content": specObject{"application/json": specObject{"schema": ref("Error")}}}
		}
		if op.Path == "/health/ready" {
			responses["503"] = specObject{"description": "PostgreSQL или Redis недоступен; status=unavailable.", "content": specObject{"application/json": specObject{"schema": ref("Health")}}}
		}
		v["responses"] = responses
		if paths[op.Path] == nil {
			paths[op.Path] = specObject{}
		}
		paths[op.Path].(specObject)[op.Method] = v
	}
	return specObject{"openapi": "3.0.3", "info": specObject{"title": "Heimdall API", "version": "0.1.0", "description": "API управления доступом к Linux/FreeBSD.\n\nBearer требует audience `api`; права = актуальный RBAC владельца ∩ scopes ∩ группы токена. Browser cookie `linpam_session` сохранена для совместимости, для записей нужен X-Heimdall-CSRF: 1. Сервисные учётки используют токены.\n\nПринятое изменение не равно доставленному. Полный отзыв отключает native учётку, удаляет ключи/пароль/sudo и завершает сессии и процессы до ACK. При отключении control plane локальный доступ сохраняется.\n\nSwagger включает подтверждение перед записью. MCP доступен отдельно на /mcp по Streamable HTTP и audience mcp, протокол описан в документации продукта; mTLS gRPC агентского канала не является REST API."}, "servers": []any{specObject{"url": "/", "description": "Текущий control plane / proxy"}}, "tags": tags, "paths": paths, "components": specObject{"schemas": models, "securitySchemes": specObject{"cookieAuth": specObject{"type": "apiKey", "in": "cookie", "name": "linpam_session", "description": "HttpOnly browser session, срок 8 часов; изменённые auth_version/права проверяются при запросе."}, "bearerAuth": specObject{"type": "http", "scheme": "bearer", "description": "API token, audience api; secret показывается один раз, текущие права владельца перепроверяются."}, "telegramWebhook": specObject{"type": "apiKey", "in": "header", "name": "X-Telegram-Bot-Api-Secret-Token"}}}}
}
func openAPIFilters(path string) specObject {
	out := specObject{}
	switch path {
	case "/api/v1/users":
		out = specObject{"query": specString("Login/имя."), "kind": specEnum("Тип", "human", "service"), "status": specEnum("Статус; удалённые учётки исключены из каталога.", "active", "invited", "disabled"), "unix_sync": specEnum("Синхронизация UNIX-учётки", "enabled", "disabled"), "factor": specString("Фильтр факторов: totp, passkey, missing, none."), "people_group": specUUID("Группа людей."), "unix_group": specUUID("UNIX-группа; включает отдельный режим каталога."), "members": specBool("С unix_group: true — участники; false — все для добавления.")}
	case "/api/v1/nodes":
		out = specObject{"query": specString("Имя/hostname/IP."), "group_id": specUUID("Группа нод."), "status": specEnum("Единый статус", "healthy", "warning", "offline", "disabled"), "platform": specEnum("Платформа", "linux", "freebsd")}
	case "/api/v1/roles":
		out = specObject{"query": specString("Название."), "status": specEnum("Вид роли", "all", "unix", "application")}
	case "/api/v1/groups":
		out = specObject{"query": specString("Название."), "parent": specString("root — корневые; UUID — непосредственные дочерние; пусто — все видимые.")}
	case "/api/v1/security/labels":
		out = specObject{"resource_type": specEnum("Тип", "user", "node_group"), "resource_id": specUUID("Владелец метки.")}
	case "/api/v1/access/graph":
		out = specObject{"query": specString("Субъект/роль/группа нод."), "kind": specEnum("Источник назначения", "unix_group", "people_group", "user")}
	case "/api/v1/announcements":
		out = specObject{"query": specString("Заголовок."), "all": specBool("Показать также выключенные/истёкшие; announcements.manage.")}
	case "/api/v1/incidents":
		out = specObject{"query": specString("Тип, сообщение, имя ноды."), "status": specEnum("По умолчанию только нерешённые; all включает историю.", "all")}
	case "/api/v1/auth/oidc/{provider}/callback":
		out = specObject{"state": specString("Одноразовое OAuth state."), "code": specString("Authorization code провайдера.")}
	default:
		for _, collection := range []string{"user-groups", "unix-groups", "unix-assignments", "join-tokens", "audit", "operations", "security/events", "tokens", "documentation", "me/nodes", "users/{id}/nodes", "users/{id}/keys", "users/{id}/bindings", "user-groups/{id}/bindings", "users/{id}/unix-groups"} {
			if path == "/api/v1/"+collection {
				out["query"] = specString(fmt.Sprintf("Поиск %s, до 200 символов (документация до 256).", collection))
			}
		}
	}
	return out
}
