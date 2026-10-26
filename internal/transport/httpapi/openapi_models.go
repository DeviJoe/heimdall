package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"Heimdall/internal/knowledge"
	"Heimdall/internal/synchronization"
	"reflect"
	"strings"
	"time"
)

type specObject = map[string]any

func ref(name string) specObject { return specObject{"$ref": "#/components/schemas/" + name} }
func specString(description string) specObject {
	return specObject{"type": "string", "description": description}
}
func specBool(description string) specObject {
	return specObject{"type": "boolean", "description": description}
}
func specInt(description string, min, max int) specObject {
	return specObject{"type": "integer", "description": description, "minimum": min, "maximum": max}
}
func specArray(item specObject) specObject { return specObject{"type": "array", "items": item} }
func specEnum(description string, values ...string) specObject {
	return specObject{"type": "string", "description": description, "enum": values}
}
func specUUID(description string) specObject {
	s := specString(description)
	s["format"] = "uuid"
	return s
}
func specTime(description string) specObject {
	s := specString(description)
	s["format"] = "date-time"
	return s
}
func specBody(props specObject, required ...string) specObject {
	s := specObject{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}
func openAPIModels() specObject {
	models := specObject{}
	types := map[reflect.Type]string{}
	register := func(name string, v any) { types[reflect.TypeOf(v)] = name }
	for name, v := range map[string]any{"User": identity.User{}, "Role": authorization.Role{}, "SudoRule": authorization.SudoRule{}, "Binding": authorization.Binding{}, "Principal": authorization.Principal{}, "NodeGroup": fleet.Group{}, "Node": fleet.Node{}, "SSHKey": credentials.Key{}, "Token": application.Token{}, "JoinToken": application.JoinToken{}, "Settings": application.Settings{}, "PeopleGroup": application.UserGroup{}, "UnixGroup": application.UnixGroup{}, "UnixAssignment": application.UnixAssignment{}, "FactorState": application.FactorState{}, "Passkey": application.Passkey{}, "SecurityLabel": authorization.SecurityLabel{}, "LabelPolicy": application.LabelPolicy{}, "Announcement": application.Announcement{}, "DocumentationPage": knowledge.Page{}, "AccessibleNode": application.AccessibleNode{}, "AccessRole": application.AccessRole{}, "NativeAccessPolicy": application.NativeAccessPolicy{}, "SyncOperation": synchronization.Operation{}, "Incident": synchronization.Incident{}, "AccessConnection": application.AccessConnection{}, "AccessRecommendation": application.AccessRecommendation{}, "AccessGraph": application.AccessGraph{}} {
		register(name, v)
	}
	var schema func(reflect.Type) specObject
	schema = func(t reflect.Type) specObject {
		if t.Kind() == reflect.Pointer {
			item := schema(t.Elem())
			return specObject{"allOf": []any{item}, "nullable": true}
		}
		if t == reflect.TypeOf(time.Time{}) {
			return specTime("Время RFC3339 с часовым поясом; ответы в UTC.")
		}
		if name, ok := types[t]; ok {
			return ref(name)
		}
		switch t.Kind() {
		case reflect.Bool:
			return specObject{"type": "boolean"}
		case reflect.Int, reflect.Int32, reflect.Int64:
			return specObject{"type": "integer", "format": "int64"}
		case reflect.Slice:
			if t.Elem().Kind() == reflect.Uint8 {
				return specObject{"type": "string", "format": "byte"}
			}
			return specArray(schema(t.Elem()))
		default:
			return specObject{"type": "string"}
		}
	}
	for t, name := range types {
		props := specObject{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if !f.IsExported() || len(tag) == 0 || tag[0] == "" || tag[0] == "-" {
				continue
			}
			key := tag[0]
			props[key] = schema(f.Type)
			if len(tag) == 1 {
				required = append(required, key)
			}
		}
		model := specObject{"type": "object", "properties": props}
		if len(required) > 0 {
			model["required"] = required
		}
		models[name] = model
	}
	field := func(model, key, description string, extras specObject) {
		p := models[model].(specObject)["properties"].(specObject)
		v := p[key].(specObject)
		if v["$ref"] != nil {
			v = specObject{"allOf": []any{v}}
			p[key] = v
		}
		v["description"] = description
		for k, x := range extras {
			v[k] = x
		}
	}
	field("Role", "permissions", "Права управления Heimdall. UNIX-назначения не предоставляют эти права.", specObject{"items": specEnum("Разрешение RBAC", append([]string{"*"}, authorization.Permissions...)...), "example": []string{}})
	field("Role", "linux_access", "Роль может предоставлять вход на Linux/FreeBSD через явное назначение. Имя поля сохранено для совместимости API.", specObject{"default": false})
	field("Role", "allow_password", "Явное разрешение UNIX-пароля; по умолчанию false. Не связано с паролем входа в Heimdall.", specObject{"default": false})
	field("Role", "allow_ssh_keys", "Явное разрешение SSH-ключей; по умолчанию false.", specObject{"default": false})
	field("Role", "sudoers", "Нативная правая часть User_Spec, одна строка на правило, без имени пользователя. Агент добавляет проверенный login и выполняет visudo. Не используйте include, aliases или Defaults.", specObject{"maxLength": 32768, "example": "ALL=(root) NOPASSWD: /usr/bin/id *"})
	field("Role", "sudo", "Совместимый структурированный редактор правил. sudoers и sudo складываются, UI использует нативный текст.", specObject{"example": []any{}})
	field("User", "sync_to_nodes", "false по умолчанию. При true UNIX-учётка создаётся только на нодах с разрешённым доступом. Выключение отзывает уже доставленный доступ и завершает процессы.", specObject{"default": false})
	field("User", "uid", "UID управляемой UNIX-учётки; 10000–2147483646, при создании 0 вычисляет автоматически.", nil)
	field("User", "gid", "Primary GID, отдельно от групп людей Heimdall. Дополнительные группы задаются через UNIX-каталог.", nil)
	field("User", "kind", "human: пользователь; service: сервисная учётка, без интерактивного входа в Heimdall.", specObject{"enum": []string{"human", "service"}})
	field("User", "status", "Блокировка/удаление отзывает доступ. Возврат active не воскрешает отозванные SSH-ключи.", specObject{"enum": []string{"invited", "active", "disabled", "deleted"}})
	field("User", "mfa_policy", "Минимум администратора. Пользователь может усилить требования личной политикой, но не ослабить их.", specObject{"enum": []string{"none", "any", "totp", "passkey", "both"}})
	field("User", "auth_version", "Версия аутентификации: изменение отзывается в прежних браузерных сессиях. Только чтение.", specObject{"readOnly": true})
	field("Node", "health", "Единый статус: healthy — на связи и синхронизирована; warning — связь/синхронизация нарушена; offline — не на связи; disabled — управление выключено.", specObject{"enum": []string{"healthy", "warning", "offline", "disabled"}})
	field("Node", "desired_revision", "Внутренний номер желаемого состояния. Доставка ещё не означает применение.", specObject{"readOnly": true})
	field("Node", "applied_revision", "Номер состояния, подтверждённого агентом после применения, включая завершение процессов при отзыве.", specObject{"readOnly": true})
	field("Node", "certificate_status", "Транспортный сертификат: current — соответствует текущей политике; pending — ожидает перевыпуска; expired — нужен recovery-токен.", specObject{"enum": []string{"current", "pending", "expired"}, "readOnly": true})
	field("Settings", "node_certificate_ttl_seconds", "Срок транспортных сертификатов нод, по умолчанию 3650 дней. Изменение запускает подписанный перевыпуск на всех нодах, включая отложенное применение offline-нода́ми.", specObject{"minimum": 86400, "maximum": 315360000, "default": 315360000})
	for _, name := range []string{"certificate_policy_version", "certificates_total", "certificates_pending"} {
		field("Settings", name, "Статус перевыпуска транспортных сертификатов. Только чтение; отдельно от UNIX ACK.", specObject{"readOnly": true})
	}
	field("Token", "scopes", "Права токена пересекаются с актуальными правами владельца. self разрешает операции над своей учёткой; токен не повышает доступ.", nil)
	field("Token", "audiences", "api — REST/Ansible, mcp — MCP. Чужая audience отклоняется.", specObject{"items": specEnum("Audience", "api", "mcp")})
	field("Token", "groups", "UUID областей нод или *. Срок и scope проверяются при каждом запросе.", nil)
	field("JoinToken", "max_uses", "0 — неограниченное число присоединений; лимит использований не меняет срок действия.", specObject{"minimum": 0, "maximum": 1000000000})
	field("SSHKey", "status", "Отозванный или истёкший fingerprint нельзя добавить снова.", specObject{"enum": []string{"active", "revoked", "expired"}})
	for _, m := range []string{"DocumentationPage", "Announcement", "Settings"} {
		field(m, "version", "Оптимистическая версия. Для создания 0; при обновлении передайте актуальную версию GET. Конфликт — HTTP 409.", nil)
	}
	field("SecurityLabel", "level", "Уровень 0–3. Допуск пользователя должен доминировать над уровнем и категориями группы нод с учётом наследования.", specObject{"minimum": 0, "maximum": 3})
	field("AccessGraph", "recommendations", "Анализ только текущей страницы; не решение авторизации. Не анализирует произвольные sudoers-шаблоны и пересечение членства разных групп.", nil)
	field("AccessConnection", "ancestors", "Области-предки группы нод, включая её саму. Используются для анализа наследуемых пересечений.", nil)
	models["Error"] = specBody(specObject{"error": specString("Понятное сообщение об ошибке. Некоторые инфраструктурные/auth ответы возвращают пустое тело.")}, "error")
	models["OperationAccepted"] = specBody(specObject{"operation_id": specUUID("Идентификатор принятого изменения; проверяйте /operations/{id}/targets до подтверждения всех нод.")}, "operation_id")
	models["OK"] = specBody(specObject{"ok": specBool("Операция выполнена.")}, "ok")
	models["NameInput"] = specBody(specObject{"name": specString("Отображаемое имя.")}, "name")
	models["PasswordLogin"] = specBody(specObject{"login": specString("Login Heimdall."), "password": specObject{"type": "string", "format": "password", "writeOnly": true}, "provider": specString("Опциональный ID LDAP-провайдера; пусто — локальная учётка.")}, "login", "password")
	models["TOTPLogin"] = specBody(specObject{"challenge": specString("Одноразовый challenge предыдущего входа; TTL 5 минут."), "code": specString("6 цифр TOTP либо одноразовый recovery code.")}, "challenge", "code")
	models["InvitationInput"] = specBody(specObject{"token": specString("Одноразовый токен из fragment ссылки приглашения."), "password": specObject{"type": "string", "format": "password", "writeOnly": true}}, "token", "password")
	models["LoginResult"] = specBody(specObject{"authenticated": specBool("true — сессия создана; при незавершённых требованиях доступ ограничен регистрацией факторов."), "mfa_required": specBool("Требуется регистрация факторов."), "totp_required": specBool("Для завершения входа требуется TOTP."), "passkey_required": specBool("Требуется passkey."), "challenge": specString("Передайте /auth/totp; отсутствует при завершённом входе.")})
	models["LoginName"] = specBody(specObject{"login": specString("Login для passkey-входа.")}, "login")
	models["TOTPCode"] = specBody(specObject{"code": specObject{"type": "string", "pattern": "^[0-9]{6}$", "example": "123456"}}, "code")
	models["TOTPEnrollment"] = specBody(specObject{"secret": specString("Показывается владельцу при регистрации. Не логировать."), "uri": specString("otpauth URI для локального QR-кода; не передавать внешним QR-сервисам.")}, "secret", "uri")
	models["FactorRegistered"] = specBody(specObject{"ok": specBool("Фактор подключён."), "recovery_codes": specArray(specString("Одноразовый резервный код. Сохраните офлайн; прежние коды могут быть отозваны."))}, "ok", "recovery_codes")
	models["WebAuthnOptions"] = specBody(specObject{"publicKey": specObject{"type": "object", "additionalProperties": true, "description": "PublicKeyCredentialCreationOptions / PublicKeyCredentialRequestOptions по WebAuthn. Challenge кодируется base64url; ответ передавайте browser WebAuthn SDK."}}, "publicKey")
	models["WebAuthnCredential"] = specBody(specObject{"id": specString("Credential ID base64url."), "rawId": specString("Raw ID base64url."), "type": specEnum("Тип", "public-key"), "response": specObject{"type": "object", "additionalProperties": true, "description": "attestationObject/clientDataJSON либо authenticatorData/signature/userHandle (может быть null) из WebAuthn SDK."}, "clientExtensionResults": specObject{"type": "object", "additionalProperties": true}, "authenticatorAttachment": specString("platform / cross-platform.")}, "id", "rawId", "type", "response")
	models["MFAPolicyInput"] = specBody(specObject{"policy": specEnum("Минимум администратора либо личное усиление.", "none", "any", "totp", "passkey", "both")}, "policy")
	props := models["User"].(specObject)["properties"].(specObject)
	input := specObject{}
	for _, key := range []string{"login", "display_name", "kind", "uid", "gid", "home", "shell", "gecos", "require_mfa", "require_sk", "mfa_policy", "sync_to_nodes"} {
		input[key] = props[key]
	}
	models["UserCreate"] = specBody(input, "login")
	update := specObject{}
	for k, v := range input {
		update[k] = v
	}
	update["maintenance"] = specBool("POSIX migration: только после подтверждённого отключения на всех нодах.")
	models["UserUpdate"] = specBody(update, "login", "uid", "gid", "home", "shell")
	models["UserCreated"] = specBody(specObject{"user": ref("User"), "operation_id": specUUID("Изменение."), "invitation_url": specString("Для human ссылка первого входа; service — пустая строка. Токен показан только здесь.")}, "user", "operation_id", "invitation_url")
	models["UserStatusInput"] = specBody(specObject{"status": specEnum("active — активировать; disabled/deleted — отозвать доступ и завершить процессы после доставки.", "active", "disabled", "deleted")}, "status")
	models["UnixPasswordInput"] = specBody(specObject{"password": specObject{"type": "string", "format": "password", "writeOnly": true, "description": "Отдельный UNIX-пароль. Пустая строка отключает его. Непустой допустим только при явном allow_password."}}, "password")
	models["SSHKeyInput"] = specBody(specObject{"name": specString("Имя ключа."), "public_key": specString("OpenSSH public key. SK-only политика отклоняет ключи без sk-.")}, "name", "public_key")
	models["SSHKeyCreated"] = specBody(specObject{"key": ref("SSHKey"), "operation_id": specUUID("Изменение.")}, "key", "operation_id")
	models["RoleInput"] = specBody(models["Role"].(specObject)["properties"].(specObject), "name")
	models["BindingInput"] = specBody(specObject{"user_id": specUUID("Пользователь, для персонального исключения."), "role_id": specUUID("Роль."), "group_id": specString("UUID группы нод или *; дочерние группы наследуют назначение.")}, "user_id", "role_id", "group_id")
	models["GroupBindingInput"] = specBody(specObject{"role_id": specUUID("Роль."), "group_id": specString("UUID области или *.")}, "role_id", "group_id")
	models["NodeGroupInput"] = specBody(specObject{"name": specString("Имя."), "parent_id": specString("UUID родительской группы или пусто для корня.")}, "name")
	models["NodeGroupCreated"] = specBody(specObject{"group": ref("NodeGroup"), "operation_id": specUUID("Изменение.")}, "group", "operation_id")
	models["NodeInput"] = specBody(specObject{"group_id": specUUID("Новая/текущая группа."), "disabled": specBool("Выключает управление нодой; не является отзывом пользователей.")}, "group_id", "disabled")
	models["NodeSSHInput"] = specBody(specObject{"host": specString("DNS или IP для SSH/inventory."), "port": specInt("SSH-порт.", 1, 65535)}, "host", "port")
	ids := specArray(specUUID("UUID."))
	ids["minItems"] = 1
	ids["maxItems"] = 500
	models["MoveNodesInput"] = specBody(specObject{"node_ids": ids, "group_id": specUUID("Целевая группа.")}, "node_ids", "group_id")
	models["PeopleMoveInput"] = specBody(specObject{"users": ids, "source": specString("Исходная группа; пусто — без удаления источника."), "target": specUUID("Целевая группа.")}, "users", "target")
	models["PeopleRemoveInput"] = specBody(specObject{"users": ids}, "users")
	peopleProps := models["PeopleGroup"].(specObject)["properties"].(specObject)
	peopleSummary, peopleInput := specObject{}, specObject{}
	for _, key := range []string{"id", "name", "purpose", "mfa_policy", "require_sk", "member_count", "totp_count", "passkey_count", "missing_factors"} {
		peopleSummary[key] = peopleProps[key]
	}
	for _, key := range []string{"id", "name", "purpose", "mfa_policy", "require_sk", "members"} {
		peopleInput[key] = peopleProps[key]
	}
	peopleInput["members"] = specArray(specUUID("Необязательная замена участников. Отсутствие сохраняет членство; используйте отдельные операции перемещения для больших групп."))
	models["PeopleGroupSummary"] = specBody(peopleSummary, "id", "name", "purpose", "mfa_policy", "require_sk", "member_count", "totp_count", "passkey_count", "missing_factors")
	models["PeopleGroupInput"] = specBody(peopleInput, "name", "mfa_policy")
	models["UnixMembersInput"] = specBody(specObject{"add": specArray(specUUID("Добавить дополнительное членство.")), "remove": specArray(specUUID("Удалить дополнительное членство; primary GID отдельно."))})
	models["UnixGroupInput"] = specBody(specObject{"id": specString("UUID для изменения; пусто — создать."), "name": specString("POSIX-имя группы."), "gid": specInt("0 вычисляет GID при создании; после создания идентичность неизменяема.", 0, 2147483646), "members": specArray(specUUID("Необязательная замена списка дополнительных участников; отсутствие сохраняет членство."))}, "name")
	models["UnixGroupSummary"] = specBody(specObject{"id": specUUID("Группа."), "name": specString("cn."), "gid": specInt("gidNumber.", 10000, 2147483646), "member_count": specInt("Число дополнительных участников.", 0, 2147483646), "primary_count": specInt("Число primary GID участников.", 0, 2147483646)}, "id", "name", "gid", "member_count", "primary_count")
	models["UnixMembership"] = specBody(specObject{"id": specUUID("Группа."), "name": specString("cn."), "gid": specInt("gidNumber.", 10000, 2147483646), "primary": specBool("Основная группа."), "supplementary": specBool("Дополнительная группа.")}, "id", "name", "gid", "primary", "supplementary")
	models["UnixAssignmentSummary"] = specObject{"allOf": []any{ref("UnixAssignment"), specObject{"type": "object", "properties": specObject{"unix_group_name": specString("Имя UNIX-группы."), "group_name": specString("Имя группы нод."), "role_name": specString("Роль.")}}}}
	models["JoinTokenInput"] = specBody(specObject{"name": specString("Опциональное имя."), "group_id": specUUID("Группа новых нод."), "max_uses": specInt("0 — без лимита.", 0, 1000000000), "ttl_seconds": specInt("Независимый TTL, например 31536000 = 365d.", 60, 315360000)}, "group_id", "max_uses", "ttl_seconds")
	models["JoinTokenUpdate"] = specBody(specObject{"max_uses": specInt("0 — без лимита; не менее уже использованного количества.", 0, 1000000000), "expires_at": specTime("Новый срок действия.")}, "max_uses", "expires_at")
	models["TokenSecret"] = specBody(specObject{"token": specString("Секрет присоединения показывается один раз. Не логировать.")}, "token")
	models["TokenIssued"] = specBody(specObject{"token": ref("Token"), "secret": specString("Bearer секрет показывается один раз.")}, "token", "secret")
	models["TokenInput"] = specBody(specObject{"name": specString("Имя."), "user_id": specString("Опциональный владелец service; требуется tokens.manage. Иначе текущий пользователь."), "audiences": specArray(specEnum("Назначение", "api", "mcp")), "scopes": specArray(specString("Разрешения RBAC / self / *.")), "groups": specArray(specString("UUID / *.")), "expires_at": specTime("Конечный срок действия.")}, "name", "audiences", "scopes", "expires_at")
	models["IncidentsInput"] = specBody(specObject{"ids": ids}, "ids")
	models["RecoveryToken"] = specBody(specObject{"token": specString("Одноразовый токен восстановления сертификата."), "expires_in": specInt("TTL в секундах.", 600, 600)}, "token", "expires_in")
	models["AgentJoin"] = specBody(specObject{"name": specString("Имя ноды."), "token": specString("Join secret."), "csr": specObject{"type": "string", "format": "byte", "description": "PEM CSR в base64 (JSON []byte). Приватный ключ остаётся на ноде."}, "bootstrap_nonce": specString("Случайный nonce агента для привязки первого подписанного состояния.")}, "name", "token", "csr", "bootstrap_nonce")
	models["AgentRecover"] = specBody(specObject{"node_id": specUUID("Нода."), "token": specString("Одноразовый recovery secret."), "csr": specObject{"type": "string", "format": "byte"}}, "node_id", "token", "csr")
	models["AgentCertificate"] = specBody(specObject{"node_id": specUUID("Нода."), "certificate": specObject{"type": "string", "format": "byte", "description": "PEM-сертификат в base64. Далее mTLS gRPC; это REST только enrollment/recovery."}}, "node_id", "certificate")
	models["Me"] = specBody(specObject{"user": ref("User"), "principal": ref("Principal"), "factor_state": ref("FactorState"), "permissions": specArray(specString("Доступные имена разрешений, не эффективные права.")), "require_sk": specBool("Эффективная SK-only политика."), "key_ttl_seconds": specInt("TTL новых ключей.", 60, 31536000), "telegram_enabled": specBool("Telegram настроен."), "mattermost_enabled": specBool("Mattermost настроен."), "swagger_enabled": specBool("Swagger разрешён конфигурацией и runtime."), "mcp_enabled": specBool("MCP разрешён.")})
	models["Factors"] = specBody(specObject{"passkeys": specArray(ref("Passkey")), "totp_enabled": specBool("TOTP подключён."), "required": specArray(specString("Эффективные требования.")), "administrator_required": specArray(specString("Администраторский минимум.")), "personal_policy": specString("Личное усиление."), "can_remove_totp": specBool("Разрешено отвязать без нарушения политики либо административный сброс."), "can_remove_passkey": specBool("Можно отвязать passkey.")})
	models["Summary"] = specBody(specObject{"nodes": specInt("Все видимые ноды.", 0, 2147483646), "healthy": specInt("Синхронизированы.", 0, 2147483646), "warning": specInt("Нарушение синхронизации/связи.", 0, 2147483646), "offline": specInt("Offline / отключены.", 0, 2147483646), "pending": specInt("Ожидают применения.", 0, 2147483646), "incidents": specInt("Активные инциденты.", 0, 2147483646)})
	models["SyncTarget"] = specBody(specObject{"node_id": specUUID("Нода."), "name": specString("Имя ноды."), "group_id": specUUID("Группа."), "status": specEnum("Подтверждение ноды.", "pending", "applied", "failed"), "error": specString("Причина отказа; включая незавершённое прекращение процессов."), "revision": specInt("Внутренняя ревизия.", 0, 2147483646), "updated_at": specTime("Обновление.")})
	models["UserSync"] = specObject{"type": "object", "additionalProperties": true, "description": "Состояние UNIX-профиля на ноде. Отсутствие applied не является подтверждением отзыва.", "properties": specObject{"node_id": specUUID("Нода."), "name": specString("Имя."), "status": specString("Статус."), "error": specString("Ошибка."), "revision": specInt("Ревизия.", 0, 2147483646)}}
	models["AuditEvent"] = specBody(specObject{"id": specInt("Монотонный ID.", 1, 2147483646), "actor_id": specString("Инициатор."), "channel": specString("api / mcp / system."), "action": specString("Действие."), "resource_id": specString("Ресурс."), "created_at": specTime("Время.")})
	models["SecurityEvent"] = specBody(specObject{"id": specString("ID события."), "node_id": specUUID("Нода."), "node_name": specString("Имя ноды."), "login": specString("UNIX-login."), "address": specString("Источник."), "kind": specString("Тип."), "severity": specString("Уровень."), "observed_at": specTime("Время на ноде.")})
	models["IntegrationStatus"] = specBody(specObject{"provider": specString("Провайдер."), "phase": specString("Состояние синхронизации каталога."), "error": specString("Ошибка."), "last_attempt": specString("Время последней попытки."), "last_success": specString("Последний успех или пусто.")})
	models["NotificationChannel"] = specBody(specObject{"id": specUUID("Канал."), "provider": specString("telegram / mattermost."), "enabled": specBool("Разрешён."), "severity": specString("Минимальная важность.")})
	models["Provider"] = specBody(specObject{"id": specString("ID из конфигурации."), "type": specEnum("Тип", "oidc", "ldap")}, "id", "type")
	models["IdentityInput"] = specBody(specObject{"provider": specString("Настроенный OIDC provider ID."), "subject": specString("sub у провайдера."), "user_id": specUUID("Пользователь Heimdall.")}, "provider", "subject", "user_id")
	models["OAuthURL"] = specBody(specObject{"url": specString("URL для перехода в провайдер; далее browser redirect callback.")}, "url")
	models["InventoryHostVars"] = specBody(specObject{"ansible_host": specString("Host."), "ansible_port": specInt("Port.", 1, 65535), "ansible_user": specString("UNIX-login."), "heimdall_node_id": specUUID("Нода."), "heimdall_node_name": specString("Имя ноды."), "heimdall_group_id": specUUID("Группа.")})
	models["InventoryGroup"] = specBody(specObject{"hosts": specArray(specString("n_UUID без дефисов.")), "children": specArray(specString("g_UUID без дефисов.")), "vars": specObject{"type": "object", "additionalProperties": true}})
	models["Inventory"] = specObject{"type": "object", "description": "Ansible --list. Полный RBAC-ограниченный inventory по токену; исключение из пагинации для протокола Ansible.", "properties": specObject{"_meta": specBody(specObject{"hostvars": specObject{"type": "object", "additionalProperties": ref("InventoryHostVars")}}, "hostvars"), "all": ref("InventoryGroup"), "ungrouped": ref("InventoryGroup")}, "additionalProperties": ref("InventoryGroup")}
	models["Health"] = specBody(specObject{"status": specString("alive / ready.")})
	return models
}
