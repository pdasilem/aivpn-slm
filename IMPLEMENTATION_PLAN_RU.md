# План реализации AIVPN Admin, UI и клиентов

Документ фиксирует поэтапную реализацию серверного администрирования, метрик, кроссплатформенного клиентского UI и iOS jailbreak-клиента. Каждый этап должен завершаться проверяемым результатом, который можно принять отдельно.

## Текущий статус

- Этапы 1-2: реализованы `aivpn-admin` и тесты базовых admin-операций.
- Этапы 3-4: реализованы `/metrics`, Prometheus target и Grafana provisioning.
- Этап 5: реализован минимальный `aivpn-admin-web`, который вызывает `aivpn-admin --json`; поддержаны list/add/show key/rename/enable/disable/remove, bearer token и Docker Compose service. QR-код пока follow-up.
- Добавлен корневой серверный менеджер `install.sh`: install/update/uninstall, генерация server key/admin token, Docker Compose запуск и firewall/Tailscale diagnostics.
- Этап 6: реализован Avalonia 12 UI shell, mock backend, process backend и pipe backend.
- Этапы 7-8: начата общая основа service/helper через `aivpn-client-contracts` и `aivpn-clientd`; добавлены Generic Host, Windows Service install/uninstall scripts, Inno Setup skeleton и systemd unit. Проверка на реальных Windows/Linux и polkit hardening еще впереди.
- Этапы 9-12: не начаты.

## Принципы

- VPN gateway и протокольную логику не менять без отдельной причины.
- Серверное администрирование вынести в отдельный `aivpn-admin` binary.
- Серверный web UI должен управлять системой через `aivpn-admin`, а не напрямую через внутренности gateway.
- Live-метрики допустимо добавить в сервер как read-only HTTP endpoint, потому что счетчики находятся в памяти gateway.
- Клиентский UI делать кроссплатформенным на Avalonia, включая Windows и Linux desktop. Для Linux учитывать Wayland в Avalonia 12.
- Для роутеров/OpenWrt считать основным интерфейсом CLI/web, а Avalonia использовать как удаленную desktop-админку, если запуск UI на самом устройстве непрактичен.
- iOS-клиент делать только для jailbreak-устройств, без App Store/Apple Developer Program как обязательного требования.

## Этап 1. `aivpn-admin` CLI для управления клиентами

Цель: вынести администрирование клиентов в отдельный binary без запуска VPN gateway.

Работы:
- Добавить workspace crate или отдельный binary `aivpn-admin`.
- Переиспользовать формат `/etc/aivpn/clients.json` и логику `ClientDatabase`.
- Добавить JSON-friendly команды:
  - `aivpn-admin client add --name NAME --server-ip HOST[:PORT] --key-file PATH --clients-db PATH --json`
  - `aivpn-admin client list --clients-db PATH --json`
  - `aivpn-admin client show --id ID --server-ip HOST[:PORT] --key-file PATH --clients-db PATH --json`
  - `aivpn-admin client remove --id ID --clients-db PATH`
  - `aivpn-admin client rename --id ID --name NAME --clients-db PATH`
  - `aivpn-admin client enable --id ID --clients-db PATH`
  - `aivpn-admin client disable --id ID --clients-db PATH`
- Сохранить атомарную запись `clients.json`.
- Добавить человекочитаемый вывод по умолчанию и `--json` для UI.

Проверка:
- `cargo build --release -p aivpn-admin`
- Создать временный `clients.json`, добавить клиента, получить connection key.
- Выполнить `list --json` и проверить валидный JSON через `jq`.
- Переименовать, отключить, включить и удалить клиента.
- Убедиться, что `aivpn-server --list-clients --clients-db <same file>` видит изменения.

Критерий готовности:
- Все базовые операции над клиентами выполняются через `aivpn-admin`.
- Gateway не требуется запускать для управления клиентами.
- Формат базы совместим с текущим сервером.

## Этап 2. Тесты для admin-операций

Цель: зафиксировать совместимость `aivpn-admin` с существующим форматом клиентской базы.

Работы:
- Добавить unit/integration tests для add/list/show/remove/rename/enable/disable.
- Проверить генерацию `aivpn://...` ключа с IP и портом.
- Проверить атомарную запись и отсутствие повреждения JSON при повторных операциях.
- Проверить ошибки: дубликат имени, неизвестный ID, нехватка IP.

Проверка:
- `cargo test -p aivpn-admin`
- `cargo test -p aivpn-server client`

Критерий готовности:
- Тесты покрывают основные команды и ошибки.
- Изменение формата `clients.json` не происходит случайно.

## Этап 3. Метрики `/metrics` в сервере

Цель: довести Prometheus metrics до рабочего read-only endpoint.

Работы:
- Исправить текущий недоделанный metrics handler: либо добавить корректную HTTP-зависимость, либо заменить на `axum`.
- Добавить флаги:
  - `--metrics-listen 127.0.0.1:9090`
  - `--disable-metrics`, если endpoint нужен не всегда.
- Поднять HTTP server параллельно UDP gateway.
- Экспортировать существующие счетчики:
  - sessions total/active
  - packets received/sent
  - bytes received/sent
  - packet/tag processing histograms
  - mask rotations
  - key rotations
  - neural checks/failed
  - DPI attacks detected
- Не добавлять write/admin API в этот endpoint.

Проверка:
- `cargo build --release -p aivpn-server --features metrics`
- Запустить сервер с `--metrics-listen 127.0.0.1:9090`.
- `curl http://127.0.0.1:9090/metrics`
- Проверить наличие строк `aivpn_packets_received_total`, `aivpn_bytes_received_total`, `aivpn_mask_rotations_total`.

Критерий готовности:
- `/metrics` доступен и отдает Prometheus text format.
- Сервер продолжает принимать VPN traffic.
- Endpoint read-only и не содержит admin-действий.

## Этап 4. Prometheus и Grafana provisioning

Цель: сделать мониторинг запускаемым одной командой через Docker Compose.

Работы:
- Исправить `monitoring/prometheus.yml` под реальный адрес metrics endpoint.
- Добавить provisioning datasource для Grafana.
- Добавить dashboard JSON:
  - Overview
  - Traffic
  - Sessions
  - Neural/DPI
  - Rotations
- Обновить `docker-compose.yml` для профиля `monitoring`.
- Добавить README-раздел с запуском мониторинга.

Проверка:
- `docker compose --profile monitoring up -d`
- Открыть Prometheus targets и убедиться, что `aivpn-server` в состоянии `UP`.
- Открыть Grafana и увидеть dashboard без ручного импорта.

Критерий готовности:
- Prometheus scrape работает.
- Grafana открывается с datasource и dashboard из репозитория.

## Этап 5. Server admin-web через `aivpn-admin`

Цель: добавить web UI для Linux-сервера без прямой интеграции с gateway.

Работы:
- Создать отдельный `aivpn-admin-web` сервис.
- Реализовать backend, который вызывает `aivpn-admin --json` и валидирует вывод.
- Реализовать UI:
  - список клиентов
  - добавление клиента
  - просмотр connection key
  - QR-код connection key
  - rename
  - enable/disable
  - remove
  - просмотр статистики из `clients.json`
  - ссылки на Grafana dashboards
- Добавить auth:
  - admin password из env/файла
  - session cookie или token
  - bind по умолчанию на `127.0.0.1`
- Добавить Docker Compose service с mount `./config:/etc/aivpn`.

Проверка:
- Запустить `aivpn-admin-web` локально.
- Через UI добавить клиента и получить QR/key.
- Выполнить `aivpn-admin client list --clients-db ./config/clients.json --json` и увидеть клиента.
- Отключить клиента в UI и проверить, что `enabled=false`.
- Удалить клиента в UI и проверить, что он исчез из `clients.json`.

Критерий готовности:
- Web UI управляет клиентами через `aivpn-admin`.
- VPN gateway не содержит admin write API.
- Все операции воспроизводимы CLI-командами.

## Этап 6. Avalonia UI: общий клиентский shell

Цель: создать кроссплатформенный клиентский UI, пригодный для Windows и Linux desktop.

Работы:
- Создать `aivpn-ui` на Avalonia 12.
- Сделать MVVM-модель профилей:
  - список подключений
  - add/edit/delete
  - выбор активного профиля
  - full tunnel toggle
  - connect/disconnect
  - status
  - traffic counters
  - logs
- Вынести взаимодействие с system helper в интерфейс `IClientService`.
- Добавить mock backend для локальной разработки UI без root/admin прав.
- Поддержать RU/EN локализацию.

Проверка:
- `dotnet build`
- Запустить UI с mock backend на Windows.
- Запустить UI с mock backend на Linux/Wayland.
- Создать, изменить, удалить профиль.
- Переключить статус connect/disconnect в mock mode.

Критерий готовности:
- Один UI-код запускается на Windows и Linux.
- UI не содержит платформенного кода управления TUN/Wintun/routes.
- Профили и состояния отображаются корректно в mock mode.

## Этап 7. Windows service/helper и installer

Цель: сделать продуктовый Windows-клиент без ручного размещения `wintun.dll` рядом с exe.

Работы:
- Создать privileged `AIVPN.Service`.
- Service управляет `aivpn-client.exe`, Wintun, PID, логами и статусом.
- UI общается с service через named pipe.
- Хранить чувствительные данные через DPAPI или Windows Credential Manager.
- Сделать installer, который кладет в `C:\Program Files\AIVPN`:
  - Avalonia UI app
  - Windows service
  - `aivpn-client.exe`
  - `wintun.dll`
  - uninstall assets
- Service устанавливается и запускается installer-ом.
- UI не требует UAC на каждый connect/disconnect.

Проверка:
- Установить fresh package на Windows VM.
- Убедиться, что пользователь не копирует `wintun.dll` вручную.
- Добавить профиль в UI.
- Подключиться и отключиться.
- Перезагрузить Windows и проверить автозапуск service/UI.
- Проверить uninstall.

Критерий готовности:
- Setup.exe устанавливает все зависимости.
- Подключение работает из UI без ручной раскладки файлов.
- Service корректно стартует, останавливается и удаляется.

## Этап 8. Linux desktop helper для Avalonia UI

Цель: подключить тот же Avalonia UI к Linux-клиенту.

Работы:
- Создать `aivpn-clientd` или systemd helper для Linux.
- Helper запускает `aivpn-client` с нужными правами.
- IPC через Unix socket.
- Интегрировать UI с Linux helper через тот же `IClientService` контракт.
- Хранение профилей:
  - Secret Service/libsecret, если доступно
  - encrypted file fallback
- Подготовить packaging:
  - `.deb` или tarball
  - systemd unit
  - polkit rule, если нужен controlled privilege escalation

Проверка:
- Установить package на Linux desktop с Wayland.
- Запустить UI.
- Добавить профиль.
- Подключиться и отключиться.
- Проверить, что helper восстанавливает маршруты после disconnect.
- Проверить работу после reboot.

Критерий готовности:
- Linux UI использует тот же Avalonia app.
- Платформенная часть изолирована в helper/service.
- Full tunnel работает и корректно откатывается.

## Этап 9. OpenWrt/router management

Цель: дать управляемость на роутерах без требования запускать Avalonia на самом роутере.

Работы:
- Собрать/адаптировать `aivpn-admin` для OpenWrt target, если поддерживается toolchain.
- Подготовить lightweight admin mode:
  - CLI-first
  - web UI через отдельный маленький сервис или LuCI plugin
  - удаленное управление из Avalonia desktop app через admin API, если включено
- Документировать ограничения ресурсов и поддерживаемые архитектуры.

Проверка:
- Запустить `aivpn-admin client list --json` на целевом OpenWrt устройстве или эмуляции.
- Добавить/удалить клиента через CLI.
- Если есть web/LuCI UI, повторить add/list/remove через браузер.
- Если есть удаленная Avalonia админка, подключиться к router admin endpoint и выполнить list.

Критерий готовности:
- Роутер управляется без desktop GUI на самом устройстве.
- Avalonia может использоваться как внешний desktop admin client.

## Этап 10. iOS jailbreak proof of concept

Цель: проверить техническую жизнеспособность iOS jailbreak-клиента без Apple Developer Program.

Работы:
- Определить поддерживаемые jailbreak окружения:
  - rootless/rootful
  - версии iOS
  - доступность `utun`/routing APIs
- Вынести mobile core из Android-специфичного JNI в общий Rust core с C ABI.
- Реализовать минимальный daemon:
  - read profile
  - open tunnel interface
  - UDP connect to server
  - route setup/cleanup
  - start/stop/status
- Сделать минимальный UI или CLI wrapper.
- Упаковать в `.deb` для jailbreak package manager.

Проверка:
- Установить package на тестовое jailbreak-устройство.
- Импортировать `aivpn://...` профиль.
- Запустить tunnel.
- Проверить доступ до VPN server и внешний IP/маршрут.
- Остановить tunnel и проверить откат маршрутов.

Критерий готовности:
- На конкретной зафиксированной связке iOS + jailbreak tunnel поднимается и отключается.
- Есть список поддерживаемых и неподдерживаемых окружений.

## Этап 11. iOS jailbreak Avalonia UI evaluation

Цель: определить, можно ли использовать Avalonia UI и на jailbreak iOS target.

Работы:
- Проверить сборку Avalonia UI под нужный iOS/jailbreak target.
- Проверить размер, запуск, доступ к локальному daemon IPC и стабильность.
- Если Avalonia непрактична, зафиксировать fallback:
  - Swift/UIKit или SwiftUI UI
  - тот же локальный daemon API
  - тот же формат профилей/connection key

Проверка:
- Собрать минимальный экран профилей.
- Запустить на jailbreak-устройстве.
- Выполнить `status`, `connect`, `disconnect` через локальный daemon API.

Критерий готовности:
- Принято решение: Avalonia на iOS jailbreak используется или заменяется native UI.
- Решение основано на запуске на реальном устройстве, а не на предположении.

## Этап 12. Документация и релизные сценарии

Цель: привести все новые компоненты к повторяемой установке и проверке.

Работы:
- Обновить README/README_RU:
  - `aivpn-admin`
  - server admin-web
  - metrics/Grafana
  - Avalonia client UI
  - Windows installer
  - Linux package
  - iOS jailbreak status
- Добавить smoke tests:
  - admin CLI smoke
  - metrics smoke
  - Windows service smoke
  - Linux helper smoke
- Добавить release checklist.

Проверка:
- Пройти README с чистого окружения.
- Собрать release artifacts.
- Выполнить smoke tests для поддерживаемых платформ.

Критерий готовности:
- Новый пользователь может поднять серверный admin UI и мониторинг по документации.
- Windows/Linux клиентский UI устанавливается воспроизводимо.
- iOS jailbreak статус честно описан как experimental или supported для конкретных окружений.
