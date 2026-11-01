# Что проверено перед передачей

Проверки выполнены в Linux-среде. Xcode, Swift compiler и iOS SDK здесь отсутствуют.

## Успешные статические проверки

- Все 9 Swift-файлов, включая XCTest, разобраны грамматикой Swift в tree-sitter: синтаксических ERROR и missing nodes нет. Это проверка синтаксиса, не Swift type checking.
- `Info.plist` и `PrivacyInfo.xcprivacy` разобраны стандартным plist-парсером Python.
- `project.pbxproj` разобран OpenStep-парсером: 52 объекта. Все ссылки на объекты существуют.
- Все 12 локальных ссылок на файлы или каталоги проекта разрешены. Все 8 Swift-файлов приложения включены в Sources build phase.
- Shared scheme и workspace разобраны XML-парсером. Идентификаторы target, имена продуктов и BlueprintName в схеме совпадают с проектом.
- 11 типов в `NSBonjourServices` точно совпадают с 10 типами поиска и одним типом временной проверки доступа.
- Нет entitlements-файла, wildcard Bonjour, чтения sysctl или SOCK_RAW. TCP-список содержит ровно 80, 443, 22, 445 и 62078.
- Каталог Assets: валидный JSON, AppIcon — PNG 1024×1024 RGB без прозрачности.
- Privacy manifest содержит причину CA92.1 для app-only UserDefaults.
- YAML workflow разобран; все его shell-блоки прошли `bash -n`.

## Что не выполнялось

- Компиляция Swift с iOS SDK и линковка Apple frameworks.
- Запуск шести XCTest-методов. Их код включён в проект, но они не объявляются прошедшими.
- Работа Local Network permission prompt, Bonjour и TCP на физическом iPhone.
- Сборка или подпись IPA, запуск GitHub Actions.
- App Review.

Настоящую сборку и XCTest запускает включённый GitHub Actions workflow на macOS либо Xcode. Поведение сетевого разрешения и обнаружения дополнительно требует проверки на физическом устройстве; ручные сценарии приведены в `README_RU.md`.
