(function () {
    function getCookie(name) {
        return document.cookie
            .split('; ')
            .find((row) => row.startsWith(name + '='))
            ?.split('=')[1] || '';
    }

    const lang = decodeURIComponent(getCookie('panel_lang') || 'ru');

    const dict = {
        'Панель управления': 'Dashboard',
        'Дашборд': 'Dashboard',
        'Дашборд сервера': 'Server dashboard',
        'Клиенты': 'Clients',
        'Журнал': 'Events',
        'Журнал событий': 'Event log',
        'Настройки': 'Settings',
        'Смена пароля': 'Change password',
        'Настройки VPN': 'VPN settings',
        'Каскад': 'Cascade',
        'Каскад Amnezia': 'Amnezia cascade',
        'Настройки панели': 'Panel settings',
        'API Документация': 'API documentation',
        'API': 'API',
        'Диагностика': 'Diagnostics',
        'Проверить': 'Check',
        'Проверить конфиг': 'Check config',
        'Выйти': 'Log out',
        'Пароль': 'Password',
        'Администратор': 'Administrator',
        'Главный admin': 'Main admin',
        'Сохранить': 'Save',
        'Сохранить Telegram': 'Save Telegram',
        'Отмена': 'Cancel',
        'Закрыть': 'Close',
        'Обновить': 'Refresh',
        'Включить': 'Enable',
        'Отключить': 'Disable',
        'Удалить': 'Delete',
        'Продлить': 'Extend',
        'Дней': 'Days',
        'Поиск': 'Search',
        'Копировать': 'Copy',
        'Скачать': 'Download',
        'Загрузить и восстановить': 'Upload and restore',
        'Создать': 'Create',
        'Создать ключ': 'Create key',
        'Создать клиента': 'Create client',
        'Новый клиент': 'New client',
        'Назад': 'Back',
        'Дальше': 'Next',
        'Новый ключ': 'New key',
        'Клиенты не найдены.': 'No clients found.',
        'Активен': 'Active',
        'Запущен': 'Running',
        'Остановлен': 'Stopped',
        'Включен': 'Enabled',
        'Выключен': 'Disabled',
        'Истек срок': 'Expired',
        'Лимит исчерпан': 'Limit reached',
        'Безлимит': 'Unlimited',
        'Ограничение не задано': 'No limit set',
        'Онлайн': 'Online',
        'Не подключен': 'Not connected',
        'Конфиг': 'Config',
        'Ключ': 'Key',
        'Клиент': 'Client',
        'Внутренний IP': 'Internal IP',
        'Действует до': 'Valid until',
        'Подключение': 'Connection',
        'Действия': 'Actions',
        'Тип ключа': 'Key type',
        'Состояние клиента': 'Client status',
        'Проверка клиента': 'Client check',
        'Клиент найден в базе': 'Client exists in database',
        'Peer есть на сервере': 'Peer exists on server',
        'Последний handshake': 'Latest handshake',
        'Трафик на сервере': 'Server traffic',
        'Локальный': 'Local',
        'Лимит / трафик': 'Limit / traffic',
        'Управление клиентами VPN': 'VPN client management',
        'Добавить нового клиента AmneziaWG': 'Add a new AmneziaWG client',
        'Имя клиента / устройство': 'Client name / device',
        'Где создать ключ': 'Where to create the key',
        'Обычная Amnezia на этом сервере': 'Regular Amnezia on this server',
        'Дней действия': 'Valid days',
        'Лимит трафика (ГБ, 0 = безлимит)': 'Traffic limit (GB, 0 = unlimited)',
        'Активные VPN-ключи': 'Active VPN keys',
        'Продлить на 30 дней': 'Extend by 30 days',
        '+30 дней': '+30 days',
        'Удалить выбранных клиентов?': 'Delete selected clients?',
        'Удалить этого клиента?': 'Delete this client?',
        'Поиск по имени или IP...': 'Search by name or IP...',

        'Полный туннель': 'Full tunnel',
        'Раздельный': 'Split tunnel',
        'Раздельное туннелирование': 'Split tunneling',
        'Список маршрутов и доменов': 'Routes and domains list',
        'Конфигурация': 'Configuration',
        'Конфигурация ключа': 'Client configuration',
        'Конфигурация AmneziaWG:': 'AmneziaWG configuration:',
        'Конфигурация Amnezia 1 / Legacy:': 'Amnezia 1 / Legacy configuration:',
        'Конфигурация Amnezia 2.0:': 'Amnezia 2.0 configuration:',
        'QR-коды для AmneziaVPN': 'QR codes for AmneziaVPN',
        'Нажми показать, затем сканируй части по кругу.': 'Click show, then scan the parts in rotation.',
        'Сканируй все части одной версии по порядку.': 'Scan all parts of one version in order.',
        'Показать QR': 'Show QR',
        'Скрыть QR': 'Hide QR',
        'QR недоступен': 'QR unavailable',
        'Загрузка...': 'Loading...',
        'Копировать конфиг': 'Copy config',
        'Скачать .conf': 'Download .conf',
        'Скачать Amnezia 2.0': 'Download Amnezia 2.0',
        'Скачать Legacy': 'Download Legacy',
        'Ссылка для импорта в приложение:': 'App import link:',
        'Импорт': 'Import',
        'Не удалось сгенерировать ссылку': 'Could not generate link',

        'Внешний IP сервера (Endpoint)': 'Server public IP (Endpoint)',
        'Параметры AmneziaWG': 'AmneziaWG parameters',
        'Редактировать конфигурацию подключения': 'Edit connection configuration',
        'UDP-порт Amnezia 2.0': 'Amnezia 2.0 UDP port',
        'UDP-порт Legacy': 'Legacy UDP port',
        'DNS для клиентов': 'Client DNS',
        'Сетевые настройки': 'Network settings',
        'Маскировка AmneziaWG': 'AmneziaWG masking',
        'Эти параметры должны совпадать на сервере и в ключах клиентов.': 'These parameters must match on the server and in client keys.',
        'Legacy использует свои значения маскировки. S3/S4 здесь не показываются, потому что конфиг Amnezia 1 не должен их содержать.': 'Legacy uses its own masking values. S3/S4 are not shown here because Amnezia 1 configs must not include them.',
        'Все строки из этого списка пойдут через VPN в split-ключах. Можно писать CIDR, одиночные IP или домены. Домены сервер преобразует в IP при генерации ключа.': 'All entries in this list go through VPN in split keys. You can enter CIDR ranges, single IPs, or domains. The server resolves domains to IPs when generating a key.',
        'Список маршрутов и доменов': 'Routes and domains list',
        'Сохранить и применить': 'Save and apply',
        'Готово.': 'Done.',
        'Ошибка:': 'Error:',
        'Ошибка': 'Error',
        'Внимание.': 'Warning.',
        'Настройки сохранены, конфигурация AmneziaWG обновлена.': 'Settings saved, AmneziaWG configuration updated.',
        'Настройки Telegram сохранены.': 'Telegram settings saved.',
        'Используется стандартный пароль admin/admin.': 'The default admin/admin password is still in use.',
        'Сменить сейчас': 'Change now',

        'Доступ к веб-панели': 'Web panel access',
        'Порт панели': 'Panel port',
        'Домен панели': 'Panel domain',
        'Секретный веб-путь': 'Secret web path',
        'Тема панели': 'Panel theme',
        'Светлая': 'Light',
        'Тёмная': 'Dark',
        'Язык панели': 'Panel language',
        'Уведомления админу': 'Admin notifications',
        'Отправлять события в Telegram': 'Send events to Telegram',
        'Токен бота': 'Bot token',
        'Chat ID администратора': 'Admin chat ID',
        'Скачать бэкап': 'Download backup',
        'Только база': 'Database only',
        'Только настройки': 'Settings only',
        'Статус безопасности': 'Security status',
        'Обновление панели': 'Panel update',
        'Web update выключен': 'Web update disabled',
        'Web update включен': 'Web update enabled',
        'Версия:': 'Version:',
        'Результат проверки': 'Check result',
        'Проверка...': 'Checking...',
        'Не удалось выполнить проверку': 'Could not run check',
        'После скана дождись следующей части': 'After scanning, wait for the next part',
        'Последний QR этой версии': 'Last QR for this version',
        'Amnezia 1 / Legacy QR': 'Amnezia 1 / Legacy QR',
        'Amnezia 2.0 QR': 'Amnezia 2.0 QR',
        'Сейчас панель доступна по адресу:': 'The panel is currently available at:',
        'После настройки DNS и прокси домен можно будет использовать как': 'After DNS and proxy setup, the domain can be used as',

        'Настройки безопасности': 'Security settings',
        'Текущий пароль': 'Current password',
        'Новый пароль': 'New password',
        'Повторите новый пароль': 'Repeat new password',
        'Изменить пароль': 'Change password',

        'Документация API для Telegram-бота': 'API documentation for Telegram bot',
        'Эндпоинты API': 'API endpoints',
        'Вариант А: Статический API-токен (Рекомендуется)': 'Option A: Static API token (recommended)',
        'Пример POST-запроса на получение токена:': 'Example POST request to get a token:',
        'Запрос на создание клиента (на 30 дней, без лимита трафика):': 'Request to create a client (30 days, no traffic limit):',

        'Клиенты и подключения': 'Clients and connections',
        'Панель': 'Panel',
        'Резервные копии': 'Backups',
        'Состояние VPN-протоколов': 'VPN protocol status',
        'Топ клиентов по трафику': 'Top clients by traffic',
        'Все клиенты': 'All clients',
        'Всего': 'Total',
        'Пока нет трафика по клиентам': 'No client traffic yet',
        'Общий объем трафика': 'Total traffic',
        'Скорость VPN-интерфейсов': 'VPN interface speed',
        'Объем на интерфейсах': 'Interface traffic',
        'IP-адреса сервера': 'Server IP addresses',
        'Публичный IP': 'Public IP',
        'VPN-интерфейсы': 'VPN interfaces',
        'Нажмите, чтобы показать IP': 'Click to show IP',
        'Бэкап восстановлен. Конфигурация VPN пересобрана.': 'Backup restored. VPN configuration rebuilt.',
        'Не удалось восстановить бэкап. Проверьте, что загружен архив Blitz Panel.': 'Could not restore backup. Check that a Blitz Panel archive was uploaded.',
        'Восстановить панель из выбранного бэкапа? Текущая база будет сохранена аварийной копией.': 'Restore the panel from the selected backup? The current database will be saved as an emergency copy.',
        'В архив входят база клиентов, настройки панели и конфиги VPN. Перед восстановлением текущая база сохраняется рядом как аварийная копия.': 'The archive contains the client database, panel settings, and VPN configs. Before restore, the current database is saved nearby as an emergency copy.',
        'ЦП:': 'CPU:',
        'ОЗУ:': 'RAM:',
        'Файл подкачки:': 'Swap:',
        'Диск:': 'Disk:',
        'Отправлено': 'Sent',
        'Получено': 'Received',
        'Скорость отправки': 'Upload speed',
        'Скорость загрузки': 'Download speed',
        'Всего отправлено': 'Total sent',
        'Всего получено': 'Total received',
        'Отправлено peer-ами': 'Sent by peers',
        'Получено peer-ами': 'Received by peers',
        'Отправка': 'Upload',
        'Загрузка': 'Download',

        'Каскад на целевом сервере': 'Cascade on target server',
        'API-токен целевой панели': 'Target panel API token',
        'Отдельный UDP-каскад на другой Amnezia-сервер': 'Separate UDP cascade to another Amnezia server',
        'IP целевого Amnezia-сервера': 'Target Amnezia server IP',
        'Входящий порт каскада 2.0': 'Incoming 2.0 cascade port',
        'Порт 2.0 на целевом сервере': '2.0 port on target server',
        'Пробрасывать Legacy-интерфейс': 'Forward Legacy interface',
        'Входящий порт каскада Legacy': 'Incoming Legacy cascade port',
        'Порт Legacy на целевом сервере': 'Legacy port on target server',
        'Создание клиентов на целевой панели': 'Create clients on target panel',
        'URL целевой Blitz Panel': 'Target Blitz Panel URL',
        'Включить каскад': 'Enable cascade',
        'Отключить каскад': 'Disable cascade',
        'Активные правила Blitz Cascade': 'Active Blitz Cascade rules',
        'Активных правил каскада сейчас нет.': 'There are no active cascade rules right now.',
        'Для каскада включите правила и укажите URL/API-токен целевой панели.': 'For cascade, enable rules and set the target panel URL/API token.'
    };

    const patterns = [
        [/^Конфигурация VPN:\s*(.+)$/u, 'VPN configuration: $1'],
        [/^Создан:\s*(.+)$/u, 'Created: $1'],
        [/^Истек срок:\s*(.+)$/u, 'Expired: $1'],
        [/^Клиентов:\s*(.+)$/u, 'Clients: $1'],
        [/^Активных:\s*(.+)$/u, 'Active: $1'],
        [/^Онлайн сейчас:\s*(.+)$/u, 'Online now: $1'],
        [/^Peer-ов на сервере:\s*(.+)$/u, 'Server peers: $1'],
        [/^Активных ключей:\s*(.+)$/u, 'Active keys: $1'],
        [/^Просрочено:\s*(.+)$/u, 'Expired: $1'],
        [/^Порт 2\.0:\s*(.+)$/u, '2.0 port: $1'],
        [/^Порт Legacy:\s*(.+)$/u, 'Legacy port: $1'],
        [/^Все строки из этого списка пойдут через VPN в split-ключах\..*Сейчас получается маршрутов:\s*(\d+)\.$/u, 'All entries in this list go through VPN in split keys. You can enter CIDR ranges, single IPs, or domains. The server resolves domains to IPs when generating a key. Current routes: $1.'],
        [/^QR\s+(\d+)\/(\d+)$/u, 'QR $1/$2'],
        [/^(\d+)\s*сек$/u, '$1 sec'],
        [/^(\d+)\s*сек\.$/u, '$1 sec.']
    ];

    function translate(text) {
        const normalized = String(text || '').replace(/\s+/g, ' ').trim();
        if (!normalized) return text;
        if (dict[normalized]) return dict[normalized];
        for (const [pattern, replacement] of patterns) {
            if (pattern.test(normalized)) {
                return normalized.replace(pattern, replacement);
            }
        }
        return text;
    }

    if (lang !== 'en') {
        window.panelT = (text) => text;
        return;
    }

    window.panelT = translate;

    const skipTags = ['SCRIPT', 'STYLE', 'TEXTAREA', 'CODE', 'PRE'];
    const attrs = ['title', 'placeholder', 'aria-label'];

    function translateTextNode(node) {
        const value = node.nodeValue;
        const trimmed = value.trim();
        const translated = translate(trimmed);
        if (!trimmed || translated === trimmed) return;
        node.nodeValue = value.replace(trimmed, translated);
    }

    function translateElementAttrs(element) {
        attrs.forEach((attr) => {
            if (!element.hasAttribute(attr)) return;
            const value = element.getAttribute(attr);
            const translated = translate(value);
            if (translated !== value) element.setAttribute(attr, translated);
        });

        if (['BUTTON', 'INPUT'].includes(element.tagName) && element.hasAttribute('value')) {
            const value = element.getAttribute('value');
            const translated = translate(value);
            if (translated !== value) element.setAttribute('value', translated);
        }
    }

    function walk(root) {
        if (!root) return;

        if (root.nodeType === Node.ELEMENT_NODE) {
            if (skipTags.includes(root.tagName)) return;
            translateElementAttrs(root);
            root.querySelectorAll('*').forEach((element) => {
                if (!skipTags.includes(element.tagName)) translateElementAttrs(element);
            });
        }

        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
            acceptNode(node) {
                const parent = node.parentElement;
                if (!parent || skipTags.includes(parent.tagName)) {
                    return NodeFilter.FILTER_REJECT;
                }
                return NodeFilter.FILTER_ACCEPT;
            }
        });

        let node;
        while ((node = walker.nextNode())) {
            translateTextNode(node);
        }
    }

    function translateTitle() {
        document.title = document.title
            .replace('Дашборд', 'Dashboard')
            .replace('Клиенты', 'Clients')
            .replace('Журнал', 'Events')
            .replace('Диагностика', 'Diagnostics')
            .replace('Настройки VPN', 'VPN settings')
            .replace('Настройки панели', 'Panel settings')
            .replace('Каскад Amnezia', 'Amnezia cascade')
            .replace('API Документация', 'API documentation');
    }

    function run() {
        translateTitle();
        walk(document.body);

        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.TEXT_NODE) {
                        translateTextNode(node);
                    } else if (node.nodeType === Node.ELEMENT_NODE) {
                        walk(node);
                    }
                });

                if (mutation.type === 'characterData') {
                    translateTextNode(mutation.target);
                }

                if (mutation.type === 'attributes') {
                    translateElementAttrs(mutation.target);
                }
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            characterData: true,
            attributes: true,
            attributeFilter: attrs
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', run);
    } else {
        run();
    }
})();
