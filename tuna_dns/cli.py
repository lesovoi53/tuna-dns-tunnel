"""Russian console interface for the standalone DNS tunnel."""
import argparse
import copy
import getpass
import json
import re
from pathlib import Path
import shutil
import subprocess
import sys

from . import config, exports, profiles, diagnostics

VERSION = '0.1.0'
SOURCE = Path(__file__).resolve().parents[1]
CONFIG = Path('/etc/tuna-dns-tunnel/server_config.toml')
PRESETS = {1: 'Жёсткая цензура', 2: 'Стандартный', 3: 'Мобильный / скоростной'}


def ask(label, default=None):
    value = input(f'{label}' + (f' [{default}]' if default is not None else '') + ': ').strip()
    return value if value or default is None else str(default)


def yes(label):
    return ask(label + ' (да/нет)', 'нет').lower() in ('да', 'yes')


def summary(settings):
    route = settings['route']
    return '\n'.join((f"  Подключение:  {settings['name']}",
        f"  Домены:       {', '.join(settings['domains'])}",
        f"  Адрес:        {settings['listen_host']}:{settings['port']} / UDP",
        f"  Шифрование:   {config.METHODS[settings['encryption_method']]}",
        '  Ключ:         ********',
        '  Выход:        ' + ('Direct' if route['mode'] == 'direct' else f"SOCKS5 · {route['host']}:{route['port']}"),
        '  SOCKS5 auth:  ' + ('Да · пароль скрыт' if route['username'] else 'Нет')))


def journal(settings):
    result = subprocess.run(['journalctl', '-u', 'tuna-dns-tunnel.service', '-n', '60', '--no-pager'],
                            check=True, capture_output=True, text=True)
    text = re.sub(r'(?im)^.*Active Encryption Key:.*$', '[ключ скрыт]', result.stdout)
    for secret in (settings['key'], settings['route']['password']):
        if secret:
            text = text.replace(secret, '********')
    print(text)


def header(state):
    print('\n╔════════════════════════════════════════════════════╗')
    print('║                  TUNA DNS Tunnel                   ║')
    print('╚════════════════════════════════════════════════════╝')
    if not state['installed']:
        print('\n  DNS-туннель не установлен\n\n  [1] Установить DNS-туннель\n  [0] Выход')
        return
    print('\n  Состояние:    ' + ('● Работает' if state['active'] else '○ Остановлен'))
    print(summary(state['settings']))
    print('''
  [1] Ссылки подключения / QR-код
  [2] Домены этого сервера
  [3] Шифрование и ключ
  [4] Выход в интернет — Direct / SOCKS5
  [5] Параметры экспортируемых профилей
  [6] Имя подключения и порт

  [7] Управление службой
  [8] Диагностика и журнал
  [9] Обновление и резервные копии
  [0] Выход''')


def route_editor(settings):
    draft = copy.deepcopy(settings)
    while True:
        print('\nВЫХОД В ИНТЕРНЕТ\n' + summary(draft))
        print('''[1] Напрямую — Direct
[2] Через SOCKS5
[3] Изменить адрес и порт прокси
[4] Настроить авторизацию SOCKS5
[5] Проверить соединение через выбранный маршрут
При недоступности SOCKS5 перехода на Direct нет.
[S] Сохранить черновик   [0] Отменить''')
        choice = ask('Выбор').lower()
        if choice == '0':
            return None
        if choice == 's':
            return config.validate(draft)
        if choice in ('1', '2'):
            draft['route']['mode'] = 'direct' if choice == '1' else 'socks5'
        elif choice == '3':
            draft['route']['host'] = ask('Адрес прокси', draft['route']['host'])
            draft['route']['port'] = int(ask('Порт прокси', draft['route']['port']))
        elif choice == '4':
            user = ask('Логин (пусто — без авторизации)')
            draft['route'].update(username=user, password=getpass.getpass('Пароль: ') if user else '')
        elif choice == '5':
            config.validate(draft)
            print('HTTP', diagnostics.probe(draft['route']))


def wizard():
    draft = config.defaults()
    draft['domains'] = ask('Домены DNS-зон через пробел').split()
    draft['listen_host'] = ask('IPv4-адрес прослушивания', draft['listen_host'])
    draft['port'] = int(ask('UDP-порт', 53))
    draft['name'] = ask('Имя подключения', draft['name'])
    for i, name in enumerate(config.METHODS):
        print(f'[{i}] {name}')
    draft['encryption_method'] = int(ask('Метод шифрования', 5))
    draft['key'] = config.generate_key(draft['encryption_method'])
    if yes('Ввести собственный ключ вместо случайного'):
        draft['key'] = getpass.getpass('Ключ: ')
    draft = config.validate(draft)
    if yes('Настроить SOCKS5 вместо Direct'):
        draft['route']['mode'] = 'socks5'
        draft = route_editor(draft)
        if draft is None:
            return None
    print('\nПРОВЕРЬТЕ НАСТРОЙКИ\n' + summary(draft))
    return draft if yes('Установить с этими настройками') else None


def domains_editor(settings):
    draft = copy.deepcopy(settings)
    while True:
        print('\nДОМЕНЫ ЭТОГО СЕРВЕРА')
        for i, domain in enumerate(draft['domains'], 1):
            print(f'  {i}. {domain}' + (' · Основной' if i == 1 else ''))
        print('[1] Добавить  [2] Удалить  [3] Основной  [4] DNS-записи  [5] Проверить DNS\n[S] Сохранить  [0] Отменить')
        try:
            choice = ask('Выбор').lower()
            if choice == '0':
                return None
            if choice == 's':
                if not draft['domains']:
                    raise ValueError('Добавьте хотя бы один домен перед сохранением. Черновик сохранён в этом меню.')
                return config.validate(draft)
            if choice == '1':
                values = draft['domains'] + [ask('Домен')]
                config.validate_domains(values)
                draft['domains'] = values
            elif choice in ('2', '3'):
                index = int(ask('Номер домена')) - 1
                if not 0 <= index < len(draft['domains']):
                    raise ValueError('Нет такого номера домена.')
                domain = draft['domains'].pop(index)
                if choice == '3':
                    draft['domains'].insert(0, domain)
            elif choice == '4':
                ns = ask('DNS-имя вашего NS-сервера', 'ns1.example.org')
                config.validate_domains([ns])
                print(f'{ns}  A  <публичный IPv4 этого сервера>')
                for domain in draft['domains']:
                    print(f'{domain}  NS  {ns}')
                print('Создайте записи у DNS-провайдера без HTTP-проксирования. Делегирование DNS использует порт 53.')
            elif choice == '5':
                check_dns(draft['domains'])
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            print('Ошибка:', error)


def check_dns(domains):
    if not shutil.which('dig'):
        raise RuntimeError('Для этой проверки установите пакет dnsutils.')
    for domain in domains:
        result = subprocess.run(['dig', '+time=3', '+tries=1', '+short', 'NS', domain], capture_output=True, text=True, timeout=8)
        if result.returncode:
            raise RuntimeError('Не удалось выполнить DNS-проверку.')
        print(domain + ': ' + (result.stdout.strip() or 'NS-запись не найдена через системный резолвер'))
    print('Это проверка DNS-записей; она не заменяет подключение клиента.')


def pick_preset():
    for i, name in PRESETS.items():
        print(f'[{i}] {name}')
    preset = int(ask('Профиль', 1))
    if preset not in PRESETS:
        raise ValueError('Выберите профиль 1–3.')
    return preset


def show_links(settings):
    preset = pick_preset()
    print('[1] TUNA — все домены в одной ссылке\n[2] StormDNS — отдельная ссылка на каждый домен')
    choice = ask('Формат', 1)
    if choice not in ('1', '2'):
        return
    links = exports.links(settings, preset, 'tuna' if choice == '1' else 'storm', CONFIG)
    qr = yes('Показать также QR-код')
    for link in links:
        print('\n' + link)
        if qr:
            if shutil.which('qrencode'):
                result = subprocess.run(['qrencode', '-t', 'UTF8'], input=link, text=True)
                if result.returncode:
                    print('QR-код не поместился. Используйте ссылку.')
            else:
                print('QR-код требует пакет qrencode. Ссылка доступна выше.')


def encryption_editor(settings):
    draft = copy.deepcopy(settings)
    for i, name in enumerate(config.METHODS):
        print(f'[{i}] {name}')
    method = int(ask('Метод', draft['encryption_method']))
    length = config.key_length(method)
    if len(draft['key'].encode()) != length:
        if not yes('Текущий ключ несовместим. Сгенерировать новый'):
            return None
        draft['key'] = config.generate_key(method)
    draft['encryption_method'] = method
    print('[1] Оставить ключ  [2] Сгенерировать новый  [3] Ввести ключ')
    choice = ask('Ключ', 1)
    if choice == '2':
        draft['key'] = config.generate_key(method)
    elif choice == '3':
        draft['key'] = getpass.getpass('Ключ: ')
    draft = config.validate(draft)
    print('Смена метода или ключа потребует обновления профилей клиентов.')
    return draft if yes('Сохранить и применить') else None


def services(manager):
    print('[1] Запустить  [2] Остановить  [3] Перезапустить\n[4] Автозапуск: вкл  [5] Автозапуск: выкл\n[6] Удалить программу  [0] Назад')
    choice = ask('Выбор')
    actions = {'1': 'start', '2': 'stop', '3': 'restart', '4': 'enable', '5': 'disable'}
    if choice in actions:
        manager.service(actions[choice])
    elif choice == '6' and yes('Удалить TUNA DNS Tunnel'):
        manager.uninstall(purge=yes('Также удалить настройки и ключ'))


def maintenance(manager):
    print('[1] Обновить из каталога новой версии\n[2] Создать резервную копию\n[3] Восстановить резервную копию\n[0] Назад')
    choice = ask('Выбор')
    if choice == '1':
        from .backend import Manager
        source = Path(ask('Полный путь к распакованной новой версии')).resolve()
        if not (source / 'install.sh').is_file() or not (source / 'tuna_dns/backend.py').is_file():
            raise ValueError('Нужен полный каталог дистрибутива TUNA DNS Tunnel.')
        # Execute the candidate's updater, not the old installed Python modules.
        subprocess.run(['bash', str(source / 'install.sh'), '--update'], check=True)
    elif choice == '2':
        print('Закрытая резервная копия:', manager.backup())
    elif choice == '3':
        path = ask('Полный путь к резервной копии')
        if yes('Восстановить файлы и состояние службы из этой копии'):
            manager.restore(path)


def menu(manager):
    while True:
        try:
            state = manager.status()
            header(state)
            choice = ask('Выбор').lower()
            if choice == '0':
                return
            if not state['installed']:
                if choice == '1':
                    settings = wizard()
                    if settings:
                        manager.install(settings)
                continue
            settings = state['settings']
            draft = None
            if choice == '1':
                show_links(settings)
            elif choice == '2':
                draft = domains_editor(settings)
            elif choice == '3':
                draft = encryption_editor(settings)
            elif choice == '4':
                draft = route_editor(settings)
            elif choice == '5':
                profiles.menu(CONFIG, pick_preset())
            elif choice == '6':
                draft = copy.deepcopy(settings)
                draft['name'] = ask('Имя', settings['name'])
                draft['listen_host'] = ask('IPv4 прослушивания', settings['listen_host'])
                draft['port'] = int(ask('UDP-порт', settings['port']))
                draft = config.validate(draft) if yes('Сохранить и применить') else None
            elif choice == '7':
                services(manager)
                if not manager.status()['installed']:
                    return
            elif choice == '8':
                print('[1] Проверить выход в интернет  [2] Проверить DNS  [3] Журнал службы')
                action = ask('Выбор')
                if action == '1':
                    print('HTTP', diagnostics.probe(settings['route']))
                elif action == '2':
                    check_dns(settings['domains'])
                elif action == '3':
                    journal(settings)
            elif choice == '9':
                maintenance(manager)
            if draft is not None:
                manager.apply(draft)
                print('Настройки сохранены. Активная служба перезапущена; остановленная остаётся остановленной.')
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
            print('Ошибка:', error)


def main(argv=None):
    parser = argparse.ArgumentParser(description='TUNA DNS Tunnel — только DNS-туннель MasterDnsVPN')
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--preview', action='store_true', help='показать макет без обращения к системе')
    sub = parser.add_subparsers(dest='command')
    p = sub.add_parser('install')
    p.add_argument('--settings-file', type=Path, help='закрытый JSON с параметрами для автоматической установки')
    p.add_argument('--archive', type=Path)
    p = sub.add_parser('update'); p.add_argument('--archive', type=Path)
    sub.add_parser('status'); sub.add_parser('backup')
    p = sub.add_parser('restore'); p.add_argument('path')
    p = sub.add_parser('service'); p.add_argument('action', choices=['start', 'stop', 'restart', 'enable', 'disable'])
    p = sub.add_parser('uninstall'); p.add_argument('--purge', action='store_true')
    p = sub.add_parser('export'); p.add_argument('--preset', type=int, choices=[1, 2, 3], default=1); p.add_argument('--format', choices=['tuna', 'storm'], default='tuna')
    args = parser.parse_args(argv)
    if args.preview:
        draft = config.defaults(); draft['domains'] = ['d.example.org', 'd1.example.org']
        header(dict(installed=True, active=True, enabled=True, settings=draft))
        return 0
    from .backend import Manager
    manager = Manager(source=SOURCE)
    try:
        if args.command == 'install':
            settings = json.loads(args.settings_file.read_text(encoding='utf-8')) if args.settings_file else wizard()
            if settings:
                manager.install(settings, archive=args.archive)
                print('TUNA DNS Tunnel установлен. Команда меню: tuna-dns')
        elif args.command == 'update':
            manager.update(archive=args.archive); print('TUNA DNS Tunnel обновлён.')
        elif args.command == 'status':
            state = manager.status(); header(state)
        elif args.command == 'backup':
            print(manager.backup())
        elif args.command == 'restore':
            manager.restore(args.path)
        elif args.command == 'service':
            manager.service(args.action)
        elif args.command == 'uninstall':
            manager.uninstall(purge=args.purge)
        elif args.command == 'export':
            state = manager.status()
            if not state['installed']:
                raise RuntimeError('DNS-туннель не установлен.')
            print('\n'.join(exports.links(state['settings'], args.preset, args.format, CONFIG)))
        else:
            menu(manager)
        return 0
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('Ошибка:', error, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('\nОперация отменена.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
