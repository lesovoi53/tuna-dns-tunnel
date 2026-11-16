#!/usr/bin/env python3
"""Local TUI for rc11 groups. Uses the server API; never probes connections."""
import argparse
import base64
import copy
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from tuna_connection_groups import DEFAULTS, FAMILIES, RANGES, Invalid, family_of, validate


def api(base, path, data=None):
    request = urllib.request.Request(base + path, data=json.dumps(data).encode() if data is not None else None,
                                     headers={'Content-Type': 'application/json'}, method='PUT' if data is not None else 'GET')
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        # Never echo an arbitrary response containing URI/token details.
        if error.code == 409:
            raise Invalid('Данные изменились. Обновите список и повторите правку.') from None
        raise Invalid('Сервер отклонил запрос (HTTP %s); изменения не сохранены.' % error.code) from None


def choose(items, label):
    if not items:
        raise Invalid('Список пуст')
    while True:
        for i, item in enumerate(items, 1):
            print('  [%d] %s' % (i, label(item)))
        number = input('Номер (0 — отмена): ').strip()
        if number == '0':
            raise Invalid('Отменено; серверные данные не изменены')
        if number.isdigit() and 1 <= int(number) <= len(items):
            return items[int(number)-1]
        print('Выберите номер из показанного списка.')


def confirm(prompt):
    print(prompt + '\n  [1] Да\n  [0] Нет')
    return input('Выбор: ').strip() in ('1', 'y')


def test_url(kind, current=None):
    if kind == 'URL_TEST':
        choices = ['https://www.gstatic.com/generate_204', 'https://cp.cloudflare.com/generate_204']
        if current and current not in choices:
            choices.append(current)
        return choose(choices, lambda url: url + (' (текущий)' if url == current else ''))
    choices = [
        ('Cloudflare — 1 МиБ', 'https://speed.cloudflare.com/__down?bytes=1048576'),
        ('Cloudflare — 10 МиБ', 'https://speed.cloudflare.com/__down?bytes=10485760'),
    ]
    if current and current not in [url for _, url in choices]:
        choices.append(('Оставить текущий URL', current))
    choices.append(('Свой HTTPS URL', None))
    print('Источник Speedtest: загрузку выполняет клиент после подключения; лимит трафика задаётся отдельно.')
    _, selected = choose(choices, lambda item: item[0] + (' (текущий)' if current and item[1] == current else ''))
    if selected is not None:
        return selected
    while True:
        value = input('HTTPS URL файла Speedtest (0 — отмена): ').strip()
        if value == '0':
            raise Invalid('Создание отменено')
        try:
            parsed = urllib.parse.urlsplit(value)
            if parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment and not any(c.isspace() for c in value):
                return value
        except ValueError:
            pass
        print('Для Speedtest нужен непустой HTTPS URL файла. Группа ещё не сохранена.')


def import_profiles(base, path, state):
    """Copy only explicitly selected user's existing subscription; preserve URIs."""
    user = api(base, path)
    token = user.get('subscription_token') or user.get('token')
    if not token:
        raise Invalid('У пользователя нет токена подписки')
    with urllib.request.urlopen(base + '/sub/' + urllib.parse.quote(token, safe=''), timeout=10) as response:
        payload = response.read(2 * 1024 * 1024 + 1)
    if len(payload) > 2 * 1024 * 1024:
        raise Invalid('Подписка превышает 2 МиБ')
    lines = base64.b64decode(payload, validate=True).decode('utf-8').splitlines()
    count = 0
    for uri in lines:
        try:
            family = family_of(uri)
        except Invalid:
            continue  # DNS and other families unsupported by the rc11 outer group contract.
        if any(p['uri'] == uri for p in state['profiles']):
            continue
        parsed = urllib.parse.urlsplit(uri)
        name = urllib.parse.unquote(parsed.fragment) or '%s %d' % (family, len(state['profiles'])+1)
        state['profiles'].append(dict(id=str(uuid.uuid4()), name=name, uri=uri))
        count += 1
    print('В черновик добавлено профилей: %d. Существующие ссылки не изменены.' % count)


def add_servers(state, family, initial=None):
    """Accept consecutive links without reopening an action menu after each one."""
    selected = list(initial or [])
    available = [p for p in state['profiles'] if family_of(p['uri']) == family]
    print('\nДобавляйте ссылки серверов по одной, нажимая Enter после каждой.')
    print('Пустая строка — закончить список; 0 — отменить. Нужно от 2 до 1000 участников.')
    if available:
        print('Можно выбрать сохранённый профиль: @номер; * — выбрать все показанные.')
        for i, profile in enumerate(available, 1):
            print('  @%d — %s' % (i, profile['name']))
    while True:
        line = input('Ссылка сервера (добавлено %d): ' % len(selected)).strip()
        if line == '0':
            raise Invalid('Добавление серверов отменено')
        if not line:
            if len(selected) >= 2:
                return selected
            print('Для автовыбора нужно минимум два разных сервера. Добавьте ещё %d.' % (2-len(selected)))
            continue
        if line == '*' and available:
            selected = list(dict.fromkeys(selected + [p['id'] for p in available]))
            print('Выбрано участников: %d.' % len(selected))
            continue
        if line.startswith('@'):
            number = line[1:]
            if not number.isdigit() or not 1 <= int(number) <= len(available):
                print('Нет такого сохранённого профиля. Вставьте ссылку или @номер из списка.')
                continue
            profile = available[int(number)-1]
        else:
            try:
                if family_of(line) != family:
                    raise Invalid('Ссылка относится к другому семейству')
            except Invalid as error:
                print(str(error))
                continue
            profile = next((p for p in state['profiles'] if p['uri'] == line), None)
            if profile is None:
                if len(state['profiles']) >= 1000:
                    print('Достигнут лимит клиента: 1000 профилей. Завершите список пустой строкой.')
                    continue
                parsed = urllib.parse.urlsplit(line)
                name = urllib.parse.unquote(parsed.fragment) or '%s %d' % (family, len(state['profiles'])+1)
                profile = dict(id=str(uuid.uuid4()), name=name, uri=line)
                state['profiles'].append(profile)
        if profile['id'] in selected:
            print('Этот сервер уже добавлен. Вставьте следующую ссылку.')
        else:
            selected.append(profile['id'])
            print('Добавлен: %s. Всего: %d.' % (profile['name'], len(selected)))


def members(state, family, initial=None):
    selected = list(initial or [])
    while True:
        available = [p for p in state['profiles'] if family_of(p['uri']) == family]
        print('\nУчастники: %d выбрано. Нужно минимум два.' % len(selected))
        for i, p in enumerate(available, 1):
            print('  [%d] %s %s' % (i+3, '[✓]' if p['id'] in selected else '[ ]', p['name']))
        print('  [1] Добавить сервер по ссылке\n  [2] Выбрать все\n  [3] Готово\n  [0] Отмена')
        answer = input('Действие или номер профиля: ').strip()
        if answer == '0':
            raise Invalid('Выбор участников отменён')
        if answer == '3':
            if len(selected) >= 2:
                return selected
            print('Добавьте ещё участника или вернитесь назад.')
            continue
        if answer == '2':
            selected = [p['id'] for p in available]
            if not selected:
                print('Сохранённых профилей этого семейства нет. Выберите 1 и добавьте ссылки серверов.')
            continue
        if answer == '1':
            selected = add_servers(state, family, selected)
        elif answer.isdigit() and 4 <= int(answer) <= len(available)+3:
            pid = available[int(answer)-4]['id']
            if pid in selected:
                selected.remove(pid)
            else:
                selected.append(pid)
        else:
            print('Выберите номер из списка.')


LABELS = dict(selectionMode='Порядок выбора', probeMethod='Метод GET/HEAD', testUrl='URL проверки подключения',
              expectedStatus='Ожидаемый HTTP статус', automatic='Повторять тест и выбирать сервер', testOnConnect='Тест при подключении',
              intervalSeconds='Интервал повторной проверки', timeoutSeconds='Таймаут запроса', holdSeconds='Удержание сервера',
              confirmations='Подтверждений улучшения / отказа', improvementMs='Допуск URLTest', improvementPercent='Допуск скорости',
              samples='Запросов на сервер', durationSeconds='Длительность загрузки',
              maxBytesPerCandidate='Лимит трафика на сервер', allowMobile='Тестировать по мобильной сети', freshnessSeconds='Срок годности результата')


def settings(group):
    while True:
        fields = list(LABELS)
        hidden = {'durationSeconds', 'maxBytesPerCandidate', 'improvementPercent'} if group['type'] == 'URL_TEST' else {'samples', 'improvementMs'}
        fields = [f for f in fields if f not in hidden]
        print('\nПараметры %s; параметры второго режима сохраняются.' % group['type'])
        for i, field in enumerate(fields, 1):
            print('%d. %s: %s' % (i, LABELS[field], group.get(field, 'не задано')))
        value = input('Параметр (0 — готово): ').strip()
        if value == '0':
            return
        if not value.isdigit() or not 1 <= int(value) <= len(fields):
            print('Неверный номер')
            continue
        field = fields[int(value) - 1]
        change_setting(group, field)

def change_setting(group, field):
    if field in ('automatic', 'testOnConnect', 'allowMobile'):
        group[field] = choose([False, True], lambda v: 'Включить' if v else 'Выключить')
    elif field == 'selectionMode':
        group[field] = choose(['BEST', 'PRIORITY'], lambda v: {'BEST': 'Лучший результат', 'PRIORITY': 'Приоритет по порядку'}[v])
    elif field == 'probeMethod':
        group[field] = choose(['GET'] if group['type'] == 'SPEEDTEST' else ['GET', 'HEAD'], str)
    elif field == 'testUrl':
        group[field] = test_url(group['type'], group.get(field))
    else:
        presets = dict(expectedStatus=[200, 204], intervalSeconds=[60, 300, 600, 1800],
            timeoutSeconds=[3, 5, 8, 15, 30], holdSeconds=[0, 60, 120, 300],
            confirmations=[1, 2, 3, 5], improvementMs=[0, 20, 50, 100, 200],
            improvementPercent=[0, 10, 20, 30, 50], samples=[1, 2, 3, 4, 5],
            durationSeconds=[3, 5, 10, 15, 30], maxBytesPerCandidate=[1048576, 5242880, 10485760, 52428800],
            freshnessSeconds=[60, 300, 600, 1800])
        values = sorted(set(presets[field] + [group[field]]))
        group[field] = choose(values, lambda v: str(v) + (' (текущее)' if v == group[field] else ''))

def display_value(field, value):
    if isinstance(value, bool):
        return 'Включено' if value else 'Выключено'
    if field == 'selectionMode':
        return {'BEST': 'Лучший результат теста', 'PRIORITY': 'Приоритет по порядку'}[value]
    if field == 'maxBytesPerCandidate':
        return '%s КиБ' % (value / 1024 if value % 1024 else value // 1024)
    if field == 'improvementMs':
        return '%s мс' % value
    if field == 'improvementPercent':
        return '%s%%' % value
    if field.endswith('Seconds'):
        return '%s с' % value
    return str(value)


def group_fields(kind):
    fields = ['name', 'type', 'testUrl']
    fields += ['probeMethod', 'improvementMs'] if kind == 'URL_TEST' else ['improvementPercent']
    fields += ['memberIds', 'memberOrder', 'selectionMode', 'automatic', 'intervalSeconds', 'testOnConnect']
    if kind == 'SPEEDTEST':
        fields += ['durationSeconds', 'maxBytesPerCandidate']
    fields += ['timeoutSeconds', 'expectedStatus', 'holdSeconds', 'confirmations', 'freshnessSeconds']
    if kind == 'URL_TEST':
        fields += ['samples']
    return fields + ['routingProfileId', 'allowMobile']


def edit(state, group):
    """One visible form for both creation and editing; no hidden mandatory wizard."""
    labels = dict(LABELS, name='Имя профиля / группы', type='Режим',
                  memberIds='Тип: список серверов', memberOrder='Порядок серверов',
                  routingProfileId='Цепочка группы (профиль-источник)')
    while True:
        by_id = {p['id']: p for p in state['profiles']}
        fields = group_fields(group['type'])
        print('\nНАСТРОЙКИ ГРУППЫ — %s' % group['family'])
        for i, field in enumerate(fields, 1):
            if field == 'memberIds':
                value = '%d профилей — добавить ссылки подряд / изменить список' % len(group['memberIds'])
            elif field == 'memberOrder':
                value = ' → '.join(by_id[pid]['name'] for pid in group['memberIds']) or 'Список пуст'
            elif field == 'routingProfileId':
                value = by_id.get(group.get(field), {}).get('name', 'Не задана — выберите участника группы')
            else:
                value = display_value(field, group[field])
            print('  [%d] %s: %s' % (i, labels[field], value))
        print('DNS и правила берутся из профиля-источника. Измерения выполняет клиент после подключения.')
        print('  [0] Готово — проверить и перейти к сохранению\n  [99] Отмена без сохранения')
        answer = input('Настройка: ').strip()
        if answer == '99':
            return False
        if answer == '0':
            try:
                validate({'profiles': state['profiles'], 'groups': [group]})
            except Invalid:
                print('Группа не готова: нужны имя, минимум два сервера и профиль-источник из списка; проверьте параметры.')
                input('Enter — вернуться к настройкам: ')
                continue
            return True
        if not answer.isdigit() or not 1 <= int(answer) <= len(fields):
            print('Выберите номер настройки.')
            continue
        field = fields[int(answer)-1]
        try:
            if field == 'name':
                name = input('Имя (Enter — оставить текущее): ').strip()
                if name:
                    group['name'] = name
            elif field == 'type':
                kind = choose(['URL_TEST', 'SPEEDTEST'], str)
                if kind != group['type']:
                    url = test_url(kind)
                    group['type'], group['testUrl'] = kind, url
                    group['expectedStatus'] = 200 if kind == 'SPEEDTEST' else 204
                    if kind == 'SPEEDTEST':
                        group['probeMethod'] = 'GET'
            elif field == 'memberIds':
                local = copy.deepcopy(state)
                selected = (members(local, group['family'], group['memberIds']) if group['memberIds']
                            else add_servers(local, group['family']))
                state['profiles'] = local['profiles']
                group['memberIds'] = selected
                if group.get('routingProfileId') not in selected:
                    group['routingProfileId'] = None
                    print('Выберите цепочку группы (профиль-источник) в настройках.')
            elif field in ('routingProfileId', 'memberOrder'):
                ordered = [by_id[pid] for pid in group['memberIds']]
                if not ordered:
                    print('Сначала добавьте серверы в список.')
                    continue
                profile = choose(ordered, lambda p: p['name'])
                if field == 'routingProfileId':
                    group[field] = profile['id']
                else:
                    direction = choose([-1, 1], lambda d: 'Выше' if d == -1 else 'Ниже')
                    old = group['memberIds'].index(profile['id'])
                    new = max(0, min(len(ordered)-1, old+direction))
                    group['memberIds'].insert(new, group['memberIds'].pop(old))
            else:
                change_setting(group, field)
        except Invalid as error:
            print(str(error))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('user_id')
    parser.add_argument('--api', default='http://127.0.0.1:22217')
    args = parser.parse_args(argv)
    path = '/api/users/' + urllib.parse.quote(args.user_id, safe='')
    draft = None
    draft_revision = None
    while True:
        state = api(args.api, path + '/connection-groups')
        if draft is not None:
            print('Есть несохранённый черновик. [11] — повторить сохранение; [12] — отбросить.')
            if state['revision'] != draft_revision:
                print('Ревизия на сервере изменилась. Черновик не будет записан поверх новых данных.')
        displayed = draft or state
        print('\nГРУППЫ АВТОВЫБОРА — измерения выполняет телефон после явного подключения.')
        for i, group in enumerate(displayed['groups'], 1):
            print('  Группа %d: %s [%s / %s / %s] — %s' % (i, group['name'], group['family'], group['type'], group['selectionMode'], 'выдаётся' if group['enabled'] else 'исключена'))
        print('  [1] Создать группу\n  [2] Редактировать группу\n  [3] Переименовать\n  [4] Включить / исключить из подписки\n  [5] Удалить группу\n  [6] Редактировать профиль\n  [7] Ссылки подписки: JSON / контейнер групп\n  [8] Показать реквизиты\n  [9] Удалить профиль\n  [10] Взять профили из подписки пользователя\n  [0] Назад')
        action = input('Действие: ').strip()
        if action == '0':
            if draft is not None and not confirm('Выйти и отбросить несохранённый черновик?'):
                continue
            return
        if action == '12':
            if confirm('Отбросить черновик и загрузить текущие данные сервера?'):
                draft = None
                draft_revision = None
            continue
        try:
            working = copy.deepcopy(displayed)
            if action == '1':
                print('Тип автовыбора:')
                kind = choose(['URL_TEST', 'SPEEDTEST'], str)
                print('Семейство серверов:')
                family = choose(list(FAMILIES), str)
                group = dict(DEFAULTS, id=str(uuid.uuid4()), name=family + ' ' + kind,
                             family=family, category=FAMILIES[family], type=kind,
                             enabled=True, testOnConnect=kind == 'URL_TEST', memberIds=[], routingProfileId=None,
                             testUrl=('https://www.gstatic.com/generate_204' if kind == 'URL_TEST'
                                      else 'https://speed.cloudflare.com/__down?bytes=10485760'))
                if kind == 'SPEEDTEST':
                    group['expectedStatus'] = 200
                if not edit(working, group):
                    continue
                working['groups'].append(group)
            elif action in ('2', '3', '4', '5'):
                if not working['groups']:
                    print('Групп пока нет — сначала выберите [1] Создать группу.')
                    continue
                group = choose(working['groups'], lambda g: g['name'])
                if action == '2':
                    if not edit(working, group):
                        continue
                elif action == '3':
                    group['name'] = input('Новое имя: ').strip()
                elif action == '4':
                    group['enabled'] = not group['enabled']
                elif confirm('Удалить только группу? Профили сохранятся.'):
                    working['groups'].remove(group)
                else:
                    continue
            elif action in ('6', '8', '9'):
                if not working['profiles']:
                    print('Профилей пока нет — добавьте серверы при создании группы или импортируйте их пунктом [10].')
                    continue
                profile = choose(working['profiles'], lambda p: '%s [%s; реквизиты скрыты]' % (p['name'], family_of(p['uri'])))
                if action == '8':
                    if confirm('Показать полную ссылку с секретами?'):
                        print(profile['uri'])
                    continue
                if action == '9':
                    if not confirm('Удалить профиль из всех групп?'):
                        continue
                    working['profiles'].remove(profile)
                    for group in working['groups']:
                        group['memberIds'] = [pid for pid in group['memberIds'] if pid != profile['id']]
                        if group['routingProfileId'] == profile['id']:
                            raise Invalid('Сначала выберите другой профиль маршрутизации в использующих его группах')
                else:
                    print('Правка действует во всех группах этого пользователя; ID сохраняется.')
                    name = input('Новое имя (Enter — сохранить): ').strip()
                    uri = input('Новая ссылка (Enter — сохранить): ').strip()
                    if name:
                        profile['name'] = name
                    if uri:
                        profile['uri'] = uri
            elif action == '7':
                links = api(args.api, path + '/subscription-url')
                print('Для внешней подписки панели (контейнер групп; нужна поддержка tuna-groups:// в клиенте):')
                print(links.get('group_transport_subscription_url', 'Ссылка контейнера недоступна — обновите службу подписок'))
                print('Для прямого получения JSON (не добавлять как список URI в LuckUI):')
                print(links.get('structured_subscription_url', 'JSON-ссылка недоступна'))
                print('Это секретная ссылка TUNA. Импорт не запускает тесты; активную группу после правок переподключите.')
                continue
            elif action == '10':
                import_profiles(args.api, path, working)
            elif action == '11' and draft is not None:
                pass
            else:
                raise Invalid('Неверное действие')
            draft = working
            if draft_revision is None:
                draft_revision = state['revision']
            document = validate({k: working[k] for k in ('profiles', 'groups')})
            print('Проверено: %d групп, %d профилей. Измерения выполнит клиент.' % (len(document['groups']), len(document['profiles'])))
            if not confirm('Сохранить изменения?'):
                continue
            result = api(args.api, path + '/connection-groups', dict(document, expectedRevision=draft_revision))
            print('Сохранено. Ревизия: %s' % result['revision'])
            draft = None
            draft_revision = None
        except Invalid as error:
            print('Изменения не сохранены: ' + str(error))
        except OSError:
            print('Изменения не сохранены: API недоступен. Проверьте службу подписок.')


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print('\nВыход. Несохранённый черновик не записан на сервер.')
    except (OSError, Invalid):
        sys.exit('API групп недоступен. Проверьте локальную службу подписок.')
