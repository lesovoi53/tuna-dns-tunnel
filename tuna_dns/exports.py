"""Client profile export using the existing Lite/TUNA wire format."""
import base64
import json
from pathlib import Path
import zlib

from . import config, profiles


def _json(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def links(settings, preset, format, config_path=Path(config.CONFIG_PATH)):
    settings = config.validate(settings)
    if format not in ('tuna', 'storm'):
        raise ValueError('Неизвестный формат экспорта: выберите tuna или storm.')
    tuning = profiles.effective(config_path, preset)
    groups = [settings['domains']] if format == 'tuna' else [[domain] for domain in settings['domains']]
    result = []
    for domains in groups:
        profile = dict(name=settings['name'], domains=domains,
                       server=dict(domain=domains[0], encryption_key=settings['key'],
                                   encryption_method=settings['encryption_method']), **tuning)
        raw = _json(dict(schema='whitedns.profile', version=1, profile=profile))
        if len(raw) > 65536:
            raise ValueError('Профиль MasterDNS превышает допустимый размер.')
        uri = 'stormdns://' + base64.b64encode(raw).decode('ascii')
        if len(uri) > 100000:
            raise ValueError('Ссылка MasterDNS превышает допустимый размер.')
        if format == 'tuna':
            document = _json(dict(name=settings['name'], uri=uri))
            if len(document) > 4 * 1024 * 1024:
                raise ValueError('Профиль TUNA превышает допустимый размер.')
            encoded = base64.urlsafe_b64encode(zlib.compress(document, level=9)).decode('ascii').rstrip('=')
            if len(encoded) > 128 * 1024:
                raise ValueError('Ссылка TUNA превышает допустимый размер.')
            uri = 'tuna://' + encoded
        result.append(uri)
    return result
