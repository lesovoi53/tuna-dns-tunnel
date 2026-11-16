"""TUNA rc11 outer connection groups. No probes, networking, or URI rewriting."""
import datetime
import base64
import hashlib
import json
import re
import sqlite3
from urllib.parse import urlsplit

MAX_BODY = 2 * 1024 * 1024
GROUP_URI_PREFIX = 'tuna-groups://v1/'
FAMILIES = {'VPN': 'VPN', 'CSQTT_QWDTT': 'BYPASS', 'WEBDAV': 'BYPASS', 'OPENFLUX': 'BYPASS'}
SCHEMES = {scheme: 'VPN' for scheme in ('vless', 'hysteria2', 'hy2', 'snell', 'mieru', 'mierus', 'trojan', 'ss', 'tuic', 'anytls')}
SCHEMES.update(csqtt='CSQTT_QWDTT', qwdtt='CSQTT_QWDTT', webdav='WEBDAV', webdavs='WEBDAV')
SCHEMES['openflux-bundle'] = 'OPENFLUX'
DEFAULTS = dict(selectionMode='BEST', probeMethod='GET', expectedStatus=204, automatic=False,
                intervalSeconds=300, timeoutSeconds=8, holdSeconds=120, confirmations=2,
                improvementMs=50, improvementPercent=20, samples=3, durationSeconds=5,
                maxBytesPerCandidate=10485760, allowMobile=False, freshnessSeconds=600)
RANGES = dict(expectedStatus=(200, 299), intervalSeconds=(30, 86400), timeoutSeconds=(1, 120),
              holdSeconds=(0, 86400), confirmations=(1, 10), improvementMs=(0, 2147483647),
              improvementPercent=(0, 1000), samples=(1, 5), durationSeconds=(1, 30),
              maxBytesPerCandidate=(1024, 1073741824), freshnessSeconds=(30, 86400))


class Invalid(ValueError):
    """Messages name fields only; never include input values or URIs."""


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), sort_keys=True).encode('utf-8')


def text(value, field):
    if not isinstance(value, str) or not value.strip() or any(ord(c) < 32 for c in value):
        raise Invalid('Invalid ' + field)
    try:
        if len(value.encode('utf-16-le')) // 2 > 200:
            raise Invalid(field + ' exceeds 200 UTF-16 code units')
    except UnicodeError:
        raise Invalid('Invalid Unicode in ' + field) from None
    return value


def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,200}', value):
        raise Invalid('Invalid stable ID')
    return value


def family_of(uri):
    if not isinstance(uri, str) or not uri or any(c.isspace() or ord(c) < 32 for c in uri):
        raise Invalid('Invalid profile URI')
    try:
        parsed = urlsplit(uri)
        family = SCHEMES.get(parsed.scheme.lower())
        if not family or not parsed.netloc:
            raise Invalid('Unsupported profile protocol')
        if family == 'OPENFLUX' and not uri.startswith('openflux-bundle://v2/'):
            raise Invalid('OpenFlux v2 bundle required')
    except (ValueError, UnicodeError):
        raise Invalid('Invalid or unsupported profile URI') from None
    return family


def validate(document, validators=None):
    try:
        return _validate(document, validators)
    except Invalid:
        raise
    except (TypeError, ValueError, KeyError, UnicodeError):
        raise Invalid('Invalid field type or encoding in group document') from None


def _validate(document, validators=None):
    if not isinstance(document, dict) or set(document) != {'profiles', 'groups'}:
        raise Invalid('Expected profiles and groups')
    profiles, groups = document['profiles'], document['groups']
    if not isinstance(profiles, list) or len(profiles) > 1000:
        raise Invalid('At most 1000 profiles are allowed')
    if not isinstance(groups, list) or len(groups) > 100:
        raise Invalid('At most 100 groups are allowed')
    result = {'profiles': [], 'groups': []}
    by_id, uris, group_ids = {}, set(), set()
    for profile in profiles:
        if not isinstance(profile, dict) or set(profile) != {'id', 'name', 'uri'}:
            raise Invalid('Invalid profile fields')
        pid = identity(profile['id'])
        name = text(profile['name'], 'profile name')
        uri = profile['uri']
        family = family_of(uri)
        if pid in by_id or uri in uris:
            raise Invalid('Duplicate profile ID or URI; reuse the existing profile ID')
        if validators and family in validators:
            try:
                if not validators[family](uri)[0]:
                    raise Invalid('Invalid profile URI for its family')
            except Exception:
                raise Invalid('Invalid profile URI for its family') from None
        by_id[pid] = family
        uris.add(uri)
        result['profiles'].append(dict(id=pid, name=name, uri=uri))
    extra = {'id', 'name', 'category', 'family', 'type', 'memberIds', 'routingProfileId',
             'testUrl', 'testOnConnect', 'enabled'}
    for raw in groups:
        if not isinstance(raw, dict) or set(raw) - set(DEFAULTS) - extra:
            raise Invalid('Invalid group fields')
        group = dict(DEFAULTS, **raw)
        gid = identity(group.get('id'))
        if gid in group_ids:
            raise Invalid('Duplicate group ID')
        group_ids.add(gid)
        group['name'] = text(group.get('name'), 'group name')
        family = group.get('family')
        if family not in FAMILIES or group.get('category') != FAMILIES[family]:
            raise Invalid('Invalid category/family combination')
        if group.get('type') not in ('URL_TEST', 'SPEEDTEST'):
            raise Invalid('Invalid group type')
        group.setdefault('enabled', True)
        group.setdefault('testOnConnect', group['type'] == 'URL_TEST')
        if 'expectedStatus' not in raw and group['type'] == 'SPEEDTEST':
            group['expectedStatus'] = 200
        if 'testUrl' not in group and group['type'] == 'URL_TEST':
            group['testUrl'] = 'https://www.gstatic.com/generate_204'
        members = group.get('memberIds')
        if not isinstance(members, list) or not 2 <= len(members) <= 1000 or any(not isinstance(m, str) for m in members) or len(set(members)) != len(members):
            raise Invalid('A group needs 2 to 1000 unique member IDs')
        if any(by_id.get(pid) != family for pid in members):
            raise Invalid('Unknown member ID or mixed families')
        if group.get('routingProfileId') not in members:
            raise Invalid('routingProfileId must refer to a group member')
        if group['selectionMode'] not in ('BEST', 'PRIORITY'):
            raise Invalid('Invalid selectionMode')
        if group['probeMethod'] not in ('GET', 'HEAD') or (group['type'] == 'SPEEDTEST' and group['probeMethod'] != 'GET'):
            raise Invalid('Invalid probeMethod for the selected type')
        try:
            test_url = group.get('testUrl')
            if not isinstance(test_url, str) or any(c.isspace() or ord(c) < 32 for c in test_url):
                raise ValueError()
            parsed = urlsplit(test_url)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or '#' in test_url:
                raise ValueError()
            parsed.port
        except (ValueError, TypeError):
            raise Invalid('testUrl must be HTTPS with a host, without userinfo or fragment') from None
        for field in ('enabled', 'automatic', 'testOnConnect', 'allowMobile'):
            if type(group[field]) is not bool:
                raise Invalid(field + ' must be a JSON boolean')
        for field, (low, high) in RANGES.items():
            if type(group[field]) is not int or not low <= group[field] <= high:
                raise Invalid('Invalid range or JSON number type: ' + field)
        result['groups'].append(group)
    try:
        if len(encoded(result)) > MAX_BODY:
            raise Invalid('Snapshot exceeds 2 MiB')
    except UnicodeError:
        raise Invalid('Invalid Unicode in snapshot') from None
    return result


def snapshot(user, document):
    groups = [{k: v for k, v in g.items() if k != 'enabled'} for g in document['groups'] if g['enabled']]
    # Excluded groups cannot leak their credentials through otherwise unused profiles.
    members = {pid for group in groups for pid in group['memberIds']}
    value = dict(schema='tuna.subscription', schemaVersion=1, subscriptionId=user['id'],
                 revision=user['revision'], name=user['nickname'], complete=True,
                 requiredCapabilities=['connection-groups-v1'],
                 profiles=[p for p in document['profiles'] if p['id'] in members], groups=groups)
    body = encoded(value)
    if len(body) > MAX_BODY:
        raise Invalid('Snapshot exceeds 2 MiB')
    return body


class Store:
    def __init__(self, db_path, validators=None):
        self.path = db_path
        self.validators = validators
        db = self.connect()
        try:
            db.execute('''CREATE TABLE IF NOT EXISTS user_connection_groups (
                user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                document_json TEXT NOT NULL)''')
            db.commit()
        finally:
            db.close()

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        return db

    @staticmethod
    def document(db, uid):
        row = db.execute('SELECT document_json FROM user_connection_groups WHERE user_id=?', (uid,)).fetchone()
        return json.loads(row[0]) if row else {'profiles': [], 'groups': []}

    def editor(self, uid):
        db = self.connect()
        try:
            db.execute('BEGIN')
            user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            if not user:
                return 404, {'error': 'User not found'}
            return 200, dict(self.document(db, uid), revision=user['revision'], subscriptionId=user['id'])
        finally:
            db.close()

    def save(self, uid, request):
        if not isinstance(request, dict) or set(request) - {'profiles', 'groups', 'expectedRevision'}:
            return 400, {'error': 'Invalid editor document'}
        try:
            desired = validate({k: request.get(k) for k in ('profiles', 'groups')}, self.validators)
        except Invalid as error:
            return 400, {'error': str(error)}
        db = self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
            if not user:
                return 404, {'error': 'User not found'}
            if encoded(self.document(db, uid)) == encoded(desired):
                return 200, {'success': True, 'changed': False, 'revision': user['revision']}
            expected = request.get('expectedRevision')
            if type(expected) is not int or expected != user['revision']:
                return 409, {'error': 'Revision changed; reload before saving'}
            next_user = dict(user)
            next_user['revision'] += 1
            snapshot(next_user, desired)  # Validate complete final HTTP body before any write.
            db.execute('INSERT INTO user_connection_groups VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET document_json=excluded.document_json',
                       (uid, encoded(desired).decode()))
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            db.execute('UPDATE users SET revision=revision+1, updated_at=? WHERE id=?', (now, uid))
            db.commit()
            return 200, {'success': True, 'changed': True, 'revision': next_user['revision']}
        except Invalid as error:
            db.rollback()
            return 400, {'error': str(error)}
        except sqlite3.Error:
            db.rollback()
            return 500, {'error': 'Group transaction failed'}
        finally:
            db.close()

    def publish(self, token):
        db = self.connect()
        try:
            db.execute('BEGIN')
            user = db.execute('SELECT * FROM users WHERE subscription_token_hash=? AND enabled=1',
                              (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
            if not user:
                return 404, {'error': 'Subscription not found'}, b''
            document = validate(self.document(db, user['id']), self.validators)
            body = snapshot(user, document)
            return 200, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'}, body
        except (Invalid, ValueError, sqlite3.Error):
            return 500, {'error': 'Invalid structured subscription; no partial snapshot was published'}, b''
        finally:
            db.close()

    def publish_uri(self, token):
        """Transport the exact complete JSON through a URI-only aggregator.

        No compression, URL decoding, fragment or query: a panel may rename the
        URI's fragment without touching the Base64URL payload. Always emit even
        an empty snapshot so clients can remove groups previously imported.
        """
        status, headers, body = self.publish(token)
        if status != 200:
            return status, headers, body
        line = GROUP_URI_PREFIX.encode('ascii') + base64.urlsafe_b64encode(body).rstrip(b'=') + b'\n'
        payload = base64.b64encode(line)
        if len(payload) > MAX_BODY:
            return 500, {'error': 'Group URI subscription exceeds 2 MiB; no partial snapshot was published'}, b''
        return 200, {'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store'}, payload
