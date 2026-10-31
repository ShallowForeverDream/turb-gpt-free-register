"""Read the Auth page's channel policy, without executing its scripts."""
from html.parser import HTMLParser
import json
import re

import phonenumbers


MULTI_CHANNEL_CONFIG = 'phone-verification-regions-multi-channel-v2'
SINGLE_CHANNEL_CONFIG = 'phone-verification-sms-regions-by-verification-channel'


class SmsChannelUnavailableError(RuntimeError):
    pass


class _BootstrapScript(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script' and dict(attrs).get('id') == 'bootstrap-inert-script':
            self.active = True

    def handle_endtag(self, tag):
        if tag == 'script':
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.parts.append(data)


def _config_hash(name):
    value = 0
    for char in name:
        value = (value * 31 + ord(char)) & 0xffffffff
    return str(value)


def _country(value):
    return isinstance(value, str) and re.fullmatch('[A-Z]{2}', value) is not None


def read_phone_channel_policy(document):
    """Only return the two allowlisted country/channel configs, never bootstrap data."""
    if not isinstance(document, str) or len(document) > 8 * 1024 * 1024:
        return None
    try:
        script = _BootstrapScript()
        script.feed(document)
        value = ''.join(script.parts)
        if len(value) > 2 * 1024 * 1024:
            return None
        bootstrap = json.loads(value)['statsigClientInitData']['bootstrap']
        bootstrap = json.loads(bootstrap) if isinstance(bootstrap, str) else bootstrap
        configs = bootstrap['dynamic_configs']
        result = {}
        for name, key in ((MULTI_CHANNEL_CONFIG, 'multi'), (SINGLE_CHANNEL_CONFIG, 'single')):
            record = configs.get(name, configs.get(_config_hash(name)))
            if not isinstance(record, dict) or not isinstance(record.get('value'), dict):
                return None
            raw = record['value']
            if key == 'multi':
                normalized = {}
                for country, channels in raw.items():
                    country = country.strip().upper()
                    if not _country(country):
                        continue
                    if not isinstance(channels, list) or any(c not in ('sms', 'whatsapp') for c in channels):
                        return None
                    normalized[country] = list(dict.fromkeys(normalized.get(country, []) + channels))
                result[key] = normalized
            else:
                normalized = {}
                for channel in ('sms', 'whatsapp'):
                    countries = raw.get(channel, [])
                    if not isinstance(countries, list) or any(not isinstance(c, str) for c in countries):
                        return None
                    normalized[channel] = sorted({c.strip().upper() for c in countries if _country(c.strip().upper())})
                result[key] = normalized
        return result
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return None


def phone_country(phone):
    try:
        value = phonenumbers.region_code_for_number(phonenumbers.parse('+' + phone.lstrip('+'), None))
        return value if _country(value) else None
    except phonenumbers.NumberParseException:
        return None


def sms_choice(policy, country, multi_channel_allowed):
    """Mirror the add-phone form. None means its channel field must be omitted."""
    if not isinstance(policy, dict) or not _country(country):
        raise SmsChannelUnavailableError('未取得当前 Auth 页面和号码国家的短信选项，停止；不走 WhatsApp')
    if multi_channel_allowed is True:
        channels = policy['multi'].get(country, [])
        if channels:
            if 'sms' not in channels:
                raise SmsChannelUnavailableError('当前国家未提供 SMS 选项，停止；不走 WhatsApp')
            return 'sms'
        # With multi-channel enabled, the official form's no-picker default is SMS.
        return None
    single = policy['single']
    if country not in single['sms'] and country in single['whatsapp']:
        raise SmsChannelUnavailableError('当前国家仅提供 WhatsApp，不能切换为短信；未请求 WhatsApp')
    return None
