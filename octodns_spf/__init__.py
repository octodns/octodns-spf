#
#
#

from io import StringIO
from logging import getLogger

from octodns.record import Record, RecordException
from octodns.source.base import BaseSource

__VERSION__ = '0.0.1'


class SpfException(RecordException):
    def __init__(self, msg, record):
        context = getattr(record, 'context', None)
        if context:
            msg += f', from {context}'
        super().__init__(msg)


def _build_spf_value(
    a_records,
    mx_records,
    ip4_addresses,
    ip6_addresses,
    includes,
    exists,
    soft_fail,
):
    buf = StringIO()
    buf.write('v=spf1')
    if a_records:
        for a_record in a_records:
            buf.write(' a:')
            buf.write(a_record)
    if mx_records:
        for mx_record in mx_records:
            buf.write(' mx:')
            buf.write(mx_record)
    if ip4_addresses:
        for ip4_address in ip4_addresses:
            buf.write(' ip4:')
            buf.write(ip4_address)
    if ip6_addresses:
        for ip6_address in ip6_addresses:
            buf.write(' ip6:')
            buf.write(ip6_address)
    if includes:
        for include in includes:
            buf.write(' include:')
            buf.write(include)
    if exists:
        for exist in exists:
            buf.write(' exist:')
            buf.write(exist)
    if soft_fail:
        buf.write(' ~all')
    else:
        buf.write(' -all')
    return buf.getvalue()


class SpfSource(BaseSource):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('TXT'))

    DEFAULT_TTL = 3600

    def __init__(
        self,
        id,
        a_records=[],
        mx_records=[],
        ip4_addresses=[],
        ip6_addresses=[],
        includes=[],
        exists=[],
        soft_fail=False,
        ttl=DEFAULT_TTL,
    ):
        self.log = getLogger(f'SpfSource[{id}]')
        self.log.info(
            '__init__: id=%s, a_records=%s, mx_records=%s, ip4_addresses=%s, ip6_addresses=%s, includes=%s, exists=[], soft_fail=%s, ttl=%d',
            id,
            a_records,
            mx_records,
            ip4_addresses,
            ip6_addresses,
            includes,
            exists,
            soft_fail,
            ttl,
        )
        super().__init__(id)
        self.a_records = a_records
        self.mx_records = mx_records
        # TODO: validate IPs?
        self.ip4_addresses = ip4_addresses
        self.ip6_addresses = ip6_addresses
        self.includes = includes
        self.exists = exists
        self.soft_fall = soft_fail

        self.ttl = ttl

        self.spf_value = _build_spf_value(
            a_records,
            mx_records,
            ip4_addresses,
            ip6_addresses,
            includes,
            exists,
            soft_fail,
        )
        self.log.debug('__init__:   spf=%s', self.spf_value)

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        spf = None
        txt = None
        for record in zone.records:
            if record.name == '':
                if record._type == 'TXT':
                    txt = record
                elif record._type == 'SPF':
                    spf = record

        if spf:
            # TODO: support merging?
            raise SpfException('Existing SPF value found in TXT record', txt)
        elif txt:
            self.log.debug('populate:   found existing TXT record')
            for value in txt.values:
                if value.startswith('v=spf'):
                    # TODO support merging?
                    raise SpfException(
                        'Existing SPF value found in TXT record', txt
                    )
            self.log.debug('populate:   adding our value, and replacing record')
            record = txt.copy()
            record.values.append(self.spf_value)
            # replace with our updated version
            zone.add_record(record, lenient=lenient, replace=True)
        else:
            record = Record.new(
                zone,
                '',
                {'ttl': self.ttl, 'type': 'TXT', 'value': self.spf_value},
            )
            zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=False',
            len(zone.records) - before,
        )
