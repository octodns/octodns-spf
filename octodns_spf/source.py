#
#
#

from io import StringIO
from logging import getLogger

from octodns.record import Record, RecordException
from octodns.source.base import BaseSource

from .processor import SpfDnsLookupProcessor


class SpfException(RecordException):
    def __init__(self, msg, record=None):
        context = getattr(record, 'context', None)
        if context:
            msg += f', from {context}'
        super().__init__(msg)
        self.record = record


def _parse_spf(value):
    a_records = []
    mx_records = []
    ip4_addresses = []
    ip6_addresses = []
    includes = []
    exists = []
    soft_fail = None

    pieces = value.split()
    if pieces[0] != 'v=spf1':
        raise SpfException(f'Unrecognized SPF value: "{value}"')

    for piece in pieces[1:]:
        if 'all' in piece:
            soft_fail = piece.startswith('~')
            continue
        mechinism, v = piece.split(':', 1)
        if mechinism == 'a':
            a_records.append(v)
        elif mechinism == 'mx':
            mx_records.append(v)
        elif mechinism == 'ip4':
            ip4_addresses.append(v)
        elif mechinism == 'ip6':
            ip6_addresses.append(v)
        elif mechinism == 'include':
            includes.append(v)
        elif mechinism == 'exists':
            exists.append(v)
        else:
            raise SpfException(f'Unrecognized SPF mechinism: "{mechinism}"')

    return (
        a_records,
        mx_records,
        ip4_addresses,
        ip6_addresses,
        includes,
        exists,
        soft_fail,
    )


def _build_spf(
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
            buf.write(' exists:')
            buf.write(exist)
    if soft_fail is not None:
        if soft_fail:
            buf.write(' ~all')
        else:
            buf.write(' -all')
    return buf.getvalue()


def _merge_and_dedup_preserving_order(a, b):
    seen = set()
    for x in a:
        if x not in seen:
            yield x
        seen.add(x)
    for x in b:
        if x not in seen:
            yield x
        seen.add(x)


def _merge_spf(
    value,
    a_records,
    mx_records,
    ip4_addresses,
    ip6_addresses,
    includes,
    exists,
    soft_fail,
):
    (
        parsed_a_records,
        parsed_mx_records,
        parsed_ip4_addresses,
        parsed_ip6_addresses,
        parsed_includes,
        parsed_exists,
        parsed_soft_fail,
    ) = _parse_spf(value)

    if parsed_soft_fail is None:
        # just use whatever we were passed
        parsed_soft_fail = soft_fail
    else:
        # merge them, if either is true (soft) it's soft
        parsed_soft_fail |= soft_fail

    return _build_spf(
        _merge_and_dedup_preserving_order(parsed_a_records, a_records),
        _merge_and_dedup_preserving_order(parsed_mx_records, mx_records),
        _merge_and_dedup_preserving_order(parsed_ip4_addresses, ip4_addresses),
        _merge_and_dedup_preserving_order(parsed_ip6_addresses, ip6_addresses),
        _merge_and_dedup_preserving_order(parsed_includes, includes),
        _merge_and_dedup_preserving_order(parsed_exists, exists),
        parsed_soft_fail,
    )


class SpfSource(BaseSource):
    # https://datatracker.ietf.org/doc/html/rfc7208
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
        merging_enabled=False,
        ttl=DEFAULT_TTL,
        verify_dns_lookups=False,
    ):
        self.log = getLogger(f'SpfSource[{id}]')
        self.log.info(
            '__init__: id=%s, a_records=%s, mx_records=%s, ip4_addresses=%s, ip6_addresses=%s, includes=%s, exists=%s, soft_fail=%s, merging_enabled=%s, ttl=%d, verify_dns_lookups=%s',
            id,
            a_records,
            mx_records,
            ip4_addresses,
            ip6_addresses,
            includes,
            exists,
            soft_fail,
            merging_enabled,
            ttl,
            verify_dns_lookups,
        )
        super().__init__(id)
        self.a_records = a_records
        self.mx_records = mx_records
        self.ip4_addresses = ip4_addresses
        self.ip6_addresses = ip6_addresses
        self.includes = includes
        self.exists = exists

        self.soft_fail = soft_fail

        self.merging_enabled = merging_enabled
        self.ttl = ttl

        self.spf_value = _build_spf(
            a_records,
            mx_records,
            ip4_addresses,
            ip6_addresses,
            includes,
            exists,
            soft_fail,
        )
        self.log.debug('__init__:   spf=%s', self.spf_value)

        if verify_dns_lookups:
            SpfDnsLookupProcessor(self.id).check_dns_lookups(
                f'<{self.id}>', [self.spf_value]
            )

    def list_zones(self):
        # we're a specialized provider and never originate any zones ourselves.
        return []

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
            raise SpfException(
                'Existing SPF value found, cannot coexist, migrate to TXT', spf
            )
        elif txt:
            self.log.debug('populate:   found existing TXT record')
            # figure out which value is the existing SPF
            try:
                i = [v[:6] for v in txt.values].index('v=spf1')
            except ValueError:
                i = None
            if i is not None:
                if not self.merging_enabled:
                    raise SpfException(
                        'Existing SPF value found in TXT record, merging not enabled',
                        txt,
                    )
                merged = _merge_spf(
                    txt.values[i],
                    self.a_records,
                    self.mx_records,
                    self.ip4_addresses,
                    self.ip6_addresses,
                    self.includes,
                    self.exists,
                    self.soft_fail,
                )
                self.log.info(
                    'population:   existing value for zone=%s, merging with configured and replacing record',
                    zone.decoded_name,
                )
                record = txt.copy()
                # replace the existing spf value with the merged one
                record.values[i] = merged
            else:
                self.log.debug(
                    'populate:   adding our value and replacing record'
                )
                record = txt.copy()
                # add a new value
                record.values.append(self.spf_value)
                # and make sure they're sorted to match Record behavior
                record.values.sort()
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
