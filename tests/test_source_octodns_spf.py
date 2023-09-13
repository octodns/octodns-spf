#
#
#

from unittest import TestCase

from octodns.record import Record
from octodns.zone import Zone

from octodns_spf import SpfSource
from octodns_spf.processor import SpfDnsLookupException
from octodns_spf.source import (
    SpfException,
    _build_spf,
    _merge_and_dedup_preserving_order,
    _merge_spf,
    _parse_spf,
)


def _find_apex_txt(records):
    return next(r for r in records if r.name == '' and r._type == 'TXT')


class TestSpfSource(TestCase):
    def test_spf_parse_a(self):
        self.assertEqual(
            (['some.thing'], [], [], [], [], [], True),
            _parse_spf('v=spf1 a:some.thing ~all'),
        )
        self.assertEqual(
            (['some.thing', 'another.one'], [], [], [], [], [], True),
            _parse_spf('v=spf1 a:some.thing a:another.one ~all'),
        )
        self.assertEqual(
            (['some.thing', 'another.one'], [], [], [], [], [], False),
            _parse_spf('v=spf1 a:some.thing   a:another.one -all'),
        )
        # not valid, but things don't blow up
        self.assertEqual(
            ([''], [], [], [], [], [], False), _parse_spf('v=spf1 a: -all')
        )

    def test_spf_parse_mx(self):
        self.assertEqual(
            ([], ['some.thing'], [], [], [], [], True),
            _parse_spf('v=spf1 mx:some.thing ~all'),
        )
        self.assertEqual(
            ([], ['some.thing', 'another.one'], [], [], [], [], True),
            _parse_spf('v=spf1 mx:some.thing mx:another.one ~all'),
        )
        self.assertEqual(
            ([], ['some.thing', 'another.one'], [], [], [], [], False),
            _parse_spf('v=spf1 mx:some.thing   mx:another.one -all'),
        )
        # not valid, but things don't blow up
        self.assertEqual(
            ([], [''], [], [], [], [], False), _parse_spf('v=spf1 mx: -all')
        )

    def test_spf_parse_ip4(self):
        self.assertEqual(
            ([], [], ['1.2.3.4'], [], [], [], True),
            _parse_spf('v=spf1 ip4:1.2.3.4 ~all'),
        )
        self.assertEqual(
            ([], [], ['1.2.3.4', '5.6.7.8'], [], [], [], True),
            _parse_spf('v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 ~all'),
        )
        self.assertEqual(
            ([], [], ['1.2.3.4', '5.6.7.8'], [], [], [], False),
            _parse_spf('v=spf1 ip4:1.2.3.4   ip4:5.6.7.8 -all'),
        )
        # not valid, but things don't blow up
        self.assertEqual(
            ([], [], [''], [], [], [], False), _parse_spf('v=spf1 ip4: -all')
        )
        self.assertEqual(
            ([], [], ['not-an-ip'], [], [], [], False),
            _parse_spf('v=spf1 ip4:not-an-ip -all'),
        )

    def test_spf_parse_ip6(self):
        self.assertEqual(
            ([], [], [], ['2606::1'], [], [], True),
            _parse_spf('v=spf1 ip6:2606::1 ~all'),
        )
        self.assertEqual(
            ([], [], [], ['2606::1', '2606::2'], [], [], True),
            _parse_spf('v=spf1 ip6:2606::1 ip6:2606::2 ~all'),
        )
        self.assertEqual(
            ([], [], [], ['2606::1', '2606::2'], [], [], False),
            _parse_spf('v=spf1 ip6:2606::1   ip6:2606::2 -all'),
        )
        # not valid, but things don't blow up
        self.assertEqual(
            ([], [], [], [''], [], [], False), _parse_spf('v=spf1 ip6: -all')
        )
        self.assertEqual(
            ([], [], [], ['not-an-ip'], [], [], False),
            _parse_spf('v=spf1 ip6:not-an-ip -all'),
        )

    def test_spf_parse_includes(self):
        self.assertEqual(
            ([], [], [], [], ['unit.tests'], [], True),
            _parse_spf('v=spf1 include:unit.tests ~all'),
        )
        self.assertEqual(
            ([], [], [], [], ['unit.tests', 'other.thing'], [], True),
            _parse_spf('v=spf1 include:unit.tests include:other.thing ~all'),
        )
        self.assertEqual(
            ([], [], [], [], ['unit.tests', 'extra.spaces'], [], False),
            _parse_spf('v=spf1 include:unit.tests   include:extra.spaces -all'),
        )
        # not valid, but things don't blow up
        self.assertEqual(
            ([], [], [], [], [''], [], False),
            _parse_spf('v=spf1 include: -all'),
        )

    def test_spf_parse_exists(self):
        self.assertEqual(
            ([], [], [], [], [], ['%{ir}.%{l1r+-}._spf.%{d}'], True),
            _parse_spf('v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} ~all'),
        )
        self.assertEqual(
            (
                [],
                [],
                [],
                [],
                [],
                ['%{ir}.%{l1r+-}._spf.%{d}', 'other.thing'],
                True,
            ),
            _parse_spf(
                'v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} exists:other.thing ~all'
            ),
        )
        self.assertEqual(
            (
                [],
                [],
                [],
                [],
                [],
                ['%{ir}.%{l1r+-}._spf.%{d}', 'other.thing'],
                False,
            ),
            _parse_spf(
                'v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d}    exists:other.thing -all'
            ),
        )
        # not valid, but things don't blow up
        self.assertEqual(
            ([], [], [], [], [], [''], False), _parse_spf('v=spf1 exists: -all')
        )

    def test_spf_parse_soft_fail(self):
        # soft fail
        self.assertEqual(
            ([], [], [], [], [], [], False), _parse_spf('v=spf1 -all')
        )
        self.assertEqual(
            ([], [], [], [], [], [], True), _parse_spf('v=spf1 ~all')
        )
        self.assertEqual(([], [], [], [], [], [], None), _parse_spf('v=spf1'))

    def test_spf_parse_unknown_mechinism(self):
        with self.assertRaises(SpfException) as ctx:
            _parse_spf('v=spf1 unknown:thing -all')
        self.assertEqual(
            'Unrecognized SPF mechinism: "unknown"', str(ctx.exception)
        )

    def test_spf_parse_invalid(self):
        with self.assertRaises(SpfException) as ctx:
            _parse_spf('hello world v=spf1 unknown:thing -all')
        self.assertEqual(
            'Unrecognized SPF value: "hello world v=spf1 unknown:thing -all"',
            str(ctx.exception),
        )

    def test_build_spf_soft_fail(self):
        self.assertEqual('v=spf1', _build_spf([], [], [], [], [], [], None))
        self.assertEqual(
            'v=spf1 -all', _build_spf([], [], [], [], [], [], False)
        )
        self.assertEqual(
            'v=spf1 ~all', _build_spf([], [], [], [], [], [], True)
        )

    def test_build_spf_as(self):
        self.assertEqual(
            'v=spf1 a:some.thing',
            _build_spf(['some.thing'], [], [], [], [], [], None),
        )
        self.assertEqual(
            'v=spf1 a:some.thing a:another.one',
            _build_spf(['some.thing', 'another.one'], [], [], [], [], [], None),
        )

    def test_build_spf_mxs(self):
        self.assertEqual(
            'v=spf1 mx:some.thing',
            _build_spf([], ['some.thing'], [], [], [], [], None),
        )
        self.assertEqual(
            'v=spf1 mx:some.thing mx:another.one',
            _build_spf([], ['some.thing', 'another.one'], [], [], [], [], None),
        )

    def test_build_spf_ip4s(self):
        self.assertEqual(
            'v=spf1 ip4:1.2.3.4',
            _build_spf([], [], ['1.2.3.4'], [], [], [], None),
        )
        self.assertEqual(
            'v=spf1 ip4:1.2.3.4 ip4:5.6.7.8',
            _build_spf([], [], ['1.2.3.4', '5.6.7.8'], [], [], [], None),
        )

    def test_build_spf_ip6s(self):
        self.assertEqual(
            'v=spf1 ip6:2606::1',
            _build_spf([], [], [], ['2606::1'], [], [], None),
        )
        self.assertEqual(
            'v=spf1 ip6:2606::1 ip6:2606::2',
            _build_spf([], [], [], ['2606::1', '2606::2'], [], [], None),
        )

    def test_build_spf_includes(self):
        self.assertEqual(
            'v=spf1 include:some.thing',
            _build_spf([], [], [], [], ['some.thing'], [], None),
        )
        self.assertEqual(
            'v=spf1 include:some.thing include:another.one',
            _build_spf([], [], [], [], ['some.thing', 'another.one'], [], None),
        )

    def test_build_spf_exists(self):
        self.assertEqual(
            'v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d}',
            _build_spf([], [], [], [], [], ['%{ir}.%{l1r+-}._spf.%{d}'], None),
        )
        self.assertEqual(
            'v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} exists:another.one',
            _build_spf(
                [],
                [],
                [],
                [],
                [],
                ['%{ir}.%{l1r+-}._spf.%{d}', 'another.one'],
                None,
            ),
        )

    def test_merge_and_dedup_preserving_order(self):
        # b is empty
        self.assertEqual(
            (3, 2, 1),
            tuple(_merge_and_dedup_preserving_order((3, 2, 1), tuple())),
        )
        # a is empty
        self.assertEqual(
            (6, 5, 4),
            tuple(_merge_and_dedup_preserving_order(tuple(), (6, 5, 4))),
        )
        # both are unique
        self.assertEqual(
            (3, 2, 1, 6, 5, 4),
            tuple(_merge_and_dedup_preserving_order((3, 2, 1), (6, 5, 4))),
        )
        # both are identical
        self.assertEqual(
            (3, 2, 1),
            tuple(_merge_and_dedup_preserving_order((3, 2, 1), (3, 2, 1))),
        )
        # dups in a
        self.assertEqual(
            (3, 2, 1, 4),
            tuple(
                _merge_and_dedup_preserving_order((3, 3, 2, 2, 1), (4, 2, 1))
            ),
        )

    def test_merge_psf(self):
        self.assertEqual(
            'v=spf1', _merge_spf('v=spf1', [], [], [], [], [], [], None)
        )

        value = 'v=spf1 a:example-a.unit.tests mx:example-mx.unit.tests ip4:1.2.3.4 ip6:2606::1 include:example-include.unit.tests exists:%{ir}.%{l1r+-}._spf.%{d} -all'
        got = _merge_spf(
            value,
            ['another-a.unit.tests'],
            ['another-mx.unit.tests.'],
            ['5.6.7.8'],
            ['2606::2'],
            ['another-include.unit.tests.'],
            ['another-exists.unit.tests.'],
            False,
        )
        self.assertEqual(
            'v=spf1 a:example-a.unit.tests a:another-a.unit.tests mx:example-mx.unit.tests mx:another-mx.unit.tests. ip4:1.2.3.4 ip4:5.6.7.8 ip6:2606::1 ip6:2606::2 include:example-include.unit.tests include:another-include.unit.tests. exists:%{ir}.%{l1r+-}._spf.%{d} exists:another-exists.unit.tests. -all',
            got,
        )

        # soft fails
        self.assertEqual(
            'v=spf1 ~all',
            _merge_spf('v=spf1 ~all', [], [], [], [], [], [], True),
        )
        self.assertEqual(
            'v=spf1 ~all',
            _merge_spf('v=spf1 -all', [], [], [], [], [], [], True),
        )
        self.assertEqual(
            'v=spf1 ~all', _merge_spf('v=spf1', [], [], [], [], [], [], True)
        )
        self.assertEqual(
            'v=spf1 ~all',
            _merge_spf('v=spf1 ~all', [], [], [], [], [], [], False),
        )
        self.assertEqual(
            'v=spf1 -all',
            _merge_spf('v=spf1 -all', [], [], [], [], [], [], False),
        )
        self.assertEqual(
            'v=spf1 -all', _merge_spf('v=spf1', [], [], [], [], [], [], False)
        )

        self.assertEqual(
            'v=spf1', _merge_spf('v=spf1', [], [], [], [], [], [], None)
        )

    zone = Zone('unit.tests.', [])
    no_mail = SpfSource('no-mail')
    has_a = SpfSource(
        'a-records', a_records=('a.unit.tests',), merging_enabled=True
    )
    has_mx = SpfSource(
        'mx-records', mx_records=('mx.unit.tests',), merging_enabled=True
    )
    has_ip4 = SpfSource(
        'ip4-addresses',
        ip4_addresses=('1.2.3.4', '5.6.7.8'),
        merging_enabled=True,
    )
    has_ip6 = SpfSource(
        'ip6-addresses', ip6_addresses=('2606::1',), merging_enabled=True
    )
    has_includes = SpfSource(
        'includes', includes=('include.unit.tests',), merging_enabled=True
    )
    has_exists = SpfSource(
        'exists', exists=('%{ir}.%{l1r+-}._spf.%{d}',), merging_enabled=True
    )
    soft_fail = SpfSource('soft-fail', soft_fail=True, merging_enabled=True)
    has_ttl = SpfSource('ttl', ttl=42)

    def test_record_details(self):
        zone = self.zone.copy()

        # add a couple unrelated records
        apex = Record.new(
            zone, '', {'ttl': 43, 'type': 'A', 'value': '1.1.1.1'}
        )
        zone.add_record(apex)
        www = Record.new(
            zone, 'www', {'ttl': 44, 'type': 'CNAME', 'value': zone.name}
        )
        zone.add_record(www)
        txt = Record.new(
            zone,
            'txt',
            {
                'ttl': 45,
                'type': 'TXT',
                'value': 'This is not related and will be ignored',
            },
        )
        zone.add_record(txt)

        self.no_mail.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual('', spf.name)
        self.assertEqual('TXT', spf._type)
        self.assertEqual(self.no_mail.ttl, spf.ttl)
        self.assertEqual(['v=spf1 -all'], spf.values)

        # non-default TTL
        zone = self.zone.copy()
        self.has_ttl.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertEqual(self.has_ttl.ttl, spf.ttl)

    def test_has_apex_txt_without_spf(self):
        zone = self.zone.copy()

        apex_txt = Record.new(
            zone,
            '',
            {
                'ttl': 43,
                'type': 'TXT',
                'values': ['z Hello World 2!', 'Hello World 1!'],
            },
        )
        zone.add_record(apex_txt)

        self.no_mail.populate(zone)
        spf = _find_apex_txt(zone.records)
        # appended
        self.assertEqual(
            ['Hello World 1!', 'v=spf1 -all', 'z Hello World 2!'], spf.values
        )

    def test_has_apex_txt_with_spf(self):
        zone = self.zone.copy()

        apex_txt = Record.new(
            zone,
            '',
            {
                'ttl': 43,
                'type': 'TXT',
                'values': ['Hello World 1!', 'v=spf1 -all', 'z Hello World 2!'],
            },
        )
        zone.add_record(apex_txt)

        self.has_includes.populate(zone)
        spf = _find_apex_txt(zone.records)
        # replaced where it existed
        self.assertEqual(
            [
                'Hello World 1!',
                'v=spf1 include:include.unit.tests -all',
                'z Hello World 2!',
            ],
            spf.values,
        )

    def test_has_apex_txt_with_spf_no_merging(self):
        zone = self.zone.copy()

        apex_txt = Record.new(
            zone,
            '',
            {
                'ttl': 43,
                'type': 'TXT',
                'values': ['Hello World 1!', 'v=spf1 -all', 'z Hello World 2!'],
            },
        )
        zone.add_record(apex_txt)

        with self.assertRaises(SpfException) as ctx:
            self.no_mail.populate(zone)
        exception = ctx.exception
        self.assertEqual(
            'Existing SPF value found in TXT record, merging not enabled',
            str(exception),
        )
        self.assertEqual(apex_txt, exception.record)

    def test_has_spf(self):
        zone = self.zone.copy()

        apex_spf = Record.new(
            zone, '', {'ttl': 43, 'type': 'SPF', 'values': ['v=spf1 -all']}
        )
        apex_spf.context = 'needle'
        zone.add_record(apex_spf)

        with self.assertRaises(SpfException) as ctx:
            self.no_mail.populate(zone)
        exception = ctx.exception
        self.assertEqual(
            'Existing SPF value found, cannot coexist, migrate to TXT, from needle',
            str(exception),
        )
        self.assertEqual(apex_spf, exception.record)

    def test_merging(self):
        zone = self.zone.copy()

        # start with no mail as the base, will create the TXT
        self.no_mail.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual('v=spf1 -all', spf.values[0])

        # add an a
        self.has_a.populate(zone)
        # existing record wasn't modified
        self.assertEqual('v=spf1 -all', spf.values[0])
        # there's a copy that was
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual('v=spf1 a:a.unit.tests -all', spf.values[0])

        # add a mx
        self.has_mx.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual(
            'v=spf1 a:a.unit.tests mx:mx.unit.tests -all', spf.values[0]
        )

        # add a ip6, before ip4
        self.has_ip6.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual(
            'v=spf1 a:a.unit.tests mx:mx.unit.tests ip6:2606::1 -all',
            spf.values[0],
        )

        # add a ip4, after ip6, make sure ip4 still comes first
        self.has_ip4.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual(
            'v=spf1 a:a.unit.tests mx:mx.unit.tests ip4:1.2.3.4 ip4:5.6.7.8 ip6:2606::1 -all',
            spf.values[0],
        )

        # add an include
        self.has_includes.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual(
            'v=spf1 a:a.unit.tests mx:mx.unit.tests ip4:1.2.3.4 ip4:5.6.7.8 ip6:2606::1 include:include.unit.tests -all',
            spf.values[0],
        )

        # add an exists
        self.has_exists.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual(
            'v=spf1 a:a.unit.tests mx:mx.unit.tests ip4:1.2.3.4 ip4:5.6.7.8 ip6:2606::1 include:include.unit.tests exists:%{ir}.%{l1r+-}._spf.%{d} -all',
            spf.values[0],
        )

        # add a soft-fail
        self.soft_fail.populate(zone)
        spf = _find_apex_txt(zone.records)
        self.assertTrue(spf)
        self.assertEqual(
            'v=spf1 a:a.unit.tests mx:mx.unit.tests ip4:1.2.3.4 ip4:5.6.7.8 ip6:2606::1 include:include.unit.tests exists:%{ir}.%{l1r+-}._spf.%{d} ~all',
            spf.values[0],
        )

    def test_list_zones(self):
        # hard-coded [] so not much to do here
        self.assertEqual([], self.no_mail.list_zones())

    def test_verify_dns_lookups(self):
        a_records = [f'a_{i}.unit.tests.' for i in range(11)]

        # too many lookups, but no verify so we're good
        source = SpfSource('test', a_records=a_records)
        self.assertTrue(source)

        # too many lookups, verify is enabled so should blow up
        with self.assertRaises(SpfDnsLookupException):
            source = SpfSource(
                'test', a_records=a_records, verify_dns_lookups=True
            )
