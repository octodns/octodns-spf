#
#
#

from unittest import TestCase

from octodns_spf import (
    SpfException,
    SpfSource,
    _build_spf,
    _merge_spf,
    _parse_spf,
)


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

    def test_nothing(self):
        self.assertTrue(True)
        SpfSource
