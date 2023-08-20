#
#
#

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


class SpfSource(BaseSource):
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('TXT'))

    DEFAULT_TTL = 3600

    def __init__(self, id, ttl=DEFAULT_TTL):
        self.log = getLogger(f'SpfSource[{id}]')
        self.log.debug('__init__: id=%s, ttl=%d', id, ttl)
        super().__init__(id)
        self.ttl = ttl

    def populate(self, zone, target=False, lenient=False):
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        spf_value = 'v=spf1 -all'
        self.log.debug('populate: spf value="%s"', spf_value)

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
            record.values.append(spf_value)
            # replace with our updated version
            zone.add_record(record, lenient=lenient, replace=True)
        else:
            record = Record.new(
                zone, '', {'ttl': self.ttl, 'type': 'TXT', 'value': spf_value}
            )
            zone.add_record(record, lenient=lenient)

        self.log.info(
            'populate:   found %s records, exists=False',
            len(zone.records) - before,
        )
