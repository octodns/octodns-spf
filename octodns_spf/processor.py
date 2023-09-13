#
#
#

from logging import getLogger
from typing import List, Optional

import dns.resolver
from dns.resolver import Answer

from octodns.processor.base import BaseProcessor, ProcessorException


class SpfValueException(ProcessorException):
    pass


class SpfDnsLookupException(ProcessorException):
    pass


class SpfDnsLookupProcessor(BaseProcessor):
    log = getLogger('SpfDnsLookupProcessor')

    def __init__(self, name):
        self.log.debug(f"SpfDnsLookupProcessor: {name}")
        super().__init__(name)

    def _get_spf_from_txt_values(
        self, fqdn: str, values: List[str]
    ) -> Optional[str]:
        self.log.debug(
            f"_get_spf_from_txt_values: record={fqdn} values={values}"
        )

        # SPF values to validate will begin with 'v=spf1 '
        spf = [value for value in values if value.startswith('v=spf1 ')]

        # No SPF values in the TXT record
        if len(spf) == 0:
            return None

        # More than one SPF value resolves as "permerror", https://datatracker.ietf.org/doc/html/rfc7208#section-4.5
        if len(spf) > 1:
            raise SpfValueException(
                f"{fqdn} has more than one SPF value in the TXT record"
            )

        return spf[0]

    def _process_answer(self, answer: Answer) -> List[str]:
        values = []

        for value in answer:
            text_value = value.to_text()
            processed_value = text_value[1:-1].replace('" "', '')
            values.append(processed_value)

        return values

    def check_dns_lookups(
        self, fqdn: str, values: List[str], lookups: int = 0
    ) -> int:
        self.log.debug(
            f"check_dns_lookups: record={fqdn} values={values} lookups={lookups}"
        )

        spf = self._get_spf_from_txt_values(fqdn, values)

        if spf is None:
            return lookups

        terms = spf[len('v=spf1 ') :].split(' ')

        for term in terms:
            if lookups > 10:
                raise SpfDnsLookupException(
                    f"{fqdn} exceeds the 10 DNS lookup limit in the SPF record"
                )

            if term.startswith('ptr'):
                raise SpfValueException(
                    f"{fqdn} uses the deprecated ptr mechanism"
                )

            # These mechanisms cost one DNS lookup each
            if term.startswith(('a', 'mx', 'exists:', 'redirect', 'include:')):
                lookups += 1

            # The include mechanism can result in further lookups after resolving the DNS record
            if term.startswith('include:'):
                domain = term[len('include:') :]
                answer = dns.resolver.resolve(domain, 'TXT')
                answer_values = self._process_answer(answer)
                lookups = self.check_dns_lookups(fqdn, answer_values, lookups)

        return lookups

    def process_source_zone(self, zone, *args, **kwargs):
        for record in zone.records:
            if record._type != 'TXT':
                continue

            if record._octodns.get('lenient'):
                continue

            self.check_dns_lookups(record.fqdn, record.values, 0)

        return zone
