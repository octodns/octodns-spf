## SPF Value Management for octoDNS

An [octoDNS](https://github.com/octodns/octodns/) provider that supports managing SPF values in TXT records.

### Installation

#### Command line

```
pip install octodns-spf
```

#### requirements.txt/setup.py

Pinning specific versions or SHAs is recommended to avoid unplanned upgrades.

##### Versions

```
# Start with the latest versions and don't just copy what's here
octodns==0.9.14
octodns-spf==0.0.1
```

##### SHAs

```
# Start with the latest/specific versions and don't just copy what's here
-e git+https://git@github.com/octodns/octodns.git@9da19749e28f68407a1c246dfdf65663cdc1c422#egg=octodns
-e git+https://git@github.com/octodns/octodns-spf.git@ec9661f8b335241ae4746eea467a8509205e6a30#egg=octodns_spf
```

### Configuration

#### Options &amp; Defaults

```yaml
providers:
  spf-google:
    class: octodns_spf.SpfSource
    # See https://datatracker.ietf.org/doc/html/rfc7208#section-5 for the
    # details of the various mechinisms below. Each is an array of zero or more
    # items to be added to the SPF record. Mechinisms are specified in the order
    # the parameters are listed below and value order is preserved.
    # (default: empty list)
    a_records: []
    mx_records: []
    ip4_addresses: []
    ip6_addresses: []
    includes: []
    exists: []
    # The "all" value to be appended onto the SPF value, there's not a clear
    # consensus on best practice here, but there does seem to be a slight leaning
    # towards hard-failing, "-all". Soft-fail can be enabled by setting this
    # value to `true`. If for some reason you donot want to specify a fail mode,
    # this can be set to `null` and it will be ommited.
    # See https://news.ycombinator.com/item?id=34344590 for some discussion
    # (default: false, hard fail)
    soft_fail: false
    # Wether or not this provider will merge it's configuration with any
    # prexisting SPF value in an APEX TXT record. If `false` an error will be
    # thrown. If `true` the existing values, wether from a previous SpfSource or
    # any other provider, will be preserved and this provider's config will be
    # appended onto each mechinism.
    merging_enabled: false
    ttl: 3600
```

#### Read World Example

A base that disables all email applied to all Zones

```yaml
providers:
  spf-base:
    class: octodns_spf.SpfSource
```

A follow on source that will add Google Workspace's recommended config

```yaml
providers:
  spf-mail:
    class: octodns_spf.SpfSource
    includes:
      - _spf.google.com
      - _spf.salesforce.com
    soft_fail: true
    merging_enabled: true
```

Per https://support.google.com/a/answer/10684623?hl=en and
https://help.salesforce.com/s/articleView?id=000382664&type=1

Zones would have one or more of these providers added to their sources list

```yaml
zones:
  ...

  # main zone that will be generally used for email
  github.com.:
    sources:
      - config
      - spf-base
      - spf-mail
    targets:
      ...

  # ancilary zone, pretty much everything else
  githubusercontent.com.:
    sources:
      - config
      - spf-base
    targets:
      ...

  ...
```

### Support Information

#### Records

TXT

### Development

See the [/script/](/script/) directory for some tools to help with the development process. They generally follow the [Script to rule them all](https://github.com/github/scripts-to-rule-them-all) pattern. Most useful is `./script/bootstrap` which will create a venv and install both the runtime and development related requirements. It will also hook up a pre-commit hook that covers most of what's run by CI.
