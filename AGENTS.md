# Developer Agent Guide for octoDNS SPF Provider

This repository contains the SPF value management source and processor for octoDNS. It enables managing SPF values in TXT records, including merging configuration options with existing SPF records and verifying SPF records (e.g., DNS lookup limit checks).

> [!IMPORTANT]
> **Core Workflow and Guidelines**
>
> All agents working on this repository must read and follow the general instructions and workflow guidelines defined in the core octoDNS `AGENTS.md` file.
> - **Local check**: Look for the file at `../octodns/AGENTS.md`.
> - **Remote check**: If the local file is not available, fetch it from GitHub: [octoDNS Core AGENTS.md](https://github.com/octodns/octodns/raw/refs/heads/main/AGENTS.md).
>
> You must align your code structure, style, pull request guidelines, and overall development workflows with the instructions specified there.

## Repository & Module Information

### Key Components

- **Source Class**: [SpfSource](file:///home/ross/octodns/octodns-spf/octodns_spf/source.py) (defined in [octodns_spf/source.py](file:///home/ross/octodns/octodns-spf/octodns_spf/source.py)). This manages generating SPF records, merging configurations with existing TXT records when `merging_enabled` is set, and optionally verifying DNS lookups on initialization.
- **Processor Class**: [SpfDnsLookupProcessor](file:///home/ross/octodns/octodns-spf/octodns_spf/processor.py) (defined in [octodns_spf/processor.py](file:///home/ross/octodns/octodns-spf/octodns_spf/processor.py)). It validates that SPF records do not exceed the RFC 7208 limit of 10 DNS lookups, do not use the deprecated `ptr` mechanism, and do not contain multiple SPF records.

### Key Workflows & Features

1. **Supported Record Types**: `TXT`.
2. **Dynamic Routing Support**: Not supported (`SUPPORTS_GEO=False`, `SUPPORTS_DYNAMIC=False`).
3. **SPF Validation**:
   - Checks lookup counts recursively for `a`, `mx`, `exists:`, `redirect`, and `include:` mechanisms.
   - Raises `SpfDnsLookupException` if lookups exceed 10.
   - Raises `SpfValueException` on deprecated `ptr` mechanism or multiple SPF values.

## Development & Testing

- **Setup Script**: Run `./script/bootstrap` to create a virtual environment, install runtime and development dependencies (including `black`, `isort`, `pyflakes`, and `pytest`), and configure pre-commit hooks.
- **Test Suite**: Run unit tests using `pytest` via `./script/test` (or `pytest tests/`). Test files are located in [tests/](file:///home/ross/octodns/octodns-spf/tests):
  - [test_source_octodns_spf.py](file:///home/ross/octodns/octodns-spf/tests/test_source_octodns_spf.py)
  - [test_processor_octodns_spf.py](file:///home/ross/octodns/octodns-spf/tests/test_processor_octodns_spf.py)
- **Code Coverage**: Verify code coverage using `./script/coverage`.

## Key Constraints & Behaviors

- **Python Version**: Targets Python `>=3.9`.
- **Formatting**: Code formatting is enforced via `black` (version `>=26.0.0,<27.0.0`) and `isort`.
