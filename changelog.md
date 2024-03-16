# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased - v4]

### Added

- Added unit tests to increase test coverage for the packages util/encoding and util/encryption
- Added fuzzer tests for sign/tbls and sign/cosi packages
- Added two implementations for bls12-381 (circl and kilic) and benchmarks for comparing them
- Added some more benchmarks for the ecies, bn256 and proof modules

### Changed

- Migrated to sized integers for fields in structures to have x-compatibility and solve compilation on 32-bit architectures

### Removed

- 