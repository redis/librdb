## [2.3.0] - 2026-06-03

### New Features
- **RDB v14 Support — Stream XNACK (`RDB_TYPE_STREAM_LISTPACKS_5`)**:
  parse and emit the per-consumer-group NACK zone added in Redis 8.8.
  - New callback `handleStreamNackZoneEntry` on
    `RdbHandlersDataCallbacks`, fired once per NACKed stream ID after
    the consumers section of each consumer group.
- **RDB v14 Support — Array (`RDB_TYPE_ARRAY`)**: parse and emit the
  new top-level type added in Redis 8.8.
  - API additions (all additive, ABI-compatible):
    `RDB_DATA_TYPE_ARRAY` enum value, `handleArrayMetadata` /
    `handleArrayElement` callbacks on `RdbHandlersDataCallbacks`,
    `RDB_ARRAY_INSERT_IDX_NONE` sentinel (= `UINT64_MAX`), and
    `RDB_ERR_ARRAY_INVALID_STATE` error code.

---

## [2.2.0] - 2026-03-01

### New Features
- **RDB v13 Support**: Add support for RDB version 13 (#93)
  - Ensures compatibility with latest Redis RDB format, specifically key-metadata and stream IDMP
- **RESTOREMODAUX Downgrading**: Support downgrading RESTOREMODAUX commands (#92)
  - Enables compatibility when restoring to older Redis versions
- **Redis Enterprise Support**: Skip new Redis Enterprise RDB_OPCODE_SLOT_NUM opcode (#91)
  - Improves compatibility with Redis Enterprise RDB files
- **Authentication**: Add LIBRDB_AUTH environment variable support for password authentication
  - Simplifies authentication configuration in automated environments

### Bug Fixes
- **Error Handling**: Add goto cleanup on rdb-cli return error
  - Ensures proper resource cleanup on error conditions

---

## [2.1.0] - 2025-12-11

### New Features
- **TLS/SSL Support**: Add comprehensive TLS/SSL connection support (#88, closes #39, #59)
  - Server certificate verification with CA certificates
  - Mutual TLS authentication with client certificates
  - Flexible configuration: custom ciphers, SNI support
  - New API: `RdbxSSLConfig` structure for TLS configuration
  - Extended `RDBX_createRespToRedisTcp()` with optional SSL config parameter
  - SSL wrapper around socket I/O operations
  - New error codes for TLS-specific failures
- **Enhanced Networking**: Improved hostname resolution with IPv4/IPv6 support (#88)
  - Better compatibility across different network configurations
- **CLI Enhancements**: Add TLS-related command-line flags (#88)
  - `--tls`: Enable TLS/SSL connection
  - `--cacert`: Specify CA certificate file
  - `--cert`: Specify client certificate file
  - `--key`: Specify client private key file
  - Additional TLS configuration options

---

## [2.0.0] - 2025-12-02

### Breaking Changes
- **C++ Compatibility**: Renamed functions and struct members containing the reserved C++ keyword `delete` to `destroy` (#85)
  - `RdbxRespWriter.delete` → `RdbxRespWriter.destroy`
  - `respFileWriteDelete()` → `respFileWriteDestroy()`
  - `redisLoaderDelete()` → `redisLoaderDestroy()`
  - The new name `destroy` more accurately describes the operation (cleanup + memory deallocation)

### New Features
- **Script Loading**: Add option to `SCRIPT LOAD` from RDB auxiliary section (#82)
  - Enables loading Lua scripts stored in RDB auxiliary data
- **Key Privacy**: Add option to hide keys in log and print sha256(key) instead (#66)
  - RDB2PRINT: Add `%h` format specifier to output sha256(key) (#79)
  - Useful for privacy-sensitive environments
- **Redis Enterprise Support**: Add parsing support for `RDB_OPCODE_RAM_LRU` opcode (No-op) (#67)
  - Improves compatibility with Redis Enterprise RDB files
- **Redis 8.x Support**: Add Redis 8.0 and 8.2 to CI testing (#78)
  - Ensures compatibility with latest Redis versions

### Bug Fixes
- **Memory Safety**: Fix double-free segmentation fault in filter handlers cleanup (#77)
- **Networking**: Fix recv() 120s timeout on EAGAIN by retrying indefinitely (#69)
  - Prevents premature connection failures on slow networks
- **Parsing**: Fix LFU parsing for values larger than 127 (#62)
  - Corrects handling of Least Frequently Used eviction policy metadata
- **Command Filtering**: Fix `RDBX_writeFromCmdNumber()` option and filtering (#80)
  - Ensures proper command number filtering in RESP output

### Platform Support
- **macOS**: Add macOS/OSX support (#65)
  - Fix installation on macOS without GNU Coreutils (#75)
  - Fix soft-links installation on non-Darwin kernels (#83)
- **Cross-Platform**: Fix installation to custom directories (#74)
  - Improves portability across different Unix-like systems

### Documentation
- Update CHANGELOG.md with comprehensive release notes

---

## [1.0.0] - Initial Release

First stable release of librdb.