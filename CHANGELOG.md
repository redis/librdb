## [2.1.0] - TBD
<!-- TODO: Update date when PR #88 is merged and v2.1.0 is released -->

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