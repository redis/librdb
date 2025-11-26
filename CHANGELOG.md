## [2.0.0] - 2025-11-26

### Breaking Changes
- **RdbxRespWriter**: Renamed `delete` member to `destroy` for C++ compatibility
  - `delete` is a reserved keyword in C++
  - `destroy` more accurately describes the operation (cleanup + memory deallocation)
- Renamed **respFileWriteDelete** to **respFileWriteDestroy**.
- Renamed **redisLoaderDelete** to **redisLoaderDestroy**.