# libaribb61

Streaming MMT/TLV ACAS descrambler extracted from recdvb's acas implementation.
C++20 implementation with a small C API resembling libaribb25's stream API.
See [API contract](docs/API.md) for ownership, errors and current limitations.

Build (CMake, standalone Asio, PC/SC development files):

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j1
ctest --test-dir build --output-on-failure
cmake --install build --prefix "$PWD/build/install"
```

On macOS uses the system PCSC framework; Linux uses libpcsclite.
`pkg-config libaribb61` supplies flags to consumers. No tuner or remuxer included.

Source provenance: extracted from ../recdvb/acas, whose passthrough source records
upstream dantto4k revision 141fd49cf674c9c9e3f3c770a20b3291ff292969.
Preserved recdvb GPLv3 COPYING and upstream Apache-2.0 LICENSE.dantto4k;
this extraction does not relicense upstream material. Original source notices
remain in the implementation, including bundled crypto code.
