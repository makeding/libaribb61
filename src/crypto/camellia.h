#ifndef ARIBB61_CAMELLIA_H
#define ARIBB61_CAMELLIA_H

#include <cstddef>
#include <cstdint>

bool camellia128_ctr_xcrypt(const uint8_t key[16], const uint8_t iv[16],
                            uint8_t *data, size_t size);

#endif
