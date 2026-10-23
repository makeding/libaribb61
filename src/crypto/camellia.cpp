#include "crypto/camellia.h"

#include <limits>
#include <memory>

#include <openssl/evp.h>

bool camellia128_ctr_xcrypt(const uint8_t key[16], const uint8_t iv[16],
                            uint8_t *data, size_t size)
{
    if ((!data && size != 0) || size > static_cast<size_t>(std::numeric_limits<int>::max())) return false;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context || EVP_EncryptInit_ex(context.get(), EVP_camellia_128_ctr(), nullptr, key, iv) != 1) return false;
    int written = 0;
    if (size != 0 && EVP_EncryptUpdate(context.get(), data, &written, data,
                                       static_cast<int>(size)) != 1) return false;
    if (written != static_cast<int>(size)) return false;
    uint8_t final_block[EVP_MAX_BLOCK_LENGTH];
    int final_size = 0;
    return EVP_EncryptFinal_ex(context.get(), final_block, &final_size) == 1 && final_size == 0;
}
