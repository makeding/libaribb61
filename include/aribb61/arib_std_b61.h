#ifndef ARIB_STD_B61_H
#define ARIB_STD_B61_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct ARIB_STD_B61 ARIB_STD_B61;
typedef struct { uint8_t *data; uint32_t size; } ARIB_STD_B61_BUFFER;
typedef struct {
    uint64_t total_packet_count;
    uint64_t decrypted_packet_count;
    uint64_t undecrypted_packet_count;
} ARIB_STD_B61_STATISTICS;
enum { ARIB_STD_B61_OK = 0, ARIB_STD_B61_WARN_UNDECRYPTED = 1,
       ARIB_STD_B61_WARN_UNVERIFIED = 2,
       ARIB_STD_B61_ERROR_INVALID_PARAM = -1, ARIB_STD_B61_ERROR_PROCESS = -2,
       ARIB_STD_B61_ERROR_NO_MEMORY = -3, ARIB_STD_B61_ERROR_STATE = -4 };
/* Instances must be externally serialized. No card I/O occurs until signalling.
 * put copies the input. A positive status accepts it but reports a processing warning.
 * get drains output; its borrowed pointer survives only until the next mutating
 * call. Empty output is not EOF. flush emits incomplete trailing bytes unchanged.
 * reset discards stream state and keys but keeps options. After processing errors,
 * reset before reuse. Options are set before the first nonempty put or after reset.
 * Warning values are combinable flags. Packets requiring unsupported authentication
 * are discarded with WARN_UNVERIFIED. See docs/API.md for CA routing and cipher scope.
 */
ARIB_STD_B61 *create_arib_std_b61(void);
void arib_std_b61_release(ARIB_STD_B61 *ctx);
int arib_std_b61_put(ARIB_STD_B61 *ctx, const ARIB_STD_B61_BUFFER *buf);
int arib_std_b61_get(ARIB_STD_B61 *ctx, ARIB_STD_B61_BUFFER *buf);
int arib_std_b61_flush(ARIB_STD_B61 *ctx);
int arib_std_b61_reset(ARIB_STD_B61 *ctx);
int arib_std_b61_set_verbose(ARIB_STD_B61 *ctx, int enabled);
int arib_std_b61_set_strip(ARIB_STD_B61 *ctx, int enabled);
int arib_std_b61_set_emm_proc(ARIB_STD_B61 *ctx, int enabled);
int arib_std_b61_set_cas_proxy(ARIB_STD_B61 *ctx, const char *address);
int arib_std_b61_get_statistics(const ARIB_STD_B61 *ctx, ARIB_STD_B61_STATISTICS *stats);
#ifdef __cplusplus
}
#endif
#endif
