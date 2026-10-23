#include <aribb61/arib_std_b61.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
int main(void) {
    uint8_t packet[] = {0x7f, 0xfe, 0, 3, 1, 2, 3};
    uint8_t null_packet[] = {0x7f, 0xff, 0, 1, 0};
    ARIB_STD_B61 *ctx = create_arib_std_b61();
    ARIB_STD_B61_BUFFER in, out;
    ARIB_STD_B61_STATISTICS stats;
    CHECK(ctx);
    CHECK(arib_std_b61_put(ctx, NULL) == -1);
    in.data = NULL; in.size = 1;
    CHECK(arib_std_b61_put(ctx, &in) == -1);
    for (size_t split = 0; split <= sizeof(packet); ++split) {
        CHECK(arib_std_b61_reset(ctx) == 0);
        in.data = packet; in.size = split;
        CHECK(arib_std_b61_put(ctx, &in) == 0);
        in.data = packet + split; in.size = sizeof(packet) - split;
        CHECK(arib_std_b61_put(ctx, &in) == 0);
        CHECK(arib_std_b61_get(ctx, &out) == 0);
        CHECK(out.size == sizeof(packet) && !memcmp(out.data, packet, sizeof(packet)));
        CHECK(arib_std_b61_get(ctx, &out) == 0 && out.size == 0);
        CHECK(arib_std_b61_get_statistics(ctx, &stats) == 0 && stats.total_packet_count == 1);
        CHECK(arib_std_b61_set_strip(ctx, 1) == -4);
    }
    /* Batched packets preserve order and retain only the incomplete tail. */
    CHECK(arib_std_b61_reset(ctx) == 0);
    uint8_t batch[2 * sizeof(packet) + 3];
    memcpy(batch, packet, sizeof(packet));
    memcpy(batch + sizeof(packet), packet, sizeof(packet));
    memcpy(batch + 2 * sizeof(packet), packet, 3);
    in.data = batch; in.size = sizeof(batch);
    CHECK(arib_std_b61_put(ctx, &in) == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0);
    CHECK(out.size == 2 * sizeof(packet) && !memcmp(out.data, batch, out.size));
    in.data = packet + 3; in.size = sizeof(packet) - 3;
    CHECK(arib_std_b61_put(ctx, &in) == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0);
    CHECK(out.size == sizeof(packet) && !memcmp(out.data, packet, out.size));
    CHECK(arib_std_b61_get_statistics(ctx, &stats) == 0 && stats.total_packet_count == 3);
    CHECK(arib_std_b61_reset(ctx) == 0);
    CHECK(arib_std_b61_set_strip(ctx, 1) == 0);
    in.data = null_packet; in.size = sizeof(null_packet);
    CHECK(arib_std_b61_put(ctx, &in) == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0 && out.size == 0);
    in.data = packet; in.size = 3;
    CHECK(arib_std_b61_put(ctx, &in) == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0 && out.size == 0);
    CHECK(arib_std_b61_flush(ctx) == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0 && out.size == 3 && !memcmp(out.data, packet, 3));
    CHECK(arib_std_b61_flush(ctx) == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0 && out.size == 0);
    CHECK(arib_std_b61_reset(ctx) == 0);
    CHECK(arib_std_b61_get_statistics(ctx, &stats) == 0 && stats.total_packet_count == 0);
    /* Encrypted MMTP without ECM must remain byte-identical and observable. */
    uint8_t scrambled[37] = {0x7f, 0x03, 0, 33, 0, 0, 0x61};
    scrambled[7] = 0x02; /* MMTP extension present */
    scrambled[22] = 5;   /* extension length */
    scrambled[23] = 0x80; scrambled[24] = 1; /* last multitype: B61 */
    scrambled[26] = 1; scrambled[27] = 0x10; /* even */
    in.data = scrambled; in.size = sizeof(scrambled);
    CHECK(arib_std_b61_put(ctx, &in) == ARIB_STD_B61_WARN_UNDECRYPTED);
    CHECK(arib_std_b61_get_statistics(ctx, &stats) == 0);
    CHECK(stats.undecrypted_packet_count == 1 && stats.decrypted_packet_count == 0);
    CHECK(arib_std_b61_get(ctx, &out) == 0 && out.size == sizeof(scrambled));
    CHECK(!memcmp(out.data, scrambled, sizeof(scrambled)));
    arib_std_b61_release(ctx);
    arib_std_b61_release(NULL);
    return 0;
}
