#include "aribb61/arib_std_b61.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <utility>
#include <vector>

#include "card.h"
#include "crypto/aes.h"
#include "sections.h"
#include "response.h"
#include "state.h"

ARIB_STD_B61 *aribb61_create_with_card(std::unique_ptr<AcasCardClient> card);

namespace {

constexpr uint8_t kScrambleEven = 0x02;
constexpr uint8_t kTlvSync = 0x7f;
constexpr uint8_t kTlvPacketTypeCompressedIp = 0x03;

void require(bool condition, const char *message)
{
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void put_be16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}

void put_be32(uint8_t *p, uint32_t value)
{
    p[0] = static_cast<uint8_t>(value >> 24);
    p[1] = static_cast<uint8_t>(value >> 16);
    p[2] = static_cast<uint8_t>(value >> 8);
    p[3] = static_cast<uint8_t>(value);
}

uint32_t section_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < size; ++i) {
        crc ^= static_cast<uint32_t>(data[i]) << 24;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x80000000U) ? (crc << 1) ^ 0x04c11db7U : crc << 1;
        }
    }
    return crc;
}

std::vector<uint8_t> make_section(uint8_t table_id, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> section(8, 0);
    section[0] = table_id;
    section[5] = 1; // current_next_indicator: currently applicable section
    section.insert(section.end(), payload.begin(), payload.end());
    section.resize(section.size() + 4);
    const uint16_t section_length = static_cast<uint16_t>(section.size() - 3);
    section[1] = static_cast<uint8_t>(0xb0 | (section_length >> 8));
    section[2] = static_cast<uint8_t>(section_length);
    const uint32_t crc = section_crc32(section.data(), section.size() - 4);
    put_be32(section.data() + section.size() - 4, crc);
    require(section_crc32(section.data(), section.size()) == 0, "invalid test CRC");
    return section;
}

std::vector<uint8_t> make_emm_payload(const std::array<uint8_t, 6>& module_id,
                                      std::initializer_list<uint8_t> associated_information)
{
    std::vector<uint8_t> payload(module_id.begin(), module_id.end());
    payload.push_back(static_cast<uint8_t>(associated_information.size()));
    payload.insert(payload.end(), associated_information);
    return payload;
}

std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& plain,
                                     const std::array<uint8_t, 16>& key,
                                     uint16_t packet_id,
                                     uint32_t sequence)
{
    std::vector<uint8_t> encrypted = plain;
    std::array<uint8_t, 16> iv{};
    put_be16(iv.data(), packet_id);
    put_be32(iv.data() + 2, sequence);
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key.data(), iv.data());
    AES_CTR_xcrypt_buffer(&ctx, encrypted.data() + 8, encrypted.size() - 8);
    return encrypted;
}

class FakeCard final : public AcasCardClient {
public:
    FakeCard()
    {
        identity.ca_system_id = 0x1234;
        identity.module_id = { 1, 2, 3, 4, 5, 6 };
    }

    void set_proxy(const std::string&) override {}

    bool get_identity(acas_card_identity& output) override
    {
        output = identity;
        return true;
    }

    bool process_ecm(const std::vector<uint8_t>& ecm, acas_ecm_result& result) override
    {
        ++ecm_calls;
        result.return_code = fail_next_ecm ? 0xa103 : 0x0800;
        result.broadcaster_id = 0x42;
        if (fail_next_ecm) {
            fail_next_ecm = false;
            return false;
        }
        const uint8_t generation = ecm.at(3);
        result.odd_key.fill(static_cast<uint8_t>(0x10 + generation));
        result.even_key.fill(static_cast<uint8_t>(0x20 + generation));
        current_even_key = result.even_key;
        return true;
    }

    bool process_emm(const std::vector<uint8_t>& emm, uint16_t& return_code) override
    {
        ++emm_calls;
        last_emm = emm;
        return_code = 0x2100;
        return true;
    }

    acas_card_identity identity;
    std::array<uint8_t, 16> current_even_key{};
    std::vector<uint8_t> last_emm;
    int ecm_calls = 0;
    int emm_calls = 0;
    bool fail_next_ecm = false;
};

void test_ecm_metadata_and_emm_selection()
{
    std::vector<uint8_t> ecm(27, 0);
    ecm[0] = 0x21; // F1.
    ecm[1] = 0x12;
    ecm[2] = 0x34;
    ecm[3] = 0x56;
    ecm[4] = 3;
    const std::vector<uint8_t> section = make_section(0x82, ecm);

    std::vector<uint8_t> parsed;
    acas_ecm_metadata metadata;
    require(acas_parse_ecm_section(section.data(), section.size(), parsed, metadata),
            "ECM section was not parsed");
    require(parsed == ecm && metadata.is_f1 &&
            metadata.broadcaster_group_id == 0x1234 &&
            metadata.work_key_id == 0x56 &&
            metadata.scrambling_key_pair_count == 3,
            "ECM metadata mismatch");

    const std::array<uint8_t, 6> other = { 6, 5, 4, 3, 2, 1 };
    const std::array<uint8_t, 6> wanted = { 1, 2, 3, 4, 5, 6 };
    std::vector<uint8_t> emm_data = make_emm_payload(other, { 0x20, 0x01 });
    const std::vector<uint8_t> wanted_payload =
        make_emm_payload(wanted, { 0x20, 0x02, 0xaa });
    emm_data.insert(emm_data.end(), wanted_payload.begin(), wanted_payload.end());
    const std::vector<uint8_t> emm_section = make_section(0x84, emm_data);
    std::vector<uint8_t> selected;
    require(acas_select_emm_payload(emm_section.data(), emm_section.size(), wanted, selected) &&
            selected == wanted_payload,
            "EMM payload selection mismatch");

    std::vector<uint8_t> corrupt = emm_section;
    corrupt.back() ^= 1;
    require(!acas_select_emm_payload(corrupt.data(), corrupt.size(), wanted, selected),
            "corrupt EMM section was accepted");
}

std::vector<uint8_t> make_ecm_card_response(uint16_t return_code)
{
    std::vector<uint8_t> response(6 + 32 + 1 + 2, 0);
    put_be16(response.data() + 4, return_code);
    for (size_t i = 0; i < 32; ++i) {
        response[6 + i] = static_cast<uint8_t>(i);
    }
    response[38] = 0x42;
    response[39] = 0x90;
    response[40] = 0x00;
    return response;
}

void test_ecm_card_response_validation()
{
    acas_ecm_card_response parsed;
    for (uint16_t return_code : { 0x0800, 0x0600, 0x4680 }) {
        const std::vector<uint8_t> response = make_ecm_card_response(return_code);
        require(acas_parse_ecm_card_response(response, parsed) &&
                parsed.return_code == return_code && parsed.broadcaster_id == 0x42 &&
                parsed.encrypted_keys[0] == 0 && parsed.encrypted_keys[31] == 31,
                "viewable ECM card response was rejected");
    }

    std::vector<uint8_t> rejected = make_ecm_card_response(0xa103);
    require(!acas_parse_ecm_card_response(rejected, parsed) &&
            parsed.return_code == 0xa103,
            "without-Kw response was accepted");
    rejected = make_ecm_card_response(0x0800);
    rejected.back() = 1;
    require(!acas_parse_ecm_card_response(rejected, parsed),
            "non-9000 ECM response was accepted");
    rejected.resize(38);
    require(!acas_parse_ecm_card_response(rejected, parsed),
            "ECM response without broadcaster ID was accepted");
}

void test_clear_to_scrambled_key_transition()
{
    auto card = std::make_unique<FakeCard>();
    FakeCard *fake = card.get();
    AcasState state(std::move(card));

    acas_ecm_metadata metadata;
    metadata.broadcaster_group_id = 0x1001;
    metadata.work_key_id = 1;
    std::vector<uint8_t> ecm(27, 0);
    ecm[3] = metadata.work_key_id;

    require(state.on_ecm(ecm, metadata), "initial ECM failed");
    require(fake->ecm_calls == 1, "initial ECM was not sent once");

    const uint16_t packet_id = 0x1234;
    const uint32_t sequence = 0x01020304;
    const std::vector<uint8_t> plain = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    std::vector<uint8_t> encrypted =
        encrypt_payload(plain, fake->current_even_key, packet_id, sequence);
    require(state.decrypt_payload(kScrambleEven, packet_id, sequence,
                                  encrypted.data(), encrypted.size(), encrypted.size(), nullptr) &&
            encrypted == plain,
            "initial even key was not used");

    /* Clear packets bypass AcasState. A following new ECM must replace the key. */
    metadata.work_key_id = 2;
    ecm[3] = metadata.work_key_id;
    fake->fail_next_ecm = true;
    require(!state.on_ecm(ecm, metadata), "failed ECM was accepted");

    std::vector<uint8_t> unchanged = plain;
    require(!state.decrypt_payload(kScrambleEven, packet_id, sequence,
                                   unchanged.data(), unchanged.size(), unchanged.size(), nullptr) &&
            unchanged == plain,
            "old key remained active after a failed ECM");

    require(state.on_ecm(ecm, metadata), "repeated ECM was not retried");
    require(fake->ecm_calls == 3, "ECM retry count mismatch");
    encrypted = encrypt_payload(plain, fake->current_even_key, packet_id, sequence);
    require(state.decrypt_payload(kScrambleEven, packet_id, sequence,
                                  encrypted.data(), encrypted.size(), encrypted.size(), nullptr) &&
            encrypted == plain,
            "new key was not used after clear-to-scrambled transition");

    require(state.on_ecm(ecm, metadata) && fake->ecm_calls == 3,
            "successful ECM was not deduplicated");

    const std::vector<uint8_t> emm_payload =
        make_emm_payload(fake->identity.module_id, { 0x20, 0x01, 0xaa });
    const std::vector<uint8_t> emm_section = make_section(0x84, emm_payload);
    state.on_emm_section(emm_section.data(), emm_section.size());
    require(fake->emm_calls == 1 && fake->last_emm == emm_payload,
            "matching EMM was not sent to the card");
    require(state.on_ecm(ecm, metadata) && fake->ecm_calls == 4,
            "same ECM was not refreshed after EMM update");
}

int collect_output(void *opaque, const uint8_t *data, size_t size)
{
    auto *output = static_cast<std::vector<uint8_t> *>(opaque);
    output->insert(output->end(), data, data + size);
    return 0;
}

void test_clear_authenticated_passthrough()
{
    std::vector<uint8_t> mmtp(12, 0);
    mmtp[0] = 0x02;
    mmtp[2] = 0x01;
    mmtp.insert(mmtp.end(), {
        0x00, 0x00, 0x00, 0x07,
        0x80, 0x01, 0x00, 0x03,
        0x02, 0x00, 0x04,
        0x11, 0x22, 0x33, 0x44,
        0xa1, 0xa2, 0xa3,
    });

    std::vector<uint8_t> packet = {
        kTlvSync, kTlvPacketTypeCompressedIp, 0x00, 0x00,
        0x00, 0x00, 0x61,
    };
    packet.insert(packet.end(), mmtp.begin(), mmtp.end());
    put_be16(packet.data() + 2, static_cast<uint16_t>(packet.size() - 4));

    std::vector<uint8_t> expected = packet;
    expected.erase(expected.end() - 3, expected.end());
    expected.erase(expected.begin() + 28, expected.begin() + 30);
    put_be16(expected.data() + 21, 5);
    put_be16(expected.data() + 25, 1);
    expected[27] &= static_cast<uint8_t>(~0x02);
    put_be16(expected.data() + 2, static_cast<uint16_t>(expected.size() - 4));

    ARIB_STD_B61 *passthrough = create_arib_std_b61();
    require(passthrough != nullptr, "passthrough creation failed");
    std::vector<uint8_t> output;
    ARIB_STD_B61_BUFFER input{packet.data(), static_cast<uint32_t>(packet.size())}, result{};
    require(arib_std_b61_put(passthrough, &input) == 0 &&
            arib_std_b61_flush(passthrough) == 0 &&
            arib_std_b61_get(passthrough, &result) == 0, "passthrough processing failed");
    output.assign(result.data, result.data + result.size);
    arib_std_b61_release(passthrough);
    require(output == expected, "clear authenticated packet mismatch");
}

std::vector<uint8_t> signaling_packet(const std::vector<uint8_t>& message,
                                     uint8_t fragmentation, uint32_t sequence,
                                     uint16_t context = 0)
{
    std::vector<uint8_t> packet(21, 0);
    packet[0] = 0x7f; packet[1] = 3;
    put_be16(packet.data() + 4, context << 4);
    packet[6] = 0x61;
    packet[8] = 2; // signalling payload
    packet[10] = 0x42;
    put_be32(packet.data() + 15, sequence);
    packet[19] = fragmentation << 6;
    packet.insert(packet.end(), message.begin(), message.end());
    put_be16(packet.data() + 2, packet.size() - 4);
    return packet;
}

void feed(ARIB_STD_B61 *ctx, std::vector<uint8_t> packet)
{
    ARIB_STD_B61_BUFFER input{packet.data(), static_cast<uint32_t>(packet.size())};
    require(arib_std_b61_put(ctx, &input) >= 0, "feed failed");
    ARIB_STD_B61_BUFFER output{};
    require(arib_std_b61_get(ctx, &output) == 0, "get failed");
}

void test_signaling_boundaries()
{
    auto fake = std::make_unique<FakeCard>();
    auto *card = fake.get();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    std::vector<uint8_t> ecm(27, 0); ecm[3] = 0x12;
    auto section = make_section(0x82, ecm);
    std::vector<uint8_t> message{0x80, 0x00, 0, 0, 0};
    put_be16(message.data() + 3, section.size());
    message.insert(message.end(), section.begin(), section.end());
    // Future (current_next=0) ECM must not overwrite the current key state.
    auto future = section; future[5] = 0;
    put_be32(future.data() + future.size() - 4, section_crc32(future.data(), future.size() - 4));
    auto future_message = message;
    std::copy(future.begin(), future.end(), future_message.begin() + 5);
    feed(ctx.get(), signaling_packet(future_message, 0, 0));
    require(card->ecm_calls == 0, "future ECM was applied early");
    const auto half = message.size() / 2;
    std::vector<uint8_t> first(message.begin(), message.begin() + half);
    std::vector<uint8_t> last(message.begin() + half, message.end());
    // Orphan tail must not be accepted even if it contains a whole valid ECM.
    feed(ctx.get(), signaling_packet(message, 3, 1));
    require(card->ecm_calls == 0, "orphan tail accepted");
    feed(ctx.get(), signaling_packet(first, 1, 2));
    feed(ctx.get(), signaling_packet(last, 3, 4));
    require(card->ecm_calls == 0, "discontinuous fragments accepted");
    // Same PID in distinct compressed-IP contexts must not join.
    feed(ctx.get(), signaling_packet(first, 1, 5, 1));
    feed(ctx.get(), signaling_packet(last, 3, 6, 2));
    require(card->ecm_calls == 0, "fragments crossed IP contexts");
    auto malformed = signaling_packet(message, 0, 7);
    malformed[6] = 0x62;
    feed(ctx.get(), malformed);
    require(card->ecm_calls == 0, "unknown compressed header parsed as MMTP");
    auto short_length = message; short_length[4] = 1;
    feed(ctx.get(), signaling_packet(short_length, 0, 8));
    require(card->ecm_calls == 0, "message length ignored");
    feed(ctx.get(), signaling_packet(first, 1, UINT32_MAX));
    feed(ctx.get(), signaling_packet(last, 3, 0));
    require(card->ecm_calls == 1, "valid sequence wrap fragments rejected");

    // 0x8003 has a 32-bit length, unlike 0x8000's 16-bit length.
    ecm[3] = 0x13; section = make_section(0x82, ecm);
    std::vector<uint8_t> long_message{0x80, 0x03, 0, 0, 0, 0, 0};
    put_be32(long_message.data() + 3, section.size());
    long_message.insert(long_message.end(), section.begin(), section.end());
    feed(ctx.get(), signaling_packet(long_message, 0, 9));
    require(card->ecm_calls == 2, "32-bit message length rejected");
}

void test_invalid_auth_length_is_unchanged()
{
    std::vector<uint8_t> packet(34, 0);
    packet[0] = 0x7f; packet[1] = 3; packet[6] = 0x61;
    put_be16(packet.data() + 2, packet.size() - 4);
    packet[7] = 2;
    put_be16(packet.data() + 21, 7);
    put_be16(packet.data() + 23, 0x8001);
    put_be16(packet.data() + 25, 3);
    packet[27] = 2; // clear but authenticated
    put_be16(packet.data() + 28, 100); // larger than actual payload
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        create_arib_std_b61(), arib_std_b61_release);
    ARIB_STD_B61_BUFFER input{packet.data(), static_cast<uint32_t>(packet.size())}, output{};
    require(arib_std_b61_put(ctx.get(), &input) == 0, "malformed packet feed failed");
    require(arib_std_b61_get(ctx.get(), &output) == 0 && output.size == packet.size() &&
            std::equal(packet.begin(), packet.end(), output.data), "invalid auth length modified packet");
}

} // namespace

int main()
{
    test_signaling_boundaries();
    test_invalid_auth_length_is_unchanged();
    test_ecm_metadata_and_emm_selection();
    test_ecm_card_response_validation();
    test_clear_to_scrambled_key_transition();
    test_clear_authenticated_passthrough();
    return 0;
}
