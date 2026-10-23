#include <sstream>
#include <iostream>
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
#include "stream_test_support.h"

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
                                      std::initializer_list<uint8_t> variable_information)
{
    std::vector<uint8_t> payload(module_id.begin(), module_id.end());
    payload.push_back(static_cast<uint8_t>(2 + variable_information.size()));
    payload.push_back(0x20);
    payload.push_back(0x42);
    payload.insert(payload.end(), variable_information);
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
        if (unavailable) { result.error = "test reader unavailable"; return false; }
        result.response_valid = true;
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
    bool unavailable = false;
};

void test_ecm_metadata_and_emm_selection()
{
    std::vector<uint8_t> ecm(27, 0);
    ecm[0] = 26;
    ecm[1] = 0x21;
    ecm[2] = 0x12;
    ecm[3] = 0x56;
    const std::vector<uint8_t> section = make_section(0x82, ecm);

    std::vector<uint8_t> parsed;
    acas_ecm_metadata metadata;
    require(acas_parse_ecm_section(section.data(), section.size(), parsed, metadata),
            "ECM section was not parsed");
    require(parsed == ecm && metadata.associated_information_length == 26 &&
            metadata.protocol_number == 0x21 && metadata.broadcaster_id == 0x12 &&
            metadata.work_key_id == 0x56,
            "ECM metadata mismatch");

    const std::array<uint8_t, 6> other = { 6, 5, 4, 3, 2, 1 };
    const std::array<uint8_t, 6> wanted = { 1, 2, 3, 4, 5, 6 };
    std::vector<uint8_t> emm_data = make_emm_payload(other, { 0x20, 0x01 });
    const std::vector<uint8_t> wanted_payload =
        make_emm_payload(wanted, { 0x20, 0x02, 0xaa });
    emm_data.insert(emm_data.end(), wanted_payload.begin(), wanted_payload.end());
    const std::vector<uint8_t> emm_section = make_section(0x84, emm_data);
    std::vector<std::vector<uint8_t>> selected;
    require(acas_select_emm_payloads(emm_section.data(), emm_section.size(), wanted, selected) &&
            selected == std::vector<std::vector<uint8_t>>{wanted_payload},
            "EMM payload selection mismatch");

    std::vector<uint8_t> corrupt = emm_section;
    corrupt.back() ^= 1;
    require(!acas_select_emm_payloads(corrupt.data(), corrupt.size(), wanted, selected),
            "corrupt EMM section was accepted");

    std::vector<uint8_t> invalid_ecm = ecm;
    invalid_ecm[0]--;
    const std::vector<uint8_t> invalid_ecm_section = make_section(0x82, invalid_ecm);
    require(!acas_parse_ecm_section(invalid_ecm_section.data(), invalid_ecm_section.size(), parsed, metadata),
            "ECM with mismatched associated-information length was accepted");
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
    for (uint16_t return_code : { 0x0800, 0x0600, 0x4680, 0x8700 }) {
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
    metadata.broadcaster_id = 0x10;
    metadata.work_key_id = 1;
    std::vector<uint8_t> ecm(27, 0);
    ecm[3] = metadata.work_key_id;

    require(state.on_ecm(0x42, ecm, metadata), "initial ECM failed");
    require(fake->ecm_calls == 1, "initial ECM was not sent once");

    const uint16_t packet_id = 0x1234;
    const uint32_t sequence = 0x01020304;
    const std::vector<uint8_t> plain = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    std::vector<uint8_t> encrypted =
        encrypt_payload(plain, fake->current_even_key, packet_id, sequence);
    require(state.decrypt_payload(0x42, ScramblingAlgorithm::Aes128Ctr, kScrambleEven, packet_id, sequence,
                                  encrypted.data(), encrypted.size(), encrypted.size(), nullptr) &&
            encrypted == plain,
            "initial even key was not used");

    /* Clear packets bypass AcasState. A following new ECM must replace the key. */
    metadata.work_key_id = 2;
    ecm[3] = metadata.work_key_id;
    fake->fail_next_ecm = true;
    require(!state.on_ecm(0x42, ecm, metadata), "failed ECM was accepted");

    std::vector<uint8_t> unchanged = plain;
    require(!state.decrypt_payload(0x42, ScramblingAlgorithm::Aes128Ctr, kScrambleEven, packet_id, sequence,
                                   unchanged.data(), unchanged.size(), unchanged.size(), nullptr) &&
            unchanged == plain,
            "old key remained active after a failed ECM");

    require(state.on_ecm(0x42, ecm, metadata), "repeated ECM was not retried");
    require(fake->ecm_calls == 3, "ECM retry count mismatch");
    encrypted = encrypt_payload(plain, fake->current_even_key, packet_id, sequence);
    require(state.decrypt_payload(0x42, ScramblingAlgorithm::Aes128Ctr, kScrambleEven, packet_id, sequence,
                                  encrypted.data(), encrypted.size(), encrypted.size(), nullptr) &&
            encrypted == plain,
            "new key was not used after clear-to-scrambled transition");

    require(state.on_ecm(0x42, ecm, metadata) && fake->ecm_calls == 3,
            "successful ECM was not deduplicated");

    const std::vector<uint8_t> emm_payload =
        make_emm_payload(fake->identity.module_id, { 0x01, 0xaa });
    const std::vector<uint8_t> second_emm_payload =
        make_emm_payload(fake->identity.module_id, { 0x02, 0xbb });
    std::vector<uint8_t> emm_data = emm_payload;
    emm_data.insert(emm_data.end(), second_emm_payload.begin(), second_emm_payload.end());
    const std::vector<uint8_t> emm_section = make_section(0x84, emm_data);
    state.on_emm_section(emm_section.data(), emm_section.size());
    require(fake->emm_calls == 2 && fake->last_emm == second_emm_payload,
            "matching EMM payloads were not all sent to the card");
    state.on_emm_section(emm_section.data(), emm_section.size());
    require(fake->emm_calls == 2, "matching EMM payloads were not deduplicated");
    require(state.on_ecm(0x42, ecm, metadata) && fake->ecm_calls == 4,
            "same ECM was not refreshed after EMM update");

    const std::array<uint8_t, 6> other_module = { 6, 5, 4, 3, 2, 1 };
    const std::vector<uint8_t> unrelated_emm = make_emm_payload(other_module, { 0x03 });
    const std::vector<uint8_t> unrelated_section = make_section(0x84, unrelated_emm);
    state.on_emm_section(unrelated_section.data(), unrelated_section.size());
    require(fake->emm_calls == 2, "unrelated EMM was sent to the card");

    const std::vector<uint8_t> unprocessed_emm =
        make_emm_payload(fake->identity.module_id, { 0x03, 0xcc });
    std::vector<uint8_t> malformed_data = unprocessed_emm;
    malformed_data.insert(malformed_data.end(), fake->identity.module_id.begin(), fake->identity.module_id.end());
    malformed_data.push_back(2);
    malformed_data.push_back(0x20);
    const std::vector<uint8_t> malformed_section = make_section(0x84, malformed_data);
    state.on_emm_section(malformed_section.data(), malformed_section.size());
    require(fake->emm_calls == 2, "malformed later EMM payload caused partial card processing");
}

int collect_output(void *opaque, const uint8_t *data, size_t size)
{
    auto *output = static_cast<std::vector<uint8_t> *>(opaque);
    output->insert(output->end(), data, data + size);
    return 0;
}

void test_clear_authenticated_rejection()
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

    ARIB_STD_B61 *decoder = create_arib_std_b61();
    require(decoder != nullptr, "decoder creation failed");
    std::vector<uint8_t> output;
    ARIB_STD_B61_BUFFER input{packet.data(), static_cast<uint32_t>(packet.size())}, result{};
    require(arib_std_b61_put(decoder, &input) == ARIB_STD_B61_WARN_UNVERIFIED &&
            arib_std_b61_flush(decoder) == 0 &&
            arib_std_b61_get(decoder, &result) == 0, "authenticated packet processing failed");
    if (result.size != 0) output.assign(result.data, result.data + result.size);
    ARIB_STD_B61_STATISTICS stats{};
    require(arib_std_b61_get_statistics(decoder, &stats) == 0 &&
            stats.total_packet_count == 1 && stats.decrypted_packet_count == 0 &&
            stats.undecrypted_packet_count == 0, "clear authenticated packet changed decryption statistics");
    arib_std_b61_release(decoder);
    require(output.empty(), "clear authenticated packet was forwarded");
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
    const auto mpt = aribb61_test::make_mpt(1, 1,
        aribb61_test::access_control_descriptor(0x1234, 0x42), {
            aribb61_test::mpt_asset(1, 0x100, {})
        });
    feed(ctx.get(), aribb61_test::make_signaling_tlv(0, 0, 0, aribb61_test::make_pa({mpt})));
    std::vector<uint8_t> ecm(27, 0); ecm[0] = 26; ecm[3] = 0x12;
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

    auto make_ecm_message = [](std::vector<uint8_t> ecm_payload) {
        auto ecm_section = make_section(0x82, ecm_payload);
        std::vector<uint8_t> ecm_message{0x80, 0x00, 0, 0, 0};
        put_be16(ecm_message.data() + 3, ecm_section.size());
        ecm_message.insert(ecm_message.end(), ecm_section.begin(), ecm_section.end());
        return ecm_message;
    };
    auto next_ecm = ecm;
    next_ecm[10] = 1;
    auto next_message = make_ecm_message(next_ecm);
    const auto third = next_message.size() / 3;
    std::vector<uint8_t> first_third(next_message.begin(), next_message.begin() + third);
    std::vector<uint8_t> middle_third(next_message.begin() + third, next_message.begin() + third * 2);
    std::vector<uint8_t> last_third(next_message.begin() + third * 2, next_message.end());
    // Exact retransmissions must preserve the partial message, including after
    // a middle fragment has been accepted.
    feed(ctx.get(), signaling_packet(first_third, 1, 20));
    feed(ctx.get(), signaling_packet(first_third, 1, 20));
    feed(ctx.get(), signaling_packet(middle_third, 2, 21));
    feed(ctx.get(), signaling_packet(middle_third, 2, 21));
    feed(ctx.get(), signaling_packet(last_third, 3, 22));
    require(card->ecm_calls == 2, "duplicate fragments disrupted assembly");

    auto conflicting_ecm = ecm;
    conflicting_ecm[10] = 2;
    auto conflicting_message = make_ecm_message(conflicting_ecm);
    auto conflict_first = std::vector<uint8_t>(message.begin(), message.begin() + third);
    auto conflict_middle = std::vector<uint8_t>(message.begin() + third, message.begin() + third * 2);
    auto conflicting_middle = std::vector<uint8_t>(conflicting_message.begin() + third,
                                                   conflicting_message.begin() + third * 2);
    auto conflict_last = std::vector<uint8_t>(conflicting_message.begin() + third * 2, conflicting_message.end());
    auto conflicting_section = make_section(0x82, conflicting_ecm);
    require(section_crc32(conflicting_section.data(), conflicting_section.size()) == 0,
            "conflicting test ECM CRC invalid");
    // A same-sequence payload that differs from the stored fragment invalidates
    // the assembly; a new first fragment can recover afterwards.
    feed(ctx.get(), signaling_packet(conflict_first, 1, 30));
    feed(ctx.get(), signaling_packet(conflict_middle, 2, 31));
    feed(ctx.get(), signaling_packet(conflicting_middle, 2, 31));
    feed(ctx.get(), signaling_packet(conflict_last, 3, 32));
    require(card->ecm_calls == 2, "conflicting duplicate fragment was accepted");
    auto recovery_ecm = ecm;
    recovery_ecm[10] = 3;
    auto recovery_message = make_ecm_message(recovery_ecm);
    const auto recovery_half = recovery_message.size() / 2;
    auto recovery_first = std::vector<uint8_t>(recovery_message.begin(),
                                               recovery_message.begin() + recovery_half);
    auto recovery_last = std::vector<uint8_t>(recovery_message.begin() + recovery_half,
                                              recovery_message.end());
    feed(ctx.get(), signaling_packet(recovery_first, 1, 33));
    feed(ctx.get(), signaling_packet(recovery_last, 3, 34));
    require(card->ecm_calls == 3, "fragment assembly did not recover after conflict");

    // Data transmission messages must not supply ECM keys.
    ecm[3] = 0x13; section = make_section(0x82, ecm);
    std::vector<uint8_t> long_message{0x80, 0x03, 0, 0, 0, 0, 0};
    put_be32(long_message.data() + 3, section.size());
    long_message.insert(long_message.end(), section.begin(), section.end());
    feed(ctx.get(), signaling_packet(long_message, 0, 9));
    require(card->ecm_calls == 3, "data transmission message supplied ECM keys");
    auto short_message = message; short_message[1] = 2;
    feed(ctx.get(), signaling_packet(short_message, 0, 10));
    require(card->ecm_calls == 3, "short section message supplied ECM keys");
    auto trailing = message; trailing.push_back(0);
    feed(ctx.get(), signaling_packet(trailing, 0, 11));
    require(card->ecm_calls == 3, "message trailing bytes accepted");
}

void test_emm_option()
{
    for (bool enabled : {false, true}) {
        auto fake = std::make_unique<FakeCard>();
        auto *card = fake.get();
        auto section = make_section(0x84, make_emm_payload(card->identity.module_id, {0x11, 0x22}));
        std::vector<uint8_t> message{0x80, 0x00, 0, 0, 0};
        put_be16(message.data() + 3, section.size());
        message.insert(message.end(), section.begin(), section.end());
        std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
            aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
        if (enabled) require(arib_std_b61_set_emm_proc(ctx.get(), 1) == 0, "EMM option failed");
        const auto cat = aribb61_test::make_cat(1, 0x1234, 0x42);
        feed(ctx.get(), aribb61_test::make_signaling_tlv(0, 1, 0,
            aribb61_test::make_mmt_section_message(0x8001, cat)));
        feed(ctx.get(), signaling_packet(message, 0, 0));
        require(card->emm_calls == (enabled ? 1 : 0), "EMM option was ignored");
    }
}

void test_invalid_auth_length_is_rejected()
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
    require(arib_std_b61_put(ctx.get(), &input) == ARIB_STD_B61_WARN_UNVERIFIED, "malformed packet warning missing");
    require(arib_std_b61_get(ctx.get(), &output) == 0 && output.size == 0,
            "invalid authenticated packet was forwarded");
    ARIB_STD_B61_STATISTICS stats{};
    require(arib_std_b61_get_statistics(ctx.get(), &stats) == 0 &&
            stats.total_packet_count == 1 && stats.decrypted_packet_count == 0 &&
            stats.undecrypted_packet_count == 0,
            "invalid authenticated packet changed decryption statistics");
}

} // namespace

void test_diagnostics_and_recovery()
{
    auto owned = std::make_unique<FakeCard>();
    auto *fake = owned.get();
    AcasState state(std::move(owned));
    std::ostringstream log;
    auto *previous = std::cerr.rdbuf(log.rdbuf());
    acas_ecm_metadata metadata{};
    std::vector<uint8_t> ecm(32, 0);
    require(state.on_ecm(0x42, ecm, metadata), "diagnostics and recovery");
    require(log.str().empty(), "diagnostics and recovery");
    ecm[3] = 1;
    fake->unavailable = true;
    require(!state.on_ecm(0x42, ecm, metadata), "diagnostics and recovery");
    const auto first = log.str();
    require(first.find("unavailable") != std::string::npos, "diagnostics and recovery");
    require(first.find("rejected") == std::string::npos, "diagnostics and recovery");
    require(first.find("return=") == std::string::npos, "diagnostics and recovery");
    require(!state.on_ecm(0x42, ecm, metadata), "diagnostics and recovery");
    require(log.str() == first, "diagnostics and recovery");
    require(fake->ecm_calls == 3, "diagnostics and recovery");
    fake->unavailable = false;
    require(state.on_ecm(0x42, ecm, metadata), "diagnostics and recovery");
    require(log.str().find("recovered") != std::string::npos, "diagnostics and recovery");
    state.set_verbose(true);
    ecm[3] = 2;
    require(state.on_ecm(0x42, ecm, metadata), "diagnostics and recovery");
    require(log.str().find("updated") != std::string::npos, "diagnostics and recovery");
    fake->fail_next_ecm = true;
    ecm[3] = 3;
    require(!state.on_ecm(0x42, ecm, metadata), "diagnostics and recovery");
    require(log.str().find("rejected") != std::string::npos, "diagnostics and recovery");
    std::cerr.rdbuf(previous);
}

int main()
{
    test_diagnostics_and_recovery();
    test_emm_option();
    test_signaling_boundaries();
    test_invalid_auth_length_is_rejected();
    test_ecm_metadata_and_emm_selection();
    test_ecm_card_response_validation();
    test_clear_to_scrambled_key_transition();
    test_clear_authenticated_rejection();
    return 0;
}
