#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

#include "aribb61/arib_std_b61.h"
#include "card.h"
#include "routing.h"
#include "crypto/aes.h"
#include "crypto/camellia.h"
#include "stream_test_support.h"

ARIB_STD_B61 *aribb61_create_with_card(std::unique_ptr<AcasCardClient> card);

namespace {

constexpr uint16_t kCaSystem = 0x1234;
constexpr uint8_t kScrambleEven = 0x02;

void require(bool condition, const char *message)
{
    if (!condition) throw std::runtime_error(message);
}

class FakeCard final : public AcasCardClient {
public:
    FakeCard() { identity.ca_system_id = kCaSystem; }

    void set_proxy(const std::string&) override {}

    bool get_identity(acas_card_identity& output) override
    {
        if (!identity_available) return false;
        output = identity;
        return true;
    }

    bool process_ecm(const std::vector<uint8_t>& ecm, acas_ecm_result& output) override
    {
        const uint8_t generation = ecm.at(3);
        ++calls[generation];
        output.response_valid = true;
        output.return_code = failures.contains(generation) ? 0xa103 : 0x0800;
        output.broadcaster_id = 0x42;
        if (failures.contains(generation)) return false;
        output.odd_key.fill(static_cast<uint8_t>(0x10 + generation));
        output.even_key.fill(static_cast<uint8_t>(0x20 + generation));
        return true;
    }

    bool process_emm(const std::vector<uint8_t>&, uint16_t& return_code) override
    {
        return_code = 0x2100;
        return true;
    }

    bool identity_available = true;
    acas_card_identity identity{};
    std::map<uint8_t, unsigned> calls;
    std::set<uint8_t> failures;
};

struct FeedResult {
    int status = 0;
    std::vector<uint8_t> output;
};

FeedResult feed(ARIB_STD_B61 *ctx, const std::vector<uint8_t>& packet)
{
    ARIB_STD_B61_BUFFER input{const_cast<uint8_t *>(packet.data()), static_cast<uint32_t>(packet.size())};
    FeedResult result;
    result.status = arib_std_b61_put(ctx, &input);
    require(result.status >= 0, "C API put failed");
    ARIB_STD_B61_BUFFER output{};
    require(arib_std_b61_get(ctx, &output) == 0, "C API get failed");
    result.output.assign(output.data, output.data + output.size);
    return result;
}

std::vector<uint8_t> section_message(uint16_t message_id, uint8_t generation)
{
    return aribb61_test::make_mmt_section_message(message_id,
                                                   aribb61_test::make_ecm_section(generation));
}

void install_mpts(ARIB_STD_B61 *ctx, uint16_t cid, uint16_t stream, uint32_t sequence,
                  const std::vector<std::vector<uint8_t>>& tables)
{
    const auto message = aribb61_test::make_pa(tables);
    const auto packet = aribb61_test::make_signaling_tlv(cid, stream, sequence, message);
    const auto result = feed(ctx, packet);
    require(result.status == 0 && result.output == packet, "MPT signalling was altered");
}

void install_cat(ARIB_STD_B61 *ctx, uint32_t sequence, uint8_t layer_type = 1,
                 uint8_t system_id = 1)
{
    const auto message = aribb61_test::make_mmt_section_message(
        0x8001, aribb61_test::make_cat(1, kCaSystem, 0x43, layer_type, system_id));
    const auto packet = aribb61_test::make_signaling_tlv(0, 1, sequence, message);
    const auto result = feed(ctx, packet);
    require(result.status == 0 && result.output == packet, "CAT signalling was altered");
}

void send_ecm(ARIB_STD_B61 *ctx, uint16_t cid, uint16_t stream, uint32_t sequence,
              uint8_t generation)
{
    const auto message = section_message(0x8000, generation);
    const auto packet = aribb61_test::make_signaling_tlv(cid, stream, sequence, message);
    const auto result = feed(ctx, packet);
    require(result.status == 0 && result.output == packet, "ECM signalling was altered");
}

std::array<uint8_t, 16> even_key(uint8_t generation)
{
    std::array<uint8_t, 16> result{};
    result.fill(static_cast<uint8_t>(0x20 + generation));
    return result;
}

std::vector<uint8_t> encrypt_payload(std::vector<uint8_t> payload, uint8_t generation,
                                     uint16_t packet_id, uint32_t sequence, size_t size,
                                     ScramblingAlgorithm algorithm = ScramblingAlgorithm::Aes128Ctr)
{
    require(payload.size() >= size && size > 8, "invalid encrypted test payload");
    std::array<uint8_t, 16> iv{};
    aribb61_test::put_be16(iv.data(), packet_id);
    aribb61_test::put_be32(iv.data() + 2, sequence);
    if (algorithm == ScramblingAlgorithm::Aes128Ctr) {
        AES_ctx aes;
        AES_init_ctx_iv(&aes, even_key(generation).data(), iv.data());
        AES_CTR_xcrypt_buffer(&aes, payload.data() + 8, size - 8);
    } else {
        require(camellia128_ctr_xcrypt(even_key(generation).data(), iv.data(),
                                       payload.data() + 8, size - 8),
                "Camellia test encryption failed");
    }
    return payload;
}

std::vector<uint8_t> media_payload(uint8_t salt)
{
    std::vector<uint8_t> result(24);
    for (size_t i = 0; i < result.size(); ++i) result[i] = static_cast<uint8_t>(salt + i);
    return result;
}

std::vector<uint8_t> normal_media(uint16_t cid, uint16_t packet_id, uint32_t sequence,
                                  uint8_t generation, const std::vector<uint8_t>& plain)
{
    return aribb61_test::make_tlv(cid, packet_id, sequence, 0,
                                  encrypt_payload(plain, generation, packet_id, sequence, plain.size()), 0x10);
}

std::vector<uint8_t> expected_plain(uint16_t cid, uint16_t packet_id, uint32_t sequence,
                                    const std::vector<uint8_t>& plain)
{
    auto result = aribb61_test::make_tlv(cid, packet_id, sequence, 0, plain, 0x10);
    result[27] &= static_cast<uint8_t>(~0x18);
    return result;
}

std::vector<uint8_t> route_table(uint8_t version, uint16_t service, uint16_t media,
                                 uint16_t ecm, uint16_t ca_system = kCaSystem,
                                 const std::vector<uint8_t>& package_descriptors = {})
{
    auto descriptors = aribb61_test::access_control_descriptor(ca_system, ecm);
    descriptors.insert(descriptors.end(), package_descriptors.begin(), package_descriptors.end());
    return aribb61_test::make_mpt(version, service,
        descriptors,
        { aribb61_test::mpt_asset(static_cast<uint8_t>(service), media, {}) });
}

void test_camellia_ctr_vector()
{
    const std::array<uint8_t, 16> key = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    std::array<uint8_t, 16> block{};
    require(camellia128_ctr_xcrypt(key.data(), key.data(), block.data(), block.size()),
            "Camellia CTR vector encryption failed");
    const std::array<uint8_t, 16> expected = {
        0x67, 0x67, 0x31, 0x38, 0x54, 0x96, 0x69, 0x73,
        0x08, 0x57, 0x06, 0x56, 0x48, 0xea, 0xbe, 0x43,
    };
    require(block == expected, "Camellia CTR vector mismatch");
}

void test_algorithm_precedence()
{
    auto fake = std::make_unique<FakeCard>();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    require(ctx != nullptr, "C API context creation failed");
    install_cat(ctx.get(), 1);
    const auto camellia = aribb61_test::make_scrambler_descriptor(1, 2);
    install_mpts(ctx.get(), 1, 0x100, 2, { route_table(1, 0x101, 0x200, 0x300, kCaSystem, camellia) });
    send_ecm(ctx.get(), 1, 0x300, 3, 1);

    const auto plain = media_payload(0x30);
    const auto camellia_cipher = encrypt_payload(plain, 1, 0x200, 4, plain.size(),
                                                 ScramblingAlgorithm::Camellia128Ctr);
    const auto mpt_selected = aribb61_test::make_tlv(1, 0x200, 4, 0, camellia_cipher, 0x10);
    require(feed(ctx.get(), mpt_selected).output == expected_plain(1, 0x200, 4, plain),
            "MPT Camellia descriptor did not override CAT AES");

    const auto aes_cipher = encrypt_payload(plain, 1, 0x200, 5, plain.size());
    const auto packet_selected = aribb61_test::make_tlv(1, 0x200, 5, 0, aes_cipher, 0x14, 0, 0x01);
    auto expected_packet_selected = packet_selected;
    expected_packet_selected[27] &= static_cast<uint8_t>(~0x18);
    std::copy(plain.begin(), plain.end(), expected_packet_selected.end() - plain.size());
    require(feed(ctx.get(), packet_selected).output == expected_packet_selected,
            "packet AES method did not override MPT Camellia");

    const auto unsupported = aribb61_test::make_scrambler_descriptor(1, 3);
    install_mpts(ctx.get(), 1, 0x100, 6, { route_table(2, 0x101, 0x200, 0x300, kCaSystem, unsupported) });
    const auto rejected = feed(ctx.get(), mpt_selected);
    require(rejected.status == ARIB_STD_B61_WARN_UNDECRYPTED && rejected.output == mpt_selected,
            "unsupported MPT method fell back to CAT AES");
}

void test_routes_are_context_scoped_and_failures_are_isolated()
{
    auto fake = std::make_unique<FakeCard>();
    auto *card = fake.get();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    require(ctx != nullptr, "C API context creation failed");

    install_cat(ctx.get(), 1);
    install_mpts(ctx.get(), 1, 0x100, 1, {
        route_table(1, 0x101, 0x200, 0x300),
        route_table(1, 0x102, 0x201, 0x301),
    });
    install_mpts(ctx.get(), 2, 0x100, 2, { route_table(1, 0x201, 0x200, 0x300) });
    send_ecm(ctx.get(), 1, 0x300, 3, 1);
    send_ecm(ctx.get(), 1, 0x301, 4, 2);
    send_ecm(ctx.get(), 2, 0x300, 5, 3);
    require(card->calls[1] == 1 && card->calls[2] == 1 && card->calls[3] == 1,
            "routed ECM streams were not independently delivered");

    const auto a_plain = media_payload(0x20);
    const auto b_plain = media_payload(0x40);
    const auto c_plain = media_payload(0x60);
    const auto a_packet = normal_media(1, 0x200, 11, 1, a_plain);
    const auto b_packet = normal_media(1, 0x201, 12, 2, b_plain);
    const auto c_packet = normal_media(2, 0x200, 13, 3, c_plain);
    require(feed(ctx.get(), a_packet).output == expected_plain(1, 0x200, 11, a_plain),
            "first same-CID service was not decrypted");
    require(feed(ctx.get(), b_packet).output == expected_plain(1, 0x201, 12, b_plain),
            "second same-CID service was not decrypted");
    require(feed(ctx.get(), c_packet).output == expected_plain(2, 0x200, 13, c_plain),
            "cross-CID service was not decrypted");

    card->failures.insert(4);
    send_ecm(ctx.get(), 1, 0x301, 14, 4);
    require(feed(ctx.get(), a_packet).output == expected_plain(1, 0x200, 11, a_plain),
            "failed service invalidated another service key");
    const auto rejected = feed(ctx.get(), b_packet);
    require(rejected.status == ARIB_STD_B61_WARN_UNDECRYPTED && rejected.output == b_packet,
            "failed service retained a previous key");
    send_ecm(ctx.get(), 1, 0x301, 15, 2);
    require(feed(ctx.get(), b_packet).output == expected_plain(1, 0x201, 12, b_plain),
            "service did not recover before identity failure");
    card->identity_available = false;
    send_ecm(ctx.get(), 1, 0x301, 16, 5);
    const auto unavailable = feed(ctx.get(), b_packet);
    require(unavailable.status == ARIB_STD_B61_WARN_UNDECRYPTED && unavailable.output == b_packet,
            "identity failure left superseded keys active");
    require(feed(ctx.get(), a_packet).output == expected_plain(1, 0x200, 11, a_plain),
            "identity failure invalidated an unrelated stream");
}

void test_missing_wrong_and_replaced_routes()
{
    auto fake = std::make_unique<FakeCard>();
    auto *card = fake.get();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    require(ctx != nullptr, "C API context creation failed");

    const auto plain = media_payload(0x70);
    const auto no_route = normal_media(1, 0x200, 1, 1, plain);
    const auto no_route_result = feed(ctx.get(), no_route);
    require(no_route_result.status == ARIB_STD_B61_WARN_UNDECRYPTED && no_route_result.output == no_route &&
            card->calls.empty(), "media decrypted without an MPT route");

    install_mpts(ctx.get(), 1, 0x100, 2, { route_table(1, 0x101, 0x200, 0x300) });
    send_ecm(ctx.get(), 1, 0x300, 3, 1);
    const auto without_cat = feed(ctx.get(), no_route);
    require(card->calls[1] == 1 && without_cat.status == ARIB_STD_B61_OK &&
            without_cat.output == expected_plain(1, 0x200, 1, plain),
            "service-filtered input without CAT did not decrypt");
    install_cat(ctx.get(), 4);
    require(feed(ctx.get(), no_route).output == expected_plain(1, 0x200, 1, plain),
            "valid CAT did not enable decryption");

    install_mpts(ctx.get(), 1, 0x100, 5, { route_table(2, 0x101, 0x200, 0x300, 0x9999) });
    send_ecm(ctx.get(), 1, 0x300, 6, 4);
    require(card->calls[4] == 0, "wrong CA-system ECM was delivered to the card");
    require(feed(ctx.get(), no_route).status == ARIB_STD_B61_WARN_UNDECRYPTED,
            "wrong CA-system route decrypted media");

    install_mpts(ctx.get(), 1, 0x100, 7, { route_table(3, 0x101, 0x200, 0x300) });
    send_ecm(ctx.get(), 1, 0x300, 8, 1);
    require(feed(ctx.get(), no_route).output == expected_plain(1, 0x200, 1, plain),
            "valid replacement route did not decrypt");

    install_mpts(ctx.get(), 1, 0x100, 9, { route_table(4, 0x101, 0x200, 0x301) });
    require(feed(ctx.get(), no_route).status == ARIB_STD_B61_WARN_UNDECRYPTED,
            "route replacement kept a removed ECM key");
    const auto refreshed = normal_media(1, 0x200, 7, 2, plain);
    send_ecm(ctx.get(), 1, 0x301, 10, 2);
    require(feed(ctx.get(), refreshed).output == expected_plain(1, 0x200, 7, plain),
            "replacement ECM route did not decrypt");

    install_cat(ctx.get(), 11, 0, 2);
    require(feed(ctx.get(), refreshed).status == ARIB_STD_B61_WARN_UNDECRYPTED,
            "unsupported CAT update left AES available");
    install_cat(ctx.get(), 12);
    send_ecm(ctx.get(), 1, 0x301, 13, 2);
    const auto malformed = aribb61_test::make_pa({ { 0x20, 0, 0, 1, 0 } });
    const auto malformed_packet = aribb61_test::make_signaling_tlv(1, 0x100, 14, malformed);
    require(feed(ctx.get(), malformed_packet).output == malformed_packet, "malformed MPT packet changed");
    require(feed(ctx.get(), refreshed).output == expected_plain(1, 0x200, 7, plain),
            "malformed MPT corrupted a valid route");

    require(arib_std_b61_reset(ctx.get()) == 0, "C API reset failed");
    const auto after_reset = feed(ctx.get(), refreshed);
    require(after_reset.status == ARIB_STD_B61_WARN_UNDECRYPTED && after_reset.output == refreshed,
            "reset retained a route or key");
}

void test_method_and_authentication_boundaries()
{
    auto fake = std::make_unique<FakeCard>();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    require(ctx != nullptr, "C API context creation failed");
    install_cat(ctx.get(), 1);
    install_mpts(ctx.get(), 1, 0x100, 1, { route_table(1, 0x101, 0x200, 0x300) });
    send_ecm(ctx.get(), 1, 0x300, 2, 1);

    const auto plain = media_payload(0x90);
    const auto cipher = encrypt_payload(plain, 1, 0x200, 3, plain.size());
    const auto method = aribb61_test::make_tlv(1, 0x200, 3, 0, cipher, 0x14);
    const auto method_result = feed(ctx.get(), method);
    require(method_result.status == ARIB_STD_B61_WARN_UNDECRYPTED && method_result.output == method,
            "explicit scrambling method was altered or decrypted");

    std::vector<uint8_t> authenticated = cipher;
    authenticated.insert(authenticated.end(), { 0xa1, 0xa2, 0xa3 });
    const auto auth = aribb61_test::make_tlv(1, 0x200, 4, 0, authenticated, 0x12, cipher.size());
    const auto auth_result = feed(ctx.get(), auth);
    require(auth_result.status == (ARIB_STD_B61_WARN_UNDECRYPTED | ARIB_STD_B61_WARN_UNVERIFIED) &&
            auth_result.output.empty(), "encrypted authenticated packet was not discarded");

    const auto clear_auth = aribb61_test::make_tlv(1, 0x200, 5, 0, authenticated, 0x02, cipher.size());
    const auto clear_result = feed(ctx.get(), clear_auth);
    require(clear_result.status == ARIB_STD_B61_WARN_UNVERIFIED && clear_result.output.empty(),
            "clear authenticated packet was not discarded");

    const std::vector<uint8_t> auth_descriptor = { 0x80, 0x06, 2, 0x40, 1 };
    auto descriptors = aribb61_test::access_control_descriptor(kCaSystem, 0x300);
    descriptors.insert(descriptors.end(), auth_descriptor.begin(), auth_descriptor.end());
    install_mpts(ctx.get(), 1, 0x100, 6, { aribb61_test::make_mpt(2, 0x101,
        descriptors, { aribb61_test::mpt_asset(1, 0x200, {}) }) });
    const auto declared = normal_media(1, 0x200, 3, 1, plain);
    const auto declared_result = feed(ctx.get(), declared);
    require(declared_result.status == (ARIB_STD_B61_WARN_UNVERIFIED | ARIB_STD_B61_WARN_UNDECRYPTED) &&
            declared_result.output.empty(), "MPT authentication requirement was bypassed");
    install_mpts(ctx.get(), 1, 0x100, 7, { route_table(3, 0x101, 0x200, 0x300) });
    require(feed(ctx.get(), declared).output == expected_plain(1, 0x200, 3, plain),
            "removed authentication declaration still blocked media");
    auto cat = std::vector<uint8_t>{ 0x86, 1, 0, 5 };
    cat.insert(cat.end(), auth_descriptor.begin(), auth_descriptor.end());
    feed(ctx.get(), aribb61_test::make_signaling_tlv(1, 1, 8,
        aribb61_test::make_mmt_section_message(0x8001, cat)));
    const auto clear = aribb61_test::make_tlv(1, 0x200, 9, 0, plain);
    const auto cat_result = feed(ctx.get(), clear);
    require(cat_result.status == ARIB_STD_B61_WARN_UNVERIFIED && cat_result.output.empty(),
            "CAT authentication requirement was bypassed for clear media");
}

void test_new_source_snapshot_retires_other_services()
{
    auto fake = std::make_unique<FakeCard>();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    require(ctx != nullptr, "C API context creation failed");
    install_cat(ctx.get(), 1);
    install_mpts(ctx.get(), 1, 0x100, 2, { route_table(1, 0x101, 0x200, 0x300) });
    send_ecm(ctx.get(), 1, 0x300, 3, 1);
    const auto first_plain = media_payload(0xe0);
    const auto first = normal_media(1, 0x200, 4, 1, first_plain);
    require(feed(ctx.get(), first).output == expected_plain(1, 0x200, 4, first_plain),
            "initial source snapshot did not decrypt");

    install_mpts(ctx.get(), 1, 0x100, 5, { route_table(2, 0x102, 0x201, 0x301) });
    require(feed(ctx.get(), first).status == ARIB_STD_B61_WARN_UNDECRYPTED,
            "new source snapshot retained a prior service mapping");
    send_ecm(ctx.get(), 1, 0x301, 6, 2);
    const auto second_plain = media_payload(0xf0);
    const auto second = normal_media(1, 0x201, 7, 2, second_plain);
    require(feed(ctx.get(), second).output == expected_plain(1, 0x201, 7, second_plain),
            "new source snapshot did not install its service mapping");
}

void test_type2_route_and_cid_reassignment()
{
    auto fake = std::make_unique<FakeCard>();
    std::unique_ptr<ARIB_STD_B61, decltype(&arib_std_b61_release)> ctx(
        aribb61_create_with_card(std::move(fake)), arib_std_b61_release);
    require(ctx != nullptr, "C API context creation failed");
    install_cat(ctx.get(), 1);

    std::array<uint8_t, 16> src{};
    std::array<uint8_t, 16> dst{};
    for (size_t i = 0; i < src.size(); ++i) {
        src[i] = static_cast<uint8_t>(i);
        dst[i] = static_cast<uint8_t>(0x80 + i);
    }
    const uint16_t flow_port = 0x1234;
    const auto cross_route = aribb61_test::access_control_descriptor(
        kCaSystem, aribb61_test::ca_location_ipv6(src, dst, flow_port, 0x300));
    const auto table = aribb61_test::make_mpt(1, 0x101, cross_route,
        { aribb61_test::mpt_asset(1, 0x200, {}) });
    install_mpts(ctx.get(), 1, 0x100, 2, { table });

    const auto plain = media_payload(0xb0);
    const auto media = normal_media(1, 0x200, 3, 1, plain);
    send_ecm(ctx.get(), 2, 0x300, 4, 1);
    require(feed(ctx.get(), media).status == ARIB_STD_B61_WARN_UNDECRYPTED,
            "unresolved type-2 route decrypted media");

    const auto full = aribb61_test::make_full_ipv6_tlv(2, 0x100, 5, src, dst, flow_port, 0,
                                                        media_payload(0xc0));
    require(feed(ctx.get(), full).output == full, "full compressed-IP flow changed");
    send_ecm(ctx.get(), 2, 0x300, 6, 1);
    require(feed(ctx.get(), media).output == expected_plain(1, 0x200, 3, plain),
            "type-2 route did not resolve from full compressed-IP flow");

    const auto reassigned = aribb61_test::make_full_ipv6_tlv(2, 0x100, 7, src, dst,
                                                              static_cast<uint16_t>(flow_port + 1), 0,
                                                              media_payload(0xd0));
    require(feed(ctx.get(), reassigned).output == reassigned, "CID reassignment packet changed");
    const auto after_reassignment = feed(ctx.get(), media);
    require(after_reassignment.status == ARIB_STD_B61_WARN_UNDECRYPTED &&
            after_reassignment.output == media, "CID reassignment retained a resolved key");
}

} // namespace

int main()
{
    test_camellia_ctr_vector();
    test_algorithm_precedence();
    test_routes_are_context_scoped_and_failures_are_isolated();
    test_missing_wrong_and_replaced_routes();
    test_method_and_authentication_boundaries();
    test_new_source_snapshot_retires_other_services();
    test_type2_route_and_cid_reassignment();
    return 0;
}
