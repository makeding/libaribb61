#include "routing.h"

#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

void require(bool value, const char *message)
{
    if (!value) throw std::runtime_error(message);
}

void put_be16(std::vector<uint8_t>& data, uint16_t value)
{
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value));
}

void put_be32(std::vector<uint8_t>& data, uint32_t value)
{
    data.push_back(static_cast<uint8_t>(value >> 24));
    data.push_back(static_cast<uint8_t>(value >> 16));
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value));
}

std::vector<uint8_t> access_descriptor(uint16_t ca_system_id, const std::vector<uint8_t>& location)
{
    std::vector<uint8_t> descriptor;
    put_be16(descriptor, 0x8004);
    descriptor.push_back(static_cast<uint8_t>(2 + location.size()));
    put_be16(descriptor, ca_system_id);
    descriptor.insert(descriptor.end(), location.begin(), location.end());
    return descriptor;
}

std::vector<uint8_t> scrambler_descriptor(uint8_t layer_type, uint8_t system_id)
{
    std::vector<uint8_t> descriptor;
    put_be16(descriptor, 0x8005);
    descriptor.insert(descriptor.end(), { 2, static_cast<uint8_t>(layer_type << 6), system_id });
    return descriptor;
}

std::vector<uint8_t> asset(std::initializer_list<uint8_t> id,
                           const std::vector<uint8_t>& locations,
                           const std::vector<uint8_t>& descriptors)
{
    std::vector<uint8_t> data = { 0, 0, 0, 0, 1, static_cast<uint8_t>(id.size()) };
    data.insert(data.end(), id.begin(), id.end());
    data.insert(data.end(), { 'h', 'v', 'c', '1', 0 });
    size_t location_count = 0;
    for (size_t pos = 0; pos < locations.size();) {
        ++location_count;
        pos += locations[pos] == 0 ? 3 : 37;
    }
    data.push_back(static_cast<uint8_t>(location_count));
    data.insert(data.end(), locations.begin(), locations.end());
    put_be16(data, static_cast<uint16_t>(descriptors.size()));
    data.insert(data.end(), descriptors.begin(), descriptors.end());
    return data;
}

std::vector<uint8_t> mpt(const std::vector<uint8_t>& package_descriptors,
                         const std::vector<std::vector<uint8_t>>& assets)
{
    std::vector<uint8_t> data = { 0x20, 0x51, 0, 0, 0, 2, 0x12, 0x34 };
    put_be16(data, static_cast<uint16_t>(package_descriptors.size()));
    data.insert(data.end(), package_descriptors.begin(), package_descriptors.end());
    data.push_back(static_cast<uint8_t>(assets.size()));
    for (const auto& entry : assets) data.insert(data.end(), entry.begin(), entry.end());
    const uint16_t size = static_cast<uint16_t>(data.size() - 4);
    data[2] = static_cast<uint8_t>(size >> 8);
    data[3] = static_cast<uint8_t>(size);
    return data;
}

void test_mpt_routes_and_override()
{
    const std::vector<uint8_t> same_cid_ecm = { 0, 0x44, 0x55 };
    std::vector<uint8_t> ipv6_ecm = { 2 };
    for (uint8_t i = 0; i < 16; ++i) ipv6_ecm.push_back(i);
    for (uint8_t i = 0; i < 16; ++i) ipv6_ecm.push_back(static_cast<uint8_t>(0x80 + i));
    ipv6_ecm.insert(ipv6_ecm.end(), { 0x12, 0x34, 0x45, 0x67 });
    const std::vector<uint8_t> package_descriptor = access_descriptor(0x1111, same_cid_ecm);
    const std::vector<uint8_t> asset_descriptor = access_descriptor(0x2222, ipv6_ecm);
    const std::vector<uint8_t> media_same_cid = { 0, 0x20, 0x01 };
    std::vector<uint8_t> media_ipv6 = ipv6_ecm;
    media_ipv6.back() = 0x02;
    const auto table = mpt(package_descriptor, {
        asset({ 1 }, media_same_cid, {}),
        asset({ 2, 3 }, media_ipv6, asset_descriptor),
    });
    MptSnapshot snapshot;
    require(acas_parse_mpt(table.data(), table.size(), snapshot), "MPT rejected");
    require(snapshot.service_id == 0x1234 && snapshot.version == 0x51 && snapshot.assets.size() == 2,
            "MPT header mismatch");
    require(snapshot.assets[0].ca_routes[0].ca_system_id == 0x1111 &&
            snapshot.assets[0].locations[0].packet_id == 0x2001,
            "package route not inherited");
    const auto& second = snapshot.assets[1];
    require(second.ca_routes.size() == 1 && second.ca_routes[0].ca_system_id == 0x1111 &&
            second.locations[0].type == 2 && second.locations[0].packet_id == 0x4502 &&
            second.locations[0].ipv6_src[0] == 0 && second.locations[0].ipv6_dst[0] == 0x80 &&
            second.locations[0].dst_port == 0x1234,
            "asset route mismatch");

    const auto clear = mpt(package_descriptor, {
        asset({ 4 }, media_same_cid, access_descriptor(0x1111, { 0, 0xff, 0xff })),
    });
    require(acas_parse_mpt(clear.data(), clear.size(), snapshot) && snapshot.assets[0].ca_routes.empty(),
            "same-CA clear override was ignored");

}

void test_rejection_is_atomic()
{
    MptSnapshot snapshot;
    snapshot.service_id = 9;
    snapshot.assets.resize(1);
    const std::vector<uint8_t> invalid = { 0x20, 0, 0, 9, 0, 2, 0, 1, 0 };
    require(!acas_parse_mpt(invalid.data(), invalid.size(), snapshot) && snapshot.service_id == 9,
            "truncated MPT updated state");

    MhCatSnapshot cat;
    cat.version = 7;
    const std::vector<uint8_t> malformed_cat = { 0x86, 1, 0, 7, 9, 4, 0, 1 };
    require(!acas_parse_mh_cat(malformed_cat.data(), malformed_cat.size(), cat) && cat.version == 7,
            "truncated CAT updated state");
}

void test_mpt_profile_guards()
{
    const auto media = std::vector<uint8_t> { 0, 0x20, 0x01 };
    const auto valid = mpt({}, { asset({ 1 }, media, {}) });
    MptSnapshot snapshot;
    require(acas_parse_mpt(valid.data(), valid.size(), snapshot), "valid MPT rejected");

    auto reserved_bits = valid;
    reserved_bits[4] = 0xfc;
    require(acas_parse_mpt(reserved_bits.data(), reserved_bits.size(), snapshot),
            "MPT reserved bits rejected");

    auto invalid_mode = valid;
    invalid_mode[4] = 1;
    require(!acas_parse_mpt(invalid_mode.data(), invalid_mode.size(), snapshot),
            "unsupported MPT mode accepted");

    auto clock_relation = valid;
    clock_relation[22] = 1;
    require(!acas_parse_mpt(clock_relation.data(), clock_relation.size(), snapshot),
            "clock relation flag accepted");

    const auto empty_asset_id = mpt({}, { asset({}, media, {}) });
    require(acas_parse_mpt(empty_asset_id.data(), empty_asset_id.size(), snapshot) &&
            snapshot.assets[0].asset_id.empty(),
            "empty asset identifier rejected");
}

void test_mh_cat_and_pa()
{
    std::vector<uint8_t> cat = { 0x86, 0x22, 0, 0 };
    const auto access = access_descriptor(0x1234, { 0, 0x04, 0x56 });
    cat.insert(cat.end(), access.begin(), access.end());
    const auto scrambler = scrambler_descriptor(1, 1);
    cat.insert(cat.end(), scrambler.begin(), scrambler.end());
    const uint16_t cat_length = static_cast<uint16_t>(cat.size() - 4);
    cat[2] = static_cast<uint8_t>(cat_length >> 8);
    cat[3] = static_cast<uint8_t>(cat_length);
    MhCatSnapshot snapshot;
    require(acas_parse_mh_cat(cat.data(), cat.size(), snapshot) && snapshot.version == 0x22 &&
            snapshot.supported_scrambling && snapshot.emm_routes.size() == 1 &&
            snapshot.emm_routes[0].ca_system_id == 0x1234 &&
            snapshot.emm_routes[0].locations[0].packet_id == 0x0456,
            "MH-CAT mismatch");

    const auto table = mpt({}, { asset({ 1 }, { 0, 0x20, 0x01 }, {}) });
    std::vector<uint8_t> pa = { 0, 0, 0 };
    put_be32(pa, static_cast<uint32_t>(1 + table.size()));
    pa.push_back(0);
    pa.insert(pa.end(), table.begin(), table.end());
    std::vector<MptSnapshot> tables;
    require(acas_parse_pa_message(pa.data(), pa.size(), tables) && tables.size() == 1 &&
            tables[0].service_id == 0x1234,
            "PA MPT mismatch");

    std::vector<uint8_t> pa_with_directory = { 0, 0, 0 };
    put_be32(pa_with_directory, static_cast<uint32_t>(1 + 4 + table.size()));
    pa_with_directory.insert(pa_with_directory.end(), { 1, 0x20, 0x51, 0, 0 });
    pa_with_directory.insert(pa_with_directory.end(), table.begin(), table.end());
    require(acas_parse_pa_message(pa_with_directory.data(), pa_with_directory.size(), tables) &&
            tables.size() == 1,
            "PA directory was not skipped");

    const std::vector<uint8_t> unknown_table = { 0x99, 0, 0, 0 };
    std::vector<uint8_t> pa_with_unknown = { 0, 0, 0 };
    put_be32(pa_with_unknown, static_cast<uint32_t>(1 + unknown_table.size()));
    pa_with_unknown.push_back(0);
    pa_with_unknown.insert(pa_with_unknown.end(), unknown_table.begin(), unknown_table.end());
    require(acas_parse_pa_message(pa_with_unknown.data(), pa_with_unknown.size(), tables) &&
            tables.empty(),
            "PA unknown table was rejected");
}

}

int main()
{
    test_mpt_routes_and_override();
    test_rejection_is_atomic();
    test_mpt_profile_guards();
    test_mh_cat_and_pa();
    return 0;
}
