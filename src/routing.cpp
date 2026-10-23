#include "routing.h"

#include <algorithm>
#include <utility>

namespace {

constexpr uint8_t kMptTableId = 0x20;
constexpr uint8_t kMhCatTableId = 0x86;
constexpr uint16_t kAccessControlDescriptorTag = 0x8004;
constexpr uint16_t kScramblerDescriptorTag = 0x8005;
constexpr size_t kMaxTables = 256;
constexpr size_t kMaxRoutes = 256;

uint16_t be16(const uint8_t *p)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t be32(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

class Cursor {
public:
    Cursor(const uint8_t *begin, const uint8_t *end) : p(begin), e(end) {}

    size_t remaining() const { return static_cast<size_t>(e - p); }
    const uint8_t *current() const { return p; }
    bool skip(size_t count)
    {
        if (count > remaining()) return false;
        p += count;
        return true;
    }
    bool read_u8(uint8_t& value)
    {
        if (remaining() < 1) return false;
        value = *p++;
        return true;
    }
    bool read_be16(uint16_t& value)
    {
        if (remaining() < 2) return false;
        value = be16(p);
        p += 2;
        return true;
    }
    bool subcursor(size_t count, Cursor& result)
    {
        if (count > remaining()) return false;
        result = Cursor(p, p + count);
        p += count;
        return true;
    }

private:
    const uint8_t *p;
    const uint8_t *e;
};

bool parse_location(Cursor& cursor, CaLocation& location)
{
    if (!cursor.read_u8(location.type)) return false;
    switch (location.type) {
    case 0:
        return cursor.read_be16(location.packet_id);
    case 2:
        if (cursor.remaining() < 36) return false;
        std::copy_n(cursor.current(), location.ipv6_src.size(), location.ipv6_src.begin());
        if (!cursor.skip(location.ipv6_src.size())) return false;
        std::copy_n(cursor.current(), location.ipv6_dst.size(), location.ipv6_dst.begin());
        if (!cursor.skip(location.ipv6_dst.size()) ||
            !cursor.read_be16(location.dst_port) ||
            !cursor.read_be16(location.packet_id)) return false;
        return true;
    case 1:
        if (cursor.remaining() < 12 || !cursor.skip(10) || !cursor.read_be16(location.packet_id)) return false;
        return true;
    case 3:
        return cursor.skip(6);
    case 4:
        if (cursor.remaining() < 36 || !cursor.skip(34) || !cursor.read_be16(location.packet_id)) return false;
        return true;
    case 5: {
        uint8_t url_length;
        return cursor.read_u8(url_length) && cursor.skip(url_length);
    }
    default:
        return false;
    }
}

bool parse_locations(Cursor& cursor, uint8_t count, std::vector<CaLocation>& locations)
{
    if (count == 0) return false;
    std::vector<CaLocation> parsed;
    parsed.reserve(count);
    for (uint8_t i = 0; i < count; ++i) {
        CaLocation location;
        if (!parse_location(cursor, location)) return false;
        parsed.push_back(std::move(location));
    }
    locations = std::move(parsed);
    return true;
}

bool parse_access_control_descriptor(Cursor& cursor, CaRoute& route)
{
    uint16_t ca_system_id;
    if (!cursor.read_be16(ca_system_id) || cursor.remaining() == 0) return false;
    std::vector<CaLocation> locations;
    CaLocation location;
    if (!parse_location(cursor, location)) return false;
    locations.push_back(std::move(location));
    route.ca_system_id = ca_system_id;
    route.locations = std::move(locations);
    return true;
}

struct DescriptorRoutes {
    std::vector<CaRoute> routes;
    bool has_scrambler_descriptor = false;
    bool supported_scrambling = false;
    bool scrambler_conflict = false;
    uint8_t scrambler_layer_type = 0;
    uint8_t scramble_system_id = 0;
};

bool parse_mmt_descriptors(Cursor descriptors, DescriptorRoutes& result)
{
    std::vector<CaRoute> parsed;
    bool has_scrambler_descriptor = false;
    bool supported_scrambling = false;
    bool scrambler_conflict = false;
    uint8_t scrambler_layer_type = 0;
    uint8_t scramble_system_id = 0;
    while (descriptors.remaining() != 0) {
        uint16_t tag;
        uint8_t length;
        if (!descriptors.read_be16(tag) || !descriptors.read_u8(length)) return false;
        Cursor body(nullptr, nullptr);
        if (!descriptors.subcursor(length, body)) return false;
        if (tag == kAccessControlDescriptorTag) {
            if (parsed.size() == kMaxRoutes) return false;
            CaRoute route;
            if (!parse_access_control_descriptor(body, route)) return false;
            parsed.push_back(std::move(route));
        } else if (tag == kScramblerDescriptorTag) {
            if (length < 2) return false;
            uint8_t layer_and_reserved;
            uint8_t system_id;
            if (!body.read_u8(layer_and_reserved) || !body.read_u8(system_id)) return false;
            const uint8_t layer_type = layer_and_reserved >> 6;
            if (has_scrambler_descriptor &&
                (scrambler_layer_type != layer_type || scramble_system_id != system_id)) {
                scrambler_conflict = true;
            }
            has_scrambler_descriptor = true;
            scrambler_layer_type = layer_type;
            scramble_system_id = system_id;
            supported_scrambling = layer_type == 1 && system_id == 1;
        }
    }
    result.routes = std::move(parsed);
    result.has_scrambler_descriptor = has_scrambler_descriptor;
    result.supported_scrambling = supported_scrambling;
    result.scrambler_conflict = scrambler_conflict;
    return true;
}

bool parse_asset(Cursor& cursor, const DescriptorRoutes& package_descriptors, MptAssetRoute& asset)
{
    uint8_t identifier_type;
    uint32_t asset_id_scheme;
    uint8_t asset_id_length;
    uint8_t asset_type[4];
    uint8_t clock_relation;
    uint8_t location_count;
    if (!cursor.read_u8(identifier_type) || cursor.remaining() < sizeof(asset_id_scheme) ||
        !cursor.skip(sizeof(asset_id_scheme)) || !cursor.read_u8(asset_id_length)) return false;
    if (asset_id_length > cursor.remaining()) return false;
    std::vector<uint8_t> asset_id(cursor.current(), cursor.current() + asset_id_length);
    if (!cursor.skip(asset_id_length) || cursor.remaining() < sizeof(asset_type) ||
        !cursor.skip(sizeof(asset_type)) || !cursor.read_u8(clock_relation) ||
        !cursor.read_u8(location_count)) return false;
    if ((clock_relation & 0x01) != 0) return false;

    std::vector<CaLocation> locations;
    if (!parse_locations(cursor, location_count, locations)) return false;
    uint16_t descriptor_length;
    if (!cursor.read_be16(descriptor_length)) return false;
    Cursor descriptors(nullptr, nullptr);
    if (!cursor.subcursor(descriptor_length, descriptors)) return false;
    DescriptorRoutes asset_descriptors;
    if (!parse_mmt_descriptors(descriptors, asset_descriptors)) return false;

    asset.asset_id = std::move(asset_id);
    asset.locations = std::move(locations);
    asset.ca_routes = package_descriptors.routes;
    for (const CaRoute& route : asset_descriptors.routes) {
        if (route.locations.size() == 1 && route.locations[0].type == 0 &&
            route.locations[0].packet_id == 0xffff) {
            std::erase_if(asset.ca_routes, [&](const CaRoute& package_route) {
                return package_route.ca_system_id == route.ca_system_id;
            });
        }
    }
    return true;
}

} // namespace

bool acas_parse_mpt(const uint8_t *data, size_t size, MptSnapshot& snapshot)
{
    if (!data || size < 9 || (data[4] & 0x03) != 0) return false;
    const uint16_t table_length = be16(data + 2);
    if (static_cast<size_t>(table_length) + 4 != size || data[0] != kMptTableId) return false;
    const uint8_t package_id_length = data[5];
    if (package_id_length != 2 || package_id_length > size - 8) return false;
    Cursor cursor(data + 6, data + size);
    const uint16_t service_id = be16(cursor.current());
    if (!cursor.skip(package_id_length)) return false;
    uint16_t package_descriptor_length;
    if (!cursor.read_be16(package_descriptor_length)) return false;
    Cursor package_descriptors(nullptr, nullptr);
    if (!cursor.subcursor(package_descriptor_length, package_descriptors)) return false;
    DescriptorRoutes package_routes;
    if (!parse_mmt_descriptors(package_descriptors, package_routes)) return false;
    uint8_t number_of_assets;
    if (!cursor.read_u8(number_of_assets)) return false;
    std::vector<MptAssetRoute> assets;
    assets.reserve(number_of_assets);
    for (uint8_t i = 0; i < number_of_assets; ++i) {
        MptAssetRoute asset;
        if (!parse_asset(cursor, package_routes, asset)) return false;
        assets.push_back(std::move(asset));
    }
    if (cursor.remaining() != 0) return false;
    MptSnapshot parsed;
    parsed.service_id = service_id;
    parsed.version = data[1];
    parsed.assets = std::move(assets);
    snapshot = std::move(parsed);
    return true;
}

bool acas_parse_mh_cat(const uint8_t *data, size_t size, MhCatSnapshot& snapshot)
{
    if (!data || size < 4 || data[0] != kMhCatTableId ||
        static_cast<size_t>(be16(data + 2)) + 4 != size) return false;
    Cursor descriptors(data + 4, data + size);
    DescriptorRoutes routes;
    if (!parse_mmt_descriptors(descriptors, routes)) return false;
    MhCatSnapshot parsed;
    parsed.version = data[1];
    parsed.emm_routes = std::move(routes.routes);
    parsed.supported_scrambling = routes.has_scrambler_descriptor &&
                                  routes.supported_scrambling && !routes.scrambler_conflict;
    snapshot = std::move(parsed);
    return true;
}

bool acas_parse_pa_message(const uint8_t *data,
                           size_t size,
                           std::vector<MptSnapshot>& snapshots)
{
    if (!data || size < 8 || be16(data) != 0 || be32(data + 3) + 7 != size) return false;
    const uint8_t table_count = data[7];
    const size_t header_size = 8 + static_cast<size_t>(table_count) * 4;
    if (header_size > size) return false;
    Cursor tables(data + header_size, data + size);
    std::vector<MptSnapshot> parsed;
    parsed.reserve(table_count);
    while (tables.remaining() != 0) {
        if (tables.remaining() < 4) return false;
        const uint16_t table_size = be16(tables.current() + 2);
        const size_t total_table_size = static_cast<size_t>(table_size) + 4;
        if (total_table_size > tables.remaining()) return false;
        if (tables.current()[0] == kMptTableId) {
            if (parsed.size() >= kMaxTables) return false;
            MptSnapshot snapshot;
            if (!acas_parse_mpt(tables.current(), total_table_size, snapshot)) return false;
            parsed.push_back(std::move(snapshot));
        }
        if (!tables.skip(total_table_size)) return false;
    }
    if (tables.remaining() != 0) return false;
    snapshots = std::move(parsed);
    return true;
}
