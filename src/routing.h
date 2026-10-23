#ifndef ACAS_ROUTING_H
#define ACAS_ROUTING_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

struct CaLocation {
    uint8_t type = 0;
    uint16_t packet_id = 0;
    std::array<uint8_t, 16> ipv6_src{};
    std::array<uint8_t, 16> ipv6_dst{};
    uint16_t dst_port = 0;
};

struct CaRoute {
    uint16_t ca_system_id = 0;
    std::vector<CaLocation> locations;
};

struct MptAssetRoute {
    std::vector<uint8_t> asset_id;
    std::vector<CaLocation> locations;
    std::vector<CaRoute> ca_routes;
};

struct MptSnapshot {
    uint16_t service_id = 0;
    uint8_t version = 0;
    std::vector<MptAssetRoute> assets;
};

struct MhCatSnapshot {
    uint8_t version = 0;
    std::vector<CaRoute> emm_routes;
    bool supported_scrambling = false;
};

bool acas_parse_mpt(const uint8_t *data, size_t size, MptSnapshot& snapshot);
bool acas_parse_mh_cat(const uint8_t *data, size_t size, MhCatSnapshot& snapshot);
bool acas_parse_pa_message(const uint8_t *data,
                           size_t size,
                           std::vector<MptSnapshot>& snapshots);

#endif
