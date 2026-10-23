#ifndef ARIBB61_ROUTING_STATE_H
#define ARIBB61_ROUTING_STATE_H

#include "routing.h"
#include <map>
#include <optional>
#include <set>

class RoutingState {
public:
    bool update_mpts(uint32_t source, const std::vector<MptSnapshot>& snapshots);
    bool update_cat(uint32_t source, const MhCatSnapshot& snapshot);
    bool update_flow(uint16_t cid, const uint8_t *compressed_header);
    std::optional<uint32_t> ecm_for(uint32_t media, uint16_t ca_system) const;
    std::set<uint32_t> ecm_streams(uint16_t ca_system) const;
    bool allows_emm(uint32_t stream, uint16_t ca_system) const;
    std::optional<ScramblingAlgorithm> algorithm_for(
        uint32_t media, std::optional<ScramblingAlgorithm> packet_algorithm) const;
    bool mmtp_scrambling_allowed() const;
    bool authentication_required(uint32_t media) const;

private:
    std::optional<uint32_t> resolve(uint16_t cid, const CaLocation& location) const;
    struct Flow {
        std::array<uint8_t, 16> src{}, dst{};
        uint16_t port{};
        bool operator==(const Flow&) const = default;
    };
    std::map<uint16_t, Flow> flows;
    std::map<std::pair<uint32_t, uint16_t>, MptSnapshot> mpts;
    std::map<uint32_t, MhCatSnapshot> cats;
};
#endif
