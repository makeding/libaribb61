#include "routing_state.h"
#include <algorithm>

bool RoutingState::update_mpts(uint32_t source, const std::vector<MptSnapshot>& snapshots)
{
    auto next = mpts;
    std::erase_if(next, [&](const auto& item) { return item.first.first == source; });
    for (const auto& snapshot : snapshots) next[{source, snapshot.service_id}] = snapshot;
    if (next.size() > 256) return false;
    mpts.swap(next);
    return true;
}

bool RoutingState::update_cat(uint32_t source, const MhCatSnapshot& snapshot)
{
    std::map<uint32_t, MhCatSnapshot> next;
    next.emplace(source, snapshot);
    cats.swap(next);
    return true;
}

bool RoutingState::supports_scrambling() const
{
    return cats.size() == 1 && cats.begin()->second.supported_scrambling;
}

bool RoutingState::update_flow(uint16_t cid, const uint8_t *header)
{
    Flow flow;
    std::copy_n(header + 9, 16, flow.src.begin());
    std::copy_n(header + 25, 16, flow.dst.begin());
    flow.port = (header[43] << 8) | header[44];
    const auto previous = flows.find(cid);
    const bool changed = previous != flows.end() && !(previous->second == flow);
    flows[cid] = flow;
    if (changed) {
        std::erase_if(mpts, [&](const auto& item) { return (item.first.first >> 16) == cid; });
        std::erase_if(cats, [&](const auto& item) { return (item.first >> 16) == cid; });
    }
    return changed;
}

std::optional<uint32_t> RoutingState::resolve(uint16_t cid, const CaLocation& location) const
{
    if (location.packet_id == 0xffff) return {};
    if (location.type == 0) return (uint32_t{cid} << 16) | location.packet_id;
    if (location.type != 2) return {};
    std::optional<uint32_t> found;
    for (const auto& [flow_cid, flow] : flows) {
        if (flow.src == location.ipv6_src && flow.dst == location.ipv6_dst &&
            flow.port == location.dst_port) {
            if (found) return {};
            found = (uint32_t{flow_cid} << 16) | location.packet_id;
        }
    }
    return found;
}

std::optional<uint32_t> RoutingState::ecm_for(uint32_t media, uint16_t ca_system) const
{
    std::optional<uint32_t> selected;
    for (const auto& [source, table] : mpts) {
        const uint16_t cid = source.first >> 16;
        for (const auto& asset : table.assets) {
            const bool matches = std::any_of(asset.locations.begin(), asset.locations.end(),
                [&](const auto& location) { return resolve(cid, location) == media; });
            if (!matches) continue;
            bool eligible = false;
            for (const auto& route : asset.ca_routes) {
                if (route.ca_system_id != ca_system) continue;
                for (const auto& location : route.locations) {
                    const auto stream = resolve(cid, location);
                    if (!stream || (selected && selected != stream)) return {};
                    selected = stream;
                    eligible = true;
                }
            }
            if (!eligible) return {};
        }
    }
    return selected;
}

std::set<uint32_t> RoutingState::ecm_streams(uint16_t ca_system) const
{
    std::set<uint32_t> result;
    for (const auto& [source, table] : mpts)
        for (const auto& asset : table.assets)
            for (const auto& route : asset.ca_routes)
                if (route.ca_system_id == ca_system)
                    for (const auto& location : route.locations)
                        if (auto stream = resolve(source.first >> 16, location)) result.insert(*stream);
    return result;
}

bool RoutingState::allows_emm(uint32_t stream, uint16_t ca_system) const
{
    for (const auto& [source, table] : cats)
        for (const auto& route : table.emm_routes)
            if (route.ca_system_id == ca_system)
                for (const auto& location : route.locations)
                    if (resolve(source >> 16, location) == stream) return true;
    return false;
}
