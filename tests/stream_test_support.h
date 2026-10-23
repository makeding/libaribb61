#ifndef ARIBB61_STREAM_TEST_SUPPORT_H
#define ARIBB61_STREAM_TEST_SUPPORT_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace aribb61_test {

inline void put_be16(uint8_t *p, uint16_t value)
{
    p[0] = static_cast<uint8_t>(value >> 8);
    p[1] = static_cast<uint8_t>(value);
}

inline void put_be32(uint8_t *p, uint32_t value)
{
    p[0] = static_cast<uint8_t>(value >> 24);
    p[1] = static_cast<uint8_t>(value >> 16);
    p[2] = static_cast<uint8_t>(value >> 8);
    p[3] = static_cast<uint8_t>(value);
}

inline void append_be16(std::vector<uint8_t>& data, uint16_t value)
{
    data.push_back(static_cast<uint8_t>(value >> 8));
    data.push_back(static_cast<uint8_t>(value));
}

inline uint32_t section_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffffU;
    for (size_t i = 0; i < size; ++i) {
        crc ^= static_cast<uint32_t>(data[i]) << 24;
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc & 0x80000000U) ? (crc << 1) ^ 0x04c11db7U : crc << 1;
    }
    return crc;
}

inline std::vector<uint8_t> make_section(uint8_t table_id, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> section(8, 0);
    section[0] = table_id;
    section[5] = 1;
    section.insert(section.end(), payload.begin(), payload.end());
    section.resize(section.size() + 4);
    put_be16(section.data() + 1, static_cast<uint16_t>(0xb000U | (section.size() - 3)));
    put_be32(section.data() + section.size() - 4, section_crc32(section.data(), section.size() - 4));
    return section;
}

inline std::vector<uint8_t> make_ecm_section(uint8_t generation)
{
    std::vector<uint8_t> ecm(27, 0);
    ecm[0] = 26;
    ecm[1] = 0x12;
    ecm[2] = 0x34;
    ecm[3] = generation;
    ecm[4] = 1;
    return make_section(0x82, ecm);
}

inline std::vector<uint8_t> ca_location_pid(uint16_t packet_id)
{
    return { 0, static_cast<uint8_t>(packet_id >> 8), static_cast<uint8_t>(packet_id) };
}

inline std::vector<uint8_t> ca_location_ipv6(const std::array<uint8_t, 16>& src,
                                             const std::array<uint8_t, 16>& dst,
                                             uint16_t port, uint16_t packet_id)
{
    std::vector<uint8_t> result = { 2 };
    result.insert(result.end(), src.begin(), src.end());
    result.insert(result.end(), dst.begin(), dst.end());
    append_be16(result, port);
    append_be16(result, packet_id);
    return result;
}

inline std::vector<uint8_t> access_control_descriptor(uint16_t ca_system_id,
                                                       const std::vector<uint8_t>& location)
{
    std::vector<uint8_t> result;
    append_be16(result, 0x8004);
    result.push_back(static_cast<uint8_t>(2 + location.size()));
    append_be16(result, ca_system_id);
    result.insert(result.end(), location.begin(), location.end());
    return result;
}

inline std::vector<uint8_t> access_control_descriptor(uint16_t ca_system_id, uint16_t ecm_packet_id)
{
    return access_control_descriptor(ca_system_id, ca_location_pid(ecm_packet_id));
}

inline std::vector<uint8_t> mpt_asset(uint8_t asset_id, const std::vector<uint8_t>& media_location,
                                      const std::vector<uint8_t>& descriptors)
{
    std::vector<uint8_t> result = { 0, 0, 0, 0, 1, 1, asset_id, 'h', 'v', 'c', '1', 0, 1 };
    result.insert(result.end(), media_location.begin(), media_location.end());
    append_be16(result, static_cast<uint16_t>(descriptors.size()));
    result.insert(result.end(), descriptors.begin(), descriptors.end());
    return result;
}

inline std::vector<uint8_t> mpt_asset(uint8_t asset_id, uint16_t media_packet_id,
                                      const std::vector<uint8_t>& descriptors)
{
    return mpt_asset(asset_id, ca_location_pid(media_packet_id), descriptors);
}

inline std::vector<uint8_t> make_mpt(uint8_t version, uint16_t service_id,
                                     const std::vector<uint8_t>& package_descriptors,
                                     const std::vector<std::vector<uint8_t>>& assets)
{
    std::vector<uint8_t> result = { 0x20, version, 0, 0, 0, 2,
                                    static_cast<uint8_t>(service_id >> 8),
                                    static_cast<uint8_t>(service_id) };
    append_be16(result, static_cast<uint16_t>(package_descriptors.size()));
    result.insert(result.end(), package_descriptors.begin(), package_descriptors.end());
    result.push_back(static_cast<uint8_t>(assets.size()));
    for (const auto& asset : assets) result.insert(result.end(), asset.begin(), asset.end());
    put_be16(result.data() + 2, static_cast<uint16_t>(result.size() - 4));
    return result;
}

inline std::vector<uint8_t> make_mpt(uint8_t version, uint16_t service_id,
                                     const std::vector<std::vector<uint8_t>>& assets)
{
    return make_mpt(version, service_id, {}, assets);
}

inline std::vector<uint8_t> make_pa(const std::vector<std::vector<uint8_t>>& tables)
{
    std::vector<uint8_t> result = { 0, 0, 0, 0, 0, 0, 0,
                                    static_cast<uint8_t>(tables.size()) };
    result.insert(result.end(), tables.size() * 4, 0);
    for (const auto& table : tables) result.insert(result.end(), table.begin(), table.end());
    put_be32(result.data() + 3, static_cast<uint32_t>(result.size() - 7));
    return result;
}

inline std::vector<uint8_t> make_scrambler_descriptor(uint8_t layer_type, uint8_t system_id)
{
    std::vector<uint8_t> result;
    append_be16(result, 0x8005);
    result.insert(result.end(), { 2, static_cast<uint8_t>(layer_type << 6), system_id });
    return result;
}

inline std::vector<uint8_t> make_cat(uint8_t version, uint16_t ca_system_id, uint16_t emm_packet_id,
                                     uint8_t layer_type = 1, uint8_t system_id = 1)
{
    std::vector<uint8_t> result = { 0x86, version, 0, 0 };
    const auto access = access_control_descriptor(ca_system_id, emm_packet_id);
    const auto scrambler = make_scrambler_descriptor(layer_type, system_id);
    result.insert(result.end(), access.begin(), access.end());
    result.insert(result.end(), scrambler.begin(), scrambler.end());
    put_be16(result.data() + 2, static_cast<uint16_t>(result.size() - 4));
    return result;
}

inline std::vector<uint8_t> make_mmt_section_message(uint16_t message_id,
                                                      const std::vector<uint8_t>& section)
{
    std::vector<uint8_t> result = { static_cast<uint8_t>(message_id >> 8),
                                    static_cast<uint8_t>(message_id), 0,
                                    static_cast<uint8_t>(section.size() >> 8),
                                    static_cast<uint8_t>(section.size()) };
    result.insert(result.end(), section.begin(), section.end());
    return result;
}

inline std::vector<uint8_t> make_tlv(uint16_t cid, uint16_t packet_id, uint32_t sequence,
                                     uint8_t payload_type, const std::vector<uint8_t>& payload,
                                     uint8_t scramble_control = 0,
                                     size_t authenticated_payload_size = 0,
                                     uint8_t scramble_method = 0)
{
    std::vector<uint8_t> mmtp(12, 0);
    mmtp[0] = scramble_control == 0 ? 0 : 0x02;
    mmtp[1] = payload_type;
    put_be16(mmtp.data() + 2, packet_id);
    put_be32(mmtp.data() + 8, sequence);
    if (scramble_control != 0) {
        std::vector<uint8_t> related = { scramble_control };
        if (scramble_control & 0x04) related.push_back(scramble_method);
        if (scramble_control & 0x02) {
            append_be16(related, static_cast<uint16_t>(authenticated_payload_size));
        }
        append_be16(mmtp, 0);
        append_be16(mmtp, static_cast<uint16_t>(4 + related.size()));
        append_be16(mmtp, 0x8001);
        append_be16(mmtp, static_cast<uint16_t>(related.size()));
        mmtp.insert(mmtp.end(), related.begin(), related.end());
    }
    mmtp.insert(mmtp.end(), payload.begin(), payload.end());

    std::vector<uint8_t> packet = { 0x7f, 0x03, 0, 0,
                                    static_cast<uint8_t>(cid >> 4),
                                    static_cast<uint8_t>(cid << 4), 0x61 };
    packet.insert(packet.end(), mmtp.begin(), mmtp.end());
    put_be16(packet.data() + 2, static_cast<uint16_t>(packet.size() - 4));
    return packet;
}

inline std::vector<uint8_t> make_full_ipv6_tlv(uint16_t cid, uint16_t packet_id,
                                               uint32_t sequence,
                                               const std::array<uint8_t, 16>& src,
                                               const std::array<uint8_t, 16>& dst,
                                               uint16_t dst_port, uint8_t payload_type,
                                               const std::vector<uint8_t>& payload)
{
    const auto compressed = make_tlv(cid, packet_id, sequence, payload_type, payload);
    std::vector<uint8_t> packet = { 0x7f, 0x03, 0, 0,
                                    static_cast<uint8_t>(cid >> 4),
                                    static_cast<uint8_t>(cid << 4), 0x60 };
    packet.resize(4 + 45, 0);
    packet[7] = 0x60;
    packet[11] = 17;
    for (size_t i = 0; i < src.size(); ++i) packet[13 + i] = src[i];
    for (size_t i = 0; i < dst.size(); ++i) packet[29 + i] = dst[i];
    put_be16(packet.data() + 47, dst_port);
    packet.insert(packet.end(), compressed.begin() + 7, compressed.end());
    put_be16(packet.data() + 2, static_cast<uint16_t>(packet.size() - 4));
    return packet;
}

inline std::vector<uint8_t> make_signaling_tlv(uint16_t cid, uint16_t packet_id,
                                                uint32_t sequence, const std::vector<uint8_t>& message)
{
    std::vector<uint8_t> signaling = { 0, 0 };
    signaling.insert(signaling.end(), message.begin(), message.end());
    return make_tlv(cid, packet_id, sequence, 2, signaling);
}

} // namespace aribb61_test

#endif
