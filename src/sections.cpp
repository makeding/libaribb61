#include "sections.h"

#include <algorithm>

namespace {

constexpr uint8_t kEcmTable0 = 0x82;
constexpr uint8_t kEcmTable1 = 0x83;
constexpr uint8_t kEmmTable = 0x84;

uint16_t be16(const uint8_t *p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
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

bool section_bounds(const uint8_t *data, size_t size, uint8_t table_id, size_t& section_size)
{
    if (size < 12 || data[0] != table_id) {
        return false;
    }
    section_size = 3 + (be16(data + 1) & 0x0fff);
    return section_size >= 12 && section_size <= size && section_crc32(data, section_size) == 0;
}

} // namespace

bool acas_parse_ecm_section(const uint8_t *data,
                            size_t size,
                            std::vector<uint8_t>& ecm,
                            acas_ecm_metadata& metadata)
{
    size_t section_size = 0;
    if (!section_bounds(data, size, kEcmTable0, section_size) &&
        !section_bounds(data, size, kEcmTable1, section_size)) {
        return false;
    }

    const size_t payload_begin = 8;
    const size_t payload_end = section_size - 4;
    if (payload_end - payload_begin < 4) {
        return false;
    }

    ecm.assign(data + payload_begin, data + payload_end);
    metadata.protocol_number = ecm[0];
    metadata.broadcaster_group_id = be16(ecm.data() + 1);
    metadata.work_key_id = ecm[3];
    metadata.is_f1 = (metadata.protocol_number & 0x01) != 0;
    metadata.scrambling_key_pair_count = metadata.is_f1 && ecm.size() >= 5 ? ecm[4] : 0;
    return true;
}

bool acas_select_emm_payload(const uint8_t *data,
                             size_t size,
                             const std::array<uint8_t, 6>& cas_module_id,
                             std::vector<uint8_t>& emm)
{
    size_t section_size = 0;
    if (!section_bounds(data, size, kEmmTable, section_size)) {
        return false;
    }

    const size_t payload_end = section_size - 4;
    size_t pos = 8;
    while (pos < payload_end) {
        if (payload_end - pos < 7) {
            return false;
        }
        const size_t associated_information_size = data[pos + 6];
        const size_t next = pos + 7 + associated_information_size;
        if (next > payload_end) {
            return false;
        }
        if (std::equal(cas_module_id.begin(), cas_module_id.end(), data + pos)) {
            emm.assign(data + pos, data + next);
            return true;
        }
        pos = next;
    }
    return false;
}
