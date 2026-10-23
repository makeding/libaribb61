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
    if (size < 12 || data[0] != table_id || (data[5] & 1) == 0) {
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

    const size_t associated_information_length = data[payload_begin];
    if (associated_information_length < 3 ||
        associated_information_length != payload_end - payload_begin - 1) {
        return false;
    }

    std::vector<uint8_t> parsed(data + payload_begin, data + payload_end);
    acas_ecm_metadata parsed_metadata;
    parsed_metadata.associated_information_length = static_cast<uint8_t>(associated_information_length);
    parsed_metadata.protocol_number = parsed[1];
    parsed_metadata.broadcaster_id = parsed[2];
    parsed_metadata.work_key_id = parsed[3];
    ecm = std::move(parsed);
    metadata = parsed_metadata;
    return true;
}

bool acas_select_emm_payloads(const uint8_t *data,
                              size_t size,
                              const std::array<uint8_t, 6>& cas_module_id,
                              std::vector<std::vector<uint8_t>>& emms)
{
    size_t section_size = 0;
    if (!section_bounds(data, size, kEmmTable, section_size)) {
        return false;
    }

    const size_t payload_end = section_size - 4;
    std::vector<std::vector<uint8_t>> selected;
    size_t pos = 8;
    while (pos < payload_end) {
        if (payload_end - pos < 7) {
            return false;
        }
        const size_t associated_information_size = data[pos + 6];
        if (associated_information_size < 2) {
            return false;
        }
        const size_t next = pos + 7 + associated_information_size;
        if (next > payload_end) {
            return false;
        }
        if (std::equal(cas_module_id.begin(), cas_module_id.end(), data + pos)) {
            selected.emplace_back(data + pos, data + next);
        }
        pos = next;
    }
    emms = std::move(selected);
    return true;
}
